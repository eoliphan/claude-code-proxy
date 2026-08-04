//! The Kiro provider: the `Provider`/`CliHandlers` implementations that wire
//! every other module in this directory into the proxy's registry.

pub mod auth;
pub mod client;
pub mod count_tokens;
pub mod translate;

use async_trait::async_trait;
use axum::Json;
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_util::StreamExt;
use http::StatusCode;
use once_cell::sync::Lazy;

use crate::anthropic::json_error;
use crate::anthropic::schema::{CountTokensResponse, MessagesRequest};
use crate::auth::AuthStorage;
use crate::monitor::usage_from_anthropic_sse;
use crate::provider::{CliHandlers, Provider, RequestContext};
use crate::registry::KIRO_PREFIX;

use self::auth::KiroCredentials;
use self::client::KiroHttpClient;
use self::translate::model_allowlist::resolve_model;
use self::translate::model_discovery::MODEL_CACHE;
use self::translate::models::{
    DEFAULT_FIRST_TOKEN_TIMEOUT_MS, KIRO_MODELS, KiroModelMeta, resolve_api_region,
};
use self::translate::stream::{
    KiroStreamError, RunStreamOptions, StreamTimeouts, accumulate_sse_message,
    run_kiro_stream_with_base_url,
};

/// The one and only [`KiroHttpClient`] for the life of the process.
///
/// This is load-bearing, not a micro-optimization: the client owns the single
/// [`auth::KiroAuthManager`] whose in-memory credential cache and singleflight
/// refresh lock make concurrent requests share one token refresh instead of
/// racing AWS SSO-OIDC's refresh-token rotation. Constructing a client (and
/// therefore a manager) per request would silently defeat both.
static KIRO_HTTP_CLIENT: Lazy<KiroHttpClient> = Lazy::new(KiroHttpClient::new);

/// Metadata used for a model the account's `ListAvailableModels` reported but
/// that has no entry in the static [`KIRO_MODELS`] catalog. `reasoning` is
/// deliberately `false`: the capability is unverified for such a model, and
/// enabling thinking mode injects a `<thinking_mode>` system-prompt prefix
/// that a non-reasoning model would emit verbatim.
const UNTEMPLATED_MODEL: KiroModelMeta = KiroModelMeta {
    id: "",
    name: "",
    reasoning: false,
    input_image: false,
    context_window: 200_000,
    max_tokens: 64_000,
    first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
};

/// Everything `handle_messages` needs that differs between production and a
/// test pointed at a mock backend. `client` is `&'static` because the
/// `stream: true` path hands the orchestration to `tokio::spawn`, which
/// requires a `'static` future.
struct KiroRuntime {
    client: &'static KiroHttpClient,
    /// `None` in production; a mock backend's base URL in tests.
    base_url_override: Option<String>,
    timeouts: StreamTimeouts,
}

impl KiroRuntime {
    /// The only place production code reaches for the process-wide client.
    fn production() -> Self {
        Self {
            client: &KIRO_HTTP_CLIENT,
            base_url_override: None,
            timeouts: StreamTimeouts::default(),
        }
    }
}

pub struct KiroProvider;

impl Default for KiroProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KiroProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Provider for KiroProvider {
    fn name(&self) -> &'static str {
        "kiro"
    }

    fn supported_models(&self) -> Vec<String> {
        // Reads the stored credential directly rather than going through the
        // auth cascade: `Registry::new` calls this before any login has
        // happened, and `resolve_api_region("")` yields `"us-east-1"`, whose
        // model list is the full static catalog.
        let api_region = api_region_for(&auth::token_store::file_store());
        MODEL_CACHE.model_ids(&api_region)
    }

    fn cli(&self) -> &'static dyn CliHandlers {
        &KIRO_CLI
    }

    async fn handle_messages(&self, body: MessagesRequest, ctx: RequestContext) -> Response {
        self.handle_messages_with(body, ctx, KiroRuntime::production())
            .await
    }

    async fn handle_count_tokens(&self, body: MessagesRequest, ctx: RequestContext) -> Response {
        let raw_model = body.model.as_deref().unwrap_or("auto");
        let resolved = resolve_model(strip_kiro_prefix(raw_model));
        if let Some(monitor) = ctx.monitor.as_ref() {
            monitor.model_resolved(&ctx.req_id, &resolved);
        }
        let tokens = count_tokens::count_tokens(&body);
        if let Some(monitor) = ctx.monitor.as_ref() {
            monitor.usage_updated(&ctx.req_id, Some(tokens), None);
        }
        (
            StatusCode::OK,
            Json(CountTokensResponse {
                input_tokens: tokens,
            }),
        )
            .into_response()
    }
}

impl KiroProvider {
    async fn handle_messages_with(
        &self,
        mut body: MessagesRequest,
        ctx: RequestContext,
        rt: KiroRuntime,
    ) -> Response {
        let message_id = format!("msg_{}", uuid::Uuid::new_v4().simple());
        let want_stream = body.stream;

        // Registry routing (Task 8) only decided *that* this request belongs to
        // Kiro; stripping the `kiro:` disambiguation prefix off the model id
        // actually sent upstream is this provider's job.
        let raw_model = body.model.clone().unwrap_or_else(|| "auto".to_string());
        let resolved = resolve_model(strip_kiro_prefix(&raw_model));

        // Availability is decided per API region, before any network call:
        // `contains_id` consults what `ListAvailableModels` reported for this
        // region and falls back to the region-filtered static catalog when
        // discovery has not run yet. Checking `KIRO_MODELS` membership first
        // would forward, e.g., a `us-east-1`-only model upstream from an
        // `eu-central-1` account just because it exists in the catalog.
        let api_region = api_region_for(&rt.client.auth_manager().store);
        if !MODEL_CACHE.contains_id(&api_region, &resolved) {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!(
                    "Model \"{raw_model}\" resolves to \"{resolved}\", which is not available for this Kiro account (API region {api_region})"
                ),
            );
        }
        // Available, but possibly discovered live with no static template.
        let model_meta = KIRO_MODELS
            .iter()
            .copied()
            .find(|m| m.id == resolved)
            .unwrap_or(UNTEMPLATED_MODEL);

        body.model = Some(resolved.clone());

        if let Some(monitor) = ctx.monitor.as_ref() {
            monitor.model_resolved(&ctx.req_id, &resolved);
        }

        // Generated exactly once per incoming request, before any retry:
        // `run_kiro_stream`/`build_kiro_request` never mint their own, so this
        // is the sole source and every internal retry rebuild reuses it.
        let conversation_id = ctx
            .session_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        if let Some(monitor) = ctx.monitor.as_ref() {
            monitor.upstream_started(&ctx.req_id);
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);

        if want_stream {
            let client = rt.client;
            let base_url = rt.base_url_override.clone();
            let timeouts = rt.timeouts;
            let reasoning_enabled = model_meta.reasoning;
            let task_message_id = message_id.clone();
            let stream_task = tokio::spawn(async move {
                let opts = RunStreamOptions {
                    client,
                    model: &model_meta,
                    req: &body,
                    message_id: &task_message_id,
                    conversation_id: &conversation_id,
                    reasoning_enabled,
                    timeouts,
                };
                run_kiro_stream_with_base_url(opts, tx, base_url.as_deref()).await
            });

            // Wait for the first frame before committing to 200 +
            // `text/event-stream`. `run_kiro_stream` only synthesizes a
            // terminal `error` frame once it has already emitted something
            // (SSE cannot retract a `message_start`), so a failure that
            // happens before the first frame — an expired credential or a
            // rejected request, the two likeliest real failures — would
            // otherwise reach the client as a 200 with an empty body.
            let Some(first) = rx.recv().await else {
                return match stream_task.await {
                    Ok(Err(err)) => map_kiro_stream_error_to_response(&err),
                    Ok(Ok(())) => json_error(
                        StatusCode::BAD_GATEWAY,
                        "api_error",
                        "Kiro completed without producing output",
                    ),
                    Err(join_err) => json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "api_error",
                        format!("Kiro stream task join error: {join_err}"),
                    ),
                };
            };

            let progress_ctx = ctx.clone();
            if let Ok(bytes) = &first {
                record_live_stream_progress(&progress_ctx, bytes);
            }
            let rest =
                futures_util::stream::unfold((rx, progress_ctx), |(mut rx, ctx)| async move {
                    let item = rx.recv().await?;
                    if let Ok(bytes) = &item {
                        record_live_stream_progress(&ctx, bytes);
                    }
                    Some((item, (rx, ctx)))
                });
            let byte_stream = futures_util::stream::once(async move { first }).chain(rest);
            event_stream_response(byte_stream)
        } else {
            // Drain fully before committing to any response, so a terminal
            // error becomes a normal HTTP error instead of a truncated stream.
            let opts = RunStreamOptions {
                client: rt.client,
                model: &model_meta,
                req: &body,
                message_id: &message_id,
                conversation_id: &conversation_id,
                reasoning_enabled: model_meta.reasoning,
                timeouts: rt.timeouts,
            };
            let run = run_kiro_stream_with_base_url(opts, tx, rt.base_url_override.as_deref());
            let drain = async {
                let mut sse = Vec::new();
                let mut first_err: Option<std::io::Error> = None;
                while let Some(item) = rx.recv().await {
                    match item {
                        Ok(bytes) => sse.extend_from_slice(&bytes),
                        Err(e) => first_err = first_err.or(Some(e)),
                    }
                }
                (sse, first_err)
            };
            let (result, (sse, sink_err)) = tokio::join!(run, drain);

            if let Err(err) = result {
                return map_kiro_stream_error_to_response(&err);
            }
            if let Some(err) = sink_err {
                return json_error(StatusCode::BAD_GATEWAY, "api_error", err.to_string());
            }

            let json = accumulate_sse_message(&sse, &message_id, &resolved);
            if let Some(monitor) = ctx.monitor.as_ref() {
                monitor.usage_updated(
                    &ctx.req_id,
                    json.pointer("/usage/input_tokens").and_then(|v| v.as_u64()),
                    json.pointer("/usage/output_tokens")
                        .and_then(|v| v.as_u64()),
                );
            }
            (StatusCode::OK, Json(json)).into_response()
        }
    }
}

/// Strips the explicit `kiro:` disambiguation prefix, if present.
fn strip_kiro_prefix(model: &str) -> &str {
    model.strip_prefix(KIRO_PREFIX).unwrap_or(model)
}

/// Resolved Kiro **API** region for the credential in `store` (not the raw SSO
/// region stored on it), defaulting to `us-east-1` when nothing is stored yet.
fn api_region_for(store: &impl AuthStorage<KiroCredentials>) -> String {
    let sso_region = store
        .load()
        .ok()
        .flatten()
        .map(|creds| creds.region)
        .unwrap_or_default();
    resolve_api_region(&sso_region)
}

fn event_stream_response<S>(stream: S) -> Response
where
    S: futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let headers = [
        (http::header::CONTENT_TYPE, "text/event-stream"),
        (http::header::CACHE_CONTROL, "no-cache"),
        (http::header::CONNECTION, "keep-alive"),
    ];
    (headers, Body::from_stream(stream)).into_response()
}

fn count_sse_events(bytes: &[u8]) -> u64 {
    String::from_utf8_lossy(bytes).matches("event:").count() as u64
}

fn record_live_stream_progress(ctx: &RequestContext, chunk: &[u8]) {
    if let Some(monitor) = ctx.monitor.as_ref() {
        let (input_tokens, output_tokens) = usage_from_anthropic_sse(chunk);
        monitor.stream_progress(
            &ctx.req_id,
            chunk.len() as u64,
            count_sse_events(chunk),
            input_tokens,
            output_tokens,
        );
    }
}

fn map_kiro_stream_error_to_response(err: &KiroStreamError) -> Response {
    match err {
        KiroStreamError::Auth(e) => json_error(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            e.to_string(),
        ),
        KiroStreamError::ContextOverflow(message) => json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            message.clone(),
        ),
        // `NonRetryable` carries the upstream status and `Retry-After`
        // specifically so they survive into this response; collapsing every
        // variant to a 400 would tell a rate-limited client to fix its request.
        KiroStreamError::NonRetryable {
            status: 429,
            message,
            retry_after,
        } => {
            let retry_after = retry_after.as_deref().unwrap_or("5").to_string();
            let body = json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                message.clone(),
            );
            ([(http::header::RETRY_AFTER, retry_after)], body).into_response()
        }
        KiroStreamError::NonRetryable {
            status, message, ..
        } if *status >= 500 => json_error(StatusCode::BAD_GATEWAY, "api_error", message.clone()),
        KiroStreamError::NonRetryable { message, .. } => json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            message.clone(),
        ),
        KiroStreamError::Other(e) => {
            json_error(StatusCode::BAD_GATEWAY, "api_error", e.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

pub(crate) struct KiroCli;

/// Writes device-login progress to stderr so it never contaminates stdout.
struct StderrCallbacks;

impl auth::device::DeviceLoginCallbacks for StderrCallbacks {
    fn on_progress(&self, message: &str) {
        eprintln!("{message}");
    }

    fn on_auth_prompt(&self, verification_uri_complete: &str, user_code: &str) {
        eprintln!("\nVisit: {verification_uri_complete}\nCode:  {user_code}\n");
    }
}

impl KiroCli {
    /// The store-taking half of [`CliHandlers::status`], so tests can point it
    /// at a temp-dir store instead of mutating process-wide env.
    fn status_with(store: &impl AuthStorage<KiroCredentials>) -> anyhow::Result<()> {
        match store.load()? {
            Some(creds) => {
                println!("Auth path: {}", store.path());
                println!("Authenticated: true");
                println!("Region: {}", creds.region);
                println!("Method: {:?}", creds.auth_method);
                Ok(())
            }
            None => anyhow::bail!("Not authenticated"),
        }
    }

    /// The store-taking half of [`CliHandlers::logout`].
    fn logout_with(store: &impl AuthStorage<KiroCredentials>) -> anyhow::Result<()> {
        store.clear()?;
        println!("Logged out");
        Ok(())
    }
}

impl CliHandlers for KiroCli {
    fn login(&self) -> anyhow::Result<()> {
        use std::io::Write;

        print!(
            "Enter your organization's IAM Identity Center start URL, or press Enter for AWS Builder ID: "
        );
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let start_url = input.trim();

        // `bootstrap_login` rejects a contradictory (method, start_url) pair,
        // so these two must stay in lockstep.
        let (method, start_url) = if start_url.is_empty() {
            (auth::manager::KiroLoginMethod::BuilderId, None)
        } else {
            (auth::manager::KiroLoginMethod::Idc, Some(start_url))
        };

        let manager = auth::manager::KiroAuthManager::new(auth::token_store::file_store());
        let creds = manager.bootstrap_login(&StderrCallbacks, method, start_url)?;
        println!("Authenticated (region: {})", creds.region);
        Ok(())
    }

    fn device(&self) -> anyhow::Result<()> {
        // Kiro's only interactive flow *is* the device-code flow; there is no
        // separate localhost-redirect mode, so this mirrors Kimi's delegation.
        self.login()
    }

    fn status(&self) -> anyhow::Result<()> {
        KiroCli::status_with(&auth::token_store::file_store())
    }

    fn logout(&self) -> anyhow::Result<()> {
        KiroCli::logout_with(&auth::token_store::file_store())
    }
}

pub(crate) static KIRO_CLI: KiroCli = KiroCli;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::schema::Message;
    use crate::auth::FileAuthStore;
    use crate::paths::DirResolverEnv;
    use crate::providers::codex::auth::test_http;
    use crate::providers::kiro::auth::{KiroAuthManager, KiroAuthMethod};
    use crate::providers::kiro::translate::model_discovery::DiscoveredModel;
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tempfile::TempDir;

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    fn creds(region: &str) -> KiroCredentials {
        KiroCredentials {
            access: "test-access".into(),
            refresh: "test-refresh".into(),
            expires: u64::MAX,
            region: region.into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            // Pre-set so `resolve_profile_arn` never calls the backend.
            profile_arn: Some("arn:test".into()),
            expiry_buffer_ms: 0,
        }
    }

    fn temp_store(dir: &Path) -> FileAuthStore<KiroCredentials> {
        FileAuthStore::new(
            dir.join("auth.json").to_string_lossy().to_string(),
            dir.join("legacy.json").to_string_lossy().to_string(),
        )
    }

    /// A `'static` client backed by a temp-dir store and a temp HOME, so no
    /// test reads the developer's real credentials. Leaked deliberately:
    /// [`KiroRuntime::client`] is `&'static` because the `stream: true` path
    /// spawns the orchestration, and a handful of leaks in a test binary is
    /// cheaper than threading a lifetime through production code.
    fn leaked_test_client(region: &str) -> (&'static KiroHttpClient, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = temp_store(tmp.path());
        store.save(creds(region)).unwrap();
        let deps = DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        let manager = KiroAuthManager::with_deps(store, deps);
        let client: &'static KiroHttpClient =
            Box::leak(Box::new(KiroHttpClient::for_test(manager)));
        (client, tmp)
    }

    fn test_runtime(client: &'static KiroHttpClient, base_url: &str) -> KiroRuntime {
        KiroRuntime {
            client,
            base_url_override: Some(base_url.to_string()),
            timeouts: StreamTimeouts {
                first_token_ms: 5_000,
                idle_ms: 5_000,
            },
        }
    }

    fn request(model: &str, stream: bool) -> MessagesRequest {
        MessagesRequest {
            model: Some(model.to_string()),
            max_tokens: Some(1024),
            messages: vec![Message {
                role: "user".to_string(),
                content: json!("Hello"),
            }],
            stream,
            bypass_provider_model_override: false,
            extra: serde_json::Map::new(),
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            req_id: "req-kiro-provider-test".to_string(),
            session_id: None,
            session_seq: None,
            provider: "kiro".to_string(),
            traffic: None,
            monitor: None,
        }
    }

    async fn body_bytes(response: Response) -> Vec<u8> {
        response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes()
            .to_vec()
    }

    fn content_type(response: &Response) -> String {
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    // ------------------------------------------------------------------
    // Minimal mock Kiro backend
    // ------------------------------------------------------------------

    struct MockKiro {
        url: String,
        hits: Arc<AtomicUsize>,
        shutdown: Arc<AtomicBool>,
        bodies: Arc<Mutex<Vec<String>>>,
    }

    impl Drop for MockKiro {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
        }
    }

    impl MockKiro {
        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }

        fn request_bodies(&self) -> Vec<String> {
            self.bodies.lock().unwrap().clone()
        }
    }

    /// Answers every `GenerateAssistantResponse` call with the same scripted
    /// status + body. Deliberately simpler than `stream.rs`'s own mock (no
    /// per-chunk delays or gates) — this task tests provider-level branching,
    /// not stream orchestration.
    fn spawn_mock(status: u16, body: &'static str) -> MockKiro {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).expect("set nonblocking");
        let url = format!("http://{addr}");

        let hits = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (thread_hits, thread_shutdown, thread_bodies) = (
            Arc::clone(&hits),
            Arc::clone(&shutdown),
            Arc::clone(&bodies),
        );
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let _ = ready_tx.send(());
            loop {
                if thread_shutdown.load(Ordering::Relaxed) {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Some(request) = test_http::read_http_request(&mut stream) else {
                            continue;
                        };
                        thread_hits.fetch_add(1, Ordering::SeqCst);
                        if let Some((_, request_body)) = request.split_once("\r\n\r\n") {
                            thread_bodies.lock().unwrap().push(request_body.to_string());
                        }
                        let reason = if status == 200 { "OK" } else { "Bad Request" };
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mock server should be ready");

        MockKiro {
            url,
            hits,
            shutdown,
            bodies,
        }
    }

    const HELLO_BODY: &str =
        r#"{"content":"Hello"}{"content":" world"}{"contextUsagePercentage":5}"#;

    // ==================================================================
    // Step 1: name / supported_models, pre-auth
    // ==================================================================

    #[test]
    fn name_is_kiro() {
        assert_eq!(KiroProvider::new().name(), "kiro");
    }

    #[test]
    fn api_region_defaults_to_us_east_1_when_nothing_is_stored() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(api_region_for(&temp_store(tmp.path())), "us-east-1");
    }

    #[test]
    fn api_region_maps_the_sso_region_to_the_kiro_api_region() {
        let tmp = TempDir::new().unwrap();
        let store = temp_store(tmp.path());
        store.save(creds("eu-west-1")).unwrap();
        assert_eq!(api_region_for(&store), "eu-central-1");
    }

    #[test]
    fn supported_models_pre_auth_is_the_full_static_catalog() {
        // `resolve_api_region("")` is `us-east-1`, whose model list is the
        // whole catalog — this is what makes `Registry::new` able to call
        // `supported_models()` before any login has happened.
        let expected: Vec<String> = KIRO_MODELS.iter().map(|m| m.id.to_string()).collect();
        assert_eq!(MODEL_CACHE.model_ids("us-east-1"), expected);
    }

    #[test]
    fn supported_models_only_ever_reports_known_kiro_models() {
        let models = KiroProvider::new().supported_models();
        for model in &models {
            assert!(
                KIRO_MODELS.iter().any(|m| m.id == model),
                "{model} is not a known Kiro model"
            );
        }
    }

    // ==================================================================
    // Step 3: CLI status / logout
    // ==================================================================

    #[test]
    fn cli_status_errors_before_login_and_after_logout() {
        let tmp = TempDir::new().unwrap();
        let store = temp_store(tmp.path());

        let before = KiroCli::status_with(&store);
        assert!(before.is_err(), "status must fail with nothing stored");
        assert!(
            before
                .unwrap_err()
                .to_string()
                .contains("Not authenticated")
        );

        store.save(creds("us-east-1")).unwrap();
        KiroCli::status_with(&store).expect("status succeeds once authenticated");

        KiroCli::logout_with(&store).expect("logout succeeds");
        assert!(
            store.load().unwrap().is_none(),
            "logout must clear the stored credential"
        );
        assert!(
            KiroCli::status_with(&store).is_err(),
            "status must fail again after logout"
        );
    }

    #[test]
    fn cli_logout_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = temp_store(tmp.path());
        KiroCli::logout_with(&store).expect("logout with nothing stored still succeeds");
    }

    // ==================================================================
    // Step 5: model validation
    // ==================================================================

    #[tokio::test]
    async fn unknown_model_is_rejected_locally_without_any_upstream_call() {
        let server = spawn_mock(200, HELLO_BODY);
        let (client, _tmp) = leaked_test_client("us-east-1");

        let response = KiroProvider::new()
            .handle_messages_with(
                request("kiro:not-a-real-model", false),
                ctx(),
                test_runtime(client, &server.url),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body["error"]["type"], "invalid_request_error");
        assert_eq!(server.hits(), 0, "no request may reach the backend");
    }

    #[tokio::test]
    async fn a_model_absent_from_this_regions_catalog_is_rejected() {
        // `resolve_api_region` passes an unmapped region through unchanged and
        // `models_for_region` reports no models for it, so nothing is
        // available to this account — including catalog models.
        let server = spawn_mock(200, HELLO_BODY);
        let (client, _tmp) = leaked_test_client("zz-kiro-provider-empty-region");

        let response = KiroProvider::new()
            .handle_messages_with(
                request("claude-sonnet-4-6", false),
                ctx(),
                test_runtime(client, &server.url),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(server.hits(), 0, "no request may reach the backend");
    }

    #[tokio::test]
    async fn a_dynamically_discovered_model_with_no_static_template_is_accepted() {
        let region = "zz-kiro-provider-discovered-region";
        MODEL_CACHE.set(
            region,
            vec![DiscoveredModel {
                id: "zz-discovered-model".to_string(),
                name: "Discovered".to_string(),
                reasoning: false,
                input_image: false,
                context_window: 200_000,
                max_tokens: 64_000,
            }],
        );
        let server = spawn_mock(200, HELLO_BODY);
        let (client, _tmp) = leaked_test_client(region);

        let response = KiroProvider::new()
            .handle_messages_with(
                request("zz-discovered-model", false),
                ctx(),
                test_runtime(client, &server.url),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(server.hits(), 1);
    }

    // ==================================================================
    // Step 6: stream: true vs stream: false
    // ==================================================================

    #[tokio::test]
    async fn stream_true_returns_incremental_sse() {
        let server = spawn_mock(200, HELLO_BODY);
        let (client, _tmp) = leaked_test_client("us-east-1");

        let response = KiroProvider::new()
            .handle_messages_with(
                request("claude-sonnet-4-6", true),
                ctx(),
                test_runtime(client, &server.url),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(content_type(&response), "text/event-stream");
        let sse = String::from_utf8(body_bytes(response).await).unwrap();
        assert!(sse.contains("event: message_start"), "{sse}");
        assert!(sse.contains("event: message_stop"), "{sse}");
        assert!(sse.contains("Hello"), "{sse}");
    }

    #[tokio::test]
    async fn stream_false_returns_one_accumulated_json_message() {
        let server = spawn_mock(200, HELLO_BODY);
        let (client, _tmp) = leaked_test_client("us-east-1");

        let response = KiroProvider::new()
            .handle_messages_with(
                request("claude-sonnet-4-6", false),
                ctx(),
                test_runtime(client, &server.url),
            )
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(content_type(&response), "application/json");
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body["type"], "message");
        assert_eq!(body["role"], "assistant");
        assert_eq!(body["model"], "claude-sonnet-4-6");
        assert_eq!(body["content"][0]["type"], "text");
        assert_eq!(body["content"][0]["text"], "Hello world");
        assert_eq!(body["stop_reason"], "end_turn");
    }

    #[tokio::test]
    async fn both_branches_report_the_same_resolved_model() {
        // An alias, so a branch that reported the *requested* id rather than
        // the resolved one is visibly wrong.
        let server = spawn_mock(200, HELLO_BODY);
        let (client, _tmp) = leaked_test_client("us-east-1");
        let expected = resolve_model("sonnet");

        let streamed = KiroProvider::new()
            .handle_messages_with(
                request("kiro:sonnet", true),
                ctx(),
                test_runtime(client, &server.url),
            )
            .await;
        let sse = String::from_utf8(body_bytes(streamed).await).unwrap();

        let buffered = KiroProvider::new()
            .handle_messages_with(
                request("kiro:sonnet", false),
                ctx(),
                test_runtime(client, &server.url),
            )
            .await;
        let json: Value = serde_json::from_slice(&body_bytes(buffered).await).unwrap();

        assert_eq!(json["model"], expected.as_str());
        assert!(
            sse.contains(&format!("\"model\":\"{expected}\"")),
            "streamed message_start should report {expected}: {sse}"
        );
    }

    #[tokio::test]
    async fn stream_true_failing_before_the_first_frame_returns_an_http_error() {
        // `run_kiro_stream` only synthesizes an `error` SSE frame once it has
        // already emitted something, so committing to 200 + text/event-stream
        // before the first frame arrives would turn every pre-stream failure
        // into an empty 200 body.
        let server = spawn_mock(400, r#"{"message":"nope"}"#);
        let (client, _tmp) = leaked_test_client("us-east-1");

        let response = KiroProvider::new()
            .handle_messages_with(
                request("claude-sonnet-4-6", true),
                ctx(),
                test_runtime(client, &server.url),
            )
            .await;

        assert_ne!(
            response.status(),
            StatusCode::OK,
            "a failure before the first frame must not be a 200"
        );
        assert_ne!(content_type(&response), "text/event-stream");
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body["type"], "error");
    }

    #[tokio::test]
    async fn one_conversation_id_is_generated_per_request_from_the_session_id() {
        let server = spawn_mock(200, HELLO_BODY);
        let (client, _tmp) = leaked_test_client("us-east-1");
        let mut request_ctx = ctx();
        request_ctx.session_id = Some("session-abc".to_string());

        KiroProvider::new()
            .handle_messages_with(
                request("claude-sonnet-4-6", false),
                request_ctx,
                test_runtime(client, &server.url),
            )
            .await;

        let bodies = server.request_bodies();
        assert_eq!(bodies.len(), 1);
        let sent: Value = serde_json::from_str(&bodies[0]).expect("request body is JSON");
        assert_eq!(
            sent["conversationState"]["conversationId"], "session-abc",
            "conversation id must come from the session id: {sent}"
        );
    }

    // ==================================================================
    // Step 7: the HTTP client is a process-wide singleton
    // ==================================================================

    #[test]
    fn every_request_shares_one_http_client_and_one_auth_manager() {
        // `KiroRuntime::production()` is the sole path production code takes to
        // a client; if a refactor ever made it construct one per call, Task 5's
        // singleflight refresh lock and credential cache would silently stop
        // being shared across concurrent requests.
        let first = KiroRuntime::production();
        let second = KiroRuntime::production();
        assert!(
            std::ptr::eq(first.client, second.client),
            "every request must borrow the same KiroHttpClient"
        );
        assert!(
            std::ptr::eq(first.client, &*KIRO_HTTP_CLIENT),
            "the shared client must be the process-wide static"
        );
        assert!(
            Arc::ptr_eq(
                &first.client.auth_manager_handle(),
                &second.client.auth_manager_handle()
            ),
            "every request must share one KiroAuthManager (singleflight refresh)"
        );
        // Separate provider instances must not imply separate clients.
        let _ = KiroProvider::new();
        let _ = KiroProvider::new();
        assert!(std::ptr::eq(
            KiroRuntime::production().client,
            &*KIRO_HTTP_CLIENT
        ));
    }

    #[test]
    fn production_runtime_never_overrides_the_upstream_base_url() {
        assert!(KiroRuntime::production().base_url_override.is_none());
    }

    // ==================================================================
    // Error mapping
    // ==================================================================

    #[test]
    fn rate_limit_errors_keep_their_status_and_retry_after() {
        let err = KiroStreamError::NonRetryable {
            status: 429,
            message: "slow down".to_string(),
            retry_after: Some("7".to_string()),
        };
        let response = map_kiro_stream_error_to_response(&err);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("7")
        );
    }

    #[test]
    fn upstream_5xx_becomes_a_bad_gateway() {
        let err = KiroStreamError::NonRetryable {
            status: 503,
            message: "upstream down".to_string(),
            retry_after: None,
        };
        assert_eq!(
            map_kiro_stream_error_to_response(&err).status(),
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn client_errors_become_invalid_request_errors() {
        let err = KiroStreamError::NonRetryable {
            status: 400,
            message: "bad request".to_string(),
            retry_after: None,
        };
        assert_eq!(
            map_kiro_stream_error_to_response(&err).status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn auth_and_context_overflow_errors_map_to_their_own_statuses() {
        assert_eq!(
            map_kiro_stream_error_to_response(&KiroStreamError::Auth(anyhow::anyhow!("expired")))
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            map_kiro_stream_error_to_response(&KiroStreamError::ContextOverflow(
                "too long".to_string()
            ))
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    // ==================================================================
    // count_tokens
    // ==================================================================

    #[tokio::test]
    async fn count_tokens_reports_a_positive_estimate() {
        let response = KiroProvider::new()
            .handle_count_tokens(request("kiro:sonnet", false), ctx())
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert!(body["input_tokens"].as_u64().unwrap() > 0);
    }
}
