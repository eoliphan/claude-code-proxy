//! Async Kiro HTTP client: single-attempt primitives for
//! `GenerateAssistantResponse` (streaming) and `ListAvailableModels`
//! (single-shot lookup).
//!
//! Deliberately a "dumb" primitive, per the plan's design notes: this module
//! classifies each response (retryable? capacity error? what Retry-After did
//! the server send?) and returns that classification to the caller. It does
//! **not** retry anything itself, and in particular it does **not**
//! auto-refresh-and-retry on 401/403 — that decision belongs entirely to
//! Task 15's outer retry loop, which owns three separate retry budgets
//! (auth, stall/empty-stream, capacity) that only it can see across
//! multiple attempts of the same logical request. A client that refreshed
//! and retried internally (the way Kimi's blocking client does) couldn't
//! share those budgets correctly.
//!
//! `KiroAuthManager::get_auth`/`force_refresh` (Task 5) are synchronous —
//! they only do blocking file/SQLite I/O — so this module calls `get_auth`
//! via `tokio::task::spawn_blocking` to avoid blocking the async executor
//! thread. Unlike Kimi (whose entire client is blocking and is invoked via
//! `spawn_blocking` at its call site), only that one blocking call is
//! wrapped here: the HTTP round-trip itself is genuinely async via
//! `reqwest::Client`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, RETRY_AFTER};
use serde::Serialize;
use serde_json::Value;

use super::auth::token_store::file_store;
use super::auth::{KiroAuthManager, KiroCredentials};
use super::translate::models::resolve_api_region;
use crate::auth::FileAuthStore;

/// This proxy's own identity, sent as both `User-Agent` and
/// `x-amz-user-agent`. Doesn't need to match `pi-provider-kiro`'s exact
/// string byte-for-byte — Kiro's backend doesn't appear to validate it
/// beyond presence.
const PROXY_USER_AGENT: &str = concat!("claude-code-proxy/", env!("CARGO_PKG_VERSION"), " md/kiro");

#[derive(Debug)]
pub struct KiroError {
    pub status: u16,
    pub message: String,
    pub body: Option<String>,
    /// True for: a transport-level failure (`status: 0`, e.g. connection
    /// refused/DNS failure — retrying a fresh attempt may well succeed),
    /// 401/403 (auth — retryable *after* a refresh, which this client never
    /// attempts itself), and capacity errors (see `capacity_error`).
    /// Everything else — generic 429/5xx and the other body-marker
    /// classifications below — is non-retryable *from this client's point
    /// of view* (Adversarial Review Findings #14): it's propagated
    /// immediately, with `retry_after` forwarded, rather than retried
    /// inside this provider.
    ///
    /// 401/403 is checked by status code *before* any body-marker
    /// inspection, deliberately: a response coincidentally containing e.g.
    /// `"MONTHLY_REQUEST_COUNT"` in its body alongside a 401 status is
    /// still, unambiguously, an auth failure first.
    pub retryable: bool,
    /// True specifically for `INSUFFICIENT_MODEL_CAPACITY`. Task 15 tracks
    /// this against its own dedicated capacity-retry budget, distinct from
    /// the generic `retryable` budget.
    pub capacity_error: bool,
    /// Forwarded verbatim from the upstream `Retry-After` response header,
    /// when present.
    pub retry_after: Option<String>,
}

/// A response received (status + headers already read) but whose body has
/// not been consumed yet. `next_chunk` is the only way to drive the read;
/// Task 15 owns that loop.
#[derive(Debug)]
pub struct KiroStreamResponse {
    inner: reqwest::Response,
}

#[derive(Debug)]
pub enum ChunkOutcome {
    Bytes(Bytes),
    TimedOut,
    EndOfStream,
    Error(anyhow::Error),
}

impl KiroStreamResponse {
    /// Waits up to `timeout` for the next body chunk. `reqwest::Response::chunk()`
    /// is the async incremental-read primitive (distinct from `.bytes()`,
    /// which awaits the *entire* body) — this is what lets Task 15 apply an
    /// idle-timeout per chunk rather than one timeout for the whole stream.
    pub async fn next_chunk(&mut self, timeout: Duration) -> ChunkOutcome {
        match tokio::time::timeout(timeout, self.inner.chunk()).await {
            Ok(Ok(Some(bytes))) => ChunkOutcome::Bytes(bytes),
            Ok(Ok(None)) => ChunkOutcome::EndOfStream,
            Ok(Err(e)) => ChunkOutcome::Error(e.into()),
            Err(_elapsed) => ChunkOutcome::TimedOut,
        }
    }
}

pub struct KiroHttpClient {
    client: reqwest::Client,
    /// `Arc`-wrapped purely so `spawn_blocking` (see module docs) can take
    /// an owned, `'static` handle to call the synchronous `get_auth`/
    /// `force_refresh` on without needing `KiroAuthManager` itself to be
    /// `Clone`. This has no bearing on the "exactly one instance for the
    /// life of the process" requirement (Adversarial Review Findings #13):
    /// the manager's in-memory cache and singleflight lock live *inside*
    /// the `KiroAuthManager` this `Arc` points at, so as long as exactly one
    /// `KiroHttpClient` (and therefore exactly one underlying manager) is
    /// constructed, every clone of the `Arc` shares that same state.
    auth_manager: Arc<KiroAuthManager<FileAuthStore<KiroCredentials>>>,
}

impl Default for KiroHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl KiroHttpClient {
    pub fn new() -> Self {
        Self::from_parts(
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .build()
                .expect("failed to create Kiro HTTP client"),
            KiroAuthManager::new(file_store()),
        )
    }

    fn from_parts(
        client: reqwest::Client,
        auth_manager: KiroAuthManager<FileAuthStore<KiroCredentials>>,
    ) -> Self {
        Self {
            client,
            auth_manager: Arc::new(auth_manager),
        }
    }

    /// Test-only seam: builds a client around a caller-supplied auth
    /// manager (e.g. one backed by a temp-dir `FileAuthStore`) instead of
    /// `KiroHttpClient::new()`'s hardcoded real-filesystem `file_store()`,
    /// so unit tests never touch the real `~/.config/claude-code-proxy`
    /// paths.
    #[cfg(test)]
    pub(crate) fn for_test(auth_manager: KiroAuthManager<FileAuthStore<KiroCredentials>>) -> Self {
        Self::from_parts(reqwest::Client::new(), auth_manager)
    }

    pub fn auth_manager(&self) -> &KiroAuthManager<FileAuthStore<KiroCredentials>> {
        &self.auth_manager
    }

    /// Owned, `'static` handle to the same auth manager `auth_manager()`
    /// borrows. Task 15's retry loop needs to call the manager's
    /// *synchronous* `get_auth`/`force_refresh` from async code, which means
    /// handing them to `tokio::task::spawn_blocking` — that requires an
    /// owned `'static` value, which a plain `&KiroAuthManager` can't
    /// provide. Cloning the `Arc` shares the exact same cache/singleflight
    /// state (see the `auth_manager` field's doc comment), so this is not a
    /// second manager instance.
    pub fn auth_manager_handle(&self) -> Arc<KiroAuthManager<FileAuthStore<KiroCredentials>>> {
        Arc::clone(&self.auth_manager)
    }

    /// Single-attempt POST to `AmazonCodeWhispererStreamingService.GenerateAssistantResponse`.
    /// Returns the still-unread response on any 2xx; classifies everything
    /// else into a [`KiroError`] without retrying. `endpoint` and `body` are
    /// supplied by the caller (Task 15 builds the endpoint from the
    /// resolved API region; Task 14 builds `body`).
    pub async fn post_generate_assistant_response(
        &self,
        endpoint: &str,
        body: &impl Serialize,
    ) -> Result<KiroStreamResponse, KiroError> {
        let creds = self.get_auth_blocking().await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-amz-json-1.0"),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            auth_header_value(&creds.access).map_err(invalid_credentials_error)?,
        );
        headers.insert(
            "X-Amz-Target",
            HeaderValue::from_static(
                "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
            ),
        );
        headers.insert(
            "x-amzn-codewhisperer-optout",
            HeaderValue::from_static("true"),
        );
        headers.insert(
            "amz-sdk-invocation-id",
            // Freshly generated per HTTP attempt (including capacity-error
            // retries within the same logical request): header construction
            // lives inside this function, so every call to this method
            // naturally gets a new UUID.
            HeaderValue::from_str(&uuid::Uuid::new_v4().to_string())
                .expect("uuid string is always a valid header value"),
        );
        headers.insert(
            "amz-sdk-request",
            HeaderValue::from_static("attempt=1; max=1"),
        );
        headers.insert("x-amzn-kiro-agent-mode", HeaderValue::from_static("vibe"));
        headers.insert(
            "x-amz-user-agent",
            HeaderValue::from_static(PROXY_USER_AGENT),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_static(PROXY_USER_AGENT),
        );

        let resp = match self
            .client
            .post(endpoint)
            .headers(headers)
            .json(body)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(_) => {
                return Err(KiroError {
                    status: 0,
                    message: "Network error".to_string(),
                    body: None,
                    retryable: true,
                    capacity_error: false,
                    retry_after: None,
                });
            }
        };

        let status = resp.status().as_u16();

        if (200..300).contains(&status) {
            return Ok(KiroStreamResponse { inner: resp });
        }

        // 401/403: classify and return immediately. No auto-refresh, no
        // retry — see the module doc comment for why that decision belongs
        // to Task 15 alone. The body is deliberately not read here (unlike
        // the "any other non-2xx" branch below): there's nothing in it this
        // client needs, and reading it would be wasted work on the most
        // latency-sensitive error path.
        if status == 401 || status == 403 {
            return Err(auth_failure_error(status));
        }

        Err(classify_error_response(status, resp).await)
    }

    /// Single-shot `AmazonCodeWhispererService.ListAvailableModels` call.
    /// Reads the full JSON body (unlike the streaming call) since model
    /// discovery isn't a streaming operation. Takes `credentials` directly
    /// rather than going through `self.auth_manager` — callers that already
    /// resolved credentials (e.g. as part of the same request that's about
    /// to call `post_generate_assistant_response`) shouldn't pay for a
    /// second `get_auth` round-trip.
    pub async fn post_list_available_models(
        &self,
        credentials: &KiroCredentials,
    ) -> Result<Value, KiroError> {
        self.post_list_available_models_impl(credentials, None)
            .await
    }

    /// Internal seam for testing: `base_url_override` replaces
    /// `https://q.{api_region}.amazonaws.com` with an arbitrary base (e.g. a
    /// mock server's URL) when present, mirroring the same pattern Task 7's
    /// `model_discovery.rs` already uses for its equivalent call.
    async fn post_list_available_models_impl(
        &self,
        credentials: &KiroCredentials,
        base_url_override: Option<&str>,
    ) -> Result<Value, KiroError> {
        let api_region = resolve_api_region(&credentials.region);
        let base = base_url_override
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://q.{api_region}.amazonaws.com"));
        let url = format!("{base}/?origin=KIRO_CLI");

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-amz-json-1.0"),
        );
        headers.insert(
            AUTHORIZATION,
            auth_header_value(&credentials.access).map_err(invalid_credentials_error)?,
        );
        headers.insert(
            "X-Amz-Target",
            HeaderValue::from_static("AmazonCodeWhispererService.ListAvailableModels"),
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_static(PROXY_USER_AGENT),
        );

        let resp = match self
            .client
            .post(&url)
            .headers(headers)
            .json(&serde_json::json!({"origin": "KIRO_CLI"}))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(_) => {
                return Err(KiroError {
                    status: 0,
                    message: "Network error".to_string(),
                    body: None,
                    retryable: true,
                    capacity_error: false,
                    retry_after: None,
                });
            }
        };

        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            return resp.json::<Value>().await.map_err(|e| KiroError {
                status,
                message: "Failed to parse ListAvailableModels response".to_string(),
                body: Some(e.to_string()),
                retryable: false,
                capacity_error: false,
                retry_after: None,
            });
        }

        // Same 401/403-first precedence as `post_generate_assistant_response`
        // (Adversarial Review, this task's own follow-up round): originally
        // this method routed every non-2xx through `classify_error_response`
        // uniformly, which meant a 401/403 here landed in that function's
        // generic fallback (`retryable: false`) — silently contradicting
        // `KiroError::retryable`'s documented contract that 401/403 is
        // always retryable-after-refresh. Kept consistent across both
        // methods now, even though today's only caller
        // (`model_discovery.rs`, once retrofitted) treats this call as
        // best-effort and may not act on `retryable` either way.
        if status == 401 || status == 403 {
            return Err(auth_failure_error(status));
        }

        Err(classify_error_response(status, resp).await)
    }

    /// Runs the synchronous, blocking `KiroAuthManager::get_auth` on a
    /// blocking-pool thread (see module docs) and maps its failure modes
    /// into a `KiroError`. A missing/invalid stored credential is not
    /// something retrying will fix on its own, so `retryable: false`.
    async fn get_auth_blocking(&self) -> Result<KiroCredentials, KiroError> {
        let manager = Arc::clone(&self.auth_manager);
        match tokio::task::spawn_blocking(move || manager.get_auth()).await {
            Ok(Ok(creds)) => Ok(creds),
            Ok(Err(e)) => Err(KiroError {
                status: 0,
                message: "Auth error".to_string(),
                body: Some(e.to_string()),
                retryable: false,
                capacity_error: false,
                retry_after: None,
            }),
            Err(join_err) => Err(KiroError {
                status: 0,
                message: "Auth task join error".to_string(),
                body: Some(join_err.to_string()),
                retryable: false,
                capacity_error: false,
                retry_after: None,
            }),
        }
    }
}

/// Builds the `Authorization: Bearer {token}` header value. Marked
/// `set_sensitive(true)` so the token never shows up in `HeaderMap`/request
/// `Debug` output (a real risk given this crate's traffic-capture and
/// tracing machinery) and so HTTP/2 doesn't add it to the HPACK dynamic
/// table for indexing. `HeaderValue::from_str` itself already rejects
/// control characters (CR/LF in particular), so a malformed/malicious
/// stored token can't smuggle extra headers via this path — it just fails
/// with `InvalidHeaderValue`, mapped to a non-retryable `KiroError` by the
/// caller.
fn auth_header_value(
    access_token: &str,
) -> Result<HeaderValue, reqwest::header::InvalidHeaderValue> {
    let mut value = HeaderValue::from_str(&format!("Bearer {access_token}"))?;
    value.set_sensitive(true);
    Ok(value)
}

fn invalid_credentials_error(_: reqwest::header::InvalidHeaderValue) -> KiroError {
    KiroError {
        status: 0,
        message: "Stored access token is not a valid HTTP header value".to_string(),
        body: None,
        retryable: false,
        capacity_error: false,
        retry_after: None,
    }
}

/// Shared 401/403 classification for both `post_generate_assistant_response`
/// and `post_list_available_models`: no auto-refresh, no retry, `retryable:
/// true` so a future outer retry loop (Task 15) knows a refresh-and-retry is
/// worth attempting. The body is deliberately not read for this branch in
/// either caller — see `post_generate_assistant_response`'s inline comment.
fn auth_failure_error(status: u16) -> KiroError {
    KiroError {
        status,
        message: format!("Kiro authentication failed ({status})"),
        body: None,
        retryable: true,
        capacity_error: false,
        retry_after: None,
    }
}

/// Shared "any other non-2xx" classification for both
/// `post_generate_assistant_response` and `post_list_available_models`.
/// `resp`'s body is consumed here — callers must have already handled 2xx
/// and (where applicable) 401/403 before reaching this function.
///
/// Priority order (Adversarial Review Findings #14, and the design doc's
/// corrected retry-policy section):
/// 1. `MONTHLY_REQUEST_COUNT` in the body → terminal, non-retryable (quota
///    exhausted for the month; retrying cannot help).
/// 2. `INSUFFICIENT_MODEL_CAPACITY` in the body → retryable, and flagged
///    `capacity_error` so Task 15 can track it against its own dedicated
///    capacity-retry budget rather than a generic one.
/// 3. `413`, or `400` with a context-overflow marker in the body →
///    non-retryable, with a `message` containing the substring `"context
///    window"` (case-insensitive). This matches this codebase's existing
///    convention, not an invented one: `codex/mod.rs::is_context_window_overflow`
///    already does `message.to_ascii_lowercase().contains("context window")`
///    to route Codex's own context-overflow failures to a `413
///    request_too_large` response. Using the same substring here means
///    Task 15/17 can reuse (or trivially mirror) that exact check instead of
///    inventing a second, Kiro-specific convention.
/// 4. Everything else (including plain `429`/`5xx`) → non-retryable *inside
///    this client*, with `retry_after` forwarded so the caller can surface
///    it to the client that made the original request. This is a
///    deliberate departure from a naive "retry all 429/5xx" policy: this
///    codebase's `kimi/mod.rs::map_kimi_error_to_response` already treats
///    429 the same way (propagate with `Retry-After`, don't retry
///    provider-side), and the TS reference does the same
///    (`stream.test.ts:1559`).
async fn classify_error_response(status: u16, resp: reqwest::Response) -> KiroError {
    let retry_after = resp
        .headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body_text = resp.text().await.unwrap_or_default();

    if body_text.contains("MONTHLY_REQUEST_COUNT") {
        return KiroError {
            status,
            message: "Kiro monthly request quota exhausted".to_string(),
            body: Some(body_text),
            retryable: false,
            capacity_error: false,
            retry_after,
        };
    }

    if body_text.contains("INSUFFICIENT_MODEL_CAPACITY") {
        return KiroError {
            status,
            message: "Kiro reported insufficient model capacity".to_string(),
            body: Some(body_text),
            retryable: true,
            capacity_error: true,
            retry_after,
        };
    }

    let is_context_overflow = status == 413
        || (status == 400
            && (body_text.contains("CONTENT_LENGTH_EXCEEDS_THRESHOLD")
                || body_text.contains("Input is too long")
                || body_text.contains("Improperly formed")));
    if is_context_overflow {
        return KiroError {
            status,
            // Deliberately contains "context window" (case-insensitively)
            // to match `codex/mod.rs::is_context_window_overflow`'s existing
            // substring check — see this function's doc comment.
            message: "Kiro request exceeded the model's context window".to_string(),
            body: Some(body_text),
            retryable: false,
            capacity_error: false,
            retry_after,
        };
    }

    KiroError {
        status,
        message: format!("Kiro upstream error: {status}"),
        body: Some(body_text),
        retryable: false,
        capacity_error: false,
        retry_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthStorage, FileAuthStore};
    use crate::providers::codex::auth::test_http;
    use crate::providers::kiro::auth::KiroAuthMethod;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn far_future_creds() -> KiroCredentials {
        KiroCredentials {
            access: "test-access".into(),
            refresh: "test-refresh".into(),
            expires: u64::MAX,
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 0,
        }
    }

    /// Builds a `KiroHttpClient` backed by a temp-dir `FileAuthStore`
    /// pre-populated with a far-future-valid credential, so `get_auth()`
    /// never touches the real `~/.config/claude-code-proxy` paths or the
    /// (non-existent, in these tests) network. Returns the `TempDir`
    /// alongside the client — the caller must keep it alive (bind it, don't
    /// discard it) for as long as the client is used, or the backing file
    /// disappears out from under `get_auth()`'s `store.load()` fallback.
    fn test_client() -> (KiroHttpClient, TempDir) {
        let tmp = TempDir::new().unwrap();
        let primary = tmp.path().join("auth.json");
        let legacy = tmp.path().join("legacy-auth.json");
        let store = FileAuthStore::new(
            primary.to_string_lossy().to_string(),
            legacy.to_string_lossy().to_string(),
        );
        store.save(far_future_creds()).unwrap();
        (KiroHttpClient::for_test(KiroAuthManager::new(store)), tmp)
    }

    // ------------------------------------------------------------------
    // Streaming: happy path + timeout
    // ------------------------------------------------------------------

    /// Spawns a raw TCP server that writes an HTTP/1.1 200 response whose
    /// body arrives in the given `(delay-before-write, bytes)` parts,
    /// flushing after each write. This is deliberately a hand-rolled TCP
    /// server rather than `test_http::spawn_mock_server` (Task 3's shared
    /// helper): that helper's handler returns one complete response string
    /// written in a single `write_all`, which can't model bytes arriving
    /// incrementally with a real gap between them — exactly what these two
    /// tests need to exercise `next_chunk`'s per-call behavior. Mirrors the
    /// same "hand-roll a `TcpListener` for finer control" approach already
    /// used by `codex/auth/manager.rs`'s own tests for a similar reason.
    /// Returns the mock server's URL and a `JoinHandle` for its background
    /// thread. Callers that can afford to wait for the server to finish
    /// writing (i.e. they drain the response to completion) should `.join()`
    /// it, matching `codex/auth/manager.rs`'s own raw-`TcpListener` test
    /// pattern (which always joins) rather than leaving the thread detached.
    /// Callers that intentionally stop reading early (e.g. the timeout test
    /// below, which only needs the *first* 50ms) may drop the handle instead
    /// — `listener.accept()` still only blocks for a single connection, and
    /// the thread exits on its own once that connection's writes finish or
    /// the peer disconnects, well before the test process itself exits.
    fn spawn_chunked_mock_server(
        parts: Vec<(Duration, Vec<u8>)>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = test_http::read_http_request(&mut stream);
                let total_len: usize = parts.iter().map(|(_, bytes)| bytes.len()).sum();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {total_len}\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(header.as_bytes()).is_err() {
                    return;
                }
                let _ = stream.flush();
                for (delay, bytes) in parts {
                    std::thread::sleep(delay);
                    if stream.write_all(&bytes).is_err() {
                        return;
                    }
                    let _ = stream.flush();
                }
            }
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn streaming_post_yields_chunks_incrementally() {
        let (url, server) = spawn_chunked_mock_server(vec![
            (Duration::from_millis(10), b"{\"first\":true}".to_vec()),
            (Duration::from_millis(80), b"{\"second\":true}".to_vec()),
        ]);
        let (client, _tmp) = test_client();

        let mut stream = client
            .post_generate_assistant_response(&url, &serde_json::json!({"hello": "world"}))
            .await
            .expect("mock server returns 200");

        // Accumulate every `Bytes` outcome until `EndOfStream` rather than
        // asserting exact per-call chunk boundaries: TCP has no message
        // boundaries, so exactly how many bytes land in each `.chunk()` call
        // — or even whether the two delayed writes ever surface as two
        // *separate* outcomes, as opposed to one call happening to observe
        // both after they're already buffered — is not a property this
        // client controls or should be tested against (Adversarial Review:
        // an earlier version of this test asserted `bytes_outcomes >= 2`,
        // which is usually true given the write delays below but is not
        // actually guaranteed by TCP/hyper, so it was dropped as a source of
        // rare CI flakiness). What *is* guaranteed, and is what this test
        // asserts: nothing is lost, corrupted, or reordered, and the stream
        // correctly reaches `EndOfStream` once the full `Content-Length` has
        // been delivered. `next_chunk_times_out_when_no_data_arrives_in_time`
        // below is what actually proves bounded, incremental (not
        // wait-for-the-whole-body) delivery.
        let generous_timeout = Duration::from_millis(2000);
        let mut received = Vec::new();
        loop {
            match stream.next_chunk(generous_timeout).await {
                ChunkOutcome::Bytes(b) => received.extend_from_slice(&b),
                ChunkOutcome::EndOfStream => break,
                other => panic!("unexpected outcome while draining stream: {other:?}"),
            }
        }

        assert_eq!(received, b"{\"first\":true}{\"second\":true}");
        server.join().expect("mock server thread should not panic");
    }

    #[tokio::test]
    async fn next_chunk_times_out_when_no_data_arrives_in_time() {
        // The server sends headers immediately (so `send().await` succeeds)
        // but withholds any body bytes until well after the short
        // per-chunk timeout below has elapsed. The server-side delay (2s) is
        // deliberately much larger than the client-side timeout (50ms) to
        // absorb scheduling jitter on a loaded CI box: `next_chunk` returns
        // as soon as its own 50ms elapses regardless of how long the server
        // thread sleeps afterward, so a larger margin here costs nothing at
        // runtime.
        // Deliberately not joined: this test only needs the first 50ms of
        // behavior, and joining would mean waiting out the server's full 2s
        // sleep for no additional signal (see `spawn_chunked_mock_server`'s
        // doc comment for why dropping the handle here is safe).
        let (url, _server) = spawn_chunked_mock_server(vec![(
            Duration::from_secs(2),
            b"{\"too\":\"late\"}".to_vec(),
        )]);
        let (client, _tmp) = test_client();

        let mut stream = client
            .post_generate_assistant_response(&url, &serde_json::json!({}))
            .await
            .expect("mock server returns 200");

        match stream.next_chunk(Duration::from_millis(50)).await {
            ChunkOutcome::TimedOut => {}
            _ => panic!("expected a timeout"),
        }
    }

    // ------------------------------------------------------------------
    // Error classification
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn monthly_request_count_is_non_retryable() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(400, r#"{"reason":"MONTHLY_REQUEST_COUNT"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("400 is not success");

        assert_eq!(err.status, 400);
        assert!(!err.retryable);
        assert!(!err.capacity_error);
    }

    #[tokio::test]
    async fn insufficient_model_capacity_is_retryable_and_flagged() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(500, r#"{"reason":"INSUFFICIENT_MODEL_CAPACITY"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("500 is not success");

        assert_eq!(err.status, 500);
        assert!(err.retryable, "capacity errors must be retryable");
        assert!(err.capacity_error);
    }

    #[tokio::test]
    async fn plain_500_is_non_retryable() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(500, r#"{"error":"internal"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("500 is not success");

        assert_eq!(err.status, 500);
        assert!(
            !err.retryable,
            "generic 5xx must not be retried inside the client/provider (Findings #14)"
        );
        assert!(!err.capacity_error);
    }

    #[tokio::test]
    async fn plain_429_preserves_retry_after_and_is_not_retryable_internally() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 30\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string()
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("429 is not success");

        assert_eq!(err.status, 429);
        assert!(
            !err.retryable,
            "generic 429 must not be retried inside the client/provider (Findings #14)"
        );
        assert_eq!(err.retry_after.as_deref(), Some("30"));
    }

    #[tokio::test]
    async fn status_403_is_retryable_with_no_auto_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |_req| {
            counter.fetch_add(1, Ordering::SeqCst);
            test_http::json_response(403, r#"{"error":"forbidden"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("403 is not success");

        assert_eq!(err.status, 403);
        assert!(err.retryable);
        assert!(!err.capacity_error);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "this client must not attempt any refresh-and-retry on its own"
        );
    }

    #[tokio::test]
    async fn status_401_is_retryable_with_no_auto_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |_req| {
            counter.fetch_add(1, Ordering::SeqCst);
            test_http::json_response(401, r#"{"error":"unauthorized"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("401 is not success");

        assert_eq!(err.status, 401);
        assert!(err.retryable);
        assert!(!err.capacity_error);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "this client must not attempt any refresh-and-retry on its own"
        );
    }

    #[tokio::test]
    async fn status_401_short_circuits_before_any_body_marker_check() {
        // Regression lock (Adversarial Review, this task's own follow-up
        // round): 401/403 is classified by status code *before* any
        // body-marker inspection, by design (see `KiroError::retryable`'s
        // doc comment) — a response that happens to carry a
        // MONTHLY_REQUEST_COUNT-shaped body alongside a 401 status is still,
        // unambiguously, an auth failure, not a non-retryable quota error.
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(401, r#"{"reason":"MONTHLY_REQUEST_COUNT"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("401 is not success");

        assert_eq!(err.status, 401);
        assert!(
            err.retryable,
            "401 must win over any body marker, including MONTHLY_REQUEST_COUNT"
        );
        assert!(!err.capacity_error);
    }

    #[tokio::test]
    async fn context_overflow_body_on_400_is_non_retryable() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(400, r#"{"reason":"CONTENT_LENGTH_EXCEEDS_THRESHOLD"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("400 is not success");

        assert_eq!(err.status, 400);
        assert!(!err.retryable);
        assert!(
            err.message.to_ascii_lowercase().contains("context window"),
            "message must match codex/mod.rs::is_context_window_overflow's existing \
             substring convention so a future context-overflow handler can reuse it, \
             got: {:?}",
            err.message
        );
    }

    #[tokio::test]
    async fn status_413_is_non_retryable_context_overflow() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(413, r#"{"error":"payload too large"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("413 is not success");

        assert_eq!(err.status, 413);
        assert!(!err.retryable);
        assert!(
            err.message.to_ascii_lowercase().contains("context window"),
            "message must match codex/mod.rs::is_context_window_overflow's existing \
             substring convention so a future context-overflow handler can reuse it, \
             got: {:?}",
            err.message
        );
    }

    #[tokio::test]
    async fn monthly_request_count_wins_priority_over_capacity_marker() {
        // Both markers present in the same body: MONTHLY_REQUEST_COUNT must
        // win (priority 1 beats priority 2) — a body that happens to also
        // mention capacity must not be treated as retryable.
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(
                400,
                r#"{"reason":"MONTHLY_REQUEST_COUNT","also":"INSUFFICIENT_MODEL_CAPACITY"}"#,
            )
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("400 is not success");

        assert!(
            !err.retryable,
            "MONTHLY_REQUEST_COUNT must win over INSUFFICIENT_MODEL_CAPACITY"
        );
        assert!(!err.capacity_error);
    }

    #[tokio::test]
    async fn capacity_marker_wins_priority_over_context_overflow_marker() {
        // Both markers present: INSUFFICIENT_MODEL_CAPACITY (priority 2)
        // must win over the context-overflow check (priority 3).
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(
                400,
                r#"{"reason":"INSUFFICIENT_MODEL_CAPACITY","also":"CONTENT_LENGTH_EXCEEDS_THRESHOLD"}"#,
            )
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await
            .expect_err("400 is not success");

        assert!(
            err.capacity_error,
            "INSUFFICIENT_MODEL_CAPACITY must win over the context-overflow marker"
        );
        assert!(err.retryable);
    }

    // ------------------------------------------------------------------
    // Headers on the wire
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn sends_expected_streaming_headers() {
        let requests_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = requests_seen.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |req| {
            seen.lock().unwrap().push(req.to_string());
            test_http::json_response(200, r#"{}"#)
        });
        let (client, _tmp) = test_client();

        let _ = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await;

        let requests = requests_seen.lock().unwrap();
        let req = requests.first().expect("one request should have been sent");
        assert!(req.contains("content-type: application/x-amz-json-1.0"));
        assert!(req.contains("accept: application/json"));
        assert!(req.contains("authorization: Bearer test-access"));
        assert!(req.contains(
            "x-amz-target: AmazonCodeWhispererStreamingService.GenerateAssistantResponse"
        ));
        assert!(req.contains("x-amzn-codewhisperer-optout: true"));
        assert!(req.contains("amz-sdk-request: attempt=1; max=1"));
        assert!(req.contains("x-amzn-kiro-agent-mode: vibe"));
        assert!(req.contains("amz-sdk-invocation-id:"));
        assert!(req.contains(&format!("x-amz-user-agent: {PROXY_USER_AGENT}")));
        assert!(req.contains(&format!("user-agent: {PROXY_USER_AGENT}")));
    }

    /// Adversarial Review note (this task's own): the design notes require a
    /// fresh UUID *per HTTP attempt*, including capacity-error retries of
    /// the same logical request — Task 15 is expected to call
    /// `post_generate_assistant_response` again per retry and rely on this
    /// function generating a new one each time, since header construction
    /// lives entirely inside this function.
    #[tokio::test]
    async fn invocation_id_is_fresh_on_every_call() {
        let requests_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = requests_seen.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |req| {
            seen.lock().unwrap().push(req.to_string());
            test_http::json_response(200, r#"{}"#)
        });
        let (client, _tmp) = test_client();

        let _ = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await;
        let _ = client
            .post_generate_assistant_response(&server.url, &serde_json::json!({}))
            .await;

        let requests = requests_seen.lock().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "both calls should have reached the server"
        );
        let first_id = extract_header(&requests[0], "amz-sdk-invocation-id")
            .expect("first request should carry an invocation id");
        let second_id = extract_header(&requests[1], "amz-sdk-invocation-id")
            .expect("second request should carry an invocation id");
        assert_ne!(
            first_id, second_id,
            "each HTTP attempt must get its own fresh UUID"
        );
    }

    /// Pulls a single header's value out of a raw HTTP request string
    /// (as captured by `test_http::spawn_mock_server`'s handler), matching
    /// case-insensitively on the header name the way real HTTP does.
    fn extract_header(request: &str, name: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    // ------------------------------------------------------------------
    // Auth-manager wiring
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn get_auth_failure_is_non_retryable() {
        let tmp = TempDir::new().unwrap();
        let primary = tmp.path().join("auth.json");
        let legacy = tmp.path().join("legacy-auth.json");
        let store = FileAuthStore::new(
            primary.to_string_lossy().to_string(),
            legacy.to_string_lossy().to_string(),
        );
        let client = KiroHttpClient::for_test(KiroAuthManager::new(store));

        let err = client
            .post_generate_assistant_response("http://127.0.0.1:1", &serde_json::json!({}))
            .await
            .expect_err("no stored credentials");

        assert!(!err.retryable);
        assert_eq!(err.message, "Auth error");
    }

    // ------------------------------------------------------------------
    // post_list_available_models
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn list_available_models_sends_expected_wire_format_and_parses_body() {
        let requests_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = requests_seen.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |req| {
            seen.lock().unwrap().push(req.to_string());
            test_http::json_response(200, r#"{"models":[{"modelId":"m"}]}"#)
        });
        let (client, _tmp) = test_client();

        let value = client
            .post_list_available_models_impl(&far_future_creds(), Some(&server.url))
            .await
            .expect("mock server returns 200");

        assert_eq!(value["models"][0]["modelId"], "m");

        let requests = requests_seen.lock().unwrap();
        let req = requests.first().expect("one request should have been sent");
        assert!(req.starts_with("POST /?origin=KIRO_CLI"));
        assert!(req.contains("x-amz-target: AmazonCodeWhispererService.ListAvailableModels"));
        assert!(req.contains("authorization: Bearer test-access"));
    }

    #[tokio::test]
    async fn list_available_models_classifies_non_2xx() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(500, r#"{"error":"boom"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_list_available_models_impl(&far_future_creds(), Some(&server.url))
            .await
            .expect_err("500 is not success");

        assert_eq!(err.status, 500);
        assert!(!err.retryable);
    }

    #[tokio::test]
    async fn list_available_models_401_is_retryable_with_no_auto_refresh() {
        // Regression lock (Adversarial Review, this task's own follow-up
        // round): this method must classify 401/403 the same way as
        // `post_generate_assistant_response` (`retryable: true`, no second
        // attempt) rather than falling through to `classify_error_response`'s
        // generic non-retryable fallback.
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |_req| {
            counter.fetch_add(1, Ordering::SeqCst);
            test_http::json_response(401, r#"{"error":"unauthorized"}"#)
        });
        let (client, _tmp) = test_client();

        let err = client
            .post_list_available_models_impl(&far_future_creds(), Some(&server.url))
            .await
            .expect_err("401 is not success");

        assert_eq!(err.status, 401);
        assert!(err.retryable);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
