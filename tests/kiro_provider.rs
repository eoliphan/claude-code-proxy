//! Acceptance-level integration coverage for the Kiro provider (Task 18 of
//! the Kiro provider plan): black-box HTTP tests through the real axum
//! `Router`, CLI-level tests through the compiled binary (`assert_cmd`), and
//! a black-box regression proof for Task 8's alias-collision routing fix.
//!
//! Tasks 1-17 already have exhaustive crate-internal coverage (see
//! `src/providers/kiro/mod.rs`'s own `#[cfg(test)]` module, which drives
//! `KiroProvider::handle_messages_with` against a hand-rolled mock backend
//! via the private `KiroRuntime.base_url_override` seam) for the full
//! `MessagesRequest -> KiroRequest -> mock backend -> KiroStreamEvent -> SSE`
//! round trip, including request-body shape on the wire. That seam is
//! deliberately not `pub`: `KiroRuntime`, `handle_messages_with`, and
//! `run_kiro_stream_with_base_url`'s siblings are private or `pub(crate)`,
//! so this top-level integration test -- a separate crate that only sees
//! `claude_code_proxy`'s public API -- cannot reach it. Unlike Codex/Kimi,
//! Kiro's production runtime (`KiroRuntime::production()`) has no
//! `CCP_KIRO_BASE_URL`-style env override wired into it, so there is
//! currently no way to redirect a *production* `Provider::handle_messages`
//! call at a mock backend from outside the crate.
//!
//! Adding that seam (mirroring `config::codex_base_url()`/`kimi_base_url()`
//! and `CCP_CODEX_BASE_URL`/`CCP_KIMI_BASE_URL`) would close this gap and
//! is the natural next step if a future task wants the same
//! `smoke_cutover.rs`-style mocked-upstream black-box test Codex/Kimi
//! already have. This task's brief is explicit that it "doesn't introduce
//! new production code", so that seam is deliberately *not* added here;
//! it is called out as a follow-up for the plan owner to decide on,
//! documented at each point below where it limits what this file can
//! prove. What *is* provable at the true black-box HTTP level without that
//! seam -- registry routing to the real (non-placeholder) `KiroProvider`,
//! local-only request handling (`count_tokens`, unknown-model rejection),
//! the CLI surface, and the alias-collision regression -- is covered here.
//!
//! ## Hermeticity
//!
//! Every in-process test that reaches `KiroProvider::handle_messages`/
//! `handle_count_tokens` is designed to *never* call
//! `KiroAuthManager::get_auth()` (only the cheap, read-only
//! `store.load()` used by the local model-availability gate), which means
//! none of them can ever reach `KiroAuthManager::adopt()` -- the only
//! function that writes to the process-global
//! `translate::model_discovery::MODEL_CACHE`. That statement is verified
//! against `src/providers/kiro/mod.rs` directly, not assumed: see the
//! module doc comment on `reject_unavailable_model`. So this file never
//! writes to `MODEL_CACHE["us-east-1"]` or any other real region key --
//! the hazard flagged for this task is discharged by construction, not by
//! convention alone.
//!
//! A second, related process-global hazard applies specifically to Kiro
//! (not Codex/Kimi, whose base URL and config dir are re-read from the
//! environment on every request): `KIRO_HTTP_CLIENT` is a
//! `once_cell::sync::Lazy` static, so `KiroHttpClient::new()` -- and with
//! it, the `FileAuthStore` file paths it resolves from `CCP_CONFIG_DIR`/
//! `HOME` -- runs *once* for the life of this test binary's process, on
//! whichever test first dereferences it. Every test below that touches
//! Kiro's production handlers therefore holds `env_lock()` for its full
//! duration and points `CCP_CONFIG_DIR` at an empty temp dir, so that
//! whichever test wins the race to initialize `KIRO_HTTP_CLIENT` still
//! resolves to a directory with no `kiro/auth.json` in it -- the same
//! "nothing stored" state every other such test also expects. No test in
//! this file ever seeds a real credential into a directory used by an
//! in-process (non-`assert_cmd`) call, so this race can't change any
//! assertion's outcome. `assert_cmd`-based CLI tests are unaffected: each
//! spawns a brand new OS process with its own fresh `KIRO_HTTP_CLIENT`.

use assert_cmd::Command;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use claude_code_proxy::config::AliasProvider;
use claude_code_proxy::monitor::MonitorHandle;
use claude_code_proxy::registry::Registry;
use claude_code_proxy::server::app_with_monitor;
use predicates::str::contains;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, OnceLock};
use tempfile::TempDir;
use tower::util::ServiceExt;

// ---------------------------------------------------------------------------
// Env isolation (mirrors tests/smoke_cutover.rs's ENV_LOCK/EnvGuard exactly)
// ---------------------------------------------------------------------------

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Serialize every env-var-mutating test in this file so none of them ever
/// run concurrently. See the module doc comment: this is also what makes
/// the `KIRO_HTTP_CLIENT` lazy-init race harmless rather than merely rare.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    let m = ENV_LOCK.get_or_init(|| Mutex::new(()));
    match m.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct EnvGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

fn json_body(value: Value) -> Body {
    Body::from(value.to_string())
}

async fn post(app: axum::Router, uri: &str, body: Value) -> Response {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .body(json_body(body))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn json_of(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn messages_request(model: &str) -> Value {
    json!({
        "model": model,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hello"}]
    })
}

fn count_tokens_request(model: &str) -> Value {
    json!({
        "model": model,
        "messages": [{"role": "user", "content": "hello"}]
    })
}

// ---------------------------------------------------------------------------
// Group 1: registry-level, black-box HTTP tests
// ---------------------------------------------------------------------------

/// `count_tokens` is the one Kiro route that is both fully local (no
/// network, no `get_auth()`/`adopt()` -- see the module doc comment) and
/// reachable only through the *real* `KiroProvider`: a `PlaceholderProvider`
/// would answer with 501 `unsupported_provider_error` instead of a real
/// token estimate. A 200 with a positive `input_tokens` here proves the
/// full real HTTP surface -- request parsing, registry routing to the
/// concrete (not placeholder) Kiro provider, and response serialization --
/// is wired correctly end to end.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn kiro_count_tokens_reaches_the_real_provider_through_the_http_surface() {
    let _guard = env_lock();
    let config = TempDir::new().unwrap();
    let _config_env = EnvGuard::set("CCP_CONFIG_DIR", config.path());

    let registry = Registry::new(AliasProvider::Codex);
    let app = app_with_monitor(Arc::new(registry), None);
    let response = post(
        app,
        "/v1/messages/count_tokens",
        count_tokens_request("kiro:claude-sonnet-4-6"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_of(response).await;
    assert!(
        body["input_tokens"].as_u64().unwrap_or(0) > 0,
        "expected a positive local token estimate, got {body}"
    );
}

/// The `/v1/messages` counterpart of the test above, using an unknown model
/// id specifically so the request is rejected locally by
/// `reject_unavailable_model` -- no network call, no `MODEL_CACHE` write --
/// while still exercising the real HTTP surface for the streaming route
/// (not just `count_tokens`). Mirrors
/// `unknown_model_is_rejected_locally_without_any_upstream_call` from
/// `src/providers/kiro/mod.rs`'s own test module, but through the real
/// axum `Router` rather than calling `handle_messages_with` directly.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn kiro_unknown_model_is_rejected_locally_through_the_http_surface() {
    let _guard = env_lock();
    let config = TempDir::new().unwrap();
    let _config_env = EnvGuard::set("CCP_CONFIG_DIR", config.path());

    let registry = Registry::new(AliasProvider::Codex);
    let app = app_with_monitor(Arc::new(registry), None);
    let response = post(
        app,
        "/v1/messages",
        messages_request("kiro:not-a-real-model"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_of(response).await;
    assert_eq!(body["error"]["type"], "invalid_request_error");
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("not-a-real-model"),
        "expected the raw model id in the rejection message, got {message:?}"
    );
}

/// `/v1/models` is served from `Registry::all_supported_models()`, a static,
/// region-blind, pre-auth snapshot (see Task 17's review notes) -- it never
/// touches `MODEL_CACHE`/the auth store, so this needs no env isolation.
/// `deepseek-3-2` is a real Kiro-only model id used elsewhere in this
/// codebase's own registry tests as a bare (unprefixed) id that still
/// routes to kiro without colliding with any alias.
#[tokio::test]
async fn models_endpoint_lists_a_kiro_model() {
    let app = claude_code_proxy::server::app(Arc::new(Registry::with_default_alias()));
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/models?limit=1000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_of(response).await;
    let ids: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&"deepseek-3-2"),
        "expected a kiro-only model id in /v1/models, got {ids:?}"
    );
}

// ---------------------------------------------------------------------------
// Group 2: CLI-level tests (assert_cmd spawns a fresh process per call, so
// no ENV_LOCK/MODEL_CACHE interaction is possible here at all).
// ---------------------------------------------------------------------------

fn kiro_credentials_fixture() -> Value {
    // Deliberately the minimal shape -- `expiry_buffer_ms` is
    // `#[serde(default)]` and `client_id`/`client_secret`/`profile_arn` are
    // all `skip_serializing_if` on write, matching how a real persisted
    // credential with none of the optional fields set would look on disk
    // (see `KiroCredentials`'s own
    // `expiry_buffer_ms_defaults_to_zero_for_pre_existing_persisted_json`
    // unit test for the same minimal shape).
    json!({
        "access": "kiro-test-access",
        "refresh": "kiro-test-refresh",
        "expires": 4102444800000u64,
        "region": "us-east-1",
        "auth_method": "idc"
    })
}

/// Exercises the binary-level `kiro auth status`/`kiro auth logout` CLI
/// surface (not `CliHandlers` called in isolation) across the full
/// pre-login -> fixture-seeded -> post-logout lifecycle, matching
/// `tests/cli.rs::kimi_auth_status_reads_stored_auth`'s established
/// convention for isolating credential state via `CCP_CONFIG_DIR`.
#[test]
fn kiro_auth_cli_lifecycle_status_and_logout() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;

    // Before any login: `status` must fail with exit code 1 (matching
    // `run_provider_cli`'s `"Not authenticated"` special-case) and print
    // "Not authenticated" to stdout.
    let mut status_before = Command::cargo_bin("claude-code-proxy")?;
    status_before.args(["kiro", "auth", "status"]);
    status_before.env("CCP_CONFIG_DIR", temp.path());
    status_before
        .assert()
        .failure()
        .code(1)
        .stdout(contains("Not authenticated"));

    // Seed a fixture credential exactly where `kiro auth status`'s
    // `FileAuthStore` (via `CCP_CONFIG_DIR`) will look for it.
    let auth_dir = temp.path().join("kiro");
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::write(
        auth_dir.join("auth.json"),
        serde_json::to_vec(&kiro_credentials_fixture())?,
    )?;

    let mut status_after = Command::cargo_bin("claude-code-proxy")?;
    status_after.args(["kiro", "auth", "status"]);
    status_after.env("CCP_CONFIG_DIR", temp.path());
    status_after
        .assert()
        .success()
        .stdout(contains("Authenticated: true"))
        .stdout(contains("Region: us-east-1"))
        .stdout(contains("Method: Idc"));

    let mut logout = Command::cargo_bin("claude-code-proxy")?;
    logout.args(["kiro", "auth", "logout"]);
    logout.env("CCP_CONFIG_DIR", temp.path());
    logout.assert().success().stdout(contains("Logged out"));

    // After logout the credential file is gone, so status must fail again.
    let mut status_final = Command::cargo_bin("claude-code-proxy")?;
    status_final.args(["kiro", "auth", "status"]);
    status_final.env("CCP_CONFIG_DIR", temp.path());
    status_final
        .assert()
        .failure()
        .code(1)
        .stdout(contains("Not authenticated"));

    Ok(())
}

/// `kiro auth logout` with nothing stored must still succeed (mirrors
/// `tests/cli.rs::provider_logout_without_auth_is_success`, which covers
/// this for kimi).
#[test]
fn kiro_auth_logout_without_prior_login_is_success() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let mut cmd = Command::cargo_bin("claude-code-proxy")?;
    cmd.args(["kiro", "auth", "logout"]);
    cmd.env("CCP_CONFIG_DIR", temp.path());
    cmd.assert().success();
    Ok(())
}

/// Regression lock for the CLI wiring gap this task surfaced: `kiro` was
/// missing from `main.rs`'s `Commands` enum entirely (no `Commands::Kiro`
/// variant, and `print_models`'s provider loop didn't include `"kiro"`),
/// which meant `kiro auth status`/`logout` were not valid subcommands at
/// all and `claude-code-proxy models` never listed kiro models -- silently,
/// since every other provider's CLI wiring worked and this proxy has no
/// exhaustiveness check tying `Registry`'s provider set to `main.rs`'s
/// `Commands` enum. Fixed forward in `src/main.rs` as part of this task,
/// per the brief's explicit instruction to fix wiring bugs this
/// acceptance-level test surfaces rather than working around them.
#[test]
fn models_cli_lists_kiro() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("claude-code-proxy")?;
    cmd.arg("models");
    let out = String::from_utf8(cmd.output()?.stdout)?;
    assert!(out.contains("kiro:"), "models output: {out}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Group 3: regression proof for Task 8's alias-collision routing fix, at
// the black-box HTTP level (the existing unit-level test is
// `registry.rs::kiro_prefix_routes_to_kiro_even_when_id_collides_with_an_alias`).
// ---------------------------------------------------------------------------

/// `"claude-sonnet-4-6"` is simultaneously a real Kiro model id and an
/// `ANTHROPIC_STYLE_ALIASES` entry. With the alias provider configured as
/// Codex, the *unprefixed* id must route to codex (existing alias-routing
/// behavior, unchanged) while the `kiro:`-prefixed id must route to kiro
/// regardless -- the exact bug Task 8 fixed, and the design doc's stated
/// reason for this whole plan existing. Both requests go through the real
/// axum `Router`/`Registry`, using `MonitorHandle` (as
/// `tests/server.rs::monitor_records_successful_request_events` already
/// does for codex) as the observable proof of which provider actually
/// handled each request, since neither response body alone identifies the
/// backend.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn alias_collision_black_box_kiro_prefix_wins_bare_id_stays_on_alias_provider() {
    let _guard = env_lock();
    let config = TempDir::new().unwrap();
    let _config_env = EnvGuard::set("CCP_CONFIG_DIR", config.path());

    // `Registry::new(AliasProvider::Codex)` explicitly, not
    // `with_default_alias()` -- the latter reads ambient config/env and
    // would make this collision assertion depend on the developer's box.
    let kiro_monitor = MonitorHandle::new(10);
    let kiro_app = app_with_monitor(
        Arc::new(Registry::new(AliasProvider::Codex)),
        Some(kiro_monitor.clone()),
    );
    let kiro_response = post(
        kiro_app,
        "/v1/messages/count_tokens",
        count_tokens_request("kiro:claude-sonnet-4-6"),
    )
    .await;
    assert_eq!(kiro_response.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(kiro_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let kiro_state = kiro_monitor.snapshot();
    assert_eq!(
        kiro_state.recent.first().and_then(|r| r.provider.clone()),
        Some("kiro".to_string()),
        "kiro:-prefixed request must be handled by the kiro provider"
    );

    let codex_monitor = MonitorHandle::new(10);
    let codex_app = app_with_monitor(
        Arc::new(Registry::new(AliasProvider::Codex)),
        Some(codex_monitor.clone()),
    );
    let codex_response = post(
        codex_app,
        "/v1/messages/count_tokens",
        count_tokens_request("claude-sonnet-4-6"),
    )
    .await;
    assert_eq!(codex_response.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(codex_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let codex_state = codex_monitor.snapshot();
    assert_eq!(
        codex_state.recent.first().and_then(|r| r.provider.clone()),
        Some("codex".to_string()),
        "the same bare, unprefixed id must still route via alias resolution to codex"
    );
}

/// Same collision, with kiro itself configured as the alias provider: the
/// bare id must now resolve to kiro too, and the prefixed id must agree.
/// This is the mirror image of Task 8's
/// `registry.rs::kiro_as_alias_provider_routes_bare_aliases_to_kiro` unit
/// test, again proven through the real HTTP surface rather than
/// `provider_for_model` directly.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn alias_collision_black_box_kiro_as_alias_provider_routes_bare_id_to_kiro_too() {
    let _guard = env_lock();
    let config = TempDir::new().unwrap();
    let _config_env = EnvGuard::set("CCP_CONFIG_DIR", config.path());

    let monitor = MonitorHandle::new(10);
    let app = app_with_monitor(
        Arc::new(Registry::new(AliasProvider::Kiro)),
        Some(monitor.clone()),
    );
    let response = post(
        app,
        "/v1/messages/count_tokens",
        count_tokens_request("claude-sonnet-4-6"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let state = monitor.snapshot();
    assert_eq!(
        state.recent.first().and_then(|r| r.provider.clone()),
        Some("kiro".to_string()),
        "with kiro as the alias provider, the bare colliding id must also route to kiro"
    );
}
