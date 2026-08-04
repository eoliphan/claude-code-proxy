//! Dynamic model discovery (`ListAvailableModels`) and profile-ARN
//! resolution (`ListAvailableProfiles`) against Kiro's backend, plus two
//! small in-memory caches and a single wiring entry point that keeps them
//! fresh after every successful credential refresh.
//!
//! Endpoint/body/header shapes were verified directly against the
//! `pi-provider-kiro` reference (`src/api.ts` for `ListAvailableModels`,
//! `src/stream.ts::resolveProfileArn` for `ListAvailableProfiles`) rather
//! than assumed from summarized research:
//!
//! - `ListAvailableModels`: `POST https://q.{api_region}.amazonaws.com/?origin=KIRO_CLI`,
//!   body `{"origin":"KIRO_CLI"}`, response `{defaultModel?, models: KiroModel[]}`.
//! - `ListAvailableProfiles`: `POST https://q.{api_region}.amazonaws.com/`
//!   (the streaming endpoint's host with its `/generateAssistantResponse`
//!   path segment and query string stripped, per `stream.ts`), body `{}`
//!   (not `{"origin":"KIRO_CLI"}` — the reference does not reuse
//!   `api.ts`'s `postOperation` helper for this call), response
//!   `{profiles?: Array<{arn?: string}>}`. The reference does not set a
//!   custom `User-Agent` on this specific call (unlike `ListAvailableModels`
//!   and unlike this module's other calls); this proxy sends its own
//!   `User-Agent` on both calls anyway for consistent backend observability
//!   — a deliberate, harmless deviation from the reference, not an
//!   oversight.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use serde::Deserialize;

use crate::providers::kiro::auth::KiroCredentials;

use super::models::{KIRO_MODELS, dot_to_dash, models_for_region, resolve_api_region};

/// User-Agent this proxy sends on Kiro metadata calls — this proxy's own
/// identity, not `pi-provider-kiro`'s (which sends `"pi-provider-kiro"`).
const USER_AGENT: &str = "claude-code-proxy";

/// A model discovered via `ListAvailableModels`, mapped to this proxy's
/// dash-form ID and filled in from [`KIRO_MODELS`] template metadata where
/// the API response omits a field.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredModel {
    pub id: String,
    pub name: String,
    pub reasoning: bool,
    pub input_image: bool,
    pub context_window: u64,
    pub max_tokens: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenLimits {
    #[serde(default)]
    max_input_tokens: Option<u64>,
    #[serde(default)]
    max_output_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KiroModelResponse {
    model_id: String,
    #[serde(default)]
    model_name: Option<String>,
    #[serde(default)]
    token_limits: Option<TokenLimits>,
    #[serde(default)]
    supported_input_types: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ListAvailableModelsResponse {
    // Required, not `#[serde(default)]`: the TS reference does
    // `response.models.map(...)` unguarded, so a response that omits
    // `models` entirely is a malformed response, not a legitimate empty
    // catalog — it should fail deserialization rather than silently
    // resolve to an empty `Vec`.
    models: Vec<KiroModelResponse>,
}

#[derive(Debug, Deserialize)]
struct KiroProfile {
    #[serde(default)]
    arn: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListAvailableProfilesResponse {
    #[serde(default)]
    profiles: Vec<KiroProfile>,
}

fn default_base_url(api_region: &str) -> String {
    format!("https://q.{api_region}.amazonaws.com")
}

/// Shared client for both metadata calls in this module. These are
/// best-effort, off-the-hot-path calls (per the design notes: reuse Task
/// 13's async client if convenient, otherwise a fresh one is fine) — a
/// single lazily-built client is used here both to amortize connection
/// setup across the two calls `refresh_cache_for_credentials` makes back to
/// back, and, more importantly, to guarantee a bounded request timeout: a
/// `tokio::spawn`ed "best-effort, never blocks the caller" refresh (per
/// Task 5's design notes) must not be able to hang forever against a
/// degraded or unreachable backend.
static HTTP_CLIENT: once_cell::sync::Lazy<reqwest::Client> = once_cell::sync::Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// The streaming endpoint URL for a resolved API region — this is the cache
/// key [`ProfileCache`] uses, matching `pi-provider-kiro`'s
/// `profileArnCache: Map<string, string>` keyed by the endpoint used for
/// `GenerateAssistantResponse`.
pub fn streaming_endpoint(api_region: &str) -> String {
    format!("{}/generateAssistantResponse", default_base_url(api_region))
}

/// Maps a single `ListAvailableModels` response entry to a [`DiscoveredModel`],
/// filling in `reasoning` / `input_image` / `context_window` / `max_tokens`
/// from the matching [`KIRO_MODELS`] template entry (by dash-form ID) when
/// the API response omits them, falling back to `false` / `false` /
/// `200_000` / `64_000` when there's no template match at all. Note the
/// `64_000` no-template `max_tokens` default is deliberately distinct from
/// the static catalog's own `65_536` used by some entries — this mirrors a
/// literal discrepancy in the TS reference's `mapKiroModel`, not a bug.
fn map_model(model: &KiroModelResponse) -> DiscoveredModel {
    let id = dot_to_dash(&model.model_id);
    let template = KIRO_MODELS.iter().find(|m| m.id == id.as_str());

    let name = model
        .model_name
        .clone()
        .unwrap_or_else(|| model.model_id.clone());

    let reasoning = template.map(|t| t.reasoning).unwrap_or(false);

    let input_image = model
        .supported_input_types
        .as_ref()
        .map(|types| types.iter().any(|t| t == "IMAGE"))
        .unwrap_or_else(|| template.map(|t| t.input_image).unwrap_or(false));

    let context_window = model
        .token_limits
        .as_ref()
        .and_then(|t| t.max_input_tokens)
        .unwrap_or_else(|| template.map(|t| t.context_window).unwrap_or(200_000));

    let max_tokens = model
        .token_limits
        .as_ref()
        .and_then(|t| t.max_output_tokens)
        .unwrap_or_else(|| template.map(|t| t.max_tokens).unwrap_or(64_000));

    DiscoveredModel {
        id,
        name,
        reasoning,
        input_image,
        context_window,
        max_tokens,
    }
}

/// Internal seam for testing: `base_url_override` replaces
/// `https://q.{api_region}.amazonaws.com` with an arbitrary base (e.g. a
/// mock server's URL) when present.
async fn fetch_available_models_impl(
    credentials: &KiroCredentials,
    base_url_override: Option<&str>,
) -> Result<Vec<DiscoveredModel>, anyhow::Error> {
    let api_region = resolve_api_region(&credentials.region);
    let base = base_url_override
        .map(str::to_string)
        .unwrap_or_else(|| default_base_url(&api_region));
    let url = format!("{base}/?origin=KIRO_CLI");

    let resp = HTTP_CLIENT
        .post(&url)
        .header("Content-Type", "application/x-amz-json-1.0")
        .header("User-Agent", USER_AGENT)
        .header("Authorization", format!("Bearer {}", credentials.access))
        .header(
            "X-Amz-Target",
            "AmazonCodeWhispererService.ListAvailableModels",
        )
        .json(&serde_json::json!({"origin": "KIRO_CLI"}))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "ListAvailableModels failed with status {}",
            resp.status()
        ));
    }

    let parsed: ListAvailableModelsResponse = resp.json().await?;
    Ok(parsed.models.iter().map(map_model).collect())
}

/// Fetches the live model catalog for `credentials`'s resolved API region
/// via `ListAvailableModels`.
pub async fn fetch_available_models(
    credentials: &KiroCredentials,
) -> Result<Vec<DiscoveredModel>, anyhow::Error> {
    fetch_available_models_impl(credentials, None).await
}

/// Internal seam for testing, mirroring [`fetch_available_models_impl`].
async fn fetch_available_profile_arn_impl(
    credentials: &KiroCredentials,
    base_url_override: Option<&str>,
) -> Result<Option<String>, anyhow::Error> {
    if let Some(arn) = &credentials.profile_arn {
        return Ok(Some(arn.clone()));
    }

    let api_region = resolve_api_region(&credentials.region);
    let base = base_url_override
        .map(str::to_string)
        .unwrap_or_else(|| default_base_url(&api_region));
    let url = format!("{base}/");

    let resp = HTTP_CLIENT
        .post(&url)
        .header("Content-Type", "application/x-amz-json-1.0")
        .header("User-Agent", USER_AGENT)
        .header("Authorization", format!("Bearer {}", credentials.access))
        .header(
            "X-Amz-Target",
            "AmazonCodeWhispererService.ListAvailableProfiles",
        )
        .json(&serde_json::json!({}))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "ListAvailableProfiles failed with status {}",
            resp.status()
        ));
    }

    let parsed: ListAvailableProfilesResponse = resp.json().await?;
    // Mirrors the TS reference's `j.profiles?.find((p) => p.arn)?.arn`
    // exactly: the first profile *that has a non-null `arn`*, not
    // unconditionally `profiles[0].arn` — a profile entry with a null/absent
    // `arn` is skipped rather than treated as "no ARN available at all".
    Ok(parsed.profiles.into_iter().find_map(|p| p.arn))
}

/// Resolves a `profileArn` for `credentials`: returns it immediately
/// (without a network call) if already populated (e.g. from a kiro-cli-reused
/// credential), otherwise calls `ListAvailableProfiles` and returns the ARN
/// of the first profile that has one. Returns `Ok(None)` — not an error —
/// when the account has no profiles at all (some Builder ID accounts
/// legitimately don't need one); callers must treat `None` as "omit
/// `profileArn` from the request".
///
/// `Err` is reserved for actual resolution failures (non-2xx status,
/// transport error, unparseable body) — unlike the TS reference, which
/// swallows every failure mode into `undefined` and proceeds without a
/// `profileArn`. Callers that want that same best-effort behavior (Task 15's
/// request path in particular) must treat `Err` here the same way they'd
/// treat `Ok(None)` — "profile resolution unavailable, omit `profileArn` and
/// proceed" — not as a reason to fail the in-flight user request. Only
/// [`refresh_cache_for_credentials`] does this automatically today, by
/// discarding the `Err` case entirely.
pub async fn fetch_available_profile_arn(
    credentials: &KiroCredentials,
) -> Result<Option<String>, anyhow::Error> {
    fetch_available_profile_arn_impl(credentials, None).await
}

/// Caches [`DiscoveredModel`]s per resolved API region.
pub struct ModelCache {
    inner: Arc<RwLock<HashMap<String, Vec<DiscoveredModel>>>>,
}

impl ModelCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get(&self, api_region: &str) -> Option<Vec<DiscoveredModel>> {
        self.inner.read().unwrap().get(api_region).cloned()
    }

    pub fn set(&self, api_region: &str, models: Vec<DiscoveredModel>) {
        self.inner
            .write()
            .unwrap()
            .insert(api_region.to_string(), models);
    }

    /// Dash-form model IDs cached for `api_region`, falling back to
    /// [`models_for_region`] (Task 6's region-filtered static list) only
    /// when *nothing at all* has been cached yet for that region (no `set()`
    /// call has happened). This is what makes `supported_models()` work
    /// correctly before the first successful discovery call.
    ///
    /// Deliberately does **not** fall back when a prior `set()` cached an
    /// authoritative empty list — if `ListAvailableModels` genuinely
    /// reported zero models for this region, that's real backend state, not
    /// "discovery hasn't run yet"; silently substituting the static catalog
    /// in that case would make `contains_id` accept models the backend just
    /// said aren't available.
    pub fn model_ids(&self, api_region: &str) -> Vec<String> {
        match self.get(api_region) {
            Some(models) => models.into_iter().map(|m| m.id).collect(),
            None => models_for_region(api_region)
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    pub fn contains_id(&self, api_region: &str, id: &str) -> bool {
        self.model_ids(api_region).iter().any(|cached| cached == id)
    }
}

impl Default for ModelCache {
    fn default() -> Self {
        Self::new()
    }
}

pub static MODEL_CACHE: once_cell::sync::Lazy<ModelCache> =
    once_cell::sync::Lazy::new(ModelCache::new);

/// Caches resolved `profileArn`s per streaming endpoint URL.
pub struct ProfileCache {
    inner: Arc<RwLock<HashMap<String, String>>>,
}

impl ProfileCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get(&self, endpoint: &str) -> Option<String> {
        self.inner.read().unwrap().get(endpoint).cloned()
    }

    pub fn set(&self, endpoint: &str, profile_arn: String) {
        self.inner
            .write()
            .unwrap()
            .insert(endpoint.to_string(), profile_arn);
    }

    /// Removes a cached entry. Called by Task 15's 403 handler — a stale
    /// cached profile ARN can itself be the cause of a 403, so it must be
    /// dropped before re-resolving rather than left to be reused.
    pub fn invalidate(&self, endpoint: &str) {
        self.inner.write().unwrap().remove(endpoint);
    }
}

impl Default for ProfileCache {
    fn default() -> Self {
        Self::new()
    }
}

pub static PROFILE_CACHE: once_cell::sync::Lazy<ProfileCache> =
    once_cell::sync::Lazy::new(ProfileCache::new);

/// Internal seam for testing, mirroring the other `_impl` functions in this
/// module.
async fn refresh_cache_for_credentials_impl(
    credentials: &KiroCredentials,
    api_region: &str,
    base_url_override: Option<&str>,
) {
    if let Ok(models) = fetch_available_models_impl(credentials, base_url_override).await {
        MODEL_CACHE.set(api_region, models);
    }

    let endpoint = base_url_override
        .map(|base| format!("{base}/generateAssistantResponse"))
        .unwrap_or_else(|| streaming_endpoint(api_region));
    match fetch_available_profile_arn_impl(credentials, base_url_override).await {
        Ok(Some(profile_arn)) => PROFILE_CACHE.set(&endpoint, profile_arn),
        // Resolution succeeded and authoritatively found no profile for
        // this account — proactively drop any previously cached ARN for
        // this endpoint rather than leaving it to go stale. Without this, a
        // credential whose profile was removed would keep serving a defunct
        // cached ARN indefinitely: only Task 15's 403 handler calls
        // `invalidate()`, and a stale ARN causing repeated 403s is exactly
        // the loop this cache exists to avoid.
        Ok(None) => PROFILE_CACHE.invalidate(&endpoint),
        // Best-effort: a transient failure says nothing about whether the
        // existing cached ARN (if any) is still valid, so leave it alone.
        Err(_) => {}
    }
}

/// Best-effort: refreshes both [`MODEL_CACHE`] and [`PROFILE_CACHE`] for one
/// credential's resolved API region. Called from Task 5's `adopt()` after
/// every successful login/refresh — this is what makes discovery and profile
/// resolution reachable at all (Adversarial Review Findings #5, #8 — both
/// were previously defined but never invoked from anywhere). Swallows all
/// errors; never blocks or fails the caller. `adopt()` is synchronous, so
/// Task 5's call site is expected to `tokio::spawn` this as a detached task
/// rather than block on it.
pub async fn refresh_cache_for_credentials(credentials: &KiroCredentials, api_region: &str) {
    refresh_cache_for_credentials_impl(credentials, api_region, None).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::codex::auth::test_http;
    use crate::providers::kiro::auth::KiroAuthMethod;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_credentials(region: &str, profile_arn: Option<&str>) -> KiroCredentials {
        KiroCredentials {
            access: "test-access".to_string(),
            refresh: "test-refresh".to_string(),
            expires: u64::MAX,
            region: region.to_string(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: profile_arn.map(str::to_string),
            expiry_buffer_ms: 0,
        }
    }

    // --- fetch_available_models ---

    #[tokio::test]
    async fn fetch_available_models_maps_template_and_default_fallback() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(
                200,
                r#"{"models":[{"modelId":"claude-sonnet-4.6","modelName":"Claude Sonnet 4.6 (Dynamic)"},{"modelId":"brand-new-model-1.0"}]}"#,
            )
        });

        let creds = test_credentials("us-east-1", None);
        let models = fetch_available_models_impl(&creds, Some(&server.url))
            .await
            .expect("fetch should succeed");

        assert_eq!(models.len(), 2);

        let known = models
            .iter()
            .find(|m| m.id == "claude-sonnet-4-6")
            .expect("known model should be mapped");
        assert_eq!(known.name, "Claude Sonnet 4.6 (Dynamic)");
        assert!(known.reasoning, "should fill reasoning from template");
        assert!(known.input_image, "should fill input_image from template");
        assert_eq!(known.context_window, 1_000_000);
        assert_eq!(known.max_tokens, 65_536);

        let unknown = models
            .iter()
            .find(|m| m.id == "brand-new-model-1-0")
            .expect("unknown model should still be mapped");
        assert_eq!(
            unknown.name, "brand-new-model-1.0",
            "should fall back to modelId when modelName absent"
        );
        assert!(!unknown.reasoning, "no template: reasoning defaults false");
        assert!(
            !unknown.input_image,
            "no template: input_image defaults false"
        );
        assert_eq!(
            unknown.context_window, 200_000,
            "no template: context_window default"
        );
        assert_eq!(
            unknown.max_tokens, 64_000,
            "no template: max_tokens default (distinct from catalog's 65_536)"
        );
    }

    #[tokio::test]
    async fn fetch_available_models_explicit_fields_override_template_when_present() {
        // "claude-sonnet-4-6"'s KIRO_MODELS template has input_image: true,
        // context_window: 1_000_000, max_tokens: 65_536. This response
        // supplies its own tokenLimits and a supportedInputTypes list that
        // omits IMAGE — every explicit field must win over the template,
        // not be OR'd with it.
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(
                200,
                r#"{"models":[{"modelId":"claude-sonnet-4.6","tokenLimits":{"maxInputTokens":123456,"maxOutputTokens":7777},"supportedInputTypes":["TEXT"]}]}"#,
            )
        });

        let creds = test_credentials("us-east-1", None);
        let models = fetch_available_models_impl(&creds, Some(&server.url))
            .await
            .expect("fetch should succeed");

        assert_eq!(models.len(), 1);
        let model = &models[0];
        assert_eq!(model.id, "claude-sonnet-4-6");
        assert_eq!(
            model.context_window, 123456,
            "explicit maxInputTokens should override the template's context_window"
        );
        assert_eq!(
            model.max_tokens, 7777,
            "explicit maxOutputTokens should override the template's max_tokens"
        );
        assert!(
            !model.input_image,
            "supportedInputTypes present without IMAGE must yield false, \
             even though the template says true — explicit fields are not \
             OR'd with the template"
        );
        assert!(
            model.reasoning,
            "reasoning has no per-response field, so the template still applies"
        );
    }

    #[tokio::test]
    async fn fetch_available_models_sends_expected_wire_format() {
        let requests_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = requests_seen.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |req| {
            seen.lock().unwrap().push(req.to_string());
            test_http::json_response(200, r#"{"models":[]}"#)
        });

        let creds = test_credentials("us-east-1", None);
        fetch_available_models_impl(&creds, Some(&server.url))
            .await
            .expect("fetch should succeed");

        let requests = requests_seen.lock().unwrap();
        let req = requests.first().expect("one request should have been sent");
        assert!(req.starts_with("POST /?origin=KIRO_CLI"));
        assert!(req.contains("content-type: application/x-amz-json-1.0"));
        assert!(req.contains("authorization: Bearer test-access"));
        assert!(req.contains("x-amz-target: AmazonCodeWhispererService.ListAvailableModels"));
        assert!(
            req.contains("user-agent: claude-code-proxy"),
            "should send this proxy's own identity, not pi-provider-kiro's"
        );
        assert!(req.contains(r#"{"origin":"KIRO_CLI"}"#));
    }

    #[tokio::test]
    async fn fetch_available_models_errors_on_non_success_status() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(500, r#"{"error":"boom"}"#)
        });

        let creds = test_credentials("us-east-1", None);
        let err = fetch_available_models_impl(&creds, Some(&server.url))
            .await
            .expect_err("non-2xx should be an error");
        assert!(err.to_string().contains("500"));
    }

    // --- fetch_available_profile_arn ---

    #[tokio::test]
    async fn fetch_available_profile_arn_short_circuits_when_already_present() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |_req| {
            counter.fetch_add(1, Ordering::SeqCst);
            test_http::json_response(200, r#"{"profiles":[{"arn":"should-not-be-used"}]}"#)
        });

        let creds = test_credentials("us-east-1", Some("arn:aws:iam::123:profile/preset"));
        let arn = fetch_available_profile_arn_impl(&creds, Some(&server.url))
            .await
            .expect("should succeed without a network call");

        assert_eq!(arn, Some("arn:aws:iam::123:profile/preset".to_string()));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "must not hit the network when profile_arn is already set"
        );
    }

    #[tokio::test]
    async fn fetch_available_profile_arn_resolves_via_list_available_profiles() {
        let requests_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = requests_seen.clone();
        let server = test_http::spawn_mock_server("mock server should be ready", move |req| {
            seen.lock().unwrap().push(req.to_string());
            test_http::json_response(
                200,
                r#"{"profiles":[{"arn":"arn:aws:iam::123:profile/resolved"}]}"#,
            )
        });

        let creds = test_credentials("us-east-1", None);
        let arn = fetch_available_profile_arn_impl(&creds, Some(&server.url))
            .await
            .expect("should succeed");

        assert_eq!(arn, Some("arn:aws:iam::123:profile/resolved".to_string()));

        let requests = requests_seen.lock().unwrap();
        let req = requests.first().expect("one request should have been sent");
        assert!(req.starts_with("POST / HTTP"), "no query string expected");
        assert!(req.contains("x-amz-target: AmazonCodeWhispererService.ListAvailableProfiles"));
        assert!(req.contains("authorization: Bearer test-access"));
        assert!(req.contains("content-type: application/x-amz-json-1.0"));
        assert!(
            req.trim_end().ends_with("{}"),
            "body should be empty JSON object"
        );
    }

    #[tokio::test]
    async fn fetch_available_profile_arn_returns_none_for_empty_profile_list() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(200, r#"{"profiles":[]}"#)
        });

        let creds = test_credentials("us-east-1", None);
        let arn = fetch_available_profile_arn_impl(&creds, Some(&server.url))
            .await
            .expect("empty profile list should not be an error");

        assert_eq!(arn, None);
    }

    #[tokio::test]
    async fn fetch_available_profile_arn_errors_on_non_success_status() {
        let server = test_http::spawn_mock_server("mock server should be ready", |_req| {
            test_http::json_response(403, r#"{"error":"forbidden"}"#)
        });

        let creds = test_credentials("us-east-1", None);
        let err = fetch_available_profile_arn_impl(&creds, Some(&server.url))
            .await
            .expect_err("non-2xx should be an error, distinct from Ok(None)");
        assert!(err.to_string().contains("403"));
    }

    // --- ModelCache / ProfileCache (no network) ---

    #[test]
    fn model_cache_falls_back_to_models_for_region_when_uncached() {
        let cache = ModelCache::new();
        let expected: Vec<String> = models_for_region("us-east-1")
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(cache.model_ids("us-east-1"), expected);
    }

    #[test]
    fn model_cache_authoritative_empty_set_does_not_fall_back_to_static_catalog() {
        // An empty Vec from a successful set() is a real backend answer
        // ("this region has zero models"), not the same as "nothing cached
        // yet" — model_ids must not paper over it with the static list.
        let cache = ModelCache::new();
        cache.set("us-east-1", Vec::new());
        assert_eq!(cache.model_ids("us-east-1"), Vec::<String>::new());
        assert!(!cache.contains_id("us-east-1", "claude-opus-4-8"));
    }

    #[test]
    fn model_cache_set_and_get_round_trip_and_is_region_independent() {
        let cache = ModelCache::new();
        let models = vec![DiscoveredModel {
            id: "custom-model-1".to_string(),
            name: "Custom Model".to_string(),
            reasoning: true,
            input_image: false,
            context_window: 1_000,
            max_tokens: 100,
        }];
        cache.set("us-east-1", models.clone());

        assert_eq!(cache.get("us-east-1"), Some(models));
        assert_eq!(
            cache.model_ids("us-east-1"),
            vec!["custom-model-1".to_string()]
        );

        // eu-central-1 wasn't set, so it must still fall back independently.
        let expected_eu: Vec<String> = models_for_region("eu-central-1")
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(cache.model_ids("eu-central-1"), expected_eu);
        assert!(cache.get("eu-central-1").is_none());
    }

    #[test]
    fn model_cache_contains_id_checks_cached_or_fallback_ids() {
        let cache = ModelCache::new();
        assert!(
            cache.contains_id("us-east-1", "claude-opus-4-8"),
            "static fallback should be consulted when nothing cached"
        );
        assert!(!cache.contains_id("us-east-1", "not-a-real-model"));

        cache.set(
            "us-east-1",
            vec![DiscoveredModel {
                id: "only-this-one".to_string(),
                name: "Only This One".to_string(),
                reasoning: false,
                input_image: false,
                context_window: 1,
                max_tokens: 1,
            }],
        );
        assert!(cache.contains_id("us-east-1", "only-this-one"));
        assert!(
            !cache.contains_id("us-east-1", "claude-opus-4-8"),
            "once cached, only cached IDs should count"
        );
    }

    #[test]
    fn profile_cache_invalidate_removes_a_previously_set_entry() {
        let cache = ProfileCache::new();
        let endpoint = "https://q.us-east-1.amazonaws.com/generateAssistantResponse";
        cache.set(endpoint, "arn:aws:iam::123:profile/1".to_string());
        assert!(cache.get(endpoint).is_some());

        cache.invalidate(endpoint);
        assert!(cache.get(endpoint).is_none());
    }

    // --- refresh_cache_for_credentials wiring ---

    #[tokio::test]
    async fn refresh_cache_for_credentials_populates_both_caches_end_to_end() {
        let server = test_http::spawn_mock_server("mock server should be ready", |req| {
            if req.contains("ListAvailableModels") {
                test_http::json_response(200, r#"{"models":[{"modelId":"claude-haiku-4.5"}]}"#)
            } else if req.contains("ListAvailableProfiles") {
                test_http::json_response(
                    200,
                    r#"{"profiles":[{"arn":"arn:aws:iam::999:profile/e2e"}]}"#,
                )
            } else {
                test_http::json_response(404, r#"{"error":"not_found"}"#)
            }
        });

        let creds = test_credentials("us-east-1", None);
        // A region key unlikely to collide with any other test touching the
        // process-global MODEL_CACHE/PROFILE_CACHE statics.
        let region = "zz-test-region-refresh-cache-wiring";

        refresh_cache_for_credentials_impl(&creds, region, Some(&server.url)).await;

        let cached = MODEL_CACHE
            .get(region)
            .expect("models should be cached after refresh");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].id, "claude-haiku-4-5");

        let endpoint = format!("{}/generateAssistantResponse", server.url);
        assert_eq!(
            PROFILE_CACHE.get(&endpoint),
            Some("arn:aws:iam::999:profile/e2e".to_string()),
            "profile cache should also be populated, keyed by the streaming endpoint"
        );
    }

    #[tokio::test]
    async fn refresh_cache_for_credentials_swallows_connection_errors() {
        // No server at all — port 1 refuses the connection immediately, so
        // this exercises the "network error propagates as Err and gets
        // swallowed" path specifically. It does NOT exercise HTTP_CLIENT's
        // 15s request timeout (a genuinely hanging peer) — doing that
        // without slowing this test down by 15s would need a per-call
        // timeout override this module doesn't expose, so that behavior is
        // asserted by code review of the shared client config rather than a
        // test here.
        let creds = test_credentials("us-east-1", None);
        let region = "zz-test-region-refresh-cache-error-swallowed";
        refresh_cache_for_credentials_impl(&creds, region, Some("http://127.0.0.1:1")).await;
        assert!(
            MODEL_CACHE.get(region).is_none(),
            "model cache must be untouched on failure"
        );
        assert!(
            PROFILE_CACHE
                .get(&format!(
                    "{}/generateAssistantResponse",
                    "http://127.0.0.1:1"
                ))
                .is_none(),
            "profile cache must be untouched on failure"
        );
    }
}
