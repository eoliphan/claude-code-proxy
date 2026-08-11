//! Native AWS SSO-OIDC device-code login flow.
//!
//! This is the third and final credential source for Kiro: when neither the
//! Kiro IDE's cached token file (`kiro_ide.rs`) nor the `kiro-cli` SQLite
//! store (`kiro_cli.rs`) has anything to reuse, this module drives the
//! standard AWS SSO-OIDC device-authorization flow directly (the same
//! mechanism behind "enter this code on this URL" CLI logins).
//!
//! This is a one-shot interactive flow, not on the hot request path, so it
//! uses `reqwest::blocking::Client` (matching `kimi/auth/login.rs::run_device_login`'s
//! shape) rather than the async client used elsewhere in the proxy.

use std::time::Duration;

use anyhow::anyhow;
use serde::Deserialize;

use super::kiro_credentials::{KiroAuthMethod, KiroCredentials};

pub const BUILDER_ID_START_URL: &str = "https://view.awsapps.com/start";
pub const SSO_SCOPES: &[&str] = &[
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
    "codewhisperer:transformations",
    "codewhisperer:taskassist",
];
pub const IDC_PROBE_REGIONS: &[&str] = &[
    "us-east-1",
    "eu-west-1",
    "eu-central-1",
    "us-east-2",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "ap-southeast-1",
    "ap-northeast-1",
    "us-west-2",
];

const BUILDER_ID_REGION: &str = "us-east-1";

/// The User-Agent and `clientName` this proxy identifies itself with on
/// OIDC calls, shown to the user on AWS's device-approval page.
const OIDC_USER_AGENT: &str = "claude-code-proxy";

pub trait DeviceLoginCallbacks {
    fn on_progress(&self, message: &str);
    fn on_auth_prompt(&self, verification_uri_complete: &str, user_code: &str);
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterClientResponse {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceAuthResponse {
    #[serde(default)]
    #[allow(dead_code)]
    verification_uri: Option<String>,
    verification_uri_complete: String,
    user_code: String,
    device_code: String,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenPollResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// RegisterClient + StartDeviceAuthorization against a single OIDC host.
/// Returns `None` if either call fails (non-2xx or transport/parse error) —
/// this is treated as "this region isn't viable", not a hard error, so the
/// IDC variant can move on to the next probed region.
fn try_register_and_authorize(
    oidc_base: &str,
    start_url: &str,
) -> Option<(String, String, DeviceAuthResponse)> {
    let client = reqwest::blocking::Client::new();

    let register_body = serde_json::json!({
        "clientName": OIDC_USER_AGENT,
        "clientType": "public",
        "scopes": SSO_SCOPES,
        "grantTypes": [
            "urn:ietf:params:oauth:grant-type:device_code",
            "refresh_token",
        ],
    });
    let register_resp = client
        .post(format!("{oidc_base}/client/register"))
        .header("User-Agent", OIDC_USER_AGENT)
        .json(&register_body)
        .send()
        .ok()?;
    if !register_resp.status().is_success() {
        return None;
    }
    let register: RegisterClientResponse = register_resp.json().ok()?;

    let auth_body = serde_json::json!({
        "clientId": register.client_id,
        "clientSecret": register.client_secret,
        "startUrl": start_url,
    });
    let auth_resp = client
        .post(format!("{oidc_base}/device_authorization"))
        .header("User-Agent", OIDC_USER_AGENT)
        .json(&auth_body)
        .send()
        .ok()?;
    if !auth_resp.status().is_success() {
        return None;
    }
    let dev_auth: DeviceAuthResponse = auth_resp.json().ok()?;

    Some((register.client_id, register.client_secret, dev_auth))
}

/// Poll `CreateToken` until success, a non-retryable error, or the device
/// code's expiry deadline passes.
fn poll_device_code(
    oidc_base: &str,
    client_id: &str,
    client_secret: &str,
    region: &str,
    dev_auth: &DeviceAuthResponse,
    callbacks: &dyn DeviceLoginCallbacks,
) -> Result<KiroCredentials, anyhow::Error> {
    callbacks.on_auth_prompt(&dev_auth.verification_uri_complete, &dev_auth.user_code);

    let client = reqwest::blocking::Client::new();
    let expires_in_secs = dev_auth.expires_in.unwrap_or(600);
    let base_interval_ms = dev_auth.interval.unwrap_or(5).saturating_mul(1000);
    let mut interval_ms = base_interval_ms;
    let deadline = now_ms().saturating_add(expires_in_secs.saturating_mul(1000));

    while now_ms() < deadline {
        std::thread::sleep(Duration::from_millis(interval_ms));

        let body = serde_json::json!({
            "clientId": client_id,
            "clientSecret": client_secret,
            "deviceCode": dev_auth.device_code,
            "grantType": "urn:ietf:params:oauth:grant-type:device_code",
        });
        let resp = client
            .post(format!("{oidc_base}/token"))
            .header("User-Agent", OIDC_USER_AGENT)
            .json(&body)
            .send()?;
        // Per the brief: success requires HTTP 200 *and* both tokens present —
        // a non-2xx response that happens to echo token-shaped keys must not
        // be treated as success.
        let status_is_success = resp.status().is_success();
        let poll: TokenPollResponse = resp
            .json()
            .map_err(|e| anyhow!("failed to parse token response: {e}"))?;

        if status_is_success
            && let (Some(access_token), Some(refresh_token)) =
                (poll.access_token, poll.refresh_token)
        {
            let token_expires_in = poll.expires_in.unwrap_or(3600);
            return Ok(KiroCredentials {
                // `refresh` is always the raw refresh token — client_id/client_secret/
                // auth_method are the separate struct fields Task 1 already defined, so
                // there is nothing to pack into it.
                refresh: refresh_token,
                access: access_token,
                expires: now_ms()
                    .saturating_add(token_expires_in.saturating_mul(1000))
                    .saturating_sub(5 * 60 * 1000),
                region: region.to_string(),
                auth_method: KiroAuthMethod::Idc,
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                profile_arn: None,
                // Matches the 5-minute buffer subtracted just above.
                expiry_buffer_ms: 5 * 60 * 1000,
            });
        }

        match poll.error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval_ms = interval_ms.saturating_add(base_interval_ms),
            Some(other) => return Err(anyhow!("Authorization failed: {other}")),
            None => return Err(anyhow!("Authorization failed: malformed token response")),
        }
    }

    Err(anyhow!("Authorization timed out"))
}

/// Register + authorize + poll against a single, already-resolved OIDC host.
/// Builder ID always uses this directly (single region); the IDC variant
/// uses `try_register_and_authorize` + `poll_device_code` directly so it can
/// fall through to the next probed region on failure instead of bailing.
fn run_device_login_for(
    oidc_base: &str,
    start_url: &str,
    region: &str,
    callbacks: &dyn DeviceLoginCallbacks,
) -> Result<KiroCredentials, anyhow::Error> {
    let (client_id, client_secret, dev_auth) = try_register_and_authorize(oidc_base, start_url)
        .ok_or_else(|| anyhow!("Device authorization failed for region {region}"))?;
    poll_device_code(
        oidc_base,
        &client_id,
        &client_secret,
        region,
        &dev_auth,
        callbacks,
    )
}

pub fn run_device_login_builder_id(
    callbacks: &dyn DeviceLoginCallbacks,
) -> Result<KiroCredentials, anyhow::Error> {
    let oidc_base = format!("https://oidc.{BUILDER_ID_REGION}.amazonaws.com");
    run_device_login_for(
        &oidc_base,
        BUILDER_ID_START_URL,
        BUILDER_ID_REGION,
        callbacks,
    )
}

/// Internal seam: builds the OIDC host to probe for each region via a
/// closure rather than hardcoding `https://oidc.{region}.amazonaws.com`, so
/// tests can point every "region" at a single local mock server.
fn run_device_login_idc_with_base(
    callbacks: &dyn DeviceLoginCallbacks,
    start_url: &str,
    oidc_base_for_region: &dyn Fn(&str) -> String,
) -> Result<KiroCredentials, anyhow::Error> {
    callbacks.on_progress("Detecting your Identity Center region...");

    let mut failed_regions = Vec::new();
    for region in IDC_PROBE_REGIONS {
        let oidc_base = oidc_base_for_region(region);
        match try_register_and_authorize(&oidc_base, start_url) {
            Some((client_id, client_secret, dev_auth)) => {
                callbacks.on_progress(&format!("Region detected: {region}"));
                return poll_device_code(
                    &oidc_base,
                    &client_id,
                    &client_secret,
                    region,
                    &dev_auth,
                    callbacks,
                );
            }
            None => failed_regions.push(*region),
        }
    }

    Err(anyhow!(
        "Device authorization failed in all probed regions: {}",
        failed_regions.join(", ")
    ))
}

pub fn run_device_login_idc(
    callbacks: &dyn DeviceLoginCallbacks,
    start_url: &str,
) -> Result<KiroCredentials, anyhow::Error> {
    run_device_login_idc_with_base(callbacks, start_url, &|region| {
        format!("https://oidc.{region}.amazonaws.com")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::codex::auth::test_http;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordingCallbacks {
        progress: Mutex<Vec<String>>,
        prompts: Mutex<Vec<(String, String)>>,
    }

    impl DeviceLoginCallbacks for RecordingCallbacks {
        fn on_progress(&self, message: &str) {
            self.progress.lock().unwrap().push(message.to_string());
        }
        fn on_auth_prompt(&self, verification_uri_complete: &str, user_code: &str) {
            self.prompts
                .lock()
                .unwrap()
                .push((verification_uri_complete.to_string(), user_code.to_string()));
        }
    }

    #[test]
    fn builder_id_login_succeeds_after_slow_down_retry() {
        let poll_count = Arc::new(AtomicU32::new(0));
        let pc = poll_count.clone();
        let requests_seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = requests_seen.clone();
        let server = test_http::spawn_mock_server(
            "mock oidc server should become ready",
            move |request: &str| {
                seen.lock().unwrap().push(request.to_string());
                if request.contains("/client/register") {
                    test_http::json_response(
                        200,
                        r#"{"clientId":"cid-1","clientSecret":"csecret-1"}"#,
                    )
                } else if request.contains("/device_authorization") {
                    test_http::json_response(
                        200,
                        r#"{"verificationUri":"https://device.sso.example.com","verificationUriComplete":"https://device.sso.example.com?user_code=ABCD-EFGH","userCode":"ABCD-EFGH","deviceCode":"devicecode-1","interval":1,"expiresIn":600}"#,
                    )
                } else if request.contains("/token") {
                    let count = pc.fetch_add(1, Ordering::Relaxed);
                    if count == 0 {
                        test_http::json_response(400, r#"{"error":"slow_down"}"#)
                    } else {
                        test_http::json_response(
                            200,
                            r#"{"accessToken":"access-1","refreshToken":"refresh-1","expiresIn":3600}"#,
                        )
                    }
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            },
        );

        let callbacks = RecordingCallbacks::default();
        let creds =
            run_device_login_for(&server.url, BUILDER_ID_START_URL, "us-east-1", &callbacks)
                .expect("device login should succeed");

        // `refresh` is the raw refresh token, never packed into a delimited string.
        assert_eq!(creds.refresh, "refresh-1");
        assert_eq!(creds.access, "access-1");
        assert_eq!(creds.client_id, "cid-1");
        assert_eq!(creds.client_secret, "csecret-1");
        assert_eq!(creds.region, "us-east-1");
        assert_eq!(creds.auth_method, KiroAuthMethod::Idc);
        assert!(
            poll_count.load(Ordering::Relaxed) >= 2,
            "expected the slow_down response to be retried, not treated as a failure"
        );

        let prompts = callbacks.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].1, "ABCD-EFGH");
        assert_eq!(
            prompts[0].0,
            "https://device.sso.example.com?user_code=ABCD-EFGH"
        );

        // Wire-format assertions: verify the actual bytes sent, not just the
        // outcome, so a header/method/body regression would fail this test.
        let requests = requests_seen.lock().unwrap();
        let register_req = requests
            .iter()
            .find(|r| r.contains("/client/register"))
            .expect("register request should have been sent");
        assert!(register_req.starts_with("POST /client/register"));
        assert!(
            register_req
                .to_lowercase()
                .contains("user-agent: claude-code-proxy")
        );
        assert!(
            register_req
                .to_lowercase()
                .contains("content-type: application/json")
        );
        assert!(register_req.contains(r#""clientName":"claude-code-proxy""#));
        assert!(register_req.contains(r#""clientType":"public""#));
        assert!(register_req.contains("codewhisperer:completions"));
        assert!(register_req.contains("urn:ietf:params:oauth:grant-type:device_code"));

        let authorize_req = requests
            .iter()
            .find(|r| r.contains("/device_authorization"))
            .expect("device_authorization request should have been sent");
        assert!(authorize_req.starts_with("POST /device_authorization"));
        assert!(authorize_req.contains(r#""clientId":"cid-1""#));
        assert!(authorize_req.contains(r#""clientSecret":"csecret-1""#));
        assert!(authorize_req.contains(&format!(r#""startUrl":"{BUILDER_ID_START_URL}""#)));

        let token_reqs: Vec<&String> = requests.iter().filter(|r| r.contains("/token")).collect();
        assert_eq!(
            token_reqs.len(),
            2,
            "expected exactly one retry after slow_down"
        );
        for token_req in &token_reqs {
            assert!(token_req.starts_with("POST /token"));
            assert!(token_req.contains(r#""deviceCode":"devicecode-1""#));
            assert!(
                token_req.contains(r#""grantType":"urn:ietf:params:oauth:grant-type:device_code""#)
            );
        }
    }

    #[test]
    fn poll_does_not_treat_non_success_status_as_success_even_with_token_shaped_body() {
        // Regression test: a non-2xx response must never be accepted as
        // success even if its body happens to contain accessToken/
        // refreshToken keys — success requires HTTP 200 *and* both tokens.
        let server = test_http::spawn_mock_server(
            "mock oidc server should become ready",
            |request: &str| {
                if request.contains("/token") {
                    test_http::json_response(
                        500,
                        r#"{"accessToken":"should-not-be-used","refreshToken":"should-not-be-used"}"#,
                    )
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            },
        );

        let callbacks = RecordingCallbacks::default();
        let dev_auth = DeviceAuthResponse {
            verification_uri: None,
            verification_uri_complete: "https://device.sso.example.com?user_code=BAD1-0000"
                .to_string(),
            user_code: "BAD1-0000".to_string(),
            device_code: "devicecode-bad-status".to_string(),
            interval: Some(0),
            expires_in: Some(600),
        };

        let err = poll_device_code(
            &server.url,
            "cid",
            "csecret",
            "us-east-1",
            &dev_auth,
            &callbacks,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("malformed token response"),
            "a non-2xx status must not be accepted as success even with token-shaped keys, got: {err}"
        );
    }

    #[test]
    fn poll_fails_immediately_on_non_retryable_error() {
        let poll_count = Arc::new(AtomicU32::new(0));
        let pc = poll_count.clone();
        let server = test_http::spawn_mock_server(
            "mock oidc server should become ready",
            move |request: &str| {
                if request.contains("/token") {
                    pc.fetch_add(1, Ordering::Relaxed);
                    test_http::json_response(400, r#"{"error":"access_denied"}"#)
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            },
        );

        let callbacks = RecordingCallbacks::default();
        let dev_auth = DeviceAuthResponse {
            verification_uri: None,
            verification_uri_complete: "https://device.sso.example.com?user_code=DENY-0001"
                .to_string(),
            user_code: "DENY-0001".to_string(),
            device_code: "devicecode-denied".to_string(),
            interval: Some(0),
            expires_in: Some(600),
        };

        let err = poll_device_code(
            &server.url,
            "cid",
            "csecret",
            "us-east-1",
            &dev_auth,
            &callbacks,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("access_denied"),
            "expected a terminal-error message, got: {err}"
        );
        assert_eq!(
            poll_count.load(Ordering::Relaxed),
            1,
            "a non-retryable error must not be retried"
        );
    }

    #[test]
    fn poll_returns_timeout_error_when_deadline_already_passed() {
        let callbacks = RecordingCallbacks::default();
        let dev_auth = DeviceAuthResponse {
            verification_uri: None,
            verification_uri_complete: "https://device.sso.example.com?user_code=TIME-OUT1"
                .to_string(),
            user_code: "TIME-OUT1".to_string(),
            device_code: "devicecode-timeout".to_string(),
            interval: Some(1),
            expires_in: Some(0),
        };

        // expires_in = 0 means the deadline is already in the past by the time the
        // loop condition is checked, so no HTTP call is ever made.
        let err = poll_device_code(
            "http://127.0.0.1:9",
            "cid",
            "csecret",
            "us-east-1",
            &dev_auth,
            &callbacks,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Authorization timed out"),
            "got: {err}"
        );
    }

    #[test]
    fn idc_login_probes_regions_until_one_succeeds() {
        let register_attempts = Arc::new(AtomicU32::new(0));
        let ra = register_attempts.clone();
        let server = test_http::spawn_mock_server(
            "mock oidc server should become ready",
            move |request: &str| {
                if request.contains("/client/register") {
                    let attempt = ra.fetch_add(1, Ordering::Relaxed);
                    if attempt < 2 {
                        test_http::json_response(500, r#"{"error":"internal_error"}"#)
                    } else {
                        test_http::json_response(
                            200,
                            r#"{"clientId":"cid-2","clientSecret":"csecret-2"}"#,
                        )
                    }
                } else if request.contains("/device_authorization") {
                    test_http::json_response(
                        200,
                        r#"{"verificationUri":"https://device.sso.example.com","verificationUriComplete":"https://device.sso.example.com?user_code=WXYZ-9999","userCode":"WXYZ-9999","deviceCode":"devicecode-2","interval":0,"expiresIn":600}"#,
                    )
                } else if request.contains("/token") {
                    test_http::json_response(
                        200,
                        r#"{"accessToken":"access-2","refreshToken":"refresh-2","expiresIn":3600}"#,
                    )
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            },
        );

        let callbacks = RecordingCallbacks::default();
        let mock_url = server.url.clone();
        let creds = run_device_login_idc_with_base(
            &callbacks,
            "https://example.awsapps.com/start",
            &move |_region| mock_url.clone(),
        )
        .expect("device login should succeed on a later probed region");

        assert_eq!(creds.refresh, "refresh-2");
        assert_eq!(creds.region, IDC_PROBE_REGIONS[2]);
        assert_eq!(register_attempts.load(Ordering::Relaxed), 3);

        let progress = callbacks.progress.lock().unwrap();
        assert!(
            progress
                .iter()
                .any(|m| m.contains("Detecting your Identity Center region")),
            "expected a progress message before probing, got: {progress:?}"
        );
        assert!(
            progress
                .iter()
                .any(|m| m == &format!("Region detected: {}", IDC_PROBE_REGIONS[2])),
            "expected a progress message naming the detected region, got: {progress:?}"
        );
    }

    #[test]
    fn idc_login_fails_when_all_regions_exhausted() {
        let server = test_http::spawn_mock_server(
            "mock oidc server should become ready",
            |request: &str| {
                if request.contains("/client/register") {
                    test_http::json_response(500, r#"{"error":"internal_error"}"#)
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            },
        );

        let callbacks = RecordingCallbacks::default();
        let mock_url = server.url.clone();
        let err = run_device_login_idc_with_base(
            &callbacks,
            "https://example.awsapps.com/start",
            &move |_region| mock_url.clone(),
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("Device authorization failed in all probed regions"));
        for region in IDC_PROBE_REGIONS {
            assert!(
                message.contains(region),
                "expected {region} listed in: {message}"
            );
        }
    }
}
