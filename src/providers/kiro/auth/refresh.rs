//! Direct credential refresh for both IDC and desktop auth methods.
//!
//! This module refreshes credentials directly against AWS OIDC endpoints (for IDC)
//! or Kiro's own refresh endpoint (for desktop), without involving kiro-cli.
//! This is off the hot request path (tokens are refreshed infrequently), so we
//! use `reqwest::blocking::Client` like the device-login flow.

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use super::kiro_credentials::{KiroAuthMethod, KiroCredentials};

const OIDC_USER_AGENT: &str = "pi-cli";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopRefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopRefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdcRefreshRequest {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    grant_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdcRefreshResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Internal seam for testing: allows base URL override.
/// Production callers use `refresh_token_direct` which calls this with default URLs.
fn refresh_token_direct_for(
    credentials: &KiroCredentials,
    base_url_for_region: &dyn Fn(&str) -> String,
) -> Result<KiroCredentials, anyhow::Error> {
    match credentials.auth_method {
        KiroAuthMethod::Desktop => {
            let base = base_url_for_region(&credentials.region);
            let url = format!("{base}/refreshToken");
            let client = reqwest::blocking::Client::new();

            let body = DesktopRefreshRequest {
                refresh_token: credentials.refresh.clone(),
            };

            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("User-Agent", OIDC_USER_AGENT)
                .json(&body)
                .send()?;

            if !resp.status().is_success() {
                return Err(anyhow!(
                    "Desktop refresh failed with status {}",
                    resp.status()
                ));
            }

            let refresh_resp: DesktopRefreshResponse = resp.json()?;
            let new_refresh = refresh_resp
                .refresh_token
                .unwrap_or_else(|| credentials.refresh.clone());

            Ok(KiroCredentials {
                refresh: new_refresh,
                access: refresh_resp.access_token,
                expires: now_ms()
                    .saturating_add(refresh_resp.expires_in.saturating_mul(1000))
                    .saturating_sub(5 * 60 * 1000),
                region: credentials.region.clone(),
                auth_method: KiroAuthMethod::Desktop,
                client_id: String::new(),
                client_secret: String::new(),
                profile_arn: credentials.profile_arn.clone(),
            })
        }
        KiroAuthMethod::Idc => {
            if credentials.client_id.is_empty() {
                return Err(anyhow!("IDC refresh requires client_id, but it is empty"));
            }

            let base = base_url_for_region(&credentials.region);
            let url = format!("{base}/token");
            let client = reqwest::blocking::Client::new();

            let body = IdcRefreshRequest {
                client_id: credentials.client_id.clone(),
                client_secret: credentials.client_secret.clone(),
                refresh_token: credentials.refresh.clone(),
                grant_type: "refresh_token".to_string(),
            };

            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("User-Agent", OIDC_USER_AGENT)
                .json(&body)
                .send()?;

            if !resp.status().is_success() {
                return Err(anyhow!("IDC refresh failed with status {}", resp.status()));
            }

            let refresh_resp: IdcRefreshResponse = resp.json()?;

            Ok(KiroCredentials {
                refresh: refresh_resp.refresh_token,
                access: refresh_resp.access_token,
                expires: now_ms()
                    .saturating_add(refresh_resp.expires_in.saturating_mul(1000))
                    .saturating_sub(5 * 60 * 1000),
                region: credentials.region.clone(),
                auth_method: KiroAuthMethod::Idc,
                client_id: credentials.client_id.clone(),
                client_secret: credentials.client_secret.clone(),
                profile_arn: credentials.profile_arn.clone(),
            })
        }
    }
}

/// Refresh a token directly against AWS or Kiro endpoints.
/// Dispatches on the auth method to determine the endpoint and request format.
pub fn refresh_token_direct(
    credentials: &KiroCredentials,
) -> Result<KiroCredentials, anyhow::Error> {
    refresh_token_direct_for(credentials, &|region| match credentials.auth_method {
        KiroAuthMethod::Desktop => format!("https://prod.{region}.auth.desktop.kiro.dev"),
        KiroAuthMethod::Idc => format!("https://oidc.{region}.amazonaws.com"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::codex::auth::test_http;

    #[test]
    fn desktop_refresh_with_refreshtoken_rotation() {
        let server = test_http::spawn_mock_server(
            "mock server should be ready",
            |request: &str| {
                if request.contains("/refreshToken") {
                    test_http::json_response(
                        200,
                        r#"{"accessToken":"new-access-1","refreshToken":"new-refresh-1","expiresIn":3600}"#,
                    )
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            },
        );

        let creds = KiroCredentials {
            access: "old-access".to_string(),
            refresh: "old-refresh".to_string(),
            expires: 1000,
            region: "us-east-1".to_string(),
            auth_method: KiroAuthMethod::Desktop,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
        };

        let refreshed = refresh_token_direct_for(&creds, &|_region| server.url.clone())
            .expect("desktop refresh should succeed");

        assert_eq!(refreshed.access, "new-access-1");
        assert_eq!(
            refreshed.refresh, "new-refresh-1",
            "should use rotated refresh token"
        );
        assert_eq!(refreshed.auth_method, KiroAuthMethod::Desktop);
        assert!(
            refreshed.expires > now_ms(),
            "expires should be in the future"
        );
    }

    #[test]
    fn desktop_refresh_without_refreshtoken_rotation() {
        let server =
            test_http::spawn_mock_server("mock server should be ready", |request: &str| {
                if request.contains("/refreshToken") {
                    // Response without refreshToken — should reuse the old one
                    test_http::json_response(
                        200,
                        r#"{"accessToken":"new-access-2","expiresIn":3600}"#,
                    )
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            });

        let creds = KiroCredentials {
            access: "old-access".to_string(),
            refresh: "old-refresh".to_string(),
            expires: 1000,
            region: "us-east-1".to_string(),
            auth_method: KiroAuthMethod::Desktop,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
        };

        let refreshed = refresh_token_direct_for(&creds, &|_region| server.url.clone())
            .expect("desktop refresh should succeed even without new refresh token");

        assert_eq!(refreshed.access, "new-access-2");
        assert_eq!(
            refreshed.refresh, "old-refresh",
            "should reuse old refresh token"
        );
        assert_eq!(refreshed.auth_method, KiroAuthMethod::Desktop);
    }

    #[test]
    fn idc_refresh_sends_client_credentials_and_returns_them() {
        let requests_seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = requests_seen.clone();

        let server = test_http::spawn_mock_server(
            "mock server should be ready",
            move |request: &str| {
                seen.lock().unwrap().push(request.to_string());
                if request.contains("/token") {
                    test_http::json_response(
                        200,
                        r#"{"accessToken":"new-idc-access","refreshToken":"new-idc-refresh","expiresIn":3600}"#,
                    )
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            },
        );

        let creds = KiroCredentials {
            access: "old-access".to_string(),
            refresh: "old-refresh".to_string(),
            expires: 1000,
            region: "us-east-1".to_string(),
            auth_method: KiroAuthMethod::Idc,
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            profile_arn: None,
        };

        let refreshed = refresh_token_direct_for(&creds, &|_region| server.url.clone())
            .expect("IDC refresh should succeed");

        assert_eq!(refreshed.access, "new-idc-access");
        assert_eq!(refreshed.refresh, "new-idc-refresh");
        assert_eq!(refreshed.client_id, "test-client-id");
        assert_eq!(refreshed.client_secret, "test-client-secret");
        assert_eq!(refreshed.auth_method, KiroAuthMethod::Idc);

        // Wire-format assertions: verify the request body contains the client credentials.
        let requests = requests_seen.lock().unwrap();
        let token_req = requests
            .iter()
            .find(|r| r.contains("/token"))
            .expect("token request should have been sent");
        assert!(token_req.contains(r#""clientId":"test-client-id""#));
        assert!(token_req.contains(r#""clientSecret":"test-client-secret""#));
        assert!(token_req.contains(r#""grantType":"refresh_token""#));
        assert!(token_req.contains(r#""refreshToken":"old-refresh""#));
    }

    #[test]
    fn idc_refresh_with_empty_client_id_returns_error() {
        let server =
            test_http::spawn_mock_server("mock server should be ready", |_request: &str| {
                // Should never reach the server
                test_http::json_response(200, r#"{"accessToken":"should-not-happen"}"#)
            });

        let creds = KiroCredentials {
            access: "old-access".to_string(),
            refresh: "old-refresh".to_string(),
            expires: 1000,
            region: "us-east-1".to_string(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(), // Empty — this is the error condition
            client_secret: "test-secret".to_string(),
            profile_arn: None,
        };

        let err = refresh_token_direct_for(&creds, &|_region| server.url.clone())
            .expect_err("IDC refresh with empty client_id should error");

        assert!(
            err.to_string().contains("client_id"),
            "error message should mention client_id: {}",
            err
        );
    }

    #[test]
    fn desktop_refresh_returns_error_on_non_2xx_status() {
        let server =
            test_http::spawn_mock_server("mock server should be ready", |request: &str| {
                if request.contains("/refreshToken") {
                    test_http::json_response(401, r#"{"error":"unauthorized"}"#)
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            });

        let creds = KiroCredentials {
            access: "old-access".to_string(),
            refresh: "old-refresh".to_string(),
            expires: 1000,
            region: "us-east-1".to_string(),
            auth_method: KiroAuthMethod::Desktop,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
        };

        let err = refresh_token_direct_for(&creds, &|_region| server.url.clone())
            .expect_err("desktop refresh with non-2xx status should error");

        assert!(
            err.to_string().contains("401"),
            "error should mention status code"
        );
    }

    #[test]
    fn idc_refresh_returns_error_on_non_2xx_status() {
        let server =
            test_http::spawn_mock_server("mock server should be ready", |request: &str| {
                if request.contains("/token") {
                    test_http::json_response(403, r#"{"error":"forbidden"}"#)
                } else {
                    test_http::json_response(404, r#"{"error":"not_found"}"#)
                }
            });

        let creds = KiroCredentials {
            access: "old-access".to_string(),
            refresh: "old-refresh".to_string(),
            expires: 1000,
            region: "us-east-1".to_string(),
            auth_method: KiroAuthMethod::Idc,
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            profile_arn: None,
        };

        let err = refresh_token_direct_for(&creds, &|_region| server.url.clone())
            .expect_err("IDC refresh with non-2xx status should error");

        assert!(
            err.to_string().contains("403"),
            "error should mention status code"
        );
    }
}
