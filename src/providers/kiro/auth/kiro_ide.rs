use super::kiro_credentials::{KiroAuthMethod, KiroCredentials};
use crate::paths::DirResolverEnv;
use serde::Deserialize;
use std::path::PathBuf;

const EXPIRY_BUFFER_MS: i64 = 2 * 60 * 1000;

#[derive(Debug, Deserialize)]
struct KiroIdeTokenFile {
    #[serde(rename = "accessToken")]
    access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    region: Option<String>,
    #[serde(rename = "clientIdHash")]
    client_id_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KiroIdeClientFile {
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    #[serde(rename = "clientSecret")]
    client_secret: Option<String>,
}

fn sso_cache_dir(deps: &DirResolverEnv) -> PathBuf {
    PathBuf::from(&deps.home)
        .join(".aws")
        .join("sso")
        .join("cache")
}

pub fn read_ide_credentials_for(
    deps: &DirResolverEnv,
    allow_expired: bool,
) -> Option<KiroCredentials> {
    let cache_dir = sso_cache_dir(deps);
    let token_path = cache_dir.join("kiro-auth-token.json");
    let raw = std::fs::read_to_string(&token_path).ok()?;
    let token: KiroIdeTokenFile = serde_json::from_str(&raw).ok()?;
    let access = token.access_token?;
    let refresh = token.refresh_token?;
    let expires_at_raw = token.expires_at?;
    let expires_at_ms = time::OffsetDateTime::parse(
        &expires_at_raw,
        &time::format_description::well_known::Rfc3339,
    )
    .ok()?
    .unix_timestamp()
        * 1000;
    let expires = (expires_at_ms - EXPIRY_BUFFER_MS).max(0) as u64;

    if !allow_expired {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if now_ms >= expires {
            return None;
        }
    }

    let region = token.region.unwrap_or_else(|| "us-east-1".to_string());
    let (client_id, client_secret) = token
        .client_id_hash
        .and_then(|hash| {
            let reg_path = cache_dir.join(format!("{hash}.json"));
            let raw = std::fs::read_to_string(reg_path).ok()?;
            let reg: KiroIdeClientFile = serde_json::from_str(&raw).ok()?;
            Some((
                reg.client_id.unwrap_or_default(),
                reg.client_secret.unwrap_or_default(),
            ))
        })
        .unwrap_or_default();

    Some(KiroCredentials {
        access,
        refresh,
        expires,
        region,
        auth_method: KiroAuthMethod::Idc,
        client_id,
        client_secret,
        profile_arn: None,
    })
}

pub fn read_ide_credentials(allow_expired: bool) -> Option<KiroCredentials> {
    read_ide_credentials_for(&DirResolverEnv::default(), allow_expired)
}

pub fn get_ide_credentials() -> Option<KiroCredentials> {
    read_ide_credentials(false)
}

pub fn get_ide_credentials_allow_expired() -> Option<KiroCredentials> {
    read_ide_credentials(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_token_file(home: &std::path::Path, body: &str) {
        let dir = home.join(".aws").join("sso").join("cache");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("kiro-auth-token.json"), body).unwrap();
    }

    #[test]
    fn reads_valid_token_file() {
        let tmp = TempDir::new().unwrap();
        let future_iso = "2099-01-01T00:00:00.000Z";
        write_token_file(
            tmp.path(),
            &format!(
                r#"{{"accessToken":"at","refreshToken":"rt","expiresAt":"{future_iso}","region":"eu-west-1"}}"#
            ),
        );
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        let creds = read_ide_credentials_for(&deps, false).expect("should read credentials");
        assert_eq!(creds.access, "at");
        assert_eq!(creds.region, "eu-west-1");
        assert_eq!(creds.auth_method, KiroAuthMethod::Idc);
    }

    #[test]
    fn returns_none_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        assert!(read_ide_credentials_for(&deps, false).is_none());
    }

    #[test]
    fn returns_none_when_expired_and_not_allowed() {
        let tmp = TempDir::new().unwrap();
        write_token_file(
            tmp.path(),
            r#"{"accessToken":"at","refreshToken":"rt","expiresAt":"2000-01-01T00:00:00.000Z"}"#,
        );
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        assert!(read_ide_credentials_for(&deps, false).is_none());
        assert!(read_ide_credentials_for(&deps, true).is_some());
    }

    #[test]
    fn reads_companion_client_registration_file() {
        let tmp = TempDir::new().unwrap();
        let future_iso = "2099-01-01T00:00:00.000Z";
        write_token_file(
            tmp.path(),
            &format!(
                r#"{{"accessToken":"at","refreshToken":"rt","expiresAt":"{future_iso}","clientIdHash":"abc123"}}"#
            ),
        );
        fs::write(
            tmp.path()
                .join(".aws")
                .join("sso")
                .join("cache")
                .join("abc123.json"),
            r#"{"clientId":"cid","clientSecret":"csecret"}"#,
        )
        .unwrap();
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        let creds = read_ide_credentials_for(&deps, false).unwrap();
        assert_eq!(creds.client_id, "cid");
        assert_eq!(creds.client_secret, "csecret");
    }

    #[test]
    fn tolerates_missing_client_registration_file() {
        let tmp = TempDir::new().unwrap();
        let future_iso = "2099-01-01T00:00:00.000Z";
        write_token_file(
            tmp.path(),
            &format!(
                r#"{{"accessToken":"at","refreshToken":"rt","expiresAt":"{future_iso}","clientIdHash":"missing123"}}"#
            ),
        );
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        let creds = read_ide_credentials_for(&deps, false).unwrap();
        assert_eq!(creds.client_id, "");
        assert_eq!(creds.client_secret, "");
    }

    #[test]
    fn returns_none_when_access_token_missing() {
        let tmp = TempDir::new().unwrap();
        let future_iso = "2099-01-01T00:00:00.000Z";
        write_token_file(
            tmp.path(),
            &format!(r#"{{"refreshToken":"rt","expiresAt":"{future_iso}"}}"#),
        );
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        assert!(read_ide_credentials_for(&deps, false).is_none());
    }

    #[test]
    fn returns_none_when_refresh_token_missing() {
        let tmp = TempDir::new().unwrap();
        let future_iso = "2099-01-01T00:00:00.000Z";
        write_token_file(
            tmp.path(),
            &format!(r#"{{"accessToken":"at","expiresAt":"{future_iso}"}}"#),
        );
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        assert!(read_ide_credentials_for(&deps, false).is_none());
    }

    #[test]
    fn returns_none_when_expires_at_unparseable() {
        let tmp = TempDir::new().unwrap();
        write_token_file(
            tmp.path(),
            r#"{"accessToken":"at","refreshToken":"rt","expiresAt":"not-a-date"}"#,
        );
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        assert!(read_ide_credentials_for(&deps, false).is_none());
    }
}
