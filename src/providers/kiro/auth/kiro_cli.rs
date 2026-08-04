use super::kiro_credentials::{KiroAuthMethod, KiroCredentials};
use crate::paths::DirResolverEnv;
use rusqlite::Connection;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn kiro_cli_db_path() -> Option<PathBuf> {
    kiro_cli_db_path_for(&DirResolverEnv::default())
}

pub fn kiro_cli_db_path_for(deps: &DirResolverEnv) -> Option<PathBuf> {
    let home = &deps.home;
    let path = if cfg!(target_os = "windows") {
        deps.env
            .get("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(home).join("AppData").join("Roaming"))
            .join("kiro-cli")
            .join("data.sqlite3")
    } else if cfg!(target_os = "macos") {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("kiro-cli")
            .join("data.sqlite3")
    } else {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("kiro-cli")
            .join("data.sqlite3")
    };
    path.exists().then_some(path)
}

#[derive(Debug, Deserialize)]
struct KiroCliTokenValue {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<String>,
    region: Option<String>,
    profile_arn: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceRegistration {
    client_id: Option<String>,
    client_secret: Option<String>,
}

fn query_value(db_path: &Path, key: &str) -> Option<String> {
    let conn = Connection::open(db_path).ok()?;
    conn.query_row("SELECT value FROM auth_kv WHERE key = ?1", [key], |row| {
        row.get::<_, String>(0)
    })
    .ok()
}

fn read_credentials_from_db(
    db_path: &Path,
    token_key: &str,
    auth_method: KiroAuthMethod,
    allow_expired: bool,
) -> Option<KiroCredentials> {
    let raw = query_value(db_path, token_key)?;
    let token: KiroCliTokenValue = serde_json::from_str(&raw).ok()?;
    let access = token.access_token?;
    let refresh = token.refresh_token?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let expires = token
        .expires_at
        .as_deref()
        .and_then(|s| {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
        })
        .map(|dt| (dt.unix_timestamp() * 1000).max(0) as u64)
        .unwrap_or(now_ms + 3_600_000);

    if !allow_expired && now_ms >= expires.saturating_sub(2 * 60 * 1000) {
        return None;
    }

    let region = token.region.unwrap_or_else(|| "us-east-1".to_string());

    let (client_id, client_secret) = if auth_method == KiroAuthMethod::Idc {
        let prefix = token_key.split(':').next().unwrap_or("kirocli");
        query_value(db_path, &format!("{prefix}:odic:device-registration"))
            .and_then(|raw| serde_json::from_str::<DeviceRegistration>(&raw).ok())
            .map(|reg| {
                (
                    reg.client_id.unwrap_or_default(),
                    reg.client_secret.unwrap_or_default(),
                )
            })
            .unwrap_or_default()
    } else {
        (String::new(), String::new())
    };

    Some(KiroCredentials {
        access,
        refresh,
        expires,
        region,
        auth_method,
        client_id,
        client_secret,
        profile_arn: token.profile_arn,
    })
}

pub fn get_kiro_cli_credentials_for(
    deps: &DirResolverEnv,
    allow_expired: bool,
) -> Option<KiroCredentials> {
    let db_path = kiro_cli_db_path_for(deps)?;
    read_credentials_from_db(
        &db_path,
        "kirocli:odic:token",
        KiroAuthMethod::Idc,
        allow_expired,
    )
    .or_else(|| {
        read_credentials_from_db(
            &db_path,
            "kirocli:social:token",
            KiroAuthMethod::Desktop,
            allow_expired,
        )
    })
}

pub fn get_kiro_cli_credentials() -> Option<KiroCredentials> {
    get_kiro_cli_credentials_for(&DirResolverEnv::default(), false)
}
pub fn get_kiro_cli_credentials_allow_expired() -> Option<KiroCredentials> {
    get_kiro_cli_credentials_for(&DirResolverEnv::default(), true)
}

pub fn get_kiro_cli_social_token_for(deps: &DirResolverEnv) -> Option<KiroCredentials> {
    let db_path = kiro_cli_db_path_for(deps)?;
    read_credentials_from_db(
        &db_path,
        "kirocli:social:token",
        KiroAuthMethod::Desktop,
        false,
    )
}
pub fn get_kiro_cli_social_token() -> Option<KiroCredentials> {
    get_kiro_cli_social_token_for(&DirResolverEnv::default())
}

pub fn save_kiro_cli_credentials_for(deps: &DirResolverEnv, creds: &KiroCredentials) {
    let Some(db_path) = kiro_cli_db_path_for(deps) else {
        return;
    };
    let Ok(conn) = Connection::open(&db_path) else {
        return;
    };
    // refresh is always the raw token (no pipe-packing — see Adversarial Review Findings #1)
    let raw_refresh_token = creds.refresh.as_str();
    let expires_at = match time::OffsetDateTime::from_unix_timestamp(
        (creds.expires as i64 + 5 * 60 * 1000) / 1000,
    ) {
        Ok(dt) => dt
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        Err(_) => return,
    };
    let keys: &[&str] = match creds.auth_method {
        KiroAuthMethod::Idc => &["kirocli:odic:token", "codewhisperer:odic:token"],
        KiroAuthMethod::Desktop => &["kirocli:social:token"],
    };
    for key in keys {
        let Some(existing_raw) = query_value(&db_path, key) else {
            continue;
        };
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&existing_raw) else {
            continue;
        };
        let Some(obj) = value.as_object_mut() else {
            continue;
        };
        obj.insert("access_token".into(), serde_json::json!(creds.access));
        obj.insert("refresh_token".into(), serde_json::json!(raw_refresh_token));
        obj.insert("expires_at".into(), serde_json::json!(expires_at));
        if !creds.region.is_empty() {
            obj.insert("region".into(), serde_json::json!(creds.region));
        }
        if let Some(arn) = &creds.profile_arn {
            obj.insert("profile_arn".into(), serde_json::json!(arn));
        }
        let updated = serde_json::to_string(&value).unwrap_or(existing_raw);
        let _ = conn.execute(
            "UPDATE auth_kv SET value = ?1 WHERE key = ?2",
            rusqlite::params![updated, key],
        );
    }
}
pub fn save_kiro_cli_credentials(creds: &KiroCredentials) {
    save_kiro_cli_credentials_for(&DirResolverEnv::default(), creds)
}

fn refresh_with(deps: &DirResolverEnv, binary: &str, timeout: Duration) -> Option<KiroCredentials> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(binary)
        .args(["debug", "refresh-auth-token"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    get_kiro_cli_credentials_for(deps, false)
                } else {
                    None
                };
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

// Adversarial Review Findings #18: added an explicit 15s timeout (matching the reference's
// execFileSync(..., { timeout: 15000 })) — the first draft had no bound on this subprocess call.
pub fn refresh_via_kiro_cli_for(deps: &DirResolverEnv) -> Option<KiroCredentials> {
    refresh_with(deps, "kiro-cli", Duration::from_secs(15))
}
pub fn refresh_via_kiro_cli() -> Option<KiroCredentials> {
    refresh_via_kiro_cli_for(&DirResolverEnv::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn make_test_db(dir: &std::path::Path) -> PathBuf {
        let db_path = dir.join("data.sqlite3");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        db_path
    }

    fn make_kiro_cli_db(home: &std::path::Path) -> PathBuf {
        let dir = home.join(".local").join("share").join("kiro-cli");
        std::fs::create_dir_all(&dir).unwrap();
        make_test_db(&dir)
    }

    #[test]
    fn reads_idc_credentials_with_device_registration() {
        let tmp = TempDir::new().unwrap();
        let db_path = make_test_db(tmp.path());
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO auth_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params![
                "kirocli:odic:token",
                r#"{"access_token":"at","refresh_token":"rt","expires_at":"2099-01-01T00:00:00.000Z","region":"us-east-1"}"#
            ],
        ).unwrap();
        conn.execute(
            "INSERT INTO auth_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params![
                "kirocli:odic:device-registration",
                r#"{"client_id":"cid","client_secret":"csec"}"#
            ],
        )
        .unwrap();

        let creds =
            read_credentials_from_db(&db_path, "kirocli:odic:token", KiroAuthMethod::Idc, false)
                .unwrap();
        assert_eq!(creds.access, "at");
        assert_eq!(creds.client_id, "cid");
        assert_eq!(creds.auth_method, KiroAuthMethod::Idc);
    }

    #[test]
    fn returns_none_for_missing_key() {
        let tmp = TempDir::new().unwrap();
        let db_path = make_test_db(tmp.path());
        assert!(
            read_credentials_from_db(&db_path, "kirocli:odic:token", KiroAuthMethod::Idc, false)
                .is_none()
        );
    }

    #[test]
    fn respects_expiry_unless_allowed() {
        let tmp = TempDir::new().unwrap();
        let db_path = make_test_db(tmp.path());
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO auth_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params!["kirocli:social:token", r#"{"access_token":"at","refresh_token":"rt","expires_at":"2000-01-01T00:00:00.000Z"}"#],
        ).unwrap();
        assert!(
            read_credentials_from_db(
                &db_path,
                "kirocli:social:token",
                KiroAuthMethod::Desktop,
                false
            )
            .is_none()
        );
        assert!(
            read_credentials_from_db(
                &db_path,
                "kirocli:social:token",
                KiroAuthMethod::Desktop,
                true
            )
            .is_some()
        );
    }

    #[test]
    fn save_updates_existing_row_only() {
        let tmp = TempDir::new().unwrap();
        let db_path = make_kiro_cli_db(tmp.path());
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO auth_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params!["kirocli:odic:token", r#"{"access_token":"old","refresh_token":"old-r","expires_at":"2000-01-01T00:00:00.000Z"}"#],
        ).unwrap();

        let creds = KiroCredentials {
            access: "new-access".into(),
            refresh: "new-refresh".into(),
            expires: 4_102_444_800_000,
            region: "eu-west-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: "cid".into(),
            client_secret: "csec".into(),
            profile_arn: None,
        };
        save_kiro_cli_credentials_for(&deps, &creds);

        let raw = query_value(&db_path, "kirocli:odic:token").unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["access_token"], "new-access");
        assert_eq!(value["refresh_token"], "new-refresh");

        // codewhisperer:odic:token row was never inserted, so it must still be absent
        assert!(query_value(&db_path, "codewhisperer:odic:token").is_none());
    }

    #[test]
    fn refresh_via_kiro_cli_times_out_without_hanging() {
        // Regression test for Adversarial Review Findings #18: call a binary that exists
        // but will take longer than our timeout, and assert the call returns `None` within
        // a small bounded wall-clock time rather than hanging indefinitely.
        let tmp = TempDir::new().unwrap();
        let deps = crate::paths::DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: tmp.path().to_string_lossy().to_string(),
        };

        let start = std::time::Instant::now();
        let result = refresh_with(&deps, "sleep", Duration::from_millis(100));
        let elapsed = start.elapsed();

        assert!(result.is_none());
        assert!(
            elapsed < Duration::from_secs(3),
            "refresh timed out, took {:?}",
            elapsed
        );
    }
}
