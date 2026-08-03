# Kiro Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Kiro (AWS CodeWhisperer/Q) as a fifth backend provider in claude-code-proxy, following the existing `Provider`/`CliHandlers` trait shape used by codex/kimi/cursor/grok.

**Architecture:** A new `src/providers/kiro/` module: `auth/` (three-source credential cascade — Kiro IDE token file, kiro-cli SQLite reuse, native SSO-OIDC device flow — plus refresh), `translate/` (Anthropic MessagesRequest ⇄ Kiro's alternating-history JSON protocol, including a hand-rolled JSON-object-boundary stream parser and a `<thinking>`-tag state machine), `client.rs` (async reqwest client with per-chunk timeout support), `count_tokens.rs`, and `mod.rs` wiring it all into the `Provider` trait. `Registry` gets a `kiro:` prefix rule and a static fallback model list so Kiro model IDs that collide with existing Anthropic aliases route correctly.

**Tech Stack:** Rust 2024, axum, tokio, reqwest (async, not blocking — see Global Constraints), serde/serde_json, rusqlite (new dependency).

**Reference source:** `/home/erich.oliphant/IdeaProjects/pi-provider-kiro` (TypeScript reference implementation). File/line references like `event-parser.ts:43` point there. Design doc: `file:///home/erich.oliphant/IdeaProjects/claude-code-proxy/cdocs/2026-08-03-kiro-provider-design.md`.

## Global Constraints

- New dependency `rusqlite = { version = "0.32", features = ["bundled"] }` added to the end of `[dependencies]` in `Cargo.toml` (matches the file's existing convention of appending, not alphabetizing).
- Follow the existing `Provider`/`CliHandlers` trait shape exactly (`src/provider.rs`) — no new trait methods.
- **Kiro's client uses async `reqwest::Client`, not the blocking client Kimi/Codex's buffered path use.** Reason: first-token-timeout and idle-timeout retry (design doc §5) require per-chunk wall-clock timing (race each chunk read against `tokio::time::timeout`), which a blocking client can't give without extra thread/channel plumbing. `handle_messages` is already `async fn`, so this needs no `spawn_blocking` wrapper — unlike Kimi's client, which is deliberately blocking and wrapped in `spawn_blocking`.
- Kiro's stream is **not SSE** — it's back-to-back raw JSON objects (embedded in AWS binary Event Stream framing that can contain stray `{"` sequences). Never assume `data:`-prefixed lines or newline delimiters.
- Outbound Anthropic SSE events are built as `serde_json::json!()` values and encoded via `crate::anthropic::sse::encode_sse_event(Some(event_name), &data.to_string())` — mirror `src/providers/codex/translate/stream.rs`'s `emit()` helper. There is no dedicated Anthropic-event-type enum anywhere in this codebase; don't invent one.
- Parse incoming Anthropic content blocks via `crate::providers::translate_shared::{normalize_content, ContentBlock, image_source_to_url, flatten_system_text, read_effort}` — don't hand-roll a second JSON content-block walker.
- Credentials persist via `crate::auth::FileAuthStore<T>` using the existing generic `crate::paths::provider_auth_file("kiro")` / `provider_legacy_auth_file("kiro")` helpers (already defined in `paths.rs:99,104` — no new path-helper functions needed, unlike Kimi's dedicated `kimi_auth_file()`).
- Model ID convention: this proxy and pi both use dash-separated version numbers (`claude-sonnet-4-6`); Kiro's API uses dots (`claude-sonnet-4.6`). Conversion is always via the digit-dash-digit / digit-dot-digit regex pair, never a lookup table.
- Every new source file gets inline `#[cfg(test)] mod tests` covering the behaviors specified in its task — no separate `tests/` files except the integration-level task at the end (Task 18).
- Run `just check` (or `mvnd`-equivalent — this is the Rust project's existing lint/build gate; use `cargo build` / `cargo test` per the repo's actual justfile if `just check` does't exist) before every commit. Confirm the exact command by reading `justfile` at the start of Task 1 if unfamiliar.

---

## Task 1: Kiro credential type + auth module skeleton + Kiro IDE token source

**Files:**
- Create: `src/providers/kiro/mod.rs` (stub — just `pub mod auth;` for now, filled in fully by Task 17)
- Create: `src/providers/kiro/auth/mod.rs`
- Create: `src/providers/kiro/auth/kiro_credentials.rs`
- Create: `src/providers/kiro/auth/kiro_ide.rs`
- Modify: `src/providers/mod.rs` — add `pub mod kiro;` (alphabetically after `kimi`, before `translate_shared`: `codex, cursor, grok, kimi, kiro, translate_shared`)
- Test: inline `#[cfg(test)] mod tests` in `kiro_credentials.rs` and `kiro_ide.rs`

**Interfaces:**
- Produces (used by every later auth task):
  ```rust
  // src/providers/kiro/auth/kiro_credentials.rs
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "lowercase")]
  pub enum KiroAuthMethod { Idc, Desktop }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct KiroCredentials {
      pub access: String,
      pub refresh: String,
      pub expires: u64,           // ms since epoch
      pub region: String,
      pub auth_method: KiroAuthMethod,
      #[serde(default, skip_serializing_if = "String::is_empty")]
      pub client_id: String,
      #[serde(default, skip_serializing_if = "String::is_empty")]
      pub client_secret: String,
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub profile_arn: Option<String>,
  }

  impl KiroCredentials {
      pub fn is_expired(&self, now_ms: u64) -> bool { self.expires <= now_ms }
  }
  ```
  ```rust
  // src/providers/kiro/auth/kiro_ide.rs
  pub fn read_ide_credentials(allow_expired: bool) -> Option<KiroCredentials>
  pub fn get_ide_credentials() -> Option<KiroCredentials> { read_ide_credentials(false) }
  pub fn get_ide_credentials_allow_expired() -> Option<KiroCredentials> { read_ide_credentials(true) }
  ```

**Design notes (from `kiro-ide.ts`, full file read):** Token file at `~/.aws/sso/cache/kiro-auth-token.json` (same path on all platforms — `~/.aws/sso/cache` is the AWS SSO cache dir). File shape: `{accessToken, refreshToken, expiresAt (ISO string), region?, clientIdHash?, authMethod?, provider?}`. If `clientIdHash` is present, a companion file `~/.aws/sso/cache/{clientIdHash}.json` holds `{clientId, clientSecret}` needed for refresh — read it too if it exists, tolerating read/parse failure (client_id/client_secret just stay empty in that case, matching the TS `catch { /* ignore */ }`). `expires` is stored with a 2-minute buffer subtracted from the raw `expiresAt` (`expiresAt - 2*60*1000`), same as the TS `readKiroIdeToken`. `auth_method` is always `Idc` for this source (Kiro IDE only writes IDC-flavored tokens). Reject (return `None`) if `accessToken` or `refreshToken` is missing, or — when `allow_expired` is false — if `now_ms >= expires - 2*60*1000` (the buffer is applied twice conceptually in the TS: once baked into the stored `expires`, once again as the live check margin; port this exactly — i.e. the live check in Rust is `now_ms >= expires` since `expires` already has the buffer baked in, matching `readKiroIdeToken`'s `if (!allowExpired && Date.now() >= expiresAt - 2*60*1000) return undefined` where `expiresAt` there is the *raw* un-buffered value — so the final stored `KiroCredentials.expires` field already IS `expiresAt - 2*60*1000`, and `is_expired`/live-check reuses that same buffered value with no further subtraction).

Use this proxy's existing home-dir resolution — `crate::paths::DirResolverEnv` (checks `HOME` then `USERPROFILE`) — not a new `dirs`/`home` crate, per the design doc.

- [ ] **Step 1: Read `justfile` and `Cargo.toml` to confirm the build/test/lint commands this repo actually uses**

Run: `cat justfile` (or `rg -n "^[a-z_-]+:" justfile`) — note the exact `check`/`test`/`build` recipe names for use in every later "run tests" step in this plan. Do not proceed until this is confirmed; substitute the real command names into every subsequent task's test-run steps.

- [ ] **Step 2: Write the failing test for `KiroCredentials::is_expired`**

```rust
// src/providers/kiro/auth/kiro_credentials.rs (bottom of file)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_expired_true_when_now_past_expiry() {
        let creds = KiroCredentials {
            access: "a".into(), refresh: "r".into(), expires: 1000,
            region: "us-east-1".into(), auth_method: KiroAuthMethod::Idc,
            client_id: String::new(), client_secret: String::new(), profile_arn: None,
        };
        assert!(creds.is_expired(1000));
        assert!(creds.is_expired(1001));
        assert!(!creds.is_expired(999));
    }

    #[test]
    fn serializes_auth_method_lowercase() {
        let creds = KiroCredentials {
            access: "a".into(), refresh: "r".into(), expires: 1000,
            region: "us-east-1".into(), auth_method: KiroAuthMethod::Desktop,
            client_id: String::new(), client_secret: String::new(), profile_arn: None,
        };
        let json = serde_json::to_value(&creds).unwrap();
        assert_eq!(json["authMethod"].as_str(), None); // no rename on the field itself
        assert_eq!(json["auth_method"], "desktop");
    }
}
```

- [ ] **Step 3: Run the test to verify it fails to compile (types don't exist yet)**

Run: `cargo test -p claude-code-proxy providers::kiro::auth::kiro_credentials` (adjust package name/target if `cargo test` alone works in this single-crate repo — confirm via Step 1's justfile read)
Expected: FAIL — `KiroCredentials`/`KiroAuthMethod` not found.

- [ ] **Step 4: Implement `kiro_credentials.rs`, `auth/mod.rs`, `kiro/mod.rs`, and wire into `providers/mod.rs`**

Write the struct/enum shown in Interfaces above (full file). `src/providers/kiro/auth/mod.rs`:
```rust
pub mod kiro_credentials;
pub mod kiro_ide;

pub use kiro_credentials::{KiroAuthMethod, KiroCredentials};
```
`src/providers/kiro/mod.rs`:
```rust
pub mod auth;
```
Add `pub mod kiro;` to `src/providers/mod.rs` in the alphabetical position noted in Files above.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test providers::kiro::auth::kiro_credentials`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add src/providers/kiro/mod.rs src/providers/kiro/auth/mod.rs src/providers/kiro/auth/kiro_credentials.rs src/providers/mod.rs
git commit -m "feat(kiro): add KiroCredentials type and module skeleton"
```

- [ ] **Step 7: Write the failing test for `kiro_ide::read_ide_credentials`**

Use a temp-dir-based `HOME` override (mirror however existing tests in this repo fake `HOME` for `paths.rs` — check `tests/` or `paths.rs`'s own `#[cfg(test)]` block for the established pattern, e.g. `DirResolverEnv { env: ..., home: ... }` constructed directly rather than mutating the real `HOME` env var, to keep tests parallel-safe per the `checkle-and-rust-toolchain` convention already used in this repo per its most recent commit "make configuration tests parallel-safe"). If `kiro_ide.rs`'s path resolution takes a `DirResolverEnv`-like dependency-injection parameter (preferred, for testability) rather than reading `std::env::var("HOME")` directly, structure the function as `read_ide_credentials_for(deps: &DirResolverEnv, allow_expired: bool) -> Option<KiroCredentials>` with `read_ide_credentials` as a thin wrapper calling `DirResolverEnv::default()`.

```rust
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
        write_token_file(tmp.path(), &format!(
            r#"{{"accessToken":"at","refreshToken":"rt","expiresAt":"{future_iso}","region":"eu-west-1"}}"#
        ));
        let deps = crate::paths::DirResolverEnv { env: Default::default(), home: Ok(tmp.path().to_string_lossy().to_string()) };
        let creds = read_ide_credentials_for(&deps, false).expect("should read credentials");
        assert_eq!(creds.access, "at");
        assert_eq!(creds.region, "eu-west-1");
        assert_eq!(creds.auth_method, KiroAuthMethod::Idc);
    }

    #[test]
    fn returns_none_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        let deps = crate::paths::DirResolverEnv { env: Default::default(), home: Ok(tmp.path().to_string_lossy().to_string()) };
        assert!(read_ide_credentials_for(&deps, false).is_none());
    }

    #[test]
    fn returns_none_when_expired_and_not_allowed() {
        let tmp = TempDir::new().unwrap();
        write_token_file(tmp.path(), r#"{"accessToken":"at","refreshToken":"rt","expiresAt":"2000-01-01T00:00:00.000Z"}"#);
        let deps = crate::paths::DirResolverEnv { env: Default::default(), home: Ok(tmp.path().to_string_lossy().to_string()) };
        assert!(read_ide_credentials_for(&deps, false).is_none());
        assert!(read_ide_credentials_for(&deps, true).is_some());
    }

    #[test]
    fn reads_companion_client_registration_file() {
        let tmp = TempDir::new().unwrap();
        let future_iso = "2099-01-01T00:00:00.000Z";
        write_token_file(tmp.path(), &format!(
            r#"{{"accessToken":"at","refreshToken":"rt","expiresAt":"{future_iso}","clientIdHash":"abc123"}}"#
        ));
        fs::write(
            tmp.path().join(".aws").join("sso").join("cache").join("abc123.json"),
            r#"{"clientId":"cid","clientSecret":"csecret"}"#,
        ).unwrap();
        let deps = crate::paths::DirResolverEnv { env: Default::default(), home: Ok(tmp.path().to_string_lossy().to_string()) };
        let creds = read_ide_credentials_for(&deps, false).unwrap();
        assert_eq!(creds.client_id, "cid");
        assert_eq!(creds.client_secret, "csecret");
    }
}
```

(First check `paths.rs`'s actual `DirResolverEnv` field types/visibility via `Read` before writing this — the struct shown in the earlier registry.rs/paths.rs research used `env: HashMap<String,String>` and `home: Result<String, std::env::VarError>`-shaped fields; confirm exact field names/types and adjust the test fixture construction to match precisely before proceeding.)

- [ ] **Step 8: Run to verify failure**

Run: `cargo test providers::kiro::auth::kiro_ide`
Expected: FAIL — function doesn't exist.

- [ ] **Step 9: Implement `kiro_ide.rs`**

```rust
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

fn sso_cache_dir(deps: &DirResolverEnv) -> Option<PathBuf> {
    let home = deps.home.as_ref().ok()?;
    Some(PathBuf::from(home).join(".aws").join("sso").join("cache"))
}

pub fn read_ide_credentials_for(deps: &DirResolverEnv, allow_expired: bool) -> Option<KiroCredentials> {
    let cache_dir = sso_cache_dir(deps)?;
    let token_path = cache_dir.join("kiro-auth-token.json");
    let raw = std::fs::read_to_string(&token_path).ok()?;
    let token: KiroIdeTokenFile = serde_json::from_str(&raw).ok()?;
    let access = token.access_token?;
    let refresh = token.refresh_token?;
    let expires_at_raw = token.expires_at?;
    let expires_at_ms = time::OffsetDateTime::parse(&expires_at_raw, &time::format_description::well_known::Rfc3339)
        .ok()?
        .unix_timestamp() * 1000;
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
            Some((reg.client_id.unwrap_or_default(), reg.client_secret.unwrap_or_default()))
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
```

Note: `time` crate is already a dependency (`Cargo.toml`: `time = { version = "0.3", features = ["formatting", "parsing"] }`) — confirm the `"parsing"` feature covers `Rfc3339` parsing (it does, via `time::format_description::well_known::Rfc3339`), no new dependency needed here.

- [ ] **Step 10: Run to verify pass**

Run: `cargo test providers::kiro::auth::kiro_ide`
Expected: PASS (4 tests).

- [ ] **Step 11: Add `tempfile` as available in tests (already a dev-dependency per `Cargo.toml`), run full test suite once, then commit**

```bash
cargo test providers::kiro
git add src/providers/kiro/auth/kiro_ide.rs src/providers/kiro/auth/mod.rs
git commit -m "feat(kiro): read Kiro IDE credential token file"
```

---

## Task 2: kiro-cli SQLite credential reuse

**Files:**
- Create: `src/providers/kiro/auth/kiro_cli.rs`
- Modify: `Cargo.toml` — add `rusqlite = { version = "0.32", features = ["bundled"] }`
- Modify: `src/providers/kiro/auth/mod.rs` — add `pub mod kiro_cli;`
- Test: inline in `kiro_cli.rs`

**Interfaces:**
- Consumes: `KiroCredentials`, `KiroAuthMethod` from Task 1.
- Produces:
  ```rust
  pub fn kiro_cli_db_path() -> Option<PathBuf>
  pub fn get_kiro_cli_credentials() -> Option<KiroCredentials>                  // valid (non-expired) only
  pub fn get_kiro_cli_credentials_allow_expired() -> Option<KiroCredentials>
  pub fn get_kiro_cli_social_token() -> Option<KiroCredentials>                 // desktop-flavored only
  pub fn save_kiro_cli_credentials(creds: &KiroCredentials)                     // best-effort, never errors out to caller
  pub fn refresh_via_kiro_cli() -> Option<KiroCredentials>                      // shells out: kiro-cli debug refresh-auth-token
  ```

**Design notes (from `kiro-cli.ts`, full file read):** DB path: `~/.local/share/kiro-cli/data.sqlite3` on Linux, `~/Library/Application Support/kiro-cli/data.sqlite3` on macOS, `%APPDATA%/kiro-cli/data.sqlite3` on Windows — only return `Some` if the file actually exists. Table `auth_kv(key TEXT, value TEXT)`. IDC token key `kirocli:odic:token` (note: literal typo "odic" not "oidc" — preserve exactly, it's the real key name), social/desktop token key `kirocli:social:token`. Token JSON value shape: `{access_token, refresh_token, expires_at? (ISO string), region?, profile_arn?}` — if `expires_at` missing, assume `now + 1hr`. For IDC tokens, also look up `{prefix}:odic:device-registration` (prefix = the part of the token key before the first `:`, i.e. `"kirocli"`) for `{client_id, client_secret}` needed for refresh; tolerate its absence. Preference order in `get_kiro_cli_credentials`: try IDC key first, then social key. `save_kiro_cli_credentials` only overwrites an *existing* row for the auth-method-appropriate key(s) (`idc` → `["kirocli:odic:token", "codewhisperer:odic:token"]`, `desktop` → `["kirocli:social:token"]`) — it does not insert new rows, only updates rows that already exist, matching the TS `UPDATE ... WHERE key = '...'` with no `INSERT`.

- [ ] **Step 1: Add the `rusqlite` dependency**

Edit `Cargo.toml`, append after the `jiff` line in `[dependencies]`:
```toml
rusqlite = { version = "0.32", features = ["bundled"] }
```
Run: `cargo build` — confirm it compiles with the new dependency present but unused (expect an "unused" warning is fine at this stage, or add `#[allow(dead_code)]` temporarily — actually just proceed to Step 2 immediately, the dependency will be used within this same task).

- [ ] **Step 2: Write the failing test for reading IDC credentials from a fixture SQLite DB**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn make_test_db(dir: &std::path::Path) -> PathBuf {
        let db_path = dir.join("data.sqlite3");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)", []).unwrap();
        db_path
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
            rusqlite::params!["kirocli:odic:device-registration", r#"{"client_id":"cid","client_secret":"csec"}"#],
        ).unwrap();

        let creds = read_credentials_from_db(&db_path, "kirocli:odic:token", KiroAuthMethod::Idc, false).unwrap();
        assert_eq!(creds.access, "at");
        assert_eq!(creds.client_id, "cid");
        assert_eq!(creds.auth_method, KiroAuthMethod::Idc);
    }

    #[test]
    fn returns_none_for_missing_key() {
        let tmp = TempDir::new().unwrap();
        let db_path = make_test_db(tmp.path());
        assert!(read_credentials_from_db(&db_path, "kirocli:odic:token", KiroAuthMethod::Idc, false).is_none());
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
        assert!(read_credentials_from_db(&db_path, "kirocli:social:token", KiroAuthMethod::Desktop, false).is_none());
        assert!(read_credentials_from_db(&db_path, "kirocli:social:token", KiroAuthMethod::Desktop, true).is_some());
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test providers::kiro::auth::kiro_cli`
Expected: FAIL — `read_credentials_from_db` undefined.

- [ ] **Step 4: Implement `kiro_cli.rs`**

```rust
use super::kiro_credentials::{KiroAuthMethod, KiroCredentials};
use crate::paths::DirResolverEnv;
use rusqlite::Connection;
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub fn kiro_cli_db_path() -> Option<PathBuf> {
    kiro_cli_db_path_for(&DirResolverEnv::default())
}

fn kiro_cli_db_path_for(deps: &DirResolverEnv) -> Option<PathBuf> {
    let home = deps.home.as_ref().ok()?;
    let path = if cfg!(target_os = "windows") {
        deps.env.get("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(home).join("AppData").join("Roaming"))
            .join("kiro-cli").join("data.sqlite3")
    } else if cfg!(target_os = "macos") {
        PathBuf::from(home).join("Library").join("Application Support").join("kiro-cli").join("data.sqlite3")
    } else {
        PathBuf::from(home).join(".local").join("share").join("kiro-cli").join("data.sqlite3")
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
    conn.query_row(
        "SELECT value FROM auth_kv WHERE key = ?1",
        [key],
        |row| row.get::<_, String>(0),
    ).ok()
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

    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let expires = token.expires_at
        .as_deref()
        .and_then(|s| time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())
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
            .map(|reg| (reg.client_id.unwrap_or_default(), reg.client_secret.unwrap_or_default()))
            .unwrap_or_default()
    } else {
        (String::new(), String::new())
    };

    Some(KiroCredentials {
        access, refresh, expires, region, auth_method,
        client_id, client_secret, profile_arn: token.profile_arn,
    })
}

fn get_credentials(allow_expired: bool) -> Option<KiroCredentials> {
    let db_path = kiro_cli_db_path()?;
    read_credentials_from_db(&db_path, "kirocli:odic:token", KiroAuthMethod::Idc, allow_expired)
        .or_else(|| read_credentials_from_db(&db_path, "kirocli:social:token", KiroAuthMethod::Desktop, allow_expired))
}

pub fn get_kiro_cli_credentials() -> Option<KiroCredentials> { get_credentials(false) }
pub fn get_kiro_cli_credentials_allow_expired() -> Option<KiroCredentials> { get_credentials(true) }

pub fn get_kiro_cli_social_token() -> Option<KiroCredentials> {
    let db_path = kiro_cli_db_path()?;
    read_credentials_from_db(&db_path, "kirocli:social:token", KiroAuthMethod::Desktop, false)
}

pub fn save_kiro_cli_credentials(creds: &KiroCredentials) {
    let Some(db_path) = kiro_cli_db_path() else { return };
    let Ok(conn) = Connection::open(&db_path) else { return };
    let raw_refresh_token = creds.refresh.split('|').next().unwrap_or("");
    let expires_at = match time::OffsetDateTime::from_unix_timestamp((creds.expires as i64 + 5 * 60 * 1000) / 1000) {
        Ok(dt) => dt.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        Err(_) => return,
    };
    let keys: &[&str] = match creds.auth_method {
        KiroAuthMethod::Idc => &["kirocli:odic:token", "codewhisperer:odic:token"],
        KiroAuthMethod::Desktop => &["kirocli:social:token"],
    };
    for key in keys {
        let Some(existing_raw) = query_value(&db_path, key) else { continue };
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&existing_raw) else { continue };
        let Some(obj) = value.as_object_mut() else { continue };
        obj.insert("access_token".into(), serde_json::json!(creds.access));
        obj.insert("refresh_token".into(), serde_json::json!(raw_refresh_token));
        obj.insert("expires_at".into(), serde_json::json!(expires_at));
        if !creds.region.is_empty() { obj.insert("region".into(), serde_json::json!(creds.region)); }
        if let Some(arn) = &creds.profile_arn { obj.insert("profile_arn".into(), serde_json::json!(arn)); }
        let updated = serde_json::to_string(&value).unwrap_or(existing_raw);
        let _ = conn.execute("UPDATE auth_kv SET value = ?1 WHERE key = ?2", rusqlite::params![updated, key]);
    }
}

pub fn refresh_via_kiro_cli() -> Option<KiroCredentials> {
    let status = std::process::Command::new("kiro-cli")
        .args(["debug", "refresh-auth-token"])
        .output();
    match status {
        Ok(out) if out.status.success() => get_kiro_cli_credentials(),
        _ => None,
    }
}

#[cfg(test)]
mod tests { /* as written in Step 2, plus save/refresh tests added in Step 6 below */ }
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test providers::kiro::auth::kiro_cli`
Expected: PASS (3 tests).

- [ ] **Step 6: Write and pass a test for `save_kiro_cli_credentials` (update-only, no insert)**

```rust
#[test]
fn save_updates_existing_row_only() {
    let tmp = TempDir::new().unwrap();
    let db_path = make_test_db(tmp.path());
    let conn = Connection::open(&db_path).unwrap();
    conn.execute(
        "INSERT INTO auth_kv (key, value) VALUES (?1, ?2)",
        rusqlite::params!["kirocli:odic:token", r#"{"access_token":"old","refresh_token":"old-r","expires_at":"2000-01-01T00:00:00.000Z"}"#],
    ).unwrap();

    let creds = KiroCredentials {
        access: "new-access".into(), refresh: "new-refresh|cid|csec|idc".into(),
        expires: 4_102_444_800_000, region: "eu-west-1".into(),
        auth_method: KiroAuthMethod::Idc, client_id: "cid".into(), client_secret: "csec".into(), profile_arn: None,
    };
    save_kiro_cli_credentials(&creds);

    let raw = query_value(&db_path, "kirocli:odic:token").unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["access_token"], "new-access");
    assert_eq!(value["refresh_token"], "new-refresh");

    // codewhisperer:odic:token row was never inserted, so it must still be absent
    assert!(query_value(&db_path, "codewhisperer:odic:token").is_none());
}
```

Run: `cargo test providers::kiro::auth::kiro_cli`
Expected: PASS (4 tests).

- [ ] **Step 7: Wire the module and commit**

```bash
# add `pub mod kiro_cli;` to src/providers/kiro/auth/mod.rs
cargo test providers::kiro
git add Cargo.toml Cargo.lock src/providers/kiro/auth/kiro_cli.rs src/providers/kiro/auth/mod.rs
git commit -m "feat(kiro): read and refresh credentials via kiro-cli's SQLite store"
```

---

## Task 3: Native SSO-OIDC device-code login flow

**Files:**
- Create: `src/providers/kiro/auth/device.rs`
- Modify: `src/providers/kiro/auth/mod.rs` — add `pub mod device;`
- Test: inline in `device.rs`, using a local mock HTTP server (`tests` dev-dependency check: confirm whether this repo already has a mock-HTTP crate via existing `codex/auth/test_http.rs` — reuse that pattern rather than adding a new one)

**Interfaces:**
- Consumes: `KiroCredentials`, `KiroAuthMethod` from Task 1.
- Produces:
  ```rust
  pub const BUILDER_ID_START_URL: &str = "https://view.awsapps.com/start";
  pub const SSO_SCOPES: &[&str] = &[
      "codewhisperer:completions", "codewhisperer:analysis",
      "codewhisperer:conversations", "codewhisperer:transformations", "codewhisperer:taskassist",
  ];
  pub const IDC_PROBE_REGIONS: &[&str] = &[
      "us-east-1", "eu-west-1", "eu-central-1", "us-east-2", "eu-west-2",
      "eu-west-3", "eu-north-1", "ap-southeast-1", "ap-northeast-1", "us-west-2",
  ];

  pub trait DeviceLoginCallbacks {
      fn on_progress(&self, message: &str);
      fn on_auth_prompt(&self, verification_uri_complete: &str, user_code: &str);
  }

  pub fn run_device_login_builder_id(callbacks: &dyn DeviceLoginCallbacks) -> Result<KiroCredentials, anyhow::Error>;
  pub fn run_device_login_idc(callbacks: &dyn DeviceLoginCallbacks, start_url: &str) -> Result<KiroCredentials, anyhow::Error>;
  ```

**Design notes (from `login.ts`, full file read):** Two entry points, both funnel into the same register→authorize→poll sequence, differing only in region selection: Builder ID always uses `us-east-1` with `BUILDER_ID_START_URL`; IDC probes `IDC_PROBE_REGIONS` in order with the user-supplied `start_url`, using the first region where RegisterClient + StartDeviceAuthorization both succeed.

Per-region attempt (`try_register_and_authorize`):
1. **RegisterClient**: `POST https://oidc.{region}.amazonaws.com/client/register`, headers `Content-Type: application/json`, `User-Agent: pi-cli` (reuse literally — this is what the Kiro backend expects, not this proxy's own UA), body:
   ```json
   {"clientName":"pi-cli","clientType":"public","scopes":[...SSO_SCOPES],"grantTypes":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}
   ```
   Non-2xx → treat as failure for this region (return `None`, try next region for IDC; bail immediately for Builder ID since there's only one region). Response: `{clientId, clientSecret}`.
2. **StartDeviceAuthorization**: `POST https://oidc.{region}.amazonaws.com/device_authorization`, same headers, body `{"clientId":..,"clientSecret":..,"startUrl":start_url}`. Non-2xx → same failure handling as step 1. Response: `{verificationUri, verificationUriComplete, userCode, deviceCode, interval, expiresIn}` (all camelCase on the wire — use `#[serde(rename_all = "camelCase")]`, all fields optional except `deviceCode`/`userCode`/`verificationUriComplete`, defaulting `interval`→5, `expiresIn`→600 per the TS fallback).

Polling (`poll_device_code`):
- Call `callbacks.on_auth_prompt(devAuth.verification_uri_complete, devAuth.user_code)` once, before the loop starts.
- `deadline = now + expires_in.unwrap_or(600) * 1000`ms; `base_interval_ms = interval.unwrap_or(5) * 1000`; mutable `interval_ms` starts at `base_interval_ms`.
- Loop while `now < deadline`: **always sleep `interval_ms` first** (no immediate poll), then `POST https://oidc.{region}.amazonaws.com/token`, body `{"clientId":..,"clientSecret":..,"deviceCode":..,"grantType":"urn:ietf:params:oauth:grant-type:device_code"}`.
  - Success (200, both `accessToken` and `refreshToken` present): return `KiroCredentials { refresh: format!("{refresh_token}|{client_id}|{client_secret}|idc"), access: access_token, expires: now_ms() + expires_in.unwrap_or(3600)*1000 - 5*60*1000, region, auth_method: Idc, client_id, client_secret, profile_arn: None }`. **The pipe-delimited `refresh` field format must be reproduced exactly** — it's the serialization Task 4's refresh logic parses back apart.
  - `error == "authorization_pending"`: no-op, loop continues at the same `interval_ms`.
  - `error == "slow_down"`: `interval_ms += base_interval_ms` (additive, not multiplicative).
  - Any other `error` value (e.g. `access_denied`, `expired_token`): return `Err(anyhow!("Authorization failed: {error}"))` immediately — non-retryable.
- If the loop exits via deadline without returning: `Err(anyhow!("Authorization timed out"))`.

Use `reqwest::blocking::Client` here (this is a one-shot interactive CLI login flow, not the streaming request path — no chunk-timing need, so blocking is fine and matches `kimi/auth/login.rs::run_device_login`'s shape exactly).

- [ ] **Step 1: Read `src/providers/codex/auth/test_http.rs` to confirm the existing mock-HTTP-server test pattern**

Run: `Read src/providers/codex/auth/test_http.rs` — reuse its exact helper (likely a tiny local `std::net::TcpListener`-based mock, or `httptest`/similar crate already in `[dev-dependencies]`). Do not introduce a new mocking crate if one already exists.

- [ ] **Step 2: Write the failing test for a successful Builder ID device-code flow against the mock server**

Using whatever pattern Step 1 revealed, stand up a mock OIDC server that returns canned RegisterClient/StartDeviceAuthorization/CreateToken responses, point `run_device_login_builder_id` at it via a region-URL override parameter (add an internal `run_device_login_for(oidc_base: &str, ...)` that the public function wraps with the real `https://oidc.{region}.amazonaws.com` — this is required for testability regardless, since hardcoding the real AWS host makes the function untestable). Assert the returned `KiroCredentials.refresh` matches the exact pipe-delimited format and that a `slow_down` response is retried rather than failing.

- [ ] **Step 3: Run to verify failure**

Expected: FAIL — module/functions don't exist.

- [ ] **Step 4: Implement `device.rs`** per the Design notes above, structuring internals as `try_register_and_authorize(oidc_base: &str, start_url: &str) -> Option<(String, String, DeviceAuthResponse)>` and `poll_device_code(oidc_base: &str, client_id: &str, client_secret: &str, region: &str, dev_auth: &DeviceAuthResponse, callbacks: &dyn DeviceLoginCallbacks) -> Result<KiroCredentials, anyhow::Error>`, with `run_device_login_idc` looping `IDC_PROBE_REGIONS`, firing `on_progress("Detecting your Identity Center region...")` before probing and `on_progress(&format!("Region detected: {region}"))` on the first success, and returning `Err(anyhow!("Device authorization failed in all probed regions: {regions}"))` (joined list) if every region fails.

- [ ] **Step 5: Run to verify pass, then run the full auth test suite**

Run: `cargo test providers::kiro::auth`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/providers/kiro/auth/device.rs src/providers/kiro/auth/mod.rs
git commit -m "feat(kiro): native SSO-OIDC device-code login (Builder ID + IdC)"
```

---

## Task 4: Direct token refresh (IDC + desktop) and kiro-cli fallback shellout

**Files:**
- Create: `src/providers/kiro/auth/refresh.rs`
- Modify: `src/providers/kiro/auth/mod.rs` — add `pub mod refresh;`
- Test: inline in `refresh.rs`

**Interfaces:**
- Consumes: `KiroCredentials`, `KiroAuthMethod` (Task 1); reads `credentials.refresh` (the pipe-delimited string produced by Task 3's device flow, or by `kiro_cli.rs`/`kiro_ide.rs`'s own credential construction).
- Produces:
  ```rust
  pub fn refresh_token_direct(credentials: &KiroCredentials) -> Result<KiroCredentials, anyhow::Error>;
  ```

**Design notes (from `oauth.ts::refreshKiroTokenDirect`, full function read):** Parse `credentials.refresh` by splitting on `|`. Last segment is the auth-method tag (`"idc"` or `"desktop"`); for `desktop`, the format is `{refreshToken}|desktop` (2 parts); for `idc`, it's `{refreshToken}|{clientId}|{clientSecret}|idc` (4 parts).

- **Desktop refresh**: `POST https://prod.{region}.auth.desktop.kiro.dev/refreshToken`, headers `Content-Type: application/json`, `User-Agent: pi-cli`, body `{"refreshToken": refresh_token}`. Non-2xx → `Err`. Response `{accessToken, refreshToken?, expiresIn}` — if `refreshToken` absent in the response, reuse the original `refresh_token` (rotation is optional server-side). Returns `KiroCredentials { refresh: format!("{new_or_reused_refresh}|desktop"), access: accessToken, expires: now_ms() + expiresIn*1000 - 5*60*1000, region, auth_method: Desktop, client_id: "", client_secret: "", profile_arn: None }`.
- **IDC refresh**: `POST https://oidc.{region}.amazonaws.com/token`, same headers, body `{"clientId":..,"clientSecret":..,"refreshToken":..,"grantType":"refresh_token"}`. Non-2xx → `Err`. Response `{accessToken, refreshToken, expiresIn}` (both required this time — no optional fallback). Returns `KiroCredentials { refresh: format!("{refreshToken}|{clientId}|{clientSecret}|idc"), access: accessToken, expires: now_ms()+expiresIn*1000-5*60*1000, region, auth_method: Idc, client_id, client_secret, profile_arn: None }`.

Both use `reqwest::blocking::Client` (refresh calls are infrequent, off the hot streaming path — no chunk-timing concern here, unlike `client.rs` in Task 13).

- [ ] **Step 1: Write the failing tests** — one for desktop refresh (with and without a rotated `refreshToken` in the response), one for IDC refresh, one for malformed `refresh` field (fewer than 2 pipe-delimited parts) returning `Err` without panicking. Use the same mock-server pattern confirmed in Task 3 Step 1, with an internal `refresh_token_direct_for(base_override: ...)` seam for testability exactly as in Task 3.

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `refresh.rs`** per the Design notes, splitting `credentials.refresh` via `.split('|').collect::<Vec<_>>()` and matching on `parts.last()`.

- [ ] **Step 4: Run to verify pass.**

Run: `cargo test providers::kiro::auth::refresh`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/providers/kiro/auth/refresh.rs src/providers/kiro/auth/mod.rs
git commit -m "feat(kiro): direct IDC and desktop token refresh"
```

---

## Task 5: Credential cascade orchestration — `token_store.rs` + `manager.rs`

**Files:**
- Create: `src/providers/kiro/auth/token_store.rs`
- Create: `src/providers/kiro/auth/manager.rs`
- Modify: `src/providers/kiro/auth/mod.rs` — add both modules, re-export `KiroAuthManager`
- Test: inline in both files

**Interfaces:**
- Consumes: everything from Tasks 1–4 (`KiroCredentials`, `kiro_ide::{get_ide_credentials, get_ide_credentials_allow_expired}`, `kiro_cli::{get_kiro_cli_credentials, get_kiro_cli_credentials_allow_expired, get_kiro_cli_social_token, save_kiro_cli_credentials, refresh_via_kiro_cli}`, `device::{run_device_login_builder_id, run_device_login_idc, DeviceLoginCallbacks}`, `refresh::refresh_token_direct`); `crate::auth::{AuthStorage, FileAuthStore}`; `crate::paths::{provider_auth_file, provider_legacy_auth_file}`.
- Produces (consumed by `client.rs` in Task 13 and `mod.rs` in Task 17):
  ```rust
  // token_store.rs
  pub fn file_store() -> FileAuthStore<KiroCredentials>;

  // manager.rs
  pub struct KiroAuthManager<S: AuthStorage<KiroCredentials>> {
      pub store: S,
      cached: Arc<Mutex<Option<KiroCredentials>>>,
  }
  impl<S: AuthStorage<KiroCredentials>> KiroAuthManager<S> {
      pub fn new(store: S) -> Self;
      pub fn get_auth(&self) -> Result<KiroCredentials, anyhow::Error>;      // proactive refresh if near expiry
      pub fn force_refresh(&self) -> Result<KiroCredentials, anyhow::Error>; // unconditional refresh (401/403 path)
      pub fn bootstrap_login(&self, callbacks: &dyn DeviceLoginCallbacks, preferred: KiroLoginMethod, start_url: Option<&str>) -> Result<KiroCredentials, anyhow::Error>;
      pub fn reset_cache(&self);
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum KiroLoginMethod { Auto, BuilderId, Idc }
  ```

**Design notes:**

`token_store.rs` mirrors Kimi's `file_store()` (Task-2-research item 3) but uses the **generic** path helpers instead of dedicated `kiro_auth_file()`/legacy functions (per Global Constraints — `provider_auth_file`/`provider_legacy_auth_file` already exist in `paths.rs:99,104` and take a provider-name string):
```rust
use crate::auth::FileAuthStore;
use super::kiro_credentials::KiroCredentials;

pub fn file_store() -> FileAuthStore<KiroCredentials> {
    let primary = crate::paths::provider_auth_file("kiro");
    let legacy = crate::paths::provider_legacy_auth_file("kiro");
    FileAuthStore::new(primary.to_string_lossy().to_string(), legacy.to_string_lossy().to_string())
}
```

`manager.rs`'s `get_auth()` mirrors Kimi's `KimiAuthManager::get_auth()` shape (Task-2-research item 2: check in-memory cache → load from store → refresh-margin check) but **the refresh step must consult the same 3-source cascade order the design doc specifies**, not just call `refresh_token_direct` directly. This is the single most important piece of business logic in the whole auth subsystem — port it precisely from `oauth.ts::refreshKiroToken` (already fully read):

```rust
const REFRESH_MARGIN_MS: u64 = 5 * 60 * 1000;

impl<S: AuthStorage<KiroCredentials>> KiroAuthManager<S> {
    pub fn get_auth(&self) -> Result<KiroCredentials, anyhow::Error> {
        if let Some(cached) = self.cached.lock().unwrap().clone() {
            if !cached.is_expired(now_ms() + REFRESH_MARGIN_MS) { return Ok(cached); }
        }
        let stored = self.store.load()?
            .ok_or_else(|| anyhow::anyhow!("Not authenticated. Run: claude-code-proxy kiro auth login"))?;
        *self.cached.lock().unwrap() = Some(stored.clone());
        if !stored.is_expired(now_ms() + REFRESH_MARGIN_MS) {
            return Ok(stored);
        }
        self.refresh_cascade(&stored)
    }

    pub fn force_refresh(&self) -> Result<KiroCredentials, anyhow::Error> {
        let current = self.cached.lock().unwrap().clone()
            .or(self.store.load()?)
            .ok_or_else(|| anyhow::anyhow!("Not authenticated. Run: claude-code-proxy kiro auth login"))?;
        self.refresh_cascade(&current)
    }

    fn refresh_cascade(&self, current: &KiroCredentials) -> Result<KiroCredentials, anyhow::Error> {
        // Layer 0: Kiro IDE token is the freshest source (IDE keeps it continuously refreshed) — always prefer it if valid.
        if let Some(ide) = super::kiro_ide::get_ide_credentials() {
            return self.adopt(ide);
        }
        // Layer 1: any currently-valid kiro-cli token (social preferred if present, else IDC).
        let precheck = super::kiro_cli::get_kiro_cli_social_token().or_else(super::kiro_cli::get_kiro_cli_credentials);
        if let Some(creds) = precheck {
            return self.adopt(creds);
        }
        // Layer 2: attempt our own direct refresh using the credentials we currently hold.
        match super::refresh::refresh_token_direct(current) {
            Ok(refreshed) => {
                super::kiro_cli::save_kiro_cli_credentials(&refreshed);
                self.adopt(refreshed)
            }
            Err(refresh_err) => {
                // Layer 3: kiro-cli may have rotated the refresh token concurrently — re-read its DB once.
                if let Some(retry_creds) = super::kiro_cli::get_kiro_cli_credentials() {
                    return self.adopt(retry_creds);
                }
                // Layer 4: kiro-cli may hold a newer (still-expired-to-us) refresh token; try refreshing with those.
                if let Some(expired_cli) = super::kiro_cli::get_kiro_cli_credentials_allow_expired() {
                    if expired_cli.refresh != current.refresh {
                        if let Ok(refreshed) = super::refresh::refresh_token_direct(&expired_cli) {
                            super::kiro_cli::save_kiro_cli_credentials(&refreshed);
                            return self.adopt(refreshed);
                        }
                    }
                }
                // Layer 5: graceful degradation — our buffer subtracted 5 min from the real AWS expiry,
                // so the access token may still work. Buy time rather than failing outright.
                let actual_expiry = current.expires + REFRESH_MARGIN_MS;
                if !current.access.is_empty() && now_ms() < actual_expiry {
                    let mut extended = current.clone();
                    extended.expires = actual_expiry;
                    return self.adopt(extended);
                }
                Err(refresh_err)
            }
        }
    }

    fn adopt(&self, creds: KiroCredentials) -> Result<KiroCredentials, anyhow::Error> {
        self.store.save(creds.clone())?;
        *self.cached.lock().unwrap() = Some(creds.clone());
        Ok(creds)
    }
}
```

`bootstrap_login` implements the TS `loginKiro`'s ordering for the **initial** (no-stored-credentials) case, which differs from `refresh_cascade` mainly in trying the device-code flow as the final fallback instead of returning an error:
1. If `preferred == Idc` and a `start_url` was given (or `preferred == Auto`): try `kiro_ide::get_ide_credentials()` first.
2. Else/then: try `kiro_cli::get_kiro_cli_social_token().or_else(get_kiro_cli_credentials)`.
3. Else: try silent refresh from expired IDE creds (`get_ide_credentials_allow_expired` → `refresh_token_direct`), then expired kiro-cli creds the same way (writing back via `save_kiro_cli_credentials` on success).
4. Else: run the interactive device flow — `run_device_login_idc(callbacks, start_url)` if `start_url` is `Some`, else `run_device_login_builder_id(callbacks)`.
5. On any success path, `self.adopt(creds)` before returning.

`now_ms() -> u64` is a small private helper (`SystemTime::now().duration_since(UNIX_EPOCH)...as_millis() as u64`) — same pattern as `kimi/client.rs`'s `now_ms()`.

- [ ] **Step 1: Write the failing test for `get_auth` returning a cached, non-expiring credential without touching any cascade source**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::InMemoryAuthStore;

    fn far_future_creds() -> KiroCredentials {
        KiroCredentials {
            access: "a".into(), refresh: "r|idc".into(), expires: now_ms() + 3_600_000,
            region: "us-east-1".into(), auth_method: KiroAuthMethod::Idc,
            client_id: String::new(), client_secret: String::new(), profile_arn: None,
        }
    }

    #[test]
    fn get_auth_returns_valid_stored_credentials_without_refresh() {
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        store.save(far_future_creds()).unwrap();
        let manager = KiroAuthManager::new(store);
        let result = manager.get_auth().unwrap();
        assert_eq!(result.access, "a");
    }

    #[test]
    fn get_auth_errors_clearly_when_never_authenticated() {
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::new(store);
        let err = manager.get_auth().unwrap_err();
        assert!(err.to_string().contains("claude-code-proxy kiro auth login"));
    }
}
```

(Confirm `crate::auth::InMemoryAuthStore<T>`'s exact constructor — Task-2-research item 6 noted it exists for tests but didn't give its exact `new()`/`Default` signature; check `src/auth.rs` directly and adjust.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test providers::kiro::auth::manager`
Expected: FAIL — types don't exist.

- [ ] **Step 3: Implement `token_store.rs` and the `get_auth`/`force_refresh`/`refresh_cascade`/`adopt` portion of `manager.rs`** per the Design notes (defer `bootstrap_login` to Step 6, since it depends on `device.rs`'s `DeviceLoginCallbacks` in a way worth testing separately).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test providers::kiro::auth::manager`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/providers/kiro/auth/token_store.rs src/providers/kiro/auth/manager.rs src/providers/kiro/auth/mod.rs
git commit -m "feat(kiro): credential cascade orchestration (get_auth/force_refresh)"
```

- [ ] **Step 6: Write the failing test for `bootstrap_login`'s ordering — kiro-cli credentials win over a fresh device-code flow when both are available**

```rust
#[test]
fn bootstrap_login_prefers_kiro_cli_over_device_flow() {
    // This test needs kiro_cli::get_kiro_cli_credentials to be swappable for a test double —
    // if kiro_cli.rs's functions are free functions with no injection seam (as designed in Task 2),
    // this test must instead run against a real temp-dir-backed kiro-cli DB fixture (same helper
    // pattern as Task 2 Step 2's make_test_db), with HOME/APPDATA overridden via the same
    // DirResolverEnv-injection seam used throughout — confirm kiro_cli::kiro_cli_db_path_for is
    // reachable from this test (may need `pub(crate)` visibility instead of private).
    // Assert: no network call is attempted (device flow's mock server, if wired, receives zero requests)
    // and the returned credentials match the fixture DB's values.
}
```

Adjust `kiro_cli.rs`'s visibility (`pub(crate) fn kiro_cli_db_path_for`) if needed to make this test reachable — this is a legitimate small retrofit to Task 2's file, not scope creep, since Task 2 didn't anticipate needing dependency injection from a different module's tests.

- [ ] **Step 7: Run to verify failure, implement `bootstrap_login`, run to verify pass**

Run: `cargo test providers::kiro::auth::manager`
Expected: PASS (3 tests).

- [ ] **Step 8: Commit**

```bash
git add src/providers/kiro/auth/manager.rs src/providers/kiro/auth/kiro_cli.rs
git commit -m "feat(kiro): bootstrap login cascade (IDE -> kiro-cli -> silent refresh -> device flow)"
```

---

## Task 6: Static model catalog + ID conversion

**Files:**
- Create: `src/providers/kiro/translate/mod.rs`
- Create: `src/providers/kiro/translate/models.rs`
- Modify: `src/providers/kiro/mod.rs` — add `pub mod translate;`
- Test: inline in `models.rs`

**Interfaces:**
- Produces (consumed by Task 7's dynamic discovery, Task 8's registry wiring, Task 14's request building):
  ```rust
  pub struct KiroModelMeta {
      pub id: &'static str,           // dash form, e.g. "claude-opus-4-8"
      pub name: &'static str,
      pub reasoning: bool,
      pub input_image: bool,          // true if input modalities include image
      pub context_window: u64,
      pub max_tokens: u64,
      pub first_token_timeout_ms: u64,
  }
  pub const KIRO_MODELS: &[KiroModelMeta];       // static catalog, dash-form ids — Registry::new fallback
  pub const DEFAULT_FIRST_TOKEN_TIMEOUT_MS: u64 = 90_000;

  pub fn dash_to_dot(model_id: &str) -> String;  // "claude-sonnet-4-6" -> "claude-sonnet-4.6"
  pub fn dot_to_dash(model_id: &str) -> String;  // inverse, for mapping API responses back
  pub fn resolve_api_region(sso_region: &str) -> &'static str;
  pub fn first_token_timeout_for(model_id: &str) -> u64;
  ```

**Design notes (from `models.ts`, full file read):** Static catalog, dash-form IDs, from the research (exact list — reproduce verbatim, not paraphrased):
`claude-opus-4-8, claude-opus-4-7, claude-opus-4-6, claude-opus-4-6-1m, claude-sonnet-4-6, claude-sonnet-4-6-1m, claude-opus-4-5, claude-sonnet-4-5, claude-sonnet-4, claude-haiku-4-5, deepseek-3-2, kimi-k2-5, minimax-m2-1, minimax-m2-5, glm-5, qwen3-coder-next, agi-nova-beta-1m, qwen3-coder-480b, auto`.

Only `claude-opus-4-8` and `claude-opus-4-7` set `first_token_timeout_ms: 180_000`; every other entry uses the `DEFAULT_FIRST_TOKEN_TIMEOUT_MS = 90_000` fallback (`first_token_timeout_for` looks up the const table, defaulting if not found — mirrors `firstTokenTimeoutForModel`). Context windows / max tokens per the three example entries already captured: `claude-opus-4-8` → `context_window: 1_000_000, max_tokens: 128_000, reasoning: true, input_image: true`; `claude-sonnet-4-5` → `200_000 / 65_536`, reasoning true, image true; `deepseek-3-2` → `128_000 / 8_192`, reasoning true, image **false**. For the remaining entries not individually detailed in research, use `context_window: 200_000, max_tokens: 65_536, reasoning: true, input_image: true` as the safe default **except** `auto` (`reasoning: false`, since it's a meta-selector, not a real model) — this default-filling is an explicit judgment call flagged here for the plan executor to sanity-check against `pi-provider-kiro/src/models.ts` directly (`Read` the file, it's short enough) before finalizing every entry's numbers, since research summarized only 3 of 19 entries verbatim.

`dash_to_dot`: `regex_lite::Regex::new(r"(\d)-(\d)").unwrap().replace_all(model_id, "$1.$2")` — this proxy already depends on `regex-lite` (`Cargo.toml`), no new dependency. `dot_to_dash` is the mirror: `Regex::new(r"(\d)\.(\d)").replace_all(model_id, "$1-$2")`.

`resolve_api_region` table (`API_REGION_MAP`, exact from research): SSO region → Kiro API region — `us-west-1|us-west-2|us-east-2|ap-southeast-1|ap-southeast-2|ap-northeast-1|ap-south-1 → us-east-1`; `eu-west-1|eu-west-2|eu-west-3|eu-north-1|eu-south-1|eu-south-2|eu-central-2 → eu-central-1`; anything else (including `us-east-1`/`eu-central-1` themselves, and empty) → `"us-east-1"` default, matching the TS fallback-to-input-region-or-us-east-1 behavior for unmapped regions — **note**: TS falls back to the *input* region itself if unmapped, not hardcoded `us-east-1`, except when the input is empty. Port that distinction: `if sso_region.is_empty() { "us-east-1" } else { API_REGION_MAP.get(sso_region).copied().unwrap_or(sso_region) }` — but since the Rust return type here is `&'static str` and an arbitrary unmapped `sso_region` isn't `'static`, change the signature to return `String` instead: `pub fn resolve_api_region(sso_region: &str) -> String`.

- [ ] **Step 1: Read `pi-provider-kiro/src/models.ts` directly to fill in the remaining 16 catalog entries' exact `reasoning`/`input`/`contextWindow`/`maxTokens` values** (per the Design notes above) before writing any code — this is a data-accuracy prerequisite, not a coding step.

- [ ] **Step 2: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dash_to_dot_converts_version_numbers_only() {
        assert_eq!(dash_to_dot("claude-sonnet-4-6"), "claude-sonnet-4.6");
        assert_eq!(dash_to_dot("claude-opus-4-6-1m"), "claude-opus-4.6-1m");
        assert_eq!(dash_to_dot("deepseek-3-2"), "deepseek-3.2");
        assert_eq!(dash_to_dot("auto"), "auto");
    }

    #[test]
    fn dot_to_dash_is_the_inverse() {
        assert_eq!(dot_to_dash("claude-sonnet-4.6"), "claude-sonnet-4-6");
        assert_eq!(dot_to_dash(&dash_to_dot("claude-opus-4-8")), "claude-opus-4-8");
    }

    #[test]
    fn resolve_api_region_maps_known_regions() {
        assert_eq!(resolve_api_region("us-west-2"), "us-east-1");
        assert_eq!(resolve_api_region("eu-west-1"), "eu-central-1");
        assert_eq!(resolve_api_region(""), "us-east-1");
        assert_eq!(resolve_api_region("ap-northeast-2"), "ap-northeast-2"); // unmapped, passthrough
    }

    #[test]
    fn first_token_timeout_overrides_for_large_opus_models() {
        assert_eq!(first_token_timeout_for("claude-opus-4-8"), 180_000);
        assert_eq!(first_token_timeout_for("claude-opus-4-7"), 180_000);
        assert_eq!(first_token_timeout_for("claude-sonnet-4-5"), DEFAULT_FIRST_TOKEN_TIMEOUT_MS);
        assert_eq!(first_token_timeout_for("unknown-model"), DEFAULT_FIRST_TOKEN_TIMEOUT_MS);
    }

    #[test]
    fn catalog_has_all_nineteen_models_with_unique_ids() {
        assert_eq!(KIRO_MODELS.len(), 19);
        let mut ids: Vec<&str> = KIRO_MODELS.iter().map(|m| m.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 19);
    }
}
```

- [ ] **Step 3: Run to verify failure**

Expected: FAIL — module doesn't exist.

- [ ] **Step 4: Implement `models.rs`** per the Design notes and Step 1's verified data.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test providers::kiro::translate::models`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add src/providers/kiro/translate/mod.rs src/providers/kiro/translate/models.rs src/providers/kiro/mod.rs
git commit -m "feat(kiro): static model catalog and dash/dot ID conversion"
```

---

## Task 7: Dynamic model discovery (`ListAvailableModels`)

**Files:**
- Create: `src/providers/kiro/translate/model_discovery.rs`
- Modify: `src/providers/kiro/translate/mod.rs` — add module
- Test: inline

**Interfaces:**
- Consumes: `KiroCredentials` (Task 1), `resolve_api_region`/`dot_to_dash`/`KIRO_MODELS` (Task 6).
- Produces:
  ```rust
  pub struct DiscoveredModel { pub id: String, pub name: String, pub reasoning: bool, pub input_image: bool, pub context_window: u64, pub max_tokens: u64 }

  pub async fn fetch_available_models(credentials: &KiroCredentials) -> Result<Vec<DiscoveredModel>, anyhow::Error>;

  pub struct ModelCache { /* Arc<RwLock<HashMap<String /* region */, Vec<DiscoveredModel>>>> */ }
  impl ModelCache {
      pub fn new() -> Self;
      pub fn get(&self, region: &str) -> Option<Vec<DiscoveredModel>>;
      pub fn set(&self, region: &str, models: Vec<DiscoveredModel>);
      pub fn model_ids(&self, region: &str) -> Vec<String>; // dash-form, falls back to KIRO_MODELS ids if cache empty
  }
  pub static MODEL_CACHE: once_cell::sync::Lazy<ModelCache> = once_cell::sync::Lazy::new(ModelCache::new);
  ```

**Design notes (from `api.ts` + `models.ts::fetchKiroModels`/`mapKiroModel`, both fully read):** `POST https://q.{api_region}.amazonaws.com/?origin=KIRO_CLI` (query-string endpoint, note: **no** `/generateAssistantResponse` path segment — that's only on the streaming endpoint used by Task 13/15). Headers: `Content-Type: application/x-amz-json-1.0`, `User-Agent: claude-code-proxy` (this proxy's own UA, not `pi-provider-kiro`'s), `Authorization: Bearer {access}`, `X-Amz-Target: AmazonCodeWhispererService.ListAvailableModels`. Body: `{"origin":"KIRO_CLI"}`. Response: `{defaultModel?: KiroModel, models: KiroModel[]}` where `KiroModel = {modelId, modelName?, description?, tokenLimits?: {maxInputTokens?, maxOutputTokens?}, supportedInputTypes?: ("TEXT"|"IMAGE")[]}`.

Mapping each `KiroModel` → `DiscoveredModel`: `id = dot_to_dash(&model.model_id)`; `name = model.model_name.unwrap_or_else(|| model.model_id.clone())`; look up a `KIRO_MODELS` entry with matching `id` as a template for `reasoning` (default `false` if no template match — matches TS `template?.reasoning ?? false`); `input_image = model.supported_input_types.map(|types| types.contains(&"IMAGE")).unwrap_or_else(|| template.map(|t| t.input_image).unwrap_or(false))`; `context_window = model.token_limits.and_then(|t| t.max_input_tokens).unwrap_or_else(|| template.map(|t| t.context_window).unwrap_or(200_000))`; `max_tokens` same pattern with `64_000` fallback (note: `64_000` here, not `65_536` — the TS fallback constant for this specific fallback path is literally `64000`, distinct from the static catalog's `65536` for some entries; preserve the discrepancy exactly, don't "fix" it).

Use **async** `reqwest::Client` here (this call happens off the streaming hot-path but there's no reason to add a second blocking client just for this — reuse whatever async client Task 13 builds if it's convenient to share, otherwise a fresh `reqwest::Client::new()` is fine since this is a one-shot request per login/cache-refresh, not per-message).

`ModelCache::model_ids(region)` returns the cached dash-form IDs for that region if present, else falls back to `KIRO_MODELS.iter().map(|m| m.id.to_string()).collect()` — this is what makes `Provider::supported_models()` (Task 17) work correctly both before and after the first successful discovery call, and it's also what Task 8's registry-routing prefix rule (`is_kiro_model`) should consult for validating arbitrary discovered IDs, not just the static list.

- [ ] **Step 1: Write the failing test for mapping a `ListAvailableModels`-shaped JSON response into `DiscoveredModel`s**, using a mock HTTP server (same pattern as Task 3) to serve a canned response body with 2 models — one matching a static catalog entry by ID (to verify template fallback fields get filled in), one with an ID not in `KIRO_MODELS` at all (to verify the `reasoning: false` / `200_000` / `64_000` no-template defaults apply).

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `model_discovery.rs`** per the Design notes, with `fetch_available_models` taking an internal `base_url_override: Option<&str>` seam for the mock-server test (mirroring Task 3/4's pattern), and `ModelCache` as a thin `RwLock<HashMap<...>>` wrapper.

- [ ] **Step 4: Write and pass a `ModelCache` unit test** (no network) verifying `model_ids()` falls back to the static catalog when nothing has been cached yet, and returns cached values after a `set()` call.

- [ ] **Step 5: Run full module test, then commit**

```bash
cargo test providers::kiro::translate::model_discovery
git add src/providers/kiro/translate/model_discovery.rs src/providers/kiro/translate/mod.rs
git commit -m "feat(kiro): dynamic model discovery via ListAvailableModels"
```

---

## Task 8: Registry routing fix + alias-provider wiring

**Files:**
- Modify: `src/registry.rs` — add `KIRO_MODELS` const (dash-form ids from Task 6, re-exported or duplicated as `&'static [&'static str]` to match the existing `KIMI_MODELS`/`GROK_MODELS` const shape used elsewhere in this file), `KIRO_PREFIX`, `is_kiro_model()`, a `"kiro"` arm in `Registry::new`'s `handlers` match, explicit `"kiro"` arms in `PlaceholderProvider::new`/`PlaceholderCli` (fixing the silent-default-to-codex footgun noted in the design doc), and a `kiro:` prefix check in `provider_for_model` before the alias branch's fallback but positioned so it still lets aliases route normally for non-prefixed requests (see exact ordering below).
- Modify: `src/config.rs` — add `AliasProvider::Kiro` variant + `as_str()` arm.
- Modify: `src/providers/kiro/translate/model_allowlist.rs` (**create** this file — new) — per-tier alias→concrete-Kiro-model mapping.
- Test: extend `registry.rs`'s existing `#[cfg(test)] mod tests` block; add inline tests to `model_allowlist.rs`.

**Interfaces:**
- Produces:
  ```rust
  // registry.rs additions
  pub const KIRO_PREFIX: &str = "kiro:";
  pub fn is_kiro_model(model: &str) -> bool; // true for "kiro:" prefix OR bare match against KIRO_MODELS/dynamic cache

  // model_allowlist.rs
  pub fn resolve_model(alias_or_id: &str) -> String; // returns a concrete Kiro model id, dash form
  ```

**Design notes — routing, ported from the design doc's already-approved fix:**

In `Registry::new`, add to the `models` `BTreeMap` construction:
```rust
models.insert("kiro".into(), crate::providers::kiro::translate::models::KIRO_MODELS.iter().map(|m| m.id.to_string()).collect());
```
and to the `handlers` match:
```rust
"kiro" => Arc::new(crate::providers::kiro::KiroProvider::new()),
```
(this arm's `KiroProvider` won't exist until Task 17 — until then, leave this task's own tests passing against the `PlaceholderProvider` path is fine for everything *except* the explicit-arm fix itself, which just needs `"kiro"` to stop falling through to the `_ =>` default; do **not** block this task on Task 17 — order the match arm now so Task 17 only has to change one line later.)

Fix the silent-default footgun in both `PlaceholderProvider::new` and `PlaceholderCli`'s dispatch (`registry.rs`'s existing `match name { "codex" => "codex", "kimi" => "kimi", "cursor" => "cursor", "grok" => "grok", _ => "codex" }` pattern, and the equivalent in `cli()`'s match on `self.name`): add `"kiro" => "kiro"` explicitly to each — this is a one-line addition per match, not a rewrite, and applies regardless of whether `KiroProvider` exists yet (a `PlaceholderProvider` named `"kiro"` should still answer as `"kiro"`, not silently as `"codex"`).

`is_kiro_model`:
```rust
pub fn is_kiro_model(model: &str) -> bool {
    if let Some(stripped) = model.strip_prefix(KIRO_PREFIX) {
        return !stripped.is_empty();
    }
    false
}
```
(Kept deliberately narrow — prefix-only. Bare, unprefixed Kiro model IDs that don't collide with `ANTHROPIC_STYLE_ALIASES` already route correctly via the existing linear scan over `self.models["kiro"]`, so `is_kiro_model` doesn't need to also check the static/dynamic catalog — that would just duplicate what the linear scan already does. Its only job is recognizing the explicit-disambiguation prefix, mirroring `is_cursor_model`'s role for the `cursor:` prefixes.)

`provider_for_model` gets one new branch, positioned **before** the `is_anthropic_alias` check (so `kiro:claude-sonnet-4-6` never gets hijacked by the alias branch, matching how a prefix is supposed to be an unconditional override):
```rust
pub fn provider_for_model(&self, raw_model: &str, session_affinity: Option<&AliasProvider>) -> Option<Arc<dyn Provider>> {
    let normalized = normalize_incoming_model(raw_model);
    if is_kiro_model(&normalized) {
        let stripped = normalized.strip_prefix(KIRO_PREFIX).unwrap_or(&normalized);
        let _ = stripped; // the stripped model id itself is extracted by the provider from body.model downstream, not here — provider_for_model only resolves *which provider*, per its existing contract (see is_cursor_model, which also doesn't strip the prefix here)
        return self.handlers.get("kiro").cloned();
    }
    if is_anthropic_alias(&normalized) {
        let target = session_affinity.unwrap_or(&self.alias_provider);
        return self.handlers.get(target.as_str()).cloned();
    }
    if is_cursor_model(&normalized) {
        return self.handlers.get("cursor").cloned();
    }
    for (name, models) in &self.models {
        if models.iter().any(|candidate| candidate == &normalized) {
            return self.handlers.get(name).cloned();
        }
    }
    None
}
```
Confirm via `Read` how `is_cursor_model`'s prefix is actually stripped downstream (likely inside `cursor`'s own `handle_messages`, reading `body.model` and stripping the prefix itself) before writing `KiroProvider::handle_messages` in Task 17 — this task only needs the routing decision correct, not the stripping.

`AliasProvider::Kiro` — add to `config.rs`:
```rust
pub enum AliasProvider { Codex, Kimi, Kiro }
impl AliasProvider {
    pub fn as_str(&self) -> &str {
        match self {
            AliasProvider::Codex => "codex",
            AliasProvider::Kimi => "kimi",
            AliasProvider::Kiro => "kiro",
        }
    }
}
```
Also check (`Read src/config.rs` in full during this task, not just the enum) whether `AliasProvider` implements `FromStr`/`clap::ValueEnum`/similar for the `--alias-provider` CLI flag parsing — if so, add the `"kiro"` arm there too; this wasn't captured in earlier research and must be verified directly before considering this task done.

`model_allowlist.rs` (new file, mirrors Kimi's `translate/model_allowlist.rs` shape but with **per-tier** mapping instead of one default, per the design doc):
```rust
use once_cell::sync::Lazy;
use std::collections::HashMap;

static ALIAS_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for alias in ["haiku", "claude-haiku-4-5", "claude-haiku-4-5-20251001"] {
        m.insert(alias, "claude-haiku-4-5");
    }
    for alias in ["sonnet", "claude-sonnet-4-6", "claude-sonnet-5"] {
        m.insert(alias, "claude-sonnet-4-6");
    }
    for alias in ["opus", "claude-opus-4-7", "claude-opus-4-8", "claude-opus-5"] {
        m.insert(alias, "claude-opus-4-8");
    }
    // No Kiro tier corresponds to "fable" — nearest available tier per the design doc's note.
    for alias in ["fable", "claude-fable-5"] {
        m.insert(alias, "claude-opus-4-8");
    }
    m
});

pub fn resolve_model(alias_or_id: &str) -> String {
    ALIAS_MAP.get(alias_or_id).map(|s| s.to_string()).unwrap_or_else(|| alias_or_id.to_string())
}
```

- [ ] **Step 1: Write the failing tests in `registry.rs`'s existing test module** — this must include a regression test proving the exact bug the design doc identified is fixed:

```rust
#[test]
fn kiro_prefix_routes_to_kiro_even_when_id_collides_with_an_alias() {
    let registry = Registry::new(AliasProvider::Codex);
    // "claude-sonnet-4-6" is BOTH a real Kiro model id AND an ANTHROPIC_STYLE_ALIASES entry —
    // the prefix must win regardless of which provider is configured as the alias target.
    let p = registry.provider_for_model("kiro:claude-sonnet-4-6", None);
    assert_eq!(p.expect("provider").name(), "kiro");
}

#[test]
fn bare_colliding_model_id_still_honors_alias_routing() {
    // Without the prefix, the existing alias-routing behavior for shared literal names is unchanged —
    // this proves the fix is additive, not a regression on existing routing semantics.
    let registry = Registry::new(AliasProvider::Codex);
    let p = registry.provider_for_model("claude-sonnet-4-6", None);
    assert_eq!(p.expect("provider").name(), "codex");
}

#[test]
fn kiro_as_alias_provider_routes_bare_aliases_to_kiro() {
    let registry = Registry::new(AliasProvider::Kiro);
    for model in ["sonnet", "opus", "haiku", "claude-sonnet-5"] {
        let p = registry.provider_for_model(model, None);
        assert_eq!(p.expect("provider").name(), "kiro", "{model} should route to kiro");
    }
}

#[test]
fn kiro_placeholder_never_silently_answers_as_codex() {
    let registry = Registry::new(AliasProvider::Codex);
    let p = registry.provider_for_model("kiro:deepseek-3-2", None).expect("provider");
    assert_eq!(p.name(), "kiro"); // fails today if the PlaceholderProvider/Cli default-to-codex bug isn't fixed
}

#[test]
fn bare_non_colliding_kiro_model_routes_without_prefix() {
    let registry = Registry::new(AliasProvider::Codex);
    let p = registry.provider_for_model("deepseek-3-2", None);
    assert_eq!(p.expect("provider").name(), "kiro");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test registry::tests`
Expected: FAIL on all 5 new tests.

- [ ] **Step 3: Implement the `registry.rs` changes** exactly as in Design notes.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test registry::tests`
Expected: PASS — including the 5 new tests and every pre-existing test in this file (`alias_routes_to_configured_provider`, `opus_4_8_routes_to_configured_provider`, `claude_5_aliases_route_to_configured_provider`, `cursor_prefix_routes`, `normalize_model_trims_hint`), confirming no regression.

- [ ] **Step 5: Implement `config.rs`'s `AliasProvider::Kiro` addition** (plus any `FromStr`/`ValueEnum` arm found during the `Read` called for in the Design notes), and its own test if the existing test suite has one for alias-provider CLI parsing (check `tests/cli.rs`).

- [ ] **Step 6: Write, fail, implement, and pass `model_allowlist.rs`'s tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_every_anthropic_alias_to_a_concrete_kiro_model() {
        for alias in ["haiku", "sonnet", "opus", "fable", "claude-sonnet-5", "claude-opus-5"] {
            let resolved = resolve_model(alias);
            assert_ne!(resolved, alias, "{alias} should resolve to a concrete model, not pass through");
        }
    }

    #[test]
    fn passes_through_ids_with_no_alias_entry() {
        assert_eq!(resolve_model("deepseek-3-2"), "deepseek-3-2");
    }
}
```

- [ ] **Step 7: Run the full workspace test suite once to confirm no cross-file regressions, then commit**

```bash
cargo test
git add src/registry.rs src/config.rs src/providers/kiro/translate/model_allowlist.rs src/providers/kiro/translate/mod.rs
git commit -m "fix(registry): route Kiro models correctly around alias collisions; add AliasProvider::Kiro"
```

---

## Task 9: Kiro history types + `build_history`

**Files:**
- Create: `src/providers/kiro/translate/transform.rs`
- Modify: `src/providers/kiro/translate/mod.rs` — add module
- Test: inline

**Interfaces:**
- Consumes: `crate::anthropic::schema::{MessagesRequest, Message}`; `crate::providers::translate_shared::{ContentBlock, normalize_content, image_source_to_url}`.
- Produces (consumed by Task 10's truncation and Task 14's request assembly):
  ```rust
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroImage { pub format: String, pub source: KiroImageSource }
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroImageSource { pub bytes: String }

  #[derive(Debug, Clone, Serialize)]
  pub struct KiroToolUse { pub name: String, #[serde(rename = "toolUseId")] pub tool_use_id: String, pub input: Value }
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroToolResult { pub content: Vec<KiroToolResultText>, pub status: KiroToolResultStatus, #[serde(rename = "toolUseId")] pub tool_use_id: String }
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroToolResultText { pub text: String }
  #[derive(Debug, Clone, Copy, Serialize)]
  #[serde(rename_all = "lowercase")]
  pub enum KiroToolResultStatus { Success, Error }
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroToolSpec { #[serde(rename = "toolSpecification")] pub tool_specification: KiroToolSpecification }
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroToolSpecification { pub name: String, pub description: String, #[serde(rename = "inputSchema")] pub input_schema: KiroInputSchema }
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroInputSchema { pub json: Value }

  #[derive(Debug, Clone, Serialize, Default)]
  pub struct KiroUserInputMessage {
      pub content: String,
      #[serde(rename = "modelId")]
      pub model_id: String,
      pub origin: String, // always "KIRO_CLI"
      #[serde(skip_serializing_if = "Option::is_none")]
      pub images: Option<Vec<KiroImage>>,
      #[serde(rename = "userInputMessageContext", skip_serializing_if = "Option::is_none")]
      pub user_input_message_context: Option<KiroUserInputMessageContext>,
  }
  #[derive(Debug, Clone, Serialize, Default)]
  pub struct KiroUserInputMessageContext {
      #[serde(rename = "toolResults", skip_serializing_if = "Option::is_none")]
      pub tool_results: Option<Vec<KiroToolResult>>,
      #[serde(skip_serializing_if = "Option::is_none")]
      pub tools: Option<Vec<KiroToolSpec>>,
  }
  #[derive(Debug, Clone, Serialize, Default)]
  pub struct KiroAssistantResponseMessage {
      pub content: String,
      #[serde(rename = "toolUses", skip_serializing_if = "Option::is_none")]
      pub tool_uses: Option<Vec<KiroToolUse>>,
  }
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroHistoryEntry {
      #[serde(rename = "userInputMessage", skip_serializing_if = "Option::is_none")]
      pub user_input_message: Option<KiroUserInputMessage>,
      #[serde(rename = "assistantResponseMessage", skip_serializing_if = "Option::is_none")]
      pub assistant_response_message: Option<KiroAssistantResponseMessage>,
  }

  pub const TOOL_RESULT_LIMIT: usize = 250_000;

  pub fn sanitize_surrogates(text: &str) -> String;
  pub fn truncate_text(text: &str, limit: usize) -> String;
  pub fn get_content_text(role: &str, content: &Value) -> String;   // getContentText port
  pub fn extract_images(role: &str, content: &Value) -> Vec<ImageSource>; // via ContentBlock::Image
  pub fn convert_images_to_kiro(images: &[ImageSource]) -> Vec<KiroImage>;
  pub fn convert_tools_to_kiro(tools: &[Value]) -> Vec<KiroToolSpec>;

  pub struct BuildHistoryResult {
      pub history: Vec<KiroHistoryEntry>,
      pub system_prepended: bool,
      pub current_msg_start_idx: usize,
  }
  pub fn build_history(messages: &[Message], model_id: &str, system_prompt: Option<&str>) -> BuildHistoryResult;
  ```

**Design notes:** This ports `transform.ts` items 2 (full read) verbatim. Key subtleties to get exactly right, since these are the parts most likely to silently misbehave:

1. **This proxy's `Message.content` is untyped `serde_json::Value`**, unlike pi's typed content-block array — so every helper here takes `&Value` and dispatches via `crate::providers::translate_shared::normalize_content(content, Value::Null)` to get a `Vec<ContentBlock>`, then matches on `ContentBlock` variants (`Text`, `Image`, `ToolUse`, `ToolResult`, `Thinking`) instead of pi's `{type: "text"|"image"|...}` tagged objects. There's no `role: "toolResult"` in this proxy's `Message` shape the way pi has — **this proxy represents tool results as `role: "user"` messages whose content array contains a `ContentBlock::ToolResult` block**, per Anthropic's actual wire format (which `translate_shared::normalize_content` already parses). So wherever the TS checks `msg.role === "toolResult"`, the Rust port must instead check `role == "user" && normalize_content(...).iter().any(|b| matches!(b, ContentBlock::ToolResult{..}))` — **and specifically, per Anthropic's format, a message is only a "pure tool-result message" if its content array consists entirely of `ToolResult` blocks** (mixed user-text + tool-result in one message is a different case Anthropic doesn't produce from Claude Code, but defensively treat a message as tool-result-shaped only when the *first* content block is a `ToolResult`, matching how Claude Code always emits tool results as their own dedicated user turn).

2. `sanitize_surrogates`: Rust strings are always valid UTF-8 (no unpaired surrogates possible in a `&str`), so **this function is a no-op passthrough** in the Rust port — `pub fn sanitize_surrogates(text: &str) -> String { text.to_string() }` with a doc comment explaining why (the TS original strips unpaired UTF-16 surrogate halves, which cannot occur in valid Rust `String`/`&str` — this isn't a missing feature, it's a non-issue in this language). Still call it at the same call sites as the TS for structural parity (makes future review/diffing against the reference easier), even though it does nothing.

3. `truncate_text(text, limit)`: **must operate on `char` boundaries, not byte indices** (unlike JS's UTF-16 code-unit `.length`/`.substring`, naive Rust byte slicing on a multi-byte UTF-8 boundary panics). Use `text.chars().count()` for the length check and `text.chars().take(half)`/`.rev().take(half).collect::<Vec<_>>().into_iter().rev()` (or `char_indices()` to find safe byte offsets) for the head/tail split. Exact literal separator: `"\n... [TRUNCATED] ...\n"`.

4. `build_history`'s `current_msg_start_idx` boundary-finding, tool-result consecutive-consumption, and the user/assistant merge rules are exactly as specified in the design doc's translation section — port `buildHistory`'s algorithm from the fully-read TS (Task-2-research item 2) line-for-line, translating the role checks per note 1 above. Pay specific attention to: the **thinking-block-prepend** quirk (`armContent = "<thinking>{t}</thinking>\n\n{armContent}"`, prepending not appending), the **assistant messages are never merged** rule (unlike consecutive user messages, which do merge), and the **`"Tool results provided."` sentinel text** used both when merging trailing tool results into a preceding `userInputMessage` and when starting a fresh one.

- [ ] **Step 1: Write the failing tests for the small helpers first** (`sanitize_surrogates`, `truncate_text`, `convert_images_to_kiro`, `convert_tools_to_kiro`) — straightforward table-driven tests mirroring the TS behavior (e.g. `truncate_text` on a 10-char string with limit 6 producing `"ab...[sep]...ij"`-shaped output using the exact separator; a multi-byte-emoji string to prove no panic on non-ASCII).

- [ ] **Step 2: Run to verify failure, implement the small helpers, run to verify pass.**

- [ ] **Step 3: Write the failing tests for `build_history`**, covering at minimum:
   - A simple single user→assistant→user exchange with no tools (baseline alternation, no merging needed).
   - Two consecutive user messages merging into one `userInputMessage` entry with `\n\n`-joined content.
   - An assistant message with a `tool_use` block followed by a user message carrying the matching `tool_result` — verify the tool result gets folded into a synthetic user entry with `"Tool results provided."` content and a populated `userInputMessageContext.toolResults`.
   - Two consecutive tool-result messages (simulating parallel tool calls) — verify both get consumed into the same merged entry and neither is emitted as a separate history entry.
   - An assistant message containing only a `thinking` block followed by a `text` block — verify the resulting `content` is `"<thinking>...</thinking>\n\n..."` with thinking prepended, not appended.
   - An empty assistant message (no text, no tool calls) — verify it's skipped entirely (no history entry emitted).
   - A `system_prompt` passed in — verify it's prepended to only the *first* user message in history, not subsequent ones.

- [ ] **Step 4: Run to verify failure, implement `build_history`, run to verify pass.**

Run: `cargo test providers::kiro::translate::transform`
Expected: PASS (all tests from Steps 1–3).

- [ ] **Step 5: Commit**

```bash
git add src/providers/kiro/translate/transform.rs src/providers/kiro/translate/mod.rs
git commit -m "feat(kiro): message transform - Kiro history types and build_history"
```

---

## Task 10: History truncation, sanitization, and synthetic tool-call repair

**Files:**
- Create: `src/providers/kiro/translate/history.rs`
- Modify: `src/providers/kiro/translate/mod.rs` — add module
- Test: inline

**Interfaces:**
- Consumes: `KiroHistoryEntry`, `KiroToolSpec` (Task 9).
- Produces (consumed by Task 14's request assembly):
  ```rust
  pub const HISTORY_LIMIT: usize = 850_000;
  pub const HISTORY_LIMIT_CONTEXT_WINDOW: u64 = 200_000;

  pub fn dynamic_history_limit(model_context_window: u64) -> usize {
      ((model_context_window as f64 / HISTORY_LIMIT_CONTEXT_WINDOW as f64) * HISTORY_LIMIT as f64) as usize
  }
  pub fn strip_history_images(history: Vec<KiroHistoryEntry>) -> Vec<KiroHistoryEntry>;
  pub fn sanitize_history(history: Vec<KiroHistoryEntry>) -> Vec<KiroHistoryEntry>;
  pub fn inject_synthetic_tool_calls(history: Vec<KiroHistoryEntry>) -> Vec<KiroHistoryEntry>;
  pub fn truncate_history(history: Vec<KiroHistoryEntry>, limit: usize) -> Vec<KiroHistoryEntry>;
  pub fn extract_tool_names_from_history(history: &[KiroHistoryEntry]) -> std::collections::HashSet<String>;
  pub fn add_placeholder_tools(declared: Vec<KiroToolSpec>, history: &[KiroHistoryEntry]) -> Vec<KiroToolSpec>;
  ```

**Design notes:** Port `history.ts` (fully read, Task-2-research item 5) exactly:

- `strip_history_images`: clears `.images` on every `user_input_message` entry (set to `None`), leaves everything else untouched.
- `sanitize_history`: (a) drop leading entries while `history[0]` has no `user_input_message`, or has one whose `user_input_message_context.tool_results` is `Some` (history must start clean); (b) rebuild via a fold — drop empty assistant entries (`content` empty AND `tool_uses` is `None`/empty); keep an assistant entry with `tool_uses` only if the immediately-following original-array entry is a user message carrying matching `tool_results` — **note this check is against the position in the array being rebuilt, matching the TS's `result[result.length-1]`/next-entry lookahead exactly, not the original pre-sanitization array** (re-read `history.ts`'s `sanitizeHistory` once more at implementation time to get the lookahead direction exactly right — the TS does a single forward pass building `result` incrementally and makes each decision by peeking at `result[result.length-1]` for tool-result entries and at the *next original* entry for tool-use entries, an asymmetric lookback/lookahead that's easy to get backwards).
- `inject_synthetic_tool_calls`: collect every `tool_use_id` referenced anywhere in `assistant_response_message.tool_uses` into a `HashSet<String>`; walk again, and for any `user_input_message` whose `tool_results` contains an entry whose `tool_use_id` isn't in that set, insert a synthetic assistant entry immediately before it: `KiroAssistantResponseMessage { content: "Tool calls were made.".into(), tool_uses: Some(orphaned.iter().map(|tr| KiroToolUse { name: "unknown_tool".into(), tool_use_id: tr.tool_use_id.clone(), input: json!({}) }).collect()) }`, then add those IDs to the valid set so later entries in the same pass don't re-flag them.
- `truncate_history(history, limit)`: `sanitized = sanitize_history(strip_history_images(history))`; `history_size = serde_json::to_string(&sanitized).unwrap().len()` (byte length of the JSON serialization — matches the TS's `JSON.stringify(...).length` character-count proxy closely enough for a heuristic budget, byte-vs-UTF16-codeunit divergence is immaterial here since this is just a size *budget*, not an exact figure); while `history_size > limit && sanitized.len() > 2`: `sanitized.remove(0)` (drop oldest), then keep removing from the front while the new front isn't a `user_input_message`, then `sanitized = sanitize_history(sanitized)` (re-repair), recompute `history_size`, loop. Finally `inject_synthetic_tool_calls(sanitized)`.
- `extract_tool_names_from_history` / `add_placeholder_tools`: collect every `name` referenced in any `tool_uses` across history; for each not already present in `declared` (matched by `tool_specification.name`), append a placeholder `KiroToolSpec { tool_specification: KiroToolSpecification { name, description: "Tool".into(), input_schema: KiroInputSchema { json: json!({}) } } }`.

- [ ] **Step 1: Write the failing tests** — one per function: `strip_history_images` clears images but preserves tool results; `sanitize_history` drops a leading orphaned-tool-result entry and drops an assistant tool-use entry whose following user entry has no matching tool result; `inject_synthetic_tool_calls` inserts exactly one synthetic entry for an orphaned tool result and none when all tool results have matching tool uses; `truncate_history` on a deliberately oversized synthetic history (build via a loop generating N large entries) shrinks below the limit while never dropping below 2 entries and never leaving a non-`user_input_message` at the front; `dynamic_history_limit` returns `850_000` for a `200_000`-context model and scales proportionally for `1_000_000`.

- [ ] **Step 2: Run to verify failure, implement `history.rs` per the Design notes (re-reading `pi-provider-kiro/src/history.ts` directly at this step, not just from research notes, given the asymmetric-lookahead subtlety flagged above), run to verify pass.**

Run: `cargo test providers::kiro::translate::history`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/providers/kiro/translate/history.rs src/providers/kiro/translate/mod.rs
git commit -m "feat(kiro): history truncation, sanitization, and orphaned-tool-call repair"
```

---

## Task 11: Kiro stream event parser (`event_parser.rs`)

**Files:**
- Create: `src/providers/kiro/translate/event_parser.rs`
- Modify: `src/providers/kiro/translate/mod.rs` — add module
- Test: inline

**Interfaces:**
- Produces (consumed by Task 15's stream orchestration):
  ```rust
  #[derive(Debug, Clone, PartialEq)]
  pub enum KiroStreamEvent {
      Content(String),
      ToolUse { name: String, tool_use_id: String, input: String, stop: Option<bool> },
      ToolUseInput { input: String },
      ToolUseStop { stop: bool },
      ContextUsage { context_usage_percentage: f64 },
      FollowupPrompt(String),
      Usage { input_tokens: Option<u64>, output_tokens: Option<u64> },
      Error { error: String, message: Option<String> },
  }

  pub struct ParseResult { pub events: Vec<KiroStreamEvent>, pub remaining: String }
  pub fn parse_kiro_events(buffer: &str) -> ParseResult;
  ```

**Design notes — this is the highest-stakes port in the whole plan; follow the exact algorithm from research item 1 (`event-parser.ts`, full file), do not simplify:**

`find_json_end(text: &str, start: usize) -> Option<usize>` — **operates on byte indices into `text`, but must be UTF-8-boundary-safe** (unlike the TS original, which indexes UTF-16 code units freely). Iterate `text[start..].char_indices()`, tracking `brace_count: i32`, `in_string: bool`, `escape_next: bool`: backslash inside a string sets `escape_next = true` and the following char is skipped for quote-toggle purposes; `"` toggles `in_string` when not preceded by an unescaped backslash; outside strings, `{` increments `brace_count`, `}` decrements it, and when it hits 0 return `Some(start + byte_offset_of_that_closing_brace)`. Return `None` if the text ends before `brace_count` reaches 0 (incomplete JSON, must wait for more bytes).

`EVENT_PATTERNS` — exact literal list, order doesn't matter for correctness (the scan takes the *minimum* index across all of them), but reproduce every entry: `{"content":`, `{"name":`, `{"input":`, `{"stop":`, `{"contextUsagePercentage":`, `{"followupPrompt":`, `{"usage":`, `{"toolUseId":`, `{"unit":`, `{"error":`, `{"Error":`, `{"message":`.

`find_next_event_start(buffer: &str, from: usize) -> Option<usize>` — for each pattern, `buffer[from..].find(pattern).map(|i| i + from)`; return the smallest `Some` value found, or `None` if every pattern misses.

`parse_kiro_event(parsed: &serde_json::Value) -> Option<KiroStreamEvent>` — dispatch in this **exact priority order** (first match wins, ports the TS if/else-if chain literally):
1. `parsed.get("content").is_some()` → `Content(parsed["content"].as_str().unwrap_or_default().to_string())`
2. `parsed.get("name").is_some() && parsed.get("toolUseId").is_some()` → `ToolUse`. Input normalization: if `parsed["input"]` is a JSON string, use it directly; else if it's a non-null object with at least one key, `serde_json::to_string(&parsed["input"])`; else `String::new()`. `stop` passed through as `parsed.get("stop").and_then(Value::as_bool)`.
3. `parsed.get("input").is_some() && parsed.get("name").is_none()` → `ToolUseInput` (same string-or-restringify normalization as above).
4. `parsed.get("stop").is_some() && parsed.get("contextUsagePercentage").is_none()` → `ToolUseStop { stop: parsed["stop"].as_bool().unwrap_or(false) }`.
5. `parsed.get("contextUsagePercentage").is_some()` → `ContextUsage`.
6. `parsed.get("followupPrompt").is_some()` → `FollowupPrompt`.
7. `parsed.get("error").is_some() || parsed.get("Error").is_some()` → `Error`. `error` field: `parsed.get("error").or_else(|| parsed.get("Error"))`, stringified if not already a JSON string, defaulting to `"unknown"` if neither key has a value. `message`: `parsed.get("message").or_else(|| parsed.get("Message")).or_else(|| parsed.get("reason")).and_then(Value::as_str).map(String::from)`.
8. `parsed.get("usage").is_some()` → `Usage { input_tokens: parsed["usage"]["inputTokens"].as_u64(), output_tokens: parsed["usage"]["outputTokens"].as_u64() }`.
9. Otherwise `None` (event silently dropped).

`parse_kiro_events(buffer: &str) -> ParseResult` — loop with `pos: usize = 0`:
1. `let Some(json_start) = find_next_event_start(buffer, pos) else { break };` — **if the loop breaks here (no more recognized event starts), the function returns with `remaining: String::new()`** — this is the "discard unrecognized trailing bytes" behavior from research item 1, and it's counterintuitive enough to get wrong by "helpfully" preserving that tail — don't. Only the *found-a-start-but-incomplete-JSON* case (next bullet) preserves bytes.
2. `let Some(json_end) = find_json_end(buffer, json_start) else { return ParseResult { events, remaining: buffer[json_start..].to_string() } };` — incomplete trailing event: return immediately, handing everything from the event's opening `{` onward back to the caller to prepend to the next chunk.
3. Parse `&buffer[json_start..=json_end]` via `serde_json::from_str::<Value>`; on success, `parse_kiro_event` it and push if `Some`; **on parse failure (brace-balanced but invalid JSON — a false-positive pattern match inside binary framing), silently continue** (no panic, no error propagated — matches the TS's swallowed `catch`).
4. `pos = json_end + 1`; loop.
5. Natural loop exit (step 1's `break`) returns `ParseResult { events, remaining: String::new() }`.

- [ ] **Step 1: Write the failing tests**, covering:
   - A buffer containing exactly one complete `{"content":"hello"}` event → one `Content("hello")` event, empty remaining.
   - A buffer with two back-to-back complete events → both parsed in order.
   - A buffer ending mid-event (`{"content":"unfinis`) → zero events, `remaining` equal to the whole partial fragment starting at its `{`.
   - A buffer with garbage bytes before a recognized pattern (simulating AWS binary framing noise, e.g. `"\x00\x01{\"conte" + r#"{"content":"ok"}"#`) → the garbage before the *first recognized pattern match* is silently skipped, not returned as `remaining` or as an error.
   - A `toolUse` event with a JSON-object (not string) `input` field → `input` in the resulting `ToolUse` is a re-stringified JSON string, not the raw object.
   - An event matching a pattern but containing invalid JSON inside the balanced braces (e.g. `{"content":,}`) → parsing continues past it without panicking and without emitting a bogus event.
   - A `stop` field co-occurring with `contextUsagePercentage` in the same object → dispatches to `ContextUsage`, not `ToolUseStop` (tests priority-order rule #4 vs #5).
   - A multi-byte UTF-8 character (e.g. `"café ☕"`) straddling a `find_json_end` scan → no panic, correct content extracted (tests the UTF-8-boundary-safety requirement explicitly, since this is the one place the Rust port's indexing model diverges from the TS original's UTF-16 assumption).

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `event_parser.rs`** per the Design notes above.

- [ ] **Step 4: Run to verify pass.**

Run: `cargo test providers::kiro::translate::event_parser`
Expected: PASS (all 8+ tests from Step 1).

- [ ] **Step 5: Commit**

```bash
git add src/providers/kiro/translate/event_parser.rs src/providers/kiro/translate/mod.rs
git commit -m "feat(kiro): Kiro stream event boundary parser"
```

---

## Task 12: `<thinking>` tag streaming state machine

**Files:**
- Create: `src/providers/kiro/translate/thinking_parser.rs`
- Modify: `src/providers/kiro/translate/mod.rs` — add module
- Test: inline

**Interfaces:**
- Produces (consumed by Task 15):
  ```rust
  #[derive(Debug, Clone)]
  pub enum ThinkingStreamEvent {
      TextStart, TextDelta(String), TextStop,
      ThinkingStart, ThinkingDelta(String), ThinkingStop,
  }

  pub struct ThinkingTagParser {
      // internal state: text_buffer, in_thinking, thinking_extracted, active_end_tag
  }
  impl ThinkingTagParser {
      pub fn new() -> Self;
      pub fn process_chunk(&mut self, chunk: &str) -> Vec<ThinkingStreamEvent>;
      pub fn finalize(&mut self) -> Vec<ThinkingStreamEvent>;
  }
  ```

**Design notes — port `thinking-parser.ts` (research item 3, full file) exactly:**

Recognized tag pairs, checked in this order (earliest match in buffer wins; ties broken by this declaration order): `<thinking>`/`</thinking>`, `<think>`/`</think>`, `<reasoning>`/`</reasoning>`, `<thought>`/`</thought>`.

`process_chunk`: append `chunk` to `text_buffer`; loop running, in order, `process_before_thinking` (if not yet in/past thinking), then `process_inside_thinking` (if now in thinking), then `process_after_thinking` (if already past thinking) — bounded by a "buffer length didn't change" check each iteration to avoid infinite-looping when nothing more can be resolved from the current buffer contents; collect and return every event emitted across all sub-calls in this `process_chunk` invocation.

`process_before_thinking`: find the earliest byte-offset occurrence of any of the 4 open tags in `text_buffer` (`str::find` on each, take the minimum `Some`). If found: emit everything before it as `TextDelta`/`TextStart` (lazily starting a text block on first emission, same as `emit_text` below), slice `text_buffer` to start right after the opening tag, record which close tag is now active, set `in_thinking = true`. If not found: compute the longest suffix of `text_buffer` that could be an in-progress prefix of *any* of the 4 open tags (check decreasing suffix lengths, from `tag.len()-1` down to 1, against each tag's own prefix — a tag can only split at a chunk boundary, so the max suffix length worth checking is `tag.len()-1`), emit everything except that ambiguous suffix as text, and leave the suffix in `text_buffer` for the next chunk. **This "longest possible tag prefix at the end of the buffer" check must be done over `char`s, not bytes**, since `<thinking>` etc. are ASCII so byte/char indices coincide for the tag literals themselves, but the *text preceding* the ambiguous suffix may contain multi-byte characters — slice at a `char_indices()` boundary, never a raw byte offset, to avoid a UTF-8 panic.

`process_inside_thinking`: same shape, searching for the single currently-active close tag instead of 4 open tags; on match, emit everything before it as `ThinkingDelta`, push `ThinkingStop`, slice past the close tag, flip `in_thinking = false, thinking_extracted = true`; **special case**: if the very next 2 chars of the remaining buffer are `"\n\n"`, strip them (swallows the conventional blank-line separator between a thinking block and the following text) before continuing the same `process_chunk` loop iteration (so `process_after_thinking` sees the already-stripped remainder). On no match, same partial-tag-suffix handling as above but against only the one active close tag.

`process_after_thinking`: once `thinking_extracted` is true, unconditionally emit the entire remaining `text_buffer` as `TextDelta` (starting a text block first if none is open yet) and clear the buffer.

`finalize()`: if `text_buffer` is non-empty and `in_thinking` is still true (stream ended without a closing tag), flush the remainder as `ThinkingDelta` and force-push `ThinkingStop` — the raw unterminated remainder is treated as thinking content, not dropped. Otherwise flush the remainder as `TextDelta` (starting a text block if needed).

Block-ordering guarantee: if plain text was already emitted (a `TextStart` happened) before a thinking block is later detected (an observed real Kiro quirk per the TS comments), thinking content must still be presented **before** the text in the final output — Task 15's caller is responsible for honoring event order by index when assembling `content_block_start`/`content_block_delta` sequences (this parser just emits events in the order it detects them; if downstream ordering needs correction, that's Task 15's `content_block_start` index-assignment responsibility, not this parser's — keep this module a pure incremental tokenizer with no knowledge of Anthropic's content-block indexing scheme).

- [ ] **Step 1: Write the failing tests**, covering:
   - Plain text with no thinking tags at all → only `TextStart`/`TextDelta` events, `thinking_extracted` never set.
   - A complete `<thinking>reasoning here</thinking>\n\nfinal answer` in one `process_chunk` call → `ThinkingStart, ThinkingDelta("reasoning here"), ThinkingStop, TextStart, TextDelta("final answer")` (verify the `\n\n` separator is swallowed, not present in the text delta).
   - The same content split across many small `process_chunk` calls, including splits that land mid-tag (e.g. one chunk ending in `<thi`, next starting with `nking>`) → identical resulting event sequence to the single-call case (this is the critical incremental-correctness test).
   - `<think>` / `</think>` (the short variant) — same behavior as `<thinking>`.
   - A stream that ends (`finalize()` called) while still inside a thinking block with no closing tag → the buffered content is flushed as `ThinkingDelta` + forced `ThinkingStop`, nothing lost.
   - A stream that ends with pending plain text and no thinking ever seen → `finalize()` flushes it as `TextDelta`.
   - Multi-byte UTF-8 content straddling a chunk boundary right at the ambiguous-tag-prefix check → no panic (mirrors event_parser's UTF-8-boundary test).

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `thinking_parser.rs`** per the Design notes.

- [ ] **Step 4: Run to verify pass.**

Run: `cargo test providers::kiro::translate::thinking_parser`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/providers/kiro/translate/thinking_parser.rs src/providers/kiro/translate/mod.rs
git commit -m "feat(kiro): thinking-tag streaming state machine"
```

---

## Task 13: Async Kiro HTTP client with per-chunk timeout support

**Files:**
- Create: `src/providers/kiro/client.rs`
- Modify: `src/providers/kiro/mod.rs` — add `pub mod client;`
- Test: inline, using the same mock-HTTP-server pattern as Task 3

**Interfaces:**
- Consumes: `KiroAuthManager` (Task 5), `KiroRequest` (produced by Task 14 — for this task, accept `&impl Serialize` or a placeholder `&Value` body so this task doesn't block on Task 14; swap to the real `KiroRequest` type in Task 14's own integration).
- Produces (consumed by Task 15):
  ```rust
  #[derive(Debug)]
  pub struct KiroError { pub status: u16, pub message: String, pub body: Option<String>, pub retryable: bool }

  pub struct KiroStreamResponse {
      inner: reqwest::Response,
  }
  impl KiroStreamResponse {
      pub async fn next_chunk(&mut self, timeout: std::time::Duration) -> ChunkOutcome;
  }
  pub enum ChunkOutcome { Bytes(bytes::Bytes), TimedOut, EndOfStream, Error(anyhow::Error) }

  pub struct KiroHttpClient {
      client: reqwest::Client,
      auth_manager: KiroAuthManager<crate::auth::FileAuthStore<KiroCredentials>>,
  }
  impl KiroHttpClient {
      pub fn new() -> Self;
      pub fn auth_manager(&self) -> &KiroAuthManager<crate::auth::FileAuthStore<KiroCredentials>>;
      pub async fn post_generate_assistant_response(
          &self,
          endpoint: &str,
          body: &impl serde::Serialize,
      ) -> Result<KiroStreamResponse, KiroError>;
      pub async fn post_list_available_models(&self, credentials: &KiroCredentials) -> Result<serde_json::Value, KiroError>;
  }
  ```

**Design notes:**

Headers for the streaming call (`AmazonCodeWhispererStreamingService.GenerateAssistantResponse`), exact from research item 7:
```
Content-Type: application/x-amz-json-1.0
Accept: application/json
Authorization: Bearer {access_token}
X-Amz-Target: AmazonCodeWhispererStreamingService.GenerateAssistantResponse
x-amzn-codewhisperer-optout: true
amz-sdk-invocation-id: {uuid}
amz-sdk-request: attempt=1; max=1
x-amzn-kiro-agent-mode: vibe
x-amz-user-agent: {ua}
user-agent: {ua}
```
where `{ua}` is a fixed literal string this proxy constructs once (doesn't need to match `pi-provider-kiro`'s exact UA string byte-for-byte — Kiro's backend doesn't appear to validate it beyond presence, per the reference just hardcoding a fixed value — use something identifying this proxy, e.g. `format!("claude-code-proxy/{} md/kiro", env!("CARGO_PKG_VERSION"))`) and `{uuid}` is freshly generated (`uuid::Uuid::new_v4()`) **per HTTP attempt**, including capacity-error retries within the same logical request (Task 15 is responsible for calling `post_generate_assistant_response` again per retry, which naturally gets a fresh UUID each call since header construction lives inside this function).

`post_generate_assistant_response`:
1. `let creds = self.auth_manager.get_auth().await.map_err(...)?;` — note `get_auth`/`force_refresh` from Task 5 are synchronous (`Result<_, _>`, not `async fn`) since they only do blocking file/SQLite I/O; call them via `tokio::task::spawn_blocking` if this async function needs to avoid blocking the executor thread, mirroring the *reason* (not the exact mechanism) Kimi wraps its blocking client in `spawn_blocking` — a small justified difference: only the auth-manager calls need `spawn_blocking` here, not the whole HTTP round-trip, since the HTTP call itself is genuinely async via `reqwest::Client`.
2. Build headers and `self.client.post(endpoint).headers(...).json(body).send().await`.
3. On network error, return `KiroError { status: 0, message: "Network error".into(), body: None, retryable: true }`.
4. On response received: `let status = resp.status().as_u16();`
   - `200..=299` → `Ok(KiroStreamResponse { inner: resp })` (do **not** read the body here — Task 15 drives the chunked read via `next_chunk`).
   - `403` → **do not auto-refresh inside this function** — return `KiroError { status: 403, retryable: true, ... }` and let Task 15's outer retry loop own the "refresh, then retry" decision (this differs from Kimi's client, which refreshes-and-retries internally; Kiro's 403 retry needs to share a retry-attempt budget with the stall/empty-stream retries, which only Task 15's outer loop can see — see design doc §5 and research item 7's exact shared-budget behavior — so this client must stay a dumb single-attempt primitive for error responses, pushing the retry *policy* entirely into Task 15).
   - Any other non-2xx: read the body via `resp.text().await.unwrap_or_default()`, check `body.contains("MONTHLY_REQUEST_COUNT")` → `retryable: false`; `body.contains("INSUFFICIENT_MODEL_CAPACITY")` → `retryable: true` but tag via a `KiroError.capacity_error: bool` field (add this field — Task 15 needs to distinguish "capacity, use the dedicated capacity-retry budget" from "generic retryable, use the outer budget"); `413` or (`400` and body contains any of `CONTENT_LENGTH_EXCEEDS_THRESHOLD`/`Input is too long`/`Improperly formed`) → `retryable: false` with a `message` this proxy's own context-overflow detection can recognize (check how Codex's `translate/request.rs` or similar signals `context_length_exceeded` today — likely a specific error message substring or status code convention — and match it, so Kiro requests that overflow context surface the same way to Claude Code as Codex's do); everything else → generic `retryable: status is 429 or 5xx` (reuse `crate::retry::should_retry_status`).

`KiroStreamResponse::next_chunk(timeout)`: `tokio::time::timeout(timeout, self.inner.chunk()).await` — `reqwest::Response::chunk()` is the async incremental-read primitive (distinct from `.bytes()`, which awaits the full body). Map: `Ok(Ok(Some(bytes)))` → `ChunkOutcome::Bytes(bytes)`; `Ok(Ok(None))` → `ChunkOutcome::EndOfStream`; `Ok(Err(e))` → `ChunkOutcome::Error(e.into())`; `Err(_elapsed)` → `ChunkOutcome::TimedOut`.

`post_list_available_models`: thin wrapper — different endpoint (`https://q.{region}.amazonaws.com/?origin=KIRO_CLI`, no `/generateAssistantResponse`), different `X-Amz-Target` (`AmazonCodeWhispererService.ListAvailableModels`), body `{"origin":"KIRO_CLI"}`, and this one *does* read the full body via `.json().await` since model discovery isn't a streaming call. **Consider whether Task 7's `model_discovery.rs` should just call this method instead of building its own client** — if so, revisit Task 7 to remove its duplicate HTTP-call code and depend on `KiroHttpClient` instead; note this as a cleanup to apply retroactively once this task lands (small, don't block Task 13 on it — flag it and do the retrofit as the first step of Task 15 or as a fast-follow, whichever the implementer judges lower-risk at the time).

- [ ] **Step 1: Write the failing test for a successful streaming POST returning chunks incrementally**, using a mock server that writes response bytes with an artificial delay between chunks (whatever primitive Task 3's mock-server research surfaced supports this — if not, this may need a small addition to that shared test helper; check before assuming it's a blocker).

- [ ] **Step 2: Write the failing test for `next_chunk` timing out** — mock server that never sends a chunk within the test's short timeout window; assert `ChunkOutcome::TimedOut`.

- [ ] **Step 3: Write the failing tests for error-body classification** — `MONTHLY_REQUEST_COUNT` in a 400 body → `retryable: false`; `INSUFFICIENT_MODEL_CAPACITY` → `retryable: true, capacity_error: true`; a plain 500 → `retryable: true, capacity_error: false`; a 403 → `status: 403, retryable: true` with no auto-refresh attempted (assert the mock server received exactly one request, not two).

- [ ] **Step 4: Run all to verify failure.**

- [ ] **Step 5: Implement `client.rs`** per the Design notes.

- [ ] **Step 6: Run to verify pass.**

Run: `cargo test providers::kiro::client`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/providers/kiro/client.rs src/providers/kiro/mod.rs
git commit -m "feat(kiro): async HTTP client with per-chunk timeout and error classification"
```

---

## Task 14: Full `KiroRequest` assembly (`request.rs`)

**Files:**
- Create: `src/providers/kiro/translate/request.rs`
- Modify: `src/providers/kiro/translate/mod.rs` — add module
- Test: inline

**Interfaces:**
- Consumes: `MessagesRequest` (Anthropic wire format), `build_history`/`BuildHistoryResult` (Task 9), `truncate_history`/`dynamic_history_limit`/`add_placeholder_tools` (Task 10), `resolve_model` (Task 8's `model_allowlist`), `dash_to_dot`/`KIRO_MODELS` (Task 6), `translate_shared::{flatten_system_text, read_effort}`.
- Produces (consumed by Task 15):
  ```rust
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroRequest {
      #[serde(rename = "conversationState")]
      pub conversation_state: KiroConversationState,
      #[serde(rename = "profileArn", skip_serializing_if = "Option::is_none")]
      pub profile_arn: Option<String>,
      #[serde(rename = "agentMode")]
      pub agent_mode: String, // always "vibe"
  }
  #[derive(Debug, Clone, Serialize)]
  pub struct KiroConversationState {
      #[serde(rename = "chatTriggerType")]
      pub chat_trigger_type: String, // "MANUAL"
      #[serde(rename = "agentTaskType")]
      pub agent_task_type: String,   // "vibe"
      #[serde(rename = "conversationId")]
      pub conversation_id: String,
      #[serde(rename = "currentMessage")]
      pub current_message: CurrentMessage,
      #[serde(skip_serializing_if = "Option::is_none")]
      pub history: Option<Vec<KiroHistoryEntry>>, // omitted entirely (not even empty array) if empty
  }
  #[derive(Debug, Clone, Serialize)]
  pub struct CurrentMessage { #[serde(rename = "userInputMessage")] pub user_input_message: KiroUserInputMessage }

  pub struct BuildRequestOptions<'a> {
      pub session_id: Option<&'a str>,
      pub reasoning_enabled: bool,
      pub thinking_budget: Option<u32>, // tokens, see budget table below
  }

  pub fn build_kiro_request(req: &MessagesRequest, opts: BuildRequestOptions) -> Result<(KiroRequest, /* current tool results for retry-context, if any */ ()), anyhow::Error>;
  ```

**Design notes:**

`conversation_id`: `opts.session_id.map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string())` — **must stay stable across Task 15's outer retry-loop re-attempts within the same incoming request** (build it once per incoming Anthropic request, pass it down, never regenerate mid-retry — matches the TS comment "stable across outer retries").

Thinking-mode system-prompt prefix (only when `opts.reasoning_enabled`), exact budget table from research item 7: `xhigh` → `50_000`, `high` → `30_000`, `medium` → `20_000`, default → `10_000`. This proxy's effort-level string comes from `translate_shared::read_effort(req)` (already returns e.g. `"xhigh"`/`"high"`/etc., or `None`) — map it to a budget via this table, then prepend to whatever `system_prompt` string gets passed into `build_history`:
```
<thinking_mode>enabled</thinking_mode><max_thinking_length>{budget}</max_thinking_length>
```
prepended *before* the actual system prompt text (concatenate, don't replace).

Model resolution: `let requested = req.model.as_deref().unwrap_or("auto"); let resolved_alias = model_allowlist::resolve_model(requested); let kiro_model_id = models::dash_to_dot(&resolved_alias);` — this `kiro_model_id` (dot form) is what goes into every `KiroUserInputMessage.model_id` field (both history entries and the current message).

Current-message assembly (the part `buildHistory` in Task 9 deliberately leaves undone — everything from `BuildHistoryResult.current_msg_start_idx` onward): take `req.messages[current_msg_start_idx..]`, and branch on the **first** message's role/content shape (mirrors `stream.ts`'s inline logic, research item 7):
- If it's tool-result-shaped (per Task 9 note 1's role-detection rule): collect it and every immediately-following tool-result-shaped message into `current_tool_results: Vec<KiroToolResult>` (same truncate-to-`TOOL_RESULT_LIMIT` + status/toolUseId shape as `build_history`'s tool-result handling); `current_content = "Tool results provided."`.
- If the first message is `role: "assistant"` with pending tool-use blocks (a resumed/continued turn): merge its tool uses into history's last entry if that entry is already an `assistant_response_message`, else push a new one; then treat any following tool-result messages the same as the bullet above; `current_content` is `"Tool results provided."` if tool results follow, else `"Please proceed with the task."` if there's nothing else to say.
- Otherwise (plain user message): `current_content = get_content_text(...)`, with the system prompt prepended only if `build_history` reports `system_prepended == false` (i.e., there was no prior user message in history to attach it to, so it must go on the current message instead).

If `crate::providers::translate_shared`'s truncation-notice detection exists already for another provider (check whether a `wasPreviousResponseTruncated`-equivalent exists anywhere in this codebase, e.g. for Codex's compaction handling — `codex/compaction.rs` looked relevant per the earlier directory listing) — reuse it if so; if this proxy has no equivalent concept, **skip porting `TRUNCATION_NOTICE` prepending entirely for v1** and note it as a deliberate scope-trim (it's a minor UX nicety in the reference, not correctness-critical, and inventing a new cross-cutting "was the previous response truncated" signal in this proxy is out of scope for a single-provider port).

Tools: `convert_tools_to_kiro(req.extra.get("tools").and_then(Value::as_array).unwrap_or(&vec![]))` then `add_placeholder_tools(...)` against the full (truncated) history, per Task 10.

`history: Option<...>` — `Some(truncated_history)` only if non-empty, `None` otherwise, matching the TS's "omit history key entirely when empty" behavior (not an empty array).

- [ ] **Step 1: Write the failing tests**, covering:
   - A simple single-turn request (one user message, no history) → `history: None`, `current_message.user_input_message.content` equals the user text, `model_id` in dot form.
   - A multi-turn request with prior exchanges → `history: Some(...)` populated via `build_history`, and `conversation_state.current_message` built from only the trailing unconsumed messages.
   - A request with `reasoning_enabled: true` and effort `"xhigh"` → the thinking-mode prefix with `50000` appears at the start of whatever ends up as the system-prompt-bearing content.
   - A request whose `model` is a bare Anthropic alias (`"sonnet"`) → resolves through `model_allowlist::resolve_model` then `dash_to_dot` to the correct concrete dot-form Kiro model ID.
   - A request with declared tools plus history referencing tool names not in that declared list → `add_placeholder_tools` fills the gap (assert the placeholder appears in the final tool spec list).
   - `conversation_id` stability: calling `build_kiro_request` twice with the same `opts.session_id` produces the same `conversation_id` both times; omitting `session_id` produces a fresh UUID each call.

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `request.rs`** per the Design notes, wiring together every prior translate/ module.

- [ ] **Step 4: Run to verify pass.**

Run: `cargo test providers::kiro::translate::request`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/providers/kiro/translate/request.rs src/providers/kiro/translate/mod.rs
git commit -m "feat(kiro): assemble full KiroRequest from Anthropic MessagesRequest"
```

---

## Task 15: Stream orchestration — retry loops and Anthropic SSE emission

**Files:**
- Create: `src/providers/kiro/translate/stream.rs`
- Modify: `src/providers/kiro/translate/mod.rs` — add module
- Test: inline, using the mock-server pattern

**Interfaces:**
- Consumes: everything — `KiroHttpClient` (Task 13), `build_kiro_request`/`BuildRequestOptions` (Task 14), `parse_kiro_events`/`KiroStreamEvent` (Task 11), `ThinkingTagParser`/`ThinkingStreamEvent` (Task 12), `first_token_timeout_for`/`KiroModelMeta` (Task 6), `crate::anthropic::sse::encode_sse_event`.
- Produces (consumed by Task 17's `mod.rs`):
  ```rust
  pub async fn stream_kiro_response(
      client: &KiroHttpClient,
      model: &KiroModelMeta,
      req: &MessagesRequest,
      message_id: &str,
      session_id: Option<&str>,
  ) -> Result<Vec<u8>, anyhow::Error>; // complete Anthropic SSE byte buffer — buffered translation, same output shape as codex/translate/stream.rs's translate_stream_bytes, even though the *input* side reads Kiro incrementally for timeout purposes
  ```

**Design notes — this ports `stream.ts`'s orchestration (research item 7) and emits via the `codex/translate/stream.rs` pattern (research item 7 from the Rust-side agent) simultaneously. Structure as nested loops exactly matching the reference's control flow, since the retry-budget-sharing rules are easy to get subtly wrong:**

**Outer loop** (`retry_count: u32`, `max_retries: u32 = 3`, shared across 403 retries, stall retries, AND empty/echo-response retries — confirmed in research item 7 as one shared counter, not three separate ones):
1. Rebuild the full request from scratch every outer iteration: `build_kiro_request(req, opts)` (this recomputes history/current-message on every retry, not just resends the same payload — matches the reference exactly, and matters because a stall/timeout on attempt 1 might have been mid-way through a huge tool-result payload the model choked on).
2. Reset per-attempt state: `output` content-block accumulator, `text_block_index`, `thinking_parser` (fresh `ThinkingTagParser::new()`), `sent_any_content_block`, `capacity_retry_count = 0` (resets every outer iteration, per research item 7's explicit note).
3. **Inner loop** (HTTP send + capacity retry, own counter `capacity_retry_count`, `capacity_max_retries: u32 = 3`, base delay 5000ms, cap 30_000ms — distinct backoff params from the outer loop's, don't conflate):
   - Call `client.post_generate_assistant_response(endpoint, &kiro_request).await`.
   - On `Err(e)` where `e.status == 403`: if `retry_count < max_retries`, refresh via `client.auth_manager().force_refresh()` (async-wrapped per Task 13's note), sleep `exponential_backoff(retry_count, 500, 10_000)`, `retry_count += 1`, **break the inner loop to re-enter the outer loop** (rebuilds the request too — matches research item 7's "shares the outer retry_count budget" finding). Else propagate the error.
   - On `Err(e)` where `e.capacity_error && capacity_retry_count < capacity_max_retries`: sleep `exponential_backoff(capacity_retry_count, 5_000, 30_000)`, `capacity_retry_count += 1`, **continue the inner loop** (resend the *same* request — capacity retries do not rebuild history/current-message, unlike every other retry path here).
   - On `Err(e)` where `!e.retryable` (covers `MONTHLY_REQUEST_COUNT`, exhausted capacity retries, and the too-big/context-overflow case): propagate immediately as the terminal error — **no further retry of any kind**, this is intentionally not folded into the outer loop's budget (research item 7: prevents any caller-side generic retry from misinterpreting these as ordinary retryable errors).
   - On `Ok(stream_response)`: proceed to the read loop below.
4. **Chunked read loop**: `buffer: String = String::new()`, `first_token_received = false`.
   - First read: race against `first_token_timeout_for(model.id)` ms (180_000 for opus-4-8/4-7, else `DEFAULT_FIRST_TOKEN_TIMEOUT_MS = 90_000`). `ChunkOutcome::TimedOut` on this first read → `first_token_timed_out = true`, break the read loop (falls through to the unified stall-retry check below).
   - Every subsequent read races against `IDLE_TIMEOUT = 300_000`ms (5 minutes, fixed regardless of model), reset on every chunk received (including chunks that decode to zero parsed events, e.g. mid-way through a large tool-call JSON payload — the timer cares about *byte* arrival, not *event* arrival).
   - On `ChunkOutcome::Bytes(bytes)`: `buffer.push_str(&String::from_utf8_lossy(&bytes))`; `first_token_received = true`; `let ParseResult { events, remaining } = parse_kiro_events(&buffer); buffer = remaining;` for each event, route per the Event routing section below.
   - On `ChunkOutcome::EndOfStream`: break the read loop normally (successful completion).
   - On `ChunkOutcome::TimedOut` (idle case) or `ChunkOutcome::Error(_)`: set `idle_cancelled`/`stream_error` respectively, break the read loop.
5. **Unified stall/error retry check** (after the read loop, only reached for the first-token-timeout / idle-timeout / stream-error exits, not normal completion or the 403/capacity paths already handled above): if any of `first_token_timed_out || idle_cancelled || stream_error.is_some()`: if `retry_count < max_retries`, sleep `exponential_backoff(retry_count, 1_000, 10_000)`, `retry_count += 1`, continue the **outer** loop. Else return `Err` with the appropriate message (`"Kiro API stream error after max retries: {e}"` or `"Kiro API error: {first-token|idle} timeout after max retries"`).
6. **Empty-stream / echo-loop check** (only reached on a clean `EndOfStream` completion): `has_text = text_block_index.is_some() && !accumulated_text.is_empty()`; `is_echo_loop = has_text && !saw_any_tool_calls && ECHO_REGEX.is_match(&accumulated_text)` where `ECHO_REGEX` matches (case-insensitive) `^\s*(continue|\.+)\s*$`. If `(!has_text && !saw_any_tool_calls) || is_echo_loop`: if `retry_count < max_retries`, reset `output` content array and `text_block_index`, sleep `exponential_backoff(retry_count, 1_000, 10_000)`, `retry_count += 1`, continue outer loop. Else: for the echo-loop case, blank the text content and log a warning (proceed to emit a `stop` with empty text, don't error); for the plain-empty case, log a warning and proceed to normal finalization with `stop_reason` computed as below.
7. On a clean, non-empty, non-echo completion: fall through to finalization.

**Event routing** (inside the chunked-read loop, per `KiroStreamEvent` variant):
- `Content(text)`: if reasoning enabled, `thinking_parser.process_chunk(&text)` → route each resulting `ThinkingStreamEvent` to `content_block_start`/`content_block_delta` emission (lazily opening a `thinking` or `text` block per Task 12's ordering guarantee — thinking block must get an earlier `index` than any text block emitted after it was detected, even if text was emitted first chronologically: if a `ThinkingStart` arrives after a `text` block is already open, this function must retroactively insert the thinking block's `content_block_start` at the *text block's original index* and shift the text block (and any already-emitted delta events referencing its old index) to `index + 1` — since Anthropic's SSE protocol has no "insert a block before an already-started one" primitive, the pragmatic port here is: **buffer content-block-start emission until the first `Content` event is fully routed through the thinking parser once**, so the thinking-before-text ordering from Task 12 is settled before this function commits to any index numbering, rather than trying to retroactively rewrite already-sent SSE bytes. If reasoning is disabled, route directly to a plain `text` block, no thinking-parser involvement.
- `ToolUse { name, tool_use_id, input, stop }`: flush any open text/thinking block (`content_block_stop`), open a new `tool_use` content block (`content_block_start` with `{"type":"tool_use","id":tool_use_id,"name":name,"input":{}}`), emit `input` (if non-empty) as an `input_json_delta`. If `stop == Some(true)`, immediately close the block too. Track `saw_any_tool_calls = true`, `emitted_tool_calls += 1`.
- `ToolUseInput { input }`: append to the currently-open tool_use block's accumulated JSON via another `input_json_delta`.
- `ToolUseStop { .. }`: close the currently-open tool_use content block.
- `ContextUsage { context_usage_percentage }`: record it (`received_context_usage = true`); compute `estimated_input_tokens = (context_usage_percentage / 100.0 * model.context_window as f64) as u64` for later usage reporting if the `Usage` event never arrives.
- `FollowupPrompt(_)`: no Anthropic equivalent — drop (matches the reference not surfacing this to the client either, it's Kiro-internal UI hinting).
- `Usage { input_tokens, output_tokens }`: overwrite the context-usage-derived estimate if present.
- `Error { error, message }`: treat as a mid-stream error — set `stream_error = Some(format!("{error}: {message:?}"))`, break the read loop (feeds into step 5 above).

**Finalization** (after Step 6/7 above resolves cleanly): flush any still-open content block (`content_block_stop`); finalize the thinking parser (`thinking_parser.finalize()`, route any trailing events same as above); `stop_reason`: `if !received_context_usage && emitted_tool_calls == 0 { "end_turn" — actually match the TS's "length" mapping: research item 7 says stopReason = "length" for this branch, which in Anthropic's vocabulary is the closest analog to "the model didn't finish cleanly and we have no context-usage confirmation it completed normally" } else if emitted_tool_calls > 0 { "tool_use" } else { "end_turn" }`. Compute final usage: `output_tokens` from the `Usage` event if seen, else a local heuristic estimate over the accumulated text + tool-call JSON (reuse `kimi/count_tokens.rs`'s `approx_token_count`-style heuristic rather than inventing a second one — call into Task 16's estimator here, or factor the shared piece out if Task 16 hasn't landed yet; order these two tasks so this dependency resolves cleanly, or write a small shared heuristic directly in this file and note it as intentionally duplicating a few lines from Task 16 rather than blocking on it). Emit `message_delta` (`stop_reason`, usage) then `message_stop`, matching `codex/translate/stream.rs`'s `emit()` pattern exactly (`serde_json::json!()` + `encode_sse_event`) — reuse that file's `MessageMetadata`/`OpenBlock`/`emit` shapes directly rather than inventing parallel ones; consider whether they can be moved to `translate_shared.rs` and shared across providers as a small refactor, but don't block this task on that refactor — duplicating ~40 lines of emission plumbing here is an acceptable, explicitly-noted trade-off for v1.

- [ ] **Step 1: Write the failing test for the simple happy path** — mock server streams a handful of `{"content":"..."}` chunks then closes; assert the returned SSE byte buffer, when parsed back via `crate::anthropic::sse::parse_sse_events`, contains `message_start` → `content_block_start` (text) → one or more `content_block_delta` (text_delta) → `content_block_stop` → `message_delta` (stop_reason `"end_turn"`) → `message_stop`, and that the concatenated `text_delta` values reconstruct the original content.

- [ ] **Step 2: Write the failing test for a tool-use response** — mock server streams a `{"name":..,"toolUseId":..,"input":"{}"}` event and a `{"stop":true}` follow-up; assert `content_block_start` (type `tool_use`) appears and `stop_reason` is `"tool_use"`.

- [ ] **Step 3: Write the failing test for reasoning content** — mock server streams `{"content":"<thinking>reasoning</thinking>\n\nanswer"}` with `reasoning_enabled: true`; assert a `thinking`-type content block precedes the `text`-type block in the output SSE sequence.

- [ ] **Step 4: Write the failing test for first-token-timeout retry** — mock server delays its first chunk beyond a test-injected short timeout (this task's `stream_kiro_response` needs a `first_token_timeout_override`/`idle_timeout_override` test seam, since the real 90s/300s values are far too slow for a unit test — add these as optional parameters threaded through from a `#[cfg(test)]`-only entry point, or a `StreamTimeouts { first_token_ms: u64, idle_ms: u64 }` struct parameter with a `Default` matching production values); assert the mock server receives exactly 2 requests (one failed attempt + one retry) and the second succeeds.

- [ ] **Step 5: Write the failing test for 403 → refresh → retry** — mock server returns 403 once then 200; assert exactly 2 requests received and the auth manager's refresh path was exercised (e.g. via a fixture `KiroAuthManager` backed by an `InMemoryAuthStore` whose stored credentials change between the two requests, proving refresh actually ran).

- [ ] **Step 6: Write the failing test for `INSUFFICIENT_MODEL_CAPACITY` retry not consuming the outer budget** — mock server returns the capacity-error body twice then succeeds; assert 3 requests received and, separately (a second sub-test), that a capacity error exhausting its own 3-retry budget throws immediately without ever touching the outer `retry_count` (assert via a case where `max_retries` for the outer loop is deliberately set to 0 via test-only override, capacity retries still work up to their own budget).

- [ ] **Step 7: Write the failing test for `MONTHLY_REQUEST_COUNT` being non-retryable** — mock server returns it once; assert exactly 1 request received and the function returns `Err` immediately.

- [ ] **Step 8: Write the failing test for the empty-response retry** — mock server returns a stream with zero content and zero tool calls twice, then real content on the third attempt; assert 3 requests received.

- [ ] **Step 9: Run all to verify failure.**

- [ ] **Step 10: Implement `stream.rs`** per the Design notes — this is the largest single implementation step in the plan; budget real time for it, and lean on `codex/translate/stream.rs` open in a second editor pane as a structural reference for the SSE-emission half while writing the Kiro-specific retry/routing half fresh.

- [ ] **Step 11: Run to verify pass.**

Run: `cargo test providers::kiro::translate::stream`
Expected: PASS (all 8 tests from Steps 1–8).

- [ ] **Step 12: Commit**

```bash
git add src/providers/kiro/translate/stream.rs src/providers/kiro/translate/mod.rs
git commit -m "feat(kiro): stream orchestration with retry budgets and Anthropic SSE emission"
```

---

## Task 16: Heuristic token counting

**Files:**
- Create: `src/providers/kiro/count_tokens.rs`
- Modify: `src/providers/kiro/mod.rs` — add `pub mod count_tokens;`
- Test: inline

**Interfaces:**
- Consumes: `MessagesRequest`; `translate_shared::{normalize_content, ContentBlock}`.
- Produces:
  ```rust
  pub fn count_tokens(req: &MessagesRequest) -> u64;
  pub fn approx_token_count(text: &str) -> u64; // also used by Task 15's finalization fallback
  ```

**Design notes:** This is an honest estimate, not a real tokenizer — say so in a doc comment on `count_tokens`, per the design doc's explicit scope note (Kiro only reports `contextUsagePercentage`, never a real input/output token count). Mirror `kimi/count_tokens.rs`'s structure exactly (Task-2-research item 5, full read): `approx_token_count(text)` counts contiguous alphanumeric/`-`/`_` runs as one token each plus one per individual punctuation character, floored at 1 for non-empty text; `count_tokens` walks `req.messages` via `normalize_content`, dispatching per `ContentBlock` variant (`Text` → `approx_token_count`, `Image` → flat `IMAGE_TOKEN_ESTIMATE = 2000`, `Thinking` → `approx_token_count` on the thinking text, `ToolUse` → `approx_token_count(name) + approx_token_count(&input.to_string())`, `ToolResult` → recurse on its content), adds `MESSAGE_OVERHEAD_TOKENS = 4` per message, and adds tool-definition token cost by walking `req.extra.get("tools")` the same way Kimi's does. Reuse Kimi's exact constants (`IMAGE_TOKEN_ESTIMATE`, `MESSAGE_OVERHEAD_TOKENS`) rather than inventing new numbers — there's no Kiro-specific reason for these two providers' estimates to diverge.

- [ ] **Step 1: Write the failing tests** — mirror whatever test cases exist in spirit for Kimi's `count_tokens` (check `kimi/count_tokens.rs`'s own `#[cfg(test)]` block for its exact test shapes and port equivalent ones here): a plain single-text-block message, an image block contributing exactly 2000, a tool-use block, a multi-message conversation with the per-message overhead applied correctly, an empty-content edge case not panicking.

- [ ] **Step 2: Run to verify failure, implement, run to verify pass.**

Run: `cargo test providers::kiro::count_tokens`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/providers/kiro/count_tokens.rs src/providers/kiro/mod.rs
git commit -m "feat(kiro): heuristic token count estimate"
```

---

## Task 17: `KiroProvider` — final wiring into the `Provider`/`CliHandlers` traits

**Files:**
- Modify: `src/providers/kiro/mod.rs` — replace the Task-1 stub with the full provider implementation
- Modify: `src/registry.rs` — the `"kiro" => Arc::new(...)` arm added in Task 8 already points here; no further registry change needed, but re-run Task 8's tests to confirm the placeholder-vs-real swap didn't break anything
- Test: inline in `mod.rs`, covering `Provider`/`CliHandlers` method-level behavior; end-to-end request/response wiring is Task 18's job

**Interfaces:**
- Consumes: everything from every prior task.
- Produces: the actual `pub struct KiroProvider;` satisfying `crate::provider::Provider` and a `KiroCli`/`static KIRO_CLI: KiroCli` satisfying `crate::provider::CliHandlers`, matching `kimi/mod.rs`'s exact shape (Task-2-research item 1).

**Design notes:**

```rust
pub struct KiroProvider;
impl Default for KiroProvider { fn default() -> Self { Self::new() } }
impl KiroProvider { pub fn new() -> Self { Self } }

#[async_trait]
impl Provider for KiroProvider {
    fn name(&self) -> &'static str { "kiro" }

    fn supported_models(&self) -> Vec<String> {
        // consult the dynamic cache first (Task 7), falling back to the static catalog (Task 6) —
        // region here is best-effort: use whatever region the currently-stored credentials report,
        // or "us-east-1" if not yet authenticated (matches Registry::new's need to call this
        // pre-auth without erroring).
        let region = auth::token_store::file_store().load().ok().flatten()
            .map(|c| c.region).unwrap_or_else(|| "us-east-1".to_string());
        translate::model_discovery::MODEL_CACHE.model_ids(&region)
    }

    fn cli(&self) -> &'static dyn CliHandlers { &KIRO_CLI }

    async fn handle_messages(&self, mut body: MessagesRequest, ctx: RequestContext) -> Response {
        let message_id = format!("msg_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        let raw_model = body.model.clone().unwrap_or_else(|| "auto".to_string());
        // strip an explicit "kiro:" prefix if present (registry routing (Task 8) only decided
        // *that* this request goes to Kiro; stripping the disambiguation prefix from the actual
        // model id used in the request is this provider's job, matching how is_cursor_model's
        // prefix stripping is handled downstream inside cursor's own handler per Task 8's note)
        let model_id = raw_model.strip_prefix(crate::registry::KIRO_PREFIX).unwrap_or(&raw_model).to_string();
        body.model = Some(model_id.clone());

        let resolved = translate::model_allowlist::resolve_model(&model_id);
        let dot_id = translate::models::dash_to_dot(&resolved);
        let model_meta = translate::models::KIRO_MODELS.iter()
            .find(|m| m.id == resolved)
            .cloned()
            .unwrap_or(translate::models::DEFAULT_MODEL_META); // a sane fallback entry for unrecognized-but-discovered ids

        ctx.monitor.as_ref().map(|m| m.model_resolved(&ctx.req_id, &resolved));

        let client = client::KiroHttpClient::new();
        let reasoning_enabled = model_meta.reasoning;
        let opts = translate::request::BuildRequestOptions {
            session_id: ctx.session_id.as_deref(),
            reasoning_enabled,
            thinking_budget: None, // computed internally by build_kiro_request from read_effort
        };

        match translate::stream::stream_kiro_response(&client, &model_meta, &body, &message_id, ctx.session_id.as_deref()).await {
            Ok(sse_bytes) => {
                let headers = [
                    (http::header::CONTENT_TYPE, "text/event-stream"),
                    (http::header::CACHE_CONTROL, "no-cache"),
                    (http::header::CONNECTION, "keep-alive"),
                ];
                (headers, sse_bytes).into_response()
            }
            Err(e) => map_kiro_stream_error_to_response(&e),
        }
    }

    async fn handle_count_tokens(&self, body: MessagesRequest, _ctx: RequestContext) -> Response {
        let tokens = count_tokens::count_tokens(&body);
        (StatusCode::OK, Json(CountTokensResponse { input_tokens: tokens })).into_response()
    }
}
```

(`opts` above is constructed but `stream_kiro_response`'s actual signature from Task 15 doesn't take `opts` as shown — reconcile the two signatures when implementing this task; Task 15's interface evolved slightly during its own implementation to fold `BuildRequestOptions` construction inside `stream_kiro_response` itself rather than the caller, since the effort-derived `thinking_budget` needs the `req` body Task 15 already has — treat this as the two tasks needing a one-line signature alignment pass at integration time, not a design conflict.)

`map_kiro_stream_error_to_response`: mirrors `kimi/mod.rs`'s `map_kimi_error_to_response` shape but dispatching on the terminal `anyhow::Error` message/downcast from Task 15 rather than a typed `KiroError` (since `stream_kiro_response` returns `Result<Vec<u8>, anyhow::Error>`, not `Result<_, KiroError>` — the typed `KiroError` from Task 13 only exists at the single-HTTP-attempt layer inside `stream.rs`; by the time an error reaches `mod.rs` it's already been classified and turned into a final message string). Map based on message-prefix conventions established during Task 15/13 (e.g. a `context_length_exceeded`-tagged message → 400 with that error type, an auth failure → 401, everything else → 502 `api_error`) — this requires `stream.rs`'s error paths to actually tag their `anyhow::Error`s distinguishably (e.g. via `anyhow::Error::context()` strings this function pattern-matches on, or better, a small `KiroStreamError` enum Task 15 should have returned instead of a bare `anyhow::Error` — **retroactively upgrade Task 15's `stream_kiro_response` return type to `Result<Vec<u8>, KiroStreamError>` where `KiroStreamError` is a small enum (`Auth(anyhow::Error)`, `ContextOverflow(String)`, `NonRetryable(String)`, `Other(anyhow::Error)`) if the plain-`anyhow::Error` version proves too lossy for this function to map correctly — flag this as a likely necessary adjustment to Task 15 discovered here, not a new task**).

`CliHandlers` impl (`KiroCli`), mirroring `kimi/mod.rs`'s `KimiCli` shape exactly:
```rust
pub(crate) struct KiroCli;
impl CliHandlers for KiroCli {
    fn login(&self) -> Result<()> {
        // interactive prompt per the design doc: ask for an IDC start URL, blank = Builder ID
        print!("Enter your organization's IAM Identity Center start URL, or press Enter for AWS Builder ID: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let start_url = input.trim();

        struct StderrCallbacks;
        impl auth::device::DeviceLoginCallbacks for StderrCallbacks {
            fn on_progress(&self, message: &str) { eprintln!("{message}"); }
            fn on_auth_prompt(&self, url: &str, code: &str) {
                eprintln!("\nVisit: {url}\nCode:  {code}\n");
            }
        }

        let manager = auth::manager::KiroAuthManager::new(auth::token_store::file_store());
        let method = if start_url.is_empty() { auth::manager::KiroLoginMethod::BuilderId } else { auth::manager::KiroLoginMethod::Idc };
        let start_url_opt = if start_url.is_empty() { None } else { Some(start_url) };
        manager.bootstrap_login(&StderrCallbacks, method, start_url_opt)?;
        println!("Authentication complete");
        Ok(())
    }

    fn device(&self) -> Result<()> { self.login() } // no separate localhost-redirect mode for Kiro — same rationale as Kimi's device()->login() delegation

    fn status(&self) -> Result<()> {
        let store = auth::token_store::file_store();
        match store.load()? {
            Some(creds) => {
                println!("Authenticated (region: {}, method: {:?})", creds.region, creds.auth_method);
                Ok(())
            }
            None => Err(anyhow::anyhow!("Not authenticated")),
        }
    }

    fn logout(&self) -> Result<()> {
        auth::token_store::file_store().clear()?;
        println!("Logged out");
        Ok(())
    }
}
pub(crate) static KIRO_CLI: KiroCli = KiroCli;
```

- [ ] **Step 1: Write the failing test for `KiroProvider::name()` and `supported_models()`** (the cheap, non-networked methods) — `name()` returns `"kiro"`; `supported_models()` returns the full static catalog's IDs when no auth file exists yet (proves the pre-auth fallback in `supported_models` works, matching the requirement that `Registry::new` can call this before any login happened).

- [ ] **Step 2: Run to verify failure, implement, run to verify pass.**

- [ ] **Step 3: Write the failing test for `CliHandlers::status`/`logout`** against an `InMemoryAuthStore`-backed fixture (or, if `file_store()` is hardcoded to real paths with no injection seam, against a temp-`HOME`-overridden real file store, same pattern as Task 1/2's tests) — `status()` errors clearly pre-login, `logout()` clears a previously-saved credential and `status()` errors again afterward.

- [ ] **Step 4: Run to verify failure, implement, run to verify pass.**

- [ ] **Step 5: Reconcile the `stream_kiro_response`/`BuildRequestOptions` signature mismatch flagged in the Design notes** — read Task 15's actual final signature (not this task's draft assumption above) and adjust `handle_messages` to call it correctly; if Task 15's error type needs the `KiroStreamError` enum upgrade flagged above, implement that now (touches Task 15's file too — expect to `git add` both).

- [ ] **Step 6: Run the full `providers::kiro` test tree once**

Run: `cargo test providers::kiro`
Expected: PASS across every prior task's tests plus this task's new ones — this is the first point in the plan where every module is wired together, so treat any failure here as seriously as a fresh bug, not just a flaky rerun.

- [ ] **Step 7: Commit**

```bash
git add src/providers/kiro/mod.rs src/providers/kiro/translate/stream.rs
git commit -m "feat(kiro): wire KiroProvider into the Provider/CliHandlers traits"
```

---

## Task 18: Integration tests — registry routing, CLI, and end-to-end mocked request

**Files:**
- Create: `tests/kiro_provider.rs` (top-level integration test, follows `tests/codex_websocket.rs`'s pattern per the design doc)
- Test: this task *is* the tests

**Interfaces:**
- Consumes: the public surface of `crate::registry::Registry`, `crate::providers::kiro::KiroProvider`, and this proxy's axum `Router` (however `tests/server.rs` or `tests/foundation.rs` currently constructs one for black-box HTTP testing — `Read` one of those files first to match the existing integration-test setup convention exactly, e.g. `app_with_features` from `server.rs`, before writing new test scaffolding from scratch).

**Design notes:** This task doesn't introduce new production code — it's the acceptance-level proof that Tasks 1–17 actually cohere as one working provider reachable via the real HTTP surface, not just via unit tests calling internal functions directly. Cover:

1. **Registry-level, black-box**: send a `POST /v1/messages` with `model: "kiro:claude-sonnet-4-6"` against a test server instance wired to a mock Kiro backend (reuse whatever mock-HTTP-server helper the auth/client tasks established, or — if this proxy's existing integration tests use `wiremock` or similar at the `tests/` level rather than the lighter helper used in unit tests — match *that* convention instead, since `tests/` often has different tooling latitude than inline `#[cfg(test)]` blocks; check `tests/codex_websocket.rs`/`tests/server.rs` for precedent before choosing) — assert the response is a valid Anthropic `message_start`...`message_stop` SSE sequence and that the mock backend actually received a well-formed `KiroRequest` body (proves the whole `MessagesRequest → KiroRequest → mock backend → KiroStreamEvent → SSE` round trip works end to end, not just each half independently).

2. **CLI-level**: exercise `claude-code-proxy kiro auth status` / `logout` via `assert_cmd` (already a dev-dependency per `Cargo.toml`, used elsewhere in this repo per `tests/cli.rs` — match its existing invocation pattern) against a temp-`HOME`-isolated environment, confirming the binary-level CLI surface (not just the `CliHandlers` trait methods in isolation) behaves correctly pre- and post- a fixture-seeded credential file.

3. **Regression proof for the design doc's core bug**: a black-box HTTP-level version of Task 8's `kiro_prefix_routes_to_kiro_even_when_id_collides_with_an_alias` test — send two requests, one with `model: "kiro:claude-sonnet-4-6"` and one with `model: "claude-sonnet-4-6"` (no prefix, default alias provider = codex), against a server wired with *both* a mock Kiro backend and a mock Codex-shaped backend, and assert each request reaches the correct backend. This is the single test in the whole plan most directly validating the design doc's stated reason for existing.

- [ ] **Step 1: Read `tests/server.rs`, `tests/foundation.rs`, and `tests/cli.rs`** to confirm the exact test-server construction and CLI-invocation conventions already established in this repo, and adjust every "Design notes" assumption above to match precisely — do not invent a new test-setup pattern if one already exists.

- [ ] **Step 2: Write the three test groups above as failing tests** (they'll fail if any prior task has a wiring bug, which is the point — don't be surprised if this step surfaces small integration issues Tasks 1–17's unit tests couldn't see, like a header casing mismatch or a JSON field name typo; fix forward in the relevant task's file, not by weakening this test).

- [ ] **Step 3: Run to verify current state (expect some failures — investigate and fix root causes in the relevant module, re-running after each fix), then verify full pass.**

Run: `cargo test --test kiro_provider`
Expected: PASS.

- [ ] **Step 4: Run the entire workspace test suite one final time**

Run: `cargo test`
Expected: PASS, zero regressions anywhere else in the codebase.

- [ ] **Step 5: Commit**

```bash
git add tests/kiro_provider.rs
git commit -m "test(kiro): end-to-end integration coverage for the Kiro provider"
```

---

## Self-Review Notes (for the plan author, not a task)

- **Spec coverage**: every design-doc section (auth cascade incl. IDE source, dynamic model discovery, registry routing fix, AliasProvider::Kiro, request/response translation incl. history/thinking/streaming, error handling/retry, testing) maps to at least one task above. The one deliberate trim beyond the design doc's own deferred list: `TRUNCATION_NOTICE` prepending (Task 14) — flagged inline as a scope-trim with rationale, not silently dropped.
- **Known soft spots flagged inline for the implementer to resolve at build time rather than guessed at here**: the exact remaining 16 model catalog entries' metadata (Task 6 Step 1 — read the source directly), the `KiroStreamError` enum question (Task 15/17 boundary), and the `stream_kiro_response`/`BuildRequestOptions` call-signature reconciliation (Task 17 Step 5). These are marked because getting them wrong from research-summary-only would have been guessing, not because the plan is incomplete — each has a concrete "read the source / align at integration time" instruction, not a placeholder.
- **Type consistency check**: `KiroCredentials`, `KiroAuthMethod`, `KiroHistoryEntry` and friends, `KiroStreamEvent`, `ThinkingStreamEvent`, `KiroModelMeta`, `KiroRequest`/`KiroConversationState`/`CurrentMessage` are each defined exactly once (Tasks 1, 9, 11, 12, 6, 14 respectively) and referenced by the same names in every later task that consumes them — verified during authoring by grep-checking each type name's task-of-origin against every later mention.

