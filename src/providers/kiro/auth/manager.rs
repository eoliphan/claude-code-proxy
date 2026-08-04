//! Credential cascade orchestration: `KiroAuthManager` ties together every
//! credential source from Tasks 1-4 (Kiro IDE token file, kiro-cli's SQLite
//! store, native device-code login, direct token refresh) into one
//! `get_auth`/`force_refresh` surface, with a singleflight guard around the
//! refresh critical section (Adversarial Review Findings #13) and a
//! `bootstrap_login` entry point for the no-stored-credentials case.
//!
//! Ported from `oauth.ts::refreshKiroToken` / `loginKiro` in the TS
//! reference, plus the concurrency fix layered on top per Findings #13.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::AuthStorage;
use crate::paths::DirResolverEnv;

use super::device::DeviceLoginCallbacks;
use super::kiro_credentials::KiroCredentials;

const REFRESH_MARGIN_MS: u64 = 5 * 60 * 1000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Which login method `bootstrap_login` should prefer when there is no
/// stored credential yet. `Auto` reuses any currently-valid Kiro IDE token
/// first, regardless of its auth method; `BuilderId`/`Idc` skip that reuse
/// step (forcing a specific device-code flow if nothing else is available).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KiroLoginMethod {
    Auto,
    BuilderId,
    Idc,
}

/// Signature of `refresh::refresh_token_direct`. Boxed and stored on the
/// manager purely as a testing seam: production code always constructs it
/// via [`default_refresh_fn`], which just wraps that free function. This is
/// what lets `concurrent_force_refresh_only_hits_the_network_once` count
/// real refresh attempts without touching the network.
type RefreshFn = dyn Fn(&KiroCredentials) -> Result<KiroCredentials, anyhow::Error> + Send + Sync;

fn default_refresh_fn() -> Box<RefreshFn> {
    Box::new(super::refresh::refresh_token_direct)
}

pub struct KiroAuthManager<S: AuthStorage<KiroCredentials>> {
    pub store: S,
    cached: Arc<Mutex<Option<KiroCredentials>>>,
    /// Singleflight guard around the refresh critical section (Adversarial
    /// Review Findings #13). A single shared `KiroAuthManager` instance
    /// (Task 17's responsibility to hold exactly one) makes this effective
    /// across concurrent requests: without it, two concurrent callers can
    /// each independently decide a refresh is needed and race AWS
    /// SSO-OIDC's refresh-token rotation, where the loser's refresh token is
    /// already invalid by the time its request lands.
    refresh_lock: Mutex<()>,
    /// Injected home-dir resolution, so kiro_ide/kiro_cli calls are testable
    /// (Findings #17) — this manager never touches the real filesystem
    /// locations directly, only through `deps`-taking `_for` functions.
    deps: DirResolverEnv,
    refresh_fn: Box<RefreshFn>,
}

impl<S: AuthStorage<KiroCredentials>> KiroAuthManager<S> {
    pub fn new(store: S) -> Self {
        Self::with_deps(store, DirResolverEnv::default())
    }

    pub fn with_deps(store: S, deps: DirResolverEnv) -> Self {
        Self {
            store,
            cached: Arc::new(Mutex::new(None)),
            refresh_lock: Mutex::new(()),
            deps,
            refresh_fn: default_refresh_fn(),
        }
    }

    /// Test-only constructor: swaps in a fake `refresh_fn` so tests can
    /// count/control "network" refresh attempts. Not part of the public
    /// production surface — see the `RefreshFn` doc comment above.
    #[cfg(test)]
    fn with_deps_and_refresh_fn(
        store: S,
        deps: DirResolverEnv,
        refresh_fn: Box<RefreshFn>,
    ) -> Self {
        Self {
            store,
            cached: Arc::new(Mutex::new(None)),
            refresh_lock: Mutex::new(()),
            deps,
            refresh_fn,
        }
    }

    pub fn get_auth(&self) -> Result<KiroCredentials, anyhow::Error> {
        if let Some(cached) = self.cached.lock().unwrap().clone()
            && !cached.is_expired(now_ms() + REFRESH_MARGIN_MS)
        {
            return Ok(cached);
        }
        let stored = self.store.load()?.ok_or_else(|| {
            anyhow::anyhow!("Not authenticated. Run: claude-code-proxy kiro auth login")
        })?;
        *self.cached.lock().unwrap() = Some(stored.clone());
        if !stored.is_expired(now_ms() + REFRESH_MARGIN_MS) {
            return Ok(stored);
        }
        self.refresh_singleflight(&stored)
    }

    pub fn force_refresh(&self) -> Result<KiroCredentials, anyhow::Error> {
        let current = self
            .cached
            .lock()
            .unwrap()
            .clone()
            .or(self.store.load()?)
            .ok_or_else(|| {
                anyhow::anyhow!("Not authenticated. Run: claude-code-proxy kiro auth login")
            })?;
        self.refresh_singleflight(&current)
    }

    /// Serializes the whole refresh critical section behind `refresh_lock`,
    /// and re-checks the *durable* store (not just the in-memory cache)
    /// after acquiring it — a concurrent request that won the race may have
    /// already written a fresher credential to disk while this caller was
    /// waiting for the lock.
    ///
    /// The short-circuit only fires when the store's token is *different*
    /// from `hint.access`, not merely "not locally expired". This is
    /// deliberate and distinct from the plan's initial draft: `force_refresh`
    /// exists specifically for the 401/403 path, where the caller passes in
    /// the token the server just rejected as `hint`. That token is often
    /// still "not expired" by our own 5-minute-margin heuristic — comparing
    /// only `is_expired` would let a losing/solo caller read back the exact
    /// same rejected token and hand it straight to the retrying caller,
    /// silently defeating "force". Comparing `access` distinguishes "someone
    /// else already won this race" (different token, safe to reuse) from
    /// "this really is the token that needs refreshing" (same token, must
    /// fall through to a real refresh attempt).
    fn refresh_singleflight(
        &self,
        hint: &KiroCredentials,
    ) -> Result<KiroCredentials, anyhow::Error> {
        let _guard = self.refresh_lock.lock().unwrap();
        if let Ok(Some(latest)) = self.store.load()
            && latest.access != hint.access
            && !latest.is_expired(now_ms() + REFRESH_MARGIN_MS)
        {
            *self.cached.lock().unwrap() = Some(latest.clone());
            return Ok(latest);
        }
        self.refresh_cascade(hint)
    }

    fn refresh_cascade(&self, current: &KiroCredentials) -> Result<KiroCredentials, anyhow::Error> {
        // Layer 0: Kiro IDE token is the freshest source (IDE keeps it
        // continuously refreshed) — always prefer it if valid.
        if let Some(ide) = super::kiro_ide::read_ide_credentials_for(&self.deps, false) {
            return self.adopt(ide);
        }
        // Layer 1: any currently-valid kiro-cli token (social preferred if
        // present, else IDC).
        let precheck = super::kiro_cli::get_kiro_cli_social_token_for(&self.deps)
            .or_else(|| super::kiro_cli::get_kiro_cli_credentials_for(&self.deps, false));
        if let Some(creds) = precheck {
            return self.adopt(creds);
        }
        // Layer 2: attempt our own direct refresh using the credentials we
        // currently hold.
        match (self.refresh_fn)(current) {
            Ok(refreshed) => {
                super::kiro_cli::save_kiro_cli_credentials_for(&self.deps, &refreshed);
                self.adopt(refreshed)
            }
            Err(refresh_err) => {
                // Layer 3: kiro-cli may have rotated the refresh token
                // concurrently — re-read its DB once.
                if let Some(retry_creds) =
                    super::kiro_cli::get_kiro_cli_credentials_for(&self.deps, false)
                {
                    return self.adopt(retry_creds);
                }
                // Layer 3.5 (Adversarial Review Findings #18 — previously
                // defined but never called anywhere): ask kiro-cli to
                // refresh itself, then re-read its DB. Bounded by
                // refresh_via_kiro_cli's own 15s subprocess timeout (Task 2).
                if let Some(cli_refreshed) = super::kiro_cli::refresh_via_kiro_cli_for(&self.deps) {
                    return self.adopt(cli_refreshed);
                }
                // Layer 4: kiro-cli may hold a newer (still-expired-to-us)
                // refresh token; try refreshing with those.
                if let Some(expired_cli) =
                    super::kiro_cli::get_kiro_cli_credentials_for(&self.deps, true)
                    && expired_cli.refresh != current.refresh
                    && let Ok(refreshed) = (self.refresh_fn)(&expired_cli)
                {
                    super::kiro_cli::save_kiro_cli_credentials_for(&self.deps, &refreshed);
                    return self.adopt(refreshed);
                }
                // Layer 5: graceful degradation — our buffer subtracted 5
                // min from the real AWS expiry, so the access token may
                // still work. Buy time rather than failing outright. (No
                // extra store re-read needed here: refresh_singleflight
                // already re-checked the store once under refresh_lock
                // before entering this cascade at all.)
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

    /// `bootstrap_login` implements the TS `loginKiro`'s ordering for the
    /// *initial* (no-stored-credentials) case, which differs from
    /// `refresh_cascade` mainly in trying the device-code flow as the final
    /// fallback instead of returning an error. Uses the same
    /// `self.deps`-injected `_for` variants as `refresh_cascade` throughout.
    pub fn bootstrap_login(
        &self,
        callbacks: &dyn DeviceLoginCallbacks,
        preferred: KiroLoginMethod,
        start_url: Option<&str>,
    ) -> Result<KiroCredentials, anyhow::Error> {
        // Step 1: try an existing valid Kiro IDE token, unless the caller
        // explicitly requested Builder ID (which should not silently reuse
        // an IDC-sourced IDE token) or requested Idc without a start_url.
        let try_ide_first = matches!(preferred, KiroLoginMethod::Auto)
            || (matches!(preferred, KiroLoginMethod::Idc) && start_url.is_some());
        if try_ide_first
            && let Some(ide) = super::kiro_ide::read_ide_credentials_for(&self.deps, false)
        {
            return self.adopt(ide);
        }

        // Step 2: any currently-valid kiro-cli token (social preferred if
        // present, else IDC).
        let cli = super::kiro_cli::get_kiro_cli_social_token_for(&self.deps)
            .or_else(|| super::kiro_cli::get_kiro_cli_credentials_for(&self.deps, false));
        if let Some(creds) = cli {
            return self.adopt(creds);
        }

        // Step 3: silent refresh from expired IDE creds, then expired
        // kiro-cli creds, writing the result back to kiro-cli's DB on
        // success either way.
        if let Some(expired_ide) = super::kiro_ide::read_ide_credentials_for(&self.deps, true)
            && let Ok(refreshed) = (self.refresh_fn)(&expired_ide)
        {
            super::kiro_cli::save_kiro_cli_credentials_for(&self.deps, &refreshed);
            return self.adopt(refreshed);
        }
        if let Some(expired_cli) = super::kiro_cli::get_kiro_cli_credentials_for(&self.deps, true)
            && let Ok(refreshed) = (self.refresh_fn)(&expired_cli)
        {
            super::kiro_cli::save_kiro_cli_credentials_for(&self.deps, &refreshed);
            return self.adopt(refreshed);
        }

        // Step 4: nothing to reuse — run the interactive device flow.
        let creds = if let Some(url) = start_url {
            super::device::run_device_login_idc(callbacks, url)?
        } else {
            super::device::run_device_login_builder_id(callbacks)?
        };
        self.adopt(creds)
    }

    fn adopt(&self, creds: KiroCredentials) -> Result<KiroCredentials, anyhow::Error> {
        self.store.save(creds.clone())?;
        *self.cached.lock().unwrap() = Some(creds.clone());
        // Best-effort model/profile cache refresh for this credential's
        // resolved API region (Adversarial Review Findings #5 — previously
        // defined in Task 7 but never called from anywhere). Fire-and-forget:
        // refresh_cache_for_credentials is async and this is not on the
        // critical path of returning a response, so adopt() must not block
        // on it. Keyed consistently by the *resolved* API region everywhere,
        // not the raw SSO region (Findings #5's second point).
        //
        // Deliberate deviation from the plan's draft (`tokio::spawn`
        // unconditionally): that panics if `adopt()` is ever reached from a
        // caller not running inside a Tokio runtime — a real risk, since
        // this is a plain synchronous method (a raw `std::thread::spawn`ed
        // caller, or any future non-async call site, would crash the whole
        // process on its first successful login/refresh). Guarding with
        // `Handle::try_current()` preserves identical behavior everywhere
        // the plan's version worked (both `handle_messages` and the CLI
        // commands run under `#[tokio::main]`, so `try_current()` succeeds
        // there) while silently no-op'ing instead of panicking everywhere
        // else — which is what "best-effort, never blocks or fails the
        // caller" already promised.
        let api_region =
            crate::providers::kiro::translate::models::resolve_api_region(&creds.region);
        let creds_for_cache = creds.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                crate::providers::kiro::translate::model_discovery::refresh_cache_for_credentials(
                    &creds_for_cache,
                    &api_region,
                )
                .await;
            });
        }
        Ok(creds)
    }

    pub fn reset_cache(&self) {
        if let Ok(mut guard) = self.cached.lock() {
            *guard = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::InMemoryAuthStore;
    use crate::providers::kiro::auth::KiroAuthMethod;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    fn far_future_creds() -> KiroCredentials {
        KiroCredentials {
            access: "a".into(),
            refresh: "r".into(),
            expires: now_ms() + 3_600_000,
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
        }
    }

    fn deps_for(home: &std::path::Path) -> DirResolverEnv {
        DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: home.to_string_lossy().to_string(),
        }
    }

    /// Mirrors `kiro_ide.rs`'s own `write_token_file` test helper — kept
    /// local rather than shared, since the "same helper pattern" the plan
    /// calls for is a handful of lines, and duplicating it here keeps this
    /// file's tests independent of kiro_ide.rs's private test module.
    fn write_ide_token_file(home: &std::path::Path, access: &str, expires_at_iso: &str) {
        let dir = home.join(".aws").join("sso").join("cache");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("kiro-auth-token.json"),
            format!(
                r#"{{"accessToken":"{access}","refreshToken":"ide-refresh","expiresAt":"{expires_at_iso}","region":"us-east-1"}}"#
            ),
        )
        .unwrap();
    }

    /// Mirrors `kiro_cli.rs`'s own `make_kiro_cli_db` test helper, same
    /// reasoning as `write_ide_token_file` above — this is Task 2's
    /// `.local/share/kiro-cli/data.sqlite3` shape on Linux, which is what
    /// `kiro_cli_db_path_for` resolves to under a non-Windows, non-macOS
    /// `DirResolverEnv` (matching what this test suite runs under).
    fn write_kiro_cli_idc_db(home: &std::path::Path, access: &str, expires_at_iso: &str) {
        let dir = home.join(".local").join("share").join("kiro-cli");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("data.sqlite3");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO auth_kv (key, value) VALUES (?1, ?2)",
            rusqlite::params![
                "kirocli:odic:token",
                format!(
                    r#"{{"access_token":"{access}","refresh_token":"cli-refresh","expires_at":"{expires_at_iso}","region":"us-east-1"}}"#
                )
            ],
        )
        .unwrap();
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
        assert!(
            err.to_string()
                .contains("claude-code-proxy kiro auth login")
        );
    }

    #[test]
    fn refresh_cascade_prefers_ide_token_over_kiro_cli() {
        // Layer 0 (Kiro IDE token) must win over Layer 1 (kiro-cli) even
        // when both sources have a currently-valid credential available.
        let tmp = TempDir::new().unwrap();
        write_ide_token_file(tmp.path(), "ide-access", "2099-01-01T00:00:00.000Z");
        write_kiro_cli_idc_db(tmp.path(), "cli-access", "2099-01-01T00:00:00.000Z");
        let deps = deps_for(tmp.path());
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps(store, deps);

        let hint = far_future_creds();
        let result = manager.refresh_cascade(&hint).unwrap();

        assert_eq!(result.access, "ide-access");
    }

    #[test]
    fn force_refresh_forces_a_real_refresh_even_when_the_stored_token_still_looks_locally_valid() {
        // Regression test for the discriminator fix in `refresh_singleflight`
        // (see its doc comment): force_refresh exists for the 401/403 path,
        // where the caller passes in the token the server just rejected as
        // `hint`. That token is often still "not expired" by our own
        // 5-minute-margin heuristic -- if the store re-check only asked "is
        // the stored token still fresh enough" (ignoring whether it's the
        // *same* token), a solo caller would read back the exact same
        // rejected token from the store and hand it straight back to the
        // retrying caller, silently defeating "force". This test uses a
        // credential that is deliberately NOT locally expired, so a version
        // of the re-check without the access-token comparison would
        // short-circuit here and never call refresh_fn at all.
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let valid = far_future_creds();
        store.save(valid).unwrap();

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let refresh_fn: Box<RefreshFn> = Box::new(move |current: &KiroCredentials| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(KiroCredentials {
                access: "forced-refresh-access".into(),
                refresh: "forced-refresh-refresh".into(),
                expires: now_ms() + 3_600_000,
                region: current.region.clone(),
                auth_method: current.auth_method,
                client_id: current.client_id.clone(),
                client_secret: current.client_secret.clone(),
                profile_arn: current.profile_arn.clone(),
            })
        });

        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let result = manager.force_refresh().unwrap();

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "force_refresh must hit the network even though the stored token wasn't locally expired"
        );
        assert_eq!(result.access, "forced-refresh-access");
    }

    #[test]
    fn concurrent_force_refresh_only_hits_the_network_once() {
        // Regression test for Adversarial Review Findings #13. Two threads
        // call force_refresh() concurrently on the SAME manager instance
        // with an expired credential; the refresh_lock singleflight must
        // ensure only one of them actually performs the (fake, counted)
        // refresh work, and the other observes the already-refreshed store
        // value instead of racing it.
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let expired = KiroCredentials {
            access: "old-access".into(),
            refresh: "old-refresh".into(),
            expires: now_ms().saturating_sub(1_000),
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
        };
        store.save(expired.clone()).unwrap();

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        // Sleeps inside the "network" call to widen the race window, so the
        // second thread reliably arrives at refresh_lock while the first is
        // still inside the critical section.
        let refresh_fn: Box<RefreshFn> = Box::new(move |current: &KiroCredentials| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(50));
            Ok(KiroCredentials {
                access: "new-access".into(),
                refresh: "new-refresh".into(),
                expires: now_ms() + 3_600_000,
                region: current.region.clone(),
                auth_method: current.auth_method,
                client_id: current.client_id.clone(),
                client_secret: current.client_secret.clone(),
                profile_arn: current.profile_arn.clone(),
            })
        });

        // Empty temp dir: no Kiro IDE token file, no kiro-cli DB, so Layers
        // 0/1 both miss and the cascade actually reaches refresh_fn.
        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let manager = Arc::new(KiroAuthManager::with_deps_and_refresh_fn(
            store, deps, refresh_fn,
        ));

        let start = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let m = manager.clone();
                let b = start.clone();
                std::thread::spawn(move || {
                    b.wait();
                    m.force_refresh()
                })
            })
            .collect();

        let results: Vec<KiroCredentials> = handles
            .into_iter()
            .map(|h| h.join().unwrap().unwrap())
            .collect();

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "singleflight must only hit the network once"
        );
        assert_eq!(results[0].access, "new-access");
        assert_eq!(results[1].access, "new-access");
        assert_eq!(results[0].access, results[1].access);

        let stored = manager.store.load().unwrap().unwrap();
        assert_eq!(
            stored.access, "new-access",
            "store's final content must be the single refresh, not an earlier/stale write"
        );
    }

    struct RecordingCallbacks {
        progress_calls: AtomicUsize,
        prompt_calls: AtomicUsize,
    }

    impl DeviceLoginCallbacks for RecordingCallbacks {
        fn on_progress(&self, _message: &str) {
            self.progress_calls.fetch_add(1, Ordering::SeqCst);
        }
        fn on_auth_prompt(&self, _verification_uri_complete: &str, _user_code: &str) {
            self.prompt_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn bootstrap_login_prefers_kiro_cli_over_device_flow() {
        // Per Adversarial Review Findings #17, kiro_cli.rs's functions all
        // take the same `_for(deps)` injectable-path pattern kiro_ide.rs
        // already used in Task 1 — so this test constructs a real
        // temp-dir-backed kiro-cli DB fixture, builds a `DirResolverEnv`
        // pointing at that temp dir, constructs the manager via
        // `KiroAuthManager::with_deps`, and calls `bootstrap_login`. No
        // network mock is needed: the cascade must never reach the device
        // flow at all when kiro-cli has a valid credential, which the
        // `RecordingCallbacks` zero-call assertions verify directly.
        let tmp = TempDir::new().unwrap();
        write_kiro_cli_idc_db(tmp.path(), "cli-access", "2099-01-01T00:00:00.000Z");
        let deps = deps_for(tmp.path());
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps(store, deps);
        let callbacks = RecordingCallbacks {
            progress_calls: AtomicUsize::new(0),
            prompt_calls: AtomicUsize::new(0),
        };

        let result = manager
            .bootstrap_login(&callbacks, KiroLoginMethod::Auto, None)
            .unwrap();

        assert_eq!(result.access, "cli-access");
        assert_eq!(
            callbacks.progress_calls.load(Ordering::SeqCst),
            0,
            "device flow must never be attempted when kiro-cli already has a valid credential"
        );
        assert_eq!(callbacks.prompt_calls.load(Ordering::SeqCst), 0);
    }
}
