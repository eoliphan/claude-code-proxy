//! Credential cascade orchestration: `KiroAuthManager` ties together every
//! credential source from Tasks 1-4 (Kiro IDE token file, kiro-cli's SQLite
//! store, native device-code login, direct token refresh) into one
//! `get_auth`/`force_refresh` surface, with a singleflight guard around the
//! refresh critical section (Adversarial Review Findings #13) and a
//! `bootstrap_login` entry point for the no-stored-credentials case.
//!
//! Ported from `oauth.ts::refreshKiroToken` / `loginKiro` in the TS
//! reference, plus the concurrency fix layered on top per Findings #13.

use std::sync::atomic::{AtomicU64, Ordering};
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

/// True when `access` is exactly the token a caller told us was just
/// rejected (401/403). `rejected_access` is `None` for `get_auth`'s
/// ordinary near-expiry-triggered refreshes (nothing was rejected, so
/// nothing is excluded) and `Some(rejected_access)` for `force_refresh`'s
/// 401/403 path. Establishes the same "pass the rejected token explicitly,
/// gate candidates against it" convention already used by
/// `codex/auth/manager.rs::CodexAuthManager::force_refresh` in this same
/// codebase.
fn is_rejected_token(access: &str, rejected_access: Option<&str>) -> bool {
    rejected_access.is_some_and(|rejected| access == rejected)
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
    /// Bumped once, inside `adopt()`, every time a credential is
    /// successfully adopted (from any cascade layer, including Layer 5's
    /// graceful degradation). `refresh_singleflight` samples this before
    /// acquiring `refresh_lock` and compares it again after acquiring the
    /// lock: if it changed, some other caller completed a full adoption
    /// while this caller was waiting, so the store's current value is
    /// authoritative regardless of whether its `access` token happens to
    /// match what this caller already had. This is what makes singleflight
    /// work even when the completed refresh's outcome has the *same*
    /// `access` as before it started (Layer 5's extension never changes
    /// `access`, only `expires`) — an access-token-equality check alone
    /// cannot distinguish "someone already refreshed, reuse their result"
    /// from "nobody has refreshed yet" in that case.
    refresh_generation: AtomicU64,
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
            refresh_generation: AtomicU64::new(0),
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
            refresh_generation: AtomicU64::new(0),
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
        self.refresh_singleflight(&stored, None)
    }

    /// `rejected_access` is the access token that just got a 401/403 from
    /// the backend — required, not optional, because a caller retrying
    /// after an auth failure always has one. It's threaded all the way
    /// through `refresh_cascade` so every layer that can hand back an
    /// *existing* credential without ever contacting the network (0, 1, 3,
    /// and 5) refuses to re-adopt that exact token — see `refresh_cascade`'s
    /// doc comment for the full per-layer breakdown and why a value
    /// comparison, not just singleflight, is necessary here.
    pub fn force_refresh(&self, rejected_access: &str) -> Result<KiroCredentials, anyhow::Error> {
        // Note: read the cache into an owned value in its own statement
        // (dropping the `cached` MutexGuard immediately) before ever
        // touching the store — deliberately *not* the equivalent-looking
        // `self.cached.lock().unwrap().clone().or(self.store.load()?)`,
        // which has two problems: it holds the `cached` lock for the
        // duration of the store read (unnecessary contention), and it
        // evaluates `self.store.load()?` unconditionally even when the
        // cache already had a value — so a transient store-read error would
        // fail this call outright even with a perfectly good cached
        // credential in hand.
        let cached = self.cached.lock().unwrap().clone();
        let current = match cached {
            Some(creds) => creds,
            None => self.store.load()?.ok_or_else(|| {
                anyhow::anyhow!("Not authenticated. Run: claude-code-proxy kiro auth login")
            })?,
        };
        self.refresh_singleflight(&current, Some(rejected_access))
    }

    /// Serializes the whole refresh critical section behind `refresh_lock`,
    /// and re-checks whether a concurrent caller already completed a full
    /// adoption while this caller was waiting for the lock — a generation
    /// counter, not a value comparison, decides that (see
    /// `refresh_generation`'s doc comment for why).
    ///
    /// Three earlier approaches were tried and rejected here, all worth
    /// recording so they aren't reintroduced:
    ///
    /// 1. Re-checking only `!latest.is_expired(...)`: `force_refresh` exists
    ///    specifically for the 401/403 path, where the caller passes in the
    ///    token the server just rejected as `hint`. That token is often
    ///    still "not expired" by our own 5-minute-margin heuristic, so a
    ///    losing/solo caller would read back the exact same rejected token
    ///    from the store and hand it straight to the retrying caller,
    ///    silently defeating "force".
    /// 2. Comparing `latest.access != hint.access` instead: this fixed (1)
    ///    but broke the *opposite* case. Layer 5's graceful-degradation
    ///    fallback (see `refresh_cascade`) returns a credential with the
    ///    SAME `access` as `current` — it only extends `expires`. When a
    ///    winner's refresh resolves via Layer 5, an access-comparison
    ///    re-check sees `latest.access == hint.access` and wrongly concludes
    ///    "nobody refreshed yet", sending every loser through the entire
    ///    cascade again — including a second real (and likely also-failing)
    ///    Layer 2 refresh attempt and, worse, `refresh_via_kiro_cli_for`'s
    ///    15-second subprocess (Layer 3.5) — serialized one loser at a time
    ///    behind the very lock meant to prevent exactly that.
    /// 3. A bare generation counter (no `rejected_access` at all) fixed (2)
    ///    but reopened a variant of (1): Layers 0 (Kiro IDE), 1 (kiro-cli
    ///    precheck), and 5 (graceful degradation) can all hand back an
    ///    *existing* credential without ever contacting the network, so a
    ///    rejected token that the IDE genuinely hasn't rotated yet would
    ///    keep coming back from Layer 0 unchanged, forever, across any
    ///    number of solo `force_refresh` retries — no lock/generation
    ///    bookkeeping inside `refresh_singleflight` alone can fix that,
    ///    because the bug isn't a synchronization bug; the cascade itself
    ///    needs to know which token is disqualified.
    ///
    /// The fix is two parts working together, mirroring the pattern already
    /// established by `codex/auth/manager.rs`'s
    /// `CodexAuthManager::force_refresh(&self, rejected_access: &str)`:
    /// `rejected_access` is threaded explicitly from `force_refresh` all the
    /// way through `refresh_cascade`, and every layer that can hand back an
    /// existing credential without contacting the network (0, 1, 3, and 5;
    /// see `refresh_cascade`'s doc comment for the full breakdown, including
    /// why 3 needed the same treatment as 1 despite reading the identical
    /// kiro-cli row) refuses to adopt/extend a candidate whose `access`
    /// equals it. The generation counter still does its job for everything
    /// else (avoiding redundant work when a *different*, non-rejected
    /// credential was concurrently adopted), but it is deliberately not
    /// trusted blindly here either: the fast-path re-check below also
    /// verifies the store's value isn't the rejected token before trusting
    /// it, because the generation bump it observes could belong to an
    /// unrelated concurrent caller (e.g. a plain `get_auth()` that knows
    /// nothing about this rejection) that itself re-adopted the very token
    /// this caller is trying to get rid of.
    fn refresh_singleflight(
        &self,
        hint: &KiroCredentials,
        rejected_access: Option<&str>,
    ) -> Result<KiroCredentials, anyhow::Error> {
        let generation_before = self.refresh_generation.load(Ordering::SeqCst);
        let _guard = self.refresh_lock.lock().unwrap();
        if self.refresh_generation.load(Ordering::SeqCst) != generation_before
            && let Ok(Some(latest)) = self.store.load()
            && !is_rejected_token(&latest.access, rejected_access)
        {
            *self.cached.lock().unwrap() = Some(latest.clone());
            return Ok(latest);
        }
        self.refresh_cascade(hint, rejected_access)
    }

    /// `rejected_access` (see `force_refresh`'s doc comment) disqualifies a
    /// candidate credential whose `access` matches it. Layer-by-layer:
    ///
    /// - Layers 0, 1, and 3 read an *existing* kiro-cli/IDE-file credential
    ///   without ever contacting the network, so each is filtered directly
    ///   (`!is_rejected_token(...)`) — this is the only thing that can stop
    ///   them from handing the caller back the exact token it just told us
    ///   was rejected. Layer 3 in particular reads the *same* kiro-cli DB
    ///   row Layer 1 already checked: Layer 2's success path always writes
    ///   our own token into that DB (`save_kiro_cli_credentials_for`), so
    ///   "kiro-cli's DB holds exactly the token we're currently using" is
    ///   the steady state, not an edge case — an unfiltered Layer 3 would
    ///   reliably replay the rejected token right back whenever Layer 2's
    ///   refresh attempt itself fails (e.g. the token was actually revoked,
    ///   not just expired), which is exactly the scenario `rejected_access`
    ///   exists to prevent.
    /// - Layer 3.5 shells out to kiro-cli to actually perform a refresh
    ///   before re-reading its DB, so it would normally yield something new
    ///   on success — but it's filtered anyway (cheap, and removes any
    ///   dependence on kiro-cli's own refresh actually rotating the token).
    /// - Layer 4 is filtered implicitly by its own `expired_cli.refresh !=
    ///   current.refresh` discriminator: if kiro-cli's expired credential
    ///   has the identical refresh token to the one we're already holding,
    ///   there is nothing "newer" to retry with regardless of its access
    ///   token, so Layer 4 already declines to touch it.
    /// - Layer 2's real refresh isn't gated: it always talks to the server
    ///   and gets back a genuinely new token (or fails), so it cannot
    ///   reproduce the rejected one.
    /// - Layer 5 is filtered directly: extending the rejected token's
    ///   expiry would falsely mark a token we have direct evidence is bad
    ///   as "good for longer".
    fn refresh_cascade(
        &self,
        current: &KiroCredentials,
        rejected_access: Option<&str>,
    ) -> Result<KiroCredentials, anyhow::Error> {
        // Layer 0: Kiro IDE token is the freshest source (IDE keeps it
        // continuously refreshed) — always prefer it if valid, unless it's
        // the exact token that was just rejected (the IDE hasn't rotated
        // yet; reusing it would just repeat the same 401/403).
        if let Some(ide) = super::kiro_ide::read_ide_credentials_for(&self.deps, false)
            && !is_rejected_token(&ide.access, rejected_access)
        {
            return self.adopt(ide);
        }
        // Layer 1: any currently-valid kiro-cli token (social preferred if
        // present, else IDC). Each source is filtered against
        // rejected_access *before* falling through to the next, not after
        // the whole chain — so a rejected social token doesn't discard a
        // still-viable IDC alternative underneath it.
        let precheck = super::kiro_cli::get_kiro_cli_social_token_for(&self.deps)
            .filter(|creds| !is_rejected_token(&creds.access, rejected_access))
            .or_else(|| {
                super::kiro_cli::get_kiro_cli_credentials_for(&self.deps, false)
                    .filter(|creds| !is_rejected_token(&creds.access, rejected_access))
            });
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
                // concurrently — re-read its DB once. Filtered against
                // rejected_access: this reads the identical row Layer 1
                // already checked, and Layer 2's own success path is what
                // put our (now-rejected) token there in the first place —
                // see this function's doc comment for why an unfiltered
                // read here is a real, reachable replay of the rejected
                // token, not a theoretical concern.
                if let Some(retry_creds) =
                    super::kiro_cli::get_kiro_cli_credentials_for(&self.deps, false)
                        .filter(|creds| !is_rejected_token(&creds.access, rejected_access))
                {
                    return self.adopt(retry_creds);
                }
                // Layer 3.5 (Adversarial Review Findings #18 — previously
                // defined but never called anywhere): ask kiro-cli to
                // refresh itself, then re-read its DB. Bounded by
                // refresh_via_kiro_cli's own 15s subprocess timeout (Task 2).
                // Filtered against rejected_access too, even though a
                // successful kiro-cli-side refresh would normally yield a
                // new token anyway.
                if let Some(cli_refreshed) = super::kiro_cli::refresh_via_kiro_cli_for(&self.deps)
                    .filter(|creds| !is_rejected_token(&creds.access, rejected_access))
                {
                    return self.adopt(cli_refreshed);
                }
                // Layer 4: kiro-cli may hold a newer (still-expired-to-us)
                // refresh token; try refreshing with those. Implicitly
                // filtered by `expired_cli.refresh != current.refresh` (see
                // this function's doc comment) rather than an explicit
                // rejected_access check.
                if let Some(expired_cli) =
                    super::kiro_cli::get_kiro_cli_credentials_for(&self.deps, true)
                    && expired_cli.refresh != current.refresh
                    && let Ok(refreshed) = (self.refresh_fn)(&expired_cli)
                {
                    super::kiro_cli::save_kiro_cli_credentials_for(&self.deps, &refreshed);
                    return self.adopt(refreshed);
                }
                // Layer 5: graceful degradation. Reconstruct the true AWS
                // expiry using *this credential's own* `expiry_buffer_ms`
                // (0 for kiro-cli-sourced credentials, 2 min for Kiro
                // IDE-sourced tokens, 5 min for this proxy's own refresh/
                // device-code sources — see that field's doc comment) rather
                // than assuming every source subtracted the same universal
                // buffer: kiro-cli's raw, un-buffered expiry has no such
                // slack at all, so falsely granting it 5 extra minutes would
                // persist an already-expired-per-AWS token as "good" for up
                // to 5 minutes past its true expiry. Buy time rather than
                // failing outright, but only as much time as this specific
                // source's own margin actually earned, and never for the
                // token that was just rejected -- extending its expiry
                // would falsely mark it "good for longer" when we have
                // direct evidence it isn't. (No extra store re-read needed
                // here: refresh_singleflight already re-checked the store
                // once under refresh_lock before entering this cascade at
                // all.)
                let actual_expiry = current.expires.saturating_add(current.expiry_buffer_ms);
                if !current.access.is_empty()
                    && !is_rejected_token(&current.access, rejected_access)
                    && now_ms() < actual_expiry
                {
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
        // Fail fast on a caller-contradictory (preferred, start_url) pair,
        // rather than silently running the "wrong" device flow later at
        // Step 4: that final fallback picks Builder ID vs. IDC purely from
        // `start_url.is_some()`, since Builder ID never takes one and IDC
        // always requires one — so `preferred` disagreeing with that is
        // unambiguously a caller error, not a legitimate combination to
        // interpret one way or another.
        match (preferred, start_url) {
            (KiroLoginMethod::BuilderId, Some(_)) => {
                return Err(anyhow::anyhow!(
                    "bootstrap_login: preferred=BuilderId but a start_url was given (Builder ID never takes one)"
                ));
            }
            (KiroLoginMethod::Idc, None) => {
                return Err(anyhow::anyhow!(
                    "bootstrap_login: preferred=Idc requires a start_url"
                ));
            }
            _ => {}
        }

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
        // Signals to any caller waiting in `refresh_singleflight` that a
        // full adoption has completed, regardless of what value it
        // produced — see `refresh_generation`'s doc comment. Ordered after
        // the store write above so that a waiter which observes the new
        // generation is guaranteed to also observe this write when it
        // subsequently calls `self.store.load()`.
        self.refresh_generation.fetch_add(1, Ordering::SeqCst);
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
        } else {
            // Not fatal (this refresh is best-effort by design), but worth
            // a diagnostic trail: a future off-runtime call site would
            // otherwise silently never get model/profile cache warming with
            // no signal that anything was skipped.
            tracing::debug!(
                "adopt(): no Tokio runtime in scope, skipping model/profile cache refresh for this credential"
            );
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
            expiry_buffer_ms: 0,
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
        let result = manager.refresh_cascade(&hint, None).unwrap();

        assert_eq!(result.access, "ide-access");
    }

    #[test]
    fn refresh_cascade_skips_layer_0_when_the_ide_token_is_the_rejected_one() {
        // Finding #1(b): a 401 arrives on token T, sourced from the Kiro
        // IDE. If the IDE hasn't rotated its own token yet (a real race --
        // it refreshes on its own schedule, not ours), Layer 0 must not
        // hand back that exact same rejected token; it must fall through
        // to the next layer instead, here Layer 1's valid kiro-cli
        // credential.
        let tmp = TempDir::new().unwrap();
        write_ide_token_file(tmp.path(), "rejected-token", "2099-01-01T00:00:00.000Z");
        write_kiro_cli_idc_db(tmp.path(), "cli-access", "2099-01-01T00:00:00.000Z");
        let deps = deps_for(tmp.path());
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps(store, deps);

        let hint = far_future_creds();
        let result = manager
            .refresh_cascade(&hint, Some("rejected-token"))
            .unwrap();

        assert_eq!(
            result.access, "cli-access",
            "Layer 0's rejected IDE token must be skipped in favor of Layer 1's kiro-cli credential"
        );
    }

    #[test]
    fn refresh_cascade_skips_layer_1_when_kiro_cli_holds_the_rejected_token() {
        // Same Finding #1(b) concern as Layer 0, but for kiro-cli's
        // precheck: if kiro-cli's cached token is the one that was just
        // rejected (kiro-cli hasn't refreshed either), Layer 1 must not
        // hand it back -- it must fall through, here reaching Layer 2's
        // real refresh since nothing else is available.
        let tmp = TempDir::new().unwrap();
        write_kiro_cli_idc_db(tmp.path(), "rejected-token", "2099-01-01T00:00:00.000Z");
        let deps = deps_for(tmp.path());

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let refresh_fn: Box<RefreshFn> = Box::new(move |current: &KiroCredentials| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(KiroCredentials {
                access: "freshly-refreshed-access".into(),
                refresh: "new-r".into(),
                expires: now_ms() + 3_600_000,
                region: current.region.clone(),
                auth_method: current.auth_method,
                client_id: current.client_id.clone(),
                client_secret: current.client_secret.clone(),
                profile_arn: current.profile_arn.clone(),
                expiry_buffer_ms: 0,
            })
        });

        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let hint = far_future_creds();
        let result = manager
            .refresh_cascade(&hint, Some("rejected-token"))
            .unwrap();

        assert_eq!(result.access, "freshly-refreshed-access");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "Layer 1's rejected kiro-cli token must be skipped, falling through to a real Layer 2 refresh"
        );
    }

    #[test]
    fn refresh_cascade_never_replays_the_rejected_token_via_layer_3() {
        // Finding #1(b), the gap the Layer 1 fix alone didn't cover: Layer
        // 2's success path always writes our own token into kiro-cli's DB
        // (save_kiro_cli_credentials_for), so "kiro-cli's DB holds exactly
        // the token we're currently using" is the steady state, not an
        // edge case. If that same token then gets rejected and Layer 2's
        // own refresh attempt also fails (e.g. genuinely revoked, not just
        // expired), Layer 3 re-reads the identical DB row Layer 1 already
        // filtered -- without its own filter, it would find the rejected
        // token again and hand it straight back, exactly the infinite-retry
        // loop rejected_access exists to prevent, one layer past where the
        // first fix landed.
        //
        // Setup: kiro-cli's DB is the ONLY credential source (no IDE file),
        // holding exactly the rejected token, and refresh_fn always fails
        // (simulating Layer 2 failing). The cascade must never resolve to
        // Ok(rejected-token) -- falling through further (Layer 3.5/4/5) to
        // an eventual Err is the only acceptable outcome, matching the
        // real interleaving this scenario models.
        let tmp = TempDir::new().unwrap();
        write_kiro_cli_idc_db(tmp.path(), "rejected-token", "2099-01-01T00:00:00.000Z");
        let deps = deps_for(tmp.path());

        let refresh_fn: Box<RefreshFn> = Box::new(|_current: &KiroCredentials| {
            Err(anyhow::anyhow!("simulated Layer 2 failure"))
        });

        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        // `refresh` matches write_kiro_cli_idc_db's fixed "cli-refresh"
        // value, so Layer 4's `expired_cli.refresh != current.refresh`
        // discriminator also correctly declines (nothing "newer" exists).
        let current = KiroCredentials {
            access: "rejected-token".into(),
            refresh: "cli-refresh".into(),
            expires: now_ms().saturating_sub(600_000),
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 0,
        };

        let result = manager.refresh_cascade(&current, Some("rejected-token"));

        // Failing outright is a safe, acceptable outcome here; only
        // silently replaying the rejected token is not.
        if let Ok(creds) = result {
            assert_ne!(
                creds.access, "rejected-token",
                "must never silently return the token that was just rejected"
            );
        }
    }

    #[test]
    fn get_auth_triggers_a_real_refresh_when_stored_credential_is_stale_by_time() {
        // All prior refresh-related tests drive the cascade through
        // force_refresh(); this one proves get_auth()'s own near-expiry
        // path also reaches refresh_singleflight/refresh_cascade, not just
        // force_refresh's unconditional path.
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let stale_by_time = KiroCredentials {
            access: "stale-by-time-access".into(),
            refresh: "r".into(),
            // Within the 5-minute refresh margin, but not yet past its own
            // recorded expiry -- this is get_auth's proactive-refresh
            // trigger, distinct from force_refresh's unconditional one.
            expires: now_ms() + 60_000,
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 0,
        };
        store.save(stale_by_time).unwrap();

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let refresh_fn: Box<RefreshFn> = Box::new(move |current: &KiroCredentials| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(KiroCredentials {
                access: "freshly-refreshed-access".into(),
                refresh: "new-r".into(),
                expires: now_ms() + 3_600_000,
                region: current.region.clone(),
                auth_method: current.auth_method,
                client_id: current.client_id.clone(),
                client_secret: current.client_secret.clone(),
                profile_arn: current.profile_arn.clone(),
                expiry_buffer_ms: 0,
            })
        });

        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let result = manager.get_auth().unwrap();

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "get_auth must actually refresh a stale-by-time credential, not just return it as-is"
        );
        assert_eq!(result.access, "freshly-refreshed-access");
    }

    #[test]
    fn refresh_cascade_layer_5_extends_expiry_by_the_credentials_own_buffer() {
        // Regression test for the Layer 5 fix: extension math must use
        // *this credential's* recorded expiry_buffer_ms, not a hardcoded
        // universal margin. Every earlier layer is made to miss (empty
        // deps dir, and refresh_fn always fails), so the cascade must reach
        // Layer 5.
        let refresh_fn: Box<RefreshFn> =
            Box::new(|_current: &KiroCredentials| Err(anyhow::anyhow!("simulated failure")));
        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let original_expires = now_ms().saturating_sub(60_000);
        let buffer_ms = 5 * 60 * 1000;
        let current = KiroCredentials {
            access: "buffered-access".into(),
            refresh: "r".into(),
            expires: original_expires,
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: buffer_ms,
        };

        let result = manager.refresh_cascade(&current, None).unwrap();

        assert_eq!(result.access, "buffered-access");
        assert_eq!(
            result.expires,
            original_expires + buffer_ms,
            "must extend by exactly this credential's own buffer, not a hardcoded 5-minute margin"
        );
    }

    #[test]
    fn refresh_cascade_layer_5_grants_no_extension_for_a_credential_with_no_buffer() {
        // The other half of the Layer 5 fix: a kiro-cli-sourced credential
        // (expiry_buffer_ms: 0) has no hidden slack at all. Using the same
        // `expires` value as the test above but with buffer_ms = 0, Layer 5
        // must NOT grant any extension -- under the old hardcoded
        // "+5 minutes for everyone" logic, this exact case would have been
        // wrongly kept alive for 5 more minutes past its true AWS expiry.
        let refresh_fn: Box<RefreshFn> =
            Box::new(|_current: &KiroCredentials| Err(anyhow::anyhow!("simulated failure")));
        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let current = KiroCredentials {
            access: "unbuffered-access".into(),
            refresh: "r".into(),
            expires: now_ms().saturating_sub(60_000),
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 0,
        };

        let err = manager.refresh_cascade(&current, None).unwrap_err();

        assert!(
            err.to_string().contains("simulated failure"),
            "must propagate the real refresh error instead of falsely granting extra time"
        );
    }

    #[test]
    fn refresh_cascade_layer_5_refuses_to_extend_the_rejected_token() {
        // Finding #1(b), Layer 5's half: graceful degradation must never
        // hand back the exact token that was just proven bad by a
        // 401/403 -- doing so would falsely mark it "good for longer" and
        // guarantee the caller repeats the same failure. Same shape as
        // `refresh_cascade_layer_5_extends_expiry_by_the_credentials_own_buffer`
        // (which would otherwise succeed via Layer 5), but this time the
        // token IS the one that was just rejected.
        let refresh_fn: Box<RefreshFn> =
            Box::new(|_current: &KiroCredentials| Err(anyhow::anyhow!("simulated failure")));
        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let current = KiroCredentials {
            access: "rejected-token".into(),
            refresh: "r".into(),
            expires: now_ms().saturating_sub(60_000),
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 5 * 60 * 1000,
        };

        let err = manager
            .refresh_cascade(&current, Some("rejected-token"))
            .unwrap_err();

        assert!(
            err.to_string().contains("simulated failure"),
            "must propagate the real refresh error instead of extending the rejected token's expiry"
        );
    }

    #[test]
    fn refresh_cascade_layer_3_recovers_via_kiro_cli_written_concurrently_during_a_failed_refresh()
    {
        // Layer 1's precheck can miss (nothing valid in kiro-cli's DB yet)
        // while our own Layer 2 refresh attempt is in flight; if kiro-cli
        // independently rotates its own token during that window and our
        // own refresh_fn then fails, Layer 3 re-reads kiro-cli's DB once
        // more and should pick up that freshly-written credential instead
        // of falling through further. The refresh_fn closure below writes
        // to the kiro-cli DB itself as a side effect, standing in for "some
        // other process (kiro-cli) finished its own refresh concurrently".
        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let home = tmp.path().to_path_buf();

        let refresh_fn: Box<RefreshFn> = Box::new(move |_current: &KiroCredentials| {
            write_kiro_cli_idc_db(&home, "kiro-cli-rotated-access", "2099-01-01T00:00:00.000Z");
            Err(anyhow::anyhow!("simulated direct-refresh failure"))
        });

        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let result = manager.refresh_cascade(&far_future_creds(), None).unwrap();

        assert_eq!(result.access, "kiro-cli-rotated-access");
    }

    #[test]
    fn refresh_cascade_layer_4_retries_refresh_using_a_newer_expired_kiro_cli_refresh_token() {
        // kiro-cli can hold a *different* refresh token than the one we're
        // currently holding, even though it's also past our own margin (so
        // Layer 1/3's allow_expired=false reads still miss it). Layer 4
        // retries the direct refresh using that newer token instead of
        // giving up, since it might still be valid even though ours isn't.
        let tmp = TempDir::new().unwrap();
        // Expired per our margin (allow_expired=false misses it), but with
        // a refresh token distinct from `current.refresh` below.
        write_kiro_cli_idc_db(tmp.path(), "cli-expired-access", "2000-01-01T00:00:00.000Z");
        let deps = deps_for(tmp.path());

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let refresh_fn: Box<RefreshFn> = Box::new(move |creds: &KiroCredentials| {
            let call_number = counter.fetch_add(1, Ordering::SeqCst);
            if call_number == 0 {
                // First call: refreshing with our own (current) credentials fails.
                assert_eq!(creds.refresh, "our-old-refresh");
                return Err(anyhow::anyhow!("simulated failure for our own token"));
            }
            // Second call: retried with kiro-cli's newer (still-expired-to-us) refresh token.
            assert_eq!(creds.refresh, "cli-refresh");
            Ok(KiroCredentials {
                access: "layer-4-recovered-access".into(),
                refresh: "layer-4-new-refresh".into(),
                expires: now_ms() + 3_600_000,
                region: creds.region.clone(),
                auth_method: creds.auth_method,
                client_id: creds.client_id.clone(),
                client_secret: creds.client_secret.clone(),
                profile_arn: creds.profile_arn.clone(),
                expiry_buffer_ms: 0,
            })
        });

        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let current = KiroCredentials {
            access: "our-old-access".into(),
            refresh: "our-old-refresh".into(),
            expires: now_ms().saturating_sub(600_000),
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 0,
        };

        let result = manager.refresh_cascade(&current, None).unwrap();

        assert_eq!(result.access, "layer-4-recovered-access");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "must attempt refresh with our own credentials first, then kiro-cli's newer expired ones"
        );
    }

    #[test]
    fn concurrent_refresh_reuses_a_completed_layer_5_degradation_instead_of_re_running_the_cascade()
    {
        // Regression test for the gap an access-token-equality discriminator
        // cannot close (see refresh_singleflight's doc comment, rejected
        // approach 2): Layer 5's graceful-degradation extension returns a
        // credential with the SAME `access` as `current` -- it only extends
        // `expires`. A discriminator comparing access tokens would see
        // `latest.access == hint.access` after the winner adopts a Layer-5
        // extension and wrongly conclude "nobody refreshed yet", sending the
        // loser through the entire cascade (including a second failing
        // refresh_fn call) again. The generation-counter re-check must
        // short-circuit the loser regardless of access-token identity.
        //
        // Both callers pass a `rejected_access` that deliberately does NOT
        // match "still-the-same-access" -- Layer 5 now also refuses to
        // extend a candidate that matches `rejected_access` (rejected
        // approach 3, see refresh_singleflight's doc comment), so this test
        // uses an unrelated placeholder to isolate what it's actually
        // testing here (the generation-counter singleflight mechanism) from
        // that separate rejected-token-gating mechanism, which has its own
        // dedicated coverage (`refresh_cascade_layer_5_refuses_to_extend_the_rejected_token`
        // and friends).
        let store = InMemoryAuthStore::<KiroCredentials>::default();
        let near_expiry = KiroCredentials {
            access: "still-the-same-access".into(),
            refresh: "r".into(),
            // Already past its own recorded expiry, but expiry_buffer_ms
            // leaves 5 real minutes of slack, so Layer 5 succeeds instead
            // of erroring out.
            expires: now_ms().saturating_sub(30_000),
            region: "us-east-1".into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: None,
            expiry_buffer_ms: 5 * 60 * 1000,
        };
        store.save(near_expiry).unwrap();

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let refresh_fn: Box<RefreshFn> = Box::new(move |_current: &KiroCredentials| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(50));
            Err(anyhow::anyhow!("simulated failure"))
        });

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
                    m.force_refresh("an-unrelated-401-token-not-in-play")
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
            "the loser must reuse the winner's Layer-5 result instead of re-running refresh_fn"
        );
        assert_eq!(results[0].access, "still-the-same-access");
        assert_eq!(results[1].access, "still-the-same-access");
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
                expiry_buffer_ms: 0,
            })
        });

        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let manager = KiroAuthManager::with_deps_and_refresh_fn(store, deps, refresh_fn);

        let result = manager.force_refresh("a").unwrap();

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
            expiry_buffer_ms: 0,
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
                expiry_buffer_ms: 0,
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
                    m.force_refresh("old-access")
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

    #[test]
    fn force_refresh_does_not_trust_a_fast_path_replay_of_the_rejected_token() {
        // A subtler corner of Finding #1(b): even the generation-counter
        // fast path in refresh_singleflight (added to fix the *unrelated*
        // singleflight regression) must not blindly trust "some adopt()
        // completed" -- if that completed adopt() belonged to an unrelated
        // caller (e.g. a plain get_auth() that knows nothing about this
        // 401) that itself re-adopted the exact token this caller is
        // trying to get rid of, trusting the fast path would silently hand
        // the caller back the very token it explicitly flagged as bad.
        //
        // Made fully deterministic (no thread-timing luck) by manually
        // holding `refresh_lock` from this test thread: `refresh_lock` is
        // a private field, and this test module has access to it as a
        // sibling module. Thread A blocks trying to acquire it inside
        // `refresh_singleflight`; while it's blocked, this thread performs
        // the "concurrent unrelated adopt" directly via `refresh_cascade`
        // (which itself never touches `refresh_lock` -- only
        // `refresh_singleflight` enforces it), then releases the lock.
        let tmp = TempDir::new().unwrap();
        write_ide_token_file(tmp.path(), "rejected-token", "2099-01-01T00:00:00.000Z");
        let deps = deps_for(tmp.path());

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();
        let refresh_fn: Box<RefreshFn> = Box::new(move |current: &KiroCredentials| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(KiroCredentials {
                access: "freshly-refreshed-access".into(),
                refresh: "new-r".into(),
                expires: now_ms() + 3_600_000,
                region: current.region.clone(),
                auth_method: current.auth_method,
                client_id: current.client_id.clone(),
                client_secret: current.client_secret.clone(),
                profile_arn: current.profile_arn.clone(),
                expiry_buffer_ms: 0,
            })
        });

        let store = InMemoryAuthStore::<KiroCredentials>::default();
        store
            .save(KiroCredentials {
                access: "rejected-token".into(),
                refresh: "r".into(),
                expires: now_ms() + 3_600_000,
                region: "us-east-1".into(),
                auth_method: KiroAuthMethod::Idc,
                client_id: String::new(),
                client_secret: String::new(),
                profile_arn: None,
                expiry_buffer_ms: 0,
            })
            .unwrap();

        let manager = Arc::new(KiroAuthManager::with_deps_and_refresh_fn(
            store, deps, refresh_fn,
        ));

        // Hold the lock manually so Thread A blocks inside
        // refresh_singleflight after sampling generation_before.
        let guard = manager.refresh_lock.lock().unwrap();

        let m = manager.clone();
        let handle = std::thread::spawn(move || m.force_refresh("rejected-token"));

        // Generous margin for Thread A to reach and block on the lock --
        // it only needs to sample one atomic and attempt one mutex lock
        // first, so this is not a tight race.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // The "concurrent unrelated adopt": bypasses the lock entirely
        // (exactly as refresh_cascade allows), re-adopting the Kiro IDE's
        // token -- which is still "rejected-token", since nothing here
        // passes a rejected_access to gate it.
        let hint = far_future_creds();
        let replayed = manager.refresh_cascade(&hint, None).unwrap();
        assert_eq!(
            replayed.access, "rejected-token",
            "sanity check: Layer 0 wins normally when nothing is rejected"
        );

        drop(guard);

        let result = handle.join().unwrap().unwrap();

        assert_ne!(
            result.access, "rejected-token",
            "the fast path must not trust a store value that matches rejected_access, even after a generation bump"
        );
        assert_eq!(result.access, "freshly-refreshed-access");
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

    #[test]
    fn bootstrap_login_rejects_contradictory_preferred_and_start_url_combinations() {
        // preferred=BuilderId never takes a start_url, and preferred=Idc
        // always requires one -- Step 4's device-flow selection is driven
        // purely by start_url.is_some(), so a caller supplying a
        // contradictory pair must get an explicit error, not the silently
        // "wrong" flow that pair would otherwise select.
        let tmp = TempDir::new().unwrap();
        let deps = deps_for(tmp.path());
        let callbacks = RecordingCallbacks {
            progress_calls: AtomicUsize::new(0),
            prompt_calls: AtomicUsize::new(0),
        };

        let store_a = InMemoryAuthStore::<KiroCredentials>::default();
        let manager_a = KiroAuthManager::with_deps(store_a, deps.clone());
        let err_a = manager_a
            .bootstrap_login(
                &callbacks,
                KiroLoginMethod::BuilderId,
                Some("https://example.com/start"),
            )
            .unwrap_err();
        assert!(err_a.to_string().contains("BuilderId"));

        let store_b = InMemoryAuthStore::<KiroCredentials>::default();
        let manager_b = KiroAuthManager::with_deps(store_b, deps);
        let err_b = manager_b
            .bootstrap_login(&callbacks, KiroLoginMethod::Idc, None)
            .unwrap_err();
        assert!(err_b.to_string().contains("Idc"));

        // Neither rejected combination should have touched the device flow.
        assert_eq!(callbacks.progress_calls.load(Ordering::SeqCst), 0);
        assert_eq!(callbacks.prompt_calls.load(Ordering::SeqCst), 0);
    }
}
