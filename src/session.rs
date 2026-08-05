use crate::config::AliasProvider;
use crate::registry::normalize_incoming_model;
use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};

const SESSION_IDLE_TTL_MS: u64 = 30 * 60 * 1000;
pub const MAX_SESSIONS: usize = 10_000;

#[derive(Debug, Clone)]
pub struct SessionState {
    pub seq: u64,
    pub affinity_provider: Option<AliasProvider>,
    pub last_seen: u64,
}

#[derive(Default)]
struct SessionStore {
    map: HashMap<String, SessionState>,
    order: VecDeque<String>,
}

static SESSIONS: LazyLock<Mutex<SessionStore>> =
    LazyLock::new(|| Mutex::new(SessionStore::default()));

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_millis() as u64
}

pub fn existing_session(session_id: Option<&str>, now: u64) -> Option<SessionState> {
    let id = session_id?;
    let mut store = SESSIONS.lock().expect("session lock");
    let state = store.map.get(id).cloned()?;
    if now.saturating_sub(state.last_seen) > SESSION_IDLE_TTL_MS {
        store.map.remove(id);
        store.order.retain(|item| item != id);
        return None;
    }
    Some(state)
}

pub fn existing_session_now(session_id: Option<&str>) -> Option<SessionState> {
    existing_session(session_id, now_millis())
}

pub fn record_session_request(
    session_id: Option<&str>,
    prior: Option<&SessionState>,
    provider_name: &str,
    model: &str,
    now: u64,
) -> Option<SessionState> {
    record_session_request_with_affinity_update(session_id, prior, provider_name, model, true, now)
}

pub(crate) fn record_session_request_with_affinity_update(
    session_id: Option<&str>,
    prior: Option<&SessionState>,
    provider_name: &str,
    model: &str,
    update_affinity: bool,
    now: u64,
) -> Option<SessionState> {
    let id = session_id?;
    let mut store = SESSIONS.lock().expect("session lock");
    let mut next = prior.cloned().unwrap_or(SessionState {
        seq: 0,
        affinity_provider: None,
        last_seen: now,
    });
    next.seq += 1;
    next.last_seen = now;
    if update_affinity
        && is_alias_routable_provider(provider_name)
        && !crate::registry::is_anthropic_alias(normalize_incoming_model(model).as_str())
    {
        next.affinity_provider = Some(match provider_name {
            "codex" => AliasProvider::Codex,
            "kimi" => AliasProvider::Kimi,
            "kiro" => AliasProvider::Kiro,
            _ => next.affinity_provider.unwrap_or(AliasProvider::Codex),
        });
    }

    if !store.map.contains_key(id) {
        store.order.push_back(id.to_string());
    }
    store.map.insert(id.to_string(), next.clone());

    while store.order.len() > MAX_SESSIONS {
        if let Some(evict) = store.order.pop_front() {
            store.map.remove(&evict);
        } else {
            break;
        }
    }

    Some(next)
}

/// Providers a bare Anthropic-style alias can be routed to, and therefore the
/// only ones worth pinning session affinity on. Kiro joined this set once it
/// stopped being a `PlaceholderProvider`: `AliasProvider::Kiro` is a real,
/// configurable alias target, so a session that used a concrete Kiro model
/// must keep its later alias requests on Kiro.
fn is_alias_routable_provider(name: &str) -> bool {
    matches!(name, "codex" | "kimi" | "kiro")
}

#[cfg(test)]
pub fn reset_sessions_for_test() {
    let mut store = SESSIONS.lock().expect("session lock");
    store.map.clear();
    store.order.clear();
}

pub fn affinity_provider_from_session(session: &SessionState) -> Option<AliasProvider> {
    session.affinity_provider
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_concrete_kiro_model_pins_session_affinity_to_kiro() {
        // Kiro is a real provider *and* a valid `AliasProvider`, so a session
        // that used a concrete Kiro model must keep subsequent bare-alias
        // requests on Kiro instead of falling back to the configured global
        // alias provider.
        // `deepseek-3-2` is Kiro-only and absent from `ANTHROPIC_STYLE_ALIASES`,
        // so it is a genuine affinity-establishing request.
        let session_id = "session-affinity-kiro-test";
        let state = record_session_request(Some(session_id), None, "kiro", "deepseek-3-2", 1)
            .expect("session");
        assert_eq!(state.affinity_provider, Some(AliasProvider::Kiro));
    }

    #[test]
    fn a_bare_alias_answered_by_kiro_does_not_pin_affinity() {
        // Mirrors the codex/kimi rule: an alias request is *routed* by the
        // existing affinity, so it must never establish one.
        let session_id = "session-affinity-kiro-alias-test";
        let state =
            record_session_request(Some(session_id), None, "kiro", "sonnet", 1).expect("session");
        assert_eq!(state.affinity_provider, None);
    }

    #[test]
    fn auxiliary_request_does_not_change_session_affinity() {
        let session_id = "session-affinity-auxiliary-request-test";
        let initial = record_session_request(Some(session_id), None, "codex", "gpt-5.6-sol", 1)
            .expect("initial session");
        assert_eq!(initial.affinity_provider, Some(AliasProvider::Codex));

        let after_review = record_session_request_with_affinity_update(
            Some(session_id),
            Some(&initial),
            "kimi",
            "kimi-for-coding",
            false,
            2,
        )
        .expect("updated session");
        assert_eq!(after_review.seq, 2);
        assert_eq!(after_review.affinity_provider, Some(AliasProvider::Codex));
    }
}
