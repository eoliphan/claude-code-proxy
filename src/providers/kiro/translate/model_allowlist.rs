//! Per-tier Anthropic-alias -> concrete Kiro model ID mapping.
//!
//! Unlike Kimi's `translate/model_allowlist.rs` (which collapses every alias
//! to a single default model), Kiro exposes distinct model tiers, so each
//! alias resolves to the concrete Kiro model that best matches its tier.
//! Kiro has no tier corresponding to Anthropic's "fable", so the nearest
//! available tier (Opus) is used per the design doc's note.

use once_cell::sync::Lazy;
use std::collections::HashMap;

static ALIAS_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for alias in ["haiku", "claude-haiku-4-5", "claude-haiku-4-5-20251001"] {
        m.insert(alias, "claude-haiku-4-5");
    }
    // claude-sonnet-5 stays on 4.6: Kiro's Sonnet 5 intermittently echoes the
    // injected <max_thinking_length>/<thinking_length> control tags into its
    // text output. It is still selectable explicitly as kiro:claude-sonnet-5.
    for alias in ["sonnet", "claude-sonnet-4-6", "claude-sonnet-5"] {
        m.insert(alias, "claude-sonnet-4-6");
    }
    for alias in ["claude-opus-4-7", "claude-opus-4-8"] {
        m.insert(alias, "claude-opus-4-8");
    }
    // Bare `opus` follows the newest Opus tier Kiro serves.
    m.insert("opus", "claude-opus-5-5");
    // Kiro serves these exact versions (confirmed by a live
    // ListAvailableModels call), so they map to themselves rather than to
    // the nearest older tier.
    for alias in ["claude-opus-5-5", "claude-opus-5"] {
        m.insert(alias, alias);
    }
    m
});

/// No Kiro tier corresponds to "fable"; the nearest available tier is used.
/// Matched with the registry's own pattern so every `claude-fable-*` alias
/// the registry routes here also resolves here.
const FABLE_TARGET: &str = "claude-opus-4-8";

/// Resolve an Anthropic-style alias (or already-concrete Kiro model ID) to a
/// concrete Kiro model ID, dash form. IDs with no alias entry pass through
/// unchanged.
pub fn resolve_model(alias_or_id: &str) -> String {
    if crate::registry::is_fable_alias(alias_or_id) {
        return FABLE_TARGET.to_string();
    }
    ALIAS_MAP
        .get(alias_or_id)
        .map(|s| s.to_string())
        .unwrap_or_else(|| alias_or_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_every_anthropic_alias_to_a_concrete_kiro_model() {
        // Iterates the registry's own alias list so a new upstream alias
        // (e.g. claude-opus-5-5 in v0.1.42) fails here instead of silently
        // passing through to Kiro as an unknown model ID.
        let future_fable = "claude-fable-6-20270101";
        for alias in crate::registry::ANTHROPIC_STYLE_ALIASES
            .iter()
            .copied()
            .chain([future_fable])
        {
            let resolved = resolve_model(alias);
            assert!(
                crate::providers::kiro::translate::models::KIRO_MODELS
                    .iter()
                    .any(|m| m.id == resolved),
                "{alias} -> {resolved} is not in KIRO_MODELS"
            );
        }
    }

    #[test]
    fn version_aliases_resolve_to_their_intended_kiro_models() {
        assert_eq!(resolve_model("opus"), "claude-opus-5-5");
        assert_eq!(resolve_model("claude-opus-5-5"), "claude-opus-5-5");
        assert_eq!(resolve_model("claude-opus-5"), "claude-opus-5");
        assert_eq!(resolve_model("claude-sonnet-5"), "claude-sonnet-4-6");
    }

    #[test]
    fn passes_through_ids_with_no_alias_entry() {
        assert_eq!(resolve_model("deepseek-3-2"), "deepseek-3-2");
    }

    #[test]
    fn every_alias_target_is_a_real_kiro_model() {
        // Guards against drift if Task 6's catalog changes: every value this
        // map can produce must be a real, currently-cataloged Kiro model id.
        for alias in ALIAS_MAP.keys() {
            let resolved = resolve_model(alias);
            assert!(
                crate::providers::kiro::translate::models::KIRO_MODELS
                    .iter()
                    .any(|m| m.id == resolved),
                "{alias} -> {resolved} is not in KIRO_MODELS"
            );
        }
    }
}
