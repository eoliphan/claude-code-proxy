//! Per-tier Anthropic-alias -> concrete Kiro model ID mapping.
//!
//! Unlike Kimi's `translate/model_allowlist.rs` (which collapses every alias
//! to a single default model), Kiro exposes distinct model tiers, so each
//! alias resolves to the concrete Kiro model that best matches its tier.
//! Kiro has no tier corresponding to Anthropic's "fable" — the nearest
//! available tier (Opus) is used per the design doc's note.

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
    for alias in [
        "opus",
        "claude-opus-4-7",
        "claude-opus-4-8",
        "claude-opus-5",
    ] {
        m.insert(alias, "claude-opus-4-8");
    }
    // No Kiro tier corresponds to "fable" — nearest available tier per the design doc's note.
    for alias in ["fable", "claude-fable-5"] {
        m.insert(alias, "claude-opus-4-8");
    }
    m
});

/// Resolve an Anthropic-style alias (or already-concrete Kiro model ID) to a
/// concrete Kiro model ID, dash form. IDs with no alias entry pass through
/// unchanged.
pub fn resolve_model(alias_or_id: &str) -> String {
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
        for alias in [
            "haiku",
            "sonnet",
            "opus",
            "fable",
            "claude-sonnet-5",
            "claude-opus-5",
        ] {
            let resolved = resolve_model(alias);
            assert_ne!(
                resolved, alias,
                "{alias} should resolve to a concrete model, not pass through"
            );
        }
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
