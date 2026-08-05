//! Static Kiro model catalog, dash/dot ID conversion, API-region resolution,
//! region-filtered model availability, and a heuristic token estimator.
//!
//! Kiro's own API identifies models with dots in version numbers (e.g.
//! `claude-opus-4.8`), while this proxy (and the `pi` reference client)
//! use dashes (`claude-opus-4-8`) so model IDs read naturally as CLI/URL
//! path segments. [`dash_to_dot`] / [`dot_to_dash`] convert between the two.
//!
//! The catalog data below is transcribed verbatim from the `pi-provider-kiro`
//! reference implementation's `src/models.ts` (`kiroModels`, `API_REGION_MAP`,
//! `MODELS_BY_REGION` — the last as a computed exclusion list, see
//! [`models_for_region`]), read directly at implementation time rather than
//! assumed from summarized research.

/// Metadata for a single Kiro model, keyed by its dash-form ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KiroModelMeta {
    /// Dash-form model ID, e.g. `"claude-opus-4-8"`.
    pub id: &'static str,
    pub name: &'static str,
    pub reasoning: bool,
    /// True if the model's supported input modalities include image.
    pub input_image: bool,
    pub context_window: u64,
    pub max_tokens: u64,
    pub first_token_timeout_ms: u64,
}

/// Fallback first-token timeout for models that don't override it.
pub const DEFAULT_FIRST_TOKEN_TIMEOUT_MS: u64 = 90_000;

/// Only the largest Opus models (1M context, 128K max output) need the
/// longer first-token timeout — mirrors the `firstTokenTimeout: 180_000`
/// field set solely on `claude-opus-4-8` and `claude-opus-4-7` in the TS
/// reference's `kiroModels` catalog entries (every other entry omits the
/// field, so [`first_token_timeout_for`] falls back to
/// [`DEFAULT_FIRST_TOKEN_TIMEOUT_MS`] for them).
const LARGE_OPUS_FIRST_TOKEN_TIMEOUT_MS: u64 = 180_000;

/// Static catalog of Kiro's known models, dash-form IDs. Used as
/// `Registry::new`'s fallback when dynamic model discovery (Task 7) is
/// unavailable, and as the template `first_token_timeout_for` /
/// `models_for_region` operate over.
pub const KIRO_MODELS: &[KiroModelMeta] = &[
    KiroModelMeta {
        id: "claude-opus-4-8",
        name: "Claude Opus 4.8",
        reasoning: true,
        input_image: true,
        context_window: 1_000_000,
        max_tokens: 128_000,
        first_token_timeout_ms: LARGE_OPUS_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-opus-4-7",
        name: "Claude Opus 4.7",
        reasoning: true,
        input_image: true,
        context_window: 1_000_000,
        max_tokens: 128_000,
        first_token_timeout_ms: LARGE_OPUS_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-opus-4-6",
        name: "Claude Opus 4.6",
        reasoning: true,
        input_image: true,
        context_window: 1_000_000,
        max_tokens: 32_768,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-opus-4-6-1m",
        name: "Claude Opus 4.6 (1M) [Deprecated]",
        reasoning: true,
        input_image: true,
        context_window: 1_000_000,
        max_tokens: 32_768,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-sonnet-4-6",
        name: "Claude Sonnet 4.6",
        reasoning: true,
        input_image: true,
        context_window: 1_000_000,
        max_tokens: 65_536,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-sonnet-4-6-1m",
        name: "Claude Sonnet 4.6 (1M) [Deprecated]",
        reasoning: true,
        input_image: true,
        context_window: 1_000_000,
        max_tokens: 65_536,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-opus-4-5",
        name: "Claude Opus 4.5",
        reasoning: true,
        input_image: true,
        context_window: 200_000,
        max_tokens: 32_768,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-sonnet-4-5",
        name: "Claude Sonnet 4.5",
        reasoning: true,
        input_image: true,
        context_window: 200_000,
        max_tokens: 65_536,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-sonnet-4",
        name: "Claude Sonnet 4",
        reasoning: true,
        input_image: true,
        context_window: 200_000,
        max_tokens: 65_536,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "claude-haiku-4-5",
        name: "Claude Haiku 4.5",
        reasoning: false,
        input_image: true,
        context_window: 200_000,
        max_tokens: 65_536,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "deepseek-3-2",
        name: "DeepSeek 3.2",
        reasoning: true,
        input_image: false,
        context_window: 128_000,
        max_tokens: 8_192,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "kimi-k2-5",
        name: "Kimi K2.5",
        reasoning: true,
        input_image: false,
        context_window: 200_000,
        max_tokens: 8_192,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "minimax-m2-1",
        name: "MiniMax M2.1",
        reasoning: false,
        input_image: false,
        context_window: 200_000,
        max_tokens: 8_192,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "minimax-m2-5",
        name: "MiniMax M2.5",
        reasoning: false,
        input_image: false,
        context_window: 200_000,
        max_tokens: 8_192,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "glm-5",
        name: "GLM 5",
        reasoning: true,
        input_image: false,
        context_window: 128_000,
        max_tokens: 8_192,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "qwen3-coder-next",
        name: "Qwen3 Coder Next",
        reasoning: true,
        input_image: false,
        context_window: 256_000,
        max_tokens: 8_192,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "agi-nova-beta-1m",
        name: "AGI Nova Beta (1M)",
        reasoning: true,
        input_image: true,
        context_window: 1_000_000,
        max_tokens: 65_536,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "qwen3-coder-480b",
        name: "Qwen3 Coder 480B",
        reasoning: true,
        input_image: false,
        context_window: 128_000,
        max_tokens: 8_192,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
    KiroModelMeta {
        id: "auto",
        name: "Auto",
        reasoning: true,
        input_image: true,
        context_window: 200_000,
        max_tokens: 65_536,
        first_token_timeout_ms: DEFAULT_FIRST_TOKEN_TIMEOUT_MS,
    },
];

/// Convert a dash-form model ID (this proxy's / pi's convention) to Kiro's
/// dot-form ID by joining digit-dash-digit runs with a dot, e.g.
/// `"claude-sonnet-4-6"` -> `"claude-sonnet-4.6"`. Only touches version-number
/// punctuation — words like `"auto"` pass through unchanged.
pub fn dash_to_dot(model_id: &str) -> String {
    regex_lite::Regex::new(r"(\d)-(\d)")
        .unwrap()
        .replace_all(model_id, "$1.$2")
        .into_owned()
}

/// Inverse of [`dash_to_dot`] — converts a Kiro dot-form model ID (as seen
/// in API responses) back to this proxy's dash-form ID.
pub fn dot_to_dash(model_id: &str) -> String {
    regex_lite::Regex::new(r"(\d)\.(\d)")
        .unwrap()
        .replace_all(model_id, "$1-$2")
        .into_owned()
}

const API_REGION_MAP: &[(&str, &str)] = &[
    ("us-west-1", "us-east-1"),
    ("us-west-2", "us-east-1"),
    ("us-east-2", "us-east-1"),
    ("ap-southeast-1", "us-east-1"),
    ("ap-southeast-2", "us-east-1"),
    ("ap-northeast-1", "us-east-1"),
    ("ap-south-1", "us-east-1"),
    ("eu-west-1", "eu-central-1"),
    ("eu-west-2", "eu-central-1"),
    ("eu-west-3", "eu-central-1"),
    ("eu-north-1", "eu-central-1"),
    ("eu-south-1", "eu-central-1"),
    ("eu-south-2", "eu-central-1"),
    ("eu-central-2", "eu-central-1"),
];

/// SSO/OIDC region -> Kiro API region. The Kiro Q API is only deployed in a
/// subset of regions; tokens issued by an SSO instance in, e.g., `eu-west-1`
/// must be sent to the `eu-central-1` API endpoint. Mirrors
/// `resolveApiRegion` in the TS reference, including its behavior of passing
/// an unmapped region through unchanged (rather than defaulting it), except
/// when the input is empty, which defaults to `"us-east-1"`.
pub fn resolve_api_region(sso_region: &str) -> String {
    if sso_region.is_empty() {
        return "us-east-1".to_string();
    }
    API_REGION_MAP
        .iter()
        .find(|(region, _)| *region == sso_region)
        .map(|(_, api_region)| (*api_region).to_string())
        .unwrap_or_else(|| sso_region.to_string())
}

/// Look up the first-token timeout for a model ID, defaulting to
/// [`DEFAULT_FIRST_TOKEN_TIMEOUT_MS`] for models not in [`KIRO_MODELS`] (or
/// that don't override it). Mirrors looking up the `firstTokenTimeout` field
/// on the matching `kiroModels` entry in the TS reference, falling back to
/// the default when the entry has no override.
pub fn first_token_timeout_for(model_id: &str) -> u64 {
    KIRO_MODELS
        .iter()
        .find(|m| m.id == model_id)
        .map(|m| m.first_token_timeout_ms)
        .unwrap_or(DEFAULT_FIRST_TOKEN_TIMEOUT_MS)
}

/// Dash-form model IDs available in the given Kiro API region, per
/// `MODELS_BY_REGION` in the TS reference. `"us-east-1"` gets the full
/// catalog; `"eu-central-1"` excludes the models below (verified against
/// `pi-provider-kiro/src/models.ts` directly: the set difference between its
/// `us-east-1` and `eu-central-1` allowlists). Regions outside that table get
/// zero models — `MODELS_BY_REGION` is itself an allowlist keyed only by
/// those two regions, and its call site (`filterModelsByRegion`, applied to
/// the static catalog in the TS reference's provider registration) returns
/// an empty list for any region not present, "forcing a conscious update
/// rather than silently exposing unsupported models" (source comment).
/// [`resolve_api_region`] passes genuinely unmapped SSO regions through
/// unchanged, so an unmapped region correctly yields no models here rather
/// than the full catalog.
/// The API regions [`models_for_region`] actually has an allowlist for.
///
/// Exists to distinguish [`models_for_region`]'s two very different empty
/// results: "this region is known and genuinely has no models" (impossible
/// today — both known regions have non-empty lists, and
/// `is_known_api_region_agrees_with_models_for_region` guards that) versus
/// "this region is not in the table at all, so we know nothing about it".
///
/// That distinction does not matter for *listing* models, which is what
/// `models_for_region` was written for — an empty list is the right answer
/// either way. It matters a great deal for *admission control*: see
/// `providers::kiro::reject_unavailable_model`, where treating an unknown
/// region's empty list as "reject everything" would lock the account out of
/// the proxy entirely.
pub fn is_known_api_region(api_region: &str) -> bool {
    KNOWN_API_REGIONS.contains(&api_region)
}

const KNOWN_API_REGIONS: &[&str] = &["us-east-1", "eu-central-1"];

pub fn models_for_region(api_region: &str) -> Vec<&'static str> {
    const EU_CENTRAL_1_EXCLUDED: &[&str] = &[
        "deepseek-3-2",
        "kimi-k2-5",
        "glm-5",
        "qwen3-coder-480b",
        "agi-nova-beta-1m",
        "claude-opus-4-6-1m",
        "claude-sonnet-4-6-1m",
    ];
    match api_region {
        "us-east-1" => KIRO_MODELS.iter().map(|m| m.id).collect(),
        "eu-central-1" => KIRO_MODELS
            .iter()
            .map(|m| m.id)
            .filter(|id| !EU_CENTRAL_1_EXCLUDED.contains(id))
            .collect(),
        _ => Vec::new(),
    }
}

/// Estimated token cost of an image content block. Kiro exposes no
/// token-accurate API, so this is a fixed heuristic, mirrored from
/// `kimi/count_tokens.rs`.
pub const IMAGE_TOKEN_ESTIMATE: u64 = 2000;

/// Heuristic token estimator: counts contiguous alphanumeric/`-`/`_` runs as
/// one token each, plus one per individual (non-whitespace) punctuation
/// character. Floored at 1 for non-empty text, 0 for empty text. This is not
/// a real tokenizer — Kiro exposes no token-accurate API — but gives a
/// monotonic estimate roughly proportional to actual token counts. Mirrors
/// `kimi/count_tokens.rs`'s `approx_token_count` exactly so both the stream
/// finalization usage fallback and the count_tokens endpoint agree.
pub fn approx_token_count(text: &str) -> u64 {
    if text.is_empty() {
        return 0;
    }
    let mut count = 0u64;
    let mut in_word = false;

    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '-' || ch == '_' {
            if !in_word {
                count += 1;
                in_word = true;
            }
        } else {
            in_word = false;
            if !ch.is_whitespace() {
                count += 1;
            }
        }
    }

    count.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_known_api_region_agrees_with_models_for_region() {
        // Drift guard: `is_known_api_region` and `models_for_region` keep two
        // separate lists of the same regions, and callers rely on
        // "known region" implying "non-empty allowlist".
        for region in KNOWN_API_REGIONS {
            assert!(is_known_api_region(region));
            assert!(
                !models_for_region(region).is_empty(),
                "{region} is known, so it must have models"
            );
        }
        // Real AWS SSO regions absent from `API_REGION_MAP`, which
        // `resolve_api_region` therefore passes through unchanged.
        for region in [
            "ca-central-1",
            "sa-east-1",
            "ap-northeast-2",
            "af-south-1",
            "me-south-1",
            "us-gov-west-1",
        ] {
            assert!(
                !is_known_api_region(region),
                "{region} is not in the allowlist table"
            );
            assert!(models_for_region(region).is_empty());
        }
    }

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
        assert_eq!(
            dot_to_dash(&dash_to_dot("claude-opus-4-8")),
            "claude-opus-4-8"
        );
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
        assert_eq!(
            first_token_timeout_for("claude-sonnet-4-5"),
            DEFAULT_FIRST_TOKEN_TIMEOUT_MS
        );
        assert_eq!(
            first_token_timeout_for("unknown-model"),
            DEFAULT_FIRST_TOKEN_TIMEOUT_MS
        );
    }

    #[test]
    fn catalog_has_all_nineteen_models_with_unique_ids() {
        assert_eq!(KIRO_MODELS.len(), 19);
        let mut ids: Vec<&str> = KIRO_MODELS.iter().map(|m| m.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 19);
    }

    #[test]
    fn auto_model_has_reasoning_enabled() {
        let auto = KIRO_MODELS
            .iter()
            .find(|m| m.id == "auto")
            .expect("auto entry present");
        assert!(
            auto.reasoning,
            "auto should have reasoning: true, matching the TS reference"
        );
    }

    #[test]
    fn eu_central_1_excludes_region_locked_models() {
        let models = models_for_region("eu-central-1");
        assert!(!models.contains(&"deepseek-3-2"));
        assert!(!models.contains(&"claude-opus-4-6-1m"));
        assert!(models.contains(&"claude-sonnet-4-6")); // widely-available model still present
    }

    #[test]
    fn us_east_1_gets_full_catalog() {
        assert_eq!(models_for_region("us-east-1").len(), 19);
    }

    #[test]
    fn catalog_entries_match_verified_reference_data() {
        // Spot-checks entries whose reasoning/context/max-token values are
        // easy to get wrong when defaulting from summarized research;
        // verified directly against pi-provider-kiro/src/models.ts's
        // `kiroModels` rather than trusting the plan's suggested defaults.
        let by_id = |id: &str| KIRO_MODELS.iter().find(|m| m.id == id).unwrap();

        let opus_4_7 = by_id("claude-opus-4-7");
        assert_eq!(opus_4_7.context_window, 1_000_000);
        assert_eq!(opus_4_7.max_tokens, 128_000);
        assert!(opus_4_7.reasoning);
        assert!(opus_4_7.input_image);

        let opus_4_6 = by_id("claude-opus-4-6");
        assert_eq!(opus_4_6.context_window, 1_000_000);
        assert_eq!(opus_4_6.max_tokens, 32_768);

        let sonnet_4_6 = by_id("claude-sonnet-4-6");
        assert_eq!(sonnet_4_6.context_window, 1_000_000);
        assert_eq!(sonnet_4_6.max_tokens, 65_536);

        let haiku = by_id("claude-haiku-4-5");
        assert!(
            !haiku.reasoning,
            "haiku is non-reasoning in the TS reference"
        );
        assert!(haiku.input_image);

        let kimi = by_id("kimi-k2-5");
        assert_eq!(kimi.context_window, 200_000);
        assert_eq!(kimi.max_tokens, 8_192);
        assert!(!kimi.input_image, "kimi is text-only in the TS reference");

        let minimax_1 = by_id("minimax-m2-1");
        let minimax_5 = by_id("minimax-m2-5");
        assert!(!minimax_1.reasoning);
        assert!(!minimax_5.reasoning);
        assert!(!minimax_1.input_image);
        assert!(!minimax_5.input_image);

        let glm = by_id("glm-5");
        assert_eq!(glm.context_window, 128_000);
        assert!(!glm.input_image);

        let qwen_next = by_id("qwen3-coder-next");
        assert_eq!(qwen_next.context_window, 256_000);

        let qwen_480b = by_id("qwen3-coder-480b");
        assert_eq!(qwen_480b.context_window, 128_000);
        assert!(!qwen_480b.input_image);

        let agi_nova = by_id("agi-nova-beta-1m");
        assert_eq!(agi_nova.context_window, 1_000_000);
        assert!(agi_nova.input_image);
    }

    #[test]
    fn eu_central_1_exclusion_set_is_exact() {
        let models = models_for_region("eu-central-1");
        assert_eq!(models.len(), 12);
        for excluded in [
            "deepseek-3-2",
            "kimi-k2-5",
            "glm-5",
            "qwen3-coder-480b",
            "agi-nova-beta-1m",
            "claude-opus-4-6-1m",
            "claude-sonnet-4-6-1m",
        ] {
            assert!(
                !models.contains(&excluded),
                "{excluded} should be excluded from eu-central-1"
            );
        }
    }

    #[test]
    fn resolve_api_region_covers_all_mapped_regions() {
        for region in [
            "us-west-1",
            "us-west-2",
            "us-east-2",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ap-south-1",
        ] {
            assert_eq!(resolve_api_region(region), "us-east-1");
        }
        for region in [
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-north-1",
            "eu-south-1",
            "eu-south-2",
            "eu-central-2",
        ] {
            assert_eq!(resolve_api_region(region), "eu-central-1");
        }
    }

    #[test]
    fn approx_token_count_exact_values_for_known_text() {
        assert_eq!(approx_token_count("hello"), 1);
        assert_eq!(approx_token_count("hello world"), 2);
        assert_eq!(approx_token_count("hello, world!"), 4); // hello + , + world + !
    }

    #[test]
    fn unmapped_region_gets_no_models() {
        // Matches the TS reference's `filterModelsByRegion`: a region absent
        // from `MODELS_BY_REGION` yields zero models rather than silently
        // exposing the full catalog somewhere the Q API isn't deployed.
        assert!(models_for_region("ca-central-1").is_empty());
        assert!(models_for_region("").is_empty());
    }

    #[test]
    fn approx_token_count_floors_at_one_for_nonempty_text() {
        assert_eq!(approx_token_count(""), 0);
        assert!(approx_token_count("a") >= 1);
        assert!(approx_token_count("hello world") >= 2);
    }
}
