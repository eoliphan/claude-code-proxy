//! History truncation, sanitization, and orphaned-tool-call repair.
//!
//! Line-for-line port of the `pi-provider-kiro` reference implementation's
//! `src/history.ts` (read directly at implementation time from
//! `/home/erich.oliphant/IdeaProjects/pi-provider-kiro/src/history.ts`),
//! operating on this proxy's already-built [`KiroHistoryEntry`] structures
//! (the output of `transform::build_history`) rather than on raw Anthropic
//! messages.
//!
//! `sanitizeHistory`'s asymmetric lookback/lookahead (TS lines 33-41) is the
//! one subtlety worth calling out explicitly, since it is easy to get
//! backwards:
//! - An assistant entry with `toolUses` looks **forward** into the
//!   *original* (pre-filter) array at `history[i + 1]` (TS line 34) to
//!   decide whether to keep itself.
//! - A user entry with `toolResults` looks **backward** into the *result*
//!   array being built so far, at `result[result.length - 1]` (TS line 37)
//!   to decide whether to keep itself.
//!
//! These are genuinely different arrays: the assistant-entry lookahead scans
//! the untouched input regardless of what got dropped, while the
//! tool-result-entry lookback scans only what has already survived
//! filtering -- so a dropped assistant tool-use entry correctly cascades
//! into its answering tool-result entry also being dropped (the lookback
//! sees whatever `result`'s last pushed entry actually is, not the original
//! neighbor).

use std::collections::HashSet;

use serde_json::json;

use super::transform::{
    KiroAssistantResponseMessage, KiroHistoryEntry, KiroInputSchema, KiroToolSpec,
    KiroToolSpecification, KiroToolUse,
};

/// Byte-length budget (JSON-serialized) for a history payload. Matches the
/// TS `HISTORY_LIMIT` constant, calibrated for a 200k-token context window.
pub const HISTORY_LIMIT: usize = 850_000;

/// The context window size (in tokens) that [`HISTORY_LIMIT`] was
/// calibrated for.
pub const HISTORY_LIMIT_CONTEXT_WINDOW: u64 = 200_000;

/// Scale [`HISTORY_LIMIT`] proportionally to a model's actual context
/// window.
pub fn dynamic_history_limit(model_context_window: u64) -> usize {
    ((model_context_window as f64 / HISTORY_LIMIT_CONTEXT_WINDOW as f64) * HISTORY_LIMIT as f64)
        as usize
}

/// Port of `stripHistoryImages`. Clears `.images` on every
/// `userInputMessage` entry -- they've already been processed by the model
/// in earlier turns, and re-sending them wastes context / can trigger 413s.
/// Everything else (assistant entries, the rest of a user entry) is left
/// untouched.
pub fn strip_history_images(history: Vec<KiroHistoryEntry>) -> Vec<KiroHistoryEntry> {
    history
        .into_iter()
        .map(|mut entry| {
            if let Some(uim) = entry.user_input_message.as_mut() {
                uim.images = None;
            }
            entry
        })
        .collect()
}

/// Whether `entry` is invalid as the *first* entry of a history: either it
/// has no `userInputMessage` at all, or its `userInputMessage` is itself
/// carrying tool results (which would require a preceding tool-use turn
/// that can't exist at position 0). Used only inside [`sanitize_history`]'s
/// leading-strip loop.
fn is_leading_invalid(entry: &KiroHistoryEntry) -> bool {
    match &entry.user_input_message {
        None => true,
        Some(uim) => uim
            .user_input_message_context
            .as_ref()
            .is_some_and(|ctx| ctx.tool_results.is_some()),
    }
}

fn has_nonempty_tool_uses(arm: &KiroAssistantResponseMessage) -> bool {
    arm.tool_uses.as_ref().is_some_and(|v| !v.is_empty())
}

fn entry_has_tool_results(entry: &KiroHistoryEntry) -> bool {
    entry
        .user_input_message
        .as_ref()
        .and_then(|uim| uim.user_input_message_context.as_ref())
        .is_some_and(|ctx| ctx.tool_results.is_some())
}

/// Port of `sanitizeHistory`. See the module doc comment for the
/// lookback/lookahead asymmetry this relies on.
pub fn sanitize_history(mut history: Vec<KiroHistoryEntry>) -> Vec<KiroHistoryEntry> {
    // Strip leading entries that would make the history invalid: history
    // must start with a userInputMessage that isn't itself carrying tool
    // results (a tool result needs a preceding tool-use turn, which can't
    // exist at position 0).
    while history.first().is_some_and(is_leading_invalid) {
        history.remove(0);
    }

    let mut result: Vec<KiroHistoryEntry> = Vec::with_capacity(history.len());
    for (i, m) in history.iter().enumerate() {
        // Skip assistant messages with no content and no tool uses (e.g.
        // from API errors).
        if let Some(arm) = &m.assistant_response_message
            && !has_nonempty_tool_uses(arm)
            && arm.content.is_empty()
        {
            continue;
        }

        if let Some(arm) = &m.assistant_response_message
            && has_nonempty_tool_uses(arm)
        {
            // Lookahead into the ORIGINAL (pre-filter) array: keep this
            // tool-use entry only if the very next original entry is a user
            // message carrying matching tool results.
            let next_has_tool_results = history.get(i + 1).is_some_and(entry_has_tool_results);
            if next_has_tool_results {
                result.push(m.clone());
            }
            continue;
        }

        if entry_has_tool_results(m) {
            // Lookback into the RESULT array being built so far: keep this
            // tool-result entry only if the last entry actually kept is an
            // assistant tool-use entry. If that assistant entry was dropped
            // above, this correctly cascades into dropping the tool result
            // too.
            let prev_has_tool_uses = result
                .last()
                .and_then(|p| p.assistant_response_message.as_ref())
                .is_some_and(has_nonempty_tool_uses);
            if prev_has_tool_uses {
                result.push(m.clone());
            }
            continue;
        }

        result.push(m.clone());
    }
    result
}

/// Port of `injectSyntheticToolCalls`. Collects every `toolUseId` referenced
/// by an `assistantResponseMessage.toolUses` anywhere in `history` into a
/// valid-IDs set, then walks again and inserts a synthetic assistant entry
/// immediately before any user entry whose tool results reference an ID not
/// in that set -- repairing an orphaned tool result truncation can leave
/// behind. Newly-synthesized IDs are added to the valid set so later entries
/// in the same pass don't re-flag the same orphan.
pub fn inject_synthetic_tool_calls(history: Vec<KiroHistoryEntry>) -> Vec<KiroHistoryEntry> {
    let mut valid_ids: HashSet<String> = HashSet::new();
    for entry in &history {
        if let Some(tool_uses) = entry
            .assistant_response_message
            .as_ref()
            .and_then(|arm| arm.tool_uses.as_ref())
        {
            for tu in tool_uses {
                valid_ids.insert(tu.tool_use_id.clone());
            }
        }
    }

    let mut result: Vec<KiroHistoryEntry> = Vec::with_capacity(history.len());
    for entry in history {
        if let Some(tool_results) = entry
            .user_input_message
            .as_ref()
            .and_then(|uim| uim.user_input_message_context.as_ref())
            .and_then(|ctx| ctx.tool_results.as_ref())
        {
            let orphaned: Vec<_> = tool_results
                .iter()
                .filter(|tr| !valid_ids.contains(&tr.tool_use_id))
                .collect();
            if !orphaned.is_empty() {
                result.push(KiroHistoryEntry {
                    user_input_message: None,
                    assistant_response_message: Some(KiroAssistantResponseMessage {
                        content: "Tool calls were made.".to_string(),
                        tool_uses: Some(
                            orphaned
                                .iter()
                                .map(|tr| KiroToolUse {
                                    name: "unknown_tool".to_string(),
                                    tool_use_id: tr.tool_use_id.clone(),
                                    input: json!({}),
                                })
                                .collect(),
                        ),
                    }),
                });
                for tr in &orphaned {
                    valid_ids.insert(tr.tool_use_id.clone());
                }
            }
        }
        result.push(entry);
    }
    result
}

/// Port of `truncateHistory`: sanitize, then repeatedly drop the oldest
/// entry (and any immediately-following non-`userInputMessage` entries)
/// while over `limit` bytes of JSON, re-sanitizing after each drop so
/// truncation never leaves the history in a broken state. Finally repairs
/// any orphaned tool results the truncation introduced.
pub fn truncate_history(history: Vec<KiroHistoryEntry>, limit: usize) -> Vec<KiroHistoryEntry> {
    let mut sanitized = sanitize_history(strip_history_images(history));
    let mut history_size = serde_json::to_string(&sanitized).unwrap().len();
    while history_size > limit && sanitized.len() > 2 {
        sanitized.remove(0);
        while sanitized
            .first()
            .is_some_and(|e| e.user_input_message.is_none())
        {
            sanitized.remove(0);
        }
        sanitized = sanitize_history(sanitized);
        history_size = serde_json::to_string(&sanitized).unwrap().len();
    }
    inject_synthetic_tool_calls(sanitized)
}

/// Port of `extractToolNamesFromHistory`.
pub fn extract_tool_names_from_history(history: &[KiroHistoryEntry]) -> HashSet<String> {
    let mut names = HashSet::new();
    for entry in history {
        if let Some(tool_uses) = entry
            .assistant_response_message
            .as_ref()
            .and_then(|arm| arm.tool_uses.as_ref())
        {
            for tu in tool_uses {
                if !tu.name.is_empty() {
                    names.insert(tu.name.clone());
                }
            }
        }
    }
    names
}

/// Port of `addPlaceholderTools`. Appends a minimal placeholder
/// [`KiroToolSpec`] for every tool name referenced in `history`'s tool uses
/// but missing from `declared` -- Kiro's API requires every tool a
/// transcript references to be declared, even when the original tool
/// definition fell out of scope (e.g. after truncation dropped the request
/// that declared it).
///
/// The placeholder's `inputSchema.json` matches the TS source's literal
/// `{ type: "object", properties: {} }` (not an empty object) -- Kiro
/// expects a valid (if permissive) JSON Schema shape here.
pub fn add_placeholder_tools(
    declared: Vec<KiroToolSpec>,
    history: &[KiroHistoryEntry],
) -> Vec<KiroToolSpec> {
    let history_names = extract_tool_names_from_history(history);
    if history_names.is_empty() {
        return declared;
    }
    let existing: HashSet<&str> = declared
        .iter()
        .map(|t| t.tool_specification.name.as_str())
        .collect();
    let mut missing: Vec<&String> = history_names
        .iter()
        .filter(|n| !existing.contains(n.as_str()))
        .collect();
    if missing.is_empty() {
        return declared;
    }
    // Deterministic ordering for stable output (HashSet iteration order is
    // unspecified); the TS source's Array.from(Set) preserves insertion
    // order instead, but placeholder order has no behavioral significance,
    // only test/log determinism.
    missing.sort();

    let mut result = declared;
    for name in missing {
        result.push(KiroToolSpec {
            tool_specification: KiroToolSpecification {
                name: name.clone(),
                description: "Tool".to_string(),
                input_schema: KiroInputSchema {
                    json: json!({"type": "object", "properties": {}}),
                },
            },
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::kiro::translate::transform::{
        KiroImage, KiroImageSource, KiroToolResult, KiroToolResultStatus, KiroToolResultText,
        KiroUserInputMessage, KiroUserInputMessageContext,
    };

    fn user_entry(content: &str) -> KiroHistoryEntry {
        KiroHistoryEntry {
            user_input_message: Some(KiroUserInputMessage {
                content: content.to_string(),
                model_id: "model-x".to_string(),
                origin: "KIRO_CLI".to_string(),
                images: None,
                user_input_message_context: None,
            }),
            assistant_response_message: None,
        }
    }

    fn user_entry_with_images(content: &str) -> KiroHistoryEntry {
        let mut entry = user_entry(content);
        entry.user_input_message.as_mut().unwrap().images = Some(vec![KiroImage {
            format: "png".to_string(),
            source: KiroImageSource {
                bytes: "QUJD".to_string(),
            },
        }]);
        entry
    }

    fn tool_result(tool_use_id: &str, text: &str) -> KiroToolResult {
        KiroToolResult {
            content: vec![KiroToolResultText {
                text: text.to_string(),
            }],
            status: KiroToolResultStatus::Success,
            tool_use_id: tool_use_id.to_string(),
        }
    }

    fn user_entry_with_tool_results(
        content: &str,
        results: Vec<KiroToolResult>,
    ) -> KiroHistoryEntry {
        KiroHistoryEntry {
            user_input_message: Some(KiroUserInputMessage {
                content: content.to_string(),
                model_id: "model-x".to_string(),
                origin: "KIRO_CLI".to_string(),
                images: None,
                user_input_message_context: Some(KiroUserInputMessageContext {
                    tool_results: Some(results),
                    tools: None,
                }),
            }),
            assistant_response_message: None,
        }
    }

    fn assistant_entry(content: &str) -> KiroHistoryEntry {
        KiroHistoryEntry {
            user_input_message: None,
            assistant_response_message: Some(KiroAssistantResponseMessage {
                content: content.to_string(),
                tool_uses: None,
            }),
        }
    }

    fn assistant_entry_with_tool_use(tool_use_id: &str, name: &str) -> KiroHistoryEntry {
        KiroHistoryEntry {
            user_input_message: None,
            assistant_response_message: Some(KiroAssistantResponseMessage {
                content: String::new(),
                tool_uses: Some(vec![KiroToolUse {
                    name: name.to_string(),
                    tool_use_id: tool_use_id.to_string(),
                    input: json!({}),
                }]),
            }),
        }
    }

    // ---- dynamic_history_limit ----

    #[test]
    fn dynamic_history_limit_matches_base_limit_at_calibrated_context_window() {
        assert_eq!(dynamic_history_limit(200_000), HISTORY_LIMIT);
    }

    #[test]
    fn dynamic_history_limit_scales_proportionally() {
        assert_eq!(dynamic_history_limit(1_000_000), HISTORY_LIMIT * 5);
    }

    // ---- strip_history_images ----

    #[test]
    fn strip_history_images_clears_images_but_preserves_tool_results() {
        let mut entry = user_entry_with_images("do X");
        entry
            .user_input_message
            .as_mut()
            .unwrap()
            .user_input_message_context = Some(KiroUserInputMessageContext {
            tool_results: Some(vec![tool_result("t1", "r1")]),
            tools: None,
        });
        let history = vec![entry];
        let stripped = strip_history_images(history);
        assert_eq!(stripped.len(), 1);
        let uim = stripped[0].user_input_message.as_ref().unwrap();
        assert!(uim.images.is_none());
        let results = uim
            .user_input_message_context
            .as_ref()
            .unwrap()
            .tool_results
            .as_ref()
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tool_use_id, "t1");
    }

    #[test]
    fn strip_history_images_leaves_assistant_entries_untouched() {
        let history = vec![assistant_entry("hello")];
        let stripped = strip_history_images(history);
        assert_eq!(
            stripped[0]
                .assistant_response_message
                .as_ref()
                .unwrap()
                .content,
            "hello"
        );
    }

    // ---- sanitize_history ----

    #[test]
    fn sanitize_history_drops_leading_orphaned_tool_result_entry() {
        // History starts with a user entry carrying tool results but no
        // preceding tool-use turn -- invalid, must be stripped from the
        // front.
        let history = vec![
            user_entry_with_tool_results("Tool results provided.", vec![tool_result("t1", "r1")]),
            user_entry("hi"),
            assistant_entry("hello"),
        ];
        let result = sanitize_history(history);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].user_input_message.as_ref().unwrap().content, "hi");
    }

    #[test]
    fn sanitize_history_drops_assistant_tool_use_whose_following_entry_lacks_matching_tool_result()
    {
        // Assistant makes a tool call, but the very next original entry is
        // plain user text (no tool_results) rather than the answer -- the
        // lookahead check (into the ORIGINAL array) must reject keeping the
        // tool-use entry.
        let history = vec![
            user_entry("do X"),
            assistant_entry_with_tool_use("t1", "Search"),
            user_entry("actually never mind"),
        ];
        let result = sanitize_history(history);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].user_input_message.as_ref().unwrap().content,
            "do X"
        );
        assert_eq!(
            result[1].user_input_message.as_ref().unwrap().content,
            "actually never mind"
        );
    }

    #[test]
    fn sanitize_history_keeps_matched_tool_use_and_tool_result_pair() {
        let history = vec![
            user_entry("do X"),
            assistant_entry_with_tool_use("t1", "Search"),
            user_entry_with_tool_results("Tool results provided.", vec![tool_result("t1", "r1")]),
            assistant_entry("final"),
        ];
        let result = sanitize_history(history);
        assert_eq!(result.len(), 4);
        assert!(result[1].assistant_response_message.is_some());
        assert!(entry_has_tool_results(&result[2]));
    }

    #[test]
    fn sanitize_history_keeps_tool_use_when_next_entry_has_any_tool_results_even_with_mismatched_id()
     {
        // The lookahead/lookback checks are presence-of-toolResults, NOT
        // id-matching (id-repair is inject_synthetic_tool_calls's job, not
        // sanitize_history's) -- a tool-result entry with a *different* id
        // still satisfies both the tool-use entry's lookahead and its own
        // lookback, so both entries are kept even though the ids don't
        // correspond to the same call.
        let history = vec![
            user_entry("do X"),
            assistant_entry_with_tool_use("t1", "Search"),
            user_entry_with_tool_results("Tool results provided.", vec![tool_result("t2", "r1")]),
        ];
        let result = sanitize_history(history);
        assert_eq!(result.len(), 3);
        assert!(result[1].assistant_response_message.is_some());
        assert!(entry_has_tool_results(&result[2]));
    }

    #[test]
    fn sanitize_history_lookback_drops_tool_result_entry_when_prior_kept_entry_is_not_a_tool_use() {
        // Exercises the tool-result entry's lookback (`result.last()`)
        // rejection branch directly: the immediately-preceding entry in the
        // history array is a plain-text assistant entry (no tool_uses), so
        // once it's pushed into `result` unchanged, the following
        // tool-result entry's lookback check must see a non-tool-use `prev`
        // and drop itself -- the asymmetric-lookback path this task exists
        // to get right.
        let history = vec![
            user_entry("hi"),
            assistant_entry("just text, no tool uses"),
            user_entry_with_tool_results("Tool results provided.", vec![tool_result("t1", "r1")]),
        ];
        let result = sanitize_history(history);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[1]
                .assistant_response_message
                .as_ref()
                .unwrap()
                .content,
            "just text, no tool uses"
        );
    }

    #[test]
    fn sanitize_history_drops_empty_assistant_entry() {
        let history = vec![
            user_entry("hi"),
            KiroHistoryEntry {
                user_input_message: None,
                assistant_response_message: Some(KiroAssistantResponseMessage {
                    content: String::new(),
                    tool_uses: None,
                }),
            },
            user_entry("next"),
        ];
        let result = sanitize_history(history);
        assert_eq!(result.len(), 2);
    }

    // ---- inject_synthetic_tool_calls ----

    #[test]
    fn inject_synthetic_tool_calls_inserts_exactly_one_synthetic_entry_for_orphaned_tool_result() {
        let history = vec![
            user_entry("do X"),
            user_entry_with_tool_results(
                "Tool results provided.",
                vec![tool_result("orphan-1", "r1")],
            ),
        ];
        let result = inject_synthetic_tool_calls(history);
        assert_eq!(result.len(), 3);
        let synthetic = result[1].assistant_response_message.as_ref().unwrap();
        assert_eq!(synthetic.content, "Tool calls were made.");
        let tool_uses = synthetic.tool_uses.as_ref().unwrap();
        assert_eq!(tool_uses.len(), 1);
        assert_eq!(tool_uses[0].tool_use_id, "orphan-1");
        assert_eq!(tool_uses[0].name, "unknown_tool");
    }

    #[test]
    fn inject_synthetic_tool_calls_inserts_none_when_all_tool_results_have_matching_tool_uses() {
        let history = vec![
            user_entry("do X"),
            assistant_entry_with_tool_use("t1", "Search"),
            user_entry_with_tool_results("Tool results provided.", vec![tool_result("t1", "r1")]),
        ];
        let result = inject_synthetic_tool_calls(history);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn inject_synthetic_tool_calls_does_not_reflag_an_orphan_already_synthesized_earlier_in_the_pass()
     {
        // Two separate user entries both reference the same orphaned id --
        // only the first should get a synthetic repair; the second sees it
        // already added to the valid-ids set.
        let history = vec![
            user_entry_with_tool_results("r", vec![tool_result("dup", "r1")]),
            user_entry_with_tool_results("r2", vec![tool_result("dup", "r2")]),
        ];
        let result = inject_synthetic_tool_calls(history);
        // synthetic + entry1 + entry2 == 3 (no second synthetic inserted).
        assert_eq!(result.len(), 3);
        let synthetic_count = result
            .iter()
            .filter(|e| {
                e.assistant_response_message
                    .as_ref()
                    .is_some_and(|arm| arm.content == "Tool calls were made.")
            })
            .count();
        assert_eq!(synthetic_count, 1);
    }

    // ---- truncate_history ----

    #[test]
    fn truncate_history_shrinks_oversized_history_below_limit_without_breaking_invariants() {
        // Build a deliberately oversized synthetic history: N large
        // user/assistant exchanges.
        let mut history = Vec::new();
        for i in 0..50 {
            history.push(user_entry(&"x".repeat(5_000)));
            history.push(assistant_entry(&format!("{}{}", "y".repeat(5_000), i)));
        }
        let original_len = history.len();
        let original_size = serde_json::to_string(&history).unwrap().len();

        // Chosen so the budget is reached well before the 2-entry floor,
        // proving the loop stops because it's under budget, not because it
        // hit bottom (a limit too small would pass vacuously via the floor).
        let limit = 100_000;
        assert!(
            original_size > limit,
            "fixture must start over budget to exercise shrinking"
        );
        let result = truncate_history(history, limit);

        let size = serde_json::to_string(&result).unwrap().len();
        assert!(
            size <= limit,
            "history not shrunk under budget: {size} bytes > {limit}"
        );
        assert!(
            result.len() > 2,
            "budget should be satisfied well above the 2-entry floor, got {} entries",
            result.len()
        );
        assert!(
            result.len() < original_len,
            "truncation must actually drop entries"
        );
        assert!(
            result[0].user_input_message.is_some(),
            "front of truncated history must be a userInputMessage"
        );
    }

    #[test]
    fn truncate_history_never_drops_below_two_entries() {
        let history = vec![
            user_entry(&"x".repeat(1_000_000)),
            assistant_entry(&"y".repeat(1_000_000)),
        ];
        let result = truncate_history(history, 10);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn truncate_history_repairs_orphaned_tool_results_left_behind_by_truncation() {
        // Oldest entries get dropped by truncation, potentially orphaning a
        // tool result whose matching tool-use entry got dropped along with
        // them; truncate_history must run inject_synthetic_tool_calls at the
        // end to repair this.
        let history = vec![
            user_entry(&"pad".repeat(5_000)),
            assistant_entry_with_tool_use("t1", "Search"),
            user_entry_with_tool_results(
                "Tool results provided.",
                vec![tool_result("t1", &"pad".repeat(5_000))],
            ),
            user_entry("small"),
            assistant_entry("small reply"),
        ];

        let result = truncate_history(history, 50);
        // Whatever survives, every tool_results entry must have either a
        // matching tool_use entry immediately before it, or a synthetic one
        // injected by inject_synthetic_tool_calls.
        let mut valid_ids: HashSet<String> = HashSet::new();
        for entry in &result {
            if let Some(tool_uses) = entry
                .assistant_response_message
                .as_ref()
                .and_then(|a| a.tool_uses.as_ref())
            {
                for tu in tool_uses {
                    valid_ids.insert(tu.tool_use_id.clone());
                }
            }
            if let Some(tool_results) = entry
                .user_input_message
                .as_ref()
                .and_then(|u| u.user_input_message_context.as_ref())
                .and_then(|c| c.tool_results.as_ref())
            {
                for tr in tool_results {
                    assert!(
                        valid_ids.contains(&tr.tool_use_id),
                        "tool_result {} has no matching tool_use before it",
                        tr.tool_use_id
                    );
                }
            }
        }
    }

    // ---- extract_tool_names_from_history / add_placeholder_tools ----

    #[test]
    fn extract_tool_names_from_history_collects_every_tool_use_name() {
        let history = vec![
            assistant_entry_with_tool_use("t1", "Search"),
            assistant_entry_with_tool_use("t2", "Fetch"),
        ];
        let names = extract_tool_names_from_history(&history);
        assert_eq!(names.len(), 2);
        assert!(names.contains("Search"));
        assert!(names.contains("Fetch"));
    }

    #[test]
    fn add_placeholder_tools_appends_missing_tool_referenced_only_in_history() {
        let declared = vec![KiroToolSpec {
            tool_specification: KiroToolSpecification {
                name: "Search".to_string(),
                description: "search the web".to_string(),
                input_schema: KiroInputSchema {
                    json: json!({"type": "object", "properties": {}}),
                },
            },
        }];
        let history = vec![
            assistant_entry_with_tool_use("t1", "Search"),
            assistant_entry_with_tool_use("t2", "Fetch"),
        ];
        let result = add_placeholder_tools(declared, &history);
        assert_eq!(result.len(), 2);
        let fetch = result
            .iter()
            .find(|t| t.tool_specification.name == "Fetch")
            .unwrap();
        assert_eq!(fetch.tool_specification.description, "Tool");
        assert_eq!(
            fetch.tool_specification.input_schema.json,
            json!({"type": "object", "properties": {}})
        );
    }

    #[test]
    fn add_placeholder_tools_returns_declared_unchanged_when_history_has_no_new_names() {
        let declared = vec![KiroToolSpec {
            tool_specification: KiroToolSpecification {
                name: "Search".to_string(),
                description: "search the web".to_string(),
                input_schema: KiroInputSchema {
                    json: json!({"type": "object", "properties": {}}),
                },
            },
        }];
        let history = vec![assistant_entry_with_tool_use("t1", "Search")];
        let result = add_placeholder_tools(declared, &history);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn add_placeholder_tools_returns_declared_unchanged_when_history_is_empty() {
        let declared = vec![KiroToolSpec {
            tool_specification: KiroToolSpecification {
                name: "Search".to_string(),
                description: "search the web".to_string(),
                input_schema: KiroInputSchema {
                    json: json!({"type": "object", "properties": {}}),
                },
            },
        }];
        let result = add_placeholder_tools(declared, &[]);
        assert_eq!(result.len(), 1);
    }
}
