//! Full `KiroRequest` assembly: wires together `build_history` (Task 9),
//! history truncation/placeholder-tools (Task 10), model alias resolution
//! (Task 8) and dot-form conversion (Task 6), and this proxy's shared
//! system-prompt/effort readers (`translate_shared`) into the exact request
//! body Kiro's streaming API expects.
//!
//! ## Current-message assembly
//!
//! `build_history` deliberately leaves `req.messages[current_msg_start_idx..]`
//! ("the current slice") unprocessed — that's this module's job. The
//! boundary-finding algorithm in `transform::build_history` guarantees the
//! first message of that slice is one of exactly three shapes:
//!
//! 1. A `"user"` message carrying at least one `tool_result` block anywhere
//!    in its content (per [`transform::message_has_tool_result`]'s "walk
//!    every block, not just the first" rule) — a lone/leading tool-result
//!    turn, only reachable when the backward boundary scan runs all the way
//!    to index 0 without ever finding a non-tool-result message.
//! 2. An `"assistant"` message carrying at least one `tool_use` block — a
//!    resumed/continued turn where the client is asking to proceed after an
//!    in-flight tool call. This is the case Task 9's caveat calls out
//!    explicitly: the current slice does *not* always start with a plain
//!    user message.
//! 3. Anything else, which by construction is a `"user"` message with *no*
//!    tool_result block (the boundary-adjustment step in `build_history`
//!    guarantees the slice never starts with a tool-result-free assistant
//!    message either — it bumps the boundary forward past those).
//!
//! Each of these three messages can be followed by zero or more further
//! tool-result-shaped messages in the same slice (e.g. several tool calls
//! answered together), which get folded in the same way regardless of which
//! of the three shapes started the slice — including the case 3 could be
//! followed by trailing tool-result message(s) with no intervening
//! assistant tool_use in the current slice (e.g. `[user("hi"),
//! user([tool_result])]` alone: the backward scan lands on index 0 because
//! *every* message from the end is tool-result-shaped, yet index 0 itself
//! happens to be plain text). The brief's design notes only spell this fold
//! out for cases 1 and 2; case 3 gets the same treatment here so a
//! tool-result's content is never silently dropped, mirroring why
//! `transform::user_message_contribution` exists in the first place (see
//! that module's doc comment).
//!
//! Every tool-result extraction in this module goes through
//! [`transform::user_message_contribution`] rather than
//! [`transform::get_content_text`] + [`transform::extract_images`]
//! separately: `get_content_text`'s tool-result branch only inspects
//! `blocks.first()`, and `extract_images` only sees the *outer* block array,
//! never a `ToolResult`'s own nested content (where a tool's own image
//! output, e.g. a returned screenshot, actually lives). Both would silently
//! drop data on a mixed-block or image-bearing tool-result message —
//! `user_message_contribution` already walks every block once and folds in
//! nested tool-result images, which is exactly Task 9's fix for the same
//! class of bug applied to history entries. `get_content_text` /
//! `extract_images` are still used, per the brief, for case 3's *own*
//! message text/images — safe there specifically because case 3 is defined
//! as having no `tool_result` block at all, so `get_content_text`'s
//! order-dependent branch can never trigger and it degrades to a plain,
//! order-independent join over `Text`/`Thinking` blocks.
//!
//! ## Resumed assistant tool_use and history
//!
//! Case 2's assistant message is folded into `history` (merged into the
//! last entry if it's already an `assistantResponseMessage` — e.g. the
//! client split one logical assistant turn into a text-only message
//! followed by a separate tool_use-only message — otherwise pushed as a new
//! trailing entry), *after* `truncate_history` has already run, not before:
//! `sanitize_history`'s lookahead/lookback pairing (see `history.rs`'s
//! module doc comment) would otherwise see this tool_use entry as
//! unanswered (its answering tool result lives on the *current* message,
//! not in `history`) and strip it — along with any text merged into the
//! same entry. The injection is skipped entirely when the truncated history
//! is empty, since a lone `assistantResponseMessage` can never be a valid
//! leading history entry (`sanitize_history::is_leading_invalid`) and there
//! is no later re-sanitization pass to catch it once it's added this late.

use serde::Serialize;
use serde_json::Value;

use crate::anthropic::schema::{Message, MessagesRequest};
use crate::providers::translate_shared::{ImageSource, flatten_system_text, read_effort};

use super::history::{
    HISTORY_LIMIT_CONTEXT_WINDOW, add_placeholder_tools, dynamic_history_limit, truncate_history,
};
use super::model_allowlist::resolve_model;
use super::models::{KIRO_MODELS, dash_to_dot};
use super::transform::{
    self, KIRO_ORIGIN, KiroAssistantResponseMessage, KiroHistoryEntry, KiroToolResult, KiroToolUse,
    KiroUserInputMessage, KiroUserInputMessageContext, TOOL_RESULTS_PROVIDED,
    assistant_has_tool_use, assistant_message_contribution, convert_images_to_kiro,
    convert_tools_to_kiro, extract_images, get_content_text, message_has_tool_result,
    user_message_contribution,
};

#[derive(Debug, Clone, Serialize)]
pub struct KiroRequest {
    #[serde(rename = "conversationState")]
    pub conversation_state: KiroConversationState,
    #[serde(rename = "profileArn", skip_serializing_if = "Option::is_none")]
    pub profile_arn: Option<String>,
    #[serde(rename = "agentMode")]
    pub agent_mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KiroConversationState {
    #[serde(rename = "chatTriggerType")]
    pub chat_trigger_type: String,
    #[serde(rename = "agentTaskType")]
    pub agent_task_type: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "currentMessage")]
    pub current_message: CurrentMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<KiroHistoryEntry>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CurrentMessage {
    #[serde(rename = "userInputMessage")]
    pub user_input_message: KiroUserInputMessage,
}

/// Options threaded in by Task 15 (the outer retry-loop owner). `conversation_id`
/// is generated exactly once by Task 15 before entering its retry loop and
/// passed unchanged into every rebuild of the request across retries — this
/// function trusts whatever string it's given and never generates its own
/// (Adversarial Review Findings #4: a first draft that generated a fresh UUID
/// here whenever unset would mint a new, different id on every retry attempt).
pub struct BuildRequestOptions<'a> {
    pub conversation_id: &'a str,
    pub reasoning_enabled: bool,
    /// Explicit token budget override. When `None` and `reasoning_enabled` is
    /// true, computed from `translate_shared::read_effort(req)` via the
    /// budget table below.
    pub thinking_budget: Option<u32>,
    pub profile_arn: Option<&'a str>,
}

/// `xhigh` -> 50_000, `high` -> 30_000, `medium` -> 20_000, everything else
/// (`low`, `max`, absent) -> 10_000. Research item 7's budget table, taken
/// literally: the brief names only these four buckets and a catch-all
/// default, and `"max"` (a valid `translate_shared::read_effort` value) is
/// never named as its own tier. This means `"max"` maps to the *smallest*
/// budget (10_000) despite reading as the highest-intensity setting by
/// name -- flagged here rather than silently "fixed", since deviating from
/// the brief's literal table without a citation to Kiro's actual reference
/// behavior (not verified as part of this task) would be a guess in either
/// direction.
fn thinking_budget_for(effort: Option<&str>) -> u32 {
    match effort {
        Some("xhigh") => 50_000,
        Some("high") => 30_000,
        Some("medium") => 20_000,
        _ => 10_000,
    }
}

/// What a single branch of the current-message classification (see the
/// module doc comment) contributes toward the final `KiroUserInputMessage`,
/// before the system-prompt prefix (applied once, uniformly, by the caller)
/// is folded in.
struct CurrentAssembly {
    content_body: String,
    images: Vec<ImageSource>,
    tool_results: Vec<KiroToolResult>,
}

/// What [`collect_leading_tool_results`] found across a run of consecutive
/// tool-result-shaped messages.
struct LeadingToolResults {
    /// Real user-authored text found alongside the tool_result block(s) in
    /// any of the collected messages (e.g. `[Text("also check X"),
    /// ToolResult(t1)]` in either block order — see
    /// `transform::user_message_contribution`'s doc comment on why this
    /// can't be extracted with `get_content_text`), joined across messages
    /// with a blank-line separator matching `build_history`'s own
    /// cross-message join convention. Empty when none of the collected
    /// messages carried any text of their own.
    text: String,
    tool_results: Vec<KiroToolResult>,
    images: Vec<ImageSource>,
}

/// Collect every tool-result-shaped message starting at `current[start..]`
/// (stopping at the first message that isn't), folding each one's text,
/// tool results, and images via [`user_message_contribution`] so nested
/// tool-result images and multi-block messages — including a user comment
/// sharing a message with the tool_result it's answering with, in either
/// block order — are never silently dropped.
fn collect_leading_tool_results(current: &[Message], start: usize) -> LeadingToolResults {
    let mut text_parts: Vec<String> = Vec::new();
    let mut tool_results = Vec::new();
    let mut images = Vec::new();
    let mut idx = start;
    while idx < current.len() && message_has_tool_result(&current[idx]) {
        let contribution = user_message_contribution(&current[idx].content);
        if !contribution.text.is_empty() {
            text_parts.push(contribution.text);
        }
        tool_results.extend(contribution.tool_results);
        images.extend(contribution.images);
        idx += 1;
    }
    LeadingToolResults {
        text: text_parts.join("\n\n"),
        tool_results,
        images,
    }
}

/// `build_history`'s exact "{text}\n\n{sentinel}" convention (see
/// `transform::fold_user_contribution`): bare sentinel when there's no
/// accompanying text, text-then-sentinel otherwise. Any of this module's
/// three current-message cases can end up with real user text alongside
/// tool results (a comment sharing a message with the tool_result it
/// answers, in either block order) and must not silently drop it in favor
/// of the bare sentinel.
fn with_tool_results_sentinel(text: &str) -> String {
    if text.is_empty() {
        TOOL_RESULTS_PROVIDED.to_string()
    } else {
        format!("{text}\n\n{TOOL_RESULTS_PROVIDED}")
    }
}

/// Merge a resumed assistant message's `(content, tool_uses)` into
/// `history`'s tail: merges into the last entry if it's already an
/// `assistantResponseMessage` (appending content with a blank-line join when
/// both sides are non-empty, extending `tool_uses`), else pushes a new
/// entry. No-ops entirely when `history` is empty (see the module doc
/// comment on why an injected lone assistant entry can never be valid
/// there) or when there's nothing to add.
fn merge_or_push_assistant_entry(
    history: &mut Vec<KiroHistoryEntry>,
    content: String,
    tool_uses: Vec<KiroToolUse>,
) {
    if content.is_empty() && tool_uses.is_empty() {
        return;
    }
    if history.is_empty() {
        return;
    }
    if let Some(arm) = history
        .last_mut()
        .and_then(|e| e.assistant_response_message.as_mut())
    {
        if !content.is_empty() {
            arm.content = if arm.content.is_empty() {
                content
            } else {
                format!("{}\n\n{}", arm.content, content)
            };
        }
        if !tool_uses.is_empty() {
            arm.tool_uses.get_or_insert_with(Vec::new).extend(tool_uses);
        }
        return;
    }
    history.push(KiroHistoryEntry {
        user_input_message: None,
        assistant_response_message: Some(KiroAssistantResponseMessage {
            content,
            tool_uses: if tool_uses.is_empty() {
                None
            } else {
                Some(tool_uses)
            },
        }),
    });
}

/// Classify and assemble `req.messages[current_msg_start_idx..]` per the
/// module doc comment's three cases, mutating `history` in place for case 2
/// (the resumed-assistant-tool_use merge/push).
fn assemble_current_message(
    current: &[Message],
    history: &mut Vec<KiroHistoryEntry>,
) -> CurrentAssembly {
    const PLEASE_PROCEED: &str = "Please proceed with the task.";

    let Some(first) = current.first() else {
        return CurrentAssembly {
            content_body: PLEASE_PROCEED.to_string(),
            images: Vec::new(),
            tool_results: Vec::new(),
        };
    };

    if message_has_tool_result(first) {
        // Case 1: lone/leading tool-result-shaped turn. `first` itself can
        // carry real text alongside its tool_result block(s) (in either
        // block order) -- collect_leading_tool_results folds that in, it is
        // NOT dropped in favor of the bare sentinel.
        let leading = collect_leading_tool_results(current, 0);
        return CurrentAssembly {
            content_body: with_tool_results_sentinel(&leading.text),
            images: leading.images,
            tool_results: leading.tool_results,
        };
    }

    if first.role == "assistant" && assistant_has_tool_use(first) {
        // Case 2: resumed/continued turn.
        let (content, tool_uses) = assistant_message_contribution(&first.content);
        merge_or_push_assistant_entry(history, content, tool_uses);
        let leading = collect_leading_tool_results(current, 1);
        let content_body = if leading.tool_results.is_empty() {
            PLEASE_PROCEED.to_string()
        } else {
            with_tool_results_sentinel(&leading.text)
        };
        return CurrentAssembly {
            content_body,
            images: leading.images,
            tool_results: leading.tool_results,
        };
    }

    // Case 3: plain user message (guaranteed no tool_result block by
    // construction — see the module doc comment), possibly followed by
    // trailing tool-result message(s) with no intervening assistant
    // tool_use in this slice. Both the head message's own text AND any
    // trailing tool-result message's own text must survive.
    let head_text = get_content_text(&first.role, &first.content);
    let mut images = extract_images(&first.role, &first.content);
    let leading = collect_leading_tool_results(current, 1);
    images.extend(leading.images);
    let content_body = if leading.tool_results.is_empty() {
        head_text
    } else {
        let combined = match (head_text.is_empty(), leading.text.is_empty()) {
            (true, _) => leading.text,
            (false, true) => head_text,
            (false, false) => format!("{head_text}\n\n{}", leading.text),
        };
        with_tool_results_sentinel(&combined)
    };
    CurrentAssembly {
        content_body,
        images,
        tool_results: leading.tool_results,
    }
}

/// Assemble the full Kiro request body for one attempt. `opts.conversation_id`
/// is trusted verbatim (see [`BuildRequestOptions`]'s doc comment). Returns
/// the current turn's own tool results alongside the request for callers
/// (Task 15) that need them for retry-context bookkeeping — the brief's
/// draft signature used `()` here as a placeholder; Task 15 doesn't exist
/// yet, so this fills in the type its own doc comment already described.
pub fn build_kiro_request(
    req: &MessagesRequest,
    opts: BuildRequestOptions,
) -> Result<(KiroRequest, Vec<KiroToolResult>), anyhow::Error> {
    // Called unconditionally (matching kimi/codex's `read_effort(req)?`
    // call sites) so an invalid `output_config.effort` string errors out
    // regardless of whether reasoning mode is even enabled.
    let effort = read_effort(req)?;

    let requested = req.model.as_deref().unwrap_or("auto");
    let resolved_alias = resolve_model(requested);
    let kiro_model_id = dash_to_dot(&resolved_alias);

    let system_text = flatten_system_text(req.extra.get("system"));
    let system_for_history = if opts.reasoning_enabled {
        let budget = opts
            .thinking_budget
            .unwrap_or_else(|| thinking_budget_for(effort));
        Some(format!(
            "<thinking_mode>enabled</thinking_mode><max_thinking_length>{budget}</max_thinking_length>{}",
            system_text.unwrap_or_default()
        ))
    } else {
        system_text
    };

    let raw =
        transform::build_history(&req.messages, &kiro_model_id, system_for_history.as_deref());

    // KIRO_MODELS is keyed by dash-form ids; look up with `resolved_alias`
    // (dash), not `kiro_model_id` (dot) -- the dot form would never match
    // and would silently fall back to the default for every model.
    let model_context_window = KIRO_MODELS
        .iter()
        .find(|m| m.id == resolved_alias)
        .map(|m| m.context_window)
        .unwrap_or(HISTORY_LIMIT_CONTEXT_WINDOW);
    let limit = dynamic_history_limit(model_context_window);
    let mut truncated_history = truncate_history(raw.history, limit);

    let current = &req.messages[raw.current_msg_start_idx..];
    let assembly = assemble_current_message(current, &mut truncated_history);

    // Placeholder-tools must run *after* the case-2 history mutation above,
    // so a resumed assistant tool_use's name gets a placeholder spec too if
    // it wasn't among the client's declared tools.
    let declared_tools = convert_tools_to_kiro(
        req.extra
            .get("tools")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    );
    let tools = add_placeholder_tools(declared_tools, &truncated_history);

    // `raw.system_prepended` only records that `build_history` ATTACHED the
    // system prompt to some history entry -- not that the entry SURVIVED
    // `sanitize_history`'s leading-strip (an entry carrying tool_results
    // can never be valid at position 0, and everything can cascade-strip
    // right along with it, see the module doc comment on case handling
    // above) or `truncate_history`'s size-based front-eviction. Check
    // whether the prefix is actually still there in the truncated output;
    // if not, it must be re-added to the current message regardless of
    // what the flag says.
    let system_survived_in_history = raw.system_prepended
        && system_for_history.as_deref().is_some_and(|sys| {
            truncated_history
                .first()
                .and_then(|e| e.user_input_message.as_ref())
                .is_some_and(|uim| uim.content.starts_with(sys))
        });

    let mut content = assembly.content_body;
    if !system_survived_in_history && let Some(sys) = system_for_history.as_deref() {
        // Same "{sys}\n\n{text}" join `build_history` uses for its own
        // system-prompt prepend, applied uniformly across all three current-
        // message cases (not just the plain-user case) -- `system_prepended`
        // is only ever set when a *user* message lands in history, so an
        // all-assistant or tool-result-only history leaves it `false` too,
        // and the prompt must still reach the wire somewhere.
        content = format!("{sys}\n\n{content}");
    }

    let tool_results = assembly.tool_results;
    let user_input_message_context = if tools.is_empty() && tool_results.is_empty() {
        None
    } else {
        Some(KiroUserInputMessageContext {
            tool_results: if tool_results.is_empty() {
                None
            } else {
                Some(tool_results.clone())
            },
            tools: if tools.is_empty() { None } else { Some(tools) },
        })
    };

    let user_input_message = KiroUserInputMessage {
        content,
        model_id: kiro_model_id,
        origin: KIRO_ORIGIN.to_string(),
        images: if assembly.images.is_empty() {
            None
        } else {
            Some(convert_images_to_kiro(&assembly.images))
        },
        user_input_message_context,
    };

    let history_field = if truncated_history.is_empty() {
        None
    } else {
        Some(truncated_history)
    };

    let request = KiroRequest {
        conversation_state: KiroConversationState {
            chat_trigger_type: "MANUAL".to_string(),
            agent_task_type: "vibe".to_string(),
            conversation_id: opts.conversation_id.to_string(),
            current_message: CurrentMessage { user_input_message },
            history: history_field,
        },
        profile_arn: opts.profile_arn.map(str::to_string),
        agent_mode: "vibe".to_string(),
    };

    Ok((request, tool_results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(messages: Vec<Message>) -> MessagesRequest {
        MessagesRequest {
            model: None,
            max_tokens: None,
            messages,
            stream: true,
            bypass_provider_model_override: false,
            extra: serde_json::Map::new(),
        }
    }

    fn user(content: Value) -> Message {
        Message {
            role: "user".to_string(),
            content,
        }
    }

    fn assistant(content: Value) -> Message {
        Message {
            role: "assistant".to_string(),
            content,
        }
    }

    fn text_block(text: &str) -> Value {
        json!({"type": "text", "text": text})
    }

    fn tool_use_block(id: &str, name: &str, input: Value) -> Value {
        json!({"type": "tool_use", "id": id, "name": name, "input": input})
    }

    fn tool_result_block(tool_use_id: &str, content: Value) -> Value {
        json!({"type": "tool_result", "tool_use_id": tool_use_id, "content": content})
    }

    fn image_block(data: &str) -> Value {
        json!({
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": data},
        })
    }

    fn base_opts(conversation_id: &str) -> BuildRequestOptions<'_> {
        BuildRequestOptions {
            conversation_id,
            reasoning_enabled: false,
            thinking_budget: None,
            profile_arn: None,
        }
    }

    // ---- single-turn / multi-turn ----

    #[test]
    fn single_turn_request_has_no_history_and_content_matches_user_text() {
        let request = req(vec![user(Value::String("hello there".to_string()))]);
        let (kiro, tool_results) = build_kiro_request(&request, base_opts("conv-1")).unwrap();

        assert!(kiro.conversation_state.history.is_none());
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "hello there"
        );
        // No `model` given -> defaults to "auto", which has no digit-dash-digit
        // run for `dash_to_dot` to touch, so it passes through unchanged.
        // `bare_alias_model_resolves_to_concrete_dot_form_kiro_model_id` below
        // covers the actual dash->dot conversion for a real version number.
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .model_id,
            "auto"
        );
        assert!(tool_results.is_empty());
    }

    #[test]
    fn multi_turn_request_populates_history_and_current_is_only_trailing_messages() {
        let request = req(vec![
            user(Value::String("hi".to_string())),
            assistant(Value::String("hello".to_string())),
            user(Value::String("how are you".to_string())),
        ]);
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-2")).unwrap();

        let history = kiro
            .conversation_state
            .history
            .as_ref()
            .expect("multi-turn history should be populated");
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0].user_input_message.as_ref().unwrap().content,
            "hi"
        );
        assert_eq!(
            history[1]
                .assistant_response_message
                .as_ref()
                .unwrap()
                .content,
            "hello"
        );
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "how are you"
        );
    }

    // ---- reasoning / thinking-mode prefix ----

    #[test]
    fn reasoning_enabled_with_xhigh_effort_prepends_thinking_budget_50000() {
        let mut request = req(vec![user(Value::String("go".to_string()))]);
        request
            .extra
            .insert("output_config".to_string(), json!({"effort": "xhigh"}));
        let opts = BuildRequestOptions {
            conversation_id: "conv-3",
            reasoning_enabled: true,
            thinking_budget: None,
            profile_arn: None,
        };
        let (kiro, _) = build_kiro_request(&request, opts).unwrap();
        let content = &kiro
            .conversation_state
            .current_message
            .user_input_message
            .content;
        assert!(
            content.starts_with(
                "<thinking_mode>enabled</thinking_mode><max_thinking_length>50000</max_thinking_length>"
            ),
            "unexpected content: {content}"
        );
    }

    #[test]
    fn thinking_budget_override_takes_precedence_over_effort_table() {
        let mut request = req(vec![user(Value::String("go".to_string()))]);
        request
            .extra
            .insert("output_config".to_string(), json!({"effort": "xhigh"}));
        let opts = BuildRequestOptions {
            conversation_id: "conv-3b",
            reasoning_enabled: true,
            thinking_budget: Some(1234),
            profile_arn: None,
        };
        let (kiro, _) = build_kiro_request(&request, opts).unwrap();
        let content = &kiro
            .conversation_state
            .current_message
            .user_input_message
            .content;
        assert!(content.contains("<max_thinking_length>1234</max_thinking_length>"));
    }

    #[test]
    fn reasoning_enabled_thinking_prefix_lands_on_current_message_beyond_a_single_turn() {
        // Pins WHERE the thinking-mode prefix ends up once history exists:
        // history's own entries must NOT carry it (system_for_history is
        // only ever prepended once, to whichever single place -- history or
        // current -- actually needs it), and it must still open the current
        // message's content, not get lost once there's more than one turn.
        let mut request = req(vec![
            user(Value::String("hi".to_string())),
            assistant(Value::String("hello".to_string())),
            user(Value::String("second turn".to_string())),
        ]);
        request
            .extra
            .insert("output_config".to_string(), json!({"effort": "high"}));
        let opts = BuildRequestOptions {
            conversation_id: "conv-3c",
            reasoning_enabled: true,
            thinking_budget: None,
            profile_arn: None,
        };
        let (kiro, _) = build_kiro_request(&request, opts).unwrap();

        let history = kiro
            .conversation_state
            .history
            .as_ref()
            .expect("multi-turn history should be populated");
        let first_history_content = &history[0].user_input_message.as_ref().unwrap().content;
        assert!(
            first_history_content.starts_with("<thinking_mode>enabled</thinking_mode>"),
            "the FIRST history entry should carry the prefix (it's where \
             build_history attaches the system_for_history string when a \
             prior user message exists): {first_history_content}"
        );

        let current_content = &kiro
            .conversation_state
            .current_message
            .user_input_message
            .content;
        assert_eq!(
            current_content, "second turn",
            "the CURRENT message must NOT carry the prefix a second time once \
             it already survived in history"
        );
    }

    // ---- model alias resolution ----

    #[test]
    fn bare_alias_model_resolves_to_concrete_dot_form_kiro_model_id() {
        let mut request = req(vec![user(Value::String("hi".to_string()))]);
        request.model = Some("sonnet".to_string());
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-4")).unwrap();
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .model_id,
            "claude-sonnet-4.6"
        );
    }

    // ---- placeholder tools ----

    #[test]
    fn declared_tools_plus_undeclared_history_tool_name_gets_placeholder() {
        let mut request = req(vec![
            user(Value::String("do X".to_string())),
            assistant(json!([tool_use_block("t1", "Undeclared", json!({}))])),
            user(json!([tool_result_block(
                "t1",
                Value::String("r1".to_string())
            )])),
            assistant(Value::String("final".to_string())),
            user(Value::String("thanks".to_string())),
        ]);
        request.extra.insert(
            "tools".to_string(),
            json!([{"name": "Declared", "description": "d", "input_schema": {"type": "object", "properties": {}}}]),
        );
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-5")).unwrap();
        let ctx = kiro
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .as_ref()
            .expect("context should be present -- tools were declared");
        let tools = ctx.tools.as_ref().expect("tools should be Some");
        let names: Vec<&str> = tools
            .iter()
            .map(|t| t.tool_specification.name.as_str())
            .collect();
        assert!(names.contains(&"Declared"));
        assert!(
            names.contains(&"Undeclared"),
            "placeholder for the undeclared history tool name should be present: {names:?}"
        );
    }

    #[test]
    fn declared_tools_reach_the_current_message_on_a_first_turn_with_no_history() {
        // The single most common request shape: first turn, no history yet.
        // add_placeholder_tools(declared, &[]) returns `declared` unchanged,
        // but nothing else in this test suite asserts declared tools ever
        // reach `user_input_message_context.tools` when history is empty --
        // every other placeholder/context test uses a multi-message fixture
        // with populated history.
        let mut request = req(vec![user(Value::String("hi".to_string()))]);
        request.extra.insert(
            "tools".to_string(),
            json!([{"name": "Search", "description": "search the web", "input_schema": {"type": "object", "properties": {}}}]),
        );
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-4b")).unwrap();

        assert!(
            kiro.conversation_state.history.is_none(),
            "sanity check: this fixture should have no history"
        );
        let ctx = kiro
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .as_ref()
            .expect("context should be present -- a tool was declared");
        let tools = ctx.tools.as_ref().expect("tools should be Some");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].tool_specification.name, "Search");
    }

    // ---- conversation_id passthrough ----

    #[test]
    fn conversation_id_passthrough_is_stable_across_repeated_calls() {
        let request = req(vec![user(Value::String("hi".to_string()))]);
        let (kiro1, _) = build_kiro_request(&request, base_opts("stable-id-123")).unwrap();
        let (kiro2, _) = build_kiro_request(&request, base_opts("stable-id-123")).unwrap();
        assert_eq!(kiro1.conversation_state.conversation_id, "stable-id-123");
        assert_eq!(kiro2.conversation_state.conversation_id, "stable-id-123");
    }

    // ---- current-message images ----

    #[test]
    fn plain_user_message_with_image_populates_current_images() {
        let request = req(vec![user(json!([
            text_block("look at this"),
            image_block("QUJD"),
        ]))]);
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-6")).unwrap();
        let images = kiro
            .conversation_state
            .current_message
            .user_input_message
            .images
            .as_ref()
            .expect("images should be Some");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].source.bytes, "QUJD");
    }

    #[test]
    fn tool_result_message_with_nested_image_populates_current_images() {
        // The image lives INSIDE the tool_result block's own `content` (a
        // screenshot returned by a tool call), not as an outer sibling
        // block -- `extract_images` alone would miss this; only
        // `user_message_contribution`'s tool-result handling (which also
        // walks a ToolResult's nested content) finds it.
        let request = req(vec![user(json!([tool_result_block(
            "t1",
            json!([{"type": "text", "text": "here is the screenshot"}, image_block("SCREENSHOT")]),
        )]))]);
        let (kiro, tool_results) = build_kiro_request(&request, base_opts("conv-7")).unwrap();
        let images = kiro
            .conversation_state
            .current_message
            .user_input_message
            .images
            .as_ref()
            .expect("images should be Some for a tool-result-shaped current message");
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].source.bytes, "SCREENSHOT");
        assert_eq!(tool_results.len(), 1);
        assert_eq!(tool_results[0].tool_use_id, "t1");
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "Tool results provided."
        );
    }

    // ---- mixed [Text, ToolResult] current message (Critical regression) ----

    #[test]
    fn current_message_with_text_then_tool_result_preserves_the_text() {
        // Regression: a single lone current message shaped [Text,
        // ToolResult] previously shipped with content hardcoded to the bare
        // "Tool results provided." sentinel -- the real user comment
        // sharing the message with the tool_result it's answering with was
        // silently dropped. This is the exact bug class Task 9 fixed for
        // HISTORY entries (see transform.rs's module doc comment: "a real
        // Claude Code turn can lead with a short text comment before the
        // tool result it's answering with") reintroduced one level up in
        // current-message assembly.
        let request = req(vec![user(json!([
            text_block("also, watch out for X"),
            tool_result_block("t1", Value::String("r1".to_string())),
        ]))]);
        let (kiro, tool_results) = build_kiro_request(&request, base_opts("conv-7b")).unwrap();
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "also, watch out for X\n\nTool results provided."
        );
        assert_eq!(tool_results.len(), 1);
        assert_eq!(tool_results[0].tool_use_id, "t1");
    }

    #[test]
    fn current_message_with_tool_result_then_text_preserves_the_text() {
        // Mirror of the above with the blocks in the opposite order.
        let request = req(vec![user(json!([
            tool_result_block("t1", Value::String("r1".to_string())),
            text_block("also, watch out for X"),
        ]))]);
        let (kiro, tool_results) = build_kiro_request(&request, base_opts("conv-7c")).unwrap();
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "also, watch out for X\n\nTool results provided."
        );
        assert_eq!(tool_results.len(), 1);
        assert_eq!(tool_results[0].tool_use_id, "t1");
    }

    #[test]
    fn plain_user_message_followed_by_tool_result_message_with_its_own_text_merges_both_texts() {
        // Case 3's own head text ("hi") AND the trailing tool-result
        // message's own text ("by the way") must both survive, joined with
        // the head text first (source order) before the sentinel.
        let request = req(vec![
            user(Value::String("hi".to_string())),
            user(json!([
                text_block("by the way"),
                tool_result_block("t1", Value::String("r1".to_string())),
            ])),
        ]);
        let (kiro, tool_results) = build_kiro_request(&request, base_opts("conv-7d")).unwrap();
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "hi\n\nby the way\n\nTool results provided."
        );
        assert_eq!(tool_results.len(), 1);
    }

    // ---- profile_arn passthrough / omission ----

    #[test]
    fn profile_arn_some_serializes_to_that_exact_string() {
        let request = req(vec![user(Value::String("hi".to_string()))]);
        let opts = BuildRequestOptions {
            conversation_id: "conv-8",
            reasoning_enabled: false,
            thinking_budget: None,
            profile_arn: Some("arn:aws:example:profile/1"),
        };
        let (kiro, _) = build_kiro_request(&request, opts).unwrap();
        let value = serde_json::to_value(&kiro).unwrap();
        assert_eq!(
            value.get("profileArn").and_then(|v| v.as_str()),
            Some("arn:aws:example:profile/1")
        );
    }

    #[test]
    fn profile_arn_none_omits_the_key_entirely_not_null() {
        let request = req(vec![user(Value::String("hi".to_string()))]);
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-9")).unwrap();
        let value = serde_json::to_value(&kiro).unwrap();
        assert!(
            value.get("profileArn").is_none(),
            "profileArn key must be absent, not null: {value}"
        );
    }

    #[test]
    fn serialized_top_level_keys_match_the_briefs_wire_shape_exactly() {
        // Guards every #[serde(rename = ...)] at once -- a typo in any one
        // of them would otherwise ship silently (each existing test only
        // ever reaches into the value it cares about via the typed struct,
        // never checks the full serialized key set).
        let mut request = req(vec![
            user(Value::String("do X".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
            user(json!([tool_result_block(
                "t1",
                Value::String("r1".to_string())
            )])),
        ]);
        request.extra.insert(
            "tools".to_string(),
            json!([{"name": "Search", "description": "search", "input_schema": {"type": "object", "properties": {}}}]),
        );
        let opts = BuildRequestOptions {
            conversation_id: "conv-9b",
            reasoning_enabled: false,
            thinking_budget: None,
            profile_arn: Some("arn:aws:example:profile/2"),
        };
        let (kiro, _) = build_kiro_request(&request, opts).unwrap();
        let value = serde_json::to_value(&kiro).unwrap();

        let top_level: std::collections::BTreeSet<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(
            top_level,
            ["conversationState", "profileArn", "agentMode"]
                .into_iter()
                .collect(),
            "top-level KiroRequest keys: {value}"
        );

        let conv_state = value.get("conversationState").unwrap().as_object().unwrap();
        let conv_state_keys: std::collections::BTreeSet<&str> =
            conv_state.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            conv_state_keys,
            [
                "chatTriggerType",
                "agentTaskType",
                "conversationId",
                "currentMessage",
                "history",
            ]
            .into_iter()
            .collect(),
            "KiroConversationState keys: {value}"
        );

        let current_message = conv_state
            .get("currentMessage")
            .unwrap()
            .as_object()
            .unwrap();
        assert_eq!(
            current_message
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["userInputMessage"],
            "CurrentMessage keys: {value}"
        );

        let uim = current_message
            .get("userInputMessage")
            .unwrap()
            .as_object()
            .unwrap();
        let uim_keys: std::collections::BTreeSet<&str> = uim.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            uim_keys,
            ["content", "modelId", "origin", "userInputMessageContext",]
                .into_iter()
                .collect(),
            "KiroUserInputMessage keys (images omitted -- none in this fixture): {value}"
        );
    }

    // ---- resumed assistant+tool_use current-slice head (Task 9's caveat) ----

    #[test]
    fn resumed_assistant_tool_use_with_no_existing_history_tail_pushes_new_entry_and_pairs_with_current_tool_results()
     {
        // [user, assistant(tool_use), user(tool_result)] -- boundary lands on
        // the assistant message (branch 2), and history's last entry (the
        // plain "do X" turn) is a userInputMessage, not assistant, so the
        // tool_use must be PUSHED as a new trailing history entry, and the
        // matching tool result must show up on the CURRENT message, not in
        // history.
        let request = req(vec![
            user(Value::String("do X".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
            user(json!([tool_result_block(
                "t1",
                Value::String("search results".to_string())
            )])),
        ]);
        let (kiro, tool_results) = build_kiro_request(&request, base_opts("conv-10")).unwrap();

        let history = kiro
            .conversation_state
            .history
            .as_ref()
            .expect("history should contain the do-X turn plus the injected tool_use entry");
        let last = history.last().expect("history non-empty");
        let arm = last
            .assistant_response_message
            .as_ref()
            .expect("last history entry should be the injected assistant tool_use entry");
        let tool_uses = arm.tool_uses.as_ref().expect("tool_uses should be Some");
        assert!(
            tool_uses.iter().any(|tu| tu.tool_use_id == "t1"),
            "t1 must appear in history's tool_uses"
        );

        assert_eq!(tool_results.len(), 1);
        assert_eq!(tool_results[0].tool_use_id, "t1");
        assert_eq!(tool_results[0].content[0].text, "search results");
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "Tool results provided."
        );
    }

    #[test]
    fn resumed_assistant_tool_use_merges_into_existing_trailing_assistant_history_entry() {
        // Two consecutive assistant messages with nothing in between: a
        // text-only chunk (lands in history as its own entry), then a
        // tool_use-only chunk (the boundary/current-slice head). These must
        // be MERGED into one history entry, not left as two adjacent
        // assistantResponseMessage entries.
        let request = req(vec![
            user(Value::String("do X".to_string())),
            assistant(Value::String("Let me check".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
        ]);
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-11")).unwrap();

        let history = kiro
            .conversation_state
            .history
            .as_ref()
            .expect("history should be present");
        assert_eq!(
            history.len(),
            2,
            "expected [user(do X), assistant(merged)], got {history:?}"
        );
        let arm = history[1].assistant_response_message.as_ref().unwrap();
        assert_eq!(arm.content, "Let me check");
        let tool_uses = arm.tool_uses.as_ref().expect("tool_uses should be Some");
        assert_eq!(tool_uses.len(), 1);
        assert_eq!(tool_uses[0].tool_use_id, "t1");
    }

    #[test]
    fn resumed_assistant_tool_use_injection_is_skipped_when_history_is_empty() {
        // A single-message array whose only entry is an assistant+tool_use
        // message: build_history's boundary computation puts the ENTIRE
        // array in the "current" slice (nothing lands in history), so
        // there's no valid place to push a lone assistantResponseMessage
        // (history must start with a userInputMessage). The tool_use is
        // simply not representable in history here; it must not corrupt
        // history into an invalid shape either.
        let request = req(vec![assistant(json!([tool_use_block(
            "t1",
            "Search",
            json!({})
        )]))]);
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-12")).unwrap();
        assert!(
            kiro.conversation_state.history.is_none(),
            "history must stay empty/omitted rather than gain an invalid leading assistant entry"
        );
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "Please proceed with the task."
        );
    }

    // ---- system prompt reaches the wire even when build_history never consumed it ----

    #[test]
    fn system_prompt_prepends_to_current_message_for_lone_tool_result_current_slice() {
        let mut request = req(vec![user(json!([tool_result_block(
            "t1",
            Value::String("r1".to_string())
        )]))]);
        request
            .extra
            .insert("system".to_string(), json!("SYS-PROMPT"));
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-13")).unwrap();
        let content = &kiro
            .conversation_state
            .current_message
            .user_input_message
            .content;
        assert_eq!(content, "SYS-PROMPT\n\nTool results provided.");
    }

    #[test]
    fn system_prompt_prepends_when_history_has_no_user_message_at_all() {
        // [assistant(text), assistant(tool_use), user(tool_result)]: no user
        // message ever appears anywhere, so build_history's system_prepended
        // stays false no matter what -- it must still land on the wire.
        let mut request = req(vec![
            assistant(Value::String("text".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
            user(json!([tool_result_block(
                "t1",
                Value::String("r1".to_string())
            )])),
        ]);
        request
            .extra
            .insert("system".to_string(), json!("SYS-PROMPT"));
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-14")).unwrap();
        let content = &kiro
            .conversation_state
            .current_message
            .user_input_message
            .content;
        assert!(
            content.starts_with("SYS-PROMPT\n\n"),
            "unexpected content: {content}"
        );
    }

    #[test]
    fn system_prompt_survives_when_sanitize_history_strips_the_entry_it_was_prepended_to() {
        // Important regression: [user([tool_result t0]), assistant("ok"),
        // user("hi")]. build_history prepends the system prompt to
        // history[0] and sets system_prepended = true -- but history[0] is
        // a LEADING user entry carrying tool_results, which
        // sanitize_history's leading-strip (is_leading_invalid) always
        // removes, cascading into removing whatever new leading entry is
        // left too if it also isn't a plain userInputMessage. No size
        // pressure at all is needed to trigger this -- ordinary sanitation
        // on three short messages does it. `raw.system_prepended` being
        // `true` must NOT be trusted as proof the prompt actually reached
        // the wire.
        let mut request = req(vec![
            user(json!([tool_result_block(
                "t0",
                Value::String("r0".to_string())
            )])),
            assistant(Value::String("ok".to_string())),
            user(Value::String("hi".to_string())),
        ]);
        request
            .extra
            .insert("system".to_string(), json!("SYS-PROMPT"));
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-14b")).unwrap();
        let content = &kiro
            .conversation_state
            .current_message
            .user_input_message
            .content;
        assert!(
            content.starts_with("SYS-PROMPT\n\n"),
            "system prompt must survive even though it was stripped out of history \
             by ordinary sanitization, not size-based truncation: {content}"
        );
    }

    #[test]
    fn system_prompt_survives_when_a_different_entry_ends_up_leading_history() {
        // Sharper version of the above: after leading-strip, a DIFFERENT
        // entry (not the one the prefix was attached to) ends up at the
        // front of history. A naive fix that just checks "is history
        // non-empty" would wrongly conclude the prompt survived here --
        // only checking the actual leading entry's content catches this.
        //
        // [user([tool_result t0]), assistant("ok"), user("more"),
        //  assistant("ack"), user("final")]:
        // history[0] (system-prefixed, carries tool_results) and the
        // now-leading assistant("ok") both get stripped by
        // sanitize_history's leading-strip loop; user("more") survives as
        // the new front, but it never got the system prefix.
        let mut request = req(vec![
            user(json!([tool_result_block(
                "t0",
                Value::String("r0".to_string())
            )])),
            assistant(Value::String("ok".to_string())),
            user(Value::String("more".to_string())),
            assistant(Value::String("ack".to_string())),
            user(Value::String("final".to_string())),
        ]);
        request
            .extra
            .insert("system".to_string(), json!("SYS-PROMPT"));
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-14c")).unwrap();

        // Sanity check the scenario: history must be non-empty and its
        // front entry's content must NOT carry the system prefix, so this
        // genuinely exercises the "wrong entry survived" branch rather than
        // the "history went empty" branch already covered above.
        let history = kiro
            .conversation_state
            .history
            .as_ref()
            .expect("some history should survive in this fixture");
        let front = history[0].user_input_message.as_ref().unwrap();
        assert!(
            !front.content.starts_with("SYS-PROMPT"),
            "test fixture assumption violated -- front entry unexpectedly carries the prefix: {}",
            front.content
        );

        let content = &kiro
            .conversation_state
            .current_message
            .user_input_message
            .content;
        assert!(
            content.starts_with("SYS-PROMPT\n\n"),
            "system prompt must be re-added to the current message when a \
             different, non-prefixed entry ends up leading history: {content}"
        );
    }

    // ---- plain user message followed by an orphaned tool-result message ----

    #[test]
    fn plain_user_message_followed_by_orphan_tool_result_still_surfaces_the_tool_result() {
        // [user("hi"), user(tool_result)] with nothing else: the backward
        // boundary scan lands on index 0 because every message from the end
        // is tool-result-shaped, yet index 0 itself is plain text -- so the
        // current slice's head is case 3 (plain user), but is immediately
        // followed by a tool-result message the brief's bullet 3 doesn't
        // explicitly mention. It must not be silently dropped.
        let request = req(vec![
            user(Value::String("hi".to_string())),
            user(json!([tool_result_block(
                "t1",
                Value::String("r1".to_string())
            )])),
        ]);
        let (kiro, tool_results) = build_kiro_request(&request, base_opts("conv-15")).unwrap();
        assert!(kiro.conversation_state.history.is_none());
        assert_eq!(
            kiro.conversation_state
                .current_message
                .user_input_message
                .content,
            "hi\n\nTool results provided."
        );
        assert_eq!(tool_results.len(), 1);
        assert_eq!(tool_results[0].tool_use_id, "t1");
    }

    // ---- tools and tool_results coexist in the same context, neither clobbers the other ----

    #[test]
    fn declared_tools_and_current_tool_results_both_land_in_the_same_context() {
        let mut request = req(vec![
            user(Value::String("do X".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
            user(json!([tool_result_block(
                "t1",
                Value::String("r1".to_string())
            )])),
        ]);
        request.extra.insert(
            "tools".to_string(),
            json!([{"name": "Search", "description": "search", "input_schema": {"type": "object", "properties": {}}}]),
        );
        let (kiro, _) = build_kiro_request(&request, base_opts("conv-16")).unwrap();
        let ctx = kiro
            .conversation_state
            .current_message
            .user_input_message
            .user_input_message_context
            .as_ref()
            .expect("context should be present");
        assert!(ctx.tools.as_ref().is_some_and(|t| !t.is_empty()));
        assert!(ctx.tool_results.as_ref().is_some_and(|t| !t.is_empty()));
    }
}
