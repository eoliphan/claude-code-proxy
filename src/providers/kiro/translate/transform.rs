//! Message-array -> Kiro (AWS CodeWhisperer-shaped) history conversion.
//!
//! This is a line-for-line port of the `pi-provider-kiro` reference
//! implementation's `src/transform.ts` (read directly at implementation
//! time from `/home/erich.oliphant/IdeaProjects/pi-provider-kiro/src/transform.ts`
//! rather than assumed from summarized research), adapted for this proxy's
//! different data model:
//!
//! - `pi`'s `Message` type is a tagged union with a dedicated
//!   `role: "toolResult"` variant whose `content` field IS the tool's raw
//!   output content blocks. This proxy instead represents `Message.content`
//!   as untyped `serde_json::Value` in Anthropic's wire format, where a tool
//!   result is a `role: "user"` message whose content array holds a
//!   `tool_result` block (parsed here as [`ContentBlock::ToolResult`], via
//!   [`normalize_content`]) with the tool's own output nested inside that
//!   block's `content` field. Every place the TS checks
//!   `msg.role === "toolResult"`, this port instead checks
//!   `role == "user"` AND the first normalized content block is a
//!   `ContentBlock::ToolResult` (see [`is_tool_result_message`]) — matching
//!   how Claude Code always emits tool results as their own dedicated user
//!   turn, never mixed with plain user text in the same message.
//! - Unlike `pi`'s single-tool-result-per-message model, Anthropic's actual
//!   wire format allows *multiple* `tool_result` blocks in one message
//!   (parallel tool calls answered together). Where the TS walks a run of
//!   consecutive `toolResult`-role *messages*, this port additionally walks
//!   all `ToolResult` *blocks* within each tool-result-shaped message.
//! - This proxy's [`ImageSource`] can be URL-sourced (Anthropic
//!   `source: {type: "url", ...}`), a case `pi`'s simpler
//!   `{mimeType, data}` image model never has to handle. Kiro's own image
//!   shape only has a `bytes: String` field (no URL variant), so
//!   [`convert_images_to_kiro`] falls back to [`image_source_to_url`] for
//!   the URL case (embedding a `data:`/plain URL string) and uses the raw
//!   base64 payload directly otherwise.

use serde::Serialize;
use serde_json::{Value, json};

use crate::anthropic::schema::Message;
use crate::providers::translate_shared::{
    ContentBlock, ImageSource, image_source_to_url, normalize_content,
};

#[derive(Debug, Clone, Serialize)]
pub struct KiroImage {
    pub format: String,
    pub source: KiroImageSource,
}

#[derive(Debug, Clone, Serialize)]
pub struct KiroImageSource {
    pub bytes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KiroToolUse {
    pub name: String,
    #[serde(rename = "toolUseId")]
    pub tool_use_id: String,
    pub input: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct KiroToolResult {
    pub content: Vec<KiroToolResultText>,
    pub status: KiroToolResultStatus,
    #[serde(rename = "toolUseId")]
    pub tool_use_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KiroToolResultText {
    pub text: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KiroToolResultStatus {
    Success,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct KiroToolSpec {
    #[serde(rename = "toolSpecification")]
    pub tool_specification: KiroToolSpecification,
}

#[derive(Debug, Clone, Serialize)]
pub struct KiroToolSpecification {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: KiroInputSchema,
}

#[derive(Debug, Clone, Serialize)]
pub struct KiroInputSchema {
    pub json: Value,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct KiroUserInputMessage {
    pub content: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    pub origin: String, // always "KIRO_CLI"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<KiroImage>>,
    #[serde(
        rename = "userInputMessageContext",
        skip_serializing_if = "Option::is_none"
    )]
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
    #[serde(
        rename = "assistantResponseMessage",
        skip_serializing_if = "Option::is_none"
    )]
    pub assistant_response_message: Option<KiroAssistantResponseMessage>,
}

pub const TOOL_RESULT_LIMIT: usize = 250_000;

const TOOL_RESULTS_PROVIDED: &str = "Tool results provided.";
const TRUNCATION_SEPARATOR: &str = "\n... [TRUNCATED] ...\n";
const KIRO_ORIGIN: &str = "KIRO_CLI";

/// The TS original strips unpaired UTF-16 surrogate halves
/// (`/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g`).
/// Rust's `String`/`&str` are always valid UTF-8, so unpaired surrogates
/// cannot occur in the first place — this isn't a missing feature, it's a
/// non-issue in this language. Kept as a no-op passthrough (called at the
/// same call site as the TS) purely for structural parity with the
/// reference implementation.
pub fn sanitize_surrogates(text: &str) -> String {
    text.to_string()
}

/// Middle-truncates `text` to (approximately) `limit` "characters", keeping
/// the head and tail and replacing the middle with [`TRUNCATION_SEPARATOR`].
///
/// The TS original (`truncate`) operates on `.length`/`.substring`, i.e.
/// UTF-16 code units; naively porting that to Rust byte slicing would panic
/// on a multi-byte UTF-8 boundary. This operates on `char`s instead: same
/// `half = floor(limit / 2)` head/tail split, just char-counted rather than
/// UTF-16-code-unit-counted.
pub fn truncate_text(text: &str, limit: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= limit {
        return text.to_string();
    }
    let half = limit / 2;
    let head: String = text.chars().take(half).collect();
    let tail: String = text
        .chars()
        .rev()
        .take(half)
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}{TRUNCATION_SEPARATOR}{tail}")
}

/// Join `Text`/`Thinking` block text with no separator (mirrors the TS
/// `content.map(...).join("")`); other block types contribute `""`.
fn join_blocks_text(blocks: Vec<ContentBlock>) -> String {
    blocks
        .into_iter()
        .map(|b| match b {
            ContentBlock::Text { text } => text,
            ContentBlock::Thinking { thinking, .. } => thinking,
            _ => String::new(),
        })
        .collect::<Vec<_>>()
        .concat()
}

/// Extract plain text from a raw content `Value` that is *not* an outer
/// Anthropic message content array (no `tool_use`/`tool_result` wrapper
/// expected) — used for a tool result's own nested output content.
fn extract_text_blocks(content: &Value) -> String {
    if let Value::String(s) = content {
        return s.clone();
    }
    join_blocks_text(normalize_content(content, Value::Null))
}

/// Port of `getContentText`. `role` distinguishes this proxy's
/// note-1 tool-result-shaped `"user"` messages (whose *outer* content array
/// holds a single `ContentBlock::ToolResult`, not text) from ordinary
/// messages: for those, this reaches into the tool result's own nested
/// `content` and extracts its text, exactly mirroring how `pi`'s
/// `ToolResultMessage.content` field already IS the tool's raw output.
/// For everything else, joins `Text`/`Thinking` block text with `""`.
pub fn get_content_text(role: &str, content: &Value) -> String {
    if let Value::String(s) = content {
        return s.clone();
    }
    let blocks = normalize_content(content, Value::Null);
    if role == "user"
        && let Some(ContentBlock::ToolResult {
            content: nested, ..
        }) = blocks.first()
    {
        return extract_text_blocks(nested);
    }
    join_blocks_text(blocks)
}

/// Port of `extractImages`. Returns `[]` for plain-string content and for
/// this proxy's note-1 tool-result-shaped `"user"` messages (matching the
/// TS's `role === "toolResult"` early return); otherwise returns every
/// `ContentBlock::Image` found.
pub fn extract_images(role: &str, content: &Value) -> Vec<ImageSource> {
    if let Value::String(_) = content {
        return Vec::new();
    }
    let blocks = normalize_content(content, Value::Null);
    if role == "user" && matches!(blocks.first(), Some(ContentBlock::ToolResult { .. })) {
        return Vec::new();
    }
    blocks
        .into_iter()
        .filter_map(|b| match b {
            ContentBlock::Image { source } => Some(source),
            _ => None,
        })
        .collect()
}

/// Port of `convertImagesToKiro`.
pub fn convert_images_to_kiro(images: &[ImageSource]) -> Vec<KiroImage> {
    images
        .iter()
        .map(|img| {
            let format = img
                .media_type
                .split('/')
                .nth(1)
                .unwrap_or("png")
                .to_string();
            let bytes = if img.source_type == "url" {
                image_source_to_url(img)
            } else {
                img.data.clone()
            };
            KiroImage {
                format,
                source: KiroImageSource { bytes },
            }
        })
        .collect()
}

/// Port of `convertToolsToKiro`. `tools` are raw Anthropic tool
/// definitions (`{name, description, input_schema}`), not `pi`'s typed
/// `Tool` (`parameters` field) — the note-1-style field-name translation.
pub fn convert_tools_to_kiro(tools: &[Value]) -> Vec<KiroToolSpec> {
    tools
        .iter()
        .map(|tool| {
            let name = tool
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let description = tool
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let json = tool
                .get("input_schema")
                .cloned()
                .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
            KiroToolSpec {
                tool_specification: KiroToolSpecification {
                    name,
                    description,
                    input_schema: KiroInputSchema { json },
                },
            }
        })
        .collect()
}

/// This proxy's note-1 translation of `msg.role === "toolResult"`: a
/// `"user"` message whose first normalized content block is a
/// `ContentBlock::ToolResult`. Anthropic's format never mixes plain user
/// text with tool results in one message the way Claude Code emits them,
/// so checking only the first block is sufficient and matches the design
/// notes' defensive guidance.
fn is_tool_result_message(msg: &Message) -> bool {
    if msg.role != "user" {
        return false;
    }
    let blocks = normalize_content(&msg.content, Value::Null);
    matches!(blocks.first(), Some(ContentBlock::ToolResult { .. }))
}

/// Whether an `"assistant"` message contains at least one `tool_use` block.
fn assistant_has_tool_use(msg: &Message) -> bool {
    if msg.role != "assistant" {
        return false;
    }
    normalize_content(&msg.content, Value::Null)
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolUse { .. }))
}

/// Build a single `KiroToolResult` entry from one `ContentBlock::ToolResult`
/// block's fields, truncating its own extracted text to
/// [`TOOL_RESULT_LIMIT`]. Also returns any images found in the tool
/// result's nested content (Anthropic tool results can carry image blocks
/// alongside text).
fn build_tool_result(
    tool_use_id: &str,
    nested_content: &Value,
    is_error: Option<bool>,
) -> (KiroToolResult, Vec<ImageSource>) {
    let text = truncate_text(&extract_text_blocks(nested_content), TOOL_RESULT_LIMIT);
    let images: Vec<ImageSource> = normalize_content(nested_content, Value::Null)
        .into_iter()
        .filter_map(|b| match b {
            ContentBlock::Image { source } => Some(source),
            _ => None,
        })
        .collect();
    let status = if is_error.unwrap_or(false) {
        KiroToolResultStatus::Error
    } else {
        KiroToolResultStatus::Success
    };
    (
        KiroToolResult {
            content: vec![KiroToolResultText { text }],
            status,
            tool_use_id: tool_use_id.to_string(),
        },
        images,
    )
}

#[derive(Debug)]
pub struct BuildHistoryResult {
    pub history: Vec<KiroHistoryEntry>,
    pub system_prepended: bool,
    pub current_msg_start_idx: usize,
}

/// Port of `buildHistory`. See the module doc comment for the note-1
/// role-detection translation this relies on throughout.
///
/// Boundary-finding (`current_msg_start_idx`): scan backward from the end
/// over trailing tool-result-shaped messages, then — if what's left points
/// at an `"assistant"` message that itself contains a `tool_use` — leave
/// the boundary there too, so history never ends with a dangling
/// (unanswered-in-history) tool call; its answering tool result(s) get
/// excluded from history right along with it. Otherwise (assistant message
/// with no tool_use, or any other role) the boundary sits just past it.
pub fn build_history(
    messages: &[Message],
    model_id: &str,
    system_prompt: Option<&str>,
) -> BuildHistoryResult {
    if messages.is_empty() {
        return BuildHistoryResult {
            history: Vec::new(),
            system_prepended: false,
            current_msg_start_idx: 0,
        };
    }

    let mut current_msg_start_idx = messages.len() - 1;
    while current_msg_start_idx > 0 && is_tool_result_message(&messages[current_msg_start_idx]) {
        current_msg_start_idx -= 1;
    }
    if messages[current_msg_start_idx].role == "assistant"
        && !assistant_has_tool_use(&messages[current_msg_start_idx])
    {
        current_msg_start_idx += 1;
    }

    let boundary = current_msg_start_idx;
    let mut history: Vec<KiroHistoryEntry> = Vec::new();
    let mut system_prepended = false;
    let mut i = 0usize;

    while i < boundary {
        let msg = &messages[i];
        if msg.role == "user" && !is_tool_result_message(msg) {
            let mut content = get_content_text("user", &msg.content);
            if let Some(sp) = system_prompt
                && !system_prepended
            {
                content = format!("{sp}\n\n{content}");
                system_prepended = true;
            }
            let images = extract_images("user", &msg.content);
            let sanitized_content = sanitize_surrogates(&content);

            let merges_into_prev = history
                .last()
                .is_some_and(|e| e.user_input_message.is_some());
            if merges_into_prev {
                let prev = history
                    .last_mut()
                    .and_then(|e| e.user_input_message.as_mut())
                    .expect("checked above");
                prev.content = format!("{}\n\n{}", prev.content, sanitized_content);
                if !images.is_empty() {
                    let kiro_images = convert_images_to_kiro(&images);
                    prev.images.get_or_insert_with(Vec::new).extend(kiro_images);
                }
            } else {
                history.push(KiroHistoryEntry {
                    user_input_message: Some(KiroUserInputMessage {
                        content: sanitized_content,
                        model_id: model_id.to_string(),
                        origin: KIRO_ORIGIN.to_string(),
                        images: if images.is_empty() {
                            None
                        } else {
                            Some(convert_images_to_kiro(&images))
                        },
                        user_input_message_context: None,
                    }),
                    assistant_response_message: None,
                });
            }
            i += 1;
        } else if msg.role == "assistant" {
            let blocks = normalize_content(&msg.content, Value::Null);
            let mut arm_content = String::new();
            let mut arm_tool_uses: Vec<KiroToolUse> = Vec::new();
            for block in blocks {
                match block {
                    ContentBlock::Text { text } => arm_content.push_str(&text),
                    ContentBlock::Thinking { thinking, .. } => {
                        arm_content = format!("<thinking>{thinking}</thinking>\n\n{arm_content}");
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        arm_tool_uses.push(KiroToolUse {
                            name,
                            tool_use_id: id,
                            input,
                        });
                    }
                    _ => {}
                }
            }
            if !arm_content.is_empty() || !arm_tool_uses.is_empty() {
                history.push(KiroHistoryEntry {
                    user_input_message: None,
                    assistant_response_message: Some(KiroAssistantResponseMessage {
                        content: arm_content,
                        tool_uses: if arm_tool_uses.is_empty() {
                            None
                        } else {
                            Some(arm_tool_uses)
                        },
                    }),
                });
            }
            i += 1;
        } else if is_tool_result_message(msg) {
            let mut tool_results: Vec<KiroToolResult> = Vec::new();
            let mut tr_images: Vec<ImageSource> = Vec::new();
            let mut j = i;
            while j < boundary && is_tool_result_message(&messages[j]) {
                let blocks = normalize_content(&messages[j].content, Value::Null);
                for block in blocks {
                    if let ContentBlock::ToolResult {
                        tool_use_id,
                        content: nested,
                        is_error,
                    } = block
                    {
                        let (result, images) = build_tool_result(&tool_use_id, &nested, is_error);
                        tool_results.push(result);
                        tr_images.extend(images);
                    }
                }
                j += 1;
            }
            i = j;

            let merges_into_prev = history
                .last()
                .is_some_and(|e| e.user_input_message.is_some());
            if merges_into_prev {
                let prev = history
                    .last_mut()
                    .and_then(|e| e.user_input_message.as_mut())
                    .expect("checked above");
                prev.content = format!("{}\n\n{TOOL_RESULTS_PROVIDED}", prev.content);
                if !tr_images.is_empty() {
                    let kiro_images = convert_images_to_kiro(&tr_images);
                    prev.images.get_or_insert_with(Vec::new).extend(kiro_images);
                }
                let ctx = prev
                    .user_input_message_context
                    .get_or_insert_with(KiroUserInputMessageContext::default);
                ctx.tool_results
                    .get_or_insert_with(Vec::new)
                    .extend(tool_results);
            } else {
                history.push(KiroHistoryEntry {
                    user_input_message: Some(KiroUserInputMessage {
                        content: TOOL_RESULTS_PROVIDED.to_string(),
                        model_id: model_id.to_string(),
                        origin: KIRO_ORIGIN.to_string(),
                        images: if tr_images.is_empty() {
                            None
                        } else {
                            Some(convert_images_to_kiro(&tr_images))
                        },
                        user_input_message_context: Some(KiroUserInputMessageContext {
                            tool_results: Some(tool_results),
                            tools: None,
                        }),
                    }),
                    assistant_response_message: None,
                });
            }
        } else {
            i += 1;
        }
    }

    BuildHistoryResult {
        history,
        system_prepended,
        current_msg_start_idx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn thinking_block(thinking: &str) -> Value {
        json!({"type": "thinking", "thinking": thinking})
    }

    // ---- small helpers ----

    #[test]
    fn sanitize_surrogates_is_a_passthrough() {
        assert_eq!(sanitize_surrogates("hello"), "hello");
        assert_eq!(sanitize_surrogates(""), "");
        assert_eq!(sanitize_surrogates("emoji 🙈 ok"), "emoji 🙈 ok");
    }

    #[test]
    fn truncate_text_returns_input_unchanged_under_limit() {
        assert_eq!(truncate_text("abcdefghij", 20), "abcdefghij");
        assert_eq!(truncate_text("abcdefghij", 10), "abcdefghij");
    }

    #[test]
    fn truncate_text_splits_head_and_tail_on_char_boundaries() {
        // 10 chars, limit 6 -> half = 3: head "abc", tail "hij".
        let result = truncate_text("abcdefghij", 6);
        assert_eq!(result, "abc\n... [TRUNCATED] ...\nhij");
    }

    #[test]
    fn truncate_text_does_not_panic_on_multibyte_chars() {
        let emoji = "😀😃😄😁😆😅😂🤣😊😇";
        assert_eq!(emoji.chars().count(), 10);
        let result = truncate_text(emoji, 6);
        // half = 3: 3 emoji head + separator + 3 emoji tail.
        let head: String = emoji.chars().take(3).collect();
        let tail: String = emoji.chars().skip(7).collect();
        assert_eq!(result, format!("{head}\n... [TRUNCATED] ...\n{tail}"));
    }

    #[test]
    fn convert_images_to_kiro_uses_raw_base64_for_base64_source() {
        let images = vec![ImageSource {
            media_type: "image/png".to_string(),
            data: "QUJD".to_string(),
            source_type: "base64".to_string(),
        }];
        let kiro = convert_images_to_kiro(&images);
        assert_eq!(kiro.len(), 1);
        assert_eq!(kiro[0].format, "png");
        assert_eq!(kiro[0].source.bytes, "QUJD");
    }

    #[test]
    fn convert_images_to_kiro_uses_image_source_to_url_for_url_source() {
        let images = vec![ImageSource {
            media_type: "image/jpeg".to_string(),
            data: "https://example.com/x.jpg".to_string(),
            source_type: "url".to_string(),
        }];
        let kiro = convert_images_to_kiro(&images);
        assert_eq!(kiro.len(), 1);
        assert_eq!(kiro[0].format, "jpeg");
        assert_eq!(kiro[0].source.bytes, "https://example.com/x.jpg");
    }

    #[test]
    fn convert_tools_to_kiro_maps_name_description_and_input_schema() {
        let tools = vec![json!({
            "name": "Search",
            "description": "search the web",
            "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
        })];
        let kiro = convert_tools_to_kiro(&tools);
        assert_eq!(kiro.len(), 1);
        assert_eq!(kiro[0].tool_specification.name, "Search");
        assert_eq!(kiro[0].tool_specification.description, "search the web");
        assert_eq!(
            kiro[0].tool_specification.input_schema.json,
            json!({"type": "object", "properties": {"q": {"type": "string"}}})
        );
    }

    // ---- get_content_text / extract_images (note 1 translation) ----

    #[test]
    fn get_content_text_extracts_nested_tool_result_text_for_tool_result_shaped_user_message() {
        let content = json!([tool_result_block(
            "t1",
            Value::String("the result".to_string())
        )]);
        assert_eq!(get_content_text("user", &content), "the result");
    }

    #[test]
    fn extract_images_returns_empty_for_tool_result_shaped_user_message() {
        let content = json!([tool_result_block("t1", Value::String("r".to_string()))]);
        assert!(extract_images("user", &content).is_empty());
    }

    // ---- build_history ----

    #[test]
    fn simple_exchange_alternates_with_no_merging() {
        let messages = vec![
            user(Value::String("Hi".to_string())),
            assistant(Value::String("Hello".to_string())),
            user(Value::String("How are you".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(result.current_msg_start_idx, 2);
        assert_eq!(result.history.len(), 2);
        assert_eq!(
            result.history[0]
                .user_input_message
                .as_ref()
                .unwrap()
                .content,
            "Hi"
        );
        assert_eq!(
            result.history[1]
                .assistant_response_message
                .as_ref()
                .unwrap()
                .content,
            "Hello"
        );
        assert!(!result.system_prepended);
    }

    #[test]
    fn consecutive_user_messages_merge_with_blank_line_join() {
        let messages = vec![
            user(Value::String("A".to_string())),
            user(Value::String("B".to_string())),
            assistant(Value::String("ack".to_string())),
            user(Value::String("C".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(result.current_msg_start_idx, 3);
        assert_eq!(result.history.len(), 2);
        assert_eq!(
            result.history[0]
                .user_input_message
                .as_ref()
                .unwrap()
                .content,
            "A\n\nB"
        );
    }

    #[test]
    fn tool_use_followed_by_tool_result_folds_into_synthetic_user_entry() {
        let messages = vec![
            user(Value::String("do X".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
            user(json!([tool_result_block(
                "t1",
                Value::String("result text".to_string())
            )])),
            assistant(Value::String("final answer".to_string())),
            user(Value::String("thanks".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(result.current_msg_start_idx, 4);
        assert_eq!(result.history.len(), 4);

        let assistant_tool_use = result.history[1]
            .assistant_response_message
            .as_ref()
            .unwrap();
        assert_eq!(assistant_tool_use.content, "");
        assert_eq!(assistant_tool_use.tool_uses.as_ref().unwrap().len(), 1);

        let tool_result_entry = result.history[2].user_input_message.as_ref().unwrap();
        assert_eq!(tool_result_entry.content, "Tool results provided.");
        let ctx = tool_result_entry
            .user_input_message_context
            .as_ref()
            .unwrap();
        let results = ctx.tool_results.as_ref().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tool_use_id, "t1");
        assert_eq!(results[0].content[0].text, "result text");
        assert_eq!(results[0].status, KiroToolResultStatus::Success);

        assert_eq!(
            result.history[3]
                .assistant_response_message
                .as_ref()
                .unwrap()
                .content,
            "final answer"
        );
    }

    #[test]
    fn consecutive_tool_result_messages_merge_into_one_entry() {
        let messages = vec![
            user(Value::String("do X".to_string())),
            assistant(json!([
                tool_use_block("t1", "Search", json!({})),
                tool_use_block("t2", "Fetch", json!({})),
            ])),
            user(json!([tool_result_block(
                "t1",
                Value::String("r1".to_string())
            )])),
            user(json!([tool_result_block(
                "t2",
                Value::String("r2".to_string())
            )])),
            assistant(Value::String("final".to_string())),
            user(Value::String("thanks".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        // 4 entries, NOT 5 -- both tool results consumed into a single entry.
        assert_eq!(result.history.len(), 4);
        let tool_result_entry = result.history[2].user_input_message.as_ref().unwrap();
        assert_eq!(tool_result_entry.content, "Tool results provided.");
        let results = tool_result_entry
            .user_input_message_context
            .as_ref()
            .unwrap()
            .tool_results
            .as_ref()
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].tool_use_id, "t1");
        assert_eq!(results[1].tool_use_id, "t2");
    }

    #[test]
    fn trailing_tool_results_merge_into_preceding_text_user_entry() {
        // No assistant turn between the plain user text and its "tool result" --
        // exercises the *merge-into-a-preceding-userInputMessage* branch of the
        // sentinel logic, as opposed to *starting a fresh one*.
        let messages = vec![
            user(Value::String("hi".to_string())),
            user(json!([tool_result_block(
                "t1",
                Value::String("r1".to_string())
            )])),
            assistant(Value::String("ack".to_string())),
            user(Value::String("next".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(result.history.len(), 2);
        let merged = result.history[0].user_input_message.as_ref().unwrap();
        assert_eq!(merged.content, "hi\n\nTool results provided.");
        assert_eq!(
            merged
                .user_input_message_context
                .as_ref()
                .unwrap()
                .tool_results
                .as_ref()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn thinking_block_is_prepended_not_appended_before_text() {
        let messages = vec![
            user(Value::String("hi".to_string())),
            assistant(json!([
                thinking_block("deep thought"),
                text_block("answer")
            ])),
            user(Value::String("next".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(
            result.history[1]
                .assistant_response_message
                .as_ref()
                .unwrap()
                .content,
            "<thinking>deep thought</thinking>\n\nanswer"
        );
    }

    #[test]
    fn thinking_block_prepends_even_when_it_appears_after_text_in_source_order() {
        // Regardless of the original block order, thinking always ends up
        // structurally BEFORE the text -- because prepending happens on
        // whatever has already accumulated, not just on other thinking.
        let messages = vec![
            user(Value::String("hi".to_string())),
            assistant(json!([
                text_block("answer"),
                thinking_block("deep thought")
            ])),
            user(Value::String("next".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(
            result.history[1]
                .assistant_response_message
                .as_ref()
                .unwrap()
                .content,
            "<thinking>deep thought</thinking>\n\nanswer"
        );
    }

    #[test]
    fn empty_assistant_message_is_skipped_entirely() {
        let messages = vec![
            user(Value::String("hi".to_string())),
            assistant(Value::String(String::new())),
            user(Value::String("next".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(result.history.len(), 1);
        assert!(result.history[0].user_input_message.is_some());
    }

    #[test]
    fn empty_assistant_message_with_empty_array_content_is_skipped_entirely() {
        let messages = vec![
            user(Value::String("hi".to_string())),
            assistant(json!([])),
            user(Value::String("next".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(result.history.len(), 1);
    }

    #[test]
    fn system_prompt_prepends_only_to_first_history_user_message() {
        let messages = vec![
            user(Value::String("hi".to_string())),
            assistant(Value::String("ack".to_string())),
            user(Value::String("again".to_string())),
            assistant(Value::String("ack2".to_string())),
            user(Value::String("final".to_string())),
        ];
        let result = build_history(&messages, "model-x", Some("SYS"));
        assert!(result.system_prepended);
        assert_eq!(
            result.history[0]
                .user_input_message
                .as_ref()
                .unwrap()
                .content,
            "SYS\n\nhi"
        );
        assert_eq!(
            result.history[2]
                .user_input_message
                .as_ref()
                .unwrap()
                .content,
            "again"
        );
    }

    #[test]
    fn trailing_unanswered_tool_call_and_its_result_are_excluded_from_history() {
        let messages = vec![
            user(Value::String("do X".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
            user(json!([tool_result_block(
                "t1",
                Value::String("r1".to_string())
            )])),
        ];
        let result = build_history(&messages, "model-x", None);
        assert_eq!(result.current_msg_start_idx, 1);
        assert_eq!(result.history.len(), 1);
        assert_eq!(
            result.history[0]
                .user_input_message
                .as_ref()
                .unwrap()
                .content,
            "do X"
        );
    }

    #[test]
    fn empty_messages_produce_empty_history() {
        let result = build_history(&[], "model-x", None);
        assert_eq!(result.current_msg_start_idx, 0);
        assert!(result.history.is_empty());
        assert!(!result.system_prepended);
    }

    #[test]
    fn system_prompt_is_not_consumed_when_history_is_empty() {
        // Single message -> entirely "current", nothing lands in history, so
        // there's no "first user message in history" to prepend onto. Task
        // 14 relies on `system_prepended == false` here to know it must
        // prepend the system prompt itself instead.
        let messages = vec![user(Value::String("hi".to_string()))];
        let result = build_history(&messages, "model-x", Some("SYS"));
        assert_eq!(result.current_msg_start_idx, 0);
        assert!(result.history.is_empty());
        assert!(!result.system_prepended);
    }

    #[test]
    fn tool_result_is_error_maps_to_error_status() {
        let messages = vec![
            user(Value::String("do X".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
            user(json!([
                json!({"type": "tool_result", "tool_use_id": "t1", "content": "boom", "is_error": true})
            ])),
            assistant(Value::String("final".to_string())),
            user(Value::String("thanks".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        let tool_result_entry = result.history[2].user_input_message.as_ref().unwrap();
        let results = tool_result_entry
            .user_input_message_context
            .as_ref()
            .unwrap()
            .tool_results
            .as_ref()
            .unwrap();
        assert_eq!(results[0].status, KiroToolResultStatus::Error);
    }

    #[test]
    fn tool_result_text_is_truncated_to_tool_result_limit() {
        let long_text = "x".repeat(TOOL_RESULT_LIMIT + 1000);
        let messages = vec![
            user(Value::String("do X".to_string())),
            assistant(json!([tool_use_block("t1", "Search", json!({}))])),
            user(json!([tool_result_block("t1", Value::String(long_text))])),
            assistant(Value::String("final".to_string())),
            user(Value::String("thanks".to_string())),
        ];
        let result = build_history(&messages, "model-x", None);
        let tool_result_entry = result.history[2].user_input_message.as_ref().unwrap();
        let text = &tool_result_entry
            .user_input_message_context
            .as_ref()
            .unwrap()
            .tool_results
            .as_ref()
            .unwrap()[0]
            .content[0]
            .text;
        assert!(text.contains(TRUNCATION_SEPARATOR));
        assert!(text.chars().count() < TOOL_RESULT_LIMIT + 1000);
    }

    #[test]
    fn serializes_user_entry_with_images_and_tool_results_using_kiro_wire_field_names() {
        let entry = KiroHistoryEntry {
            user_input_message: Some(KiroUserInputMessage {
                content: "Tool results provided.".to_string(),
                model_id: "model-x".to_string(),
                origin: "KIRO_CLI".to_string(),
                images: Some(vec![KiroImage {
                    format: "png".to_string(),
                    source: KiroImageSource {
                        bytes: "QUJD".to_string(),
                    },
                }]),
                user_input_message_context: Some(KiroUserInputMessageContext {
                    tool_results: Some(vec![KiroToolResult {
                        content: vec![KiroToolResultText {
                            text: "result text".to_string(),
                        }],
                        status: KiroToolResultStatus::Success,
                        tool_use_id: "t1".to_string(),
                    }]),
                    tools: None,
                }),
            }),
            assistant_response_message: None,
        };
        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            value,
            json!({
                "userInputMessage": {
                    "content": "Tool results provided.",
                    "modelId": "model-x",
                    "origin": "KIRO_CLI",
                    "images": [{"format": "png", "source": {"bytes": "QUJD"}}],
                    "userInputMessageContext": {
                        "toolResults": [{
                            "content": [{"text": "result text"}],
                            "status": "success",
                            "toolUseId": "t1",
                        }],
                    },
                },
            })
        );
    }

    #[test]
    fn serializes_assistant_entry_with_tool_uses_and_omits_absent_fields() {
        let entry = KiroHistoryEntry {
            user_input_message: None,
            assistant_response_message: Some(KiroAssistantResponseMessage {
                content: "".to_string(),
                tool_uses: Some(vec![KiroToolUse {
                    name: "Search".to_string(),
                    tool_use_id: "t1".to_string(),
                    input: json!({"q": "rust"}),
                }]),
            }),
        };
        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            value,
            json!({
                "assistantResponseMessage": {
                    "content": "",
                    "toolUses": [{
                        "name": "Search",
                        "toolUseId": "t1",
                        "input": {"q": "rust"},
                    }],
                },
            })
        );
        // userInputMessage must be entirely absent, not null, per skip_serializing_if.
        assert!(value.get("userInputMessage").is_none());
    }
}
