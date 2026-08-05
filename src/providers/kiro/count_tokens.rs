use crate::anthropic::schema::MessagesRequest;
use crate::providers::kiro::translate::models::{IMAGE_TOKEN_ESTIMATE, approx_token_count};
use crate::providers::translate_shared::{ContentBlock, normalize_content};

/// Overhead tokens per message in the request. This estimate accounts for
/// framing and formatting overhead that the API adds beyond the raw content.
const MESSAGE_OVERHEAD_TOKENS: u64 = 4;

/// Heuristic token counter for Kiro requests. This is not a real tokenizer —
/// Kiro exposes no token-accurate API, only a `contextUsagePercentage` metric.
/// This function provides a monotonic estimate roughly proportional to actual
/// token usage, suitable for compaction logic that needs approximate counts.
pub fn count_tokens(req: &MessagesRequest) -> u64 {
    let mut total = 0u64;

    // System text
    if let Some(system) = req.extra.get("system") {
        total += count_system_tokens(system);
    }

    // Messages
    for msg in &req.messages {
        total += count_message_tokens(&msg.content);
    }

    // Message overhead
    total += req.messages.len() as u64 * MESSAGE_OVERHEAD_TOKENS;

    // Tools
    if let Some(tools) = req.extra.get("tools").and_then(|v| v.as_array()) {
        total += count_tool_tokens(tools);
    }

    total
}

fn count_system_tokens(system: &serde_json::Value) -> u64 {
    match system {
        serde_json::Value::String(s) => approx_token_count(s),
        serde_json::Value::Array(arr) => {
            let mut total = 0u64;
            for block in arr {
                if let Some(text) = block.get("text").and_then(|v| v.as_str())
                    && !text.starts_with("x-anthropic-billing-header:")
                {
                    total += approx_token_count(text);
                }
            }
            total
        }
        _ => 0,
    }
}

fn count_message_tokens(content: &serde_json::Value) -> u64 {
    let blocks = normalize_content(content, serde_json::Value::Object(Default::default()));
    let mut total = 0u64;

    for block in blocks {
        total += count_content_block_tokens(&block);
    }

    total
}

fn count_content_block_tokens(block: &ContentBlock) -> u64 {
    match block {
        ContentBlock::Text { text } => approx_token_count(text),
        ContentBlock::Image { .. } => IMAGE_TOKEN_ESTIMATE,
        ContentBlock::Thinking { thinking, .. } => approx_token_count(thinking),
        ContentBlock::ToolUse { name, input, .. } => {
            let mut total = approx_token_count(name);
            total += approx_token_count(&serde_json::to_string(input).unwrap_or_default());
            total
        }
        ContentBlock::ToolResult { content, .. } => {
            let blocks = normalize_content(content, serde_json::Value::Object(Default::default()));
            let mut total = 0u64;
            for nested_block in blocks {
                total += count_content_block_tokens(&nested_block);
            }
            total
        }
    }
}

fn count_tool_tokens(tools: &[serde_json::Value]) -> u64 {
    let mut total = 0u64;
    for tool in tools {
        if let Some(name) = tool.get("name").and_then(|v| v.as_str()) {
            total += approx_token_count(name);
        }
        if let Some(desc) = tool.get("description").and_then(|v| v.as_str()) {
            total += approx_token_count(desc);
        }
        if let Some(schema) = tool.get("input_schema") {
            total += approx_token_count(&serde_json::to_string(schema).unwrap_or_default());
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn single_text_message_counts_correctly() {
        let req: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "user", "content": "hello world"}]
        }))
        .unwrap();
        let count = count_tokens(&req);
        // "hello" (1) + "world" (1) + message overhead (4) = 6
        assert_eq!(count, 6);
    }

    #[test]
    fn image_block_contributes_exactly_2000_tokens() {
        let req: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "desc"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "abc"}}
            ]}]
        }))
        .unwrap();
        let count = count_tokens(&req);
        // "desc" (1) + image (2000) + message overhead (4) = 2005
        assert_eq!(count, 2005);
    }

    #[test]
    fn tool_use_block_counts_name_and_input() {
        let req: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "assistant", "content": [
                {"type": "tool_use", "id": "123", "name": "search", "input": {"query": "test"}}
            ]}]
        }))
        .unwrap();
        let count = count_tokens(&req);
        // "search" (1) + {"query":"test"} serialized (~3) + message overhead (4) = ~8
        assert!(count > 0);
    }

    #[test]
    fn multiple_messages_have_per_message_overhead() {
        let req: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"}
            ]
        }))
        .unwrap();
        let count = count_tokens(&req);
        // "hi" (1) + "hello" (1) + 2 * message overhead (8) = 10
        assert_eq!(count, 10);
    }

    #[test]
    fn empty_content_does_not_panic() {
        let req: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "user", "content": ""}]
        }))
        .unwrap();
        let count = count_tokens(&req);
        // Empty string counts as 1 (due to max(1) in approx_token_count) + message overhead (4) = 5
        assert!(count > 0);
    }

    #[test]
    fn tool_definitions_add_tokens() {
        let req: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "user", "content": "use a tool"}],
            "tools": [{"name": "search", "description": "Search tool", "input_schema": {"type": "object"}}]
        }))
        .unwrap();
        let count = count_tokens(&req);
        // "use" (1) + "a" (1) + "tool" (1) + message overhead (4) + tool tokens
        assert!(count > 10);
    }

    #[test]
    fn thinking_block_counts_thinking_text() {
        let req: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "assistant", "content": [
                {"type": "thinking", "thinking": "let me think about this"},
                {"type": "text", "text": "here is my answer"}
            ]}]
        }))
        .unwrap();
        let count = count_tokens(&req);
        // thinking tokens + text tokens + overhead
        assert!(count > 0);
    }

    #[test]
    fn token_count_is_monotonic() {
        let short: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "user", "content": "short"}]
        }))
        .unwrap();
        let long: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "messages": [{"role": "user", "content": "this is a much longer message with many words in it"}]
        }))
        .unwrap();
        assert!(
            count_tokens(&long) >= count_tokens(&short),
            "longer message should have more tokens"
        );
    }
}
