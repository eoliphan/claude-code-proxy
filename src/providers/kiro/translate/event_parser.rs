//! Kiro stream event boundary parser.
//!
//! Kiro's streaming HTTP response body is neither SSE nor
//! newline-delimited: individual JSON objects are emitted back-to-back,
//! embedded inside AWS binary Event Stream framing, and that framing can
//! itself contain stray `{"` byte sequences that are NOT the start of a
//! real JSON object. This module is a port of the `pi-provider-kiro`
//! reference implementation's `src/event-parser.ts` (read directly at
//! implementation time from
//! `/home/erich.oliphant/IdeaProjects/pi-provider-kiro/src/event-parser.ts`,
//! cross-checked against `test/event-parser.test.ts` in the same repo),
//! adapted from the TS original's free UTF-16-code-unit indexing to
//! UTF-8-boundary-safe byte indexing.
//!
//! Two places where this port follows the TS file's literal control flow
//! rather than a looser English description of it -- both verified
//! directly against the `.ts` source, not just prose about it:
//!
//! - [`find_json_end`]'s `escape_next` flag is armed by ANY backslash,
//!   unconditionally -- not only while `in_string` (TS `event-parser.ts`
//!   lines 24-27 check `char === "\\"` *before* the `inString`-gated
//!   block, not inside it). Whichever character follows a backslash is
//!   skipped entirely -- no quote toggle, no brace counting -- even
//!   outside a string. This matters because the scanner must tolerate raw
//!   binary framing noise that can contain a stray backslash byte outside
//!   any JSON string.
//! - [`tool_use_input_string`] (dispatch case 2, `ToolUse`) and
//!   [`tool_use_input_delta_string`] (dispatch case 3, `ToolUseInput`) are
//!   genuinely different normalizations in the TS source (lines 46-53 vs.
//!   line 67), not the same logic reused twice: only the `ToolUse` path
//!   special-cases an empty object down to `""`; `ToolUseInput` always
//!   re-stringifies a non-string input, including `{}` -> `"{}"`.

use serde_json::Value;

/// One event extracted from a Kiro stream chunk.
#[derive(Debug, Clone, PartialEq)]
pub enum KiroStreamEvent {
    Content(String),
    ToolUse {
        name: String,
        tool_use_id: String,
        input: String,
        stop: Option<bool>,
    },
    ToolUseInput {
        input: String,
    },
    ToolUseStop {
        stop: bool,
    },
    ContextUsage {
        context_usage_percentage: f64,
    },
    FollowupPrompt(String),
    Usage {
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    },
    Error {
        error: String,
        message: Option<String>,
    },
}

/// Result of scanning a buffer for complete Kiro stream events.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseResult {
    pub events: Vec<KiroStreamEvent>,
    pub remaining: String,
}

/// Known JSON key patterns that start a Kiro event object. Anchoring on
/// these specific patterns (rather than a bare `{"`) is what lets the
/// scanner ride through the stray `{"` byte sequences that show up inside
/// AWS binary Event Stream framing without misfiring on them.
const EVENT_PATTERNS: [&str; 12] = [
    r#"{"content":"#,
    r#"{"name":"#,
    r#"{"input":"#,
    r#"{"stop":"#,
    r#"{"contextUsagePercentage":"#,
    r#"{"followupPrompt":"#,
    r#"{"usage":"#,
    r#"{"toolUseId":"#,
    r#"{"unit":"#,
    r#"{"error":"#,
    r#"{"Error":"#,
    r#"{"message":"#,
];

/// Scan `text[start..]` for the byte offset (into `text`) of the `}` that
/// closes the JSON object opening at `start`, tracking brace depth and
/// string/escape state. UTF-8-boundary-safe: iterates `char_indices()`
/// rather than raw bytes, so the returned offset -- and every offset this
/// module derives from it -- always lands on a char boundary, even when
/// the object's string content contains multi-byte UTF-8 characters.
///
/// Returns `None` if `text` ends before the brace depth returns to zero
/// (an incomplete object still arriving in a later chunk).
fn find_json_end(text: &str, start: usize) -> Option<usize> {
    let mut brace_count: i32 = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (offset, ch) in text[start..].char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if ch == '\\' {
            // Unconditional, matching the TS source: a backslash anywhere
            // (not only inside a string) arms escape_next, and the next
            // char is skipped entirely -- including for brace counting.
            escape_next = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if !in_string {
            match ch {
                '{' => brace_count += 1,
                '}' => {
                    brace_count -= 1;
                    if brace_count == 0 {
                        return Some(start + offset);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// Find the earliest byte offset (>= `from`) in `buffer` at which any
/// [`EVENT_PATTERNS`] entry starts. Returns `None` if none match.
fn find_next_event_start(buffer: &str, from: usize) -> Option<usize> {
    EVENT_PATTERNS
        .iter()
        .filter_map(|pattern| buffer[from..].find(pattern).map(|i| i + from))
        .min()
}

/// Normalize the `input` field for a `ToolUse` event (dispatch case 2). A
/// JSON string is used as-is; a non-empty JSON object is re-stringified;
/// every other shape (missing, null, empty object, array, number, bool)
/// becomes `""`. Intentionally NOT the same rule as
/// [`tool_use_input_delta_string`] -- see the module doc comment.
fn tool_use_input_string(input: &Value) -> String {
    match input {
        Value::String(s) => s.clone(),
        Value::Object(map) if !map.is_empty() => serde_json::to_string(input).unwrap_or_default(),
        _ => String::new(),
    }
}

/// Normalize the `input` field for a `ToolUseInput` delta event (dispatch
/// case 3). A JSON string is used as-is; anything else is unconditionally
/// re-stringified (including `{}` -> `"{}"`). Intentionally NOT the same
/// rule as [`tool_use_input_string`] -- see the module doc comment.
fn tool_use_input_delta_string(input: &Value) -> String {
    match input {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Dispatch a parsed JSON object to the [`KiroStreamEvent`] variant it
/// represents, in the exact priority order of the TS `if`/`else if` chain
/// (first match wins). Returns `None` for a recognized-but-unmapped shape
/// (silently dropped, matching the TS's `return null`).
fn parse_kiro_event(parsed: &Value) -> Option<KiroStreamEvent> {
    if parsed.get("content").is_some() {
        return Some(KiroStreamEvent::Content(
            parsed["content"].as_str().unwrap_or_default().to_string(),
        ));
    }

    if parsed.get("name").is_some() && parsed.get("toolUseId").is_some() {
        let name = parsed["name"].as_str().unwrap_or_default().to_string();
        let tool_use_id = parsed["toolUseId"].as_str().unwrap_or_default().to_string();
        let input = tool_use_input_string(&parsed["input"]);
        let stop = parsed.get("stop").and_then(Value::as_bool);
        return Some(KiroStreamEvent::ToolUse {
            name,
            tool_use_id,
            input,
            stop,
        });
    }

    if parsed.get("input").is_some() && parsed.get("name").is_none() {
        return Some(KiroStreamEvent::ToolUseInput {
            input: tool_use_input_delta_string(&parsed["input"]),
        });
    }

    if parsed.get("stop").is_some() && parsed.get("contextUsagePercentage").is_none() {
        return Some(KiroStreamEvent::ToolUseStop {
            stop: parsed["stop"].as_bool().unwrap_or(false),
        });
    }

    if parsed.get("contextUsagePercentage").is_some() {
        return Some(KiroStreamEvent::ContextUsage {
            context_usage_percentage: parsed["contextUsagePercentage"]
                .as_f64()
                .unwrap_or_default(),
        });
    }

    if parsed.get("followupPrompt").is_some() {
        return Some(KiroStreamEvent::FollowupPrompt(
            parsed["followupPrompt"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        ));
    }

    if parsed.get("error").is_some() || parsed.get("Error").is_some() {
        // A present-but-null "error"/"Error" is treated the same as an
        // absent key (falls through to "unknown"), matching the TS `||`
        // truthiness chain (`null` is falsy in JS too).
        let error_val = parsed
            .get("error")
            .filter(|v| !v.is_null())
            .or_else(|| parsed.get("Error").filter(|v| !v.is_null()));
        let error = match error_val {
            Some(Value::String(s)) => s.clone(),
            Some(other) => serde_json::to_string(other).unwrap_or_else(|_| "unknown".to_string()),
            None => "unknown".to_string(),
        };
        let message = parsed
            .get("message")
            .or_else(|| parsed.get("Message"))
            .or_else(|| parsed.get("reason"))
            .and_then(Value::as_str)
            .map(String::from);
        return Some(KiroStreamEvent::Error { error, message });
    }

    if parsed.get("usage").is_some() {
        return Some(KiroStreamEvent::Usage {
            input_tokens: parsed["usage"]["inputTokens"].as_u64(),
            output_tokens: parsed["usage"]["outputTokens"].as_u64(),
        });
    }

    None
}

/// Scan `buffer` for every complete Kiro stream event it contains.
///
/// Two behaviors that look similar but are NOT the same -- easy to
/// conflate, and pinned by separate tests below:
/// - No recognized event-start pattern found anywhere from the current
///   scan position onward: the rest of `buffer` is discarded (`remaining`
///   comes back `""`). Unrecognized trailing bytes never get handed back
///   to the caller.
/// - A recognized event-start pattern found, but its JSON is incomplete
///   (the buffer ends before brace depth returns to zero): everything
///   from that pattern's opening `{` onward is preserved in `remaining`
///   for the caller to prepend to the next chunk. Any garbage bytes
///   *before* that `{` are still discarded.
pub fn parse_kiro_events(buffer: &str) -> ParseResult {
    let mut events = Vec::new();
    let mut pos: usize = 0;

    loop {
        let Some(json_start) = find_next_event_start(buffer, pos) else {
            return ParseResult {
                events,
                remaining: String::new(),
            };
        };

        let Some(json_end) = find_json_end(buffer, json_start) else {
            return ParseResult {
                events,
                remaining: buffer[json_start..].to_string(),
            };
        };

        if let Ok(parsed) = serde_json::from_str::<Value>(&buffer[json_start..=json_end])
            && let Some(event) = parse_kiro_event(&parsed)
        {
            events.push(event);
        }
        // Brace-balanced but invalid JSON (a false-positive pattern match
        // inside binary framing) falls through silently -- no panic, no
        // error propagated, matching the TS's swallowed `catch`.

        pos = json_end + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- find_json_end -------------------------------------------------

    #[test]
    fn find_json_end_finds_end_of_simple_object() {
        assert_eq!(find_json_end(r#"{"content":"hello"}rest"#, 0), Some(18));
    }

    #[test]
    fn find_json_end_handles_nested_braces() {
        assert_eq!(find_json_end(r#"{"input":{"cmd":"ls"}}rest"#, 0), Some(21));
    }

    #[test]
    fn find_json_end_handles_escaped_quotes() {
        // Direct port of the TS test: the literal text contains real
        // backslash characters preceding the inner quotes.
        assert_eq!(
            find_json_end(r#"{"content":"say \"hi\""}rest"#, 0),
            Some(23)
        );
    }

    #[test]
    fn find_json_end_returns_none_for_incomplete_json() {
        assert_eq!(find_json_end(r#"{"content":"hel"#, 0), None);
    }

    #[test]
    fn find_json_end_respects_start_offset() {
        assert_eq!(find_json_end(r#"garbage{"content":"hi"}"#, 7), Some(22));
    }

    /// Discriminates the "escape_next unconditional" reading (ported from
    /// the TS's literal control flow) from a plausible-looking
    /// "escape_next only inside a string" reading. A backslash sitting
    /// outside any string, between the closing quote of a string value and
    /// the object's closing braces, arms escape_next and swallows the next
    /// char (the first `}`) entirely under the unconditional reading --
    /// so the scan doesn't see brace_count reach zero until the *second*
    /// `}`. Under the string-gated reading it would stop at the first.
    #[test]
    fn find_json_end_escape_next_is_armed_outside_strings_too() {
        let text = r#"{"content":"x"\}}"#;
        // Sanity: this is the layout the trace above assumes.
        assert_eq!(&text[14..15], "\\");
        assert_eq!(&text[15..16], "}");
        assert_eq!(&text[16..17], "}");
        assert_eq!(find_json_end(text, 0), Some(16));
    }

    // ---- parse_kiro_event ------------------------------------------------

    #[test]
    fn parse_kiro_event_dispatches_content() {
        assert_eq!(
            parse_kiro_event(&json!({"content": "Hello "})),
            Some(KiroStreamEvent::Content("Hello ".to_string()))
        );
    }

    #[test]
    fn parse_kiro_event_dispatches_tool_use_with_string_input_and_stop() {
        let event = parse_kiro_event(&json!({
            "name": "bash",
            "toolUseId": "tc1",
            "input": "{\"cmd\":\"ls\"}",
            "stop": true
        }));
        assert_eq!(
            event,
            Some(KiroStreamEvent::ToolUse {
                name: "bash".to_string(),
                tool_use_id: "tc1".to_string(),
                input: "{\"cmd\":\"ls\"}".to_string(),
                stop: Some(true),
            })
        );
    }

    /// A JSON-object (not string) `input` field must come back
    /// re-stringified, not as the raw object.
    #[test]
    fn parse_kiro_event_restringifies_object_input_for_tool_use() {
        let event = parse_kiro_event(&json!({
            "name": "bash",
            "toolUseId": "tc1",
            "input": {"cmd": "ls"}
        }));
        assert_eq!(
            event,
            Some(KiroStreamEvent::ToolUse {
                name: "bash".to_string(),
                tool_use_id: "tc1".to_string(),
                input: "{\"cmd\":\"ls\"}".to_string(),
                stop: None,
            })
        );
    }

    #[test]
    fn parse_kiro_event_empty_object_input_becomes_empty_string_for_tool_use() {
        let event = parse_kiro_event(&json!({
            "name": "write",
            "toolUseId": "tc1",
            "input": {}
        }));
        assert_eq!(
            event,
            Some(KiroStreamEvent::ToolUse {
                name: "write".to_string(),
                tool_use_id: "tc1".to_string(),
                input: String::new(),
                stop: None,
            })
        );
    }

    #[test]
    fn parse_kiro_event_dispatches_tool_use_input() {
        assert_eq!(
            parse_kiro_event(&json!({"input": "\"ls\"}"})),
            Some(KiroStreamEvent::ToolUseInput {
                input: "\"ls\"}".to_string()
            })
        );
    }

    /// Case-3 (`ToolUseInput`) normalization is unconditional
    /// re-stringification for non-string input -- unlike case-2
    /// (`ToolUse`), an empty object does NOT collapse to `""`. This is
    /// the discriminating test for that deliberate divergence; compare
    /// against `parse_kiro_event_empty_object_input_becomes_empty_string_for_tool_use`.
    #[test]
    fn parse_kiro_event_empty_object_input_is_restringified_for_tool_use_input() {
        assert_eq!(
            parse_kiro_event(&json!({"input": {}})),
            Some(KiroStreamEvent::ToolUseInput {
                input: "{}".to_string()
            })
        );
    }

    #[test]
    fn parse_kiro_event_dispatches_tool_use_stop() {
        assert_eq!(
            parse_kiro_event(&json!({"stop": true})),
            Some(KiroStreamEvent::ToolUseStop { stop: true })
        );
    }

    #[test]
    fn parse_kiro_event_dispatches_context_usage() {
        assert_eq!(
            parse_kiro_event(&json!({"contextUsagePercentage": 42.5})),
            Some(KiroStreamEvent::ContextUsage {
                context_usage_percentage: 42.5
            })
        );
    }

    /// `stop` co-occurring with `contextUsagePercentage` must dispatch to
    /// `ContextUsage` (priority rule 5), not `ToolUseStop` (priority rule
    /// 4 is explicitly gated on `contextUsagePercentage` being absent).
    #[test]
    fn parse_kiro_event_context_usage_wins_priority_over_tool_use_stop() {
        let event = parse_kiro_event(&json!({
            "stop": true,
            "contextUsagePercentage": 45.2
        }));
        assert_eq!(
            event,
            Some(KiroStreamEvent::ContextUsage {
                context_usage_percentage: 45.2
            })
        );
    }

    #[test]
    fn parse_kiro_event_dispatches_followup_prompt() {
        assert_eq!(
            parse_kiro_event(&json!({"followupPrompt": "What next?"})),
            Some(KiroStreamEvent::FollowupPrompt("What next?".to_string()))
        );
    }

    #[test]
    fn parse_kiro_event_dispatches_usage() {
        assert_eq!(
            parse_kiro_event(&json!({"usage": {"inputTokens": 100, "outputTokens": 50}})),
            Some(KiroStreamEvent::Usage {
                input_tokens: Some(100),
                output_tokens: Some(50),
            })
        );
    }

    #[test]
    fn parse_kiro_event_dispatches_error_with_string_error_and_message() {
        let event = parse_kiro_event(&json!({
            "error": "boom",
            "message": "details"
        }));
        assert_eq!(
            event,
            Some(KiroStreamEvent::Error {
                error: "boom".to_string(),
                message: Some("details".to_string()),
            })
        );
    }

    #[test]
    fn parse_kiro_event_error_falls_back_to_capital_error_key_and_reason() {
        let event = parse_kiro_event(&json!({
            "Error": "capitalized",
            "reason": "why"
        }));
        assert_eq!(
            event,
            Some(KiroStreamEvent::Error {
                error: "capitalized".to_string(),
                message: Some("why".to_string()),
            })
        );
    }

    #[test]
    fn parse_kiro_event_error_defaults_to_unknown_when_value_is_null() {
        let event = parse_kiro_event(&json!({"error": null}));
        assert_eq!(
            event,
            Some(KiroStreamEvent::Error {
                error: "unknown".to_string(),
                message: None,
            })
        );
    }

    #[test]
    fn parse_kiro_event_returns_none_for_unrecognized_shape() {
        assert_eq!(parse_kiro_event(&json!({"unknown": true})), None);
    }

    // ---- parse_kiro_events -----------------------------------------------

    #[test]
    fn parse_kiro_events_single_complete_event() {
        let result = parse_kiro_events(r#"{"content":"hello"}"#);
        assert_eq!(
            result.events,
            vec![KiroStreamEvent::Content("hello".to_string())]
        );
        assert_eq!(result.remaining, "");
    }

    #[test]
    fn parse_kiro_events_two_back_to_back_events_parsed_in_order() {
        let result = parse_kiro_events(r#"{"content":"a"}{"content":"b"}"#);
        assert_eq!(
            result.events,
            vec![
                KiroStreamEvent::Content("a".to_string()),
                KiroStreamEvent::Content("b".to_string()),
            ]
        );
        assert_eq!(result.remaining, "");
    }

    #[test]
    fn parse_kiro_events_mid_event_truncation_preserves_partial_fragment() {
        let buffer = r#"{"content":"unfinis"#;
        let result = parse_kiro_events(buffer);
        assert_eq!(result.events, vec![]);
        assert_eq!(result.remaining, buffer);
    }

    /// Garbage bytes before a recognized pattern (simulating AWS binary
    /// framing noise, including a stray `{"` that never completes into a
    /// real pattern match) are silently skipped -- not returned as
    /// `remaining`, not treated as an error.
    #[test]
    fn parse_kiro_events_skips_garbage_before_recognized_pattern() {
        let buffer = format!("\x00\x01{{\"conte{}", r#"{"content":"ok"}"#);
        let result = parse_kiro_events(&buffer);
        assert_eq!(
            result.events,
            vec![KiroStreamEvent::Content("ok".to_string())]
        );
        assert_eq!(result.remaining, "");
    }

    #[test]
    fn parse_kiro_events_tool_use_object_input_is_restringified() {
        let buffer = r#"{"name":"bash","toolUseId":"tc1","input":{"cmd":"ls"}}"#;
        let result = parse_kiro_events(buffer);
        assert_eq!(
            result.events,
            vec![KiroStreamEvent::ToolUse {
                name: "bash".to_string(),
                tool_use_id: "tc1".to_string(),
                input: "{\"cmd\":\"ls\"}".to_string(),
                stop: None,
            }]
        );
    }

    /// An event matching a pattern but containing invalid JSON inside the
    /// balanced braces is silently skipped -- no panic, no bogus event.
    #[test]
    fn parse_kiro_events_skips_invalid_json_inside_balanced_braces() {
        let result = parse_kiro_events(r#"{"content":,}"#);
        assert_eq!(result.events, vec![]);
        assert_eq!(result.remaining, "");
    }

    #[test]
    fn parse_kiro_events_stop_and_context_usage_dispatches_to_context_usage() {
        let result = parse_kiro_events(r#"{"stop":true,"contextUsagePercentage":45.2}"#);
        assert_eq!(
            result.events,
            vec![KiroStreamEvent::ContextUsage {
                context_usage_percentage: 45.2
            }]
        );
    }

    /// Multi-byte UTF-8 characters straddling `find_json_end`'s scan must
    /// not panic and must extract correctly -- the one place this port's
    /// byte-indexing model diverges from the TS original's UTF-16
    /// assumption.
    #[test]
    fn parse_kiro_events_handles_multibyte_utf8_content_without_panicking() {
        let buffer = r#"{"content":"café ☕"}"#;
        let result = parse_kiro_events(buffer);
        assert_eq!(
            result.events,
            vec![KiroStreamEvent::Content("café ☕".to_string())]
        );
        assert_eq!(result.remaining, "");
    }

    /// Same UTF-8 boundary concern, but for a chunk that truncates
    /// mid-multibyte-character: must return the incomplete-JSON path
    /// (`remaining` preserved) rather than panicking on a non-boundary
    /// slice.
    #[test]
    fn parse_kiro_events_handles_multibyte_utf8_truncated_mid_event_without_panicking() {
        let buffer = r#"{"content":"café"#;
        let result = parse_kiro_events(buffer);
        assert_eq!(result.events, vec![]);
        assert_eq!(result.remaining, buffer);
    }

    /// Patterns are anchored at the object's start: a known key that is
    /// NOT the first key in the object (so `{"content":` never appears
    /// literally) means the event is never found at all -- zero events,
    /// not a partial match.
    #[test]
    fn parse_kiro_events_skips_events_where_known_key_is_not_first_key() {
        let result = parse_kiro_events(r#"{"timestamp":123,"content":"hello"}"#);
        assert_eq!(result.events, vec![]);
        assert_eq!(result.remaining, "");
    }

    #[test]
    fn parse_kiro_events_stop_event_when_tool_use_id_is_first_key() {
        let result = parse_kiro_events(r#"{"toolUseId":"tc1","stop":true}"#);
        assert_eq!(
            result.events,
            vec![KiroStreamEvent::ToolUseStop { stop: true }]
        );
    }

    #[test]
    fn parse_kiro_events_empty_buffer_returns_empty_result() {
        let result = parse_kiro_events("");
        assert_eq!(result.events, vec![]);
        assert_eq!(result.remaining, "");
    }

    // ---- discard-vs-preserve: the two behaviors the brief flags as easy
    // to conflate, pinned side by side. ------------------------------------

    /// No recognized event-start pattern ANYWHERE in the buffer: all bytes
    /// are discarded. `remaining` is empty, not the leftover garbage.
    #[test]
    fn parse_kiro_events_pure_garbage_buffer_is_entirely_discarded() {
        let result = parse_kiro_events("no patterns here");
        assert_eq!(result.events, vec![]);
        assert_eq!(result.remaining, "");
    }

    /// Garbage bytes FOLLOWED BY a recognized-but-incomplete event: the
    /// garbage prefix is discarded (not part of `remaining`), but
    /// everything from the recognized pattern's opening `{` onward IS
    /// preserved in `remaining` for the next chunk. This is the case that
    /// distinguishes "discard" from "preserve" -- both behaviors fire
    /// within the same call, on different halves of the same buffer.
    #[test]
    fn parse_kiro_events_discards_leading_garbage_but_preserves_incomplete_event_tail() {
        let result = parse_kiro_events("xx{\"content\":\"unfinis");
        assert_eq!(result.events, vec![]);
        assert_eq!(result.remaining, "{\"content\":\"unfinis");
    }
}
