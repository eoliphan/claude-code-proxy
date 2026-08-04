//! Incremental `<thinking>`-tag state machine for Kiro streaming content.
//!
//! Kiro streams a single flat text channel that embeds its chain-of-thought
//! inside one of four recognized tag-pair variants
//! (`<thinking>...</thinking>`, `<think>...</think>`,
//! `<reasoning>...</reasoning>`, `<thought>...</thought>`), with ordinary
//! response text interleaved around it, and the tag delimiters themselves
//! can land split across arbitrary chunk boundaries. This module is a port
//! of the `pi-provider-kiro` reference implementation's
//! `src/thinking-parser.ts` (read directly at implementation time from
//! `/home/erich.oliphant/IdeaProjects/pi-provider-kiro/src/thinking-parser.ts`,
//! cross-checked against `test/thinking-parser.test.ts` in the same repo).
//!
//! This port deliberately drops the TS original's `output.content`
//! array/index bookkeeping (the `thinkingBlockIndex` / `textBlockIndex` /
//! `lastTextBlockIndex` fields and the `output.content.splice(...)` call
//! that reorders an already-emitted text block behind a later-discovered
//! thinking block): [`ThinkingStreamEvent`] carries no content-block index
//! at all, so there is nothing here to splice or renumber. A later task,
//! which routes these events into Anthropic SSE `content_block_*` frames,
//! owns index assignment and is responsible for presenting thinking before
//! text even when text was detected first chronologically (an observed
//! Kiro quirk); this module only guarantees that it emits events in the
//! order it detects them and never drops content.
//!
//! Two places where the actual `.ts` source diverges from what a looser
//! prose description of it would suggest -- both verified directly against
//! the source, not reconstructed from memory:
//!
//! - [`ThinkingTagParser::finalize`] does NOT flush a still-open thinking
//!   block as `ThinkingDelta` + `ThinkingStop` merely because `in_thinking`
//!   is true. The TS source's guard is
//!   `this.inThinking && this.thinkingBlockIndex !== null` (source lines
//!   74-88) -- it additionally requires that *some* thinking content was
//!   already emitted (i.e. at least one prior non-empty `ThinkingDelta`,
//!   which is what first sets `thinkingBlockIndex`). If a stream ends with
//!   `in_thinking` true but zero thinking content ever emitted -- e.g. the
//!   entire leftover buffer was held back as an ambiguous close-tag prefix
//!   that never resolved before the stream ended -- the leftover is
//!   flushed as **plain text**, not thinking. This port tracks the same
//!   condition via `thinking_started` (this module's name for "was
//!   `ThinkingStart` ever pushed"); see
//!   `finalize_unterminated_thinking_with_no_content_emits_as_text` below.
//! - The "longest possible tag prefix at the end of the buffer" check
//!   ([`trailing_possible_tag_prefix_len`]) is implemented here with plain
//!   byte lengths (`str::len`, `str::ends_with`, `str::find`), not an
//!   explicit `char_indices()` walk, despite every tag literal being
//!   compared against a buffer that may contain multi-byte characters
//!   earlier in it. This is safe -- not merely convenient -- because every
//!   tag literal is pure ASCII: an ASCII byte (< 0x80) can never be a UTF-8
//!   continuation byte, so whenever `text.ends_with(ascii_pattern)`
//!   succeeds, the byte offset immediately before the matched suffix is,
//!   by construction, always a valid `char` boundary. `str::find` and
//!   `str::ends_with` (and the slices built from their results) are
//!   therefore panic-safe here even though the *preceding* buffer content
//!   may contain multi-byte characters -- see
//!   `multibyte_utf8_content_at_ambiguous_prefix_boundary_does_not_panic`
//!   below for the discriminating test.

/// One event extracted from the incremental `<thinking>`-tag scan. Carries
/// no content-block index -- a later task owns Anthropic content-block
/// index assignment and ordering correction; see the module doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThinkingStreamEvent {
    TextStart,
    TextDelta(String),
    TextStop,
    ThinkingStart,
    ThinkingDelta(String),
    ThinkingStop,
}

/// Recognized `<open>`/`</close>` tag-pair variants, in priority order for
/// tie-breaking when more than one open tag starts at the same buffer
/// offset (never actually possible for these four literals, but this order
/// is also the iteration order used to find the *earliest* match, so it is
/// preserved to match the TS source's `for (const variant of
/// THINKING_TAG_VARIANTS)` scan order exactly).
const TAG_VARIANTS: [(&str, &str); 4] = [
    ("<thinking>", "</thinking>"),
    ("<think>", "</think>"),
    ("<reasoning>", "</reasoning>"),
    ("<thought>", "</thought>"),
];

/// Length of the longest suffix of `text` that equals a prefix of `tag`,
/// capped at `tag.len() - 1` (a full-tag match is found separately via
/// `str::find`, so this function only ever needs to detect a *partial*,
/// still-ambiguous tag at the very end of the buffer). Safe against
/// multi-byte content in `text` -- see the module doc comment.
fn trailing_possible_tag_prefix_len(text: &str, tag: &str) -> usize {
    let max_len = text.len().min(tag.len() - 1);
    for len in (1..=max_len).rev() {
        if text.ends_with(&tag[..len]) {
            return len;
        }
    }
    0
}

/// Max of [`trailing_possible_tag_prefix_len`] across every candidate tag.
fn max_trailing_possible_tag_prefix_len(text: &str, tags: &[&str]) -> usize {
    tags.iter()
        .map(|tag| trailing_possible_tag_prefix_len(text, tag))
        .max()
        .unwrap_or(0)
}

/// Stateful, incremental parser that separates `<thinking>`-tagged content
/// from ordinary text across an arbitrary sequence of `process_chunk`
/// calls, tolerating tag delimiters split across chunk boundaries in any
/// position. See the module doc comment for the full port notes.
pub struct ThinkingTagParser {
    text_buffer: String,
    in_thinking: bool,
    thinking_extracted: bool,
    active_end_tag: &'static str,
    /// Whether `ThinkingStart` has been pushed yet (this port's stand-in
    /// for the TS source's `thinkingBlockIndex !== null`). Monotonic: at
    /// most one thinking block is ever extracted per parser instance.
    thinking_started: bool,
    /// Whether `TextStart` has been pushed yet for the CURRENT text block
    /// (this port's stand-in for the TS source's `textBlockIndex !== null`).
    /// Reset to `false` when a thinking block closes (mirrors the TS
    /// source's `this.textBlockIndex = null;`, source line 145), so text
    /// arriving after a thinking block always gets a fresh `TextStart` --
    /// even if a text block was already open before the thinking block
    /// started. This port has no content-block array to splice/reindex
    /// like the TS source does, but the observable event-stream behavior
    /// (a new `TextStart` after every `ThinkingStop`) is preserved exactly.
    text_started: bool,
}

impl Default for ThinkingTagParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ThinkingTagParser {
    pub fn new() -> Self {
        Self {
            text_buffer: String::new(),
            in_thinking: false,
            thinking_extracted: false,
            active_end_tag: "</thinking>",
            thinking_started: false,
            text_started: false,
        }
    }

    /// Feed `chunk` into the parser and return every event this call
    /// resolves. Text/thinking content that turns out to be an ambiguous
    /// tag-prefix at the end of the buffer is held back for the next call.
    pub fn process_chunk(&mut self, chunk: &str) -> Vec<ThinkingStreamEvent> {
        self.text_buffer.push_str(chunk);
        let mut events = Vec::new();

        while !self.text_buffer.is_empty() {
            let prev_len = self.text_buffer.len();

            if !self.in_thinking && !self.thinking_extracted {
                self.process_before_thinking(&mut events);
                if self.text_buffer.is_empty() {
                    break;
                }
            }
            if self.in_thinking {
                self.process_inside_thinking(&mut events);
                if self.text_buffer.is_empty() {
                    break;
                }
            }
            if self.thinking_extracted {
                self.process_after_thinking(&mut events);
                break;
            }
            if self.text_buffer.len() >= prev_len {
                // Nothing more can be resolved from the current buffer
                // contents (the remainder is an ambiguous tag prefix held
                // back for the next chunk) -- stop to avoid looping
                // forever.
                break;
            }
        }

        events
    }

    /// Flush whatever remains buffered at end-of-stream. See the module
    /// doc comment for the exact (source-verified) classification rule.
    pub fn finalize(&mut self) -> Vec<ThinkingStreamEvent> {
        let mut events = Vec::new();
        if self.text_buffer.is_empty() {
            return events;
        }

        let remaining = std::mem::take(&mut self.text_buffer);
        if self.in_thinking && self.thinking_started {
            self.emit_thinking(&remaining, &mut events);
            events.push(ThinkingStreamEvent::ThinkingStop);
        } else {
            self.emit_text(&remaining, &mut events);
        }
        events
    }

    /// Search for the earliest occurrence of any recognized open tag. On a
    /// match, emit everything before it as text and enter thinking mode. On
    /// no match, emit everything except a possible in-progress open-tag
    /// prefix at the end of the buffer, holding that prefix back.
    fn process_before_thinking(&mut self, events: &mut Vec<ThinkingStreamEvent>) {
        let mut best: Option<(usize, &'static str, &'static str)> = None;
        for &(open, close) in &TAG_VARIANTS {
            if let Some(pos) = self.text_buffer.find(open) {
                let is_earlier = match best {
                    None => true,
                    Some((best_pos, _, _)) => pos < best_pos,
                };
                if is_earlier {
                    best = Some((pos, open, close));
                }
            }
        }

        if let Some((pos, open, close)) = best {
            if pos > 0 {
                let text = self.text_buffer[..pos].to_string();
                self.emit_text(&text, events);
            }
            self.text_buffer = self.text_buffer[pos + open.len()..].to_string();
            self.active_end_tag = close;
            self.in_thinking = true;
            return;
        }

        let open_tags: Vec<&str> = TAG_VARIANTS.iter().map(|(open, _)| *open).collect();
        let trailing_len = max_trailing_possible_tag_prefix_len(&self.text_buffer, &open_tags);
        let safe_len = self.text_buffer.len() - trailing_len;
        if safe_len > 0 {
            let text = self.text_buffer[..safe_len].to_string();
            self.emit_text(&text, events);
            self.text_buffer = self.text_buffer[safe_len..].to_string();
        }
    }

    /// Search for the single currently-active close tag. On a match, emit
    /// everything before it as thinking, close the thinking block, and
    /// swallow a conventional `"\n\n"` separator if present. On no match,
    /// same partial-tag-suffix handling as `process_before_thinking`, but
    /// against only the one active close tag.
    fn process_inside_thinking(&mut self, events: &mut Vec<ThinkingStreamEvent>) {
        if let Some(end_pos) = self.text_buffer.find(self.active_end_tag) {
            if end_pos > 0 {
                let thinking = self.text_buffer[..end_pos].to_string();
                self.emit_thinking(&thinking, events);
            }
            if self.thinking_started {
                events.push(ThinkingStreamEvent::ThinkingStop);
            }
            self.text_buffer = self.text_buffer[end_pos + self.active_end_tag.len()..].to_string();
            self.in_thinking = false;
            self.thinking_extracted = true;
            // Mirrors the TS source's `this.textBlockIndex = null;` (line
            // 145 of thinking-parser.ts), which runs unconditionally at
            // this point regardless of whether a text block was already
            // open. Any text that arrives from here on -- even if a text
            // block was already open before this thinking block started --
            // gets a fresh `TextStart` rather than being silently folded
            // into the earlier block. This is not an edge case: Kiro
            // routinely sends text before thinking
            // (`text_then_thinking_then_text_emits_a_new_text_block`
            // below), and upstream's own test suite documents exactly this
            // shape as ordinary observed behavior, not adversarial input.
            self.text_started = false;
            if let Some(rest) = self.text_buffer.strip_prefix("\n\n") {
                self.text_buffer = rest.to_string();
            }
            return;
        }

        let trailing_len = trailing_possible_tag_prefix_len(&self.text_buffer, self.active_end_tag);
        let safe_len = self.text_buffer.len() - trailing_len;
        if safe_len > 0 {
            let thinking = self.text_buffer[..safe_len].to_string();
            self.emit_thinking(&thinking, events);
            self.text_buffer = self.text_buffer[safe_len..].to_string();
        }
    }

    /// Once thinking has been fully extracted, every subsequent byte is
    /// unconditionally plain text.
    fn process_after_thinking(&mut self, events: &mut Vec<ThinkingStreamEvent>) {
        let text = std::mem::take(&mut self.text_buffer);
        self.emit_text(&text, events);
    }

    fn emit_text(&mut self, text: &str, events: &mut Vec<ThinkingStreamEvent>) {
        if text.is_empty() {
            return;
        }
        if !self.text_started {
            self.text_started = true;
            events.push(ThinkingStreamEvent::TextStart);
        }
        events.push(ThinkingStreamEvent::TextDelta(text.to_string()));
    }

    fn emit_thinking(&mut self, thinking: &str, events: &mut Vec<ThinkingStreamEvent>) {
        if thinking.is_empty() {
            return;
        }
        if !self.thinking_started {
            self.thinking_started = true;
            events.push(ThinkingStreamEvent::ThinkingStart);
        }
        events.push(ThinkingStreamEvent::ThinkingDelta(thinking.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ThinkingStreamEvent::*;

    /// Feeds `full` to a fresh parser in one `process_chunk` call, then
    /// `finalize()`s it, returning the combined event stream. Used as the
    /// single-call baseline that chunked variants are checked against.
    fn run_single_call(full: &str) -> Vec<ThinkingStreamEvent> {
        let mut parser = ThinkingTagParser::new();
        let mut events = parser.process_chunk(full);
        events.extend(parser.finalize());
        events
    }

    /// Feeds `full` to a fresh parser split across `chunks` (which must
    /// concatenate back to `full`), then `finalize()`s it.
    fn run_chunked(chunks: &[&str]) -> Vec<ThinkingStreamEvent> {
        let mut parser = ThinkingTagParser::new();
        let mut events = Vec::new();
        for chunk in chunks {
            events.extend(parser.process_chunk(chunk));
        }
        events.extend(parser.finalize());
        events
    }

    /// Collapses consecutive `TextDelta`/`ThinkingDelta` runs into one
    /// merged delta each, leaving every other event untouched and in
    /// place. Used to compare a heavily-fragmented chunked run against a
    /// single-call baseline without requiring identical delta-chunking
    /// granularity -- the property that actually matters for a streaming
    /// consumer is total content + block lifecycle order, not exactly
    /// where each delta was cut.
    fn normalize(events: &[ThinkingStreamEvent]) -> Vec<ThinkingStreamEvent> {
        let mut out: Vec<ThinkingStreamEvent> = Vec::new();
        for event in events {
            match (out.last_mut(), event) {
                (Some(TextDelta(acc)), TextDelta(s)) => acc.push_str(s),
                (Some(ThinkingDelta(acc)), ThinkingDelta(s)) => acc.push_str(s),
                _ => out.push(event.clone()),
            }
        }
        out
    }

    // ---- 1. plain text, no tags at all ------------------------------------

    #[test]
    fn plain_text_with_no_tags_emits_only_text_events() {
        let events = run_single_call("Just plain text, no tags at all.");
        assert_eq!(
            events,
            vec![
                TextStart,
                TextDelta("Just plain text, no tags at all.".to_string()),
            ]
        );
    }

    // ---- 2. complete thinking-then-text in one call ------------------------

    #[test]
    fn complete_thinking_then_text_in_one_call() {
        let events = run_single_call("<thinking>reasoning here</thinking>\n\nfinal answer");
        assert_eq!(
            events,
            vec![
                ThinkingStart,
                ThinkingDelta("reasoning here".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("final answer".to_string()),
            ]
        );
    }

    // ---- 3. the same content split across many small chunks ----------------

    /// The critical incremental-correctness test: the exact split the brief
    /// calls out (one chunk ending in `<thi`, the next starting with
    /// `nking>`) must produce a byte-for-byte identical event vector to the
    /// single-call case. This holds here (not just approximately) because
    /// this particular split point lands entirely within an *ambiguous* tag
    /// prefix, which the state machine holds back in full rather than
    /// partially flushing -- so by the time the second chunk arrives, the
    /// buffer is byte-identical to what the single-call case ever saw.
    #[test]
    fn split_mid_open_tag_produces_identical_events_to_single_call() {
        let full = "<thinking>reasoning here</thinking>\n\nfinal answer";
        let baseline = run_single_call(full);
        let chunked = run_chunked(&["<thi", "nking>reasoning here</thinking>\n\nfinal answer"]);
        assert_eq!(chunked, baseline);
    }

    /// Same content, split mid *close* tag this time.
    #[test]
    fn split_mid_close_tag_produces_identical_events_to_single_call() {
        let full = "<thinking>reasoning here</thinking>\n\nfinal answer";
        let baseline = run_single_call(full);
        let chunked = run_chunked(&["<thinking>reasoning here</thi", "nking>\n\nfinal answer"]);
        assert_eq!(chunked, baseline);
    }

    /// Extreme fragmentation: the full content fed one `char` at a time,
    /// covering every possible split position (including several that land
    /// mid-content, not just mid-tag). Delta chunking granularity legitimately
    /// differs from the single-call baseline here, so events are compared
    /// after `normalize`-ing consecutive same-kind deltas together -- what
    /// must be identical is total content and block lifecycle order, which
    /// is exactly the property a downstream SSE consumer depends on.
    ///
    /// Deliberately uses a thinking/text transition with NO `"\n\n"`
    /// separator between the blocks, to isolate this test's actual subject
    /// (fragmentation-tolerant tag detection) from the source-verified
    /// `"\n\n"`-swallowing limitation covered separately by
    /// `newline_separator_split_across_chunk_boundary_leaks_into_text`
    /// below -- one-char-at-a-time chunking always splits a 2-char
    /// separator, so folding that case in here would conflate two
    /// different behaviors under one assertion.
    #[test]
    fn split_one_char_at_a_time_matches_single_call_after_normalizing_deltas() {
        let full = "<thinking>reasoning here</thinking>final answer";
        let baseline = normalize(&run_single_call(full));

        let char_chunks: Vec<&str> = full
            .char_indices()
            .map(|(i, c)| &full[i..i + c.len_utf8()])
            .collect();
        let chunked = normalize(&run_chunked(&char_chunks));

        assert_eq!(chunked, baseline);
        assert_eq!(
            baseline,
            vec![
                ThinkingStart,
                ThinkingDelta("reasoning here".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("final answer".to_string()),
            ]
        );
    }

    /// Source-verified quirk, not a bug in this port: the TS source's
    /// `"\n\n"`-after-close-tag swallow (`processInsideThinking`, the final
    /// `if (this.textBuffer.startsWith("\n\n")) ...` line) is a one-shot
    /// check performed exactly once, at the instant the close tag is
    /// matched. If a chunk boundary splits the two-character separator
    /// itself (one newline arrives in the chunk that closes the thinking
    /// block, the second in the next chunk), only the first newline is
    /// present at check time, the check fails, and `thinkingExtracted`
    /// latches permanently true -- so the second newline is never re-
    /// checked and both newlines leak into the text content as literal
    /// characters instead of being swallowed. A single-call baseline with
    /// the same content does not exhibit this (both newlines are already
    /// buffered together at check time). This test locks in that real,
    /// faithfully-ported divergence rather than papering over it.
    #[test]
    fn newline_separator_split_across_chunk_boundary_leaks_into_text() {
        let single_call = run_single_call("<thinking>reasoning here</thinking>\n\nfinal answer");
        assert_eq!(
            single_call,
            vec![
                ThinkingStart,
                ThinkingDelta("reasoning here".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("final answer".to_string()),
            ]
        );

        let split_on_separator =
            run_chunked(&["<thinking>reasoning here</thinking>\n", "\nfinal answer"]);
        assert_eq!(
            split_on_separator,
            vec![
                ThinkingStart,
                ThinkingDelta("reasoning here".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("\n".to_string()),
                TextDelta("\nfinal answer".to_string()),
            ]
        );
        assert_ne!(normalize(&split_on_separator), normalize(&single_call));
    }

    // ---- 4. short `<think>` variant ----------------------------------------

    #[test]
    fn short_think_variant_behaves_like_thinking_variant() {
        let events = run_single_call("<think>brief thought</think>\n\nOK");
        assert_eq!(
            events,
            vec![
                ThinkingStart,
                ThinkingDelta("brief thought".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("OK".to_string()),
            ]
        );
    }

    #[test]
    fn short_think_variant_split_across_chunks_matches_single_call() {
        let full = "<think>brief thought</think>\n\nOK";
        let baseline = run_single_call(full);
        let chunked = run_chunked(&["<thi", "nk>brief thought</th", "ink>\n\nOK"]);
        assert_eq!(chunked, baseline);
    }

    #[test]
    fn reasoning_and_thought_variants_are_recognized() {
        let reasoning = run_single_call("<reasoning>step by step</reasoning>\n\nResult");
        assert_eq!(
            reasoning,
            vec![
                ThinkingStart,
                ThinkingDelta("step by step".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("Result".to_string()),
            ]
        );

        let thought = run_single_call("<thought>hmm</thought>\n\nDone");
        assert_eq!(
            thought,
            vec![
                ThinkingStart,
                ThinkingDelta("hmm".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("Done".to_string()),
            ]
        );
    }

    // ---- 5. unterminated thinking at stream end, via finalize() ------------

    /// The stream ends mid-thinking with no closing tag ever arriving. The
    /// second chunk truncates in the middle of what *could* be a close tag
    /// (`</thi`), so that fragment is held back as ambiguous rather than
    /// flushed during `process_chunk` -- exercising the actual "leftover
    /// buffer at finalize time" path, not a case that would have already
    /// self-resolved before `finalize()` is even called.
    #[test]
    fn finalize_flushes_unterminated_thinking_as_forced_stop() {
        let mut parser = ThinkingTagParser::new();
        let mut events = parser.process_chunk("<thinking>some reasoning");
        assert_eq!(
            events,
            vec![ThinkingStart, ThinkingDelta("some reasoning".to_string())]
        );

        let mid_close_tag_events = parser.process_chunk("</thi");
        assert_eq!(mid_close_tag_events, vec![]);

        events.extend(parser.finalize());
        assert_eq!(
            events,
            vec![
                ThinkingStart,
                ThinkingDelta("some reasoning".to_string()),
                ThinkingDelta("</thi".to_string()),
                ThinkingStop,
            ]
        );
    }

    /// The *common* shape of "unterminated thinking at stream end" -- content
    /// that does NOT happen to end in an ambiguous close-tag-prefix
    /// character -- is handled differently than the previous test's
    /// engineered case: everything gets flushed as `ThinkingDelta` already
    /// during `process_chunk` (the trailing-prefix check finds nothing
    /// ambiguous to hold back), so the buffer is already empty by the time
    /// `finalize()` runs, and `finalize()`'s early return on an empty buffer
    /// means NO `ThinkingStop` is ever emitted at all. This is faithful to
    /// the TS source (`finalize(): if (this.textBuffer.length === 0)
    /// return;`), but it means a `ThinkingStream` consumer cannot assume
    /// every `ThinkingStart` is eventually followed by a `ThinkingStop` from
    /// this parser alone -- a downstream consumer must be prepared to
    /// force-close a still-open thinking block itself if the underlying
    /// stream simply ends. See the module doc comment / task report for the
    /// hand-off implication.
    #[test]
    fn unterminated_thinking_with_no_ambiguous_tail_emits_no_stop_at_all() {
        let mut parser = ThinkingTagParser::new();
        let mut events = parser.process_chunk("<thinking>some reasoning");
        events.extend(parser.finalize());
        assert_eq!(
            events,
            vec![ThinkingStart, ThinkingDelta("some reasoning".to_string())]
        );
    }

    /// Source-verified divergence from a naive prose reading: if the stream
    /// ends `in_thinking` but NO thinking content was ever actually emitted
    /// (the whole thinking-mode buffer was, at every point, an ambiguous
    /// close-tag prefix), the TS source's guard
    /// (`this.inThinking && this.thinkingBlockIndex !== null`) fails and the
    /// leftover is flushed as plain text instead -- not as thinking. `"<"` is
    /// a valid 1-char prefix of `"</thinking>"` (which itself starts with
    /// `<`), so it is held back rather than flushed the moment thinking mode
    /// is entered.
    #[test]
    fn finalize_unterminated_thinking_with_no_content_emits_as_text() {
        let mut parser = ThinkingTagParser::new();
        let entry_events = parser.process_chunk("<thinking><");
        assert_eq!(entry_events, vec![]);

        let events = parser.finalize();
        assert_eq!(events, vec![TextStart, TextDelta("<".to_string())]);
    }

    // ---- 6. pending plain text at stream end, via finalize() ---------------

    /// The trailing `<th` looks like it could be starting a thinking tag, so
    /// it is held back by `process_chunk` and only resolved (as plain text,
    /// since no thinking tag ever followed) by `finalize()`.
    #[test]
    fn finalize_flushes_pending_plain_text() {
        let mut parser = ThinkingTagParser::new();
        let events = parser.process_chunk("Hello <th");
        assert_eq!(events, vec![TextStart, TextDelta("Hello ".to_string())]);

        let final_events = parser.finalize();
        assert_eq!(final_events, vec![TextDelta("<th".to_string())]);
    }

    #[test]
    fn finalize_on_empty_buffer_emits_nothing() {
        let mut parser = ThinkingTagParser::new();
        assert_eq!(
            parser.process_chunk("hello"),
            vec![TextStart, TextDelta("hello".to_string())]
        );
        assert_eq!(parser.finalize(), Vec::<ThinkingStreamEvent>::new());
    }

    // ---- 7. multi-byte UTF-8 content at a chunk boundary --------------------

    /// A multi-byte character sits immediately before an ambiguous
    /// open-tag-prefix suffix that gets held back across a chunk boundary.
    /// Must not panic on a non-char-boundary slice, and must preserve the
    /// multi-byte content exactly. The text after the thinking block gets
    /// its own fresh `TextStart` (a separate text block from the one
    /// before `<thinking>`) -- see
    /// `text_then_thinking_then_text_emits_a_new_text_block` for why.
    #[test]
    fn multibyte_utf8_content_at_ambiguous_prefix_boundary_does_not_panic() {
        let mut parser = ThinkingTagParser::new();
        let events = parser.process_chunk("café \u{2615} <th");
        assert_eq!(
            events,
            vec![TextStart, TextDelta("café \u{2615} ".to_string())]
        );

        let events = parser.process_chunk("inking>steam rising</thinking>\n\n\u{2615} done");
        assert_eq!(
            events,
            vec![
                ThinkingStart,
                ThinkingDelta("steam rising".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("\u{2615} done".to_string()),
            ]
        );
    }

    /// Same concern, but for the close-tag ambiguous-suffix path
    /// (`process_inside_thinking`) instead of the open-tag path.
    #[test]
    fn multibyte_utf8_content_inside_thinking_at_ambiguous_suffix_boundary_does_not_panic() {
        let mut parser = ThinkingTagParser::new();
        let events = parser.process_chunk("<thinking>caf\u{e9} \u{2615} </thi");
        assert_eq!(
            events,
            vec![
                ThinkingStart,
                ThinkingDelta("caf\u{e9} \u{2615} ".to_string())
            ]
        );

        let events = parser.process_chunk("nking>\n\ndone");
        assert_eq!(
            events,
            vec![ThinkingStop, TextStart, TextDelta("done".to_string())]
        );
    }

    // ---- text-before-thinking ordering: emission order is chronological ----

    /// This module makes no attempt to reorder events: if text was already
    /// emitted before a thinking block is later detected, the events simply
    /// appear in the order they were detected (text first, then thinking).
    /// A later task is responsible for correcting Anthropic content-block
    /// ordering; see the module doc comment.
    #[test]
    fn text_before_thinking_emits_in_chronological_detection_order() {
        let mut parser = ThinkingTagParser::new();
        let mut events = parser.process_chunk("Hello world");
        events.extend(parser.process_chunk("<thinking>reasoning</thinking>"));
        events.extend(parser.finalize());

        assert_eq!(
            events,
            vec![
                TextStart,
                TextDelta("Hello world".to_string()),
                ThinkingStart,
                ThinkingDelta("reasoning".to_string()),
                ThinkingStop,
            ]
        );
    }

    /// Regression test for a real divergence caught in review (not an
    /// intentional simplification): after a thinking block closes, the TS
    /// source resets `textBlockIndex = null` (source line 145) even if a
    /// text block was already open before the thinking block started, so
    /// text arriving after `thinking_end` always gets a brand-new
    /// `text_start`. Confirmed by running the actual TS reference
    /// (`ThinkingTagParser` from `thinking-parser.ts`) against
    /// `["Hello ", "<thinking>t</thinking>", "more"]`, which emits
    /// `text_start(0) ... thinking_end(0) text_start(2)
    /// text_delta(2)="more"` -- a second `text_start`, not a bare
    /// continuation delta. This shape is not an edge case: upstream's own
    /// test suite (`test/thinking-parser.test.ts:181-183`,
    /// "Text-before-thinking (Kiro API sends text first, thinking after)")
    /// documents it as ordinary, observed Kiro behavior. `text_started` is
    /// reset to `false` alongside `thinking_extracted = true` in
    /// `process_inside_thinking` to reproduce this: this port has no
    /// content-block array to reindex like the TS source does, but the
    /// observable event stream (a fresh `TextStart` after every
    /// `ThinkingStop`) matches. Hand-off note for the task that routes
    /// these events into Anthropic content blocks: text before AND after a
    /// thinking block are two SEPARATE text blocks, never merged.
    #[test]
    fn text_then_thinking_then_text_emits_a_new_text_block() {
        let mut parser = ThinkingTagParser::new();
        let mut events = parser.process_chunk("Hello ");
        events.extend(parser.process_chunk("<thinking>t</thinking>"));
        events.extend(parser.process_chunk("more"));
        events.extend(parser.finalize());

        assert_eq!(
            events,
            vec![
                TextStart,
                TextDelta("Hello ".to_string()),
                ThinkingStart,
                ThinkingDelta("t".to_string()),
                ThinkingStop,
                TextStart,
                TextDelta("more".to_string()),
            ]
        );
    }
}
