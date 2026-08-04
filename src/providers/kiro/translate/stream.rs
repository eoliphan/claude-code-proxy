//! Kiro stream orchestration: retry loops, event routing, and Anthropic SSE
//! emission.
//!
//! This is the module that actually talks to Kiro's live API. It drives one
//! logical Anthropic `/v1/messages` request to completion — including every
//! internal retry — and pushes each Anthropic-shaped SSE frame into a
//! `tokio::sync::mpsc::Sender` as soon as it is produced, so a `stream: true`
//! caller gets genuinely incremental output rather than one buffered blob at
//! the end.
//!
//! Ported from `pi-provider-kiro`'s `src/stream.ts` (read directly at
//! implementation time from
//! `/home/erich.oliphant/IdeaProjects/pi-provider-kiro/src/stream.ts` and
//! `src/retry.ts`, cross-checked against `test/stream.test.ts`), with the
//! parts of the port that could not be transcribed literally called out
//! below.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use once_cell::sync::Lazy;
use serde_json::{Value, json};
use tokio::sync::mpsc::Sender;

use crate::anthropic::schema::MessagesRequest;
use crate::anthropic::sse::encode_sse_event;
use crate::auth::FileAuthStore;
use crate::providers::kiro::auth::{KiroAuthManager, KiroCredentials};
use crate::providers::kiro::client::{ChunkOutcome, KiroError, KiroHttpClient, KiroStreamResponse};

use super::event_parser::{KiroStreamEvent, parse_kiro_events};
use super::model_discovery::{self, PROFILE_CACHE};
use super::models::{
    KiroModelMeta, approx_token_count, first_token_timeout_for, resolve_api_region,
};
use super::request::{BuildRequestOptions, build_kiro_request};
use super::thinking_parser::{ThinkingStreamEvent, ThinkingTagParser};

type AuthManager = KiroAuthManager<FileAuthStore<KiroCredentials>>;

/// Matches a whole response that is nothing but "continue" or a run of dots
/// (case-insensitive) — the "echo loop" the reference detects and retries.
static ECHO_REGEX: Lazy<regex_lite::Regex> =
    Lazy::new(|| regex_lite::Regex::new(r"(?i)^\s*(continue|\.+)\s*$").expect("valid regex"));

/// Terminal failure of [`run_kiro_stream`].
#[derive(Debug)]
pub enum KiroStreamError {
    /// Exhausted the auth-retry budget, or credentials could not be resolved
    /// at all.
    Auth(anyhow::Error),
    /// Maps to a local `context_length_exceeded`-style response.
    ContextOverflow(String),
    /// `MONTHLY_REQUEST_COUNT`, exhausted capacity retries, and every other
    /// upstream error this provider deliberately does not retry (generic
    /// 429/5xx in particular).
    ///
    /// Deliberate divergence from the plan's draft enum, which spelled this
    /// `NonRetryable(String)`: the plan's own Step 14 requires the upstream
    /// `Retry-After` value to survive all the way to the eventual HTTP
    /// response, and a bare `String` cannot carry it. The status code is
    /// carried for the same reason.
    NonRetryable {
        status: u16,
        message: String,
        retry_after: Option<String>,
    },
    /// Exhausted the stall/empty-retry budget, or an unclassified failure.
    Other(anyhow::Error),
}

impl std::fmt::Display for KiroStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KiroStreamError::Auth(e) => write!(f, "{e}"),
            KiroStreamError::ContextOverflow(m) => write!(f, "{m}"),
            KiroStreamError::NonRetryable { message, .. } => write!(f, "{message}"),
            KiroStreamError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for KiroStreamError {}

/// Per-request timeouts. `first_token_ms` of `0` means "resolve per-model at
/// call time" via [`first_token_timeout_for`]; a non-zero value overrides it
/// (this is the test seam that keeps first-token-timeout tests fast).
#[derive(Debug, Clone, Copy)]
pub struct StreamTimeouts {
    pub first_token_ms: u64,
    pub idle_ms: u64,
}

impl Default for StreamTimeouts {
    fn default() -> Self {
        Self {
            first_token_ms: 0,
            idle_ms: 300_000,
        }
    }
}

pub struct RunStreamOptions<'a> {
    pub client: &'a KiroHttpClient,
    pub model: &'a KiroModelMeta,
    pub req: &'a MessagesRequest,
    pub message_id: &'a str,
    /// Generated exactly ONCE by the caller, before `run_kiro_stream` is
    /// called at all, and reused verbatim across every retry rebuild — never
    /// regenerated inside this module.
    pub conversation_id: &'a str,
    pub reasoning_enabled: bool,
    pub timeouts: StreamTimeouts,
}

/// Retry budgets and backoff parameters. Production values mirror
/// `pi-provider-kiro/src/retry.ts` exactly; tests substitute millisecond-scale
/// delays (and, for one case, a zero outer budget) through
/// [`run_kiro_stream_impl`].
#[derive(Debug, Clone, Copy)]
struct RetryPolicy {
    /// Shared across auth retries, stall/timeout retries, transport-failure
    /// retries, AND empty/echo-response retries — one counter, not four.
    max_retries: u32,
    auth_base_delay_ms: u64,
    stall_base_delay_ms: u64,
    max_delay_ms: u64,
    /// Capacity errors get their own budget, reset on every outer iteration.
    capacity_max_retries: u32,
    capacity_base_delay_ms: u64,
    capacity_max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            auth_base_delay_ms: 500,
            stall_base_delay_ms: 1_000,
            max_delay_ms: 10_000,
            capacity_max_retries: 3,
            capacity_base_delay_ms: 5_000,
            capacity_max_delay_ms: 30_000,
        }
    }
}

/// Drives one logical Anthropic request to completion (including all internal
/// retries) and sends each Anthropic-shaped SSE frame to `sink` as it is
/// produced. Returns once the stream is fully finished (`Ok`) or a terminal
/// error occurred (`Err`) — in the `Err` case an `error`-typed SSE frame has
/// ALREADY been sent to `sink` if any frame was sent at all, so a caller that
/// is already streaming to a client does not need to synthesize one.
pub async fn run_kiro_stream(
    opts: RunStreamOptions<'_>,
    sink: Sender<Result<Bytes, std::io::Error>>,
) -> Result<(), KiroStreamError> {
    run_kiro_stream_impl(opts, sink, None, RetryPolicy::default()).await
}

/// Internal seam for testing, mirroring the `_impl` convention already used
/// by `client.rs` and `model_discovery.rs`: `base_url_override` replaces
/// `https://q.{api_region}.amazonaws.com` (for both the streaming endpoint
/// and profile resolution) and `policy` substitutes fast retry budgets.
async fn run_kiro_stream_impl(
    opts: RunStreamOptions<'_>,
    sink: Sender<Result<Bytes, std::io::Error>>,
    base_url_override: Option<&str>,
    policy: RetryPolicy,
) -> Result<(), KiroStreamError> {
    let model_name = opts
        .req
        .model
        .as_deref()
        .unwrap_or(opts.model.id)
        .to_string();
    let mut emitter = SseEmitter::new(sink, opts.message_id, &model_name);

    match drive(&opts, &mut emitter, base_url_override, policy).await {
        Ok(()) => Ok(()),
        // The receiving half went away (client disconnected). Nothing was
        // lost that anyone is still listening for, so this is not an error.
        Err(FlowError::SinkClosed) => Ok(()),
        Err(FlowError::Terminal(err)) => {
            if emitter.emitted_anything() {
                // A client already consuming this stream must see a clean
                // termination signal rather than a truncated connection.
                let _ = emitter.error_frame(&err.to_string()).await;
            }
            Err(err)
        }
    }
}

/// The whole orchestration: outer retry loop, inner send/capacity loop,
/// chunked read loop, event routing, and finalization.
async fn drive(
    opts: &RunStreamOptions<'_>,
    emitter: &mut SseEmitter,
    base_url_override: Option<&str>,
    policy: RetryPolicy,
) -> Result<(), FlowError> {
    let auth_manager = opts.client.auth_manager_handle();
    // Shared across auth, transport, stall, and empty/echo retries — one
    // budget, exactly as in the reference.
    let mut retry_count: u32 = 0;

    'outer: loop {
        // --- Endpoint and profile resolution, re-done every iteration: a
        // refreshed credential can carry a different region, and a
        // cache invalidation has to be picked back up.
        let creds = get_auth(Arc::clone(&auth_manager))
            .await
            .map_err(|e| FlowError::Terminal(KiroStreamError::Auth(e)))?;
        let endpoint = resolve_endpoint(&creds, base_url_override);
        let profile_arn = resolve_profile_arn(&creds, &endpoint, base_url_override).await;

        // Rebuilt from scratch every outer iteration (history/current-message
        // included), never just resent — matching the reference. The one
        // thing that is never rebuilt is `conversation_id`, which the caller
        // generated exactly once.
        let (kiro_request, _current_tool_results) = build_kiro_request(
            opts.req,
            BuildRequestOptions {
                conversation_id: opts.conversation_id,
                reasoning_enabled: opts.reasoning_enabled,
                thinking_budget: None,
                profile_arn: profile_arn.as_deref(),
            },
        )
        .map_err(|e| FlowError::Terminal(KiroStreamError::Other(e)))?;

        let mut state = AttemptState::new(opts.reasoning_enabled, opts.model.context_window);
        // Reset every outer iteration: each auth/stall retry gets a fresh
        // capacity budget.
        let mut capacity_retry_count: u32 = 0;

        // --- Inner loop: HTTP send plus capacity retries -----------------
        let mut response: KiroStreamResponse = loop {
            let err = match opts
                .client
                .post_generate_assistant_response(&endpoint, &kiro_request)
                .await
            {
                Ok(response) => break response,
                Err(err) => err,
            };

            // 401/403 first, matching the client's own classification order.
            if err.status == 401 || err.status == 403 {
                if retry_count >= policy.max_retries {
                    return Err(FlowError::Terminal(KiroStreamError::Auth(anyhow::anyhow!(
                        "Kiro authentication failed after {} retries: {}",
                        policy.max_retries,
                        err.message
                    ))));
                }
                if let Err(refresh_err) =
                    force_refresh(Arc::clone(&auth_manager), creds.access.clone()).await
                {
                    // Still worth one more attempt: another process may have
                    // rotated the stored credential underneath us.
                    tracing::warn!(
                        "kiro: credential refresh after HTTP {} failed: {refresh_err}",
                        err.status
                    );
                }
                // A stale cached profile ARN can itself cause repeated
                // 401/403s that a token refresh alone will never fix.
                PROFILE_CACHE.invalidate(&endpoint);
                sleep_backoff(retry_count, policy.auth_base_delay_ms, policy.max_delay_ms).await;
                retry_count += 1;
                continue 'outer;
            }

            if err.capacity_error {
                if capacity_retry_count < policy.capacity_max_retries {
                    tracing::warn!(
                        "kiro: INSUFFICIENT_MODEL_CAPACITY, retrying ({}/{})",
                        capacity_retry_count + 1,
                        policy.capacity_max_retries
                    );
                    sleep_backoff(
                        capacity_retry_count,
                        policy.capacity_base_delay_ms,
                        policy.capacity_max_delay_ms,
                    )
                    .await;
                    capacity_retry_count += 1;
                    // Resend the *same* request: capacity retries are the one
                    // path that does not rebuild history/current-message.
                    continue;
                }
                return Err(FlowError::Terminal(KiroStreamError::NonRetryable {
                    status: err.status,
                    message: format!(
                        "Kiro reported insufficient model capacity after {} retries",
                        policy.capacity_max_retries
                    ),
                    retry_after: err.retry_after,
                }));
            }

            if !err.retryable {
                // MONTHLY_REQUEST_COUNT, context overflow, generic 429/5xx:
                // terminal, deliberately outside the outer budget so no
                // caller-side generic retry misreads them as transient.
                return Err(FlowError::Terminal(classify_terminal(err)));
            }

            // Retryable but neither auth nor capacity: a transport-level
            // failure (`status: 0`). Shares the outer budget rather than
            // falling through — a fall-through here would loop forever.
            if retry_count < policy.max_retries {
                sleep_backoff(retry_count, policy.stall_base_delay_ms, policy.max_delay_ms).await;
                retry_count += 1;
                continue 'outer;
            }
            return Err(FlowError::Terminal(KiroStreamError::Other(
                anyhow::anyhow!("Kiro API error after max retries: {}", err.message),
            )));
        };

        // --- Chunked read loop ------------------------------------------
        let first_token_timeout = Duration::from_millis(if opts.timeouts.first_token_ms > 0 {
            opts.timeouts.first_token_ms
        } else {
            first_token_timeout_for(opts.model.id)
        });
        let idle_timeout = Duration::from_millis(opts.timeouts.idle_ms.max(1));

        // Two buffers, not one: `pending_bytes` holds an undecoded partial
        // UTF-8 sequence from the previous network read, `text_buffer` holds
        // decoded text whose JSON event is not complete yet.
        let mut pending_bytes: Vec<u8> = Vec::new();
        let mut text_buffer = String::new();
        let mut first_token_received = false;
        let mut first_token_timed_out = false;
        let mut idle_cancelled = false;
        let mut transport_error: Option<String> = None;

        'read: loop {
            // Every call gets its own deadline, so the idle timer is
            // implicitly reset by *byte* arrival, including bytes that parse
            // to zero events (mid-way through a large tool-call payload).
            let timeout = if first_token_received {
                idle_timeout
            } else {
                first_token_timeout
            };
            match response.next_chunk(timeout).await {
                ChunkOutcome::Bytes(bytes) => {
                    first_token_received = true;
                    decode_chunk(&mut pending_bytes, &bytes, &mut text_buffer);
                    let parsed = parse_kiro_events(&text_buffer);
                    text_buffer = parsed.remaining;
                    for event in parsed.events {
                        route_event(event, &mut state, emitter).await?;
                        if state.stream_error.is_some() {
                            break 'read;
                        }
                    }
                }
                ChunkOutcome::EndOfStream => break,
                ChunkOutcome::TimedOut => {
                    if first_token_received {
                        idle_cancelled = true;
                    } else {
                        first_token_timed_out = true;
                    }
                    break;
                }
                ChunkOutcome::Error(e) => {
                    transport_error = Some(e.to_string());
                    break;
                }
            }
        }

        // --- Unified stall/error retry check -----------------------------
        if first_token_timed_out
            || idle_cancelled
            || state.stream_error.is_some()
            || transport_error.is_some()
        {
            if retry_count < policy.max_retries && !emitter.emitted_anything() {
                sleep_backoff(retry_count, policy.stall_base_delay_ms, policy.max_delay_ms).await;
                retry_count += 1;
                continue 'outer;
            }
            let stream_error = state
                .stream_error
                .clone()
                .or_else(|| transport_error.clone());
            let suffix = if emitter.emitted_anything() && retry_count < policy.max_retries {
                "(cannot retry: output was already streamed)"
            } else {
                "after max retries"
            };
            let message = match stream_error {
                Some(e) => format!("Kiro API stream error {suffix}: {e}"),
                None if first_token_timed_out => {
                    format!("Kiro API error: first token timeout {suffix}")
                }
                None => format!("Kiro API error: idle timeout {suffix}"),
            };
            return Err(FlowError::Terminal(KiroStreamError::Other(
                anyhow::anyhow!(message),
            )));
        }

        // --- Clean completion: flush, finalize, classify ------------------
        // A tool call whose stop signal never arrived is still flushed, per
        // the reference.
        flush_tool_call(&mut state, emitter).await?;
        // Finalize the thinking parser BEFORE closing any open content block:
        // finalize() can emit trailing deltas (an unterminated `<thinking>`
        // tag, or a held-back partial close tag), and a delta arriving after
        // its block's content_block_stop is invalid Anthropic SSE.
        if let Some(parser) = state.thinking_parser.as_mut() {
            let events = parser.finalize();
            route_thinking_events(events, &mut state, emitter).await?;
        }

        let has_text = !state.text_content.is_empty();
        let is_echo_loop =
            has_text && !state.saw_any_tool_calls && ECHO_REGEX.is_match(&state.text_content);
        if (!has_text && !state.saw_any_tool_calls) || is_echo_loop {
            let label = if is_echo_loop {
                "echo loop (the model answered with just \"continue\")"
            } else {
                "empty response (no text, no tool calls)"
            };
            // Only retryable while nothing has reached the client: Anthropic
            // SSE has no way to retract a message_start or reuse a block
            // index, so a second attempt after any frame was sent would
            // produce an invalid stream. (Divergence from the plan's draft,
            // which assumed per-iteration state reset made this unreachable —
            // it does not, because the reset is local state, not sent bytes.)
            // In practice this means the *empty* half of the check retries
            // (nothing was ever emitted) while the *echo* half only logs: an
            // echo response is non-empty text that already went out the
            // moment it arrived.
            if retry_count < policy.max_retries && !emitter.emitted_anything() {
                tracing::warn!(
                    "kiro: {label}, retrying ({}/{})",
                    retry_count + 1,
                    policy.max_retries
                );
                sleep_backoff(retry_count, policy.stall_base_delay_ms, policy.max_delay_ms).await;
                retry_count += 1;
                continue 'outer;
            }
            tracing::warn!("kiro: {label} persisted; returning the turn as-is");
        }

        emitter.close_block().await?;

        let stop_reason = if !state.received_context_usage && state.emitted_tool_calls == 0 {
            // Deliberate: no context-usage confirmation and nothing emitted
            // is the reference's "did not finish cleanly" signal, and
            // "length" is the closest Anthropic vocabulary for it.
            "length"
        } else if state.emitted_tool_calls > 0 {
            "tool_use"
        } else {
            "end_turn"
        };
        let input_tokens = state.usage_input.unwrap_or(state.context_input_tokens);
        let output_tokens = state
            .usage_output
            .unwrap_or_else(|| approx_token_count(&state.total_content));
        emitter
            .finish(stop_reason, input_tokens, output_tokens)
            .await?;
        return Ok(());
    }
}

/// Per-attempt accumulator. Every field is reset on each outer-loop
/// iteration.
struct AttemptState {
    thinking_parser: Option<ThinkingTagParser>,
    /// Everything the assistant produced (text plus tool-call input JSON),
    /// used for the output-token estimate when no `usage` event arrives.
    total_content: String,
    /// Text-block content only — what the empty/echo checks look at.
    text_content: String,
    last_content: Option<String>,
    current_tool: Option<ToolCallState>,
    saw_any_tool_calls: bool,
    emitted_tool_calls: u32,
    received_context_usage: bool,
    context_input_tokens: u64,
    /// The model's context window, used to turn a context-usage percentage
    /// into an input-token estimate.
    context_window: u64,
    usage_input: Option<u64>,
    usage_output: Option<u64>,
    stream_error: Option<String>,
}

impl AttemptState {
    fn new(reasoning_enabled: bool, context_window: u64) -> Self {
        Self {
            thinking_parser: reasoning_enabled.then(ThinkingTagParser::new),
            total_content: String::new(),
            text_content: String::new(),
            last_content: None,
            current_tool: None,
            saw_any_tool_calls: false,
            emitted_tool_calls: 0,
            received_context_usage: false,
            context_input_tokens: 0,
            context_window,
            usage_input: None,
            usage_output: None,
            stream_error: None,
        }
    }
}

struct ToolCallState {
    tool_use_id: String,
    name: String,
    input: String,
}

async fn route_event(
    event: KiroStreamEvent,
    state: &mut AttemptState,
    emitter: &mut SseEmitter,
) -> Result<(), FlowError> {
    match event {
        KiroStreamEvent::Content(text) => {
            // Kiro sometimes repeats the immediately-previous content event
            // verbatim. Only *consecutive* duplicates are dropped: a repeat
            // separated by a different content event is real output.
            if state.last_content.as_deref() == Some(text.as_str()) {
                return Ok(());
            }
            state.last_content = Some(text.clone());
            state.total_content.push_str(&text);

            let thinking_events = state
                .thinking_parser
                .as_mut()
                .map(|parser| parser.process_chunk(&text));
            match thinking_events {
                Some(events) => route_thinking_events(events, state, emitter).await?,
                None => {
                    state.text_content.push_str(&text);
                    emitter.text_delta(&text).await?;
                }
            }
        }
        KiroStreamEvent::ToolUse {
            name,
            tool_use_id,
            input,
            stop,
        } => {
            state.saw_any_tool_calls = true;
            let same_call = state
                .current_tool
                .as_ref()
                .is_some_and(|t| t.tool_use_id == tool_use_id);
            if !same_call {
                flush_tool_call(state, emitter).await?;
                state.current_tool = Some(ToolCallState {
                    tool_use_id,
                    name,
                    input: String::new(),
                });
            }
            if let Some(tool) = state.current_tool.as_mut() {
                tool.input.push_str(&input);
            }
            state.total_content.push_str(&input);
            if stop == Some(true) {
                flush_tool_call(state, emitter).await?;
            }
        }
        KiroStreamEvent::ToolUseInput { input } => {
            if let Some(tool) = state.current_tool.as_mut() {
                tool.input.push_str(&input);
            }
            state.total_content.push_str(&input);
        }
        KiroStreamEvent::ToolUseStop { stop } => {
            if stop {
                flush_tool_call(state, emitter).await?;
            }
        }
        KiroStreamEvent::ContextUsage {
            context_usage_percentage,
        } => {
            state.received_context_usage = true;
            state.context_input_tokens =
                (context_usage_percentage / 100.0 * state.context_window as f64).round() as u64;
        }
        // Kiro-internal UI hinting with no Anthropic equivalent.
        KiroStreamEvent::FollowupPrompt(_) => {}
        KiroStreamEvent::Usage {
            input_tokens,
            output_tokens,
        } => {
            state.usage_input = input_tokens;
            state.usage_output = output_tokens;
        }
        KiroStreamEvent::Error { error, message } => {
            state.stream_error = Some(match message {
                Some(message) => format!("{error}: {message}"),
                None => error,
            });
        }
    }
    Ok(())
}

async fn route_thinking_events(
    events: Vec<ThinkingStreamEvent>,
    state: &mut AttemptState,
    emitter: &mut SseEmitter,
) -> Result<(), FlowError> {
    for event in events {
        match event {
            ThinkingStreamEvent::TextStart => {
                emitter.ensure_block(BlockKind::Text).await?;
            }
            ThinkingStreamEvent::TextDelta(text) => {
                state.text_content.push_str(&text);
                emitter.text_delta(&text).await?;
            }
            ThinkingStreamEvent::TextStop => emitter.close_block_if(BlockKind::Text).await?,
            ThinkingStreamEvent::ThinkingStart => {
                emitter.ensure_block(BlockKind::Thinking).await?;
            }
            ThinkingStreamEvent::ThinkingDelta(text) => emitter.thinking_delta(&text).await?,
            ThinkingStreamEvent::ThinkingStop => {
                emitter.close_block_if(BlockKind::Thinking).await?
            }
        }
    }
    Ok(())
}

/// Accumulate-then-validate-then-emit: the accumulated input is parsed as a
/// whole and the entire tool call is dropped if it does not parse. Raw
/// fragments are never forwarded as `input_json_delta` before the full
/// accumulation is known to be valid JSON.
async fn flush_tool_call(
    state: &mut AttemptState,
    emitter: &mut SseEmitter,
) -> Result<(), FlowError> {
    let Some(tool) = state.current_tool.take() else {
        return Ok(());
    };
    // Kiro omits the input payload for zero-argument tool calls; an empty
    // accumulation is `{}`, not a truncation.
    let final_input = if tool.input.trim().is_empty() {
        "{}".to_string()
    } else {
        tool.input
    };
    match serde_json::from_str::<Value>(&final_input) {
        Ok(_) => {
            emitter
                .tool_block(&tool.tool_use_id, &tool.name, &final_input)
                .await?;
            state.emitted_tool_calls += 1;
        }
        Err(e) => {
            // Silently dropped for the client, matching the reference: the
            // API did respond, it just sent an unusable tool call.
            tracing::warn!(
                "kiro: dropping tool call \"{}\" ({}): input is not valid JSON ({e}); {} chars",
                tool.name,
                tool.tool_use_id,
                final_input.len()
            );
        }
    }
    Ok(())
}

/// The receiving half of `sink` was dropped — the client is gone.
struct SinkClosed;

enum FlowError {
    SinkClosed,
    Terminal(KiroStreamError),
}

impl From<SinkClosed> for FlowError {
    fn from(_: SinkClosed) -> Self {
        FlowError::SinkClosed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Text,
    Thinking,
}

/// Owns Anthropic content-block index assignment and every byte written to
/// the sink. Mirrors `codex/translate/stream.rs`'s emission shapes
/// (`serde_json::json!` + `encode_sse_event`), with `message_start` deferred
/// until the first frame that actually needs it.
struct SseEmitter {
    sink: Sender<Result<Bytes, std::io::Error>>,
    message_id: String,
    model: String,
    message_started: bool,
    emitted_anything: bool,
    next_index: usize,
    open: Option<(usize, BlockKind)>,
}

impl SseEmitter {
    fn new(sink: Sender<Result<Bytes, std::io::Error>>, message_id: &str, model: &str) -> Self {
        Self {
            sink,
            message_id: message_id.to_string(),
            model: model.to_string(),
            message_started: false,
            emitted_anything: false,
            next_index: 0,
            open: None,
        }
    }

    fn emitted_anything(&self) -> bool {
        self.emitted_anything
    }

    async fn send(&mut self, event: &str, data: &Value) -> Result<(), SinkClosed> {
        let frame = encode_sse_event(Some(event), &data.to_string());
        self.sink
            .send(Ok(Bytes::from(frame)))
            .await
            .map_err(|_| SinkClosed)?;
        self.emitted_anything = true;
        Ok(())
    }

    async fn ensure_message_start(&mut self) -> Result<(), SinkClosed> {
        if self.message_started {
            return Ok(());
        }
        self.message_started = true;
        let data = json!({
            "type": "message_start",
            "message": {
                "id": self.message_id,
                "type": "message",
                "role": "assistant",
                "model": self.model,
                "content": [],
                "stop_reason": null,
                "stop_sequence": null,
                // Real counts are only known once Kiro reports context usage
                // (or a usage event lands), both of which arrive mid-stream —
                // the final numbers ride on `message_delta`.
                "usage": {"input_tokens": 0, "output_tokens": 0},
            }
        });
        self.send("message_start", &data).await
    }

    async fn ensure_block(&mut self, kind: BlockKind) -> Result<usize, SinkClosed> {
        if let Some((index, open_kind)) = self.open
            && open_kind == kind
        {
            return Ok(index);
        }
        self.close_block().await?;
        self.ensure_message_start().await?;
        let index = self.next_index;
        self.next_index += 1;
        self.open = Some((index, kind));
        let content_block = match kind {
            BlockKind::Text => json!({"type": "text", "text": ""}),
            BlockKind::Thinking => json!({"type": "thinking", "thinking": "", "signature": ""}),
        };
        self.send(
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": index,
                "content_block": content_block,
            }),
        )
        .await?;
        Ok(index)
    }

    async fn close_block(&mut self) -> Result<(), SinkClosed> {
        if let Some((index, _)) = self.open.take() {
            self.send(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": index}),
            )
            .await?;
        }
        Ok(())
    }

    async fn close_block_if(&mut self, kind: BlockKind) -> Result<(), SinkClosed> {
        if matches!(self.open, Some((_, open_kind)) if open_kind == kind) {
            self.close_block().await?;
        }
        Ok(())
    }

    async fn text_delta(&mut self, text: &str) -> Result<(), SinkClosed> {
        if text.is_empty() {
            return Ok(());
        }
        let index = self.ensure_block(BlockKind::Text).await?;
        self.send(
            "content_block_delta",
            &json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "text_delta", "text": text},
            }),
        )
        .await
    }

    async fn thinking_delta(&mut self, text: &str) -> Result<(), SinkClosed> {
        if text.is_empty() {
            return Ok(());
        }
        let index = self.ensure_block(BlockKind::Thinking).await?;
        self.send(
            "content_block_delta",
            &json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "thinking_delta", "thinking": text},
            }),
        )
        .await
    }

    /// Emits a complete, already-validated tool call as its own block. Any
    /// open text/thinking block is closed first, so blocks never interleave.
    async fn tool_block(
        &mut self,
        id: &str,
        name: &str,
        input_json: &str,
    ) -> Result<(), SinkClosed> {
        self.close_block().await?;
        self.ensure_message_start().await?;
        let index = self.next_index;
        self.next_index += 1;
        self.send(
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": index,
                "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}},
            }),
        )
        .await?;
        self.send(
            "content_block_delta",
            &json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "input_json_delta", "partial_json": input_json},
            }),
        )
        .await?;
        self.send(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": index}),
        )
        .await
    }

    async fn finish(
        &mut self,
        stop_reason: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<(), SinkClosed> {
        self.ensure_message_start().await?;
        self.send(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {"stop_reason": stop_reason, "stop_sequence": null},
                "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
            }),
        )
        .await?;
        self.send("message_stop", &json!({"type": "message_stop"}))
            .await
    }

    async fn error_frame(&mut self, message: &str) -> Result<(), SinkClosed> {
        self.send(
            "error",
            &json!({
                "type": "error",
                "error": {"type": "api_error", "message": message},
            }),
        )
        .await
    }
}

/// Folds a complete Anthropic SSE byte stream (as produced by
/// [`run_kiro_stream`]) into the single JSON message body a `stream: false`
/// request expects — the same shape `kimi/translate/accumulate.rs` produces.
pub fn accumulate_sse_message(sse_bytes: &[u8], message_id: &str, model: &str) -> Value {
    enum Block {
        Text(String),
        Thinking(String),
        Tool {
            id: String,
            name: String,
            input: String,
        },
    }

    let mut blocks: Vec<(u64, Block)> = Vec::new();
    let mut stop_reason = Value::Null;
    let mut usage = json!({"input_tokens": 0, "output_tokens": 0});

    for event in crate::anthropic::sse::parse_sse_events(sse_bytes) {
        let Ok(data) = serde_json::from_str::<Value>(&event.data) else {
            continue;
        };
        match data["type"].as_str() {
            Some("content_block_start") => {
                let index = data["index"].as_u64().unwrap_or_default();
                let block = &data["content_block"];
                let block = match block["type"].as_str() {
                    Some("text") => Block::Text(String::new()),
                    Some("thinking") => Block::Thinking(String::new()),
                    Some("tool_use") => Block::Tool {
                        id: block["id"].as_str().unwrap_or_default().to_string(),
                        name: block["name"].as_str().unwrap_or_default().to_string(),
                        input: String::new(),
                    },
                    _ => continue,
                };
                blocks.push((index, block));
            }
            Some("content_block_delta") => {
                let index = data["index"].as_u64().unwrap_or_default();
                let Some((_, block)) = blocks.iter_mut().rev().find(|(i, _)| *i == index) else {
                    continue;
                };
                let delta = &data["delta"];
                match (delta["type"].as_str(), block) {
                    (Some("text_delta"), Block::Text(text)) => {
                        text.push_str(delta["text"].as_str().unwrap_or_default())
                    }
                    (Some("thinking_delta"), Block::Thinking(text)) => {
                        text.push_str(delta["thinking"].as_str().unwrap_or_default())
                    }
                    (Some("input_json_delta"), Block::Tool { input, .. }) => {
                        input.push_str(delta["partial_json"].as_str().unwrap_or_default())
                    }
                    _ => {}
                }
            }
            Some("message_delta") => {
                stop_reason = data["delta"]["stop_reason"].clone();
                if data["usage"].is_object() {
                    usage = data["usage"].clone();
                }
            }
            _ => {}
        }
    }

    let content: Vec<Value> = blocks
        .into_iter()
        .filter_map(|(_, block)| match block {
            Block::Text(text) => (!text.is_empty()).then(|| json!({"type": "text", "text": text})),
            Block::Thinking(text) => (!text.is_empty())
                .then(|| json!({"type": "thinking", "thinking": text, "signature": ""})),
            Block::Tool { id, name, input } => {
                let parsed = serde_json::from_str::<Value>(&input).unwrap_or_else(|_| json!({}));
                Some(json!({"type": "tool_use", "id": id, "name": name, "input": parsed}))
            }
        })
        .collect();

    json!({
        "id": message_id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": usage,
    })
}

/// Runs the auth manager's synchronous `get_auth` on a blocking thread (it
/// does file/SQLite I/O), mirroring `client.rs`'s own `spawn_blocking` note.
async fn get_auth(manager: Arc<AuthManager>) -> Result<KiroCredentials, anyhow::Error> {
    tokio::task::spawn_blocking(move || manager.get_auth()).await?
}

/// Same, for `force_refresh` — which takes the access token the backend just
/// rejected so the cascade refuses to hand that exact token back.
async fn force_refresh(
    manager: Arc<AuthManager>,
    rejected_access: String,
) -> Result<KiroCredentials, anyhow::Error> {
    tokio::task::spawn_blocking(move || manager.force_refresh(&rejected_access)).await?
}

/// Cached-first profile resolution. A resolution failure is treated exactly
/// like "this account has no profile" (omit `profileArn` and proceed) —
/// never a reason to fail the in-flight user request, per
/// `fetch_available_profile_arn`'s own doc comment.
async fn resolve_profile_arn(
    creds: &KiroCredentials,
    endpoint: &str,
    base_url_override: Option<&str>,
) -> Option<String> {
    if let Some(cached) = PROFILE_CACHE.get(endpoint) {
        return Some(cached);
    }
    let resolved = model_discovery::fetch_available_profile_arn_impl(creds, base_url_override)
        .await
        .ok()
        .flatten();
    if let Some(arn) = &resolved {
        PROFILE_CACHE.set(endpoint, arn.clone());
    }
    resolved
}

fn classify_terminal(err: KiroError) -> KiroStreamError {
    // Status 0 with `retryable: false` is the client's "could not resolve or
    // use the stored credential" classification, not an upstream response.
    if err.status == 0 {
        return KiroStreamError::Auth(anyhow::anyhow!(
            "{}{}",
            err.message,
            err.body
                .as_deref()
                .map(|b| format!(": {b}"))
                .unwrap_or_default()
        ));
    }
    // Matches `codex/mod.rs::is_context_window_overflow`'s existing
    // substring convention, which `client.rs` deliberately writes into the
    // message for exactly this handoff.
    if err.message.to_ascii_lowercase().contains("context window") {
        return KiroStreamError::ContextOverflow(format!(
            "Kiro API error: context_length_exceeded ({} {})",
            err.status,
            err.body.unwrap_or_default()
        ));
    }
    KiroStreamError::NonRetryable {
        status: err.status,
        message: format!(
            "Kiro API error: {}{}",
            err.message,
            err.body
                .as_deref()
                .map(|b| format!(" ({b})"))
                .unwrap_or_default()
        ),
        retry_after: err.retry_after,
    }
}

/// `min(base * 2^attempt, max)` — `exponentialBackoff` from the reference's
/// `retry.ts`, with saturating arithmetic instead of JS float math.
fn exponential_backoff(attempt: u32, base_ms: u64, max_ms: u64) -> u64 {
    base_ms
        .saturating_mul(2u64.saturating_pow(attempt.min(32)))
        .min(max_ms)
}

async fn sleep_backoff(attempt: u32, base_ms: u64, max_ms: u64) {
    tokio::time::sleep(Duration::from_millis(exponential_backoff(
        attempt, base_ms, max_ms,
    )))
    .await;
}

/// The `GenerateAssistantResponse` endpoint for a credential's resolved API
/// region (or, in tests, the override base). Uses
/// `model_discovery::streaming_endpoint` so this URL — which is also the
/// `PROFILE_CACHE` key — can never drift from the key
/// `refresh_cache_for_credentials` writes with.
fn resolve_endpoint(creds: &KiroCredentials, base_url_override: Option<&str>) -> String {
    match base_url_override {
        Some(base) => format!("{base}/generateAssistantResponse"),
        None => model_discovery::streaming_endpoint(&resolve_api_region(&creds.region)),
    }
}

/// Appends `chunk` to `pending`, moving every complete UTF-8 character into
/// `out`.
///
/// `from_utf8`'s error has two distinct shapes and conflating them is a hang:
/// `error_len() == None` means the trailing bytes are an *incomplete*
/// sequence whose remainder is still in flight (retain them), while
/// `error_len() == Some(n)` means those `n` bytes are *invalid* and will
/// never become valid (retaining them would wedge the decoder forever, since
/// `pending` would never drain and `out` would never advance).
fn decode_chunk(pending: &mut Vec<u8>, chunk: &[u8], out: &mut String) {
    pending.extend_from_slice(chunk);
    loop {
        match std::str::from_utf8(pending) {
            Ok(valid) => {
                out.push_str(valid);
                pending.clear();
                return;
            }
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                out.push_str(
                    std::str::from_utf8(&pending[..valid_up_to])
                        .expect("valid_up_to guarantees validity"),
                );
                match e.error_len() {
                    None => {
                        // Incomplete trailing sequence: keep exactly it.
                        pending.drain(..valid_up_to);
                        return;
                    }
                    Some(invalid_len) => {
                        pending.drain(..valid_up_to + invalid_len);
                        out.push('\u{FFFD}');
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::schema::Message;
    use crate::anthropic::sse::parse_sse_events;
    use crate::auth::AuthStorage;
    use crate::paths::DirResolverEnv;
    use crate::providers::codex::auth::test_http;
    use crate::providers::kiro::auth::KiroAuthMethod;
    use crate::providers::kiro::translate::models::KIRO_MODELS;
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    const GENERATE_TARGET: &str = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse";
    const PROFILES_TARGET: &str = "AmazonCodeWhispererService.ListAvailableProfiles";

    // ------------------------------------------------------------------
    // Mock Kiro server
    // ------------------------------------------------------------------

    /// One scripted HTTP response, whose body arrives in `(delay-before-write,
    /// bytes)` parts so tests can model bytes trickling in over time (the
    /// shared `test_http::spawn_mock_server` helper writes one complete
    /// response in a single `write_all`, which cannot exercise per-chunk
    /// timeouts or split multi-byte characters).
    #[derive(Clone)]
    struct Script {
        status: u16,
        extra_headers: Vec<(String, String)>,
        parts: Vec<(Duration, Vec<u8>)>,
    }

    impl Script {
        fn ok(body: &str) -> Self {
            Self::raw_chunks(200, vec![(Duration::ZERO, body.as_bytes().to_vec())])
        }

        fn chunks(parts: Vec<(Duration, &str)>) -> Self {
            Self::raw_chunks(
                200,
                parts
                    .into_iter()
                    .map(|(d, s)| (d, s.as_bytes().to_vec()))
                    .collect(),
            )
        }

        fn raw_chunks(status: u16, parts: Vec<(Duration, Vec<u8>)>) -> Self {
            Self {
                status,
                extra_headers: Vec::new(),
                parts,
            }
        }

        fn error(status: u16, body: &str) -> Self {
            Self::raw_chunks(status, vec![(Duration::ZERO, body.as_bytes().to_vec())])
        }

        fn with_header(mut self, name: &str, value: &str) -> Self {
            self.extra_headers
                .push((name.to_string(), value.to_string()));
            self
        }
    }

    struct MockKiro {
        url: String,
        requests: Arc<Mutex<Vec<String>>>,
        finished_writing: Arc<AtomicBool>,
        shutdown: Arc<AtomicBool>,
    }

    impl Drop for MockKiro {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
        }
    }

    impl MockKiro {
        fn endpoint(&self) -> String {
            format!("{}/generateAssistantResponse", self.url)
        }

        fn all_requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        fn generate_requests(&self) -> Vec<String> {
            self.all_requests()
                .into_iter()
                .filter(|r| r.contains(GENERATE_TARGET))
                .collect()
        }

        fn generate_count(&self) -> usize {
            self.generate_requests().len()
        }

        fn profile_request_count(&self) -> usize {
            self.all_requests()
                .iter()
                .filter(|r| r.contains(PROFILES_TARGET))
                .count()
        }

        fn finished_writing(&self) -> bool {
            self.finished_writing.load(Ordering::SeqCst)
        }
    }

    /// Parses the JSON body out of a captured raw HTTP request.
    fn request_body(request: &str) -> Value {
        let (_, body) = request
            .split_once("\r\n\r\n")
            .expect("request should have a body");
        serde_json::from_str(body).expect("request body should be JSON")
    }

    fn header_value(request: &str, name: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    /// Spawns a mock Kiro backend. `generate_scripts` are consumed in order by
    /// successive `GenerateAssistantResponse` calls (the last one repeats if
    /// more arrive); `profiles_script` answers `ListAvailableProfiles`,
    /// defaulting to an empty profile list.
    fn spawn_kiro_mock(generate_scripts: Vec<Script>, profiles_script: Option<Script>) -> MockKiro {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).expect("set nonblocking");
        let url = format!("http://{addr}");

        let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let finished_writing = Arc::new(AtomicBool::new(false));
        let profiles = profiles_script
            .unwrap_or_else(|| Script::ok(r#"{"profiles":[]}"#))
            .clone();

        let thread_requests = Arc::clone(&requests);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_finished = Arc::clone(&finished_writing);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let _ = ready_tx.send(());
            let generate_index = AtomicUsize::new(0);
            loop {
                if thread_shutdown.load(Ordering::Relaxed) {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Some(request) = test_http::read_http_request(&mut stream) else {
                            continue;
                        };
                        thread_requests.lock().unwrap().push(request.clone());
                        let script = if request.contains(PROFILES_TARGET) {
                            profiles.clone()
                        } else {
                            let i = generate_index.fetch_add(1, Ordering::SeqCst);
                            generate_scripts
                                .get(i)
                                .or_else(|| generate_scripts.last())
                                .cloned()
                                .unwrap_or_else(|| Script::ok("{}"))
                        };

                        let total: usize = script.parts.iter().map(|(_, b)| b.len()).sum();
                        let reason = match script.status {
                            200 => "OK",
                            400 => "Bad Request",
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            429 => "Too Many Requests",
                            500 => "Internal Server Error",
                            _ => "Unknown",
                        };
                        let mut header = format!("HTTP/1.1 {} {reason}\r\n", script.status);
                        header.push_str("Content-Type: application/json\r\n");
                        header.push_str(&format!("Content-Length: {total}\r\n"));
                        header.push_str("Connection: close\r\n");
                        for (name, value) in &script.extra_headers {
                            header.push_str(&format!("{name}: {value}\r\n"));
                        }
                        header.push_str("\r\n");
                        if stream.write_all(header.as_bytes()).is_err() {
                            continue;
                        }
                        let _ = stream.flush();
                        for (delay, bytes) in &script.parts {
                            if !delay.is_zero() {
                                std::thread::sleep(*delay);
                            }
                            if stream.write_all(bytes).is_err() {
                                break;
                            }
                            let _ = stream.flush();
                        }
                        thread_finished.store(true, Ordering::SeqCst);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("mock server should be ready");

        let server = MockKiro {
            url,
            requests,
            finished_writing,
            shutdown,
        };
        // The profile cache is a process-global keyed by endpoint URL; make
        // sure a previous test that happened to bind the same ephemeral port
        // can't leak a cached ARN into this one.
        PROFILE_CACHE.invalidate(&server.endpoint());
        server
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    fn far_future_creds(access: &str, region: &str, profile_arn: Option<&str>) -> KiroCredentials {
        KiroCredentials {
            access: access.into(),
            refresh: "test-refresh".into(),
            expires: u64::MAX,
            region: region.into(),
            auth_method: KiroAuthMethod::Idc,
            client_id: String::new(),
            client_secret: String::new(),
            profile_arn: profile_arn.map(str::to_string),
            expiry_buffer_ms: 0,
        }
    }

    fn deps_for(home: &Path) -> DirResolverEnv {
        DirResolverEnv {
            platform: "linux".to_string(),
            env: Default::default(),
            home: home.to_string_lossy().to_string(),
        }
    }

    /// A client backed by a temp-dir `FileAuthStore` and a temp HOME, so no
    /// test ever reads the developer's real credentials (the auth cascade
    /// reads `$HOME/.aws/sso/cache` and kiro-cli's SQLite DB otherwise).
    fn test_client(
        access: &str,
        region: &str,
        profile_arn: Option<&str>,
    ) -> (KiroHttpClient, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = FileAuthStore::new(
            tmp.path().join("auth.json").to_string_lossy().to_string(),
            tmp.path().join("legacy.json").to_string_lossy().to_string(),
        );
        store
            .save(far_future_creds(access, region, profile_arn))
            .unwrap();
        let manager = KiroAuthManager::with_deps(store, deps_for(tmp.path()));
        (KiroHttpClient::for_test(manager), tmp)
    }

    /// Writes the Kiro IDE token file the auth cascade's Layer 0 reads, so a
    /// `force_refresh` resolves to `access` without any network call.
    fn write_ide_token(home: &Path, access: &str) {
        let dir = home.join(".aws").join("sso").join("cache");
        std::fs::create_dir_all(&dir).unwrap();
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(8);
        let body = json!({
            "accessToken": access,
            "refreshToken": "ide-refresh",
            "expiresAt": expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            "region": "us-east-1",
        });
        std::fs::write(dir.join("kiro-auth-token.json"), body.to_string()).unwrap();
    }

    fn sample_request() -> MessagesRequest {
        MessagesRequest {
            model: Some("claude-sonnet-4-5".to_string()),
            max_tokens: Some(1024),
            messages: vec![Message {
                role: "user".to_string(),
                content: json!("Hello"),
            }],
            stream: true,
            bypass_provider_model_override: false,
            extra: serde_json::Map::new(),
        }
    }

    fn sample_model() -> &'static KiroModelMeta {
        KIRO_MODELS
            .iter()
            .find(|m| m.id == "claude-sonnet-4-5")
            .expect("catalog entry")
    }

    fn fast_policy() -> RetryPolicy {
        RetryPolicy {
            max_retries: 3,
            auth_base_delay_ms: 1,
            stall_base_delay_ms: 1,
            max_delay_ms: 2,
            capacity_max_retries: 3,
            capacity_base_delay_ms: 1,
            capacity_max_delay_ms: 2,
        }
    }

    fn fast_timeouts() -> StreamTimeouts {
        StreamTimeouts {
            first_token_ms: 5_000,
            idle_ms: 5_000,
        }
    }

    struct RunCase<'a> {
        server: &'a MockKiro,
        client: &'a KiroHttpClient,
        req: &'a MessagesRequest,
        reasoning: bool,
        timeouts: StreamTimeouts,
        policy: RetryPolicy,
    }

    /// Runs the stream against a mock server, draining the sink concurrently
    /// (so the channel never backpressures) and returning the terminal result
    /// plus every emitted SSE byte.
    async fn run_case(case: RunCase<'_>) -> (Result<(), KiroStreamError>, Vec<u8>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let opts = RunStreamOptions {
            client: case.client,
            model: sample_model(),
            req: case.req,
            message_id: "msg_kiro_test",
            conversation_id: "conv-fixed-for-the-whole-request",
            reasoning_enabled: case.reasoning,
            timeouts: case.timeouts,
        };
        let run = run_kiro_stream_impl(opts, tx, Some(&case.server.url), case.policy);
        let drain = async move {
            let mut out = Vec::new();
            while let Some(item) = rx.recv().await {
                out.extend_from_slice(&item.expect("sink never carries io errors"));
            }
            out
        };
        tokio::join!(run, drain)
    }

    /// The common shape: no reasoning, fast timeouts, fast retries.
    async fn run_simple(
        server: &MockKiro,
        client: &KiroHttpClient,
        req: &MessagesRequest,
    ) -> (Result<(), KiroStreamError>, Vec<u8>) {
        run_case(RunCase {
            server,
            client,
            req,
            reasoning: false,
            timeouts: fast_timeouts(),
            policy: fast_policy(),
        })
        .await
    }

    // ------------------------------------------------------------------
    // SSE inspection helpers
    // ------------------------------------------------------------------

    fn frames(sse: &[u8]) -> Vec<(String, Value)> {
        parse_sse_events(sse)
            .into_iter()
            .map(|e| {
                (
                    e.event.unwrap_or_default(),
                    serde_json::from_str::<Value>(&e.data).expect("frame data is JSON"),
                )
            })
            .collect()
    }

    fn frame_names(sse: &[u8]) -> Vec<String> {
        frames(sse).into_iter().map(|(name, _)| name).collect()
    }

    fn find_frame(sse: &[u8], name: &str) -> Option<Value> {
        frames(sse)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, data)| data)
    }

    fn text_deltas(sse: &[u8]) -> Vec<String> {
        frames(sse)
            .into_iter()
            .filter(|(name, data)| {
                name == "content_block_delta" && data["delta"]["type"] == "text_delta"
            })
            .map(|(_, data)| {
                data["delta"]["text"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }

    fn thinking_deltas(sse: &[u8]) -> Vec<String> {
        frames(sse)
            .into_iter()
            .filter(|(name, data)| {
                name == "content_block_delta" && data["delta"]["type"] == "thinking_delta"
            })
            .map(|(_, data)| {
                data["delta"]["thinking"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }

    fn tool_inputs(sse: &[u8]) -> Vec<String> {
        frames(sse)
            .into_iter()
            .filter(|(name, data)| {
                name == "content_block_delta" && data["delta"]["type"] == "input_json_delta"
            })
            .map(|(_, data)| {
                data["delta"]["partial_json"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }

    /// Asserts the Anthropic SSE contract that a stopped content block never
    /// receives another event.
    fn assert_no_event_after_block_stop(sse: &[u8]) {
        let mut stopped: Vec<u64> = Vec::new();
        for (name, data) in frames(sse) {
            let index = data["index"].as_u64();
            match name.as_str() {
                "content_block_stop" => {
                    let index = index.expect("stop carries an index");
                    assert!(
                        !stopped.contains(&index),
                        "block {index} stopped twice: {:?}",
                        frame_names(sse)
                    );
                    stopped.push(index);
                }
                "content_block_delta" | "content_block_start" => {
                    let index = index.expect("block event carries an index");
                    assert!(
                        !stopped.contains(&index),
                        "block {index} received {name} after its content_block_stop: {:?}",
                        frame_names(sse)
                    );
                }
                _ => {}
            }
        }
    }

    // ==================================================================
    // Step 1: happy path
    // ==================================================================

    #[tokio::test]
    async fn happy_path_emits_a_complete_anthropic_sse_sequence() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"Hello"}{"content":" world"}{"contextUsagePercentage":5}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("happy path should succeed");
        assert_eq!(
            frame_names(&sse),
            vec![
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        assert_eq!(text_deltas(&sse).concat(), "Hello world");
        let start = find_frame(&sse, "content_block_start").unwrap();
        assert_eq!(start["content_block"]["type"], "text");
        assert_eq!(start["index"], 0);
        let delta = find_frame(&sse, "message_delta").unwrap();
        assert_eq!(delta["delta"]["stop_reason"], "end_turn");
        assert!(delta["usage"]["output_tokens"].as_u64().unwrap() > 0);
        assert_no_event_after_block_stop(&sse);
    }

    // ==================================================================
    // Step 2: true incremental delivery
    // ==================================================================

    #[tokio::test]
    async fn frames_reach_the_sink_before_the_upstream_finishes_writing() {
        let server = spawn_kiro_mock(
            vec![Script::chunks(vec![
                (Duration::ZERO, r#"{"content":"Hello"}"#),
                (Duration::from_millis(30), r#"{"content":" world"}"#),
                (
                    Duration::from_millis(600),
                    r#"{"contextUsagePercentage":5}"#,
                ),
            ])],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let opts = RunStreamOptions {
            client: &client,
            model: sample_model(),
            req: &req,
            message_id: "msg_kiro_test",
            conversation_id: "conv-fixed-for-the-whole-request",
            reasoning_enabled: false,
            timeouts: fast_timeouts(),
        };

        let run = run_kiro_stream_impl(opts, tx, Some(&server.url), fast_policy());
        let observe = async {
            let mut early = 0usize;
            let mut all = Vec::new();
            while let Some(item) = rx.recv().await {
                if !server.finished_writing() {
                    early += 1;
                }
                all.extend_from_slice(&item.unwrap());
            }
            (early, all)
        };
        let (result, (early, sse)) = tokio::join!(run, observe);

        result.expect("stream should succeed");
        assert!(
            early >= 2,
            "expected at least 2 frames delivered before the upstream finished writing, got {early} (frames: {:?})",
            frame_names(&sse)
        );
        assert_eq!(text_deltas(&sse).concat(), "Hello world");
    }

    // ==================================================================
    // Step 3: tool use
    // ==================================================================

    #[tokio::test]
    async fn tool_use_response_emits_a_tool_block_and_tool_use_stop_reason() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"name":"write","toolUseId":"tc1","input":"{}"}{"stop":true}{"contextUsagePercentage":10}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("tool-use stream should succeed");
        let start = find_frame(&sse, "content_block_start").expect("a content block was started");
        assert_eq!(start["content_block"]["type"], "tool_use");
        assert_eq!(start["content_block"]["id"], "tc1");
        assert_eq!(start["content_block"]["name"], "write");
        assert_eq!(start["content_block"]["input"], json!({}));
        assert_eq!(tool_inputs(&sse), vec!["{}".to_string()]);
        let delta = find_frame(&sse, "message_delta").unwrap();
        assert_eq!(delta["delta"]["stop_reason"], "tool_use");
        assert_no_event_after_block_stop(&sse);
    }

    // ==================================================================
    // Step 4: malformed tool JSON is silently dropped
    // ==================================================================

    #[tokio::test]
    async fn malformed_tool_input_is_dropped_without_surfacing_an_error() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"name":"bash","toolUseId":"tc1","input":"{not json"}{"stop":true}{"contextUsagePercentage":10}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("a dropped tool call is not an error");
        assert!(
            !frames(&sse)
                .iter()
                .any(|(name, data)| name == "content_block_start"
                    && data["content_block"]["type"] == "tool_use"),
            "no tool_use block should be emitted: {:?}",
            frame_names(&sse)
        );
        assert!(tool_inputs(&sse).is_empty());
        assert!(!frame_names(&sse).iter().any(|n| n == "error"));
        let delta = find_frame(&sse, "message_delta").unwrap();
        assert_eq!(
            delta["delta"]["stop_reason"], "end_turn",
            "emitted_tool_calls stays 0, so the turn does not report tool_use"
        );
        assert_eq!(
            server.generate_count(),
            1,
            "a seen-but-dropped tool call must not trigger the empty-response retry"
        );
    }

    // ==================================================================
    // Step 5: split tool input reassembly
    // ==================================================================

    #[tokio::test]
    async fn split_tool_input_is_reassembled_into_one_validated_delta() {
        let server = spawn_kiro_mock(
            vec![Script::chunks(vec![
                (
                    Duration::ZERO,
                    r#"{"name":"write","toolUseId":"tc1","input":"{\"path\":"}"#,
                ),
                (Duration::from_millis(10), r#"{"input":"\"a.txt\","}"#),
                (
                    Duration::from_millis(10),
                    r#"{"input":"\"body\":\"hi\"}"}{"stop":true}{"contextUsagePercentage":10}"#,
                ),
            ])],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("split tool input should succeed");
        assert_eq!(
            tool_inputs(&sse),
            vec![r#"{"path":"a.txt","body":"hi"}"#.to_string()],
            "fragments must be accumulated and emitted once, not forwarded individually"
        );
        let delta = find_frame(&sse, "message_delta").unwrap();
        assert_eq!(delta["delta"]["stop_reason"], "tool_use");
    }

    // ==================================================================
    // Step 6: reasoning content and block ordering
    // ==================================================================

    #[tokio::test]
    async fn reasoning_content_emits_thinking_block_before_text_block() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"<thinking>reasoning</thinking>\n\nanswer"}{"contextUsagePercentage":7}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_case(RunCase {
            server: &server,
            client: &client,
            req: &req,
            reasoning: true,
            timeouts: fast_timeouts(),
            policy: fast_policy(),
        })
        .await;

        result.expect("reasoning stream should succeed");
        let all = frames(&sse);
        let thinking_start = all
            .iter()
            .position(|(n, d)| {
                n == "content_block_start" && d["content_block"]["type"] == "thinking"
            })
            .expect("a thinking block was started");
        let text_start = all
            .iter()
            .position(|(n, d)| n == "content_block_start" && d["content_block"]["type"] == "text")
            .expect("a text block was started");
        assert!(
            thinking_start < text_start,
            "thinking must precede text: {:?}",
            frame_names(&sse)
        );
        assert_eq!(all[thinking_start].1["index"], 0);
        assert_eq!(all[text_start].1["index"], 1);
        assert_eq!(thinking_deltas(&sse).concat(), "reasoning");
        assert_eq!(text_deltas(&sse).concat(), "answer");
        assert_no_event_after_block_stop(&sse);
    }

    #[tokio::test]
    async fn thinking_parser_finalization_runs_before_the_block_is_closed() {
        // The stream ends mid-way through what could be a `</thinking>` close
        // tag, so the parser holds those bytes back until `finalize()` — which
        // emits one last thinking delta. Finalizing AFTER closing the block
        // would put that delta after its own `content_block_stop`.
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"<thinking>abc</think"}{"contextUsagePercentage":7}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_case(RunCase {
            server: &server,
            client: &client,
            req: &req,
            reasoning: true,
            timeouts: fast_timeouts(),
            policy: fast_policy(),
        })
        .await;

        result.expect("unterminated thinking should still finish cleanly");
        assert_eq!(thinking_deltas(&sse).concat(), "abc</think");
        assert_no_event_after_block_stop(&sse);
        let names = frame_names(&sse);
        let last_delta = names
            .iter()
            .rposition(|n| n == "content_block_delta")
            .unwrap();
        let last_stop = names
            .iter()
            .rposition(|n| n == "content_block_stop")
            .unwrap();
        assert!(
            last_delta < last_stop,
            "the finalize() delta must come before the block stop: {names:?}"
        );
    }

    // ==================================================================
    // Step 7: consecutive-duplicate dedup
    // ==================================================================

    #[tokio::test]
    async fn consecutive_duplicate_content_events_are_deduplicated() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"same text"}{"content":"same text"}{"content":"new text"}{"contextUsagePercentage":5}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        assert_eq!(text_deltas(&sse), vec!["same text", "new text"]);
    }

    #[tokio::test]
    async fn non_consecutive_duplicate_content_events_are_both_kept() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"same text"}{"content":"other"}{"content":"same text"}{"contextUsagePercentage":5}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        assert_eq!(
            text_deltas(&sse),
            vec!["same text", "other", "same text"],
            "dedup is strictly against the immediately-previous content event"
        );
    }

    // ==================================================================
    // Step 8: UTF-8 across a chunk boundary
    // ==================================================================

    #[tokio::test]
    async fn multibyte_character_split_across_a_chunk_boundary_is_decoded_correctly() {
        let body = r#"{"content":"café au lait"}{"contextUsagePercentage":5}"#.as_bytes();
        // Split between the two bytes of `é` (0xC3 0xA9).
        let split = body
            .iter()
            .position(|b| *b == 0xC3)
            .expect("é is present in the payload")
            + 1;
        let server = spawn_kiro_mock(
            vec![Script::raw_chunks(
                200,
                vec![
                    (Duration::ZERO, body[..split].to_vec()),
                    (Duration::from_millis(30), body[split..].to_vec()),
                ],
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        let text = text_deltas(&sse).concat();
        assert_eq!(text, "café au lait");
        assert!(
            !text.contains('\u{FFFD}'),
            "a split multi-byte character must not decode to a replacement character"
        );
    }

    #[test]
    fn decode_chunk_retains_only_an_incomplete_trailing_sequence() {
        let mut pending = Vec::new();
        let mut out = String::new();
        decode_chunk(&mut pending, &[b'a', 0xC3], &mut out);
        assert_eq!(out, "a");
        assert_eq!(pending, vec![0xC3]);
        decode_chunk(&mut pending, &[0xA9, b'b'], &mut out);
        assert_eq!(out, "aéb");
        assert!(pending.is_empty());
    }

    #[test]
    fn decode_chunk_skips_genuinely_invalid_bytes_instead_of_stalling() {
        // 0xFF is never valid UTF-8 anywhere. Retaining it (rather than
        // dropping it) would wedge the decoder forever.
        let mut pending = Vec::new();
        let mut out = String::new();
        decode_chunk(&mut pending, &[b'a', 0xFF, b'b'], &mut out);
        assert!(pending.is_empty(), "invalid bytes must not be retained");
        assert!(out.starts_with('a') && out.ends_with('b'), "got {out:?}");
    }

    // ==================================================================
    // Step 9: endpoint and profile resolution
    // ==================================================================

    #[test]
    fn endpoint_is_derived_from_the_credential_region() {
        assert_eq!(
            resolve_endpoint(&far_future_creds("t", "us-west-2", None), None),
            "https://q.us-east-1.amazonaws.com/generateAssistantResponse"
        );
        assert_eq!(
            resolve_endpoint(&far_future_creds("t", "eu-west-1", None), None),
            "https://q.eu-central-1.amazonaws.com/generateAssistantResponse"
        );
        assert_eq!(
            resolve_endpoint(&far_future_creds("t", "eu-central-1", None), None),
            "https://q.eu-central-1.amazonaws.com/generateAssistantResponse"
        );
        assert_eq!(
            resolve_endpoint(&far_future_creds("t", "us-east-1", None), Some("http://x")),
            "http://x/generateAssistantResponse"
        );
    }

    #[tokio::test]
    async fn credential_profile_arn_reaches_the_request_body_without_a_lookup() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"hi"}{"contextUsagePercentage":5}"#,
            )],
            None,
        );
        let (client, _tmp) =
            test_client("tok", "us-east-1", Some("arn:aws:codewhisperer:profile/A"));
        let req = sample_request();

        let (result, _sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        let body = request_body(&server.generate_requests()[0]);
        assert_eq!(body["profileArn"], "arn:aws:codewhisperer:profile/A");
    }

    #[tokio::test]
    async fn resolved_profile_arn_is_cached_and_absent_profiles_are_omitted() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"hi"}{"contextUsagePercentage":5}"#,
            )],
            Some(Script::ok(r#"{"profiles":[]}"#)),
        );
        let (client, _tmp) = test_client("tok", "us-east-1", None);
        let req = sample_request();

        let (result, _sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        assert_eq!(server.profile_request_count(), 1);
        let body = request_body(&server.generate_requests()[0]);
        assert!(
            body.get("profileArn").is_none(),
            "an unresolved profile must be omitted entirely: {body}"
        );
        assert!(PROFILE_CACHE.get(&server.endpoint()).is_none());
    }

    #[tokio::test]
    async fn discovered_profile_arn_is_used_and_cached() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"hi"}{"contextUsagePercentage":5}"#,
            )],
            Some(Script::ok(r#"{"profiles":[{"arn":"arn:from-api"}]}"#)),
        );
        let (client, _tmp) = test_client("tok", "us-east-1", None);
        let req = sample_request();

        let (result, _sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        let body = request_body(&server.generate_requests()[0]);
        assert_eq!(body["profileArn"], "arn:from-api");
        assert_eq!(
            PROFILE_CACHE.get(&server.endpoint()).as_deref(),
            Some("arn:from-api")
        );
        PROFILE_CACHE.invalidate(&server.endpoint());
    }

    // ==================================================================
    // Step 10: first-token timeout retry
    // ==================================================================

    #[tokio::test]
    async fn first_token_timeout_retries_the_whole_request() {
        let server = spawn_kiro_mock(
            vec![
                Script::chunks(vec![(
                    Duration::from_millis(300),
                    r#"{"content":"too late"}"#,
                )]),
                Script::ok(r#"{"content":"on time"}{"contextUsagePercentage":5}"#),
            ],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_case(RunCase {
            server: &server,
            client: &client,
            req: &req,
            reasoning: false,
            timeouts: StreamTimeouts {
                first_token_ms: 50,
                idle_ms: 5_000,
            },
            policy: fast_policy(),
        })
        .await;

        result.expect("the retry should succeed");
        assert_eq!(server.generate_count(), 2);
        assert_eq!(text_deltas(&sse).concat(), "on time");
        assert_eq!(
            frame_names(&sse)
                .iter()
                .filter(|n| *n == "message_start")
                .count(),
            1,
            "a retried attempt must not emit a second message_start"
        );
    }

    // ==================================================================
    // Step 11: 401/403 -> refresh + profile invalidate -> retry
    // ==================================================================

    async fn auth_retry_case(status: u16) {
        let server = spawn_kiro_mock(
            vec![
                Script::error(status, r#"{"error":"expired"}"#),
                Script::ok(r#"{"content":"after refresh"}{"contextUsagePercentage":5}"#),
            ],
            Some(Script::ok(r#"{"profiles":[{"arn":"arn:fresh"}]}"#)),
        );
        let tmp = TempDir::new().unwrap();
        let store = FileAuthStore::new(
            tmp.path().join("auth.json").to_string_lossy().to_string(),
            tmp.path().join("legacy.json").to_string_lossy().to_string(),
        );
        store
            .save(far_future_creds("stale-access", "us-east-1", None))
            .unwrap();
        write_ide_token(tmp.path(), "fresh-access");
        let client =
            KiroHttpClient::for_test(KiroAuthManager::with_deps(store, deps_for(tmp.path())));
        // A stale cached ARN is itself a cause of repeated 401/403s, so the
        // handler must drop it rather than resend it.
        PROFILE_CACHE.set(&server.endpoint(), "arn:stale".to_string());
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.unwrap_or_else(|e| panic!("the {status} retry should succeed, got {e}"));
        let requests = server.generate_requests();
        assert_eq!(requests.len(), 2, "one failed attempt plus one retry");
        assert_eq!(
            header_value(&requests[0], "authorization").as_deref(),
            Some("Bearer stale-access")
        );
        assert_eq!(
            header_value(&requests[1], "authorization").as_deref(),
            Some("Bearer fresh-access"),
            "the retry must use the refreshed credential"
        );
        let first = request_body(&requests[0]);
        let second = request_body(&requests[1]);
        assert_eq!(first["profileArn"], "arn:stale");
        assert_eq!(
            second["profileArn"], "arn:fresh",
            "the cached profile ARN must be invalidated and re-resolved"
        );
        assert_eq!(
            first["conversationState"]["conversationId"],
            second["conversationState"]["conversationId"],
            "conversation_id must never be regenerated across retries"
        );
        assert_eq!(
            first["conversationState"]["conversationId"],
            "conv-fixed-for-the-whole-request"
        );
        assert_eq!(text_deltas(&sse).concat(), "after refresh");
        PROFILE_CACHE.invalidate(&server.endpoint());
    }

    #[tokio::test]
    async fn status_401_refreshes_credentials_invalidates_profile_and_retries() {
        auth_retry_case(401).await;
    }

    #[tokio::test]
    async fn status_403_refreshes_credentials_invalidates_profile_and_retries() {
        auth_retry_case(403).await;
    }

    #[tokio::test]
    async fn auth_failures_stop_after_the_shared_retry_budget() {
        let server = spawn_kiro_mock(vec![Script::error(403, r#"{"error":"nope"}"#)], None);
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, _sse) = run_simple(&server, &client, &req).await;

        assert!(matches!(result, Err(KiroStreamError::Auth(_))));
        assert_eq!(
            server.generate_count(),
            4,
            "the initial attempt plus max_retries=3 retries"
        );
    }

    // ==================================================================
    // Step 12: capacity retries have their own budget
    // ==================================================================

    #[tokio::test]
    async fn capacity_errors_retry_on_their_own_budget_and_then_succeed() {
        let server = spawn_kiro_mock(
            vec![
                Script::error(500, r#"{"reason":"INSUFFICIENT_MODEL_CAPACITY"}"#),
                Script::error(500, r#"{"reason":"INSUFFICIENT_MODEL_CAPACITY"}"#),
                Script::ok(r#"{"content":"capacity freed"}{"contextUsagePercentage":5}"#),
            ],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("the third attempt should succeed");
        assert_eq!(server.generate_count(), 3);
        assert_eq!(text_deltas(&sse).concat(), "capacity freed");
    }

    #[tokio::test]
    async fn exhausted_capacity_budget_is_non_retryable_without_touching_the_outer_budget() {
        let server = spawn_kiro_mock(
            vec![Script::error(
                500,
                r#"{"reason":"INSUFFICIENT_MODEL_CAPACITY"}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();
        let policy = RetryPolicy {
            max_retries: 0,
            ..fast_policy()
        };

        let (result, _sse) = run_case(RunCase {
            server: &server,
            client: &client,
            req: &req,
            reasoning: false,
            timeouts: fast_timeouts(),
            policy,
        })
        .await;

        assert!(
            matches!(result, Err(KiroStreamError::NonRetryable { .. })),
            "expected NonRetryable, got {result:?}"
        );
        assert_eq!(
            server.generate_count(),
            4,
            "capacity retries run their full budget even with the outer budget at 0"
        );
    }

    // ==================================================================
    // Step 13: MONTHLY_REQUEST_COUNT is terminal
    // ==================================================================

    #[tokio::test]
    async fn monthly_request_count_is_non_retryable_immediately() {
        let server = spawn_kiro_mock(
            vec![Script::error(400, r#"{"reason":"MONTHLY_REQUEST_COUNT"}"#)],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        assert!(
            matches!(result, Err(KiroStreamError::NonRetryable { .. })),
            "expected NonRetryable, got {result:?}"
        );
        assert_eq!(server.generate_count(), 1);
        assert!(
            sse.is_empty(),
            "nothing was streamed, so no error frame is synthesized here"
        );
    }

    // ==================================================================
    // Step 14: plain 429 is never retried internally
    // ==================================================================

    #[tokio::test]
    async fn plain_429_is_not_retried_and_preserves_retry_after() {
        let server = spawn_kiro_mock(
            vec![Script::error(429, r#"{"error":"slow down"}"#).with_header("Retry-After", "20")],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, _sse) = run_simple(&server, &client, &req).await;

        match result {
            Err(KiroStreamError::NonRetryable {
                status,
                retry_after,
                ..
            }) => {
                assert_eq!(status, 429);
                assert_eq!(retry_after.as_deref(), Some("20"));
            }
            other => panic!("expected a non-retryable 429, got {other:?}"),
        }
        assert_eq!(server.generate_count(), 1);
    }

    // ==================================================================
    // Step 15: empty-response retry
    // ==================================================================

    #[tokio::test]
    async fn empty_responses_are_retried_until_content_arrives() {
        let server = spawn_kiro_mock(
            vec![
                Script::ok(r#"{"contextUsagePercentage":5}"#),
                Script::ok(r#"{"contextUsagePercentage":5}"#),
                Script::ok(r#"{"content":"finally"}{"contextUsagePercentage":5}"#),
            ],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("the third attempt should succeed");
        assert_eq!(server.generate_count(), 3);
        assert_eq!(text_deltas(&sse).concat(), "finally");
    }

    #[tokio::test]
    async fn an_echo_loop_response_is_not_retried_once_it_has_been_streamed() {
        // The reference retries an "echo loop" (a response that is nothing
        // but "continue"/dots) because its consumer rebuilds the message from
        // snapshots. Anthropic SSE cannot retract a delta that already went
        // out, and an echo response is by definition non-empty text that was
        // streamed the moment it arrived — so this provider detects it, logs
        // it, and completes the turn rather than emitting a second
        // message_start for the same request. See the empty-response tests
        // for the branch of the same check that IS retryable (nothing has
        // been emitted at that point).
        let server = spawn_kiro_mock(
            vec![
                Script::ok(r#"{"content":"Continue"}{"contextUsagePercentage":5}"#),
                Script::ok(r#"{"content":"real answer"}{"contextUsagePercentage":5}"#),
            ],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("an echo response is surfaced, not failed");
        assert_eq!(server.generate_count(), 1);
        assert_eq!(text_deltas(&sse).concat(), "Continue");
        assert_eq!(
            frame_names(&sse)
                .iter()
                .filter(|n| *n == "message_start")
                .count(),
            1
        );
        assert_no_event_after_block_stop(&sse);
    }

    #[tokio::test]
    async fn a_persistently_empty_response_finishes_cleanly_after_the_budget() {
        let server = spawn_kiro_mock(vec![Script::ok(r#"{"contextUsagePercentage":5}"#)], None);
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("an empty response is surfaced, not failed");
        assert_eq!(server.generate_count(), 4);
        assert_eq!(
            frame_names(&sse),
            vec!["message_start", "message_delta", "message_stop"]
        );
        assert_eq!(
            find_frame(&sse, "message_delta").unwrap()["delta"]["stop_reason"],
            "end_turn"
        );
    }

    // ==================================================================
    // Step 16: stream: false accumulation
    // ==================================================================

    #[tokio::test]
    async fn sse_frames_fold_into_one_non_streaming_message() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"Hello"}{"content":" world"}{"name":"write","toolUseId":"tc1","input":"{\"path\":\"a\"}","stop":true}{"contextUsagePercentage":5}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;
        result.expect("stream should succeed");

        let message = accumulate_sse_message(&sse, "msg_kiro_test", "claude-sonnet-4-5");
        assert_eq!(message["type"], "message");
        assert_eq!(message["role"], "assistant");
        assert_eq!(message["id"], "msg_kiro_test");
        assert_eq!(message["model"], "claude-sonnet-4-5");
        assert_eq!(message["content"][0]["type"], "text");
        assert_eq!(message["content"][0]["text"], "Hello world");
        assert_eq!(message["content"][1]["type"], "tool_use");
        assert_eq!(message["content"][1]["id"], "tc1");
        assert_eq!(message["content"][1]["input"]["path"], "a");
        assert_eq!(message["stop_reason"], "tool_use");
        assert!(message["usage"]["output_tokens"].as_u64().unwrap() > 0);
    }

    // ==================================================================
    // Additional behavior locks
    // ==================================================================

    #[tokio::test]
    async fn a_text_block_reopens_after_an_interleaved_tool_call() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"before"}{"name":"t","toolUseId":"tc1","input":"{}","stop":true}{"content":"after"}{"contextUsagePercentage":5}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        // Reasoning enabled: the thinking parser will not re-emit a TextStart
        // for "after" (its text block is still logically open), so the
        // emitter itself must lazily reopen one.
        let (result, sse) = run_case(RunCase {
            server: &server,
            client: &client,
            req: &req,
            reasoning: true,
            timeouts: fast_timeouts(),
            policy: fast_policy(),
        })
        .await;

        result.expect("stream should succeed");
        let starts: Vec<(u64, String)> = frames(&sse)
            .into_iter()
            .filter(|(n, _)| n == "content_block_start")
            .map(|(_, d)| {
                (
                    d["index"].as_u64().unwrap(),
                    d["content_block"]["type"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            starts,
            vec![
                (0, "text".to_string()),
                (1, "tool_use".to_string()),
                (2, "text".to_string()),
            ]
        );
        assert_eq!(text_deltas(&sse), vec!["before", "after"]);
        assert_no_event_after_block_stop(&sse);
    }

    #[tokio::test]
    async fn usage_event_overrides_the_context_usage_estimate() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"hi"}{"contextUsagePercentage":10}{"usage":{"inputTokens":500,"outputTokens":200}}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        let delta = find_frame(&sse, "message_delta").unwrap();
        assert_eq!(delta["usage"]["input_tokens"], 500);
        assert_eq!(delta["usage"]["output_tokens"], 200);
    }

    #[tokio::test]
    async fn context_usage_seeds_input_tokens_when_no_usage_event_arrives() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"hi"}{"contextUsagePercentage":10}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        let delta = find_frame(&sse, "message_delta").unwrap();
        // sample_model()'s context window is 200_000 -> 10% -> 20_000.
        assert_eq!(delta["usage"]["input_tokens"], 20_000);
    }

    #[tokio::test]
    async fn a_response_with_no_context_usage_reports_stop_reason_length() {
        let server = spawn_kiro_mock(vec![Script::ok(r#"{"content":"partial"}"#)], None);
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        result.expect("stream should succeed");
        assert_eq!(
            find_frame(&sse, "message_delta").unwrap()["delta"]["stop_reason"],
            "length"
        );
    }

    #[tokio::test]
    async fn a_mid_stream_error_event_after_content_terminates_with_an_error_frame() {
        let server = spawn_kiro_mock(
            vec![Script::ok(
                r#"{"content":"partial"}{"error":"ThrottlingException","message":"slow down"}"#,
            )],
            None,
        );
        let (client, _tmp) = test_client("tok", "us-east-1", Some("arn:test"));
        let req = sample_request();

        let (result, sse) = run_simple(&server, &client, &req).await;

        assert!(
            matches!(result, Err(KiroStreamError::Other(_))),
            "expected Other, got {result:?}"
        );
        assert_eq!(
            server.generate_count(),
            1,
            "content was already streamed, so the request must not be retried"
        );
        let names = frame_names(&sse);
        assert_eq!(
            names.last().map(String::as_str),
            Some("error"),
            "a client already consuming the stream must see a clean termination: {names:?}"
        );
    }

    #[test]
    fn exponential_backoff_doubles_and_saturates() {
        assert_eq!(exponential_backoff(0, 500, 10_000), 500);
        assert_eq!(exponential_backoff(1, 500, 10_000), 1_000);
        assert_eq!(exponential_backoff(2, 500, 10_000), 2_000);
        assert_eq!(exponential_backoff(0, 5_000, 30_000), 5_000);
        assert_eq!(exponential_backoff(2, 5_000, 30_000), 20_000);
        assert_eq!(exponential_backoff(3, 5_000, 30_000), 30_000);
        assert_eq!(exponential_backoff(99, 1_000, 10_000), 10_000);
    }
}
