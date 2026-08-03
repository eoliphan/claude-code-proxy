# Kiro provider — design

Date: 2026-08-03
Status: Approved, pending implementation plan

## Why

claude-code-proxy already translates Claude Code's Anthropic API traffic to
Codex, Kimi, Cursor Agent, and Grok. Kiro (AWS CodeWhisperer/Q) is a fifth
subscription-backed backend worth adding: it has good quota-based pricing and,
unlike the GPT/Kimi backends, actually serves real Claude Sonnet/Opus/Haiku
tiers alongside third-party models (DeepSeek, Kimi, MiniMax, GLM, Qwen).

A reference implementation already exists at `../pi-provider-kiro`, a
TypeScript provider extension for the `pi` coding agent that speaks Kiro's
auth, model catalog, and streaming protocol. This design ports that protocol
knowledge into a native Rust provider following this proxy's existing
`Provider`/`CliHandlers` trait shape.

## Scope

### In scope for v1

- Native SSO-OIDC device-code login (IAM Identity Center / Builder ID)
- Credential reuse from two additional sources ahead of the device-code flow:
  the Kiro IDE's token file, and kiro-cli's SQLite credential store
- Token refresh (direct OIDC, and Kiro's separate "desktop" refresh endpoint
  for social-login-flavored credentials obtained via reuse)
- Dynamic model discovery via `ListAvailableModels`, cached with a static
  fallback list
- Full request/response translation: alternating history, tool calls, images,
  streaming, `<thinking>`-tag reasoning
- Kiro-specific retry/error handling (403 auth races, empty-stream retry,
  non-retryable body markers)
- `CliHandlers`: `login` / `device` / `status` / `logout`
- Registry routing fix (see below) so Kiro model IDs that collide with the
  existing Anthropic-alias list route correctly
- `AliasProvider::Kiro`, so bare `sonnet`/`opus`/`haiku`/`claude-*` aliases can
  be configured to route to real Claude models running on Kiro's quota

### Explicitly deferred (not v1)

- **Native Google/GitHub social login.** The reference delegates this to the
  `kiro-cli` binary's own browser-based login flow, which doesn't fit a
  self-contained Rust process. If a user has already logged in that way via
  `kiro-cli`, the credential-reuse path picks up and refreshes those tokens
  fine (Kiro's "desktop" refresh endpoint isn't IDC-specific) — this proxy
  just can't *initiate* a Google/GitHub login itself.
- **Bracket-tool-parser.** Only relevant if some specific Kiro-hosted model
  emits bracket-style tool syntax instead of native tool-call events. Add
  later if a concrete model requires it.
- **Precise input-token accounting.** Kiro only reports
  `contextUsagePercentage`, not real token counts. `count_tokens.rs` will
  return an honest estimate rather than porting the reference's
  `content.length / 4` guess as if it were exact.

## Registry routing

`Registry::provider_for_model` (registry.rs:142) resolves in order:
Anthropic alias → cursor prefix → linear scan of each provider's static model
list. It does not consult `Provider::supported_models()`. Several real Kiro
model IDs (`claude-sonnet-4-6`, `claude-haiku-4-5`, `claude-opus-4-7`,
`claude-opus-4-8`) are byte-identical to entries in
`ANTHROPIC_STYLE_ALIASES`. Left alone, requesting those literal IDs would be
hijacked by the alias branch and routed to whichever provider is configured
as the default alias target, not Kiro, unless Kiro itself is the alias
provider.

Fix, following the precedent `cursor:` already sets:

- Add `kiro:` as an explicit prefix (`is_kiro_model`, alongside
  `is_cursor_model`) for unambiguous selection of any Kiro-hosted model
  regardless of alias config — e.g. `kiro:claude-sonnet-4-6`,
  `kiro:deepseek-3-2`.
- Register a static fallback model list (`KIRO_MODELS` const, same pattern as
  `KIMI_MODELS`/`GROK_MODELS`) into `Registry::new`'s `models` map so bare
  (unprefixed) literal IDs that don't collide with the alias list —
  `deepseek-3-2`, `kimi-k2-5`, `minimax-m2-5`, `glm-5`, etc. — route via the
  normal linear scan without needing the prefix.
- Add `"kiro" => Arc::new(KiroProvider::new())` to the `handlers` match in
  `Registry::new`, and explicit `"kiro"` arms to `PlaceholderProvider::new`
  and `PlaceholderCli` (both currently silently default unknown provider
  names to `"codex"` — fix as part of this change so a misconfigured/missing
  arm can't silently answer as the wrong provider).
- Add `AliasProvider::Kiro` to `config.rs`.
- `translate/model_allowlist.rs`, mirroring Kimi's, maps every alias string to
  a concrete Kiro model ID **per tier** (not one default like Kimi does),
  sourced from the dynamic catalog when available and falling back to the
  static list. Separately, a regex (`(\d)-(\d)` → `$1.$2`) converts dash-form
  IDs like `claude-sonnet-4-6` to the dot-form (`claude-sonnet-4.6`) Kiro's
  API actually expects — same conversion as the reference's
  `resolveKiroModel()`. Aliases with no matching real tier in Kiro's catalog
  (e.g. `fable`/`claude-fable-5`) fall back to the nearest available tier;
  the implementation plan pins down the exact fallback per alias.

## Auth

Module layout: `src/providers/kiro/auth/` — `manager.rs`, `device.rs`
(SSO-OIDC device-code flow), `token_store.rs`, plus two Kiro-specific
credential sources: `kiro_ide.rs` and `kiro_cli.rs`.

**Credential shape** — a `KiroCredentials` struct with `access`, `refresh`,
`expires`, `region`, `auth_method` (`Idc` | `Desktop`), and
`client_id`/`client_secret` (needed for IDC refresh). The reference packs
these into a single pipe-delimited `refresh` string; this port stores them as
real struct fields in the token file instead — same information, no
behavior change.

**Bootstrap cascade**, in priority order (mirrors the reference's
`loginKiro`):

1. **Kiro IDE token file** — `~/.aws/sso/cache/kiro-auth-token.json`, plus a
   companion `~/.aws/sso/cache/{clientIdHash}.json` holding the OIDC client
   registration. Plain JSON reads via `serde_json`, no SQLite, no shelling
   out. Home-directory resolution reuses this proxy's existing
   `HOME`/`USERPROFILE` lookup in `paths.rs` rather than adding a `dirs`
   crate. Checked first because the IDE keeps this token continuously
   refreshed.
2. **kiro-cli SQLite DB** — read the `auth_kv` table for
   `kirocli:odic:token` (IDC, preferred — carries client_id/client_secret for
   refresh) then `kirocli:social:token` (desktop/social) as fallback. Read via
   the `rusqlite` crate (bundled feature) — a new dependency, chosen over
   shelling out to a `sqlite3` binary to keep the proxy self-contained and
   avoid shelling out on a credential-read path.
3. If both are expired: attempt a silent refresh, IDE credentials first, then
   kiro-cli credentials, before falling through.
4. **Native device-code login** (IDC/Builder ID via
   `https://oidc.{region}.amazonaws.com`) as the last resort — same shape as
   `kimi/auth/login.rs`'s `run_device_login` (RegisterClient →
   StartDeviceAuthorization → poll CreateToken).

**Ongoing refresh** (invoked from the client on 401/403, or proactively near
expiry): re-check the IDE file first (cheap, no network), then the kiro-cli
DB, then perform a direct OIDC refresh — POST to `{ssoEndpoint}/token` using
the stored `client_id`/`client_secret`/`refresh_token` for IDC-flavored
credentials, or POST to
`https://prod.{region}.auth.desktop.kiro.dev/refreshToken` for
desktop-flavored credentials obtained via reuse. After a successful direct
refresh, write the new tokens back into kiro-cli's SQLite DB if it exists, so
both stay in sync. If a direct refresh fails, re-read the kiro-cli DB once
more before giving up, in case it rotated the token first.

## Request/response translation & streaming

`translate/` module, mirroring `codex/translate/`:

- **`request.rs`** — builds Kiro's request body: strict alternating
  `userInputMessage`/`assistantResponseMessage` history (tool results wrapped
  in synthetic user messages, per the reference's `buildHistory()`), tool
  specs converted from Anthropic tool defs, images passed through. Reuses
  `translate_shared.rs`'s existing `normalize_content`/`image_block_to_url`
  helpers rather than reimplementing content-block parsing.
- **`stream.rs`** — Kiro's stream is not SSE; it is a raw byte buffer
  containing back-to-back JSON objects. Port `parseKiroEvents`'s
  boundary-scanning logic (`findJsonEnd`/`findNextEventStart`) into a
  `KiroStreamEvent` enum plus an incremental parser, then translate each
  event into the Anthropic streaming event shape the client expects — same
  responsibility as `codex/translate/live_stream.rs`.
- **`reasoning.rs`** (or folded into `stream.rs`) — port the `<thinking>` tag
  streaming parser for reasoning-capable models.
- **`count_tokens.rs`** — returns an honest estimate; see "Explicitly
  deferred" above.

## Error handling & retry

`client.rs` mirrors `kimi/client.rs`'s loop shape (blocking `reqwest` client,
`attempt_post` plus a retry loop) with Kiro-specific extensions:

- 401 **and** 403 both trigger one refresh-and-retry (Kiro uses 403 for some
  auth races that Kimi doesn't hit)
- 429 → existing shared backoff (`retry.rs::compute_backoff_delay`), unchanged
- Non-retryable body markers (`MONTHLY_REQUEST_COUNT`,
  `INSUFFICIENT_MODEL_CAPACITY`) are checked before any retry decision —
  these are quota/capacity errors retrying won't fix, so they surface to the
  client immediately instead of burning the retry budget
- First-token-timeout and empty-stream retry live in `stream.rs` (the
  *streaming* response stalling, not the initial POST) — one retry attempt
  with a fresh connection, then surface the error

## Testing

Same shape as the existing `tests/` layout: unit tests colocated per Rust
module (event-parser boundary cases, history-alternation edge cases,
alias/dot-vs-dash model resolution, auth-cascade priority order with mocked
file/DB sources), plus integration-level tests (e.g. `tests/kiro_*.rs`)
exercising registry routing and CLI handlers, following
`tests/codex_websocket.rs`'s pattern for a provider with both auth and
streaming to cover. `rusqlite`'s in-memory mode keeps the
kiro-cli-DB-reading tests straightforward without touching a real file.
