---
title: Kiro
description: Configure Kiro (AWS CodeWhisperer/Q) authentication, credential reuse, model selection, thinking, and retry behavior.
---

Kiro uses AWS CodeWhisperer/Q's streaming endpoint at
`https://q.{api-region}.amazonaws.com` (`GenerateAssistantResponse`), backed
by AWS SSO-OIDC at `https://oidc.{region}.amazonaws.com`.

## Account and authentication

Use an **AWS IAM Identity Center (org SSO)** account or an **AWS Builder
ID**:

```sh
claude-code-proxy kiro auth login
claude-code-proxy kiro auth status
claude-code-proxy kiro auth logout
```

`login` prompts for your organization's IAM Identity Center start URL, or
press Enter to use Builder ID instead. `device` is the same device-code
flow as `login`; Kiro has no separate browser-redirect mode.

Unlike the other providers, Kiro **can** reuse credentials from outside the
proxy before falling back to its own login. In priority order:

1. An existing **Kiro IDE** token
   (`~/.aws/sso/cache/kiro-auth-token.json`), if present and valid.
2. An existing **kiro-cli** login, read from its local SQLite credential
   store.
3. A silent refresh of either of the above, if expired.
4. The proxy's own native device-code login, as a last resort.

Ongoing token refresh follows the same order, plus a direct OIDC refresh
(IAM Identity Center-flavored credentials) or Kiro's separate desktop
refresh endpoint (credentials obtained via reuse from a Google/GitHub
social login). A successful direct refresh writes the new tokens back into
kiro-cli's database when it exists, so both stay in sync. Refreshes are
single-flighted: concurrent requests share one in-flight refresh instead of
racing separate ones. See [Files and storage](/reference/files-and-storage/)
for exact credential paths.

## Models

Kiro serves real Claude Sonnet/Opus/Haiku tiers alongside third-party
models (DeepSeek, Kimi, MiniMax, GLM, Qwen). Use `claude-code-proxy models`
for the current catalog; the list is fetched dynamically via
`ListAvailableModels` and cached, with a static fallback list.

Several Kiro model IDs (for example `claude-sonnet-4-6`) are byte-identical
to this proxy's Anthropic-style aliases. Use the explicit `kiro:` prefix to
select a Kiro model unambiguously regardless of alias configuration:

```sh
ANTHROPIC_MODEL=kiro:claude-sonnet-4-6
ANTHROPIC_SMALL_FAST_MODEL=kiro:claude-haiku-4-5
```

Setting `CCP_ALIAS_PROVIDER=kiro` (or `"aliasProvider": "kiro"`) routes
bare Anthropic-style aliases (`sonnet`, `opus`, `haiku`, `claude-*`) to real
Claude models running on Kiro's quota instead of Codex or Kimi. See
[Models and routing](/using/models-and-routing/).

## Reasoning

Reasoning-capable Kiro models stream `<thinking>`-style tags (four
recognized tag-pair variants), which the proxy parses incrementally into
Claude Code thinking blocks.

## Tools and multimodal input

- Claude function tools and tool results translate to Kiro's tool-call
  shape.
- Kiro requires strictly alternating `userInputMessage` /
  `assistantResponseMessage` history; tool results are wrapped in
  synthetic user messages to preserve that alternation.
- Images are passed through.

## Retry behavior

Kiro's error handling is more specific than a generic backoff:

- `401` and `403` both trigger one refresh-and-retry, sharing a retry
  budget with stream-stall and empty-stream retries.
- `INSUFFICIENT_MODEL_CAPACITY` is retried up to 3 times with its own
  separate, dedicated backoff budget.
- `MONTHLY_REQUEST_COUNT` (quota exhaustion) is never retried and surfaces
  immediately.
- A plain 429 or 5xx (not an auth or capacity error) is not retried
  internally; it propagates immediately with any `Retry-After` header
  forwarded.

## Limitations

- Native Google/GitHub social login is not implemented directly. If
  you've already signed in that way through kiro-cli, credential reuse
  picks up and refreshes those tokens; the proxy just can't initiate that
  login itself.
- Count-tokens is a heuristic estimate. Kiro only reports
  `contextUsagePercentage`, not exact token counts.

See [Compatibility and limitations](/reference/compatibility-and-limitations/)
for shared boundaries and [Configuration](/reference/configuration/) for
defaults.
