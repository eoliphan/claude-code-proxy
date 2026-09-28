# Kiro provider — function point sizing & cost justification

Date: 2026-08-05
Scope: IFPUG-style function point count of the Kiro backend provider
(merge commit `5b1822f`), for cost-justification purposes.

## Headline numbers

| Metric | Value |
|---|---|
| Unadjusted Function Points (UFP) | **62 FP** |
| Traditional delivery effort (Capers Jones benchmark, 8–11 hrs/FP for modern languages) | **496–682 hours** |
| Traditional-equivalent cost (mid-market dev firm, $120–250/hr) | **$59,520 – $170,500** |
| Traditional-equivalent cost (at your own $200/hr rate) | **$99,200 – $136,400** |
| Actual cost incurred (API token spend + your setup time) | **≈ $265.83** ($215.83 API + ~$50 your time) |
| Implied cost ratio | **~225x – 640x cheaper** than benchmark-rate traditional delivery |

## Methodology note — why real counting, not backfiring

Backfiring (SLOC → FP via a language ratio) was deliberately **not used**.
Two reasons: (1) Rust has no official published Capers Jones SLOC/FP ratio
— any number would be an extrapolation from adjacent languages, not a
sourced fact; (2) more importantly, backfiring penalizes exactly the kind
of engineering discipline this delivery had — tight, non-duplicated code
that does more with less. A real IFPUG count sizes *delivered business
functionality* (data groups and elementary processes), independent of how
many lines it took to write. For reference only, the diff was 16,640
inserted lines across 30 files (`git show 5b1822f --stat`) — that number
plays no role in the FP count below.

Counting basis: the actual merged source (`src/providers/kiro/**`,
`src/main.rs`, `src/registry.rs`, `src/config.rs`, `src/session.rs`), read
directly rather than recalled from memory, to get real DET/RET/FTR counts.
No Value Adjustment Factor (VAF) is applied — VAF requires scoring 14
General System Characteristics for the *whole* system, which is out of
scope for a single feature addition. UFP is used as the headline number;
industry $/hour-per-FP benchmarks are usually quoted against UFP or AFP
fairly interchangeably, with VAF typically moving the number by roughly
±10–20%, so UFP is a reasonable and slightly conservative stand-in here.

Complexity ratings below were kept deliberately conservative (Low/Average
favored over High wherever the count was ambiguous) to keep the number
defensible rather than inflated.

## Data functions (ILF / EIF)

| # | Name | Type | RET | DET | Complexity | FP |
|---|---|---|---|---|---|---|
| 1 | Kiro credential record (`KiroCredentials`: access, refresh, expires, region, auth_method, client_id, client_secret, profile_arn, expiry_buffer_ms) | ILF | 1 | 9 | Low | 7 |
| 2 | Kiro IDE token file + client-registration file (`~/.aws/sso/cache/kiro-auth-token.json` + companion) | EIF | 2 | 7 | Low | 5 |
| 3 | kiro-cli SQLite credential store (`auth_kv`: token value + device registration rows) | EIF | 2 | 7 | Low | 5 |
| 4 | Kiro model catalog (dynamic, via `ListAvailableModels`) | EIF | 1 | 6 | Low | 5 |
| | | | | | **Subtotal** | **22** |

Excluded from the count: the static 20-entry `KIRO_MODELS` fallback table
and the in-process `MODEL_CACHE`/`PROFILE_CACHE` — these are code
tables/runtime caches with no independent maintenance transaction of
their own, not IFPUG-countable data groups.

## Transactional functions (EI / EO / EQ)

| # | Name | Type | FTR | DET | Complexity | FP |
|---|---|---|---|---|---|---|
| A | Explicit login (`kiro auth login` / `device` — IDE reuse → kiro-cli reuse → device-code fallback, prompts for org SSO URL) | EI | 3 | 16+ | High | 6 |
| B | On-demand credential resolution & refresh (the singleflight-protected, generation-counter cascade invoked transparently before/during a request: IDE recheck, kiro-cli recheck, direct IDC refresh, direct Desktop refresh, graceful-degradation fallback) | EI | 3 | 16+ | High | 6 |
| C | `kiro auth logout` | EI | 1 | 4 | Low | 3 |
| D | Send message (Anthropic request → `build_kiro_request` → `GenerateAssistantResponse` dispatch, incl. tool defs, images, alternating-history repair) | EI | 2 | 16+ | High | 6 |
| E | Streaming response translation (Kiro's raw JSON-object stream → Anthropic SSE events, incl. `<thinking>`-tag state machine) | EO | 1 | 20+ | Avg | 5 |
| F | Non-streaming response assembly | EO | 1 | 10 | Low | 4 |
| G | Count-tokens estimate | EO | 1 | 3 | Low | 4 |
| H | `kiro auth status` | EQ | 1 | 5 | Low | 3 |
| I | Model listing (`/v1/models` exposure) | EQ | 1 | 4 | Low | 3 |
| | | | | | **Subtotal** | **40** |

Deliberately *not* counted as separate transactions: the `kiro:` registry
routing/alias-collision fix and the model-allowlist alias resolution —
these are internal dispatch plumbing supporting transactions D and I, not
independent user-facing elementary processes. `device()` is not counted
separately from `login()` — it's a literal code-level delegation to the
same function, not a distinct elementary process.

## Total

**UFP = 22 (data) + 40 (transactions) = 62 function points**

## Cost comparison

Benchmark source: Capers Jones' widely-cited effort figure for modern
programming languages — **8–11 staff-hours per function point** for a
competent professional (down from ~14 hrs/FP historically for older
languages). ([IFPUG](https://ifpug.org/), summarized via
[CERM Academy](https://insights.cermacademy.com/14-sources-of-software-benchmarks-c-capers-jones-2/),
[ResearchGate](https://www.researchgate.net/publication/274638632_What_Is_the_Cost_of_One_IFPUG_Method_Function_Point_-_Case_Study))

- Effort: 62 FP × 8–11 hrs/FP = **496–682 hours**
- At mid-market custom dev firm rates ($120–250/hr, per 2025/26 industry
  rate surveys) → **$59,520 – $170,500**
- At your own consulting rate ($200/hr) → **$99,200 – $136,400**

Actual cost incurred: **$215.83** in API-equivalent token spend (see prior
message for the model/cache breakdown) **+ ~$50** of your own time
supervising/steering ≈ **$265.83 total**.

That puts the delivered work at roughly **1/225th to 1/640th** of what
benchmark-rate traditional delivery of the same 62 function points would
have cost — the range reflects the spread in the underlying hours/FP and
$/hr benchmarks, not uncertainty in what was actually spent or delivered.

## Caveats

- This sizes the Kiro provider feature only, not the whole
  claude-code-proxy system.
- No VAF applied (see methodology note) — a full adjustment would move
  the FP count by roughly ±10–20%, not materially change the conclusion.
- The 8–11 hrs/FP and $120–250/hr figures are industry benchmarks, not a
  quote for this specific work — presented as a reasonable, sourced
  reference range for a cost-justification narrative, not a guarantee.
- Complexity ratings on ambiguous items were rounded down (Low/Avg over
  High) to keep the total conservative rather than inflated.
