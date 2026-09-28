# Kiro quickstart (this fork)

Practical, personal-use notes for running Kiro through `eoliphan/claude-code-proxy`
day to day. For the polished reference page, see
`docs/src/content/docs/providers/kiro.md` (part of the docs site). For how
Kiro was built, see `2026-08-03-kiro-provider-design.md` and
`2026-08-03-kiro-provider-plan.md` in this same directory.

## Why this doc exists

Kiro only exists on this fork — upstream (`raine/claude-code-proxy`) doesn't
have it. The default install methods (`brew install
raine/claude-code-proxy/claude-code-proxy`, the `install.sh` release
script) both pull upstream release binaries, which will **not** have Kiro.
You have to build from this fork's source.

## 1. Install from this fork

Prebuilt release binaries also won't work reliably on this box: they need
glibc 2.39+ and this box has 2.35. Always build from source:

```sh
cd ~/IdeaProjects/claude-code-proxy   # this fork, origin = eoliphan/claude-code-proxy
cargo install --path .
```

This replaces whatever's at `~/.cargo/bin/claude-code-proxy` (which is
first on `$PATH`, ahead of any homebrew install). Verify you're running the
fork, not a stray upstream build:

```sh
claude-code-proxy --version           # should match this repo's Cargo.toml version
claude-code-proxy models | grep kiro  # should list ~22 kiro models
```

Re-run `cargo install --path .` after pulling new commits (upstream merges,
local fixes) to pick them up — the installed binary doesn't update itself.

## 2. Authenticate

```sh
claude-code-proxy kiro auth login
```

You'll be prompted for your organization's IAM Identity Center start URL
(press Enter instead for personal AWS Builder ID). This opens a
device-code browser flow — visit the printed URL and approve the code
**promptly**, it expires in ~5–10 minutes.

If you already have a working `kiro-cli` login on this machine, the proxy
may adopt it automatically instead of prompting — this only works for the
IDC/org-SSO flow, and only if `kiro-cli`'s SQLite store has a
currently-valid (non-expired) token.

Check status any time:

```sh
claude-code-proxy kiro auth status
claude-code-proxy kiro auth logout   # clears the proxy's own stored credential
```

## 3. Model tiers

Kiro model IDs collide with this proxy's built-in Anthropic-style aliases
(e.g. `claude-sonnet-4-6` is both a real Kiro model and an alias target),
so the explicit `kiro:` prefix is what forces routing to Kiro:

```sh
ANTHROPIC_MODEL=kiro:claude-opus-5-5[1m]        # best, 1M context
ANTHROPIC_MODEL=kiro:claude-sonnet-4-6[1m]      # mid, 1M context
ANTHROPIC_MODEL=kiro:claude-haiku-4-5           # fast/cheap, 200K context (no [1m])
```

Full current catalog (DeepSeek, Kimi, MiniMax, GLM, Qwen tiers too):

```sh
claude-code-proxy models | grep kiro
```

## 4. Day-to-day: `cldk`

`~/.config/fish/functions/cldk.fish` mirrors the existing `cldo` (Codex)
function — same flag DSL, auto-starts the proxy on `:18765` if nothing's
listening there yet.

```sh
cldk                 # interactive, claude-opus-5-5
cldk "fix the bug"   # with a prompt
cldk c                # continue
cldk hkp "quick q"    # haiku + print
cldk opcvs "task"     # opus + continue + verbose + skip permissions
```

## 5. Watching the monitor on an already-running proxy

If `cldk` auto-started the proxy detached (the normal case), there's no
monitor TUI visible by default. Attach to it from another terminal:

```sh
claude-code-proxy monitor
```

This works against any running `claude-code-proxy serve` process,
including `--no-monitor`. It reads the proxy's `/monitor` endpoint (loopback
peers only) and renders the same view as `serve`'s built-in TUI. Use
`--url` for a non-default address. Quitting the dashboard (`q` or Ctrl-C)
does **not** stop the proxy. This is upstream's command since v0.1.40; it
replaced the fork's earlier `attach` command.

## 6. Known gotchas (already handled, worth knowing about)

- **Tool names over 64 characters** (routine with several active MCP
  servers, e.g. `mcp__plugin_project-management_jira-confluence__...`)
  used to make Kiro reject the entire request. Fixed — names are shortened
  automatically and translated back transparently. If you ever see
  `REQUEST_BODY_INVALID` from Kiro again, this is the first thing to
  check.
- **Count-tokens is a heuristic estimate.** Kiro's API only reports
  `contextUsagePercentage`, not exact token counts.
- **No native Google/GitHub social login.** If you've logged into Kiro
  that way via `kiro-cli`, credential reuse can pick up and refresh those
  tokens, but the proxy can't *initiate* that login itself.

## 7. Keeping this fork in sync with upstream

```sh
git fetch upstream
git diff --name-only <last-merged-upstream-commit> main   # check for file overlap first
git merge upstream/main --no-commit --no-ff
# resolve any conflicts, then:
just check
git commit
git push origin main
```

Registry/CLI/config files (`src/registry.rs`, `src/main.rs`,
`src/config.rs`, `src/session.rs`) are the highest-conflict-risk spots —
upstream tends to add new providers at the same insertion points our Kiro
work does. CHANGELOG.md conflicts on nearly every merge (both sides add
entries at the top) — always resolve by keeping both, ours first under
`## Unreleased`.
