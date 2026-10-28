# Fork Maintenance

This repo is a fork of `raine/claude-code-proxy` (remote `upstream`). The fork adds the Kiro provider and a few routing decisions that differ from upstream. Agents follow this file when they merge upstream, or add a model or provider.

## Remotes and branches

- `origin`: `eoliphan/claude-code-proxy` (this fork).
- `upstream`: `raine/claude-code-proxy`.
- `main` tracks `upstream/main` and carries fork commits on top.
- Sync with a merge commit, not a rebase. A rebase replays every fork commit and repeats old conflicts.
- Sync on a branch named `sync/upstream-<short-sha>`. Open a PR. Never push a sync directly to `main`.

## Fork decisions (keep these on every merge)

| Decision | Where it lives | Rule |
| --- | --- | --- |
| Fable aliases route to `gpt-6-astra` | `resolve_model_alias` in `src/providers/codex/translate/model_allowlist.rs`, `is_fable_alias` in `src/registry.rs` | Upstream maps `fable` and `claude-fable-5` to `gpt-6-sol`. Keep the fork mapping. |
| `gpt-6-astra` uses the full Responses API | `uses_responses_lite` in `model_allowlist.rs` | Do not add `gpt-6-astra` to the lite list. Add new upstream Sol or Luna models to the list. |
| Kiro is a real provider | `src/providers/kiro/`, `KIRO_PREFIX` and `is_kiro_model` in `src/registry.rs`, `AliasProvider::Kiro` in `src/config.rs`, `is_alias_routable_provider` in `src/session.rs`, `Commands::Kiro` and `print_models` in `src/main.rs` | Keep every Kiro line when upstream edits a neighbouring line. |
| The `kiro:` prefix forces Kiro routing | `is_kiro_model` in `src/registry.rs` | A bare model id still follows alias routing. |

Update this table in the same PR when a new fork decision is made.

## Files that conflict most often

- `CHANGELOG.md`: keep the fork `Unreleased` section above the newest upstream release section. Keep both.
- `src/registry.rs`: upstream edits model lists and alias tables. Keep upstream additions and the Kiro hooks.
- `src/providers/codex/translate/model_allowlist.rs`: merge upstream model additions into the fork's alias logic.
- `tests/server.rs`: keep both sets of assertions.
- `Cargo.toml` and `Cargo.lock`: take the upstream version number. Keep the fork dependencies for Kiro.

## Merge procedure

1. Run `git fetch upstream` and read `git log main..upstream/main`.
2. Create the branch `sync/upstream-<short-sha>` from `main`.
3. Run `git merge upstream/main`.
4. If a conflict appears, resolve it with the decision table above. If a rule is unclear, stop and ask in the PR.
5. Check for silent drift: run `git diff main...upstream/main -- src/registry.rs src/providers/codex src/config.rs src/session.rs` and look for upstream changes that bypass a fork decision without a conflict marker.
6. Run `just check-ci`. Fix failures. Do not delete or weaken a test to make it pass.
7. Add the upstream changes to the `CHANGELOG.md` `Unreleased` section when the merge brings user-visible changes.
8. Open a PR. Describe each conflict and how you resolved it. List any upstream change that touches a fork decision.

## Adding a model to a provider

Use the Kiro Opus 5.5 commits as the reference: `8c6f3ec`, `45dbbfe`, `f7c6f19`.

1. Add the model to the provider's model table (for Kiro: `src/providers/kiro/translate/models.rs`).
2. Add or change aliases only when the issue asks for it. Check that an alias does not move an existing alias target.
3. Add tests next to the existing alias and model-list tests.
4. Add one line to the `CHANGELOG.md` `Unreleased` section.
5. Update `docs/src/content/docs/providers/<provider>.md` and `using/models-and-routing.md` when the model list or routing text changes.
6. Run `just check-ci`.

## Rules for automated runs

- Open a PR for every change. Never push to `main`.
- Do not change a fork decision unless the issue says so. Name the decision and the issue in the PR.
- Stop and comment on the issue when the request is ambiguous or a fork decision conflicts with it.
