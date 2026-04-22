# Claude Code Playbook

This file is loaded automatically at Claude Code session start in this repo.
It codifies project conventions so any Claude session follows the same rules
without re-deriving them.

## PR workflow — auto-merge (Phase 1)

When creating a PR via `mcp__github__create_pull_request`, **immediately call
`mcp__github__enable_pr_auto_merge` with `mergeMethod: "SQUASH"`** as a
follow-up, UNLESS one of the guards below triggers.

### Auto-merge guards (skip enabling if any apply)

Mark the PR with label `needs-human-review` instead and do NOT enable
auto-merge if the change:

- touches shared configuration **schemas** (not just values): e.g.
  `x_folder_mapping.json` structure, `x_forced_parents.json` format,
  `pnpm-workspace.yaml` catalog additions
- touches security-sensitive code: auth flow, token storage, path-traversal
  defenses, GITHUB_TOKEN permissions
- touches merge / branch protection / concurrency in `.github/workflows/`
- is marked WIP / draft
- the user explicitly said "don't auto-merge" for this PR
- resolves a non-trivial cross-branch conflict (user judgment needed on
  which side's behavior to preserve)

If a PR is borderline, err on the side of `needs-human-review`.

### After enabling auto-merge

- Keep responding to CI failures and review comments as before
  (push fixes, iterate). Auto-merge stays enabled — GitHub merges as soon
  as required checks pass.
- If a reviewer (CodeRabbit / Codex / human) flags an architectural concern
  mid-flight, add `needs-human-review` label and call
  `mcp__github__disable_pr_auto_merge` to pause.

### Repo-level prerequisite

Auto-merge requires `Allow auto-merge` enabled in repo Settings → General →
Pull Requests. See `docs/branch-protection.md` for the full setup.

## PR conventions

- **Title**: conventional prefix (`feat` / `fix` / `chore` / `docs` /
  `refactor` / `build` / `ci` / `test`), ≤ 70 chars.
- **Body**: always include a "Test plan" section with checkboxes. Reference
  which post-mortem item / issue is being addressed where relevant.
- **Merge method**: squash (keeps main history flat and revertable).
- **Never** force-push to main, delete main, or skip CI hooks.

## CI expectations (must pass before merge)

- `pnpm test` — unit tests (currently ~173+ cases)
- `pnpm typecheck` — root `tsc --noEmit` + workspace-wide `pnpm -r typecheck`
  (depends on core being built first, handled by the root script)
- `.github/scripts/check-package-json-duplicates.py` — rejects duplicate
  JSON keys across all package.json files
- Chrome-extension job — isolated workspace (`--ignore-workspace`),
  independent lockfile

## Claude-vs-Codex experiment

Two independent X bookmarks implementations live side-by-side:

- **Claude side (flat)**: `x_bookmarks_api.ts`, `x_auth_server.ts`,
  `x_folder_mapper.ts`, `x_bookmarks_db.ts`, `hands_on_generator.ts`
- **Codex side (workspace)**: `apps/auth/`, `apps/sync/`, `packages/core/`

Rules:

- **Import graphs do not cross** — Claude side never imports from
  `packages/core`, Codex side never imports from root flat files.
- Only **two shared settings files** by design:
  `<vault>/__skills/pipeline/x_forced_parents.json` and
  `<vault>/__skills/pipeline/x_folder_mapping.json`.
- Output destinations / auth ports / proposal filenames are kept
  distinct to allow concurrent operation.
- When aligning behaviors, **prefer minimal Codex-side changes** per user
  preference — only change Codex when logic/type consistency requires it.

See README "🧪 X ブックマーク取得の対照実験" for full rules.

## Shared dev-tool versions

TypeScript, `@types/node`, and `tsx` are declared in the `catalog:` block
of `pnpm-workspace.yaml`. Bump versions there in a single edit; every
workspace package (root + apps/* + packages/*) inherits via `catalog:`
references in their own `package.json`. Chrome-extension is intentionally
outside the catalog (isolated workspace).

## Branch naming

- `claude/<short-kebab-description>` for Claude-authored branches
- Branches targeted at resolving Codex-authored PR conflicts:
  `claude/fix-<topic>-<suffix>` pattern (see PR #23's resolution history)

## See also

- `README.md` — high-level architecture + setup
- `docs/branch-protection.md` — main branch protection + auto-merge setup
- `.github/workflows/ci.yml` — CI definitions
- `.github/scripts/check-package-json-duplicates.py` — JSON lint
