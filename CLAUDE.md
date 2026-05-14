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

## X bookmarks: group-page table view (2026-05)

The Claude side moved from **1 MD per tweet under `Clippings/X-Bookmarks/`**
to **1 MD per group folder under `X_Bookmarks/`**, with a sortable /
filterable Dataview table backed by `<vault>/X_Bookmarks/.x_bookmarks.json`.

Key facts to remember:

- New default base: `X_Bookmarks/` (override via `X_BOOKMARKS_FOLDER`).
  Helper: `config.ts::getXBookmarksBaseFolder()`.
- Per-tweet MD writes are gated off for X bookmarks in
  `pipeline/interactive.ts`. Non-X clippings (Hatena/RSS) still write
  1 MD each via `saveMarkdown()`.
- SQLite (`__skills/pipeline/x_bookmarks.db`) is the transactional core
  (folder_sessions / dedupe / lifecycle). `.x_bookmarks.json` is a
  read-only **exported view** rewritten every sync.
- Dataview is a **project prerequisite** (community plugin). The
  dataviewjs template lives in `x_group_page_template.ts`; group pages
  use sentinel-bounded regeneration so user prose above/below the
  auto block is preserved.
- The Dataview table renders a **custom HTML `<table>`** (not
  `dv.table()`) so column headers are clickable for ascending/descending
  sort (Excel / Google Sheets style). Default sort: `added_at` desc.
- SQLite has both `saved_at` (last-touched, updated every upsert) and
  `added_at` (first-seen, **preserved on `ON CONFLICT DO UPDATE`** —
  do NOT add `added_at` to the SET clause). The Dataview "added" column
  is bound to `added_at`.
- `ai_summary` column is populated by `x_bookmarks_summarizer.ts` at the
  end of `--x-bookmarks` sync (inline, before JSON export + group MD
  regeneration). Output is **always Japanese, 200 graphemes max, single
  line**. Provider plumbing is shared with `classifier.ts` via
  `askAIText()` and uses `taskType: 'fast'` (Haiku 4.5 / GPT-5.4 mini /
  Gemini 3.1 Flash-Lite / local — `AI_PROVIDER` env). Already-filled
  rows are skipped (`ai_summary IS NULL` filter). Use
  `pnpm start -- --x-bookmarks --x-resummarize-all` to clear and
  re-generate all summaries after a model / prompt change. Failed
  rows stay `NULL` and are retried on next sync (best-effort, never
  throws).
- **Execution mode auto-switches by `AI_PROVIDER`** (no extra CLI flag):
  - `local` → **batch** mode: 10 posts packed into one prompt expecting
    `{"summaries": [...]}` JSON, processed sequentially. LM Studio's
    per-call overhead dominates, so batching is much faster overall.
    Batch is **all-or-nothing** — JSON parse failure / count mismatch
    leaves the whole chunk `NULL` for next-sync retry (avoids partial
    misalignment).
  - cloud (`anthropic` / `openai` / `gemini`) → **inline** mode:
    1 post = 1 call, 3-way concurrent. Cloud APIs benefit from
    parallelism and short outputs reduce hallucination risk.
  - Override via `mode: 'inline' | 'batch'` option on
    `summarizePendingBookmarks` (used by tests; no CLI flag exposed
    to keep the user-facing surface minimal).
- Folder-count invariant (enforced at sync end via
  `x_folder_invariant.ts`): X distinct folder count == leaf folder
  count under `X_Bookmarks/`. Mismatch logs a warning, not an error.
- Hands-on output moved to `Permanent Note/09_X_Bookmarks/`.
- New CLI flags: `--x-derive-rules` (auto-derive
  `x_forced_parents.json` from current vault), `--x-migrate-legacy`
  (one-shot move of `Clippings/X-Bookmarks/` → `_Archived/`).

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
