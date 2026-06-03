---
name: x-bookmarks
description: obsidian-ai-pipeline の X (Twitter) bookmarks 機能 (group-page Dataview table / SQLite 中核 / ai_summary 要約 / provider→mode 自動切替 / folder invariant) の実装知識。`x_bookmarks_*.ts` / `x_folder_mapper.ts` / `x_session_*.ts` / `hands_on_generator.ts` を読む・直す、`--x-bookmarks` 系 CLI フラグや `X_Bookmarks/` 配下・`x_forced_parents.json` / `x_folder_mapping.json` を触る、X bookmarks の挙動を変更する前に**必ずこの Skill をロードしてから**着手せよ。常時 CLAUDE.md に載せるとトークンを食うため発火条件付きで分離してある。
# allowed-tools は最小化。本 Skill は「知識参照」のみで副作用を持たない。
# 実際のコード変更は通常の Edit/Write フローで行い、本 Skill は事実集として読む。
allowed-tools: Read
---

# x-bookmarks

obsidian-ai-pipeline の **X bookmarks 機能**の実装事実集。CLAUDE.md から発火条件付きで
分離した RAG。X bookmarks 関連の調査・変更前にロードする。

## group-page table view (2026-05)

The X bookmarks feature moved from **1 MD per tweet under
`Clippings/X-Bookmarks/`** to **1 MD per group folder under `X_Bookmarks/`**,
with a sortable / filterable Dataview table backed by
`<vault>/X_Bookmarks/.x_bookmarks.json`.

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
  line**. Provider plumbing reuses `classifier.ts::askAIText` via the new
  `AskAITextOverride { provider, model }` parameter (`taskType: 'fast'`).
  Already-filled rows are skipped (`ai_summary IS NULL` filter). Use
  `pnpm start -- --x-bookmarks --x-resummarize-all` to clear and
  re-generate all summaries after a model / prompt change (works even
  with 0 new bookmarks — `runner.ts` reroutes the early-exit path
  through `regenerateXBookmarkArtifacts`). Failed rows stay `NULL` and
  are retried on next sync (best-effort, never throws).
- **Dedicated provider/model selection (decoupled from `AI_PROVIDER`)**:
  X summary picker is **separate** from the classifier provider. Stored
  at `pipeline_config.json::xSummary` (`{ provider, model }`). First
  `--x-bookmarks` run auto-launches `runXSummaryWizard` which lists
  presets (1=Anthropic Haiku 4.5 default, 2=OpenAI gpt-4o-mini,
  3=Gemini 2.5 Flash, 4=local LM Studio). Re-select with
  `--x-summary-reconfig`. Default-default (= empty Enter on the wizard)
  is **cloud / Anthropic Haiku 4.5** because 200-grapheme summaries are
  a fast-tier task and cloud Haiku gives a better quality/cost balance
  than local for this specific workload.
- **Execution mode auto-switches by `xSummary.provider`** (no extra CLI
  flag):
  - `local` → **batch** mode: 10 posts packed into one prompt expecting
    `{"summaries": [...]}` JSON, processed sequentially. LM Studio's
    per-call overhead dominates, so batching is much faster overall.
    Batch is **all-or-nothing** — JSON parse failure / count mismatch
    leaves the whole chunk `NULL` for next-sync retry (avoids partial
    misalignment).
  - cloud (`anthropic` / `openai` / `gemini`) → **inline** mode:
    1 post = 1 call, 3-way concurrent. Cloud APIs benefit from
    parallelism and short outputs reduce hallucination risk.
  - `summarizePendingBookmarks` falls back to `process.env.AI_PROVIDER`
    when `options.provider` is undefined (legacy compatibility for
    tests / direct callers).
  - Override via `mode: 'inline' | 'batch'` option on
    `summarizePendingBookmarks` (used by tests; no CLI flag exposed
    to keep the user-facing surface minimal).
- `--dry-run` honored in the resummarize-only path: when results=0 and
  `--x-resummarize-all`, runner skips `regenerateXBookmarkArtifacts`
  entirely (no SQLite ai_summary clear, no JSON / group MD rewrite) and
  logs `🧪 --dry-run: ... スキップしました。`. EOF rescue hint
  (`pnpm start -- --rescue <report>`) auto-appends
  `--x-resummarize-all` if the original run had it set.
- Folder-count invariant (enforced at sync end via
  `x_folder_invariant.ts`): X distinct folder count == leaf folder
  count under `X_Bookmarks/`. Mismatch logs a warning, not an error.
- Hands-on output moved to `Permanent Note/09_X_Bookmarks/`.
- New CLI flags: `--x-derive-rules` (auto-derive
  `x_forced_parents.json` from current vault), `--x-migrate-legacy`
  (one-shot move of `Clippings/X-Bookmarks/` → `_Archived/`).

## implementation (flat)

The X bookmarks feature is a single flat TypeScript implementation at the
repo root: `x_bookmarks_api.ts`, `x_auth_server.ts`, `x_folder_mapper.ts`,
`x_bookmarks_db.ts`, `x_session_*.ts`, `hands_on_generator.ts`, integrated
with `index.ts` / `router.ts` / `storage.ts`.

> A parallel Codex implementation (`apps/*` + `packages/core`, pnpm
> workspace) was run side-by-side as a Claude-vs-Codex control experiment.
> That comparison is over and the Codex side was **removed from the repo**
> (2026-06). Only the two settings files
> `<vault>/__skills/pipeline/x_forced_parents.json` and
> `<vault>/__skills/pipeline/x_folder_mapping.json` remain (user-maintained).

> 注: `x_folder_mapping.json` / `x_forced_parents.json` の**スキーマ**を変える
> 変更は auto-merge せず `needs-human-review` (詳細は `pr-workflow` skill)。
