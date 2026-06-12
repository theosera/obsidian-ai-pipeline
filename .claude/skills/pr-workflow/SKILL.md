---
name: pr-workflow
description: obsidian-ai-pipeline の PR ワークフロー規約 (auto-merge Phase1 の有効化条件と guards / PR title・body 規約 / squash マージ / CI 期待値=pnpm test・typecheck・oxlint・package.json 重複チェック)。**PR を作成する / auto-merge を有効化するか判断する / PR の title・body を書く / CI で何が要求されるか確認する前に、必ずこの Skill をロードしてから**着手せよ。常時 CLAUDE.md に載せず発火条件付きで分離している。
# allowed-tools は最小化。本 Skill は規約の参照のみ。実際の PR 作成/ラベル付与/
# auto-merge 操作 (mcp__github__*) は通常どおり都度承認フローで行う。
allowed-tools: Read
---

# pr-workflow

obsidian-ai-pipeline の **PR 作成〜マージ規約**。CLAUDE.md から発火条件付きで分離した
RAG。PR を作る / auto-merge 判断 / CI 期待値確認の前にロードする。

## auto-merge (Phase 1)

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
- `pnpm typecheck` — `tsc --noEmit` (root flat TypeScript).
- `pnpm lint` — **oxlint** (`oxlint --type-aware`), root app code only,
  bug-detection-only 4 rules (type-aware `no-floating-promises` /
  `no-misused-promises` via `oxlint-tsgolint`). Style → CodeRabbit.
  Config: `.oxlintrc.json`.
- `.github/scripts/check-package-json-duplicates.py` — rejects duplicate
  JSON keys across all package.json files

> 関連: `docs/branch-protection.md` (main 保護 + auto-merge セットアップ全文)、
> `.github/workflows/ci.yml` (CI 定義)。
