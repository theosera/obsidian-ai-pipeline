# Branch Protection Settings

PR #23 の post-mortem で判明した「main が静かに破損したまま複数 PR を受け入れてしまう」事故を防ぐための GitHub 側設定メモ。コードでは表現できないため、リポジトリ管理者が Web UI または `gh api` で設定する。

## 目的

- 古い base から作られた PR が merge されて main に orphan state を残すのを防ぐ
- CI(テスト + workspace typecheck + package.json lint) 未通過の merge を防ぐ
- レビュー未解決スレッドのまま merge されるのを防ぐ

## 設定場所

`Settings` → `Branches` → `Branch protection rules` → `main` (add rule / edit existing)

## 推奨設定

| 項目 | 値 | 目的 |
|---|---|---|
| **Require a pull request before merging** | ✅ | 直 push 禁止 |
| **Require status checks to pass before merging** | ✅ | CI 通過ゲート |
| &nbsp;&nbsp;&nbsp;Status checks that are required | `Pipeline (root) - test & typecheck`<br>`Chrome extension - build & typecheck` | CI ジョブ名に一致 |
| **Require branches to be up to date before merging** | ✅ | **最重要**: 古い base の PR は rebase 必須 |
| **Require conversation resolution before merging** | ✅ | レビュー未解決を防ぐ |
| **Do not allow bypassing the above settings** | お好み | 自分自身も含めて例外を作らないなら✅ |
| Allow force pushes | ❌ | main への force push 禁止 |
| Allow deletions | ❌ | main 削除防止 |

## `gh api` で一括設定する場合

```bash
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  /repos/theosera/obsidian-ai-pipeline/branches/main/protection \
  -f 'required_status_checks[strict]=true' \
  -f 'required_status_checks[contexts][]=Pipeline (root) - test & typecheck' \
  -f 'required_status_checks[contexts][]=Chrome extension - build & typecheck' \
  -F 'enforce_admins=false' \
  -f 'required_pull_request_reviews[required_approving_review_count]=0' \
  -f 'required_pull_request_reviews[require_last_push_approval]=false' \
  -F 'required_conversation_resolution=true' \
  -F 'allow_force_pushes=false' \
  -F 'allow_deletions=false' \
  -F 'restrictions=null'
```

`required_status_checks.strict=true` が **"Require branches to be up to date"** に相当。これが今回の事故の直接の再発防止策。

## この設定下での運用

- PR の base が main より古くなったら GitHub が「Update branch」ボタンを出すので、**merge 前に必ず押す**
- CI が両方緑でないと merge ボタンが活性化しない
- 未解決レビューコメントが残っていると merge 不可

## Auto-merge (Phase 1)

Claude が作成した PR は `mcp__github__enable_pr_auto_merge` で自動 merge 対象になる（詳細は `CLAUDE.md` PR workflow 参照）。この機能を有効化するには **リポジトリ側の 1 設定** が必須:

### 必須: `Allow auto-merge` を有効化

`Settings` → `General` → スクロールして `Pull Requests` セクション → **`Allow auto-merge`** にチェック → Save

または `gh api` で一括:

```bash
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  /repos/theosera/obsidian-ai-pipeline \
  -F 'allow_auto_merge=true' \
  -F 'allow_squash_merge=true' \
  -F 'allow_merge_commit=false' \
  -F 'allow_rebase_merge=false' \
  -F 'delete_branch_on_merge=true' \
  -F 'squash_merge_commit_title=PR_TITLE' \
  -F 'squash_merge_commit_message=PR_BODY'
```

ポイント:
- `allow_auto_merge=true` がないと `enable_pr_auto_merge` は silently 失敗する
- squash のみに絞ると Claude の `mergeMethod: "SQUASH"` と整合
- `delete_branch_on_merge=true` で merge 後に branch 自動削除（履歴クリーン化）

### 動作フロー

```text
1. Claude が create_pull_request で PR 作成
2. Claude が直後に enable_pr_auto_merge(SQUASH) を呼ぶ
3. CI 実行 (pipeline + chrome-extension)
4. CodeRabbit / Codex がレビュー
5. Claude が指摘に push で応答
6. CI 緑 + required status checks 満たした時点で GitHub が自動 squash merge
7. source branch 自動削除
```

ユーザーの介入が必要になるのは:
- Claude が `needs-human-review` ラベルを付けた場合（アーキテクチャ判断が必要と判定）
- CI が根本的な問題で失敗する場合（Claude が修正を push しても通らない）
- レビューアーが手動で `Require changes` を付けた場合

### Opt-out

特定 PR で auto-merge を一時停止したい場合:

```bash
# CLI から
gh pr merge <PR_NUMBER> --disable-auto

# またはツールから
mcp__github__disable_pr_auto_merge(pullNumber=XX)
```

## 一人開発で review approval が要件になる場合

`required_pull_request_reviews.required_approving_review_count=0` にしてあるので、approve 不要で自分で merge できる。もし approve 必須にしたい場合は `1` に上げる（ただしその場合 1 人開発だと別アカウントが必要になる）。
