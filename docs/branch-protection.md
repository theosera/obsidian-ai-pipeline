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

## 一人開発で review approval が要件になる場合

`required_pull_request_reviews.required_approving_review_count=0` にしてあるので、approve 不要で自分で merge できる。もし approve 必須にしたい場合は `1` に上げる（ただしその場合 1 人開発だと別アカウントが必要になる）。
