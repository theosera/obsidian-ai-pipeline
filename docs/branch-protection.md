# Branch Protection Settings

PR #23 の post-mortem で判明した「main が静かに破損したまま複数 PR を受け入れてしまう」事故を防ぐための GitHub 側設定メモ。コードでは表現できないため、リポジトリ管理者が Web UI または `gh api` で設定する。

> **適用状況 (2026-06)**: 本リポジトリは下記の保護を **Repository ruleset**
> (`Settings → Rules → Rulesets`、名前 **`Branch-protection`**) として
> **Active で適用済み**。以下の「推奨設定」「`gh api`」節は *classic branch
> protection* を前提に書かれたオリジナルだが、強制内容 (必須チェック /
> CODEOWNERS / force-push 禁止 等) は ruleset でも同一。**新規・再設定時は
> classic ではなく ruleset を推奨** (GitHub の推奨経路で、bypass actor を
> ロール単位で細かく指定できる)。ruleset 版の具体手順は
> 「[Repository ruleset で設定する (推奨)](#repository-ruleset-で設定する-推奨2026-06-適用済み)」を参照。

## 目的

- 古い base から作られた PR が merge されて main に orphan state を残すのを防ぐ
- CI(テスト + workspace typecheck + package.json lint) 未通過の merge を防ぐ
- レビュー未解決スレッドのまま merge されるのを防ぐ

## 設定場所

- **Ruleset (推奨・本リポの現行方式)**: `Settings` → `Rules` → `Rulesets` → `New branch ruleset`
- Classic (以下のオリジナル手順): `Settings` → `Branches` → `Branch protection rules` → `main` (add rule / edit existing)

## Repository ruleset で設定する (推奨・2026-06 適用済み)

本リポは classic ではなく **ruleset** で運用している。現在 Active な
`Branch-protection` ruleset の設定値は以下。再作成・監査時はこれと突き合わせる。

### 作成手順 (Web UI)

`Settings` → `Rules` → `Rulesets` → `New branch ruleset`:

1. **Ruleset Name**: `Branch-protection`
2. **Enforcement status**: **Active** (← `Disabled`/`Evaluate` のままだと強制されない)
3. **Target branches**: `Add target` → **Include default branch** (= `main`)。
   *空のままだと「does not target any resources」警告が出て何も適用されない。*
4. **Bypass list**: `Add bypass` → **Repository admin (Role)**。
   *理由は下記「CODEOWNERS と自己承認」を参照。*
5. **Branch rules** で以下を有効化:

| ルール | 値 | 目的 |
|---|---|---|
| Restrict deletions | ✅ | main 削除防止 |
| Require a pull request before merging | ✅ | 直 push 禁止 |
| &nbsp;&nbsp;└ Required approvals | `0` | ソロ運用 (CODEOWNERS は下記で別途強制) |
| &nbsp;&nbsp;└ Require review from Code Owners | ✅ | `.github/` 等 owned ファイルは owner approve 必須 |
| &nbsp;&nbsp;└ Require conversation resolution before merging | ✅ | 未解決レビューを残さない |
| Require status checks to pass | ✅ | CI 通過ゲート |
| &nbsp;&nbsp;└ required checks | `Pipeline (root) - test & typecheck` | CI ジョブ名と完全一致 (GitHub Actions ソース) |
| &nbsp;&nbsp;└ Require branches to be up to date before merging | ✅ | **最重要**: 古い base の PR は rebase 必須 (PR #23 再発防止) |
| Block force pushes | ✅ | main への force push 禁止 |

> `Allowed merge methods` は任意。履歴を平らに保つなら **Squash のみ**推奨
> (playbook の merge method=squash と整合)。

### CODEOWNERS と自己承認 (ソロ運用の注意)

`Require review from Code Owners` ✅ + `Required approvals 0` の場合、
`.github/` を変更する PR は `@theosera` の approve が必須になる。しかし GitHub は
**自分の PR を自分で approve できない**ため、コードオーナーが 1 人だと自分の
workflow 系 PR がマージ不能にロックされる。

→ 回避策として **Bypass list に `Repository admin` ロールを追加** している。
これで「無関係な collaborator / 自動化 (workflow 内 `GITHUB_TOKEN`) が
workflow を勝手に書き換えてマージする」のは引き続きブロックしつつ、admin
本人は目視後に自分の `.github/` PR をマージできる (Megalodon 系=外部/
3rd-party action 経由の改ざん、という脅威モデルには十分)。
より厳格にしたい場合は bypass を外し、第 2 の approver ID を用意する。

### `gh api` で ruleset を作る場合

```bash
gh api --method POST -H "Accept: application/vnd.github+json" \
  /repos/theosera/obsidian-ai-pipeline/rulesets \
  -f name='Branch-protection' \
  -f target='branch' \
  -f enforcement='active' \
  -f 'conditions[ref_name][include][]=~DEFAULT_BRANCH' \
  -f 'bypass_actors[][actor_id]=5' \
  -f 'bypass_actors[][actor_type]=RepositoryRole' \
  -f 'bypass_actors[][bypass_mode]=always' \
  -f 'rules[][type]=deletion' \
  -f 'rules[][type]=non_fast_forward' \
  -f 'rules[][type]=pull_request' \
  -F 'rules[][parameters][required_approving_review_count]=0' \
  -F 'rules[][parameters][dismiss_stale_reviews_on_push]=false' \
  -F 'rules[][parameters][require_code_owner_review]=true' \
  -F 'rules[][parameters][require_last_push_approval]=false' \
  -F 'rules[][parameters][required_review_thread_resolution]=true' \
  -f 'rules[][type]=required_status_checks' \
  -F 'rules[][parameters][strict_required_status_checks_policy]=true' \
  -f 'rules[][parameters][required_status_checks][][context]=Pipeline (root) - test & typecheck'
```

> `~DEFAULT_BRANCH` で default branch (`main`) を対象化。`actor_id=5` は
> `Repository admin` ロール。GitHub の rulesets API は配列パラメータの組み立てが
> 繊細なので、UI 作成のほうが確実。上記は監査・再現用の参考。

## 推奨設定

| 項目 | 値 | 目的 |
|---|---|---|
| **Require a pull request before merging** | ✅ | 直 push 禁止 |
| **Require status checks to pass before merging** | ✅ | CI 通過ゲート |
| &nbsp;&nbsp;&nbsp;Status checks that are required | `Pipeline (root) - test & typecheck` | CI ジョブ名に一致 |
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
3. CI 実行 (pipeline)
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

## CI/CD サプライチェーン防御 (Megalodon 2026-05 を受けて)

StepSecurity が 2026-05-22 に公開した Megalodon キャンペーンは、約 5,500 の
公開リポジトリに対し `.github/workflows/` を直接書き換え、CI 実行時に
Secrets / OIDC トークン / クラウド資格情報を窃取する d-PPE (Direct Poisoned
Pipeline Execution) 攻撃だった。本リポは現状 IoC 該当なしだが、再発防止と
してリポジトリ側で以下を**手動で**有効化する。

### 必須: CODEOWNERS レビュー強制

リポジトリ直下 `.github/CODEOWNERS` で `.github/` 配下の owner を `@theosera`
に固定済み (本コミットで追加)。これを **branch protection rules で強制** する。

`Settings` → `Branches` → `main` rule → 以下を有効化:

| 項目 | 値 |
|---|---|
| **Require review from Code Owners** | ✅ |

これで `.github/` 配下を変更した PR は必ず `@theosera` の approve が必要に
なり、worker bot / 自動化からの workflow 改ざんを機械的に弾ける。

`gh api` で一括設定する場合 (既存の protection に重ねがけ):

```bash
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  /repos/theosera/obsidian-ai-pipeline/branches/main/protection \
  -F 'required_status_checks[strict]=true' \
  -f 'required_status_checks[contexts][]=Pipeline (root) - test & typecheck' \
  -F 'enforce_admins=false' \
  -F 'required_pull_request_reviews[required_approving_review_count]=1' \
  -F 'required_pull_request_reviews[require_code_owner_reviews]=true' \
  -F 'required_pull_request_reviews[require_last_push_approval]=false' \
  -F 'required_conversation_resolution=true' \
  -F 'allow_force_pushes=false' \
  -F 'allow_deletions=false' \
  -F 'restrictions=null'
```

`required_approving_review_count` を `0 → 1` にすると一人開発でも CODEOWNERS
を強制できるが、自分の PR を自分では approve できない点に注意 (Claude が
代わりに approve する運用にするか、CODEOWNERS だけ強制して
`required_approving_review_count=0` に保つかは選択肢)。

### 第三者 Action は SHA pin (本コミットで対応済)

`ci.yml` 内の third-party Action (`pnpm/action-setup`) を major タグ
(`@v5`) から SHA に固定済み。`@v5` タグが書き換わっても追従しない。
`actions/*` (GitHub 公式) は major タグのまま — 相対リスクが低く、
GitHub 公式の改ざんは Megalodon とは別次元の事案になるため。

更新時は Dependabot が SHA 差し替え PR を出すので、その PR では
`@theosera` がレビューして merge する (CODEOWNERS 経由)。

### `id-token: write` は引き続き付与しない

本リポは OIDC で外部クラウドに認証する必要がないため `id-token: write` を
**1 つの job にも付けない**。仮に workflow を改ざんされても、攻撃者が
クラウド資格情報を発行する経路がない。今後 OIDC 連携が必要になった場合は、
**該当 1 job だけに付与** し、必ず `permissions:` を job スコープで
明示する。

### audit コマンド (定期実行推奨)

```bash
# Megalodon IoC
grep -RInE 'name:\s*(SysDiag|Optimize-Build)' .github/workflows
git log --all --format='%H %ae %s' \
  | grep -E 'build-bot@github-ci\.com|ci-pipeline@actions-bot\.com'
grep -RInE '216\.126\.225\.129' . --exclude-dir=node_modules --exclude-dir=.git

# Workflow 内の suspicious payload
grep -RInE 'base64\s+-d|base64\s+--decode|curl .* \| (sh|bash)' .github/workflows

# id-token 付与の確認 (本リポは付与しない方針)
grep -RInE 'id-token' .github/
```
