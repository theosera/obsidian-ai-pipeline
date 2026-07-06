---
name: vault-ops
description: 週次脅威レポート取込 CI と人間の手動 push が二重書き込みする vault repo (Permanent Note) の書込安全機構の正典。pre-push hook (non-ff/force 拒否) + safe-vault-push-perm.sh (自動 rebase・.threat_reports.json 退避・staged secret ゲート・ref 破損検知) + installer を配布する。**vault repo への push 運用 / `vault-push-perm` エイリアス / `.githooks` (pre-push) / vault の git 復旧・非常時対応 / 本 skill の scripts を触る前に必ずこの Skill をロードしてから**着手せよ。実行は人間の terminal と CI が担い、本 Skill は配布物とルールの母艦。
# allowed-tools: 導入支援 (installer / self-test 実行) に Bash が要るため許可。Write は不要 (配布物は本 skill に既収載)。
allowed-tools: Read, Bash
---

# vault-ops — vault repo 書込安全機構

vault repo は **CI (`.github/workflows/llm-sec-weekly.yml` の週次取込) と人間の手動 push
(`vault-push-perm`) の二重書き込み**であり、さらに iCloud 同期フォルダ内にあるため
`.git` 破損 (`refs/heads/main 2` 等) の前歴がある。本 skill はその既知事故を
「覚えていなくても起きない」よう実行パスに機構として埋め込む。

運用哲学: **ユーザーへの停止・確認はセキュリティ境界の突破時のみ。ルーティン障害
(push 競合 / dotfile 衝突 / 一時エラー) は機構が自動解決する。**

## 事故 → 機構 → エスカレーション境界

| 事故 | 自動解決 (現場) | 停止して人間に委ねる条件 |
|---|---|---|
| human push が non-ff 失敗 (CI 先行) | wrapper が rebase --autostash で自動追従。素の `git push` は pre-push hook が拒否 (**force push による CI commit 消しも同条件で拒否 = hook の主価値**) | rebase 衝突時のみ (手順を提示して停止) |
| 未追跡 `.threat_reports.json` が rebase を阻む | 「remote が track 済 ∧ local が未追跡」のときだけ CI 版を正として **repo 外** (`~/.claude/vault-ops/backups/`) へ退避 | なし |
| CI push が human push と競合 | CI 側も fetch→rebase→push ×4 (llm-sec-weekly.yml)。両 writer の戦略を rebase に統一 | rebase 衝突のみ loud-fail → 次 run が UPSERT 冪等で自己修復 |
| iCloud による `.git` 破損 | wrapper 起動時に検知 (ref 名の空白 / packed-refs 異常 / `*.icloud` placeholder) して**修復せず停止** | 検知時 (ref 削除は破壊的操作)。復旧の正典 = vault 管理ノート「iCloud による git 破損」節 |
| vault へ secret を commit しかける | staged を SECRET_RE で検査し該当だけ unstage | **常に停止 (唯一の必須ハード停止 = セキュリティ境界)** |

## 構成ファイル

```text
.claude/skills/vault-ops/
  SKILL.md                       … 本ファイル (規約と導入手順の正典)
  scripts/vault-pre-push.hook    … vault repo の .githooks/pre-push になるテンプレ (POSIX sh)
  scripts/safe-vault-push-perm.sh … vault-push-perm エイリアスの実体 (macOS bash 3.2 互換)
  scripts/install-vault-ops.sh   … ワンコマンド導入 (hook 配置 + symlink + zshrc 案内)
  tests/run_vault_ops_tests.sh   … サンドボックス受け入れテスト (CI でも実行 / installer --self-test でも実行)
```

## 導入 (Mac / 一度だけ)

pipeline リポのローカル clone から:

```bash
bash <clone>/.claude/skills/vault-ops/scripts/install-vault-ops.sh \
  --perm-note-path "/path/to/Permanent Note"
```

installer がやること (冪等 / 再実行安全):

1. `vault-pre-push.hook` を vault repo の `.githooks/pre-push` へコピー + 実行権付与
2. vault repo で `git config core.hooksPath .githooks` (**local config = clone ごとに要実行**)
3. hook を pathspec commit (`git commit -- .githooks/pre-push`) — 他の staged 変更は巻き込まない
4. `~/.claude/bin/safe-vault-push-perm.sh` を **symlink** 配置 (clone への symlink = `git pull`
   で自動更新され drift しない。CLAUDE.md の egress hook ユーザー層配置と同じ推奨方式。
   clone に依存したくない場合のみ `--copy`)
5. `~/.zshrc` に追記すべき managed block を**表示** (既定では書き込まない。`--write-zshrc`
   指定時のみ backup + 旧 alias コメントアウト + managed block 追記)。alias でなく
   **関数形式** (引数透過 + パスは single-quote エスケープして生成するため、空白や
   quote を含むパスでも安全):

```bash
# >>> vault-ops managed >>>
vault-push-perm() { PERM_NOTE_PATH='/path/to/vault' "$HOME/.claude/bin/safe-vault-push-perm.sh" "$@"; }
# <<< vault-ops managed <<<
```

受け入れ確認: `install-vault-ops.sh --self-test` (実 vault / 実 HOME に触れない
サンドボックスで hook 拒否・退避・rebase・secret ゲートを検証) + 新しいターミナルで
`vault-push-perm` が動くこと。

> hook / wrapper は環境変数でのみ vault を参照する (`PERM_NOTE_PATH` / `VAULT_TR_DIR`
> (既定 `10_Threat_Reports`) / `VAULT_OPS_BACKUP_DIR` / `VAULT_REMOTE`)。
> スクリプトに実パスや vault 実名を焼かない — 機微なパスは各自の zshrc にだけ存在する。

## wrapper (`safe-vault-push-perm.sh`) の停止条件一覧

自動で進むのが既定。以下の**列挙された条件でのみ**停止する (それ以外で止まるのは bug):

1. vault パス不正 / git repo でない / detached HEAD / 未完了 rebase / unmerged 残存
2. `.git` 破損兆候の検知 (修復は vault 管理ノートの手順で人間が実施)
3. rebase 衝突 (abort 済みの状態で停止) / autostash 適用衝突 (stash 退避を案内)
4. **staged secret 検知** (該当ファイルは unstage 済みの状態で停止)
5. オフラインで push 不能 (ローカル commit は完了済み = データは失われない)
6. push 3 回失敗 (認証・ネットワーク異常)

## `git add -A` 例外の根拠 (明文化)

CLAUDE.md の「`git add -A` 禁止」は **obsidian-ai-pipeline 自身の commit に対する規約**
(untracked secret の巻き込み防止)。vault repo では「編集した全ノートを push する」のが
運用上の正であり個別列挙は成立しない。wrapper は `-A` の後に:

- `:(exclude)*_quarantine*` pathspec + staged 検査で **untrusted レポート本文を決して commit しない**
- **staged secret ゲート** (下記 SLA の第 4 系統) で CLAUDE.md の Secrets 境界を機械的に補償する

## Secret-pattern 同期 SLA (第 4 系統)

`safe-vault-push-perm.sh` の `SECRET_ERE` は `.claude/hooks/block-secret-git.cjs` の
`SECRET_RE` (12 パターン + allowlist `.env.example`) の shell 転記。**新トークン形式・
新 secret ファイル名を追加するときは同一 PR で両方を更新する** (CLAUDE.md
「Secret-pattern の維持」節の 4 系統目 / 四半期レビュー対象 =
`docs/security/handover-residual-tasks.md` #16)。

## CI との契約 (couplings — 片側だけ変えると回帰する)

| 項目 | CI 側 (`llm-sec-weekly.yml`) | wrapper 側 |
|---|---|---|
| 脅威レポート dir | `TR_DIR: 10_Threat_Reports` | `VAULT_TR_DIR` 既定値 |
| `.threat_reports.json` | dotfile を `git add -f` で強制追跡 | untracked 衝突時に CI 版を正として退避 |
| `_quarantine/` | 追跡しない (untrusted 本文) | `:(exclude)` + staged assert で決して commit しない |
| non-ff 解消戦略 | fetch→rebase FETCH_HEAD→push ×4 / 衝突 abort + loud-fail | 同一戦略 ×3 / 衝突 abort + 停止 |

> **pre-push hook の判定は git 提供の `remote_sha` (push 交渉直後の権威値) を使い、
> hook 内で `git fetch` しない**。push 進行中の自前 fetch は不安定で、失敗すると
> 旧設計は fail-open で non-ff を通してしまった (実 vault で確認)。remote_sha 方式なら
> ネットワーク呼び出しゼロ、リモートオブジェクトがローカル未取得のケースも
> `merge-base --is-ancestor` がエラー→**fail-closed で拒否**する。

## 残余リスク (機構で塞がない部分 — 知っておく)

- hook は `git push --no-verify` で迂回できる (CLAUDE.md: `--no-verify` を使わない文化)。
  最終防衛は server 側 non-ff 拒否。**force push まで完全に塞ぐには vault repo 側の
  branch protection (force push 禁止) を推奨**。
- `.githooks/pre-push` 自体が iCloud に evict される (`*.icloud` placeholder 化) と git は
  hook 無しとして進む。根治は `.git`/hook の iCloud 分離 = handover #17 (保留、月 1 回以上
  再発したら着手)。
- secret ゲートは **ファイル名ベース** (block-secret-git.cjs と同水準)。内容ベース検知は
  gitleaks 系統 (SLA 参照) の守備範囲。

## テスト

- `tests/run_vault_ops_tests.sh` — tmp 配下に bare origin + 2 clone を作る決定論
  サンドボックス (network / pnpm 不要)。CI (`.github/workflows/ci.yml`) で毎 PR 実行。
  ローカル (Mac) では `install-vault-ops.sh --self-test` で同じものが走る。
- カバー: hook (ff 許可 / non-ff 拒否 / force 拒否 / `feature:main` 拒否 / delete・tag skip /
  新規 ref 許可 / リモートオブジェクト未取得→fail-closed 拒否) / wrapper (e2e / JSON 退避と非退避 / 自動 rebase / secret 停止と
  `.env.example` 通過 / ref 破損停止 / autostash 衝突停止 / rebase 衝突 abort /
  `_quarantine` 非 commit) / installer (初回 / 冪等 / `--copy`)

## See also

- `docs/security/llm-sec-weekly-automation.md` §5/§6 — CI 側の失敗表とローカル並行運用
- `.github/workflows/llm-sec-weekly.yml` — CI writer の実体 (rebase 戦略の対向側)
- `.claude/hooks/block-secret-git.cjs` — SECRET_RE の原本 (第 1 系統)
- `docs/security/handover-residual-tasks.md` #16 (パターン同期) / #17 (iCloud .git 分離・保留)
