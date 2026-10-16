---
name: vault-ops
description: 週次脅威レポート取込 CI と人間の手動 push が二重書き込みする vault repo (Permanent Note) の書込安全機構の正典。pre-push hook (non-ff/force 拒否) + safe-vault-push-perm.sh (自動 rebase・.threat_reports.json 退避・staged secret ゲート・ref 破損検知) + installer を配布する。**vault repo への push 運用 / `vault-push-perm` エイリアス / `.githooks` (pre-push) / vault の git 復旧・非常時対応 / 本 skill の scripts を触る前に必ずこの Skill をロードしてから**着手せよ。実行は人間の terminal と CI が担い、本 Skill は配布物とルールの母艦。
# allowed-tools: Read のみ。本 skill の実行は**人間の terminal と CI** が担う (下記参照) ため
# Bash の事前許可は不要 — installer は git hook 導入 / core.hooksPath 設定 / ~/.claude/bin への
# symlink / ~/.zshrc 追記まで行うので、無承認の Bash を skill ロードで開けない。Write も不要
# (配布物は本 skill に既収載)。
allowed-tools: Read
---

# vault-ops — vault repo 書込安全機構

vault repo は **CI (`.github/workflows/llm-sec-weekly.yml` の週次取込) と人間の手動 push
(`vault-push-perm`) の二重書き込み**であり、さらに iCloud 同期フォルダ内にあるため
`.git` 破損 (`refs/heads/main 2` 等) の前歴がある。本 skill はその既知事故を
「覚えていなくても起きない」よう実行パスに機構として埋め込む。

運用哲学: **ユーザーへの停止・確認はセキュリティ境界の突破時のみ。ルーティン障害
(push 競合 / dotfile 衝突 / 一時エラー) は機構が自動解決する。**

<!-- PR191:R38:VAULT:BEGIN -->

## R38: Vault運用でも同じsource条件を保持する

この節は私有最終sourceのローカル受入cut（2026-10-16T10:57:01.166111+09:00 JST）。新公開head・同head CI・fresh両review・実入口は未取得のまま分ける。後続の公開結果はPR本文と監査台帳へ記録し、このcutの履歴へ遡及させない。

DNS/Netcat/Wgetの選択sourceと、先行cd後のGit pathspecに関する[有限契約・通常費用・owner出口](../../../docs/security/git-command-guards.md#r38-current-contract)を参照する。既存の導入・permissions/settings・Vault書込手順は変更しない。literalな同一対象を安全に列挙できない動的pathspecはUNKNOWNとなり、cwd/env/sourceを保つ根拠が無ければownerへ確認する。

本節の追加はこの文書の保守であり、installer・Vault書込・実通信の実行指示ではない。ローカル受入は固定runtime sourceで直接入力8454/8454・broken0（25362 Hook呼出し）、role解析699/699と別のproduction shell parity15/15、通常root test602/602・typecheck・lint・package.json重複検査が成功。新公開head/requiredCI・両fresh review・必要な実入口L3は **PENDING**。

以下のR37以前の本文・数値・「current／現在」は、それぞれのsourceと取得日時に結合した履歴である。旧本文と順序を保持し、R38の新sourceでの測定結果へ読み替えない。

<!-- PR191:R38:VAULT:END -->

<!-- PR191:R37:VAULT:BEGIN -->
<a id="r37-vault-contract"></a>
## R37: Bash guardの選択sourceとVault運用の境界（固定sourceのローカル受入cut）

[現在の有限契約](../../../docs/security/git-command-guards.md#r37-current-contract)は、command-scope Git設定、実program/PATH、launcher/query、function source、選択された認証・resolver DATAを扱う。対応済み条件はALLOW、確定した禁止はFORBIDDEN、必要情報不足はUNKNOWN（後二者はdeny）であり、L1の意味、L2の各hook自身の判定/理由、L3の実dispatch/副作用を分ける。固定sourceのL1/parity/追加契約673/673、直接入力8204/8204・broken0・実Hook24612回が合格。旧7824のinput/順序/全oracle変更0、追加380unique・alias16の追加assertを確認した。逆検証は同じ合成sourceの100 Hook機能・455比較pair・2670実Hook呼出しを資格化し、別shell1機能は15pair/30test観測（Hook0）として保持した。必要性UNPROVED3機能と元逆期待FAIL5profileを保持し、UNKNOWNの独立maskや追加precisionを成功へ書き換えていない。publichead/CI/fresh/必要L3は公開後の別取得として **PENDING**。

ordinary設定/必要なshell・認証・hostlist・custom helperでもsourceが未検査なら停止し得る。同じrepo/対象/operation/lock/host/bind/版/backend/cwd/env/config/sourceを保つ対応形式かowner確認が出口である。設定や認証を外す、別場所へ写す、Hookを停止することを自動代替にしない。この文書更新はinstaller・realVault・wrapper実行の承認を追加せず、実行は既存の人間terminal/CIの契約に従う。

R36のfinal-basename template例外、本番shellのproducer/status/NUL/LF/error時何もunstageしない契約を保持する。curl認証file/engine/storeのUNKNOWNはraw file uploadのFORBIDDENとは別であり、template filenameの例外を認証source/内容/送信の許可へ広げない。通常root templateの対照も、保護ancestor内のtemplate判定も維持する。ordinary function-unsetは、削除され得る既存認識済みmapをopaqueにし後続選択をUNKNOWNとする。variable-only/無関係/未使用/解析済みlocal unset等の対照を保つが、部品閉鎖から統合受入や任意lifecycleの成功を推定しない。hyphen functionの選択source UNKNOWNも別の通常制限として残す。

**以下のR36/R26等はsource/日時を付けた旧cutである。歴史上の件数・parity・native sandbox成功を新sourceの実Vaultやpush成功へ持ち越さない。**


固定ローカルcut（UTC）: 2026-10-15T22:34:05.996284+00:00。公開source inventoryは旧17＋追加本番契約test2＝19を別途同headへ結合する。旧7824との集計比較は別fixtureであり、同一実tupleの因果比較と混同しない。
<!-- PR191:R37:VAULT:END -->

<!-- PR191:R36:VAULT-CONTRACT:BEGIN -->
<a id="r36-vault-template-contract"></a>
## R36: template例外の範囲と本番shell helper

Git/Vault filename判定で例外にするのは**final basenameの `.env.example` だけ**である。`secret_template_scan_path` はそのbasenameだけを例外処理し、残るancestorを既存SECRET_EREへ渡す。`secrets/.env.example`、`.env.local/.env.example` は保護を維持し、rootと通常directoryのtemplateは正常対照とする。全pathの保護familyを一括解除せず、内容の安全認証やupload許可にもしない。

本番 `scripts/safe-vault-push-perm.sh` から抽出したhelper/filterとJSへ同じfilename集合を渡すparityは、固定R36統合sourceで **15/15** を取得した（解析586と同callで601/601）。これはowned DUMMYと抽出関数の試験で、本番Vault・wrapper全体・push成功・actual dispatchではない。NUL producer/status・完全record・LF停止・読取/printf/grep失敗時UNKNOWN／何もunstageしない契約は保持する。

保護ancestor内のtemplateも止まる通常費用がある。必要な対象や公開条件を保てる対応形式がなければownerへ確認し、秘密を移す・改名することを自動代替にしない。現在の[全体契約と受入gate](../../../docs/security/git-command-guards.md#r36-current-contract)を参照する。文書cut 2026-10-16T05:34:54.883582+09:00。固定v4で全7824を新規実行してPASS、統合strictは59機能（Hook58＋shell1）/239pairs/1374actual Hook入力で閉鎖した。旧7827 FAILED4と3つの未資格cross、正常query退行修復はguideと監査receiptに保存する。新headCI/fresh/L3はこの公開前cutでPENDING。公開後の状態はPR本文と同headのreceiptを参照し、本節を実行権限追加やinstaller/Vault操作の承認として扱わない。
<!-- PR191:R36:VAULT-CONTRACT:END -->

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
7. staged filename 読取の失敗・不完全な NUL 入力・LF を含む filename。判定不能として、secret ゲートでは何も unstage せず停止する。通常の非秘密 LF 名もこの境界で停止するため、対象と実行条件を owner に確認する。
8. staged filenameを判定する `printf` のnonzero / allowlist grepまたはsecret grepのerror（status >1）/ 3段の終了状態不足。UNKNOWNとして停止し、部分offender一覧を公開せず、このsecret gateで何もunstageしない。正常なgrep0/1は従来のmatch / nonmatchとして扱う。

## R26: filename predicateのerror境界

pipeline直後の`PIPESTATUS`をsuccess / elseの両分岐で保存し、producer / allowlist / secretの各stageを確認する。全体status1だけをsafe nonmatchにしない。全filenameとNUL境界、各predicateの正常性を確認するまでoffender配列を公開せず、error後にpartial restoreしない。pattern / allowlist / `LC_ALL=C` / 通常0/1の意味は変更しない。

普通のfilenameでもtool / PATH / runtime errorで止まり得る。同じrepo / staged集合でproducer / grep / 読取条件を直して再検査するのが同目的の出口で、不足が残れば対象・失敗stage / status・tool version / PATH / localeをownerへ示す。個別操作の了承からhook停止やcopy先実行の了承を導かない。確認済みsecret matchの既存unstage停止と、UNKNOWNでこのgateのunstageをしない境界を分ける。[7列の条件と検証範囲](../../../docs/security/git-command-guards.md#r26-vault-の-staged-filename-判定-error)。

firstgrep / producerのerror-maskは依頼前df463のfilterにも観測され、R25導入退行とは扱わない。macOS Bash3.2.57 / installed BSD grep / Git2.54でのDUMMY抽出fragmentとprivate parity12（旧8契約保持＋error4）の取得は、realVault / 全wrapper / commit / push / 全shell版の受入ではない。GNU / Bashは公式domainのindexed excerptでPIPESTATUS / pipefail / grep statusを参照したが、direct fullpage timeoutとMac compiled source未確認を別限界として残す。19:00台の別DUMMY sandboxはlocal bare / clonesによるwrapper / installer25試験で、実Vault / 実外部通信の成功へ昇格させない。LIVE parity12の19:03台取得と、新sourceの公開CI / fresh review / 必要な副作用検証は各cutで別確認する。

R25のhistorical128は解析114＋旧parity8＋private denyAPI6で、変更しないCJS4 / 公開5044 / 解析114 / denyAPI6のbyte再利用と、新public parity12の確認を分ける。旧parity8の成功を新predicateへcarryしない。独立immutableca301のDUMMY fragment8/8とfirstgrep / printfを個別に外す2reverse条件は19:02:44に閉鎖した。failure-message-only09dcとの同値性はcollector / restore部分に限り、wholefileの同一や実Vault成功を主張しない。途中source / closure訂正は原phaseとして保持する。

## `git add -A` 例外の根拠 (明文化)

CLAUDE.md の「`git add -A` 禁止」は **obsidian-ai-pipeline 自身の commit に対する規約**
(untracked secret の巻き込み防止)。vault repo では「編集した全ノートを push する」のが
運用上の正であり個別列挙は成立しない。wrapper は `-A` の後に:

- `:(exclude)*_quarantine*` pathspec + staged 検査で **untrusted レポート本文を決して commit しない**
- **staged secret ゲート** (下記 SLA の第 4 系統) で CLAUDE.md の Secrets 境界を機械的に補償する

## Secret-pattern 同期 SLA (第 4 系統)

`safe-vault-push-perm.sh` の `SECRET_ERE` は `.claude/hooks/lib/git-guard-common.cjs` の
`SECRET_PATH_RE` (12 パターン) と `isSecretPath` の対応 filename predicate を転記する。
`secret_template_scan_path` でfinal basenameの `.env.example` だけを例外にし、残るancestorを
`SECRET_ERE` で判定する。`secrets/.env.example` / `.env.local/.env.example` は保護を維持する。
`.env` の境界は末尾・明示された `.*?`・ECMAScript `\s` であり、任意の nonword punctuation
ではない。shell は `LC_ALL=C` に固定した ASCII term の大小文字照合と、Unicode 空白の
完全な UTF-8 byte sequence の選択肢を使う。`.env?backup`、裸の `secrets`、case / subdir、
template の完全一致を専用 parity test で比較する。任意の Unicode filename 全体を安全認証する説明ではない。

実際の staged 名は `git diff --cached --name-only -z` の成功を確認して読取り、Git の quoted
表示を正規表現へ渡さない。完全な NUL 入力と各判定stageの正常な終了を確認した後だけ offender 配列を公開し、該当名を
`git restore --staged --` の単一引数として扱う。grep が LF で filename を分割するため、
LF 名は本文の非秘密性に関係なく読取境界で停止し、何も unstage しない。これは全 filename に
対する parity 保証ではない。Git / egress hook は同じ `isSecretPath` を使う。**新トークン形式・
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
- `node --test .claude/hooks/tests/secret-path-parity.test.cjs` — 実 production の shell assignment / filter / NUL reader を抽出し、共通 `isSecretPath` と比較する。12 families、template、ASCII 境界、全 ECMAScript 空白と隣接 Unicode DATA、caller locale、DUMMY Git の raw 名、Git / read 失敗、LF 停止、exact restore argv を確認する。全 wrapper や実 Vault の commit / push は実行しない。

## See also

- `docs/security/llm-sec-weekly-automation.md` §5/§6 — CI 側の失敗表とローカル並行運用
- `.github/workflows/llm-sec-weekly.yml` — CI writer の実体 (rebase 戦略の対向側)
- `.claude/hooks/lib/git-guard-common.cjs` — SECRET_PATH_RE の原本 (第 1 系統)
- `docs/security/handover-residual-tasks.md` #16 (パターン同期) / #17 (iCloud .git 分離・保留)
