# Obsidian AI Pipeline

> **⚠️ 注意: 個人用ワークフローツール**
> このリポジトリは私自身の Obsidian Vault 構造に特化した個人用自動化ツールです。**汎用の OSS プロダクトとして設計されていません。**
> AI 駆動の自律型ファイル分類パイプラインの設計リファレンスとして公開しています。

OneTab からエクスポートした URL リストを読み込み、Web ページを自動取得・抽出・AI 分類して Obsidian Vault へ保存する自動化パイプラインです。

---

## ドキュメント

| ドキュメント | 内容 |
|---|---|
| 本 README | 導入・アーキテクチャ・主要機能・環境要件・セットアップ・基本実行コマンド |
| [docs/cli-reference.md](docs/cli-reference.md) | 実行コマンドリファレンス（フォルダルール同期 / X ブックマーク取り込み / ハンズオン生成 / 中断再開 / ナレッジ統合 / 対話型レビュー） |
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | 詳細仕様（X ブックマーク取得 / ファイル構成） |
| [docs/tool-use.md](docs/tool-use.md) | Tool Use (Function Calling) 実行レイヤー（最小権限 / Vault サンドボックス / Human-in-the-Loop 承認） |
| [docs/security/git-command-guards.md](docs/security/git-command-guards.md) | Claude Code の Bash / Git ガード（許可する形式・fail-closed の範囲・拒否されたときの書換え） |

<!-- PR191:R33:README-CONTRACT:BEGIN -->
**R33 guard契約（公開準備）**: wrapperのcallee・option値・queryとDATA、Gitのobject/state/ref・autostash、選択された実行/認証sourceと送信値を区別します。確定禁止はFORBIDDEN、active source/argv/contextの不足はUNKNOWNで停止します。子commandが無い場合やqueryでも、外側のsocket redirection等は独立して検査します。

GNU rsyncのpopt alias/execは既知optionより先に選択され得るため、到達したoptionやargv境界が未証明なら局所UNKNOWNです。通常の`-a`・`--help`・`--version`も止まり得る大きな制約です。option無しoperand・先頭のliteral `--`はこのedgeだけinactiveで、他guardは維持します。`-a`を外すことを同目的の代替にはしません。必要なarchive/query/profile条件はownerへ確認してください。

merge/rebase/pullとcleanupの通常操作も、未検査object/state/ref/autostash・子sourceにより止まります。`merge HEAD`等が新treeを取り込まない場合も、lifecycle/ref経路の安全はflagだけでは証明しません。late builtin usageのwriter停止と、parse中のlocal message-file読取は別です。Wget netrc、telnet cmdrc/command-loop、curl engine、rsyncの接続program/remote program、GH/Ncat等のselected値も同じ役割ごとの条件で扱います。

対応21wrapperの原因matrix、通常影響、同目的の条件、owner出口、固定版sourceと測定境界は[受入ガイド](docs/security/git-command-guards.md#r33-current-contract)にまとめています。新fe3版はNode24.22.0で解析337＋parity12＝349成功。旧8917版の全7010件は初回2FAIL・broken1を保存し、新caseの矛盾したglobal期待だけを明示訂正して再試行7010/7010・broken0でした。AG timeoutは20秒制限を変えず単独再試行でも再現せず、元の原因は未特定です。その後、既存の禁止を新sourceの判断不能で覆う分類退行2経路をfe3版で修復しました。新fe3版の全7018件は7018/7018・broken0で完走しました（2026-10-15 23:49:45.395 JST）。旧7010成功を持ち越した結果ではありません。新head/同headCI/fresh両review/実project入口は本公開準備cutでPENDINGです。公開後の同一head受入はPR本文と監査台帳で更新し、本節cutを現在へ読み替えません。settingsのconditional secret-git/add-allと全Bash egressは変更しません。Node26移行はowner判断で2026年11月以降へ延期しています。
<!-- PR191:R33:README-CONTRACT:END -->

<!-- PR191:R32:README-CONTRACT:BEGIN -->
R32では、Git addの一括追加alias、scriptの実行source、Git revertのobject入力、rsync daemonの認証入力、Ncatのclient TLS metadata、SSHの選択jump、GHの選択auth環境という**7件の有限修復**を扱う。確定した禁止source/payloadはFORBIDDEN、実行source・値・選択条件を確認できない場合はUNKNOWNで停止する。通常のscript記録やrevertの`--no-commit`・再開・rollbackもUNKNOWNになり得る。秘密と無関係な既知DATA、実query、非選択sourceを一律禁止へ広げない。

対応版、正常対照、同じ目的を保つ書換えとownerへの確認事項は[受入guideのR32契約](docs/security/git-command-guards.md#r32-selected-source-auth-metadata)を参照。hookの無効化や目的の変わる操作への置換を自動的な出口にしない。

このnoteは 2026-10-15T09:00:38.732232+09:00 JST / 2026-10-15T00:00:38.732232+00:00 UTC の**公開準備時の測定記録**で、公開基底は`4727b00fa02b16ba6da89779282bcd3515b12e78`。合成固定sourceは2026-10-15 08:46:09.207〜08:56:48.905 JST（UTC2026-10-14 23:46:09.207〜23:56:48.905）に6450/6450・broken0で合格した。初回二FAILと通常revert二件の旧ALLOW→UNKNOWN採用を保存し、全入力・旧6235期待を保持した。既取得L1/parity251は同じ実行依存sourceへcode bindingし再実行とは数えない。単一判定逆検証・local検査も別に取得した。新公開head/同一head CI・fresh review・全thread・必要実入口はこのcut時点でPENDINGである。component合格、native通信・認証の成立、PR全体Goalは別条件。以後の同一head受入はPR本文と別監査台帳で更新し、下記R31 noteの過去cutを現在状態へ読み替えない。
<!-- PR191:R32:README-CONTRACT:END -->

<!-- PR191:R31:README-CONTRACT:BEGIN -->
R31は **prlimitの実child / active SSH CanonicalDomains / rsync remote-option metadata** の有限修復である。util-linux v2.41.2 / OpenSSH V_10_3_P1 / GNU rsync v3.4.1の固定一次sourceで、引数役割・実selection・値の生成元を分ける。確定禁止はFORBIDDEN、必要source/context不足はUNKNOWN。staticなprlimit no-child get/setを一般process可変性だけで新禁止へせず、knownnative事前拒否、SSH numeric/anchored/proxy条件、rsync provennon-dash prefix等のinactiveを保持する。既存独立guardを解除しない。必要limit / canonicalization / proxy / remote-optionの削除や目的変更を自動代替にせず、同対象・操作・条件を保てるsupportedsourceかowner出口へ進む。

private最終family componentはprlimit58/58・SSH54/54・rsync46/46で、それぞれ固定sourceの正常対照と個別newcheck reverseを取得した。旧frozen-v1 analysis f0c190…のprivate combined public198analysis+12parityは **210/210、2026-10-15 06:52:31.033289 JST（UTC 2026-10-14 21:52:31.033289）実取得**。全6237は **6237/6237 / failed0 / broken0 / 18711 process input引数、2026-10-15 06:49:49.180〜06:59:54.707 JST（UTC 2026-10-14 21:49:49.180〜21:59:54.707）実取得**。元6085のpresence / 値 / 順序 / assertionを保持、判定・停止Hook・理由prefix・broken差0でnew152 uniqueを加えた。currentcombined6singlecheckを個別に外す40casepairs / 80観測 / 240process inputsは2026-10-15 07:03:27.301 JST（UTC 2026-10-14 22:03:27.301）実取得で、stoploss13 / allowanceprecisionloss2 / normalindependent25same。これはactualCLI / nativebackend / newCI/freshの成功ではない。root602/602 exit0・typecheck0・lint0を取得（lint warnings/errors件数は未表示）。EOF qualitycheckが検出したanalysis末尾newline1byteを除去し、CJS4/runner/defs・full6237は同一sourceを保持した。**新公開head/requiredCI/fresh両review・実入口は、2026-10-15 07:16:41.791798 JST（UTC 2026-10-14 22:16:41.791798） のnote記録cut時点で未取得（PENDING）**。公開後の同一headの受入状態はPR本文と別監査台帳で更新する。newanalysis4474d02…は別actual210/210 exit0を2026-10-15 07:09:05.328668〜07:09:08.854371 JST（UTC 2026-10-14 22:09:05.328668〜22:09:08.854371）に取得した。oldfrozen f0・v2 SPEC collector失敗は履歴で、newanalysisへ結果を無根拠に持ち越していない。詳細は[受入guide R31](docs/security/git-command-guards.md#r31-selected-child-domain-remote-option)。private prototypeのscope overdenial / URI・proxy / fixedprefix精度 / proposal-oracle / collector事故を原FAILとともに残す。local修復受入・実入口・nativeDNS/privilege/auth/通信・全Goalは別gate。mergeしない。下記R30/R29以前は当時sourceの履歴で、時刻と本文を変更しない。
<!-- PR191:R31:README-CONTRACT:END -->

<!-- PR191:R30:README-CONTRACT:BEGIN -->
R30 は setpriv の child / context、SSH の暗黙設定 source、Git cherry-pick の object / index / sequencer state、preproxy だけでは証明できない環境proxy選択を分ける局所修復である。確認できる child の既存禁止は FORBIDDEN、検査できない実行 source / 対象 / 状態は UNKNOWN で止める。実 help / version、設定を使わない対応 SSH、既知の通常 child、未使用 source は他の独立したガードと併せて扱う。

既定設定が必要な SSH / remote SCP、通常の cherry-pick・再開・rollback・cleanup、setpriv の未対応 context も停止し得る。`-F none` はその設定を必要としない同目的の接続に限った対応形式であり、設定依存の接続の自動代替ではない。cherry-pick を別の writer に変えることも自動代替にしない。必要な対象・操作・argv・cwd・env・config・state と不足条件を owner に示す。詳しくは[ガイドの R30 条件](docs/security/git-command-guards.md#r30-execution-source-boundaries)を参照する。

curl 8.7.1 の CLI は空の `--preproxy` を拒否し、その版の nonempty library preproxy は環境proxyの検出を抑える。原レビュー入力の Hook 通過と、その版での native 送信成立は別で、後者は確認していない。preproxy 単独の存在を任意の実行版・設定での未使用証明にはせず、到達し得る未証明環境sourceを保守的な UNKNOWN にする。これは版を固定した native 漏えいの実証ではない。main proxy の対応 override、実 inactive / query / 未使用 source と独立した payload 禁止は保持する。R29 以下の測定は各 source / 時点の履歴であり、変更後の受入には持ち越さない。
<!-- PR191:R30:README-CONTRACT:END -->

<!-- PR191:R30:README-MEASUREMENTS:BEGIN -->
R30 local測定cut: 2026-10-15T05:08:05.515665+09:00。固定EG `1c823bce…` / common `f8e30d7e…`の全6085件を2026-10-15 04:51:57.206〜05:01:47.511 JSTに実行し、6085/6085・failed0 / broken0・source4 / runner / 定義の前後不変を確認した。元5982のinputと137 aliasを保持し、新103 unique profileを追加した。旧期待も保存し、理由付き122期待編集を明示した。取得済旧9dc結果との比較は122 record差（77 ALLOW→DENY、45 DENY維持、DENY→ALLOW0）、own-egressは78 ALLOW→UNKNOWN /44 FORBIDDEN→UNKNOWNである。後者は未検査sourceのfirst-stop優先によるprefix変更を含み、後段評価・native漏えいを証明しない。初回6080の22FAIL/broken0と、最終の同観測に旧期待を当てた102不一致を保存する。公開解析172＋parity12を同callで184/184、root602、typecheck / lintは成功した。新公開headのCI / fresh review / 実入口はこのlocal cutでは未取得で、Goal完了としない。
<!-- PR191:R30:README-MEASUREMENTS:END -->

R29 の局所契約案では、sudo / unshare のオプション値と実行する child を分け、curl / Wget が redirect 後に選び得る proxy source も確認する。必要な child / source が未証明なら UNKNOWN で止める。既知の通常 child / query / 未使用 source は独立した既存ガードと併せて扱い、権限・namespace・認証・実通信の成功を認証しない。

namespace / root / cwd / shell / login / host 等の未対応 context を使う通常作業や、redirect 必須で次の route を証明できない作業も止まり得る。同じ user / root / namespace / cwd / target / operation と目的を保てる対応形式がなければ、owner に exact argv・env・config・不足条件を提示する。必要な wrapper / proxy / redirect を外すことを自動的な代替にしない。詳しい条件と出口は[ガイドの R29 節](docs/security/git-command-guards.md#r29-wrapper-のchildとredirect後のproxy-source)を参照する。

<!-- PR191:R29:README-MEASUREMENTS:BEGIN -->
R29 local測定cut: 2026-10-15T03:38:05.996358+09:00。固定EG `05d7edb4…` / common `5ccff4f3…`の全5982件を2026-10-15 03:24:12.249〜03:34:02.354 JSTに実行し、5982/5982・failed0 / broken0・source4 / runner / 定義の前後不変を確認した。元5846のID・command・stdin・cwd・project・envと順序を保持し、通常期待の変更は理由付きPE-W07 / PE-W14 A→UNKNOWNだけ。停止済みP191P32の停止Hook追加1件を別に記録し、DENY→ALLOWは0。新136は入力signature数で、独立finding数ではない。公開解析契約161件、root602件、typecheck / lintも成功した。元レビュー3入力はegress自身でF / F / Uとして停止した。逆検証は新判定を個別に外した固定sourceの比較で、Wget先頭dot修復前FAILや器具・期待前提の原FAILを保持する。

このcutの受入は有限local契約に限る。新公開headのrequired CI・fresh両review・実Claude入口は未取得で、Goal / ZIPは未完。権限・namespace・URI・auth・実通信の未検証表示は停止判定の成功後も残す。残る5候補の調査は停止。下のR28記述は取得時刻付きの履歴である。
<!-- PR191:R29:README-MEASUREMENTS:END -->

R28 の候補契約では、SSH forwarding の remote request 成分、Wget の選択された URL-list stdin / base、rsync の sender filter rules、curl の range / request valuesを生成元と結び付ける。確定した policy 禁止は FORBIDDEN、source / format / operation / protocol が未証明なら UNKNOWN、対応する通常 literal / query / unused DATA は区別する。環境proxyは実export / inherit / protocolで選ばれた未証明routeだけUNKNOWNとし、ordinary scalar、未export、実unset / removal、明示disable / overrideを保持する。URI・認証・実送信の成立は別の未検証条件であり、全curl / Wget / SSHや全parameterを一律拒否しない。

通常の URL / filter file、生成値・未知forward / proxy sourceも止まり得る。同じ対象・operation・cwd / env / configと目的を保てる対応literal / query / inactive形式がなければ、ownerへexact sourceと不足条件を渡して確認する。proxy必須の仕事をdirectへ変えるdisable、DNS / authに必要なhostnameをIPへ置換することを、自動的な同目的代替にはしない。SSH config dumpでCanonicalDomainsが未使用と証明できるのは、今回の対応ではpercent token等がないfull literal IPv4 / IPv6の場合に限る。

R27の過去CI / review / 実入口とR28受入を分ける。stage-v4では全件結果PENDINGを記録し、stage-v5でprivate固定sourceの5846/5846・failed0 / broken0を2026-10-15 01:11:59.760 JST cutで確認した。元5253のinputを保持し、旧比較の差は理由付きR10EG035 A→UNKNOWNの1件だけ、D→Aは0。正常14対照と有限独立28対照も同sourceのHook DATAとして取得した。new593はrecorded signaturesで、独立finding数や全runtime unique数へ換算しない。受入は有限local componentだけで、R28実入口・新公開17source合同・CI / fresh reviewはPENDING。native URI / auth / transport / 全client runtime安全や自動Goal成功を証明しない。詳細は[ガイドのR28節](docs/security/git-command-guards.md#r28-forwarding-request-data-と入力-source)を参照する。

---

## アーキテクチャ概要

```
OneTab.txt（URL一覧） または X ブックマーク (Playwright)
    │
    ├─ evaluatePolicy()      サイトポリシー判定（skip / review / auto）
    │
    ├─ [実行前確認]           処理件数・出力先を表示 → ユーザー [y/n] 確認
    │
    ├─ fetcher.ts            Playwright でヘッドレスブラウザ取得
    ├─ extractor.ts          Readability + Turndown で Markdown 化
    │
    ├─ classifier.ts         2段階 AI 分類
    │   ├─ snippets参照       _分析コンテキスト/snippets_YYYYMMDD.xml（最新版自動解決）
    │   ├─ Fast Pass         軽量モデル（Haiku / ローカル LLM）
    │   └─ Smart Pass        高性能モデル（Sonnet / GPT-4o）エスカレーション
    │
    ├─ router.ts             公開日付 + 記事数閾値による動的フォルダルーティング
    │   └─ folder_rules.json  sync-rules.ts で snippets から自動同期可能
    │
    ├─ [分類結果レポート生成]  context/分類結果レポート/OneTab分類結果レポート-YYYYMMDD.md
    │
    ├─ [承認確認]            Obsidian でレポート確認後 → y / e / q で操作
    │
    └─ storage.ts            Vault へ .md を保存（7段階パストラバーサル防御）
```

## 主要機能

- **自動 Web フェッチ**: Playwright によるヘッドレスブラウザで SPA・動的ページも確実に取得
- **2段階ユーザー確認**: 実行前（件数・出力先の表示）と分類完了後（レポート確認）の 2 回、承認を求める
- **2段階 AI 分類 (Fast / Smart Pass)**:
  - Fast Pass: 軽量モデル（Haiku、ローカル LLM）で既存フォルダへ高速分類（コスト最小）
  - Smart Pass: confidence < 0.7 のとき高性能モデル（Sonnet、GPT-4o）へ自動エスカレーション
  - snippets 参照: `_分析コンテキスト/snippets_YYYYMMDD.xml`（最新版を自動解決）を `historical_rules` としてプロンプトへ注入
- **動的フォルダルーティング**: 記事数の閾値に応じてフラット → 四半期 → 月別へ自動昇格、既存ファイルも引越し
- **snippets→folder_rules 自動同期** (`pnpm run sync-rules`): snippets の日付パターンからルールを推定し `folder_rules.json` へマージ
- **セキュリティ強化**:
  - 7段階パストラバーサル防御（URL デコード迂回 / 絶対パス拒否 / Unicode NFC 正規化 / `..` 即時拒否 / symlink 解決検証）
  - プロンプトインジェクション緩和（`sanitizeUntrustedText` + `<untrusted_content>` デリミタ + システムポリシープロンプト）
  - AI 出力パスの検証（`validateClassificationResult`）
  - Claude Code の Bash / Git ガード: shell の引用・escape と実行 source を解析し、対応済み条件の充足、禁止操作の確認、判断不能を区別する。後二者は停止し、理由を `[禁止]` / `[判断不能]` と示す。対象や実行条件を確定できない変数・glob による add や設定を差し替えた Git も fail-closed とする（対応範囲、代替、owner 確認、試験3層: [Git ガード](docs/security/git-command-guards.md)）
    - 通常の release tag 作成・削除・署名・検証、notes 更新、stash push / pop や管理も、検査範囲外の object / ref / working state 操作として `[判断不能]` で停止する。commit `-F` / `-t` と merge `-F` の source、commit 前の grep pager、curl の query file 入力にも制限がある。対応する query / literal DATA と、同目的の writer 代替がない場合の owner 確認は上記ガイドを参照する。
    - R12 では、既定の editor も含め、未検査の editor が起動し得る Git 操作を `[判断不能]` で停止する。普通の merge も実際の `--no-edit` と確定 argv が必要となる。commit の対応 `-m` / `-F` / `-C`、実 `--no-edit` / dry-run 等は editor を起動しない条件だけの対照であり、index・message source 等の別条件も満たす必要がある。実行名の glob / brace / tilde、mapfile / readarray の実 `-C` callback、Bash の実 `/dev/tcp` / `/dev/udp` redirection、remote rsync の明示 remote-shell helper は同じく停止する。一方、literal の FD 複製・close と正確な `/dev/null` 出力は、index を書き換える redirection と区別する。通常作業への影響と同目的の代替条件は上記ガイドに記載する。
    - R13 では、実 coproc、未確定の動的実行名、hash-object の全 object 書込み、active difftool を `[判断不能]` で停止する。xargs 等から curl / wget / gh へ渡る未知 argv、curl の未確定 option / URL と追加 argv、rsync / scp の未確定な宛先・引数個数も同じ扱いになる。curl の実 cookie file 入力は、確定した対応条件では `[禁止]`。commit に関わる Git の `-c` / `--config-env` は、対応する表示・identity key と実 stdout usage 等の条件を満たす必要がある。通常の array executable・公開 object 作成・difftool・生成 query 等にも影響するため、同目的の対応形式がなければ対象と実行条件を owner に確認する。
    - R14 では、呼び出した shell 関数の本文を検査し、未検査の shell stdin / script file / dot・source、確定しない eval source、child Bash の BASH_ENV、Git / SSH / SCP / SFTP / remote-shell rsync / Wget が選ぶ認証・接続 helper を `[判断不能]` で停止する。curl は実 first literal 引数の正確な `-q` / `--disable`、Wget は実 `--no-config` で既定設定を無効化した対応 argv が必要となり、通常の GET・download・help / version にも影響する。使われない関数定義や印字 DATA、確認した local query / local copy を区別し、既存の Git context / 関数 shadow 条件は維持する。R14 の凍結 source は直接入力3498件と解析33件で確認し、CLI実入口は8試行中6件で確認、2件はBash前に停止したため未実施とする。過去 round の結果は持ち越さない。対応条件と代替・owner 確認は上記ガイドを参照する。
    - R15 では、interactive shell の ENV、child が選ぶ imported / exported function（`set -a` 等の自動 export を含む）、単独 Git 操作の active 外部 helper を `[判断不能]` で停止する。未使用の既知関数や、external diff を呼ばない通常の log の DATA は区別する。GNU timeout / nice / stdbuf は実 option の値・duration / buffering mode・child を分け、未知 / 省略形 option は停止する。共通 gh payload 分類は Release upload / create asset と edit notes file と Issue 本文 file / stdin を扱い、公開 artifact も既存の file-upload 禁止に含む。SSH `-n` でも remote command の展開結果を検査し、Git push option の DATA も named remote / ref / index と別に検査する。対応する source・argv・context で secret filename 読取が payload に結び付けば `[禁止]`、source や送信先を確定できなければ `[判断不能]` となる。Vault wrapper の filename predicate と NUL 読取も同期し、通常の LF を含む filename は判断不能で停止する。代替と通常作業への影響は上記ガイドに記載する。R14 の数値は履歴であり、R15 の全 suite / CLI 実入口 / CI の結果には持ち越さない。
    - R16ではGH本文 / notes / titleの生成値もSSH / push-optionと共通に追跡する。quoted scalarの語数確認と、送信値の生成元の確認は分ける。関連secret readerは禁止、未追跡の生成値 / selectorは判断不能、対応literal / exact scalar proofは許可。通常影響と出口はガイドのR16節へ記載する。
    - R18では、Git の no-verify 判定に対応する既知の単一語の値も使う。実 option と確認した hook 回避は禁止し、未知の argv が hook 回避 option を選び得る場合や、消費値が複数 argv に展開し得る場合は判断不能で止める。通常の `git push origin "$REF"` も、REF の意味を確認できなければ影響を受ける。実 `--` と対応 option の単一語 DATA は区別するが、未解決の短い attached `-o"$VALUE"` は空値で境界が変わり得るため停止する。config / branch / remote / add / stage の未知値は、既存の設定・action・path の担当で扱い、この境界だけでは新しく一律停止しない。同じ対象・条件を保てる literal / 値の証明を検討し、対応形式にできない場合は owner へ確認する。全 push の一括禁止ではなく、他の source / cwd / env / config 条件も残る。測定・代替の詳細は上記ガイドのR18節を参照する。
    - R19 の修正では、cwd / source が不明な add / stage、commit 前の legacy config writer、mktag、active fsmonitor / archive helper を `[判断不能]` で停止する。Wget cookie、GH key file、remote rsync files-from と、curl の `--netrc-file` / `-n` / `--netrc` / `--netrc-optional` は既存の file 送信禁止へ結び付ける。commit の message / author / date / trailer と、選択された identity env / config の生成値も出所を検査し、nameref で証明が失われた identity は UNKNOWN とする。通常の公開鍵 upload、fsmonitor を使う status / rm / mv / am、未証明の MSG / AUTHOR や内側 context を伴う生成にも影響する。消費 DATA・未使用 selector、netrc の個別解除、最後の identity 値、literal / 対応 scalar・stdout proof と owner への出口は[ガイドの R19 条件表](docs/security/git-command-guards.md#r19-修正の条件結果例外)を参照する。最終4 source の旧3834入力・旧期待の比較（2026-10-14 05:38:48 JST）は3821一致・13件がALLOWからegress UNKNOWN・broken 0・source不変。13入力を保持して期待を変更し、最終統合4021件（旧3834＋新187）は05:48:39 JSTに4021/4021・broken 0・source不変。公開解析55・filename parity 8・停止API 6の69契約、私有metadata14、公開指摘11入力と追加12入力の単一edge reverseは別々に確認済み。CLI実入口の新DUMMY2試行は、mktag停止と既知message commit許可を3 hookのdispatch・副作用と併せて確認した。API前段の拒否・timeoutと、試験器の事前untracked状態の期待を直す前のFAILも保存し、成功に加算しない。CI / fresh review / threadの時点付き状態はPR本文・監査記録で確認し、過去roundの合格を変更sourceへ持ち越さない。
    - R20 は active chroot、Git の選択された pager、GH secret / variable set の payload、Git imap-send の stdin を扱う。未検査の実行 source / 送信条件と secret の no-store mode は `[判断不能]`、確定した file 送信と秘密由来 payload は `[禁止]`。通常の chroot・custom pager・公開 env-file / 未知 stdin 登録・公開 mail 送信にも影響するため、対応する query / ordinary inline DATA / actual pager disable と owner への出口は[ガイドの R20 条件表](docs/security/git-command-guards.md#r20-修正の条件結果例外)を参照する。commit identity は値と export 属性を分け、未 export の shell local を誤って送信値としない。caller locale の parity 試験は利用可能な optional locale だけを実行し、不在 variant を記録する。最終 source は4124/4124・broken0・source不変、解析66 / parity8 / 私有停止API6の80契約が成功。旧4021の3期待変更と新unique103入力の理由、初回失敗、DUMMY実入口3 PASS / 2 API前段NOTをガイドと監査記録へ残す。CI / fresh review / threadは公開headで別に確認し、R19の証拠を新sourceへ持ち越さない。
    - R21 は Git send-email、GH workflow run の file / stdin / generated input、active filter-branch と Git daemon、Bash の PS4 / xtrace を扱う。確定した file 送信や秘密由来 payload は `[禁止]`、未検査の送信・サーバー公開・history rewrite・実行 source は `[判断不能]`。通常の公開 patch 送信、workflow file 入力、repository server、filter、動的 trace prompt にも影響する。unused / static PS4 と実 usage、消費 DATA を区別し、解除命令自身より前の trace 展開も検査する。対応範囲・代替・owner への出口は[ガイドの R21 条件表](docs/security/git-command-guards.md#r21-修正の条件結果例外)を参照する。最終v4の4208入力・94契約、私有metadata30と単一edge反転14を確認し、old4124の入力・期待は全維持。普通literal stdinの新実入口2 PASSと、旧v3の4 PASS / 1 API前段NOTはsource別に記録する。R20 の合格を変更 source へ持ち越さず、公開 head の CI / fresh review / thread を別に確認する。
    - R22 は、公式の有限 inventory に基づき、Git の driver / 直接 entrypoint、server / callback / SCM / object / 将来 helper 設定と、GH の本文 / file / stdin / 送信 metadata と、editor / browser / pager / 設定 root 等の実行 source を別に検査する。確定 file 送信や関連 secret reader は `[禁止]`、未検査の選択 source・生成元・argv / mode / context は `[判断不能]`。未対応の Git subcommand / 直接 `git-*`（未検査の Git LFS を含む）、GH auth refresh / setup-git の選択 source も停止する。通常の公開 file 投稿、custom helper、明示設定 root、implicit push / fork を伴い得る PR 作成、login / interactive startup にも影響する。PR create は対応する既知の非空 `--head` が必要で、`--json` は GH pager の解除条件ではない。skill publish の実 `--dry-run` / `--fix` は投稿しない mode だが、明示設定 root の判定は独立して残る。ENV / BASH_ENV は child への実 export、空値、POSIX / interactive / privileged 等の mode と順序を区別する。対応代替・owner への出口と検証範囲は[ガイドの R22 条件表](docs/security/git-command-guards.md#r22-gh-と-shell-の-source-と操作の境界)を参照する。固定v10の4569入力・102契約と、旧4208入力を保った新旧比較を確認した。実CLIの新DUMMY6試行は5 PASS / 1 API前段NOT_EXERCISEDで、通常検索の実dispatch未確認も記録する。公開headのCI・fresh review・threadは別に確認し、R21の成功を持ち越さない。
    - R23 は、Git am の未検査 mailbox / resume と HTTP cookie source、SCP / SSH の active helper、curl の ETag file と接続 cache を、操作・選択順・実行条件で区別する。確定 file payload は `[禁止]`、未検査 source は `[判断不能]`。通常の公開 patch / cookie / ETag file / proxy helper にも影響する。受信・local copy の条件、未使用 selector、同目的の代替と owner への出口は[ガイドの R23 条件表](docs/security/git-command-guards.md#r23-修正の条件結果例外)を参照する。R23 の全受入は未完了で、固定 source の解析・判定・reverse・実入口・CI・fresh review を別々に取得する。
    - R24 は、Git HTTP が選ぶ header / User-Agent の生成元を検査する。header の追加 / empty reset、UA の実 environment 優先、numbered config と `-c` / `--config-env` の役割を保持し、対応条件で秘密由来を確認すれば `[禁止]`、選択・生成元・argv / context が未証明なら `[判断不能]`。動的 metadata や未証明の将来設定 writer にも影響する。ordinary DATA / getter / 実 query と独立 family を区別し、同目的の代替・owner 出口・Git 2.54 の版境界は[ガイドの R24 条件表](docs/security/git-command-guards.md#r24-git-http-metadata-の選択と生成元)を参照する。私有固定 source の検証と、新公開 bank / CI / fresh review の受入を分け、R23 の成功を持ち越さない。
    - R25 は、curlの選択された送信値、Git protocolのproxy / SSH source、SSHのfirst-selected login / host metadataをoperation / export / 選択順と結び付ける。curlはscalar後勝ち / additive / nextと実backendを分け、8.7.1で無効なlong略記・equalsをnative有効形式と認定しない。新producerのunsupported grammarは`[判断不能]`、対応source / role / contextで秘密由来を確認すれば`[禁止]`。Gitのraw domain:port / fetch-pack、独立条件を保つknown-empty proxy、SSHの`-N` / `-n`と独立したmetadataを扱う。通常影響・同目的代替・owner出口は[ガイドのR25条件表](docs/security/git-command-guards.md#r25-送信値と-transport-source-の選択条件)。fixed sourceの取得時刻付きlocal検証と公開headのCI / fresh reviewは別に判断し、旧FAIL / NOTを保持する。
    - R26 は vault の staged filename ゲートで、`printf` / allowlist grep / secret grep の各終了状態を直後に取得する。producer の失敗・grep error は判断不能として止め、部分的な secret 一覧を公開せず、このゲートで何も unstage しない。正常な match / nonmatch と filename 規則は維持する。通常影響・同目的の再検査・owner 出口・実測範囲は[ガイドのR26条件](docs/security/git-command-guards.md#r26-vault-の-staged-filename-判定-error)を参照する。
    - R27 は、Wget inline body / header / credential、Ncat / Telnet auth・login、SSHのactive session SetEnv / SendEnv・PTY TERM、Git pushのdestination refを、選択role / protocol / export / sessionと値の生成元へ結び付ける。秘密由来を対応active値で確認すれば禁止、不足条件は判断不能。SSHの実 `-N` / SessionType-noneによるenv inactiveと `-n`のstdin制御は分け、接続metadata等の独立条件を保持する。通常影響・同目的代替・owner出口・未取得の最終検証は[ガイドのR27条件](docs/security/git-command-guards.md#r27-送信値と-session--protocol-の条件)を参照する。v5のbank5253は元5044入力を保持し、未知header / dst / customprogramの7期待を理由付きでUNKNOWNへ採用した定義で、fixed-v5全bank5253と公開契約138はlocal成功を取得した。実入口は1PASS/4NOTで、公開head CI / fresh受入は文書cutで未完で、旧FAIL / NOTと過去roundの結果を保持する。
  - security-guidance プラグイン（公式）: Claude Code が書くコードを編集時 / ターン終了時 / commit 時の 3 層で自動セキュリティレビュー。`.claude/claude-security-guidance.md` で本リポの脅威モデルをレビュー観点に注入（詳細・既存防御との棲み分け: `docs/security/security-guidance-plugin.md`）
- **dry-run モード**: `--dry-run` は Vault へ一切書き込まない（分類レポート・失敗ログは Vault 外の一時ディレクトリへ出力し、スナップショット / `folder_rules.json` 昇格の永続化も抑止）。実行前後で Vault ツリーが不変であることをテストで保証
- **Vault Root 外部化**: `pipeline_config.json` または環境変数 `VAULT_ROOT` で設定、ハードコードなし
- **中断リカバリ**: `pnpm start -- --rescue <レポート>.md` でレポートファイルから API コスト $0 で保存を再開（`rescue-from-report.ts` / `--dry-run` 併用可）
- **週次 LLM 脅威レポート取込・該当性レビュー** (`/sec-mode` → `/sec-review`): Gmail 取込 + injection ゲート + DB 取込 → 本リポ該当性レビュー（詳細フローは `docs/security/` / `docs/threat_reports.md`）

---

## 環境要件

| ツール | バージョン |
|---|---|
| Node.js | v24.15+（24.x）または v26+（v25 は非対応: jsdom の engines に合わせる） |
| pnpm | v9+ （推奨: v10、`packageManager` で固定） |
| tsx | `pnpm install` で自動インストール |
| Playwright Chromium | `pnpm exec playwright install chromium` |
| API キー | Anthropic / OpenAI / Gemini のいずれか（またはローカル LLM） |

---

## セットアップ

```bash
cd pipeline
pnpm install
pnpm exec playwright install chromium
```

> pnpm は [Corepack](https://nodejs.org/api/corepack.html) で `corepack enable` から導入できます。本リポジトリは `package.json` の `packageManager` フィールドで pnpm のバージョンを固定しています。

---

## 実行コマンド

基本的な実行コマンドを以下に示します。応用的なコマンド（フォルダルール同期 / X ブックマーク取り込み / ハンズオン生成 / 中断再開 / ナレッジ統合 / 対話型レビュー）は [実行コマンドリファレンス](docs/cli-reference.md) を参照してください。

### 初回設定ウィザード

```bash
pnpm start -- --config
```

プロバイダー（`local` / `anthropic` / `openai` / `gemini`）、Vault Root パス、使用モデルを対話形式で設定。
設定は `pipeline_config.json` に保存され、次回以降はスキップされます。

### 通常実行

```bash
pnpm start ../context/_分析コンテキスト/OneTab_YYYYMMDD.txt
```

実行前に処理件数・レポート出力先を表示し `[y/n]` で確認します。分類完了後は `context/分類結果レポート/` にレポートが生成されるので、**Obsidian でレポート内容を確認してから** `[y/e/q]` で承認・修正・キャンセルを選択してください。

### dry-run（ファイル書き込みなし）

```bash
pnpm start ../context/_分析コンテキスト/OneTab_YYYYMMDD.txt --dry-run
```

---

## API キーの設定

```bash
# Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export OPENAI_API_KEY="sk-proj-..."

# Google Gemini
export GEMINI_API_KEY="AIza..."
```

`~/.zshrc` への追記を推奨します。

> **X (Twitter) ブックマーク取り込みは OAuth 2.0 PKCE ベースです**。`X_CLIENT_ID` / `X_CLIENT_SECRET` を `.env` に設定し、`pnpm start -- --x-auth` で初回認可してください。詳細は [実行コマンドリファレンス](docs/cli-reference.md) の「X (Twitter) ブックマークの取り込み」節を参照。

---

## 再利用について

パスや分類ルールが私の Vault 構造にハードコードされている箇所があります。
別環境で使う場合は `pipeline_config.json` の `vaultRoot` と `folder_rules.json` を調整してください。
AI プロンプト設計・Playwright フェッチロジック・TypeScript 構造のリファレンスとして自由に参照ください。

---

## 関連リポジトリ

- **[obsidian-ai-pipeline](https://github.com/theosera/obsidian-ai-pipeline)** — パイプライン単体の公開リポジトリ（設計リファレンス）
- **obsidian-vault-skills** (private) — Vault 全体の管理リポジトリ（本ファイルが含まれる）
