# .claude/

このディレクトリは Claude Code (本プロジェクトの AI 開発エージェント) が
セッション開始時に自動で読み込む project-level 設定を置く場所。

## commands/

project-level スラッシュコマンド (`.md` ファイル) を置く。ファイル名が
コマンド名になる (`sec-mode.md` → `/sec-mode`)。frontmatter で
`description` / `allowed-tools` を宣言し、本文がプロンプトとして実行される。

| コマンド | 用途 |
|---|---|
| `/sec-mode` | Security-only mode を起動し、週次 LLM 脅威レポート取込メニューを提示する。セッション途中でも呼べる (CLAUDE.md `## Chat mode protocol` の救済経路)。上位仕様は `docs/security/llm-sec-report-consumption.md`。 |

## skills/

project-level スキル (`<name>/SKILL.md`) を置く。ディレクトリ名がスキル名になる。
`description` のトリガ文 + 親 `CLAUDE.md` の**スキル発火表**で発火する。トークン削減の
ため、特定タスクでしか要らない作業規約・機能知識を常時ロードの CLAUDE.md から外出しし、
発火条件付きでオンデマンドにロードする (3層設計: グローバル / project CLAUDE.md / skills)。

| スキル | 発火条件 | 用途 |
|---|---|---|
| `pr-workflow` | PR 作成 / auto-merge 判断 / PR body / CI 期待値確認の前 | auto-merge Phase1 + guards / PR 規約 / CI 期待値 |
| `x-bookmarks` | X bookmarks のコード・CLI・`X_Bookmarks/`・mapping json を触る前 | X bookmarks 機能の実装事実集 (SQLite / Dataview / 要約 / invariant) |
| `ts-coding-conventions` | このリポの TypeScript を書く/直す/レビューする前 | AI-native 規約の発火用サマリ (原本は `docs/ai-coding-conventions.md`) |
| `scan-threat-report` | sec-mode 取込で脅威レポート本文を扱う前 | injection ゲート L0〜L3 (検知+報告のみ) |

## settings.json

**全コラボレータに共有される設定**。git commit する。

### permissions.deny の意図

Secrets 漏洩防止 — 以下のパターンに該当するファイルを Claude (自分自身) が
**Read / Bash 経由で読まない**よう物理的にブロックする。

| 対象 | 例 | 理由 |
|---|---|---|
| `.env` / `.env.*` | API キー、DB URL | Git/Vault filename判定のtemplate例外はfinal basenameの `.env.example` だけ。保護対象ancestorの判定は維持 |
| `credentials*.json` / `service-account*.json` | GCP / AWS 認証情報 | OAuth client secret 等 |
| `token*.json` / `x_tokens.json` / `data/tokens.json` | X / Gmail OAuth refresh token | 長期有効資格情報 |
| `*.key` / `*.pem` | SSH / TLS / JWT 署名鍵 | 暗号鍵全般 |
| `id_rsa` / `id_ed25519` | SSH 秘密鍵 | パスフレーズ無しは即危険 |
| `secrets.{json,yaml,yml}` | 汎用 secrets | 名前から自明 |

Bash 側も `cat` / `head` / `tail` / `less` / `more` / `grep` / `awk` / `sed`
での読み出しを deny — Read tool を bypass するパスを塞ぐ。

### deny は許可リストに勝つ

Claude Code の permission 評価は **deny が allow より優先**。安全側に倒れる。
誤って読もうとした場合 user に approval ダイアログが出ず、即拒否される。

### 動作確認

```bash
# Claude Code セッション内で
# 「.env を読んで」とお願いしても、Read tool が即 deny で失敗するはず。
# bash 経由でも:
cat .env  # → permission denied (deny rule に該当)
```

### 関連

- `docs/security/llm-sec-report-consumption.md` §6 で TODO 化していた項目
- LLM-Sec-Weekly レポートの「Secrets 漏洩対策」推奨に対応
- 既追跡の secret 発見時の対応は CLAUDE.md「Secrets / sensitive files」節
- Bash 側の予防は `.gitignore` (commit 段階) と本ファイル (read 段階) の二重防御

### PreToolUse の Git / egress hook

<!-- PR191:R57:CLAUDE-README:BEGIN -->

[現在の契約への固定入口](../docs/security/git-command-guards.md#current-guard-contract)に、R61修復候補を置く。見つからないcommandで実選択されるhandler、`wait -p`のtarget検証と後続proofの無効化、Gitのactive operation/routeで選ぶ実効helperが対象である。選択条件・正常対照・停止費用・受入条件を示す。新sourceの全件・同head CI/reviewの完了は別に確認する。未使用handler、通常scalar/PID待機、qualifiedな設定不在、getter/inactive statusの正常対照を保持できるかを検証する。

共有入力のJSON全体1 MiB・decoded commandのUTF-8 32 KiBと、Hookの一起動全体のcommand visit 4,096回・source累計262,144 UTF-16 code unitsを引き継ぐ。関数・子source、後段の追加解析、直接のshell解析も同じ予算を使い、不足時は部分結果を許可に使わず即座にUNKNOWN。長い正常な本文・heredoc、多数の関数呼出し、重複確認も止まり得る。[R60の境界・正常対照・既知の限界](../docs/security/git-command-guards.md#r60-resource-contract)を参照する。

同じ目的・対象・操作・順序・必要なwrapper・argv・cwd/env/config/sourceを保てる対応形がなければownerへ不足条件を示す。設定変更・新L3の資格を含めない。[R57の歴史の契約](../docs/security/git-command-guards.md#r57-current-contract)と以下のround別記述は当時の履歴である。元入力・元期待・既存profile/policy契約を保持し、新sourceの全件・同head CI・両fresh review・指摘処理・本文一致を別に確認する。

<!-- PR191:R57:CLAUDE-README:END -->

<!-- PR191:R51:CLAUDE-README:BEGIN -->

[R51当時の契約](../docs/security/git-command-guards.md#r51-current-contract)では、直接のspecial builtinのprefix代入を非exportと断定せず、未資格のmode・版によるchild option順序やGH metadata等のsource選択をUNKNOWNで止める。literal ordinaryなGH_HOSTでも特殊prefixは停止し得るため、意味を保つ明示export等の条件とowner出口を契約に記す。getentの既知service指定後の真正query、実際のexport解除、普通の対照を別に保つ。単体補助と全件runnerの不正deny理由はBROKENとして失敗させる。当時、自動読込される`CLAUDE.md`にもR51契約を示した。ここに記す受入未完了はR51当時の状態であり、現在の受入判定へ持ち越さない。

<!-- PR191:R51:CLAUDE-README:END -->

<!-- PR191:R50:CLAUDE-README:BEGIN -->

### R50: child環境・正常query・理由prefixの確認

先行する未exportの`POSIXLY_CORRECT`をchildへ継承したと扱わず、prefix/export/解除・不明presenceとchild scopeを分ける。getentの真正後置queryは、実`--`や消費DATAと区別する。既存clientのoption順序が不明な境界だけをUNKNOWNとし、全clientの一律停止にはしない。[R50の契約](../docs/security/git-command-guards.md#r50-current-contract)に正常対照、loggerの固定consumerによる反証、停止後の出口を示す。

loggerのfile/message優先とsocket-errorsのarityは、help・診断文だけで実consumerと逆に変更しない。未知のdeny理由prefixは試験上BROKENとして検出する。候補の全件・新head CI・両fresh reviewは別の受入gateで、旧成功やHook DATAをnative送信・新L3へ持ち越さない。

<!-- PR191:R50:CLAUDE-README:END -->

<!-- PR191:R49:CLAUDE-README:BEGIN -->

### R49: selected resolverとremote logger

egressは`getent`のhost系keyと、util-linux `logger`のremote DATAを有限に検査する。[R49の契約](../docs/security/git-command-guards.md#r49-current-contract)に、database/option境界、server優先、messageによるfileの非選択、stdinの生成元、local/query対照と通常利用への費用を記す。秘密由来が確定した選択値やfile uploadはFORBIDDEN、未解決source/argv/contextはUNKNOWN。両者とも既存deny wireで止める。実DNS/syslog送信、新L3、任意のNSS/backendの安全性を認定する修復ではない。

<!-- PR191:R49:CLAUDE-README:END -->

<!-- PR191:R48:CLAUDE-README:BEGIN -->

### ガード全体のCI検証

必須root CIは全component test、別filename parity、standaloneの全L2 bankを実行する。[R48のCI契約](../docs/security/git-command-guards.md#r48-ci-contract)に、固定Git 2.54.0・owned fixture環境・再実行方法を示す。bankのcommandはHook JSONのDATAとして渡し、upload等の提案commandを実行するものではない。能力不足を理由に全bankをskipして緑へ変えず、失敗は必須jobの失敗として返す。新headのCI結果は実行後に別途確認する。

<!-- PR191:R48:CLAUDE-README:END -->

<!-- PR191:R47:CLAUDE-README:BEGIN -->

### R47: own Git検査の実filesystem・loaderとopaque launcher source

**修復作業中のsnapshot**。2026-10-19 02:35:24 JST時点、公開基点head `ec3bd520ef450fb2899bef1f33618417158e4ff8` に対する未commitのR47 candidateは修復作業中であり、この当時の最終source固定・統合全件・新公開head／同head CI／両fresh reviewと全指摘処理は未取得・PENDINGである。

[R47当時の契約](../docs/security/git-command-guards.md#r47-current-contract)を参照する。own検査はbase cwdからvalidated raw `-C`を順に一回渡し、symlink/`..`をlexicalな別対象へ縮約しない。PATHでcalleeを選ぶ段階と`-C`後の検査対象を分け、raw PATH候補lookupとnative realpathを既知installへ結ぶ。AG/EGはphysical CWDを使う一方、add pathspecはGitのlexical normalize先行・親canonical化・最終in-tree symlinkの個別entryを保つ。通常root-link個別追加ALLOWと`link/..`のroot包括FORBIDDENを分け、外側symlinkからrootへのselection不明はUNKNOWN。有限15名のloader変数はplatformでactive/inactiveを区別し、既知emptyは削除せず保持する。activeな非空・未知や、空の無効化を未資格の値はnative Git前にUNKNOWNとなり、通常のcommit/queryも止まり得る。

`capsh`/`start-stop-daemon`のactive commandは普通のprintfでもidentity・shell/program・cwd/env/backend未資格の費用でUNKNOWNとなる。pinned libcap2.77/dpkg1.22.22のqueryと消費DATAを有限に区別し、後置helpや`capsh --version`で前段sourceを免除しない。native検査依存testはactual option queryの能力でgateし、不対応時のnative群skipとpure DTOを分ける。fsmonitor版下限、Git2.54固定consumer資格、全OS/backendの保証は同一ではない。

同じ対象・操作・必要launcher/loader・identity・cwd/env/configを保つ対応形だけを選び、保てなければownerへsource/contextとUNKNOWN理由を示す。必要条件を外す形やHook停止を同目的とせず、個別操作承認をbypass承認にしない。今回のAPI／実送信、active launcher／loader constructorのnative成立、新L3は未証明。旧8696 bank/oracle・原FAIL/NE・以下のround履歴を変更しない。

<!-- PR191:R47:CLAUDE-README:END -->

<!-- PR191:R46:CLAUDE-README:BEGIN -->

### R46: own Git検査を実行予定のcontextへ結び付ける

**修復作業中のsnapshot**。2026-10-19 00:15:41 JST時点、公開基点head `c3b8371b35550f01587d944c5b0d35ea75b234b6` に対する未commitのR46 candidateは修復作業中であり、この当時の最終source件数・統合全件・新公開head／同head CI／両fresh review・全指摘処理は未取得・PENDINGである。 同公開headのCodex normal review5563562682は2026-10-18 23:58:48 JST、CodeRabbit normal full5563566259は23:59:20 JSTに完了したが、23:59:45.256–23:59:52.394 JST取得の全220threadには新3件（Codex P1 4307502905・4307502909、CR Minor4307504522）が未解決で残る。

[R46当時の有限契約・通常費用・owner出口](../docs/security/git-command-guards.md#r46-current-contract)を参照する。own Git検査は解析したcommitのprogram・selected env・cwdへ結合し、PATHで見つけたGitをそのまま信頼集合へ足す循環を除く。既知固定installのrealpathを独立起点にし、bare Gitはselected PATHの先頭実候補を確認する。absoluteな既知Gitを別のPATH shadowへ差し替えず、`env -u`／unset／`env -i`で消えたtracked名をprocess.envから復活させない。

未知install・動的/欠落PATH・`command -p`・未復元envは局所UNKNOWNとなり、正当な通常commitにも費用がある。必要な実行体・対象・cwd/env/config条件を保つ対応形だけを検討し、保てなければownerへ不足source/contextを示す。owner個別承認をHook停止の承認とはしない。sanitation・実取得banner・cacheのcontext結合はbinary内容由来/置換race/全OSの安全保証ではなく、native commit/helperや新L3も実証しない。以下のR38以前は取得cutに結合した全文履歴として保持する。

**R46局所調整snapshot**: 2026-10-19 00:43:29 JST時点、公開基点head `c3b8371b35550f01587d944c5b0d35ea75b234b6` に対する未commit candidateの最終新freeze・統合資格・新head/CI/freshは当時未取得・PENDINGである。 index/config検査の環境projectionを従来のactual reader/outboundのwide trackingから分離し、index専用ではAUTHOR/COMMITTERのNAME/EMAIL/DATE計6値を検査envへ載せない。実commit identityと送信policyは別wide guardで維持する。静的なordinary/identity向けnameref宣言だけをindex namespace不明とはしない一方、Git/PATH/config等の重要name/target参照や動的・無代入・未対応targetはUNKNOWNとし、後者をactual childのenv-i clear以外で勝手に解除しない。nameref全般の対応保証ではない。初回全件の過剰拒否FAILと元期待は保持し、前記の同目的条件を保つ代替とowner出口を変えない。

<!-- PR191:R46:CLAUDE-README:END -->

<!-- PR191:R38:CLAUDE-README:BEGIN -->

### R38: 既存dispatch上の有限契約

この節は私有最終sourceのローカル受入cut（2026-10-16T10:57:01.166111+09:00 JST）。新公開head・同head CI・fresh両review・実入口は未取得のまま分ける。後続の公開結果はPR本文と監査台帳へ記録し、このcutの履歴へ遡及させない。

R38はEGのDNS/Netcat/Wget sourceとAGの先行cd後pathspecを対象にする。[三結果・通常費用・owner出口・試験](../docs/security/git-command-guards.md#r38-current-contract)を参照。既存settingsは不変で、Bash全体のEGと条件付きSG/AGのdispatchを区別する。引用で結合したGit名のownAG単体結果も実settings dispatchの保証ではない。

ローカル受入は固定runtime sourceで直接入力8454/8454・broken0（25362 Hook呼出し）、role解析699/699と別のproduction shell parity15/15、通常root test602/602・typecheck・lint・package.json重複検査が成功。新公開head/requiredCI・両fresh review・必要な実入口L3は **PENDING**。旧公開2796のCI成功は別cutの観測である。

以下のR37以前の本文・数値・「current／現在」は、それぞれのsourceと取得日時に結合した履歴である。旧本文と順序を保持し、R38の新sourceでの測定結果へ読み替えない。

<!-- PR191:R38:CLAUDE-README:END -->

<!-- PR191:R37:CLAUDE-README:BEGIN -->
<a id="r37-claude-readme-contract"></a>
[R37当時の有限契約・通常影響・owner出口](../docs/security/git-command-guards.md#r37-current-contract)。

**R37 guard契約（固定sourceのローカル受入済み・公開前cut）**: 基点は公開 `7b3436bc49f8736c7b465de026a2510ae0e6b0cf`。引数の役割、実行されるprogram/source、resolver/authentication/payloadの役割、値の生成元を分ける有限修復です。対応条件を満たす経路はALLOW、確認したpolicy違反はFORBIDDEN、不足するsource/argv/contextはUNKNOWNとして、後二者は既存deny wireで停止します。

Git command-scope設定のopaqueな選択、util-linux2.39.3のflock childと選択context、queryを含むprogram/PATH identity、選択された有限hyphen function sourceを扱います。query風argvでも、実programと `exec -a` のargv0を同一視しません。既知empty/COUNT0/unused設定、通常direct child、正しいquery、消費DATA、未使用functionは各判定の正常対照を保ちます。ordinary function-unsetでは、削除され得る既存の認識済みmapだけをopaqueにし、後続の選択callをUNKNOWNにします。variable-only、未対象/未使用、解析済みlocal unset、外部unsetや真のqueryの対照を保ち、全function lifecycleを認証しません。部品の閉鎖と統合sourceへの結合は別です。

curl tool/libcurl8.7.1の明示cert/key/proxy credentialは、raw file uploadと区別し、activeなbackend/sourceが未証明ならUNKNOWNです。certificateの既知empty/last-empty clear、sourceを選ばないtype-only、未使用proxy/CA・peer検証用readを一律にcredential送信扱いしません。positive TLS別名でも既存engine-sourceの停止を維持します。SRPの有限生成値対照は既存UNKNOWNがmaskするため、そのmaskをactivation情報の完全性やnative安全性の証明へ昇格させません。

OpenSSH9.6p1 keyscanの選択address/hostlist/stdinと、GNU Wget1.25.0のlast-selected bind resolverを区別します。普通の未検査hostlistや必要な認証・shell・contextでもUNKNOWNに止まる費用があります。同じ対象・host/bind・lock・operation・版/backend・cwd/env/config/sourceを保つ対応形式がなければownerへ確認します。必要なselector削除、別場所へのコピー、hook停止を承認済み代替とは扱いません。

L1の意味/metadata、L2の各hook自身の三結果・理由・正常対照・単一edge逆検証、L3の実settings dispatchと副作用を別に確認します。固定sourceのL1/parity/追加契約673/673、直接入力8204/8204・broken0・実Hook24612回が合格。旧7824のinput/順序/全oracle変更0、追加380unique・alias16の追加assertを確認した。逆検証は同じ合成sourceの100 Hook機能・455比較pair・2670実Hook呼出しを資格化し、別shell1機能は15pair/30test観測（Hook0）として保持した。必要性UNPROVED3機能と元逆期待FAIL5profileを保持し、UNKNOWNの独立maskや追加precisionを成功へ書き換えていない。新公開head/requiredCI/fresh両review/thread/必要L3は、この公開前cutでは **PENDING**。直接Hook DATAや旧実入口を新sourceの実証へ持ち越さず、native DNS/TLS/認証/通信は未検証のままです。R37は基線7824のinput・順序・oracle変更0を受入条件とし、過去R6P38の理由付き変更履歴を消しません。

**以下のR36以前は旧cutの履歴です。本文やリンクに「current／現在／現行」とあっても、各節に結合したsourceと取得日時の範囲を表し、R37の受入結果ではありません。**


固定ローカルcut（UTC）: 2026-10-15T22:34:05.996284+00:00。公開source inventoryは旧17＋追加本番契約test2＝19を別途同headへ結合する。旧7824との集計比較は別fixtureであり、同一実tupleの因果比較と混同しない。
<!-- PR191:R37:CLAUDE-README:END -->

<!-- PR191:R36:CLAUDE:BEGIN -->
<a id="r36-CLAUDE-contract"></a>
**R36 guard契約（固定sourceのローカル受入済み・公開前cut）**: util-linux 2.39.3のchrt/nsenter/tasksetはoption値・実query・PID0/child・contextを分けます。既知の通常child／有限scalar値は維持し、未対応context・implicit shell・未確定境界はUNKNOWN。R6P38の未確定taskset mask＋通常catは、元入力と元ALLOWを保存した理由付き **ALLOW→UNKNOWN 1件**です。必要なselectorを削除して目的を変えることを自動代替にしません。

OpenSSL 3.5.0／LibreSSL 4.0.0は選択configをquery/local modeより前に確認し、default configが未検査なら通常version/help/dgstもUNKNOWNになり得ます。既知empty configは必要provider/configを失わず同じ目的を保つ場合に限る対照です。通常argv0・実global queryとdelegated help、認証source、stdin、early-dataを分け、既知file-backed early-dataは通常名でも既存upload policyでFORBIDDENです。git amの実 `-n`／`-qn` はown add-allがFORBIDDEN、消費DATA／他commandの`-n`は同じ意味にせず、独立egressのUNKNOWNは残ります。

filenameのtemplate例外は**final basenameの `.env.example` だけ**です。`secrets/.env.example` や `.env.local/.env.example` のancestor保護は残り、root／通常directoryのtemplateを正常対照にします。file内容やuploadの許可を認証する例外ではありません。判定はALLOW／FORBIDDEN／UNKNOWN、停止理由と不足条件を分け、同じ対象・操作・条件を保つ対応形式がなければownerへ確認します。

[版・正常対照・owner出口・受入gate](../docs/security/git-command-guards.md#r36-current-contract)。文書cut **2026-10-16T05:34:54.883582+09:00**、固定manifest `98224bf12725…` / AG `5b5cce55a0d5…`。L1は**601/601（解析586＋parity15）**、current単一edge逆検証は**59機能（Hook58＋shell1）/239pairs/1374actual Hook入力**で閉鎖。curl UNPROVED2featuresと、別の3 masked profilesは区別して残します。**全7824/7824を新規実行してPASS**、failed0/broken0・23472Hook入力（2026-10-16T05:28:47.371000+09:00終了）で、旧7827からのprojectionではありません。旧7827 FAILED4、元cross08/09/10の不一致、正常query R23GA10とmasked R23GA11の同原因TypeError／1文字修復を保存しました。

旧7459入力/順序とR23GA10の元ALLOWを保持し、R6P38の理由付きA→U ledger1を分けます。旧R35以下はsource/日時付き履歴で、旧成功数を現在へ持ち越しません。**新headCI・fresh両review/thread・必要L3はこの公開前cutでPENDING**です。[PR #191本文](https://github.com/theosera/obsidian-ai-pipeline/pull/191)と同headの監査receiptで公開後の状態を更新し、この日時付きcutを将来状態へ読み替えません。全Bash egress／conditional secret-git・add-allを維持し、direct Hook DATAと実dispatchを区別します。実native/通信・Goal/ZIP完成・mergeを主張しません。
<!-- PR191:R36:CLAUDE:END -->

<!-- PR191:R35:CLAUDE-README-CONTRACT:BEGIN -->
<a id="r35-claude-readme-contract"></a>
**R35 guard契約（固定統合source・全件検証中）**: 同名のmoreutils/GNU `parallel`はbackendと暗黙設定/sourceを確定できないため、external invocationをUNKNOWNに止めます。ordinary job・help・no-job・EOF・`--plain`も現時点の例外にしません。同名local functionの実callと印字DATAは既存判定で区別し、別の確定したFORBIDDENは維持します。並列性やjob/argvを失う直列化・flag削除を同目的の自動代替とはせず、必要なbackend/version・設定・目的・対象・cwd/env/sourceをownerへ確認します。

curl tool/libcurl8.7.1では選択されたinterface resolver値とIPFS/IPNS gatewayのCLI→非空env→file fallbackを扱います。確定したforced-hostの秘密由来DATAはFORBIDDEN、role/whole-URL成分/argv/backendや未検査fileはUNKNOWN。`if!`の固定scalar local-only、既知ordinary、実query、未選択/last/reset等の対照を保ちます。元レビュー3入力はownEG UNKNOWN、停止の確認とnativeの実行・送信成立は別です。必要なroute/gatewayを削除する変更を自動代替にしません。[版・正常対照・停止後の出口・限界](../docs/security/git-command-guards.md#r35-current-contract)を参照してください。

文書cut **2026-10-16T03:00:31.624+09:00 JST**。L1は518/518（analysis506＋parity12）、統合単独reverseは30features/96pairs/576Hook入力、cross10は60入力で閉鎖。必要性未証明のcurl2featuresと、同じfallback featureの別ordinary必要性は証明済みでも元入力だけmaskedのparallel1profileを分けて残します。**全7459/7459 PASS・failed0/broken0**（2026-10-16 02:57:36.522 JST終了、22377 Hook入力・typed ownEG1485）。旧7272全定義・順序・input/oracle exact、カテゴリ差0、新unique187・alias0。Node24.22.0/ABI137、固定source/runner/definitionsと全owned Git/files/modes stable。旧7272の差分は別owned fixtureでの同定義比較であり、同一実tupleの因果対照とは呼びません。新head/CI/fresh reviews/thread/L3はPENDING。全Bash egressとconditional secret-git/add-allは変更しません。local Node24.22.0、Node26は2026年11月以降のowner判断、93依頼終了・大規模refactor後続・mergeしない方針を維持します。**以下R34以前は当時のsourceと日時に結合した履歴**です。
<!-- PR191:R35:CLAUDE-README-CONTRACT:END -->

<!-- PR191:R34:CLAUDE-README:BEGIN -->
**R34の契約（公開前・ローカル受入済み、as-of 2026-10-16T01:32:55.539+09:00 JST）**: [guard受入ガイド](../docs/security/git-command-guards.md#r34-current-contract)に固定版/backend・正常対照・通常影響・owner出口をまとめます。watchの実child/source、NcatのLua/ACL、SSHのBindAddress、GNU2.8 Telnetのlogin/forwarding・USER・DISPLAY/PRINTER・TERMとargv0 DTOを扱います。確定した禁止payloadを先にFORBIDDENとし、新しい未検査source UNKNOWNで隠しません。UNKNOWNは危険と確定した記録と分けます。

実query、既知ordinary値、非選択sourceを対照に残します。通常argv0のTelnet fwd-only原入力はautologin既定falseで当該source非選択のALLOW、active credential sourceはUNKNOWN。ASCIIの既知認証無効化名とUnicode似字を同一視しません。SSHの有効`-O`＋証明済みno-ControlPathは接続前終了としてALLOWを保ち、選択されたbind DNSと区別します。普通のLua/ACL file、必要な認証・環境値も未検査なら止まり得ます。同目的・同条件を保つ対応形式がなければ、対象・操作・mode・cwd/env/config/sourceと不明点をownerへ渡します。個別操作の了承をhook無効化・別経路実行へ広げません。

全Bash egressと`if: "Bash(git *)"`のsecret-git/add-all登録は変更しません。統合私有sourceはEG`c7991eae…`/common`35e676b4…`。**全件7272/7272 PASS**＝旧7018 exact＋新254（alias1は別加算なし）、実Hook入力21816/broken0/typed EG1298、L1 **479/479 PASS**、単独reverse33機能137pairs/822入力。旧7018の判定・ownEG・denied・理由prefix・brokenの差は0ですが、過去の一時fixture/env/cwdを同一とする比較ではありません。公開head/CI/fresh/thread/L3は **PENDING**。L1解析、Hook DATA L2、実settings dispatch L3、nativeのbackend/権限/DNS/認証/transportを別gateにします。Node26/93/責務refactor/mergeの既存方針は維持します。**直後のR33以下は当時のas-ofを保った履歴**です。
<!-- PR191:R34:CLAUDE-README:END -->

<!-- PR191:R33:CLAUDE-README:BEGIN -->
**R33の現契約（公開準備）**: [guard受入ガイド](../docs/security/git-command-guards.md#r33-current-contract)を参照してください。対応calleeのoption/値/queryとDATA、Git object/state/ref/autostash、選択された認証・実行sourceと送信metadataを区別します。childが実行されない/queryの場合も、外側のsocket redirection等を独立検査します。

GNU rsyncの到達optionはpopt alias/exec sourceが先に選ばれ得るため、通常の`-a`・help・versionを含めUNKNOWNになる広い制約があります。option無し/先頭literal `--`はそのedgeだけinactiveで、他guardは維持します。同目的のarchive/queryにoption削除を案内せず、source/profile条件をownerへ確認します。Git cleanupもflagだけで安全扱いせず、必要なstate/ref/autostash条件が未検査なら止まります。

egressの全Bash登録とsecret-git/add-allの既存conditional登録は変更しません。直接Hook DATA、実settings dispatch、native通信/認証/権限は別の検証単位です。R33新head/CI/fresh/入口の資格は本公開準備cutでPENDINGで、以下の旧dated結果は履歴として保持します。公開後の同一head受入はPR本文と監査台帳で更新し、本節cutを現在へ読み替えません。
<!-- PR191:R33:CLAUDE-README:END -->

`block-secret-git.cjs` と `block-git-add-all.cjs` の設定には `if: "Bash(git *)"` の記述があり、`block-secret-egress.cjs` は全 Bash 入力を対象にする。共通 parser で引用・escape・選ばれた実行 source を検査し、確定できない pathspec、設定 root、送信先や実行 source は該当経路を fail-closed とする。設定の記述と実際の dispatch 測定を分ける。旧 a464 の CLI 2.1.296 測定では、引用 Git の例も含めて全 3 wrapper が起動した。

従来許可されていた未知の変数 / glob による add、環境の消去・差替えを伴う Git の書込みなども拒否される場合がある。許可する入力、安全な書換え、対応範囲と test command は [Git ガードの説明](../docs/security/git-command-guards.md)を参照する。

R11 では、通常の release tag 作成・削除・署名・検証と notes 更新も `[判断不能]` で停止する。対応 static query は別扱いだが、同目的の writer 代替は未対応である。commit の `-F` / `-t` と merge の実 `-F` / `--file` は単一対応 literal filename を検査し、未知 path・stdin / FD・複数 source / override は停止する。単一 public filename の許可は内容の安全認証ではない。commit 前の grep pager と curl `--url-query` の file 入力にも制限がある。必要な更新・source を対応形式にできなければ、対象と条件を owner に確認する。

通常の stash push / save / apply / pop や作成・管理・削除も、input / object / ref / index / working tree の効果が staged 検査の範囲外のため `[判断不能]` で停止する。対応 static list / show / actual help は読取対照であり、同目的の snapshot / writer 代替は未対応である。必要な操作は input / tree / ref の対象・操作・cwd / env / config / source と未確認内容を owner に渡し、個別操作承認を hook 無効化の承認に広げない。

R12 の実行 source 条件では、既定 editor も含めて editor の起動を抑止したと確認できない対応 Git 操作を `[判断不能]` とする。単独 `git commit`、普通の merge、editor を選ぶ `-e` / reedit / template / interactive / sequencer 等が影響を受ける。commit の対応 `-m` / `-F` / `-C`、実 `--no-edit` / dry-run / help と、merge の実 `--no-edit` は、それぞれ editor 条件の対照である。他の source / index / argv 条件を解除せず、消費値としての `--no-edit` を抑止 flag にしない。EDITOR / VISUAL / GIT_EDITOR 等の selector と `core.editor` / `sequence.editor` の変更・削除も実行 source の役割で扱う。

同じ R12 で、どの実行名でも active glob / brace / tilde 展開を検査不能として止め、実際の mapfile / readarray `-C` callback、Bash `/dev/tcp` / `/dev/udp` redirection、remote rsync の `-e` / `--rsh` / RSYNC_RSH も停止する。download でも helper はローカルで動き得る。callback-free 読取、単なる印字 DATA、helper が使われないと確認した local rsync は別の対照である。動的 Git config writer の key / action と、push が選ぶ include 設定も UNKNOWN とする。正確な literal `>&1` / `>&-` の FD 操作と `/dev/null` 出力は index への file 書込みと区別し、`>1` / `&>1`、未知 target や group の別条件は引き続き停止する。

R13 は、実 coproc の非同期 source、未確定の動的 executable（named array tuple / element、scalar 等）、hash-object の全 `-w` object database 書込み、active difftool の外部 source を UNKNOWN とする。引数のない query / actual help、literal 実行名の DATA、既に対応する proven positional executable は別の対照である。`command --` は実 option terminator を正しく消費して child executable を検査する精度修正であり、新しい一律禁止ではない。`command -v` / `-V` の query は実行と区別する。

network 側では incomplete な curl / wget / gh の生成 argv、curl の bare dynamic option / URL・語分割 / glob / brace、rsync / scp の未確定 destination / operand 数を UNKNOWN とする。直接の対応 query、確定 local copy、curl の対応 option が消費する quoted scalar DATA 等は別扱い。curl `-b` / `--cookie` の nonempty かつ `=` を含まない実値は file 入力であり、確定 argv / context の file-upload 禁止を適用する。empty / inline `key=value` と、option 名を印字する DATA を file 入力にしない。

commit 前と当該 commit の Git `-c` / `--config-env` は、対応する `core.quotePath` / `color.*` / `advice.*`、user / author / committer の name / email、実 stdout terminal usage を除き UNKNOWN とする。旧 common の staging / commit を含む Bash 全体に対する key 条件も独立して残るため、未対応 override を commit 後へ移すだけでは許可にならない。false 値・未使用に見える key・設定 query の名前だけで効果がないとは推定しない。既存 alias / include / hook / root 等の停止も解除しない。

試験結果は、その source で取得した L1 / L2 / L3 の記録で確認する。下記ガイドの R11 / R12 / R13 測定や過去の CLI dispatch の成功を、R14 の新しい条件の実測として持ち越さない。R14 の凍結 source は2026-10-13 17:16:02 JSTに直接入力3498/3498、broken0・source不変、L1 33/33・deny API6/6。CLI 2.1.296 は17:14:43 JSTまでに8試行・実入口確認6 PASS・0 FAIL・2 NOT_EXERCISED。BASH_ENVとCURL_HOMEの2例はAPI safeguardがBash前に停止し、hook試験成功には含めない。詳しい条件・副作用・未測定範囲はガイドに残す。

R14 では、実際に選ばれた local shell 関数の本文を独立 scope で検査する。未使用の定義・引用された `function` DATA と区別し、未対応 body / 呼出し境界は UNKNOWN とする。定義後の既存 Git context 条件と `git` 関数 shadow の保守的停止は維持する。shell の pipeline / file / interactive stdin source、競合する FD 入力、未検査の script file / dot・source、各 actual argv の bytes / 語数を確定できない eval source も停止する。対応 literal `-c` と、pipeline がなく redirection / heredoc が合計1つで original default / literal fd 0 の proof がある literal here-string / quoted heredoc は、その source と別条件を検査する。known context の Bash の実 first literal `--help` / `--version` は使用されない child source と区別するが、後続 flag を証明にせず、外側の expansion / redirection は検査する。

BASH_ENV は active child Bash の startup source、GIT_ASKPASS / SSH_ASKPASS / core.askPass は authentication-capable Git の helper source、実 Wget `--use-askpass` は helper source、実 SCP `-S` は connection source として UNKNOWN にする。SSH_ASKPASS は実 SSH / SCP / SFTP と remote-shell rsync でも対象となる。download でもローカル helper は起動し得る。対応する local query / local-only copy / daemon route、実 per-call `env -u`、実 terminal query など、selector が使われないと確認できた条件を区別する。Wget は実 `--no-config` と完全な対応 argv 下で実 `--use-askpass` がなければ、WGET_ASKPASS / SSH_ASKPASS の名前だけで helper 選択としない。単なる `unset` の出現や環境変数の名前の印字を不在・選択の証明にしない。formal review の8入力すべては local L2 で egress 自身の停止を必要とする。

curl は実際の first literal argv が `-q` / `--disable`、Wget は actual option role の `--no-config` を必要とする。見えていない既定 config の file 入力・helper 条件を通常 GET の名前だけで許可しない。curl の後続 / 消費値の `-q` と Wget の消費値の `--no-config` は抑止の証明にならず、明示 config も UNKNOWN のままである。Wget の実 option `--no-config` は先頭に限定せず、help / version にも必要とする。既定設定が目的に不要ならこの対応形式を検討し、必要なら対象・設定内容・実行条件・未確認点を owner に確認する。秘密送信を確認した理由と、source を確認できない理由を区別する。

停止理由の `[禁止]` は確認した policy 禁止、`[判断不能]` は対象・設定・source などの必要情報不足を表す。raw pattern の一致だけで実際の秘密送信を確認したとは扱わない。無出力も操作全体の安全認証や owner 承認ではなく、範囲外の経路を保護済みと記録しない。対応済みの代替がない操作は対象・実行条件・不明点を owner に確認し、hook の無効化や別の場所での実行を自動的な代替にしない。

R15 は、child shell の ENV startup と imported / exported function source を追加して検査する。interactive / noninteractive、実 terminal query、privileged / POSIX mode の確認を source 選択と分け、未知 mode を非実行の証明にしない。terminal help / version の例外は invocation context も確認できる場合に限る。関数定義後は既存の context 条件により、本文を実行しない `bash --help` でも UNKNOWN で止まることがある。明示 `export -f` / function attribute と `set -a` / `set -o allexport` による自動 export、`BASH_FUNC_name%%` 等の環境 import を名前だけで追跡し、child が選ぶ本文を確認できない場合は UNKNOWN。使われない既知関数・定義 DATA と区別し、実 `env -i` や export 解除もその呼出し・scope の条件で扱う。環境消去は cwd / config / Git target 等の別条件も変えるため、自動的な安全化手順にはしない。

同じ R15 で、GNU timeout / nice / stdbuf の正確な value-taking option arity・duration / buffering mode・child 境界を検査し、動的 / missing / 未対応・省略形 option は UNKNOWN とする。単独 Git の positive `diff.external` / GIT_EXTERNAL_DIFF、textconv / filter / hook / pager / include selector は active operation の役割で検査する。実際に helper を使わない通常 log の format / grep DATA、対応 getter / stdout query、実 disable flag は別の対照であり、消費値の `--no-ext-diff` を disable としない。共通 gh operation / payload 分類の Release upload / create asset と edit notes file と Issue 本文 file / stdin の確定 payload は公開 artifact でも FORBIDDEN。SSH `-n` は stdin だけを抑止するため remote command の展開結果を省略せず、Git push option も index / named remote と別の outbound DATA として検査する。secret filename 読取との関連と argv / context が確認できれば FORBIDDEN、未確定の producer・source・送信先 / transport は UNKNOWN。通常作業への影響、同目的を保てる対応形式、owner へ渡す条件は [ガイドの R15 節](../docs/security/git-command-guards.md#r15-startup--exported-function--outbound-data-の境界)を参照する。

R16ではGH writeのbody / notes / titleの生成値もSSH / push-optionと共通のsource-to-sink判定へ接続する。repo / tag等も、quoted scalarのword境界だけで値を認証しない。既知literal / exact scalar proofは許可し、関連secret readerはFORBIDDEN、未追跡の生成source / metadataはUNKNOWN。静的本文と無関係readerの対照は維持し、生成本文や動的selectorが止まる通常影響とowner出口はガイドのR16節へ記載する。R15の測定は新sourceへ持ち越さない。

Vault の `safe-vault-push-perm.sh` はこの PreToolUse 3 本とは別の staged gate である。R15 では canonical filename predicate との parity と、Git の `--name-only -z` の完全な読取を検査する。読取失敗・途中で切れた NUL record・LF filename は何も unstage せず停止し、非秘密の LF 名も通常作業の影響範囲になる。predicate は filename policy であり、file 内容の安全認証ではない。R15 の新 source の全 L1 / L2 / L3・CI は別に取得し、上記 R14 の成功数を持ち越さない。

## settings.local.json (gitignore 対象)

個人マシン固有の上書き設定 (例: 自分の vault path や local model endpoint)。
**commit しない**。`.gitignore` で除外済み。
