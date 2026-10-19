# Bash の Git / secret ガード

この文書は PR #191 の保護範囲、各 round の修正条件、拒否されたときの対応を説明する。目的は、秘密の履歴への混入、対象の一括追加、hook の回避、未検査のファイル送信や送信先・実行 source の変更を防ぐことである。コマンド全体や任意の外部プログラムの安全を認証するものではない。各 round の取得時刻・source を付した測定は履歴として残し、新しい source の確認へ持ち越さない。

## 判定の意味

実行前の command 文字列と、対応している argv・path・cwd・env・config・実行 source の条件を確認する。本書では、その結果を次の 3 種類に分ける。

| 結果 | 意味 | permission の扱い |
|---|---|---|
| **ALLOW** | 対応済みの経路で必要条件を確認でき、該当する禁止を検出しない | このガードからは停止を要求しない |
| **FORBIDDEN** | 解析した操作・対象、または literal secret 値が policy の禁止に当たる | `deny` |
| **UNKNOWN** | 対象・実行 source・設定・引数境界など、判定に必要な情報を確認できない | `deny`。局所的な fail-closed |

理由分類の計画で policy・必要条件・担当範囲を先に決め、その後に共通 `deny(reason, category)` API と各 hook の理由分類を実装した。本表はその条件組を PR 全体について明文化したものである。FORBIDDEN を明示し文字列の reason を渡した停止は `permissionDecisionReason` の先頭が `[禁止] `、UNKNOWN・省略・無効な category や文字列でない reason は `[判断不能] ` になる。理由は prefix を含めて最大 512 UTF-16 units に収め、JSON を同期書込みしてから終了する。

新しい wire enum は追加しない。FORBIDDEN と UNKNOWN はどちらも `permissionDecision: "deny"`、許可時は無出力である。「禁止を確認した」と「安全か判断できない」を理由 prefix で分け、試験でも別に検査する。

既存 main 由来の raw backstop も残す。文字列の形だけが一致し、実 argv・操作と message / コメント / DATA を区別できない停止は **UNKNOWN** である。この一致を、秘密ファイルが実際に送信されることの証明として扱わない。

許可時の hook の無出力は、入力全体の安全認証でも owner の承認でもない。範囲外の処理に停止が出なかった場合も、保護済みとは記録しない。

<!-- PR191:R56:CONTRACT:BEGIN -->

<a id="r56-absolute-policy-child"></a>

## R56: 子の検索条件と確定した禁止理由

head `b9964122cc9496a2fff9d1524f24264ea46dcefd`へのCodex normal review 5575302879のP2（comment 4316832587）は、sudo/doas後の独立して確認できるabsolute clientでも、子検索の未資格を一般の`pathChangedBefore`へ入れたため、確定した禁止理由がUNKNOWNへ変わる点を指摘した。以下はその修復候補の有限契約であり、新sourceの全件・CI・fresh review成功は取得前に主張しない。

| 境界 | 判定と保持する条件 | 対照・停止後の扱い |
| --- | --- | --- |
| policy後のbare child・中間wrapper | 順序付きの未資格検索を保持し、Hookの継承PATHから実行体を補わずUNKNOWNにする。 | sudo/doasを外して普通の操作が通ることを同目的の代替成功とは扱わない。 |
| 全実行段を確認できるabsolute client | 検索条件だけの未資格を、実際のPATH/FPATH変更やcwd等の一般context不明と混同しない。既存payload判定が禁止を確定できればFORBIDDENを維持する。 | ordinaryなabsolute clientや真正terminal queryの既存対照を保つ。absolute指定はpolicy・権限・認証・設定全体の証明ではない。 |
| 子shell・関数・再検査するsource | 検索の未資格を実行される子scopeへ伝え、absolute shell内のbare programを確認済みにしない。独立した別statementへ持ち出さない。 | 子sourceの不明点をownerへ示し、必要なwrapper・対象・操作・cwd/env/config/sourceを保って代替候補を確認する。 |
| 実際の環境・context変更 | PATH/FPATHの変更、未知の実行体・中間段、cwd、未検査source等には既存UNKNOWNを適用する。Gitの既存context停止も保持する。 | clientをabsoluteに変えたことだけで、他の不明条件やGitの検査境界を解除しない。 |

共通解析ではpolicyに由来する検索未資格を別のscope状態として保持し、実行体の検索snapshotと子scopeへ引き継ぐ。`pathChangedBefore`には既存の実際のPATH/FPATH・shell search変更を残す。これはsudo/doasの文字列例外や全absolute commandの許可ではなく、実行体選択と判定contextの責務を分ける修復である。R55の固定した公式source・backendの境界は拡張せず、installed policyの読取、sudo/doas実行や実通信は行わない。

受入では同じ入力をf16／b996／修復sourceへ渡し、ALLOW・FORBIDDEN・UNKNOWNとown-egressの理由prefixを比較する。解析DTOだけでなく、egressの実Hook入口でabsolute payloadのFORBIDDEN、bare／中間段／nested sourceのUNKNOWN、ordinary／query／DATAの対照を確認する。追加した境界だけを戻すreverse comparisonを別に残し、別の独立した禁止が停止を維持する場合は単独の必要性を主張しない。旧8,696入力とoracle・654宣言を変更せず、固定した修復sourceの全件結果と新head CIを別に取得する。Hookへ渡すcommandはDATAであり、native privileged/client executionや実Claude入口の追加試行ではない。

<!-- PR191:R56:CONTRACT:END -->

<!-- PR191:R55:CONTRACT:BEGIN -->

<a id="r55-current-contract"></a>

## R55: sudo/doasの子検索と非適用profileの証拠

公開基点f16ddf1e4469e4281973655729ebcd6a266103f0のCodex通常コメント6270698365は、権限変更wrapper後のbare child選択（P1）と、宣言済みだが非適用の試験証拠欠落（P2）を指摘した。以下は修復候補の有限契約である。新sourceの統合全件・新head CI・両fresh review・全指摘処理は実測前に合格とせず、旧節・原FAIL・元8,696入力とoracleを保持する。

| 境界 | 保護・UNKNOWNとなる範囲 | 正常対照・費用 |
| --- | --- | --- |
| sudo/doasが選ぶ子 | wrapper自身の検索と、policyを経たchildの検索を分ける。後者が未資格ならHookの継承PATHからbare clientの既知実行体を決めない。順序付きの未資格検索metadataを後続wrapper・calleeへ伝える。 | sudo curl等の普通の用途もUNKNOWNになり得る。これは実際のPATH消失を観測したという意味ではなく、選択条件の未資格である。 |
| terminal queryとabsolute child | 真正terminal queryで子を実行しない経路には、子実行用の追加条件を付けない。必要なwrapper自身の実行体・既存context検査は残す。独立して資格できるabsolute childは、その実行体選択を確認する候補となる。 | absolute指定でsudoers/doas policy、権限、認証、loaderや設定全体を認証しない。既存のUNKNOWNや独立FORBIDDENを解除しない。 |
| 子shellの先の検索 | absolute shellを指定しても、そのbodyが使う別のbare programへ継承PATHの安全性を持ち越さない。既存のsource再検査へ未資格検索状態を伝える。 | 親shellをabsoluteにしただけで内部のwrapper/clientが確認済みとはならない。直接の普通の操作や、実行体・source/contextを確認できる正常対照は別に保つ。 |
| profileのtext証拠 | 固定ledgerの全654宣言についてstructured rowを出す。present又はI/O不明でapplies=false、かつ元期待がPASSでも省略しない。非宣言の普通のPASSへ行を増やさず、非宣言FAILの診断は残す。 | 宣言の存在と条件適用は別である。非適用時の元semantic assertion、own-hook判定・理由、前後安定性を保持し、I/O不明をmissingへ変換しない。行の存在だけでnative semanticsを認定しない。 |

一次根拠のsudoは公式sudo-project/sudoの[v1.9.17p2 sudoers.c](https://github.com/sudo-project/sudo/blob/v1.9.17p2/plugins/sudoers/sudoers.c)と[env.c](https://github.com/sudo-project/sudo/blob/v1.9.17p2/plugins/sudoers/env.c)である。secure_pathが有効で利用者が免除対象でない条件では、command解決のPATHとchild環境のPATHへその値を使う。sudo.wsの文書URLは既存取得でrobots拒否があり、今回それを取得成功とは扱わず公式sourceを照合した。

OpenBSDは固定revision b196a8e95931e4ddf19f9a664a8498bf157fea77の[doas.c](https://github.com/openbsd/src/blob/b196a8e95931e4ddf19f9a664a8498bf157fea77/usr.bin/doas/doas.c)と[env.c](https://github.com/openbsd/src/blob/b196a8e95931e4ddf19f9a664a8498bf157fea77/usr.bin/doas/env.c)を照合した。targetのPATHを含む環境を作り、実行時のcommand検索にはruleのcommand指定に応じてsafe PATH又は元のPATHを使う境界がある。全doas呼出しが一律にtarget PATHで検索されるとは記録しない。補助資料の[doas(1)](https://man.openbsd.org/doas.1)と[doas.conf(5)](https://man.openbsd.org/doas.conf.5)も、target環境・設定による変更とcommandの制約を示すが、これは取得時のcurrent manualであり固定revisionの版とは分ける。installed policyの読取・sudo/doas実行・権限変更や実通信のnative成立はこの資料照合に含まない。

停止後は必要なsudo/doas・対象・操作・argv・cwd/env/config/sourceを保ち、確認できるabsolute childへ結ぶ形だけを同目的の代替候補とする。必要なwrapperを削除したり、absolute shellの内部検索を無視したりして代替成功とはしない。条件を保てなければ未資格の検索段と必要条件をownerへ提示する。個別操作の承認はHook停止の承認ではない。

旧646宣言の全値と順序を保持し、既存R29SW01〜07・R29SW39だけに、policyを経たbare curlの検索が未資格という8宣言を追加した。これはprogramの不在や実際のPATH削除を測った宣言ではない。元8,696入力・oracleを固定し、この8件の元FORBIDDEN期待に対するFAILと、新しいUNKNOWN契約への適合を二重に残す。absolute child・真正query・独立した置換の送信には宣言を借用せず、SG/AGの独立した禁止条件も弱めない。

受入では、bare childの停止、absolute childと真正queryの対照、子shellの先への伝播、独立FORBIDDENの維持を分けて確認する。P2は注入FSとwireによるpure試験でdeclared present/missing/I/O不明と非宣言の対照を持つ。元期待・適用件数・profile結果を併記し、条件付きUNKNOWNのPASSを欠落programのnative意味論の成功へ読み替えない。

2026-10-20 01:00:42 JSTに終端したローカルの固定source全8,696件は、更新前646宣言を使い、元期待8058 PASS / 638 FAIL、旧profile8688 PASS / 8 FAILだった。8件は上記の追加宣言と一致する。source・fixtureは前後一致し、実Hook出力26,088行を保持した。その保存出力だけに新654宣言を適用した再集計は8,696件適合・BROKEN0だったが、これは新runnerの再実行ではない。新head CIでは更新後654宣言を使う実際の全件実行と、全宣言の適用・非適用のtext証拠を別に確認する。同headのCI・両fresh review・全指摘処理は取得前に合格へ持ち越さない。

<!-- PR191:R55:CONTRACT:END -->

<!-- PR191:R54:CONTRACT:BEGIN -->

<a id="r54-executable-selection"></a>

## R54: inherited PATHと各実行段の選択

公開基点`4ac478946e5ec4e5062ef322d84200b42a761565`へのCodex正常fullはP1を2件、P2を1件返した。以下は実行体選択に関する有限契約である。固定headの全件検証・CI・両fresh reviewの結果はPR本文で別に記録し、この説明から完了を推定しない。P1の同じ2入力は初期`df463a91`と親`0bc598d3`でもHookを通過した。inertなshadow fileを使うHook DATAでの比較で、shadowの実行、秘密のstagingや外部通信は行っていない。

| 確認する境界 | 判定・守るもの | 正常対照と停止する通常作業 |
| --- | --- | --- |
| commit前の読取 | cat/head/tail/wc/ls等を名前だけで副作用なしとは扱わない。実際の最初の実行可能候補が独立した既知installと一致しなければ、index維持を証明できずUNKNOWN。 | 通常のsystem reader、確認できたabsolute reader、直接の対応builtinを保つ。独自readerが先に選ばれる通常作業も止まる。 |
| 対応するclientと実行source | 既存clientのargv/payload解釈と、既存Git/shell sourceの解釈へ実行体の確認を加える。信頼外の先頭候補、欠落、検索条件不明をtrustedと同一視しない。未知の実行体は局所UNKNOWNで、別の独立したFORBIDDENを解除しない。 | system/Homebrewの確認済みclientとordinaryな引数を対照にする。未導入clientの例や独自installは、名前が既知でもこの確認を満たさない。Git/shellのこの追加gateはprogramの選択だけを扱い、cd後や未知argvを理由に通常のstatusまで一律停止しない。操作・sourceには既存の独立検査も適用する。全プログラムを新しい送信対象に加える変更ではない。 |
| wrapper自身とchild | wrapperが検索される前のenv操作数・PATH presence・変更/default検索を保持する。inner env clear/unsetがouter wrapperの検索事実を消さない。 | inherited shadow envから、env clear後のabsolute childへ進む形もUNKNOWN。確認済みabsolute wrapperとabsolute childは、他の条件も満たす場合だけ対照にする。 |
| builtinと外部呼出し | 対応builtinのproofは直接/対応shell lookup内に限る。envやexec等が選ぶ同名外部プログラムへ引き継がない。元command位置のtime予約語と、command等のoperandである外部timeを分ける。 | 直接printfはPATHの同名fileだけで拒否しない。外部に強制されたprintfは実行体を確認する。既存function/import/source/search mutationの停止条件は保持する。 |
| absent/default/変更PATH | actual PATHのpresenceをopaqueに追跡し、生成値のliteral proofへ昇格させない。欠落・env clear・未資格command default検索へhook自身のPATHをfallbackしない。変更済みPATHを新たに一般対応する修復ではない。 | command queryのDATAと実行を分ける。実行のdefault検索、動的cwd/検索条件や独自installは通常目的でも停止し得る。 |
| 実queryとliteralなshell body | help/queryでも選択されたexternal wrapper自体は実行されるため、childなしという理由で実行体確認を飛ばさない。literal bodyは親shellが確認できてから実行sourceとして扱う。 | trusted timeoutのhelpとcommandの照会は保つ。shadow timeoutのhelpはUNKNOWN、shadow bashの文字列operandもUNKNOWN。実bashが同じbodyで禁止操作を実行する場合のFORBIDDENは残す。 |

固定信頼起点はPOSIXの`/usr/bin`・`/bin`・`/usr/sbin`・`/sbin`・`/usr/local/bin`・`/opt/homebrew/bin`にある、当該プログラム名のinstallから独立に得たnative realpathである。PATHで見つけた候補を信頼集合へ足さず、先頭の信頼外実行候補を飛ばさない。空/相対PATH entryは確認できたphysical cwdを使い、symlink/`..`を先に字句正規化しない。実行段のうち、`exec -c`が検索に使うshell状態とchildへ渡す空のenvironmentの区別は本修復では資格していない。bare childを元のPATHで補う許可は加えずUNKNOWNを保つ。これはlookup時に必ずPATHが消えているという実測ではなく、未対応の検索段による通常作業の費用である。

これはinstallの選択に関する有限policyであり、binary内容、loader、TOCTOU、任意の既存shell hash/alias/function状態やWindows searchを資格するものではない。既存の対応source/context検査も必要である。

一次根拠は[Bashのcommand search](https://www.gnu.org/software/bash/manual/html_node/Command-Search-and-Execution.html)、[GNU envのchild検索](https://www.gnu.org/s/coreutils/manual/html_node/env-invocation.html)、[POSIX commandのdefault検索](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/command.html)。今回の取得では検索cacheの一次本文を照合したが、直接ページのtimeout/403も残し、installed shell全体の実証とは分ける。

P2のnative nonlog fixtureは、選んだ信頼済みGitのplain versionで既知Git2.54.0 profileを確認し、同実行体で実際の`--no-lazy-fetch --version`が成功してからsetupする。それ以外はnative groupだけSKIPし、純粋groupは実行する。別のfsmonitor版下限をこのflagの対応証明にしない。SKIPはそのbackendの成功ではなく、outer PATH欠落時の既存pure側依存も隠さない。

停止後は、必要な対象・操作・argv・cwd/env/config/sourceを保ったまま確認できるinstall/呼出しへ結べる場合だけ、その対応形式を使う。absolute pathへの変更や読取とcommitの分割で目的・条件が変わる場合は自動代替にしない。結べなければ不明な選択段と条件をownerへ提示する。個別操作の了承をHook停止の了承へ読み替えない。

受入では、元2入力に対するown-hook UNKNOWN、対応正常入力、wrapper/checkpointの解析、各新判定だけを外す逆検証を分ける。旧8,696入力・原oracleを保持して判定差分を説明し、正常操作の余計な停止を古い期待の一括変更で隠さない。L1のrole単体試験では実行体選択を明示fixture依存に分離し、実filesystemの選択は専用試験とHook DATAで別に確認する。新L3やnative送信の資格は追加しない。

### R54の試験profileと元期待の二重表示

`node .claude/hooks/tests/git-guards.test.cjs`は、従来どおり元8,696入力・oracleをそのまま評価する。新しい実行体確認のため、未導入programや未資格lookupでは元のALLOW/FORBIDDEN期待に不一致が残る。これは元期待で全件成功したことにはしない。

CIは明示的な`--executable-profile`も使う。固定JSONの646 IDと各元CASEのhashに限り、実際のcase環境のPATHを独立FSで調べた欠落、または宣言した未資格lookup段について、ownEGの期待をUNKNOWNへ分ける。うち69件は真正query・childなし・sourceを含む外部wrapper自身の選択であり、実行体が存在すれば元の意味の期待を保持する。絶対`/sbin/ping`の1件だけは、既知installの実在・realpathを独立確認できた場合に、既存の秘密由来destination規則に従うFORBIDDENへの分類精密化を別に宣言する。元のUNKNOWN期待は残す。`caffeinate`の4件もOS名から不在とは仮定せず、actual PATHで独立に確認する同じ条件に限る。50件の試作過剰拒否はこの調整へ入れない。元CASESの値や原結果は変えず、`originalFailed`・`profileAdjusted`・`profileOK`と理由を併記する。text出力でも、条件適用又はprofile不一致の各入力について、独立資格・前後の安定性・own-hook判定・理由全文を記録し、プラットフォーム名やdenyだけから欠落を推測しない。存在する実行体、I/O不明、相対PATHや変更済み検索条件を、missing調整で通さない。profileの期待はguardの実測判定から生成しない。

変更するのは限定したownEGの分類だけで、元ALLOWのSG/AG ALLOWや、別の独立FORBIDDENを保つ。実行前後でFS資格が変わった入力は、停止結果が期待形でもprofile失敗にする。`command -p ... git add -f .env`のSG FORBIDDENは追加で必須にする。部品load失敗や例外を示す理由は、UNKNOWN期待でもprofile成功へ数えない。programが確認できる場合の元semantic assertionは維持し、未資格時のUNKNOWN検証を、そのprogram本来の意味・通信・認証の実証へ読み替えない。profile自体のID/hash/PATH結合と、qualified ordinaryに常時UNKNOWNを返す不正な実装が落ちることは、独立したpure試験で確認する。

この節は試験契約であり、特定headの全件profile・CI・fresh reviewの成功宣言ではない。元期待の不一致とprofileの結果、未資格の意味論・native動作は区別して記録する。

<!-- PR191:R54:CONTRACT:END -->

<!-- PR191:R51:CONTRACT:BEGIN -->

<a id="r51-current-contract"></a>

## R51: special builtinのexport境界と検証器のwire判定

公開基点 `4046a6cd83be746a5b6b430cd3138211652e7465` のfresh fullはCodexが4件、CodeRabbitが2件を返した。Codexの4件は通常コメント、CodeRabbitの2件はreview threadに公開されており、thread件数だけでは未処理指摘数を表せない。以下は修復候補の契約であり、新headの受入完了ではない。R50以前の節は当時の履歴として保持する。

| 境界 | 判定と根拠 | 正常対照・制限 |
| --- | --- | --- |
| special builtinへの追跡対象値のprefix代入 | 直接のspecial builtinや子なしexecに付くprefixを、次のchildへ非exportと断定しない。`POSIXLY_CORRECT`だけでなく、既に追跡しているGH metadata・identity等にも同じexport境界を保つ。外側shellのmode・版が未資格ならpresence/sourceを不明にし、依存する操作をUNKNOWNとする。 | GNU Bashの[Special Builtins](https://www.gnu.org/software/bash/manual/html_node/Special-Builtins.html)と[Environment](https://www.gnu.org/software/bash/manual/html_node/Environment.html)を参照する。DUMMY属性観測ではBash5.3.15と3.2.57で当該prefixの永続性に差があった。全Bash/backendを資格したとは扱わない。 |
| exportの実際の変更と普通のclient操作 | 後続の`export -n`・unset、実childのenv clearは別に反映する。未知presenceでも、既存loggerの両modeで同じALLOWと証明できるordinaryな選択は維持する。 | mode不明だけで全clientを禁止しない。秘密由来の生成messageや未確認sourceをordinaryの対照で免除しない。`command`/`builtin` wrapperの一時prefixやfunction・subshell scopeも直接のspecial builtinと区別する。 |
| GH metadataの正常費用 | special builtinのprefixに保存された`GH_HOST`/`GH_REPO`も、非exportとして送信先sourceから消さない。秘密由来を通常exportした場合のFORBIDDENと、export persistenceが不明な場合のUNKNOWNを分ける。 | literalのordinary hostでも、その特殊prefix形式は新たにUNKNOWNになり得る。これは実行環境・認証先の選択を確定できない費用である。単なる未export local、実際のexport解除、temporary wrapperは別に保つ。子へ渡すことが意図と一致すると確認できる場合だけ、同じ値の明示export等を検討し、意味を保てなければownerへ提示する。 |
| getentのservice指定とterminal query | glibc2.42の既知で完全なservice値の後でも、後続の真正help/usage/versionはterminalとする。service値として消費されたhelp風の語はDATAのまま。 | 未知service値・未確定argv、実`--`後のkey、active NSS/backendの既存UNKNOWNを保つ。service名がfilesであることを、active lookupの一般的な安全証明にはしない。一次根拠は[固定getent.c](https://github.com/bminor/glibc/blob/glibc-2.42/nss/getent.c)のparse_option/mainと[argp-parse.c](https://github.com/bminor/glibc/blob/glibc-2.42/argp/argp-parse.c)。 |
| 単体補助と全件runnerのdeny理由 | `[禁止] `だけをFORBIDDEN、`[判断不能] `だけをUNKNOWNとする。他prefix・欠落・非stringは検証器上のBROKENとして失敗させ、generic deny期待でも通さない。 | 入力8,696件・oracleは変えない。DUMMY Hookの不正wireを実runnerへ与え、exit/JSON/textで失敗を確認する。BROKENはHook permissionの新enumではない。 |

修正前・後に同じ入力を与える。special builtinの正確な指摘入力はR49の停止からR50の許可へ変化した退行として記録し、既存getent service queryの過拒否と区別する。危険入力の停止、普通の対照、追加したexport境界・query修復・runnerの失敗条件をそれぞれ単独で戻す逆検証を別に残す。任意の実送信・認証・installed consumerや新L3は認証しない。

停止後は、同じ対象・操作・argv・cwd/env/config/source条件を保つ対応形式だけを検討する。条件を保てなければ不足条件をownerへ提示する。必要なmode・helper・sourceを外すことや、Hookを止めることは自動的な代替経路ではない。

<!-- PR191:R51:CONTRACT:END -->

<!-- PR191:R50:CONTRACT:BEGIN -->

<a id="r50-current-contract"></a>

## R50: childのexport状態・getent queryとレビュー反証

公開基点 `c6a916e8ce528a34813f1581050d7c0b68a1f2ed` の両full reviewは正常に完了したが、未解決6件を返した。以下は2026-10-19の修復候補の契約である。候補の全件検証、新公開headの必須CI、両fresh reviewと公開thread処理は、それぞれ実測前に合格へ持ち越さない。旧8,696入力・oracleは変更しない。

| 境界 | 対応と判定 | 正常対照・通常作業への影響 |
| --- | --- | --- |
| `POSIXLY_CORRECT`のchildへの継承 | shell内の値とexport属性を分け、子が実際に受け取る場合だけ既知presenceへ入れる。先行する代入だけではchildのoption順序を変更したと扱わない。条件付きexportなどpresence不明は別metadataに保ち、option順序によって選択対象が変わる箇所をUNKNOWNにする。 | prefix・inherited・export・allexport、空値のpresence、実際のexport解除・unset・`env -u`/`env -i`、function/child scopeを区別する。未使用変数や順序に依存しないordinary操作を存在だけで一律停止しない。 |
| glibc2.42 `getent`のquery | database後の真正help/usage/versionも固定argp consumerの順序で解釈する。消費されたservice値や実`--`後のkeyをqueryにしない。生成語のoption境界や有効な順序が未証明ならUNKNOWNを保つ。 | 対応queryの過剰停止を修復する。unquoted `-?`はshell globであり、quoted `'-?'`のquery対照と分ける。既存のhost key由来検査とcustom NSS/serviceの制限は残る。 |
| 既存のoption順序consumer | logger、Ncat、Telnet、Netcatの既存roleへ、既知presenceと不明presenceを引き継ぐ。childを再解析した後のunsetを、parentのmetadataとの結合で復活させない。 | 不明presenceを理由に全clientを禁止せず、後置option等で選択結果が変わる境界だけを停止する。真正query、実delimiter、消費DATA、独立したFORBIDDENは別に保つ。 |
| Hook試験の理由prefix | `[禁止] `はFORBIDDEN、`[判断不能] `はUNKNOWN、それ以外のdeny prefixは試験上のBROKENとして失敗させる。 | BROKENは検証器具の結果であり、新しいHook permission enumではない。UNKNOWNの期待を満たすために不明なwireを合格へ変換しない。 |

loggerに限り、不明なPOSIX presenceについて両方の順序を有限に解析し、両方とも既知のgrammar・literalな選択値で、file/journaldや未検査remote stdinがなく、既存payload判定でも禁止や不足がない場合は、同じALLOWを保つ。これは通常メッセージを余計に止めないための限定した等価確認である。生成された値・秘密由来・file入力・未知option・未検査callee/env/contextを、この例外で許可しない。

### loggerの2指摘はhelp・診断文だけで採用しない

固定した[util-linux2.41.2 logger.c](https://github.com/util-linux/util-linux/blob/v2.41.2/misc-utils/logger.c)では、`--socket-errors`は`required_argument`であり、`-f`でstdinを開いてもmessage operandがあれば`logger_command_line`が選ばれる。socket-errorsの不正値は警告後にAUTOへ戻る処理で、致命的終了とは扱わない。旧版のhelpにあるoptional表記や「message is ignored」という診断だけから、後続語の消費や送信sourceを逆に変更しない。後段のconsumerまで照合する。

このため、file＋ordinary messageをfile uploadとして一律FORBIDDENへ変えたり、socket-errorsをoptionalへ変更したりする修復は採用しない。正確なレビュー入力のHook結果、選択された語とsource、値を実際に消費する正常対照を別々に残す。指定fileを開くことと、その内容が送信されることも分ける。これは固定consumerに対する反証であり、未確認のinstalled binary/build、任意backend、実接続・実送信の安全認証ではない。

child環境の一次根拠は[BashのEnvironment](https://www.gnu.org/software/bash/manual/html_node/Environment.html)、getentのqueryは[glibc2.42 getent.c](https://github.com/bminor/glibc/blob/glibc-2.42/nss/getent.c)と[argp-parse.c](https://github.com/bminor/glibc/blob/glibc-2.42/argp/argp-parse.c)で確認する。取得した版・raw/hash、原FAILと新しい期待の訂正、危険入力と正常対照、単一edgeの逆検証は別の監査記録へ保存する。

停止後の代替は、同じ対象・入力・環境・consumerを保つ対応形式だけを候補とする。必要なexport属性やoption・sourceを消して別の操作へ変えたり、Hookを止めたりすることは自動的に許可しない。条件を保てる形式が確認できなければ、対象と不足条件をownerへ提示する。

<!-- PR191:R50:CONTRACT:END -->

<!-- PR191:R49:CONTRACT:BEGIN -->

<a id="r49-current-contract"></a>

## R49: getent host keyとremote loggerの有限契約

公開基点head `30c3616656079b36d1cb68ec68016cdbf0442423` のfresh Codex review5564628944による2件を修復する。2026-10-19の作業中の契約であり、修正候補の全件成功・新head CI・新しい両fresh reviewは測定後に別途記録する。R48はCI/説明の5ファイルだけを変更し、2件のexact Hook DATAは依頼前`df463a91`・base`ae10261`・公開基点`30c3616`でいずれも全3HookがALLOWだった。既存不足の比較結果と、修正後の停止・native成立を混同しない。

| 対象・固定consumer | 判定と選択条件 | 正常対照・通常利用への費用 | 修復受入と未確認条件 |
| --- | --- | --- | --- |
| glibc2.42 `getent`の`hosts`/`ahosts`/`ahostsv4`/`ahostsv6` | database/keyと値付きservice option、`--`、実queryを分け、選択keyの元の語を既存payload判定へ渡す。秘密producerが確定したkeyはFORBIDDEN。未知database/option/語数・先頭byte・source/contextはUNKNOWN。明示serviceによるNSS選択をDNS無効化の証明へ昇格しない。non-host databaseでも明示serviceや未確定keyはNSS consumerを確認できないためUNKNOWNとする。 | ordinary host/IP、defaultの既知non-host databaseとstatic ordinary key、実help/version、消費されたoption値、印字DATA、捨てた無関係readerを保持する。正当なcustom NSS/serviceや未解決keyもUNKNOWNになり得る。non-hostはhost resolver roleが非選択という意味で、processがquery終了した意味ではない。 | 元exactをegress自身が止め、`--`等で境界を固定した秘密keyとordinary対照を別に検査する。登録だけを外すreverseで効果を測る。NSS構成がDNSへ到達すること、有効なlabel/hostname、binary/backend・実通信は未確認。key無しenumerationも含め、任意NSS処理全体を認定しない。 |
| util-linux2.41.2 `logger`の明示server/service resolverとremote payload | 選択されたserver/portはresolver DATA。headerとmessageは語の生成元、message無し時のfile/stdinは選択inputで検査する。file uploadは既存policyに従いFORBIDDEN、`/dev/null`は空source対照。秘密由来の選択DATAはFORBIDDEN、不明なsource/argv/contextはUNKNOWN。 | local logging/local socketのみ、static ordinary remote message、ordinary printf pipeline、actual query、消費DATA、無関係readerを保持する。unobserved remote stdinや正当な未検査fileは停止する。fileの内容が通常名であってもfile-backed送信を自動許可しない。 | 元exactのown-egress FORBIDDEN、正常対照、logger dispatchだけを外すreverseを検査する。syslog形式、実binary/backend、socket/権限、server受入・実送信、local daemonによる別途forwardingは未確認で、Hook停止をnative成立証明にしない。 |

`logger`はserver指定がUnix socket指定より優先する。後続のmessage operandがある場合、先行`-f`はparse中にopenされても送信内容としては無視される。`--no-act`は本文writeを止めるが、`logger_open`のserver名前解決・接続を止めない。journald modeはremote open前にlocal処理へ進む。これらを全logger/全fileの一律禁止や、全通信が無いという証明へ置き換えない。

GNU option permutationと、`POSIXLY_CORRECT`の存在によるfirst-operand stopを区別する。値として消費された`--help`、`--`後のDATA、未確定の並びを真正queryと扱わない。未知のoption/arityを推測して後続語を捨てない。

新しいUNKNOWNは既存の独立したFORBIDDENを隠さない位置で評価する。R49のcomponent testは下記R48で導入したglobへ自動的に入り、R48の「24ファイル」はその当時のsnapshotである。元8,696定義とoracleは変更せず、新しいrole/Hook DATA対照と単一edgeのreverseを別に記録する。

一次consumerは[glibc2.42 getent.c](https://github.com/bminor/glibc/blob/glibc-2.42/nss/getent.c)、[NSS databasesの公式説明](https://sourceware.org/glibc/manual/latest/html_node/Name-Service-Switch.html)、[util-linux2.41.2 logger.c](https://github.com/util-linux/util-linux/blob/v2.41.2/misc-utils/logger.c)・[logger manual](https://github.com/util-linux/util-linux/blob/v2.41.2/misc-utils/logger.1.adoc)、[glibc2.41 getopt.c](https://github.com/bminor/glibc/blob/glibc-2.41/posix/getopt.c)で固定する。取得raw/hashとread failureは私有監査記録へ残し、現在hostや全独自backendの認定へ持ち越さない。

同じoperation・database/NSS又はlog destination・入力内容・版/backend・cwd/env/sourceを保つ対応形式だけを代替候補とする。resolverを別の接続方法へ変える、remoteをlocalへ変える、必要inputを消す、別場所へcopyする、Hookを止めることを自動承認済みの出口にしない。対応形式が確認できなければ、対象・目的とUNKNOWNの不足条件をownerへ提示する。

<!-- PR191:R49:CONTRACT:END -->

<!-- PR191:R48:CI-CONTRACT:BEGIN -->

<a id="r48-ci-contract"></a>

## R48: ガード全体を必須CIで実行する

2026-10-19の修復作業中の契約である。公開基点head `9c2198cbffaae92dbe5b04ec031726160556d8b8` のCodex review5564282334は、必須CIが10個のselected role fileだけを実行し、ローカルで報告した全ガード試験を継続的に守っていない不足を指摘した。新しい実行・送信経路の修復ではなく、検証の結線を修復する。新headの全件成功・CI・両fresh reviewは実測するまでPENDINGである。

必須の `Pipeline (root) - test & typecheck` 内で、次を省略せず順に実行する。

1. `.claude/hooks/tests/*.test.cjs` からstandalone runnerとparityの2本だけを除いた全component test。現在は24ファイルで、analysis・precommit readers・全role test・ledger bindingを含む。将来追加されたcomponentも同じglobで選択する。
2. `secret-path-parity.test.cjs` を独立実行する。通常のcheckout配置にあるproduction shellを使い、凍結copy向けの参照先へ置き換えない。
3. `git-guards.test.cjs` の公開CLIで全bankを実行する。現在の8,696定義、担当Hookの判定・理由prefix・brokenも既存runnerのまま検査する。importや選択した代表入力だけの実行で代用しない。

```bash
component_tests=()
for test_file in .claude/hooks/tests/*.test.cjs; do
  case "$test_file" in
    */git-guards.test.cjs|*/secret-path-parity.test.cjs) ;;
    *) component_tests+=("$test_file") ;;
  esac
done
test "${#component_tests[@]}" -gt 0
node --test "${component_tests[@]}"
node --test .claude/hooks/tests/secret-path-parity.test.cjs
node .claude/hooks/tests/git-guards.test.cjs
```

上記はrepository rootからBashで実行するコマンドで、実Gitとfixture環境の条件も必要である。既存のaccepted bankはGit 2.54.0の固定consumerを使う正常対照を含む。たとえば `R40-QUERY-PERCMD-CAT` は、別版で必要情報を確認できずUNKNOWNになることを、原ALLOW期待の成功へ再採点しない。

CIでは[公式Git 2.54.0 source](https://www.kernel.org/pub/software/scm/git/git-2.54.0.tar.xz)をSHA-256 `f689162364c10de79ef89aa8dbf48731eb057e34edbbd20aca510ce0154681a3`（[公式checksum一覧](https://www.kernel.org/pub/software/scm/git/sha256sums.asc)）で展開前に確認し、ephemeral runner内の `/usr` へbuild/installする。[公式INSTALL](https://github.com/git/git/blob/v2.54.0/INSTALL)に従い、buildとinstallのprefixを一致させる。CLIのtransport・Perl/Python helperを省いて検査を通す構成にはせず、GUIとlocalizationだけを除外する。bare Gitと `/usr/bin/git` を同じ固定backendで確認し、実 `--no-lazy-fetch --version` の成功と別のfsmonitor版下限も確認する。runnerの既定Git 2.55.0の成功やbannerだけで、この固定consumerを認定しない。

試験はowned HOMEと一時directoryで実行し、callerのcredential・loader・Git設定・XDG selectorを継承しない。caseに明示された環境条件と既存oracleは変更しない。必要backendの欠落や各試験の非zero終了は必須jobの失敗にし、全bankのskipや `continue-on-error` へ変換しない。既存の局所native群にある能力skipは、そのtestの適用範囲の表示として残し、全bank実行の代わりにはしない。

command文字列は引き続きHook JSONのDATAで、native Gitはdisposable DUMMY fixtureの準備・検査に限る。CIの成功は、実秘密の読取・外部通信・任意backendの安全性や新しいL3 dispatchの証明ではない。元のローカル結果、原FAIL/NE、過去のCIが部分試験だけだった事実と、修復後の同head CI結果は別記録にする。

<!-- PR191:R48:CI-CONTRACT:END -->

<!-- PR191:R47:CONTRACT:BEGIN -->

<a id="r47-current-contract"></a>

## R47: ordered filesystem `-C`・loader環境・active launcherの有限契約

**修復作業中のsnapshot**。2026-10-19 02:35:24 JST時点、公開基点head `ec3bd520ef450fb2899bef1f33618417158e4ff8` に対する未commitのR47 candidateは修復作業中であり、この当時の最終source固定・統合全件・新公開head／同head CI／両fresh reviewと全指摘処理は未取得・PENDINGである。 公開ec3への新5指摘を、実行条件2・launcher2・試験能力1として修復する。旧不足と退行の比較、局所対照、最終固定sourceの資格はそれぞれ原票で区別し、過去の成功数を新R47へ持ち越さない。

### source・正常対照・通常利用への費用

| 境界 | R47 candidateの有限契約と通常費用 |
| --- | --- |
| Git own検査の`-C` | base cwdを保ち、validated literalなraw `-C`を順序どおりversion・hook-config・index/config・index-hookの各native readへ一回引き継ぐ。symlink/`..`を先に`path.resolve`で別対象へ潰さず、複数`-C`・空値もGitのfilesystem意味を保つ。calleeのPATH選択は`-C`前のcontextでraw候補をfilesystem lookupし、native realpathを既知installの独立信頼起点へ結ぶ。`-C`でcallee検索場所を後付けしない。cacheもordered `-C`を含める。未復元・動的・存在しない/非directoryのcwdはUNKNOWNで、正当な別repo/index操作も条件を復元できなければ止まる。 |
| AG/EGのroot/path比較 | 同じ`-C`原因の隣接修復としてphysical CWDを使うが、add pathspecはGit consumerのlexical normalizeが先であり、CWDのchdirと同じ解釈にはしない。lexical pathの親をcanonical化して`/var`等のaliasを合わせ、最終in-tree symlinkはそのentryを追加する対象として保つ。通常root-link個別追加はALLOW、`link/..`がlexicalにroot全体を選ぶ包括操作はFORBIDDENの対照。外側symlinkからrootへ向くselectionが不明ならUNKNOWNとする。必要な`-C`/linkを外した別対象へ変更せず、このcross-consumer修復の最終統合資格は当時PENDINGである。 |
| loaderの実backend選択 | 下記15名をselected envとindex seedへ有限に含める。Linuxは`LD_` family、Darwinは`DYLD_` familyと`LD_LIBRARY_PATH`をactiveと扱い、当該backendで確認したinactive familyだけをown検査copyから除く。activeな非空/未知はGitがhelp/versionを解釈する前にも作用し得るためnative Git前にUNKNOWNとする。未資格backendは空値も自動免除しない。 |
| known empty | qualifiedな空のloader listは削除せず空のまま検査envへ渡し、削除によりdefault fallbackを再有効化しない。activeな`LD_ORIGIN_PATH`と`DYLD_SHARED_CACHE_DIR`はempty-disablesの資格がなく、空でもUNKNOWN。inactive familyの除去やown sanitationを、実際のsourceやbinary内容が安全という証明には使わない。 |
| `capsh`のshell/self source | libcap2.77の`--`/`-+`によるshell、`==`/`=+`によるselfと、その後のargvを区別する。active sourceはidentity/capability・shell/self・cwd/env/backendが未資格なので普通のprintfでもUNKNOWN。前段の変更/fork/killを後置helpで消さない。 |
| `capsh`のqueryとDATA | pinned consumerの`--help`/`-h`や有限read-only形は非exec側の対照。`--version`はこのpinでは未対応optionのusage-errorで、真正versionではない。`--shell=--help`は値DATA、source境界後のhelpは選ばれたshell/selfのargvであり、capsh queryと混同しない。 |
| `start-stop-daemon`のsource | dpkg1.22.22のrequired-value arityに従い`--exec`/`--startas`とpost-`--` argvを区別する。active startはmatch/no-match、identity・cwd/env・daemon/backend未資格により普通のprintfでもUNKNOWN。exact help/version、status、解析済みstart/stop test modeの非selected-program対照と分ける。bare operand後はGNU permutation/POSIXLY_CORRECT差が未資格で、後置help/testだけでは免除しない。 |
| native依存test | own検査依存のALLOW/FORBIDDEN群は、選択された既知Gitで実`--no-lazy-fetch --version`が成功し、別のfsmonitor boolean版下限も満たす場合に実行する。不対応backendは当該native群をskipし、pure DTO・option error/未対応bannerの対照は維持する。Git2.43が版下限を満たしてもflag受理を証明せず、Git2.54固定consumer資格もこの能力gateとは別条件である。CIへのtest登録も成功数の先取りにはしない。 |

loader inventoryは`LD_PRELOAD`、`LD_LIBRARY_PATH`、`LD_AUDIT`、`LD_ORIGIN_PATH`、`DYLD_INSERT_LIBRARIES`、`DYLD_LIBRARY_PATH`、`DYLD_FRAMEWORK_PATH`、`DYLD_FALLBACK_LIBRARY_PATH`、`DYLD_FALLBACK_FRAMEWORK_PATH`、`DYLD_VERSIONED_LIBRARY_PATH`、`DYLD_VERSIONED_FRAMEWORK_PATH`、`DYLD_ROOT_PATH`、`DYLD_PATHS_ROOT`、`DYLD_IMAGE_SUFFIX`、`DYLD_SHARED_CACHE_DIR`の15名に限定する。全環境変数や全loader/OSの対応を保証するものではない。

印字DATA、先に消費された値、実selected sourceを別roleとして扱い、既知function shadowと未確認functionを混同しない。capshの既知function正常対照があっても、hyphenを含むdaemon functionの既存UNKNOWNを新たなALLOWへ読み替えない。専用のlate source UNKNOWNは独立に確認したFORBIDDENより後で評価し、外側の未知launcher/contextを内側queryで消さない。

### 一次consumer・設計判断・実測を分ける

`-C`のcwd順序は[Git2.54.0 documentation](https://github.com/git/git/blob/v2.54.0/Documentation/git.adoc)と[git.c](https://github.com/git/git/blob/v2.54.0/git.c)に固定する。add pathspecのprefix/lexical normalizeは同版[setup.c](https://github.com/git/git/blob/v2.54.0/setup.c)のconsumerとして別に確認する。loaderの限定は[glibc2.42 rtld.c](https://github.com/bminor/glibc/blob/glibc-2.42/elf/rtld.c)・[dl-load.c](https://github.com/bminor/glibc/blob/glibc-2.42/elf/dl-load.c)・[dl-origin.c](https://github.com/bminor/glibc/blob/glibc-2.42/sysdeps/unix/sysv/linux/dl-origin.c)、[Apple dyld-852.2](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/src/dyld2.cpp)の有限consumer読解に基づく。launcherは[libcap2.77公式source archive](https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-2.77.tar.xz)と[dpkg1.22.22公式source archive](https://deb.debian.org/debian/pool/main/d/dpkg/dpkg_1.22.22.tar.xz)のsource/manを固定した。

これらのsource契約を現在hostの全binary・独自patch・全OSのnative認定へ昇格させない。`-C`対照のowned DUMMYとnative readonly `rev-parse`、pathspec対照のGit2.54 `add --dry-run`、fixture setup、Hook stdin DATAによる提案command判定、native launcher/loader constructorの成立は別の証拠である。pathspecのdry-run対照ではindex作成・actual stage/commit/networkは0であり、全件成功の証拠ではない。このR47追補でAPI／実送信・active launcher／loader constructorのnative成立・新L3を主張しない。

### 同目的の出口と受入

同じ対象・操作・ordered cwd・実Git・loader/backend・capability/identity・shell/program・argv・env/config/source条件を保てる対応形だけを検討する。必要なlauncher/loaderや`-C`を単に除くことを同目的の代替とせず、条件を保てなければownerへ必要source/contextとUNKNOWN理由を示す。個別操作承認はHook停止・bypass承認ではない。独立FORBIDDENや別guardを解除する出口も作らない。

旧8696 bankの原入力・原期待/oracleと原FAIL/NEを保持する。局所試験・能力skip・部品閉鎖を統合全件、新公開head CI、同head両fresh正常review/全指摘処理、本文whole-body CAS/readbackの代わりにしない。新しい具体公開稿・head・各操作へのowner承認も別に確認する。以下のR46以前のround本文・日時・数値・リンクは当時の全文履歴として保持する。

<!-- PR191:R47:CONTRACT:END -->

<!-- PR191:R46:CONTRACT:BEGIN -->

<a id="r46-current-contract"></a>

## R46: parsed commitのprogram・selected env・cwdへ結び付くown検査

**修復作業中のsnapshot**。2026-10-19 00:15:41 JST時点、公開基点head `c3b8371b35550f01587d944c5b0d35ea75b234b6` に対する未commitのR46 candidateは修復作業中であり、この当時の最終source件数・統合全件・新公開head／同head CI／両fresh review・全指摘処理は未取得・PENDINGである。 同公開headのCodex normal review5563562682は2026-10-18 23:58:48 JST、CodeRabbit normal full5563566259は23:59:20 JSTに完了したが、23:59:45.256–23:59:52.394 JST取得の全220threadには新3件（Codex P1 4307502905・4307502909、CR Minor4307504522）が未解決で残る。 旧headのCI・全件成功や両normalを新R46 sourceの受入へ持ち越さない。

### 観測した不足と修復の有限契約

P1 2件のbefore対照は公開c3と本タスク初期head `df463a91b87547c8c228a4205e9ca1e3c057afff` の両方で再現し、R42–R45が新たに導入した危険側ALLOW退行とは分類しない。owned PATH側Gitがabsolute `/usr/bin/git commit`のown検査へ選ばれる不足と、提案`env -u GIT_INDEX_FILE`で除いた継承値をown検査が保持する不足を分ける。原26 Hook DATAはcommit実行0で、初期dfのprefix無しdenyはDENY_UNCLASSIFIEDとして保持する。実native commit/秘密の履歴混入/通信を実証したものではない。

| 境界 | R46で結び付ける条件・正常対照・通常費用 |
| --- | --- |
| 検査programの独立起点 | POSIXの既知固定install `/usr/bin`・`/bin`・`/usr/local/bin`・`/opt/homebrew/bin`にあるGitのrealpathを独立起点とし、見つけたPATH候補を自分で信頼集合へ足さない。bareはselected PATHの先頭実候補がこの既知canonicalと一致する場合に限り、absoluteな既知Gitは別のPATH shadowから独立に扱う。未知install・未解決/動的/欠落PATH・`command -p`は局所UNKNOWN。正当な独自installのcommitも止まり得る。 |
| selected envとcwd | parsed commitのprogram・選択env・実効cwdをown検査へ渡し、`env -u`／unset／`env -i`で消えたtracked名をprocess.env fallbackで復活させない。対応できない環境変換やcwdはUNKNOWN。意図して別index/repoを選ぶ通常操作も同じ条件を再現できなければ止まる。 |
| sanitationとcache | no-lazy-fetchやhelper除去は結合済みcontextから作るown検査copyだけの抑止であり、実行予定readerのsource非活性や安全性へ流用しない。version/config等のcacheをprogram・env・cwdで分離する。Git2.54 fixed-consumer資格は同contextで実取得したbannerだけへ結び付け、別contextの過去bannerを借用しない。 |
| common alias probe | 未登録namespaceはSGでもprobe前にUNKNOWNとし、既知namespaceで必要なprobeの実行体も独立に確認した絶対Gitへ固定する。継承envを誤って使う局所SG不足を、既存EG namespace UNKNOWNが止めることだけで安全としない。custom/missing subcommandのSG停止が増えるが、既存全体のEG停止や通常builtin対照と分ける。 |

既知Git/復元可能なselected env/cwdのclean commit ALLOWと、同じcontextのsecret stage FORBIDDENを別対照として確認する。UNKNOWNは検査不足の局所停止であり、独立に確認したFORBIDDENの優先や他guardを解除しない。unsupported raw commitを、解析したcommitと無条件に同じ検査contextへ当てはめない。

common aliasの有限before27 Hook DATAではownSGの選択config不足があったが、当該未登録namespaceはEG UNKNOWNで既に停止し、全3Hook通過や新P1とは認定しない。source/contextの同原因横断として修復し、任意namespace全般の新たな安全保証へ広げない。Minorのversion依存testも、固定consumerの実取得資格と未資格backendのUNKNOWNを区別して記録し、2.54 hostを全環境の前提にしない。

### 信頼起点の限界と同目的の出口

既知install realpathは有限の信頼起点であり、binary内容の由来、独自patch、実行までの置換race、全OSの同一動作を認証するものではない。Windowsの固定標準installという候補も実Windows OSで資格化したとはしない。Git2.54 bannerが一致するだけで任意backend全体の安全認証へ昇格させない。

拒否時は同じ対象・操作・program・argv・cwd/env/config・source条件を保てる既知の対応形だけを検討する。必要なGit/helper・index・repo・env条件を除いて同目的とはしない。readerとcommitの分割も意味と対象を保ち後commitを再検査できる場合に限り、条件を復元できなければownerへ実行source/contextとUNKNOWN理由を示す。ownerの個別操作承認はHook停止・bypass承認ではなく、必要条件が未確認のままHookを無効にする出口を作らない。

旧8696の原入力・期待や元FAIL/NEは保持し、新sourceの影響差と意図した通常費用を測る。部品閉鎖、統合全件、公開新headのrequired CI、同head両fresh normalと全指摘処理、whole-body CAS/readback、具体公開packetへのowner承認を別に確認する。このsnapshotで新R46最終件数・公開head・CI・freshを予測せず、native commit/helper・認証/通信や新L3の成立も主張しない。以下のR44以前の本文・日時・数値・リンクは各cutの全文履歴として保持する。

**R46局所調整snapshot**: 2026-10-19 00:43:29 JST時点、公開基点head `c3b8371b35550f01587d944c5b0d35ea75b234b6` に対する未commit candidateの最終新freeze・統合資格・新head/CI/freshは当時未取得・PENDINGである。 初回固定41-v2の全8696は5件の過剰UNKNOWNで不合格だった事実と原期待を保持し、その修復後sourceを旧873/15のPASSだけで資格化しない。

index/config検査に必要な環境projectionと、actual reader/outboundの従来wide trackingを分離する。index専用の検査envへは`GIT_AUTHOR_NAME`・`GIT_AUTHOR_EMAIL`・`GIT_AUTHOR_DATE`・`GIT_COMMITTER_NAME`・`GIT_COMMITTER_EMAIL`・`GIT_COMMITTER_DATE`を載せず、実commit identityや送信policyを評価する別wide guardは維持する。identityを検査envから除くことを、実際のidentity/送信sourceが安全である証明へ流用しない。

静的なordinary/identity向けnameref宣言だけでindex namespaceを不明とはしない。一方、Git/PATH/config等の重要name/targetへの参照はUNKNOWNとし、動的・無代入・未対応targetの不明状態はsticky UNKNOWNで保持する。actual childの対応済み`env -i` clear以外で自動解除せず、未対応namerefを全般対応したものではない。通常のidentityを同じ条件で使う意味を保ち、必要なtarget/envを除いた形へ逃がさない。同じ対象・操作・source/contextを復元できない場合は前記owner出口を使い、個別操作承認をHook停止承認へ読み替えない。

<!-- PR191:R46:CONTRACT:END -->

<!-- PR191:R44:CONTRACT:BEGIN -->

<a id="r44-current-contract"></a>

## R44: ordered proxy・複合empty consumer・sg/newgrpの有限契約

**修復作業中・最終受入PENDINGのsnapshot**。2026-10-18 14:46:08 JST時点、公開基点head `533a48fb08e3f27c9821eb4e145c5dc683aca670` に対する未commitのR44 candidateを対象とする。同headのCodex full5561591680は14:29:13 JST、CodeRabbit full5561600706は14:33:08 JSTに正常完了したが、14:35:36.049 JST取得の全216threadは未解決4件（Codex4305869528・4305869532・4305869534、CR4305878612）。R43承認済み公開op01–09は完了、条件付きop10は未実施であり、このsnapshotでは新R44 sourceの最終件数・全件、新公開head／同headCI／両fresh reviewと全指摘処理は当時未取得・PENDINGである。

### 選択sourceと通常操作の費用

| 境界 | 有限に扱う条件・正常対照・通常費用 |
| --- | --- |
| ordered proxy | 既存のcommit前・非query object/index-capable readerで、`core.gitProxy`の順序付き候補・domain・first match・literal `none`をprobe→parse→consumerへ保持する。last Map値へ潰さず、未知のpromisor hostに対して到達し得るprogramが残ればUNKNOWN。通常local status/object readerでも正当なproxyを使うと止まり得る。present `GIT_PROXY_COMMAND`はemptyでもconfig familyをshadowするが、他helperを無効にした意味にはしない。 |
| 複合empty shadow | Git askpassの実効選択がemptyで、選択SSH programもeffective emptyとなる両consumer条件が揃う場合だけ、当該inherited/baseline-equal `SSH_ASKPASS`のreader理由を非選択にする。既存trusted realpath/PATH同一性を満たすown inspectionが実取得したbanner `git version 2.54.0`とPOSIXのfixed-consumer資格に限定し、別版/未資格backendのcombined tupleはUNKNOWNを維持する。片方だけempty、changed-selector、他programや独立gateは解除しない。ownSG回復後も既存EG UNKNOWNが残り得るため、all3 ALLOW回復とは呼ばない。 |
| sg/newgrp | pinned shadow-utils4.13のargv0/group/login/optional -c/command・selected shellを分ける。backend/group/auth/shell contextが未資格なら、ordinary printfもlocal UNKNOWN。source roleが読めることと、そのgroupやshellの実行資格は別である。追加egress UNKNOWNはlate metadataに保持し、独立FORBIDDENを優先する。 |

proxyのactual selected DTO/configとown検査用copyは別に保持する。検査copyの`GIT_PROXY_COMMAND`除去やno-lazy-fetch hardeningを、実行予定readerのproxy不在・非活性の証明にしない。真正query/getter、commit後reader、無programの通常baselineを別に扱い、前段や独立source/context確認は維持する。`core.gitProxy`を追加しても既存exact commit -hのunsupported core UNKNOWNは変えず、既存credential noncore例外とも混同しない。

### 固定consumerの範囲

[Git2.54 connect.c](https://github.com/git/git/blob/v2.54.0/connect.c#L981)のproxyはordered/first-matchingのsourceで、promisor remote hostを未観測のまま後勝ち値だけで非選択とはしない。[prompt.c](https://github.com/git/git/blob/v2.54.0/prompt.c#L45)のaskpass shadowと[run-command.c](https://github.com/git/git/blob/v2.54.0/run-command.c#L288)のPOSIX empty dispatchは別consumerの条件として結合する。Git askpassがemptyであることだけでnative SSH側consumerの非活性を証明しない。

複合empty例外の実取得banner＋POSIX資格は、この有限な許可側判定を固定primaryへ結び付ける条件である。同bannerの独自patch全動作、他Git版/Windowsのempty dispatch、全backendのnative成立を認定するものではない。未資格backendでは通常のcombined tupleにもUNKNOWN費用が残る。actual helper/auth/contextを変更して空値を作れば同目的になる、という代替は示さない。

[shadow-utils4.13 src/newgrp.c](https://github.com/shadow-maint/shadow/blob/4.13/src/newgrp.c#L467)と[sg manual](https://github.com/shadow-maint/shadow/blob/4.13/man/sg.1.xml)／[newgrp manual](https://github.com/shadow-maint/shadow/blob/4.13/man/newgrp.1.xml)をgrammarの固定primaryとする。sgはgroup後のoptional -cが次wordを持つ場合にだけその次をcommand sourceとし、-c単独は文字列`-c`自体がsourceとなる。追加argvを連結して別commandにはしない。sgのgroupだけの形もdefault shell選択で、command無しをqueryとはしない。newgrpはgroup省略も含めselected shellのcontextを持ち、追加argvをchild commandとしない。

pinned4.13は先頭exact `-`/`-l`をlogin modeとして消費する。専用の--help/-h/version実装を確認しておらず、その後のgroup位置に残るdash tokenやsgのgroup不足は子sourceを選ばない早期usage/errorとして区別する。これを真正help/queryや実backendの資格にはしない。外側の置換・redirection・独立FORBIDDEN、printed DATAや非実行definitionの既存roleは別に評価する。primary pinはlocalのshadow-utils版・build・PAM/NSS/group設定・shell同一性の実証ではない。

### 同目的の出口と、公開受入の境界

必要なproxy・group・認証・shellを外して同目的とはしない。同じ対象・操作・argv・cwd/env/config・source/contextを保つ対応形だけを選び、readerとcommitの分割は意味を保ち後commitを再検査できる場合に限る。条件を保てなければownerへsource/contextとUNKNOWN理由を示す。

source/argv/context未確定は既存UNKNOWNのdeny wireで停止し、確認したpolicy違反のFORBIDDENと混同しない。新gateの非適用は他guardや独立sourceの安全認証ではない。提案reader・proxy・sg/newgrp・helper・認証・fetch/networkや新L3をnative実行したとは主張しない。

新R44の固定source/最終全件、公開新headのrequired CI、同head両fresh full正常完了と新指摘処理、全thread unresolved0、事実に合う本文とwhole-body CAS/readbackは別に確認する。旧533aの両normal reviewやR43の全件/CI成功を新sourceへ持ち越さず、新R44公開packetのhead/各操作を固定してowner承認を受ける。旧R43条件付きop10や本文残り操作を新headへ転用しない。

以下のR43以前のround節・日時・数値・旧「現在/current」は履歴として保持する。secret-guard-layersの旧解析noteにあるcurrent global pointerだけを最新R44へ更新する例外であり、dated round linkや旧QA結果を遡及改訂したものではない。

<!-- PR191:R44:CONTRACT:END -->

<!-- PR191:R43:CONTRACT:BEGIN -->

<a id="r43-current-contract"></a>

## R43: 継承program・設定fallback・順序付きcredentialの有限契約

**実装作業中・受入PENDINGのcut**。2026-10-18 09:24:37 JSTのdocs cutは、公開基点head `5c570d221b958dc212ac13e435d980d5f3d46080` に対する未commitのR43実装作業中candidateを対象とする。同headのCodeRabbit full5560708937は08:58:21 JST、Codex full5560746096は09:11:26 JSTに正常完了した。09:14:01.793 JST取得の全212threadは未解決3件（CR4305046733、Codex4305081716・4305081722）である。新R43 sourceの最終全件、新公開head／同head CI／両fresh fullと全指摘処理はPENDINGで、件数を予測しない。Codex依頼comment6243331421のGitHub createdAtは08:48:59 JSTで、正常完了まで22分27秒である。4305081716はSSH_ASKPASSの同種指摘、4305081722はinherited `GIT_SSH_COMMAND`をbaseline一致だけで免除する不足であり、公開threadの説明・解決は実装修復やレビュー正常完了と別に扱う。

### 旧方針との差とbefore証拠

旧R43 v1/v2はenvの継承／baseline同値を追加gateの非適用対照としていた。その未公開4docs全文・節はprivate backupへ保持する。新しい契約は、**有効な非空programが継承値やbaselineと同値でもUNKNOWNにする**。継承だからsourceが安全・不活性とは判断しない。元のinherited/equal ALLOW期待と理由を残し、新UNKNOWNは意図した通常費用の変更として記録する。元8696のbank・期待を黙って再採点しない。

修復前SSH envの20tuples／3source／180 Hook DATAでは全ownHook署名が旧2f／157c／5cで同一で、changed prefix／envの通過とlate projection欠落を観測した。core.askPassの別12tuple／4source／144 DATAではstatus・cat-fileのcore witnessが全4版3Hook ALLOWだったが、inherited GIT_ASKPASS empty/program shadowの2行には旧2f SG UNKNOWN→後続ALLOWの差があり、全12行同一とはしない。

後着2P1のbeforeは25tuple×4source×3Hook＝300 Hook DATA、pure metadata152、broken0である。exact SSH_ASKPASS findingは旧2f／157c／5cの3Hook ALLOWからcore v2修復のown SG UNKNOWNとなった。exact `git diff; git commit`にDUMMY inherited GIT_SSH_COMMANDを与えた対照では、旧2f own SG UNKNOWN→157c／5c／core v2 own SG ALLOWで、EGの既存UNKNOWNは別に残る。旧UNKNOWNはown inspectionの偶発的制限であり、実行予定readerのhelper sourceを確認した証拠ではない。inherited SSH_ASKPASSの通過は旧2fにも存在した。

core.sshCommand／credential.helperの別beforeは19tuple×4source×3Hook＝228 DATA、broken0で、非空configのstatus・cat-file witnessは全4版3Hook ALLOWだった。実late queryにkeyがなく、synthetic Mapだけを与えてもconsumerがない不足である。unsupported raw keyをparserが拒否してUNKNOWNにする経路と、実queryがkeyを取り落としてALLOWになる経路を混同しない。300／152／228はbefore証拠で、修復後の件数やnative helper実行回数へ加算しない。全19署名の同一も主張しない。

### 固定consumerとsource優先順位

| consumer | 一次根拠と有限な選択条件 | 混同しない境界 |
| --- | --- | --- |
| Git SSH program | Git2.54 [`connect.c`](https://github.com/git/git/blob/v2.54.0/connect.c#L1155)は存在するGIT_SSH_COMMAND、次にcore.sshCommandを選び、いずれも未設定なら[`GIT_SSH`、既定ssh](https://github.com/git/git/blob/v2.54.0/connect.c#L1382)へ進む。存在する空文字と未設定を分け、shadowされた下位programを選択済みとしない。 | GIT_SSH_VARIANTはoption／implementation familyでありprogramそのものではない。空SSH commandのnative不活性をこのsourceだけで証明せず、今回の新非空program gateと既存changed-selector判定を分ける。 |
| Git askpass | Git2.54 [`prompt.c`](https://github.com/git/git/blob/v2.54.0/prompt.c#L44)のPROMPT_ASKPASS経路では、存在するGIT_ASKPASS（空値を含む）、core.askPass由来askpass_program、SSH_ASKPASSの順に未設定時fallbackを選ぶ。[`environment.c`](https://github.com/git/git/blob/v2.54.0/environment.c#L466)と[core設定契約](https://github.com/git/git/blob/v2.54.0/Documentation/config/core.adoc#L496)へ結ぶ。 | 選択された非空programが実行条件で、存在する空GIT_ASKPASS／空coreも下位Git askpass fallbackをshadowする。helper失敗は下位programの再選択ではなくterminal経路へ進む。GIT_TERMINAL_PROMPT=0は後段terminalの抑止で、先行askpassの無効化ではない。 |
| native SSH askpass | portable OpenSSH [`V_10_3_P1 readpass.c`](https://github.com/openssh/openssh-portable/blob/V_10_3_P1/readpass.c#L127)はDISPLAY／WAYLAND_DISPLAY／SSH_ASKPASS_REQUIREのactivation条件と、[SSH_ASKPASS program](https://github.com/openssh/openssh-portable/blob/V_10_3_P1/readpass.c#L172)を別に選ぶ。 | GitのGIT_ASKPASS／core.askPassによるshadowでnative SSHのconsumerまで消えたとは扱わない。現在のbounded DTOにactivation変数がないことも非選択の証明ではない。portable sourceはApple patch一致やnative activationの証明ではない。 |
| Git credential helper | Git2.54 [`credential.c`](https://github.com/git/git/blob/v2.54.0/credential.c#L119)は複数helperを順序付きで保持しemptyでresetする。[helper実行consumer](https://github.com/git/git/blob/v2.54.0/credential.c#L484)と[設定契約](https://github.com/git/git/blob/v2.54.0/Documentation/config/credential.adoc)へ結ぶ。 | helper取得が必要な認証経路の実行条件であり、通常readerが必ず認証するという証明ではない。複数値・URL条件をMapのlast値へ潰して非選択と判断しない。 |

### 進行中の修復契約・正常対照・通常費用

適用は既存の順序確認とcapability条件を再利用し、同commandのcommitより前にある**非queryのobject/index-capable reader**へ限定する。全reader・standalone操作・全設定の一律拒否へ広げず、既存の確定FORBIDDENを新しいUNKNOWNで隠さない。

| 境界 | R43の進行契約 | 正常対照・費用 |
| --- | --- | --- |
| SSH envの3境界と実効program | late env projectionにSSH_ASKPASSを保持し、実効program4種GIT_SSH_COMMAND／GIT_SSH／GIT_ASKPASS／SSH_ASKPASSをsource優先順とconsumer別に扱う。非空programには継承／baseline同値でも新UNKNOWNを要求し、program選択をown inspection copyの安全性へ委ねない。 | legitimate inherited helperを持つlocal status／diffとcommitも止まり得る。inherited GIT_SSH_VARIANT自体や空programだけに今回の新UNKNOWNを追加しない。changed variant／changed空値を含む既存changed-selector UNKNOWNは維持し、空programのnative不活性や全guard ALLOWは保証しない。 |
| core.askPass／core.sshCommand | repository/globalの実効設定をbounded probe→parse→gateまで保持する。Git askpassとSSH programはそれぞれ存在／空値／優先順を区別し、選択された非空config programをUNKNOWNとする。 | envのbaseline一致はconfig全体の免除ではない。GIT_ASKPASSが存在すると新core askpass consumerはshadowされるが、その非空env program自身や独立native SSH consumerの確認は残る。exact inline core.askPass＋commit -hの既存UNKNOWNも維持する。 |
| ordered credential.helper | bounded probeの実出力順でconfig scope・raw key・URL subsection原綴り・whole valueをparseへ保持する。generic（URL subsectionなし）のemptyは全先行候補をclearし、scoped emptyは同じsubsection原綴りの候補だけをclearする。残る非空候補はUNKNOWN対象にする。 | section／variable名だけcasefoldし、URLのpath／username等をlowercaseしない。残存URL-scoped非空候補はtarget一致が未確定でも非選択と推測せずUNKNOWN。ordered metadataのないMap-only helper keyはemptyでも履歴未証明としてUNKNOWNとし、空helperの実行を確認したという理由にはしない。full URL matchingや新familyへ広げない。 |
| own inspection | 検査専用env copyからprogram sourceを除去し、actual selected Map／元envを保持する。GIT_NO_LAZY_FETCH=1、実argvの--no-lazy-fetch、trusted Gitの対応queryを継続する。 | own copyの抑止は実行予定readerのsource不在・不活性・無害認証ではない。per-config askpass resetを行ったとは主張せず、flag非対応backendや抑止下での欠落objectによる通常commit／staged scanのUNKNOWN費用も継続する。 |

実unset／env -uによる選択解除、未使用local、真正query／config getter、commit後reader、programのないordinary baseline、空／variantだけの対照を別に保持する。固定Git2.54の既存exact commit-usage例外では、inline credential.helperの値を実行sourceとしてreplayせず、実commit -hの非選択を維持する。core.askPass／core.sshCommandの既存UNKNOWN境界とは区別する。queryの語が値slotやDATAにあるだけで免除せず、各consumerの実modeと順序を見る。新gateが非適用でも他source・既存EG UNKNOWN・独立FORBIDDENは解除しない。継承非空programの元ALLOWから新UNKNOWNへの変更を、旧期待を黙って再採点した成功と呼ばない。

同じ対象・目的・mode・argv・cwd/env/config・認証sourceを保てる場合だけreaderとcommitを分け、後commitを新しいPreToolUseで再検査する。必要helperの除去・認証条件の変更・未知の実行sourceへの置換を同目的の代替とはしない。条件を保つ対応形式がなければownerへsource／contextとUNKNOWN理由を示す。

### 証拠と受入の限界

Hook DATAのown判定、pure metadata、固定consumer source、owned fixtureの診断、公開head CI、通常完了したfresh full reviewは別の証拠である。native helper／認証／fetch／network activationと新L3の成立は未証明で、提案reader／commit／helperはnative実行していない。own診断のsyscall traceや任意shell・全config・全Git版の安全認証も主張しない。追加L3は行わず、原FAIL／NOT_EXERCISEDを保持する。

新sourceの最終全件、新公開headのrequired CI、同head両fresh full正常完了と全指摘処理、全thread unresolved0、全本文CASと公開後の別GET readbackをそれぞれ確認する。公開5cに対する両reviewの正常完了は、新R43 sourceのfresh受入ではない。merge／公開の承認をこの文書からは得られない。以下のR42以前の全文・順序・数値・「現在/current」は各取得日時とsourceの履歴であり、旧継承免除や成功・partialを新R43の契約・資格へ持ち越さない。

<!-- PR191:R43:CONTRACT:END -->

<!-- PR191:R42:CONTRACT:BEGIN -->

<a id="r42-current-contract"></a>

## R42: 選択transport・署名consumer・run0とown inspectionの有限契約

2026-10-18 07:35:30 JST snapshotは、当時の公開基点head `157c15ebddae485a05fba350dae82435a432eea6` に対する未commit candidateを対象とし、最後の全体取得07:15:05.546の209thread／未解決9（CR6＋Codex3）を保持し、後着修復後の最終sourceの全件・新head CI・fresh両reviewの受入は当時PENDINGである。

公開157cへの両fresh fullはCodeRabbit5560271970（06:53:01 JST）とCodex5560315140（07:07:01 JST）が正常完了したが、新指摘の処理とは別である。R42 v1 actual36の初回paired fullは07:33:00.815 JSTに全8696の実行を完了し、旧157c・candidateとも8694 PASS／2 FAIL、broken0、差分0、source36／fixture安定だった。これは合格資格ではない。07:35:30 JST時点ではowned XDG_CONFIG_HOMEによる実行profile差の原因照合は未閉鎖であり、原2FAILを保存する。新readerのtarget75/75とrun0の19/19（owned Hook DATAを含む）は局所票として分け、format/source matrixと最終統合全件は別に確認する。後着2P1修復sourceはv1と別に資格化し、初回の結果を最終sourceへ持ち越さない。原8696入力・順序・非oracle項目、R41独立1oracle台帳、原FAIL／NEとR41以前の全文は保持する。

| 対象・固定consumer | 確認条件と停止の境界 | 正常対照・通常作業の費用・同目的の出口 |
| --- | --- | --- |
| commit前readerの選択transport | 非queryでobject/index能力を持つ先行readerでは、`context.selected`の`GIT_SSH`／`GIT_SSH_COMMAND`／`GIT_SSH_VARIANT`／`GIT_ASKPASS`が継承baselineと異なると`command-selected-transport` UNKNOWN。検査envからselectorを消すだけで実行予定readerのsourceを判定済みとしない。 | 完全local fixtureの通常status＋commitでも、明示transport prefixがあるとremote activationの非選択を証明できず停止し得る。継承／baseline同値、未使用local、unset／env-u、対応するstdout query／config getter、commit後readerは新gateの追加停止対象外。helper本文の安全認証や他guard解除ではない。 |
| guard自身のobject検査 | 検査専用env copyの`GIT_NO_LAZY_FETCH=1`と実argvの`--no-lazy-fetch`を設定し、初回trusted Git query `--no-lazy-fetch --version`で対応を確認する。実行予定readerの選択contextはDATAのまま保持する。 | fsmonitor BooleanのGit>=2.36資格とは別。stock Git2.36〜2.44等の非対応backendや、抑止下で必要objectを読めないcontextでは通常commit／staged scanもUNKNOWN。実測Git2.54以外の独自backport全動作を認証せず、backend更新または同等contextをownerへ確認する。 |
| Git2.54の非log署名consumer | `shortlog`のpretty／formatと加算される`--group=format`、`for-each-ref`／`branch`のref-filter署名atom・sortを別consumerとして確認する。`shortlog` summaryがdescriptionを省いてもgroupは残る。`branch.sort`のrepository-config fallbackはboundedな多値・順序付きのsortとしてactivationを確認し、CLI `--sort`は追加、`--no-sort`は消去として扱う。inline `-c`／`--config-env`の同keyは従来UNKNOWNの境界を維持し、global config-key allowlistは広げない。 | 普通の表示・grouping・sortも未検査verifierを選び得るとUNKNOWN。`%%` escape、raw `contents:signature` DATA、last非署名format、消費grep値・実terminatorは別対照。対応する実`-h`の終端を確認し、manを呼び得る`--help`等を一律query免除しない。`shortlog`が消費しない`format.pretty`は非選択の正常対照。repository fallbackの`--no-sort`正常対照は07:35:30 JSTの旧cutではSG ALLOW／EG UNKNOWNだったが、07:40:07.042 JSTの閉鎖票ではknown flag対応後の同じsort resetでSG／EG／AG全ALLOWを確認した。`reflog`は既存secret-git全体のUNKNOWNのまま非対応で、新たなoperation ALLOWを足さない。必要な署名表示は勝手に外さない。 |
| systemd v256 `run0` | v256の独自option/value/child grammarに限定して登録し、`systemd-run` grammarを流用しない。v258 sourceはrun0対defaultのdispatchと追加optionを照合した範囲で、v258全grammarの対応証明ではない。未知の新option、manager／identity／cwd/env／PAM等の未知実行contextはUNKNOWN。 | 普通の`printf` childもcontext未証明なら止まり得る。`--help`／`--version`／`-h`／`-V`はCOMMAND前の実optionとして到達した場合だけ正常queryとし、消費値やchild内の同語を免除に使わない。対応するknown scalarでは、同statementのprefix上書き前の値がargvへ展開される順序を保ち、新代入値だけでquery／childを判断しない。未知値をqueryへ推測せず、先行semicolonで確定したscalarや対応local functionを別対照にする。必要なrun0／認証／contextを削除して同目的とせず、対応形式がなければownerへ条件を渡す。 |
| post-index-changeのP2反証 | `hook.<friendly-name>.enabled`とevent選択を区別する。`hook.post-index-change.enabled=false`が全event／traditional callbackを無効化するという提案は、Git2.54 sourceと独立した非実行listで反証され、現行policyを維持する。 | event名と同じfriendly名のfalseだけではconfigured dummyとtraditional hookが残り、dummy自身のfalseでconfigured dummyだけdisabledとなる。これはhook listの非実行queryで、callback／index／status／commitを実行した証拠ではない。公開threadは未解決のままで、説明・resolveを別に扱う。 |
| 試験用hooks path | curl credential／curl alias／Wget credential試験のhooks引数を`path.resolve`し、`require`とfile readのtargetを一致させる。 | default／absolute／relativeの同targetを確認し、旧relative MODULE_NOT_FOUNDは原結果として残す。 |

### 一次根拠と確認の限界

署名consumerは[Git2.54 shortlog](https://git-scm.com/docs/git-shortlog/2.54.0)／[for-each-ref](https://git-scm.com/docs/git-for-each-ref/2.54.0)の有限なformat契約を使う。P2は[hook.cのconfigured＋traditional列挙](https://github.com/git/git/blob/v2.54.0/hook.c#L359)／[disabled判定](https://github.com/git/git/blob/v2.54.0/hook.c#L403)と[friendly-name enabledの公式設定](https://git-scm.com/docs/git-hook/2.54.0#_configuration)を、owned Git2.54の非実行listに照合した。run0対応は[systemd v256 source](https://github.com/systemd/systemd/blob/v256/src/run/run.c)／[v256 manual](https://github.com/systemd/systemd/blob/v256/man/run0.xml)へ固定し、[v258 source](https://github.com/systemd/systemd/blob/v258/src/run/run.c)のdispatch差分照合と分ける。own検査の[flag/env契約](https://git-scm.com/docs/git#Documentation/git.txt---no-lazy-fetch)も別に確認する。known scalarのprefix／argv順序は[GNU Bash 3.7.1](https://www.gnu.org/software/bash/manual/html_node/Simple-Command-Expansion.html)の有限な対応範囲に結ぶ。

初回run0 candidateの同tuple Hook DATAでは、旧公開の未登録通過と、登録のみ除去したcopyでの反転を観測した。ただしprinted-DATA witnessの既存EG UNKNOWNは残り、全DATAのALLOWとは呼ばない。Hook DATA・非実行query・native実行は別の層であり、run0／PAM／認証／verifier／transportのnative成立を主張しない。最終sourceの件数・資格は冒頭の取得cutに従って別に結合する。

進行candidateのPENDINGは対象source／head・snapshot時刻・当時未取得項目を同じ文へ結ぶ。新sourceの全件、same-head CI、両fresh fullと全指摘処理、公開本文readbackを別に確認し、追加L3・ZIP・全記録網羅・main報告統合をmerge4条件へ足さない。以下のR41以前は当時cutの契約・数値・current表示として保持する。

<!-- PR191:R42:CONTRACT:END -->

<!-- PR191:R41:CONTRACT:BEGIN -->

<a id="r41-current-contract"></a>

## R41: index更新callback・署名verifier・systemd-runの追加境界

基点は公開 `2f8e3c62b285073b0714a6fd39325d6fa72938af`。fresh Codex review5553871277（2026-10-17 06:25:41 JST）から、`post-index-change`、pretty signature placeholder、`systemd-run`の3件を受領した。06:29:17.947676 JSTの保存primaryは全197thread終端取得・未解決3（Codex P1、CR0）。指摘本文が報告するnative再現を、こちらのHook DATA試験や全版の成立証明へ読み替えない。

**公開前snapshot**: 2026-10-17 06:47:19.559 JSTのv2固定時点では、当時の公開基点head `2f8e3c62b285073b0714a6fd39325d6fa72938af` に対する未公開R41 candidateの部品・統合全件・新head CI・fresh reviewの最終受入をPENDINGとして記録した。06:49:50.108 JSTのv3は同じ公開基点でのdocs文言修正で、この当時の状態を保持した。

後続の公開head `157c15ebddae485a05fba350dae82435a432eea6` では、required CI run [38972258568](https://github.com/theosera/obsidian-ai-pipeline/actions/runs/38972258568) のjobが2026-10-17 06:53:02 JSTに成功完了した。2026-10-18 06:54:58.180 JST取得snapshotの当時head `157c15ebddae485a05fba350dae82435a432eea6` では、fresh CodeRabbit full review5560271970は06:53:01 JSTに正常完了して新6件が未解決で、fresh Codex fullは進行中のため、両fresh reviewの受入と指摘処理はPENDINGである。

進行candidateの記録を更新するときは、PENDINGとする未測定・未受入の項目、snapshot取得日時、対象head（未公開なら当時の公開基点headとcandidate版）を必ず同じ文に記す。後続の公開・CI・review結果は別の取得として追記し、過去snapshotや原FAIL／NEを現状へ書き換えない。

この節はR41の修復範囲と確認条件を保持する。R40の公開headでの8696／Node789／別parity15／CI成功はその固定sourceの履歴として下に保持し、新sourceの全件・公開CI・fresh両reviewと指摘処理へ持ち越さない。

**R42局所追補**: 2026-10-18 06:58:26 JST snapshotの当時の公開基点head `157c15ebddae485a05fba350dae82435a432eea6` に対する未commitcandidateであり、このcandidateの新全件・新公開head CI・fresh両reviewの受入は当時未取得である。commitより前の非queryでobject/index能力を持つreaderは、`context.selected` の `GIT_SSH`／`GIT_SSH_COMMAND`／`GIT_SSH_VARIANT`／`GIT_ASKPASS` が継承baselineと異なる場合、`command-selected-transport` UNKNOWNとなる。promisorのmissing object／lazy fetchやsubmodule等によるremote activationの非選択をbounded probeで証明していないため、完全local fixtureでも、明示transport prefix付きの通常statusとcommitの連結が停止し得る。継承値／baselineと同値の選択／未使用local／対応するenv -u／真正query／config getterはこの新gateの追加停止対象外だが、helper本文の安全認証や他guardの解除ではない。sourceの移動や検査用envの消去だけで、実行予定readerの選択sourceを判定済みとは扱わず、native helper起動・通信成立の実証も主張しない。必要なsourceを外して同じ目的と扱わず、既存の同目的・同条件を保つ出口に従う。

**R42 own inspection追補**: 2026-10-18 07:02:52 JST snapshotの当時の公開基点head `157c15ebddae485a05fba350dae82435a432eea6` に対する未commitcandidateの局所修復であり、試験件数と新全件・新公開head CI・fresh両reviewの受入は当時PENDINGである。guard自身のdiff／ls-files等のobject読取が欠落promisor objectからlazy fetchへ進むのを抑えるため、検査専用env copyに `GIT_NO_LAZY_FETCH=1`、実own Git argvに `--no-lazy-fetch` を加え、最初のtrusted Git queryも `--no-lazy-fetch --version` で対応を確認する。[公式manualのflag/env契約](https://git-scm.com/docs/git#Documentation/git.txt---no-lazy-fetch)と[Git 2.54.0 git.c](https://github.com/git/git/blob/v2.54.0/git.c#L192)／[odb.c](https://github.com/git/git/blob/v2.54.0/odb.c#L610)／[promisor-remote.c](https://github.com/git/git/blob/v2.54.0/promisor-remote.c#L29)が同原因のown-side抑止の根拠である。既存のGit 2.36以上という資格はfsmonitor Boolean専用で、lazy fetch抑止flagの対応確認とは別である。たとえばstock Git 2.36〜2.44などflag非対応backendでは、通常のcommit／staged scanもown inspection UNKNOWNとして停止し得る。欠落objectを抑止下で検査できない場合も、backend更新または同等の検査contextをownerへ確認する費用がある。実測backendはGit 2.54.0に限り、capability queryの受理だけで独自backportの全動作を認証しない。実行予定readerの選択env/contextはDATAのまま保持し、検査用copyでの抑止をそのsourceの非選択判定やhelper本文の安全認証へ流用しない。source移動・env sanitizationだけで判定済みとせず、必要sourceを外して同等操作と扱わない既存の出口に従う。

| 追加範囲 | 確認するconsumerとUNKNOWNの境界 | 通常作業への影響・正常対照 | 同目的の出口 |
| --- | --- | --- | --- |
| commit前readerのindex更新 | index refresh/writeに伴う`post-index-change`の選択source・presenceを、pager/fsmonitor等と別に確認する。reader名だけでcallbackなしと推測しない。 | indexを更新し得る普通のreaderも、実効hook条件が未検査なら止まり得る。非選択／対応query・独立FORBIDDEN等を別対照にし、全Git readerの禁止へ広げない。 | 分割して意味を保てる場合はreader後のcommitでstaged状態を新しく検査する。必要なhookの削除・無効化を同等操作と決めつけない。 |
| history表示の署名verifier | signature placeholderや署名表示optionが選ぶverifierと設定sourceを確認する。formatを一律に不活性DATAとは認定せず、未検査active verifierはUNKNOWNにする範囲を詰める。 | 署名表示を要求する通常のlog/show等にも費用がある。非署名format、literalなformat DATA、非選択条件を別に試験する。選択historyに署名があるか、backendが実際に起動したかはHook DATAだけでは証明しない。 | 署名検証が不要で表示の意味を保てる場合だけ非署名の対応形式を選ぶ。検証が目的なら勝手に外さず、分割後のcommit再検査またはowner確認へ。 |
| `systemd-run` launcher | option/value/child境界と、system/user manager・service/scope・cwd/env/source等の実行contextを分ける。子が見つかってもcontext既知とはしない。未知のoptionや暗黙sourceを推測ALLOWにしない。 | 同じargvを直接起動する場合とmanager経由は同等とは限らない。真正terminal query、消費されたquery風DATA、子command、独立した確定FORBIDDENを分けて確認する。 | service/scopeや環境を外して同じ目的とは扱わない。同じ対象・操作・contextを保つ対応形式がなければownerへ不足条件を示す。 |

reader側の固定consumerはGit 2.54.0である。index能力のある先行readerでは、同じcwd・Git global option・選択envでGitにtraditional `hooks/post-index-change`のpathを解決させ、本文を読まず実行可能性だけを観測する。存在または確認不能ならUNKNOWN、不存在／nonexecならこのconsumerの確認を継続する。stdout queryや非index操作での非選択は、他のsource検査の免除ではない。configured `hook.*.event`は多値をlast値へ潰さず保持し、有効な`post-index-change` eventがあればtraditional pathと別にUNKNOWNとする。guard自身の読取りにも`core.hooksPath=/dev/null`と`GIT_OPTIONAL_LOCKS=0`を使い、configured post-index callbackは別に事前停止する。任意hook本文の無害判定やcallbackのnative実行試験ではない。

署名verifierの選択は`log`／`show`／`whatchanged`／`rev-list`のpretty `%G`、`--show-signature`／`log.showSignature`／`format.pretty`等で分ける。`%%`のescape、literalな無署名format、値に消費されたDATA、実`--`境界を区別する。`--no-show-signature`でもpretty `%G`自体のconsumerは残る。dynamic formatや未検査named format aliasもUNKNOWNとなる通常費用があり、選択historyが無署名だと推測して通さない。検証を目的とする作業から署名表示を勝手に外さない。

未確定pretty formatの正常対照1件は、原ALLOW期待に対しR41全件でownSG UNKNOWNとなった原FAILを保持し、独立台帳で期待変更を宣言する。`-P`はpagerだけを非選択にするため、未確定formatの署名consumerまで除外した証明にはしない。これは実`%G`やverifierが実行された証明ではなく、情報不足の局所UNKNOWNという通常費用である。literalな無署名formatは別の正常対照として保持する。元8696の原定義・原期待は別exportで保存し、inputの非oracle項目は変えない。台帳適用後の全件受入は終端票待ちである。

`systemd-run`の固定consumerは[systemd v258の実装](https://github.com/systemd/systemd/blob/v258/src/run/run.c)と[同tagのmanual](https://github.com/systemd/systemd/blob/v258/man/systemd-run.xml)で区別する。serviceはmanager親・detached環境、scopeはcaller側の子実行／環境継承だが、scopeにも独自の環境展開が残る。現bounded対応はmanager・identity・target・cwd/env・展開の同値を認証していないため、active実行を局所UNKNOWNとする。実COMMAND前のoption解析中に到達するexact `--help`／`-h`／`--version`と、値slotや子argv内の同じ語は分ける。query／printf DATA／function overrideの対照を保ち、全shell禁止や実systemd backendの検証済みという意味にしない。

FORBIDDENは確認できた操作・対象のpolicy違反、UNKNOWNはconsumer/source/contextの必要情報不足として、既存wire enum／理由prefixを使う。新しいsource不確実性で独立した確定FORBIDDENを隠さないこと、通常ALLOW対照を不要に失わないことも受入条件にする。既存standalone readerの制限を一括解除・拡張するものではない。

### 確認と限界

元reviewのcommandとinput/cwd/project/env、旧case/oracleを保持し、追加境界のownHook分類・正常対照・独立FORBIDDEN・単一edge除去時の差を有限に確認する。新option/backend/contextを未確認のまま対応済みと記録せず、実Git hook／verifier／systemd manager・transportのnative実行をHook DATAの成功から推定しない。

部品targeted／全件比較／公開head CI／fresh両review通常完了と指摘処理／thread0／公開本文readbackは別のgateである。最終件数・公開完了はROOTの終端票待ち。追加L3やZIPを受入条件へ足さず、原FAIL／NOT_EXERCISEDを保持し、mergeは行わない。以下のR40以前は当時cutの契約・数値・current表示である。

<!-- PR191:R41:CONTRACT:END -->

<!-- PR191:R40:CONTRACT:BEGIN -->

<a id="r40-current-contract"></a>

## R40: commit 前の Git reader と検査用 Git の有限契約

基点は公開 `d0d4f6f070078195f1e6e7df824a4a2b325ec667`。読取りというcommand名でも、commit前にpager・fsmonitor・diff driver／textconv等が動けば、PreToolUseが見たindexを後から変え得る。今回追加するのは、**同じcommandの最初のactive commitより前にあるGit reader**について、実効設定と選択sourceを確認するsecret-gitの局所UNKNOWNである。commit自身のcallback全部の認証でも、standalone readerの新しい一律禁止でもない。別の既存guardが単独readerを止める条件は解除しない。

### 選択条件・通常作業への費用・停止後の出口

| 境界 | 止める条件と正常対照 | 通常作業への費用・同目的の出口 |
| --- | --- | --- |
| 実効設定とcontext | 信頼済みGit実体、対象の`-C`／git-dir等、選択されたHOME/XDG・Git設定・pager・PATH等のenvを対応するroleで確認する。prefix/export/unset/`env -u`/`env -i`の順序を保ち、未exportのlocalを子envへ渡したと扱わない。未証明の設定root変更、非許可Git env、未知argv/context/実行先は新probe前にUNKNOWN。設定読取失敗・上限超過・不完全な形式もUNKNOWN。 | 通常のreaderでも別PATHや動的な設定rootが必要なら止まり得る。bare `command -p git`の既定検索先をhookのPATHと同一視しない。通常の`command`や`--`と区別し、絶対calleeも実際の信頼済みGit identityとの一致が必要。同じ実行先・対象・cwd/env/config/sourceを確かめられなければownerへ不足条件を渡す。別HOMEや別repositoryへ移すことを自動代替にしない。 |
| pager | 実際にpageし得る操作、実global `-P`/`--no-pager`、per-command設定、選択env/configの順序を分ける。global `-p`で強制する場合はper-command pager選択をskipし、GIT_PAGER→core.pager→PAGER→defaultを確認する。未選定の既定pagerもsource不明ならUNKNOWN。正確な空文字/`cat`や対応済みdisableを区別し、option値に消費されたno-pager風DATAは解除でない。 | 普通のdiff/log/show等をcommitと連結するだけでも止まり得る。表示helperが不要で目的を保てる場合だけ実no-pagerを使う。必要なpagerを外して同等だとは決めつけない。 |
| grep quiet・不正argv | 実`-q`/`--quiet`はdefault pagingだけを非選択にする。消費DATA、option解析終了、`--no-quiet`のresetを区別し、明示pager/強制`-p`/trace/index/textconvは独立に確認する。有限対応のcontext/-A/-B/-Cのliteral非数値と、first pattern後で実`--`前のliteral dash pathはmode UNKNOWN。 | quietなのに既定pagerが選ばれたという説明で拒否しない。消費値がDATAであることだけで正常な数値/pathとは認定せず、pager未到達の不正modeをpager費用へ混ぜない。正常なliteral数値や明示`--`後のpathは別対照とし、元入力の同等代替と決めつけない。 |
| grep NODASH式 | 対応する式の括弧をbare path境界へ変えず、式の途中の実option・消費DATA・実`--`の役割を保つ。 | true-P正常対照をmode UNKNOWNへ誤分類した退行を修復した範囲であり、元compoundの既定pagerや独立helper条件を解除しない。任意の式parser全体の同値証明ではない。 |
| fsmonitor・diff driver・textconv | index能力を除外できないreaderの有効fsmonitor、diffの外部program/driver、変換が有効なroleを別々に確認する。blameの変換、grepの明示textconv、cat-fileのmodeも実option・last toggle・消費DATAで分け、未対応modeや未検査helperはUNKNOWN。 | custom driver等を使う正常な読取りも止まり得る。revision/object/attribute readerも名前だけでindex非依存とはせず、能力を除外できない場合は有効fsmonitorによりUNKNOWNとなる。driverのattribute適用を全件解決していないため、変換可能なroleでは未検査のdriver設定だけでも費用が生じる。`-P`はfsmonitorや変換まで無効にしない。`--no-ext-diff`/`--no-textconv`等は、それを外しても同じ目的を保てる場合だけ選ぶ。必要なhelperに同等代替がなければownerへ。 |
| query・非選択source・順序 | 対応するstdoutの真正queryと、manual viewer/未知mode、消費されたquery風DATAを分ける。真正queryはhelper非選択でも、実行先・設定source・診断出力先の確認を通る。commit後のreaderは新しいprior-reader gateの対象外。 | query風の語だけで免除せず、真正queryでもsource条件が不明なら止まり得る。単独の対応readerを新gateで一括停止しない。読取りとcommitを分ける場合も、reader自体の既存source制限を免除しない。 |
| 診断出力先 | 実行予定readerのtrace環境変数と、repository setupより前に選ばれるsystem/globalのTrace2設定を区別する。activeな診断sinkや非許可Git envは新probeへ転送せずUNKNOWN。local/worktree/commandのTrace2設定をearly sourceと同じに扱わない。 | queryやno-pagerでも診断出力の副作用は別に残る。同じ作業・sourceを保てる場合だけ対応した診断無効化を選ぶ。必要な診断出力を消して同目的と決めつけない。 |

queryの非消費証明もmodeと固定consumerに限定する。非強制のbuiltin versionはRUN_SETUP/per-command pagerを選ばないが、実行先・env・Trace2等の確認は残る。Git 2.54.0で正確に`commit -h`へ到達する有限形は、setup/source/target/helper consumerに属さない有効literal keyだけを省略し得る。include/includeIf、remote URLの間接source選択、未知core等まで免除しない。他builtinや別版の未知namespaceへ一般化せず、grepのstdout usageも前段file callbackがない対応prefixだけを扱う。後置helpだけで`-f`等の先行読取を取り消さない。

early configと通常probeは条件付きincludeの文脈が異なるため、scope/last valueだけで同値とはしない。system/global conditional宣言のTrace2不確実性は、元envの三target全てが明示非空0/大小文字falseのときだけその分を除ける。空文字やprobe用抑止では代用しない。pager側のconditional選択は別境界として残し、実no-pagerや選択されたinactive GIT_PAGER等の対応条件で分ける。

新UNKNOWNは従来の解析・literal filename・staged/pathspec等の確定FORBIDDENより後に判定し、既存の禁止を新source不足で覆わない。二回目の解析はreader用の選択envを追跡するためだけに使い、最初の解析のcallee・引数・実行順が変わっていないことを確認する。ALLOWは対応条件内でこのgateが停止しない結果で、helperや任意shellの安全認証ではない。

停止後は、対象・操作・表示/変換要件・cwd/env/config/sourceを保てる場合だけ、対応optionや読取りとcommitの分割を選ぶ。分割後の独立commitはstaged状態を新しく検査する。意味を保つ対応形式がなければownerへ条件と不明点を提示する。個別操作の了承をhook無効化の了承へ読み替えない。

### secret-git 自身の staged/path 読取は別責務

guard自身のindex/path照合は、提案された先行readerとは別の検査呼出しである。信頼済みGit実体を使い、検査にはno-pager・fsmonitor無効化、diffにはno-ext-diff/no-textconvを指定する。このfsmonitor boolean無効化を使えるGit 2.36以上という版条件を確認できなければ検査失敗として止める。旧Gitへ同じ文字列を無条件で渡して無害とはしない。

検査自身のtrace出力も別に抑止する。新moduleの最初のversion照会・三つのstaged/path読取・実効config probeではTrace2三targetを明示0にしてsystem/global設定へのfallbackを止め、active traceや非許可Git envを確認できない場合はprobe前に停止する。共通部品のalias config観測も別の一呼出しとしてno-pagerとtrace抑止を適用する。SG三読取、新probe/version、共通alias観測を同じ呼出しや同じ試験として合算しない。これらの内部抑止を、実行予定readerのsourceが非選択だった証明へ流用しない。

一方、先行readerの実効設定の観測には検査用fsmonitor上書きを混ぜない。選択helperを消してからhelperなしと観測することを避けるためである。対象contextでhelper・診断に関係するkeyだけを上限付きで読み、scope NUL／key LF value NULの形式とlast valueを確認する。設定値/helper本文/環境値を拒否理由や公開結果へdumpせず、呼出元には固定のsource種別と不足理由だけを返す。固定consumerのsource照合はGit 2.54.0であり、config/includeや任意helperの全副作用、設定読取から実行までの競合、native全挙動・全版をこの有限gateだけで保証しない。

実装は[reader部品](../../.claude/hooks/lib/git-precommit-readers.cjs)、[secret-git](../../.claude/hooks/block-secret-git.cjs)、[共通env/context解析](../../.claude/hooks/lib/git-guard-common.cjs)に分ける。[reader role試験](../../.claude/hooks/tests/git-precommit-reader-roles.test.cjs)はrole/context/config framing/query/helper選択と自前読取hardening、[選択env試験](../../.claude/hooks/tests/git-precommit-environment.test.cjs)はexport/prefix/unset等を扱う。[内部Git診断試験](../../.claude/hooks/tests/git-inspection-diagnostics.test.cjs)はowned DUMMYで抑止前のactivation controlと抑止後の出力不存在を確認する。この1件はGit/Node subprocessを使うためpure解析試験ではない。提案された攻撃commandやClaude入口を実行した証拠でもない。

### 受入と履歴

2026-10-17 00:47:48 JSTの固定sourceに対し、Node 24.22.0の契約試験は00:48:36.216880までに776/776成功、別production shell parityは00:48:49.694677までに15/15成功した。776には選択env14件・reader role23件・binding追加1件・上記内部Git診断1件を含む。全776をpure解析L1とは呼ばず、parity15や部品単一edgeの成功を全件比較へ加算しない。

元8586定義・期待を維持した新69追加、計8655の初回全比較は2026-10-17 00:59:00.455 JSTに完走した。baseline期待不一致0に対しcandidate期待不一致48、旧signature差51、新69全一致・broken0、source/fixture安定である。51差はすべてownSG ALLOW→UNKNOWN、EG/AG分類差0。48件はaggregate ALLOW→DENY、残3件は別Hookで既にDENYのままで、51を新しい脆弱性数や48を合意済みcostと扱わない。危険側ALLOW拡大0でも、元期待に適合した結果ではない。

後続の995d source full8687は2026-10-17 01:34:04.188 JSTに完走し、baseline旧8586不一致0／candidate旧8586不一致46／new101不一致0／broken0。49signature差は全てownSG ALLOW→UNKNOWN、EG/AG分類差0、旧SG FORBIDDEN127件を維持した。未適用46台帳は静的整合18/18でもquiet過剰拒否1と不正argv2件へのdefault pager理由不一致があり、適用前に棄却した。原48/46FAILと元入力・oracleを保持し、契約費用と修復すべき過剰拒否を混ぜない。

3b0112 sourceの限定修復ではR11SG40の元ALLOWがfocusedで復帰し、R11SG29/31は原ALLOW期待を残したままmode UNKNOWNへ説明を訂正した。部品pure33/33とsyntax3/3、12入力×2stage×3Hook=72callsはそのsourceの限定結果で、元2不一致を成功へ再採点しない。固定source全体のNode契約は2026-10-17 01:42:51.105333 JSTまでに786/786、別production shell parityは01:43:01.559529までに15/15成功。内部Git診断のowned DUMMY activation/suppressionを含むため、全786をpure解析とは呼ばない。

同じ3b0112 sourceの単一edge逆検証は12profiles／36pairs／216Hook／failed0。各witnessのownSG UNKNOWN→ALLOWとaggregate DENY→ALLOW、通常ALLOWと独立FORBIDDENの維持、source5安定を確認した局所証拠である。旧9profiles／27pairs／162Hook／19unique inputsのcutは履歴として別に保持し、合算しない。

その後3b0112 sourceの全8695は2026-10-17 01:50:45.859 JSTに完走し、原8586期待に対して45不一致／baseline0不一致／new109不一致0／broken0だった。理由wireの再取得ではNODASH式の正常対照を新dashpath modeへ誤分類する1FAILを見つけ、C7で1行修復した。同じtrue-P入力はd0 ALLOW→3b UNKNOWN→C7 ALLOW、9Hook・broken0。元R11SG48 compoundは既定pager UNKNOWNであり、別正常対照のALLOWと混ぜない。原45FAIL・理由wire1FAIL、旧pureの前提訂正と棄却されたregex-LF仮説も履歴として保持する。

現在の固定readerは29936B、SHA c7fb90994ab81cf937820a4101ce409b9594a4b8719f4908a24cd052fa9b776b。停止時のNode 24.22.0契約787/787（01:51:44.435809 JST完了）、別production shell parity15/15（01:51:54.564548完了）を保持する。内部Git診断のowned DUMMY activation/suppressionを含むため、全787をpure解析と呼ばない。C7逆検証12profiles/36pairs/216Hook・failed0と、45入力135Hookの理由一致（41default pager／2変更HOME/config source／2不正mode）も同sourceの局所証拠である。理由一致は原ALLOW期待の合格や45台帳の適用ではない。

元8586原期待＋new110、計8696の旧runはowner停止で2832/8696、complete:false／interrupted:true／exit1だった。実行済み16992Hookは旧2832入力のbaseline/candidateで、新110は未実行。partial44不一致／broken0を最終件数にせず、未完rawを保存する。再開時にROOTが27source/testの停止時一致を確認し、同じ固定C7を新runで全件再比較した。旧中断分を新runへ加算せず、既存unit/parity/逆/理由証拠は同hashの範囲で再利用する。

再開後、45件の理由付きversioned期待を公開loaderへ明示適用した。元8586の原定義・原期待は全記録を保持し、変更は宣言した期待値fieldだけ、command/stdin/cwd/project/env等の非oracle入力は不変。現在評価の全8696定義JSON SHAは8a29fc91004f79d3c36caca6ef5659068bf0f0d204e939a3038afac27f3adfcaであり、元8586 bankや未適用時の全定義SHAと混同しない。loaderのtemplate/挿入位置は独立static11/11で確認した。改変検知を含むbinding再資格後のNode契約は2026-10-17 05:46:32.682433 JSTまでに789/789成功、別parityは05:46:43.948107までに15/15成功。停止時787は履歴として残し、全789をpure解析とは呼ばない。

再開後の新runは2026-10-17 05:44:14.127〜05:56:56.436 JSTに8696件を完走した。原8586のbaseline期待不一致0に対しcandidateは元期待45不一致、new110不一致0／broken0、実Hook51846、source/fixture安定だった。旧signature差48はすべてownSG ALLOW→UNKNOWNで、EG/AGカテゴリ差0、旧SG FORBIDDEN127件の欠落0。原45FAILとexit1を保持する。

05:57:00.566 JSTの独立再集計は、この同じHook記録へ宣言した45件の期待を明示適用して**8696/8696適合・failed0**を確認した。理由は既定pager未検査41・変更HOME/config source未検査2・不正grep argv2で、元入力・非oracle項目は全保持、runtime5は固定sourceと一致する。これは追加の8696実行ではなく、raw結果を書き換えない期待の再評価である。中断runやunit/逆検証を今回の件数に加算しない。

**05:57 JSTの公開前cutでは、新head CI・fresh両reviewと指摘処理をPENDINGとした**。その後の公開2f8e3c62のCI run38966630535は成功し、両fresh fullは正常完了したが、新6件は未処理（06:43:48 JST取得）。未公開R41の新head CI・全件受入は別にPENDINGである。部品修復・期待再評価をnative exploit成立や任意shell/設定の安全認証へ昇格しない。R39の8586/8586、L1 737/737等は旧source/cutの履歴で、R40数値や合格へ転記しない。追加L3やZIPをgateへ足さず、原FAIL/NOT_EXERCISED/未資格を残す。

current参照はこのR40 anchorへ結び付ける。明示したR35〜R39の歴史anchorや本文を一括置換しない。以下のR39以前は取得当時の契約・結果である。

<!-- PR191:R40:CONTRACT:END -->

<!-- PR191:R39:CONTRACT:BEGIN -->

<a id="r39-current-contract"></a>

## R39: 実行対象・SSH互換名・認証source・ping宛先の有限契約

基点は `2aa6edfa35d1d6774df054130b924866bc360a70`。この4件は基点のHookへ元レビュー入力をDATAとして与えたときの不足である。直前の`93eedd0c`と基点のruntime4ファイルは同一であり、直前のtest/台帳修正が新しく作ったruntimeの穴とは区別する。Hook通過、固定consumerのコード上の成立条件、実hostでの実行・認証・通信成功は別の証拠である。元入力の危険なコマンドをnative実行せず、追加L3も行わない。

| 対象・固定consumer | 守るもの／止める条件 | 通常対照・影響・出口 |
|---|---|---|
| D-Bus 1.14.10 `dbus-run-session` | option値・`--`・PROGRAMを役割別に消費し、実childを既存ガードへ渡す。明示daemon/configや未解決argvはUNKNOWN。外側で選択されたsourceを、内側childのhelpで不活性にしない。 | 既定起動の既知ordinary child、真正query、source起動前の確定した引数エラー、PROGRAM後のoption DATAを区別。明示config/daemonが必要な通常作業もUNKNOWN。同じbus/config・child・cwd/env条件を保てなければownerへ確認する。既定daemonを含む任意binaryの内容を認証するものではない。 |
| OpenSSHの`ssh`互換名`slogin`（Debian bookwormの同名manual、OpenSSH 9.6p1のSSH consumer） | parsed calleeが実際に互換名のときに既存SSHのstdin・remote DATA・metadata・auth/config/identity検査を適用。実name/nameWordを`ssh`へ書換えない。 | `-F none`を含む対応済みordinary操作、真正query、実stdin抑止、印字DATA・既知function overrideを区別。新aliasのactive command-valued helperは選択後にopaque UNKNOWNとし、本文内のFORBIDDENを全て解析したとは主張しない。canonical sshの既存解析は保持。同じhelper/設定/認証・対象を保てない場合はownerへ不足条件を渡す。全SSHの一律禁止やhelper無効化を自動の代替にしない。 |
| Nmap `f06480daed9a9b2cdce61904222cc87788afdf84` のNcat TLS credential consumer | 選択されたcertificate/keyの組、last-value、暗黙のTLS有効化、client/listenerと起動前exitを区別。実際に読み得る未検査の認証file/backendはUNKNOWN。private keyのローカル使用をraw key uploadと同一視しない。 | 真正query、consumerへ到達しない確定条件、無関係reader・ordinary接続を区別。正常なcertificate/keyを使う通信も未検査sourceならUNKNOWN。認証・宛先・操作・cwd/env/sourceを保つ対応済み形式がなければownerへ確認する。独立した秘密stdin/payloadのFORBIDDENは維持する。 |
| iputils 20240117／Apple network_cmds-606.140.1の`ping`・`ping6` | 選択hostnameの元の語と生成元をresolver判定へ渡す。秘密由来が確定した選択値はFORBIDDEN。未知の先頭byte・option/値/operand境界、backend差・未解決生成元はUNKNOWN。`-n`は宛先のforward lookupを免除しない。 | ordinary hostname/IP、共通のcount等のarity、`--`、真正の先頭query、印字DATA・無関係readerを残す。`-h`はAppleで値付きの別操作であり、一般的helpと扱わない。複数operand・operand後option・ping6の`-t/-W`等の版差はUNKNOWNになり得る。同じ対象・mode・source・backendを保てなければownerへ確認し、hostnameのIP置換を自動の同目的代替にしない。 |

固定一次資料は[D-Bus manual](https://dbus.freedesktop.org/doc/dbus-run-session.1.html)と[1.14.10 release](https://dbus.freedesktop.org/releases/dbus/dbus-1.14.10.tar.xz)、[Debian slogin manual](https://manpages.debian.org/bookworm/openssh-client/slogin.1.en.html)、[OpenSSH 9.6p1 consumer](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/ssh.c)、[Ncat main](https://github.com/nmap/nmap/blob/f06480daed9a9b2cdce61904222cc87788afdf84/ncat/ncat_main.c)・[connect](https://github.com/nmap/nmap/blob/f06480daed9a9b2cdce61904222cc87788afdf84/ncat/ncat_connect.c)・[listen](https://github.com/nmap/nmap/blob/f06480daed9a9b2cdce61904222cc87788afdf84/ncat/ncat_listen.c)、[iputils ping](https://github.com/iputils/iputils/blob/20240117/ping/ping.c)、[Apple ping](https://github.com/apple-oss-distributions/network_cmds/blob/network_cmds-606.140.1/ping.tproj/ping.c)・[ping6](https://github.com/apple-oss-distributions/network_cmds/blob/network_cmds-606.140.1/ping6.tproj/ping6.c)に限定する。上流9.6p1が`slogin`を作成することや、実hostに同alias/binaryが存在することは、このmanualの同義性から推定しない。各Hook試験は入力DATAであり、native DNS/TLS/認証・外部送信は未実証のまま残す。

### 公開runnerの台帳binding退行

直前の根拠ID整理で台帳JSONの内容が変わった一方、runner内の固定hashが旧値のまま残り、`require`が`R38_LEDGER_EXACT_JSON_BINDING`で終了した。これは今回の作業で生じた器具の退行であり、4件のruntime不足とは別である。固定hash2箇所を実際の台帳JSONへ合わせ、元8454件の入力・順序・oracleを変えずimportを回復する。required CIへ実runner importの成功と、使い捨てcopyの台帳改変がimport前半で拒否される正負対照を加える。import成功を全件試験成功へ数えない。

全件試験では元8454件の定義を保持し、新しいroleの対照を別IDとして追加する。修復の逆検証は一つの新しい判定または接続だけを外し、無関係なFORBIDDENと正常ALLOWを維持する。固定sourceのL1/L2と、公開headのCI/fresh reviewは別に記録する。過去のL3 FAIL/NOT_EXERCISED・未資格は消さず、追加試行しない。

全件の最初の比較では、起動元から継承された`TERM`により旧・新source双方のTelnet正常対照35件がUNKNOWNとなった（元8454件の旧・新判定差は0、追加132件は全て期待一致）。これは同じ条件の35件を合格へ読み替えず保存する。試験用の基底環境から`TERM`／`DISPLAY`／`PRINTER`を外し、各caseの明示`env`は変更せず後段で適用する。productionで継承sourceを検査する判定は変えない。端末環境による試験の揺れを除いた同一入力・同一fixture条件で、旧・新sourceを再比較する。

<!-- PR191:R39:CONTRACT:END -->

<!-- PR191:R38:CONTRACT:BEGIN -->

<a id="r38-current-contract"></a>

## R38: DNS・Netcat・client認証source・先行cd後pathspecの有限契約

この節は私有最終sourceのローカル受入cut（2026-10-16T10:57:01.166111+09:00 JST）。新公開head・同head CI・fresh両review・実入口は未取得のまま分ける。後続の公開結果はPR本文と監査台帳へ記録し、このcutの履歴へ遡及させない。

基点は公開 `2796fdd0c3a5b0cf807f80fc70ad53c14ade488d`。私有最終runtime sourceのローカル受入が完了した段階であり、新公開head/CI/reviews/実入口の受入を分ける。R38はDNS clientの選択値、Netcat別名とbackend、Wget client認証source、先行cd後のGit pathspecを有限に扱う。ALLOWは対応条件内で当該Hookが拒否しない結果、FORBIDDENは確認したpolicy違反、UNKNOWNは選択source・argv・contextが未検査の結果で、後二者は停止する。 無関係readerの存在だけで送信とせず、選択された値・stdin・設定・認証sourceとそのconsumer条件を調べる。未検査sourceを根拠なく不活性としない。

### 四責務・固定consumer・通常費用・同目的の出口

| 担当／固定根拠 | 選択条件と三結果の範囲 | 通常操作の費用・停止後の出口 |
| --- | --- | --- |
| EG: direct DNS — ISC BIND 9.20.0のdig／host／nslookup／delv | active query/server値の生成元を既存payload判定へ接続。秘密producerが確定すればFORBIDDEN。暗黙`.digrc`、batch/auth key、対話source、未知argvはUNKNOWN。digの`-r`は設定前preparse、消費された`-q -r`のDATAは解除条件でない。先に解決するserverと、後の真正query exitを分ける。auth key読取をraw uploadとはしない。 | ordinaryなqueryやdefault helpでも暗黙設定が未検査ならUNKNOWN。対応済みの真正query／known ordinary値／印字DATA／無関係readerを残す。同じ目的・target・source条件を保つ対応形式が無ければownerへ版・cwd/env/configと不明点を提示する。drill/kdig/resolvectl/getentはこの修復で保護済みとはしていない。 |
| EG: Netcat aliases — Debian netcat-openbsd 1.219-1／OpenBSD 7.6／traditional 1.10-47、Nmap f06480d／Apple 845f93c固定consumerの版差 | `nc.openbsd`／`nc.traditional`を別roleで扱い、実行名を`nc`へ書換えない。`nc`／`netcat`のalternativesに一backendのoption意味を流用しない。確定した秘密stdinはFORBIDDEN、backend/option arity・callee・selected DATAが不明ならUNKNOWN。独立に確定した秘密stdinやlate Git等のFORBIDDENは新UNKNOWNより優先する。旧Apple文法だけの仮定に由来する11件とcanonical `nc -e`のgeneric-deny2件のF→U契約再分類は別であり、その13件を一律F維持とはしない。 | 共通のordinary接続・真正help・対応済みreceive-onlyを残す。正常helperで非選択としたのはこのegress新UNKNOWN edgeであり、Ncatのhexlog等のlocal副作用が消える保証でも、元proxy操作との同等性の保証でもない。backend依存のstdin抑止やproxy等はUNKNOWNとなる費用がある。実binary/backendは名前だけでは認証されない。目的・対象・stdin・backend/版を保てる形式がなければownerへ確認する。 |
| EG: Wget client認証 — GNU Wget 1.25.0のOpenSSL/GnuTLS consumer | 明示certificate/private-keyのlast値と各独立fallbackを扱う。TLS retrievalに達し得る未検査file/format/backendはUNKNOWN。empty-only/type-onlyや真正query／無retrievalは条件付きで不活性。未知scalarもoption名になり得るので、argv role未証明のhelp/type/body-error/last-emptyを不活性証明に使わない。HTTPはredirect0だけではHSTSを除けず、linked retrievalも別に残る。 | 通常のclient認証fileもUNKNOWNとなる。認証素材を使用することと秘密鍵raw bytesのpeer送信を同一視しない。認証selector削除を同等代替とはせず、同じ認証・対象・操作・cwd/env/config/sourceを保てる対応形式が無ければownerへ条件を渡す。 |
| AG: post-cd pathspec — 公開2796の共通Git argv/context解析に結合 | shellの動的PWD展開とGitの静的絶対`-C`を分ける。先行cdと絶対`-C`の組合せでも、動的PWDに加えglob／pathspec magic／optionに見える語／pathspec-file等でrootとの関係を確定できないunsafePathspecはUNKNOWNを最後に返す。独立した旧blanket FORBIDDENの優先を保つ。literal file／静的nested-C／真正help／印字DATAは既存結果を保つ。native Git版・実index変更をこの小componentで認証したとはしない。 | scalarがshellで固定に見えても共通DTOにliteral proofが無ければownAG UNKNOWNになる。aggregateは旧から他Hookが停止する場合もあり、新たな危険成立と混同しない。literalな同一対象を列挙できなければ操作・cwd・sourceと不明点をownerへ確認する。 |

<!-- PR191:R38:NC20-DISPOSITION:RECORDED --> NC旧20件のうちknown-port1の元ALLOWを回復し維持した。残19件は通常A→U8／分類F→U11という局所UNKNOWNの契約改訂で、元generic-denyを満たす別2件にはownEG/prefixを追加した。[版付き期待台帳](../../.claude/hooks/tests/r38-guard-oracle-adjustments.json)は19改訂＋2分類assertを明示し、全beforeDefinition・元入力・非oracle欄・順序を保持する。正常8件の元ALLOWも維持した。新8454全件で原期待との19差分と改訂後0差分を同じactual結果から確認し、旧8204実行の28不一致を成功へ書き換えていない。

<!-- PR191:R38:NC-PORT-REASON:RECORDED --> known-port1の限定許可は、共通nc/netcatでsole z/sole selected x・既知の単一scalar/literal・固定2operands・既存payload違反なしに限る。Nmap commit `f06480daed9a9b2cdce61904222cc87788afdf84` の[ncat_main.c](https://github.com/nmap/nmap/blob/f06480daed9a9b2cdce61904222cc87788afdf84/ncat/ncat_main.c)・[ncat_connect.c](https://github.com/nmap/nmap/blob/f06480daed9a9b2cdce61904222cc87788afdf84/ncat/ncat_connect.c)・[options initializer](https://github.com/nmap/nmap/blob/f06480daed9a9b2cdce61904222cc87788afdf84/ncat/ncat_core.c)、Apple commit `845f93c35a748cf75630eb7d352798accb1ae2f8` の[netcat.c](https://github.com/apple-oss-distributions/netcat/blob/845f93c35a748cf75630eb7d352798accb1ae2f8/netcat.c)・[socks.c](https://github.com/apple-oss-distributions/netcat/blob/845f93c35a748cf75630eb7d352798accb1ae2f8/socks.c)をGit blobまで照合した。解除するのは新egress UNKNOWN edgeだけで、独立stdin/GitのFORBIDDEN、local hexlog副作用、proxy操作との同等性、実binary/backendの認証は別である。

固定根拠は取得済みの[ISC BIND 9.20.0 source](https://raw.githubusercontent.com/isc-projects/bind9/v9.20.0/bin/dig/dig.c)、[GNU Wget 1.25.0 release](https://ftp.gnu.org/gnu/wget/wget-1.25.0.tar.gz)、[Debian nc.openbsd manual](https://manpages.debian.org/bookworm/netcat-openbsd/nc.openbsd.1.en.html)、[OpenBSD 7.6 nc manual](https://man.openbsd.org/OpenBSD-7.6/nc.1)、[traditional 1.10-47 consumer](https://sources.debian.org/src/netcat/1.10-47/netcat.c/)に限定する。取得済みsource/manualの照合と、実hostのbinary/backend・locale・設定・認証・DNS/接続/transport成立は別である。

### 試験と受入を分ける

| gate | 確認するもの | この記録cutのR38状態 |
| --- | --- | --- |
| <!-- PR191:R38:L1-RESULT:RECORDED --> L1 | productionに結合したrole・選択値・argv境界、正常query/DATA、秘密filenameとshell断片 | **PASS scoped** — Node role解析699/699、別のproduction shell parity15/15。identity内18assertはNode test-file1件に含み追加18件としない。旧parity v3のSPEC出力後observer FAIL/child exit未保存は保持し、新v4で明示TAP・status先保存・exit0を取得。全wrapper/Vault/実dispatchの試験ではない。 |
| <!-- PR191:R38:STRICT-RESULT:RECORDED --> L2単一edge | own停止・分類・正常ALLOWを一つのphysical spanだけ外し、同一actual tupleで比較 | **PASS with limits** — 新7edge/31pairs/186 Hook/broken0、source exact undoとowned安定。別の同一v3 identity検証216callsの正常8pairsを再利用し、新186へ加算しない。AG exactはownAG U→Aだが他Hookの停止が残りaggregate必要性は未証明。Wget argvKnownの2 L1は既存source boundaryにmaskされ、Hook単独必要性の証明ではない。旧R37 whole100は再実行していない。 |
| <!-- PR191:R38:FULL-RESULT:RECORDED --> L2全件 | 原入力・各Hook自身/aggregate/理由/broken・原8204定義と21版付き改訂・全owned/source安定 | **PASS scoped** — 8454/8454、failed0/broken0、25362 actual Hook calls。旧8204入力・非oracle欄・順序は不変で、原期待8185一致/19差分と版付き期待8454一致を同じactualから別々に照合。新250中2入力は旧入力と重複し、8454を全unique commandとは呼ばない。normal8＋known-port1は元ALLOWのまま。全sourceとowned Git HEAD/refs/index/objects/files/modes安定。入力commandのnative実行・外部通信・Claude CLI実行は0。owned DUMMY Gitのsetup/readは別である。 |
| <!-- PR191:R38:NEW-HEAD-CI:RECORDED_PENDING --> 新公開head／CI | 最終inventory・runtime/testsを同headへ結合してrequired check取得 | **PENDING**。本cutは私有最終sourceのローカル受入で、新公開head/CIは未取得。旧2796 successを持ち越さない。 |
| <!-- PR191:R38:REVIEWS:RECORDED_PENDING --> 両fresh review／threads | 同headの正常full完了・正式指摘・全thread・outside-diff/失敗/不明の分離 | **PENDING**。10:33:12 JSTの旧公開2796ではCodex3/CodeRabbit1が未解決。修復候補の成功は返信投稿/解決/新review zeroを意味しない。 |
| <!-- PR191:R38:L3:RECORDED_PENDING --> 実project入口 | settings dispatch・実Hook start/finish・own判定・markerと保護state副作用 | **PENDING**。新sourceの実入口は未取得。旧sourceのfirst trial overall FAILと27 NOT_ATTEMPTEDを保持し、直接Hook DATAやAPI前停止を入口成功へ数えない。 |

公開状態の別観測: **2026-10-16 09:45:59.915725 JST（00:45:59.915725 UTC）**には公開2796・186 threads中182 resolved／4 open（CR1/Codex3）と同headのrequired名対応check successを観測した。branch rulesをこの取得で再照合したものではなく、root test件数はnullである。この日時以後の状態や新head結果を推定しない。

実入口の既存記録では、公開2796に結合した新器具generation2の最初の1試行は3Hook ALLOWだったが、extra unexpected Git markerにより全体は **FAIL_UNQUALIFIED_ENTRY**、残27は **NOT_ATTEMPTED**。当該失敗の正確なGit argv/callerは未記録で不明、provider request件数／費用も不明である。この「最初」は当該器具generationの範囲であり、PR全履歴には別sourceの実入口記録がある。旧記録を消さず、R38の新実入口成功へも読み替えない。

Node 24.22を明示する検証と旧24.13／CI24.21の測定は区別する。Node 26はowner判断で11月以降の別作業とし、engine／CIを変更しない。settingsは不変で、Bash全体のEGと条件付きSG/AGを区別する。quoted Git aliasのownAG単独結果は実dispatch保証ではない。93への依頼は終了し、mergeは行わない。

修復の有限受入、nativeでの認証／通信成立、PR全体Goalは別条件である。旧入力・原oracle・raw FAIL、私有prototypeの危険ALLOW／正常overdeny／分類退行、器具と新prospectiveの誤りを別監査台帳へ残す。ローカル受入が成功しても、新公開head/CI/fresh両review/実入口が未取得のこのcutではGoal完了・ZIP作成を主張しない。

<!-- PR191:R38:FIXED-LOCAL-SOURCE:BEGIN -->
このローカル受入のruntime SHA256は、EG `370b66e27bdbb3f84655f95fa6c20830d0d37fc40ea5518071f0c904ba8c6227`、common `a13d591bf498973cc6305aec6ccce86ea6f8abfa3020928f13dd7633592a7fcf`、SG `273f6be441ba85cb295303b929a8427e2a88e5f883800f9cd1d0f51f875c9664`、AG `c8873c1391f6eaccc9496d919647bd0b2c8c2e2d7900ac7038d79e23b813a565`。settingsは不変。root test初回はtsxのローカルIPC作成がsandboxでEPERMとなりtest本体未到達だったため、原FAILを保持し、必要権限の別実行で602/602・exit0を取得した。
<!-- PR191:R38:FIXED-LOCAL-SOURCE:END -->

以下のR37以前の本文・数値・「current／現在」は、それぞれのsourceと取得日時に結合した履歴である。旧本文と順序を保持し、R38の新sourceでの測定結果へ読み替えない。

<!-- PR191:R38:CONTRACT:END -->

<!-- PR191:R37:CONTRACT:BEGIN -->
<a id="r37-current-contract"></a>
## R37: 選択された実行source・設定・認証・resolverの有限契約（固定sourceのローカル受入cut）

このR37節は公開基点 `7b3436bc49f8736c7b465de026a2510ae0e6b0cf` からの固定sourceを合成したローカル受入cutである。部品の閉鎖だけで受入せず、同じ合成sourceで再検証した。公開head/CI/fresh review/実入口は公開後の別取得gateとして下に残す。旧日時付き節の成功数や実dispatchを新sourceへ運ばない。

### 範囲・三結果・通常費用・停止後の出口

結果は上のALLOW/FORBIDDEN/UNKNOWN契約と同じである。ALLOWはこのguardから停止を要求しないこと、FORBIDDENは確認したpolicy違反、UNKNOWNは必要情報不足である。FORBIDDEN/UNKNOWNはいずれもdenyだが、理由prefixと各hook自身の結果を区別する。別guardが止めたaggregateの緑だけで担当guardの欠落や退行を閉じない。

| 担当・固定版/選択条件 | 対応と停止 | 正常対照・通常作業への費用 | 同じ目的を保つ出口 |
|---|---|---|---|
| command-scope Git設定（共通metadata/add-all、Git2.54.0の設定選択） | 選択された非空のopaque PARAMETERSや未確定numbered設定を、対応するhook維持operationでUNKNOWNにする。確定core.hooksPath違反のFORBIDDENを先行させる。値の本文を証明できないだけで全Git configを一律禁止しない | known-empty、COUNT0、未使用KEY/VALUE、非export DATA、actual unset、実query/getter/未選択operationを新edgeの正常対照にする。serializedなordinary設定でも内容/選択が未検査なら停止し得る | 同じ有効設定とoperationを保つ対応形式があれば再検査する。設定を消して目的を変えることは自動代替にせず、設定source/優先順位/argvと不明点をownerへ示す |
| flockと有限util-linux2.39.3 consumer（common/egress） | lock/option値の後のdirect childを既存判定へ渡す。lock後に選ばれるshell command、unknown argv、setarch/runuser/suのactiveなidentity/environment/contextはUNKNOWN。独立した確定FORBIDDENは維持 | ordinary direct child、既知有限scalar、真のhelp/version、pinned consumerでchild非選択の対照を維持。必要なshell/lock/PAM/personality操作も止まり得る。exact setarch install aliasesは同consumerのキーで、独立family数や全wrapper網羅を主張しない | lock/identity/contextを除去せず、同じ条件の対応argvまたはowner確認へ進む。installed binary/symlink、権限、lock取得、PAM、native成功は別確認 |
| 認識clientとutil-linux queryの実program（egress/common） | GET/queryでも不確定なPATH lookup/custom program/先行contextならUNKNOWN。wrapperProgramWordsの実programとargv0を分け、nonExecのquery carrierもcollectorから捨てない | known default program、既存解析済みの通常名local functionと印字DATA、PATHだけが不明で実programが明示system absoluteの限定対照を維持。他のcwd/env/source不明までは解除しない。必要なcustom helperのhelpでも停止し得る | program/版/対象/operation/cwd/env/config/sourceを保つ対応形かowner確認。system absoluteという綴りは実binary/backendのattestationではない |
| 明示curl認証source（egress、tool/libcurl8.7.1、backend条件付き） | cert/key/proxy-cert/proxy-key、選択pubkey/auto-client-certをactive operation/last/next/proxy条件で評価する。未検査のfile/engine/store/backendはUNKNOWN。既存の確定upload FORBIDDENを隠さない。private keyのローカル使用をraw key uploadと呼ばない | cert/proxy-certの既知empty/last-empty clear、認証source非選択のformat-only type、未使用proxy、真のquery、消費DATAを維持。key/pubkeyのblankはnativeの全transfer前parse errorであり、認証成功例ではない。proxy-key emptyはNULL clearと同一ではなく、他の選択cert/autoを解除しない。CA/capath/pinnedpubkeyのpeer検証readをcredential送信へ誤認しない | 必要な認証/proxy/TLSを外すことを自動代替にせず、同じsource/目的に必要なbackend・operation条件をownerへ示す。ordinary cert名でも未検査ならUNKNOWNとなる費用を明記する |
| curlのpositiveTLS別名とengine（egress、同8.7.1） | ftp-ssl/ftp-ssl-reqdをnative flag registryへ登録し、後続の選択engine sourceが解析から消えないようにする。optional/required/control TLSは独立stateとして扱う | engine-looking消費DATA、engine list/実help、engine非選択のordinary操作を維持。negativeTLS toggleは独立engine選択を消す証明ではない | backend/engine sourceの不足はUNKNOWNとしてownerへ渡す。SRPのcanonical/alias生成値は有限対照で既存UNKNOWNに停止しており、追加修復不要というmask記録とactivation completeness未証明を分ける |
| 選択hyphen function source（共通/egress） | 既存二形式のliteral/unquoted headerに限る有限ASCII名を保持する。実callのbody/lifecycleが未検査なら通常printfのbodyでもUNKNOWN。外部clientの確定実行と取り違えず、独立したFORBIDDENを先行させる | 未使用定義と印字DATAは別扱い。旧通常2入力のALLOW→試作FORBIDDEN→採用UNKNOWNは、ALLOW回復ではなく明示した通常制限。任意function文法・全lifecycle・POSIX/Dashの保証ではない | 同じ目的・lookup・source・shell条件を保つ対応形式を再検査するか、body/call/lifecycle/対象/版/backend/cwd/envをownerへ示す。単なる改名やbodyのcopyを自動代替にしない |
| ordinary function-unset（共通/egress、GNU Bash5.3の取得内容に結合した有限map修復） | 実builtinのfunction mode/default fallbackや未確定targetが削除し得る、既存の認識済みmapだけをtyped opaqueにし、後続の選択callをUNKNOWNにする。古い無害な本文を選び続けるALLOWを止める。削除成功を推測せず、全shell/全lifecycleへ広げない | variable-only、no-target、無関係/未使用、解析済みlocal unset function、外部unset、実queryの対照を維持。普通のdefault unsetでも、同名variable/readonly/conditional等で実際に削除されない可能性を解けなければ選択callがUNKNOWNとなる費用がある。evalの既存UNKNOWN maskは別記 | target・variable/functionの目的・shell/backend・定義/import source・lookup・cwd/envを保つ対応形式かowner確認。unset削除、mode変更、古い本文の保持/copyを自動代替にしない |
| OpenSSH9.6p1 keyscanのresolver入力（egress） | 選択addressのfirst whitespace field、累積hostlist、-f stdinを分ける。確定secret filename由来の選択address/hostlistはFORBIDDEN、source/argv不足はUNKNOWN。後続output-only namelistはresolver sinkではない | literal host/IP、known-empty source、真正のusage退出、消費DATA、捨てられた無関係readerを対照にする。ordinary未検査hostlistやbackend依存argvも停止し得る。output選択はresolution無効化の証明ではない | 同じscan host/対象/sourceを保つproofと、版/backend/argv/cwd/envをownerへ渡す。usage退出をnative成功や通信しない全保証へはしない |
| GNUWget1.25.0 selected bind resolver（egress） | bind-addressの有効last hostname sourceをresolverへ結び付け、確定secret生成元はFORBIDDEN、不足はUNKNOWN。bind-dns-addressはHAVE_LIBCARES条件のnumeric-only consumerであり、同じhostname lookupではない | literal local bind、last ordinary選択、query/file/noURL/known-empty input、pre-retrieval invalid-bodyの対照を維持。dynamic/unproved numeric inputはUNKNOWN。既存body/payload判定は独立に残す | 必要なlocal bindと対象operationを保つknown source/版/backend/argv条件かowner確認。bind selectorを消すだけの提案はしない |

hyphenの継承sourceやnongit nested shell sourceはegressの担当範囲も含む。defaultのSG/AGがsource seedを受けずALLOWでも、それを保護済みの証拠にしない。最終settings dispatchと各hookの担当結果をL3で別に結合する。

初期設定の継承は、必要な名前・known-empty/COUNT/KEY等の有限選択metadataとopaque sourceを分ける。実private PARAMETERS/VALUE、認証情報やCLI HOMEを取り出して公開する手順ではない。任意program/暗黙設定/環境全体の安全性はこの表から導かない。

### L1・L2・L3とnative成立の別gate

| 層/条件 | 最終sourceで確認するもの | 状態 |
|---|---|---|
| <!-- PR191:R37:L1-GATE --> L1 | option arity/消費DATA、programとargv0、設定/値の選択、function lifecycleのtyped metadata、本番抽出helperの意味 | **673/673 PASS**（L1解析651＋parity15＋追加本番契約7、固定source前後一致） |
| <!-- PR191:R37:STRICT-GATE --> L2単一edge逆検証 | 自身の停止/分類/正常ALLOWを、修復一つだけを外した同一実tupleで確認。independent mask/UNPROVEDを残し、他guardをまとめて解除しない | 逆検証は同じ合成sourceの100 Hook機能・455比較pair・2670実Hook呼出しを資格化し、別shell1機能は15pair/30test観測（Hook0）として保持した。必要性UNPROVED3機能と元逆期待FAIL5profileを保持し、UNKNOWNの独立maskや追加precisionを成功へ書き換えていない。部品結果のcarryではなく同一合成sourceで再測定。 |
| <!-- PR191:R37:FULL-GATE --> L2全件 | 元witnessの一字不変再投入、ownEG/SG/AG・reason prefix・broken、旧7824の入力/順序/oracle、正常対照と全owned/source安定 | **8204/8204 PASS、broken0、実Hook24612回**。旧7824の定義・順序・全oracle完全維持、追加380unique・alias16全assert、全owned/source安定。 |
| <!-- PR191:R37:HEAD-CI-GATE --> 公開source/requiredCI | 最終manifest/source4/固定public source inventoryを同headへjoinし、required jobの実結果/Node版を取得 | **PENDING** |
| <!-- PR191:R37:REVIEW-GATE --> fresh両review/thread | 同headの正常full review完了・zero findings・未解決thread処理。status成功と内部errorを区別 | **PENDING** |
| <!-- PR191:R37:L3-GATE --> 実project入口 | 元settingsのdispatch/start/finish・own-hook判定、normal markerと停止後のHEAD/refs/index/objects/files等の副作用 | **PENDING**。Hook前API/safeguard停止はNOT_EXERCISED、prepare失敗はHook成功でない |
| nativeの動作成立 | 実backend/版/設定/engine/PAM/権限、resolver/DNS、TLS/認証/transport等の必要条件 | **未検証**。局所修復を受け入れても表示を消さない |

`if: "Bash(git *)"` 付きsecret-git/add-allと全Bash egressの既存登録は維持する。ifをraw prefixだと推測せず、quoted Gitのdirect判定を実dispatchへ移し替えない。L3でstub markerを確認した場合も、native client/DNS/TLS/認証/通信の証明とは分ける。

R37の受入条件は旧7824のinput・順序・oracle変更0である。R36以前のR6P38 ALLOW→UNKNOWNという理由付き履歴は保持し、今回の変更と合算しない。旧headに同じ入力を入れた不足、私有prototypeが作った危険ALLOW/正常過剰拒否、器具/schema/新規prospective誤りを区分し、原FAIL・未完了・maskを監査台帳に残す。公開後gateがPENDINGである限り、ローカル受入や旧全件成功からPRのGoal達成を主張しない。

同目的の対応形式を案内できなければ対象/operation/版/backend/argv/cwd/env/config/sourceと不明点をownerへ示す。個別操作の了承はhook無効化や別経路実行の了承ではない。local Node24.22.0を継続し、Node26は11月以降のowner判断、93依頼は閉鎖、大規模な責務refactorは後続とする。mergeしない。監査台帳を含む最終ZIPは実Goal達成後の別deliverableであり、このローカル受入だけでは作成しない。

固定一次source: [Git2.54.0](https://git-scm.com/docs/git-config/2.54.0)、[util-linux2.39.3](https://github.com/util-linux/util-linux/tree/2da5c904e18fdcffd2b252d641e6f76374c7b406)、[curl8.7.1 consumer](https://github.com/curl/curl/tree/curl-8_7_1)、[OpenSSH9.6p1 keyscan](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/ssh-keyscan.c)、[Wget1.25.0 release](https://ftp.gnu.org/gnu/wget/wget-1.25.0.tar.gz)、[GNU Bash Builtins](https://www.gnu.org/software/bash/manual/html_node/Bourne-Shell-Builtins.html)。ordinary-unsetの根拠は今回取得したGNU Bash5.3/Edition5.3本文の固定hashに結合し、旧取得失敗とは別にする。hyphen構文の既存Bash3.2 DUMMY観測や、installed binary/異版/backendの未確認を全shellの保証へ広げない。

**以下のR36以前は旧cutの履歴である。古い本文・anchor名の「current／現在／現行」は当時のsource/日時を指し、R37の現在結果や導線の優先順位ではない。歴史本文は書き換えず保持する。**


固定ローカルcut（UTC）: 2026-10-15T22:34:05.996284+00:00。公開source inventoryは旧17＋追加本番契約test2＝19を別途同headへ結合する。旧7824との集計比較は別fixtureであり、同一実tupleの因果比較と混同しない。
<!-- PR191:R37:CONTRACT:END -->

<!-- PR191:R36:CONTRACT:BEGIN -->
<a id="r36-current-contract"></a>

## R36: child 選択・設定 source・送信入力・template 例外の適用範囲

この節は公開親 `f1e6c7ef8843528e741541d3d06c6d59e1bc91ad` に対する有限修復の契約である。固定統合 source の全件検証、新 head の CI・fresh review、必要な実入口の合格は、取得した receipt とともに別に記録する。以前の成功数を新しい source の成功として持ち越さない。R35 以下は当時の source と日時に結合した履歴である。

| 守るもの・担当 | 対応条件と結果 | 判断できない条件・通常作業への影響 | 同じ目的を保つ出口・対照 |
|---|---|---|---|
| wrapper の実 child（common と egress） | util-linux 2.39.3（固定 commit `2da5c904e18fdcffd2b252d641e6f76374c7b406`）の `chrt`、`nsenter`、`taskset` で、実 option・消費値・query・child を区別する。確認できた child は既存の payload/source 判定へ渡す | active な未対応 namespace・root・cwd・env 等の context、未確定 argv、implicit shell は UNKNOWN。未確定 taskset mask が option と operand の境界を変え得る場合も UNKNOWN。旧正常対照 R6P38 は input を変えず ALLOW→UNKNOWN とする明示的な制限であり、旧期待を保存した別 ledger に理由を残す。selector の存在だけを child 不在の証拠にしない。後続 query より前に source を開く処理と、query が先に終了して使わない deferred context を分ける | 通常 child と真の query は対応条件で維持する。必要な selector を削除して目的を変える書換えは自動代替にしない。不足する backend・版・argv・context を owner へ渡す |
| OpenSSL の選択された設定と送信入力（egress） | OpenSSL 3.5.0／LibreSSL 4.0.0 の設定読込を subcommand/query 判定より先の source として扱う。対応 `s_client` の stdin は既存 provenance に結び付け、確定した秘密 filename 由来 payload は FORBIDDEN | default／明示 config、engine/provider、未対応 active mode、stdin／argv／source が未証明なら UNKNOWN。通常の `version`、help、`dgst` も config が未確認なら停止し得る | 選択された `OPENSSL_CONF=/dev/null` が必要な config/provider を失わず同じ目的を保つ場合に限り、対応 query/local mode の対照に使う。設定依存の暗号処理では自動代替にしない。認証用 key/cert は未検査 source とし、raw upload と誤認せず stdin と分ける。明示 early_data の既知 file-backed upload は通常 filename も既存 upload policy に従い FORBIDDEN、path/argv 不明は UNKNOWN |
| 保護対象 path の template 例外（共通 JS と Vault shell） | final basename の `.env.example` だけを `.env` filename 規則の例外にする。残る ancestor は従来の filename 規則で判定し、`secrets/.env.example` や `.env.local/.env.example` の保護を維持する | file 内容を安全と認証する規則ではない。NUL record の読取失敗・不完全 record・LF filename は従来どおり UNKNOWN、何も unstage しない | root と通常 directory の template は許可対照。秘密 directory が必要な対象を別場所へ写すことを自動代替にしない。対象 path と stage 操作を owner に確認する |
| committed hook の維持（add-all） | `git am -n` と bundle 中の実 `n` を `--no-verify` として FORBIDDEN にする。`-C`／`-p` の必須 DATA、`-S` の optional attached DATA、実 `--` 以後の operand と区別する | 空になり得る attached 必須値が次の option を消費する境界は am 限定で UNKNOWN。通常 am の mail/state 等に関する別の egress UNKNOWN は解除しない | hook を維持して同じ am を行う。push/merge/rebase/revert の別の意味の `-n` は新しく禁止しない。未確定値は同じ対象・目的の確定 argv にできる場合だけ再検査する |

`taskset` は PID 指定でも 0 と child が選ばれる分岐があり、`chrt` の PID selector とともに consumer の条件で判定する。`ionice` と `setsid` も同じ固定 util-linux source の有限隣接表で確認し、それぞれの selector/query の意味を保つ。名前が似た wrapper 全体や全 Git option の網羅を証明したとはしない。Mac 上で利用できない native launcher の権限・affinity・namespace 成立も、Hook DATA の停止から推定しない。

OpenSSL は argc なしの bare help と global query alias も、通常 argv0・既知 empty config などの条件を満たす場合だけ対照にする。`help CMD` は official main が対象 mode へ委譲するため、その実 role で解析し、未対応 target は UNKNOWN。multicall argv0 が subcommand より先に処理されるため、非標準／未確定 argv0 を後続の version/help だけで許可しない。global query の後続 argv が application に使われなくても、外側 shell の substitution を無視する理由にはしない。

OpenSSL の既知の active sibling は `s_server`、`s_time`、`ocsp`、`cmp` に限定して source 不足を明示する。各 mode の実通信や server side を認証するものではない。設定が必要な通常処理も止まり得る費用を明示し、query 名や consumed DATA の help という綴りを config/source 無効化の証拠にしない。無関係の reader から静的 stdin/EOF へ誤った provenance を作らない。

template の例外は filename 規則の union 全体を解除しない。JS と production shell の実 helper/filter を同じ filename 集合で照合し、shell の producer/status/NUL/LF/restore 契約を保持する。shell reader の試験は owned DUMMY fixture と抽出した本番関数の試験であり、本番 Vault・全 wrapper・push の成功ではない。

`git am -n` は Git の `pre-applypatch` と `applypatch-msg` を省くが、`post-applypatch` は省かない。自身の add-all 判定と、別の egress が既に UNKNOWN で停止する aggregate 結果を分ける。新 edge を単独で外して自身の停止が失われても、独立した guard が残って全体 deny のままなら、その mask をそのまま記録する。

### 入口と受入の区別

settings は全 Bash egress と `if: "Bash(git *)"` 付き secret-git/add-all のままである。現在の Claude Code 公式資料は `if` を subcommand 等を確認する best-effort 条件として説明し、判定不能時に Hook を起動する場合も示す。単純な raw prefix とはみなさず、引用を結合した Git の direct Hook 結果を実 dispatch の成功／省略のどちらにも読み替えない。固定 CLI の exact command と各 Hook の start/finish を実入口で別に取得する。API／safeguard による Hook 前の停止は NOT_EXERCISED である。

受入は、元入力の再投入、正常対照、同一入力の旧版比較、新機能一つずつを外す逆検証、新全件試験、同 head の required CI・fresh 両 review と thread 処理、必要な実入口を分けて確認する。旧7459の順序・入力・元定義は保持する。未確定 mask が option を選び得るため旧 ALLOW を UNKNOWN に改める場合は、変更した oracle・公式 consumer・理由・通常制限を個別に記録し、「旧 oracle 全件不変」とは記載しない。実秘密の読取、DNS／TLS／認証／transport／被害の成立を主張しない。実通信を確認していない表示は、局所修復を受け入れた後も残す。merge は行わない。

一次 source: [util-linux v2.39.3](https://github.com/util-linux/util-linux/tree/2da5c904e18fdcffd2b252d641e6f76374c7b406)、[OpenSSL 3.5.0](https://github.com/openssl/openssl/tree/openssl-3.5.0)、[LibreSSL 4.0.0](https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.0.0.tar.gz)、[Git am v2.54.0](https://git-scm.com/docs/git-am/2.54.0)、[Claude Code Hook 条件](https://code.claude.com/docs/en/hooks#how-if-patterns-match-bash-commands)。取得した版・consumer・hash・正常対照・終了条件は有限監査台帳へ結合し、live docs の説明を固定 CLI の実測と取り違えない。


### 固定sourceの取得cutと受入gate

文書cut: **2026-10-16T05:34:54.883582+09:00**。公開親は `f1e6c7ef8843528e741541d3d06c6d59e1bc91ad`。固定統合sourceは manifest SHA256 `98224bf12725424044bd1cb3d4ba0d18092241f48f700419c57de59e3c09d3bf`、egress `f37e6b157cfb…` / common `500f791f5360…` / secret-git `273f6be441ba…` / add-all `5b5cce55a0d5…` に結合する。この節は公開前のローカル受入cutであり、以下のPENDINGを公開後の現在状態へ読み替えない。

| gate | この固定sourceで取得した結果 | 限界・次の閉鎖条件 |
|---|---|---|
| L1解析＋本番抽出filename parity | **601/601 PASS**＝analysis586＋parity15、fail0、SPEC reporter、Node24.22.0。receipt `7ce75db57321…` | L2全件・実dispatch・native backend成立とは別 |
| 現sourceの単一edge逆検証 | **59機能＝Hook58＋shell1**。L2 **239pairs / 458 actual observations / 1374 actual Hook入力、failed0/broken0**。current資格summary `4fa351e6486…` / 詳細 `d32a8fca988…` | own-hook停止必要性33＝EG30/AG2/SG1、aggregate29、allowance precision13、classification precision10。curl **2 featuresはUNPROVED**、別にutil2＋元parallel1の**3 masked profiles**を保持。機能数を脆弱性数へ数えない |
| reverseの数え方と状態 | amは10基準観測を3mutantで共有し、30pairsに対するactualは40観測/120Hook入力。新helpは15pairs中2件で正常ALLOWを失い、残13は同じ。shellは15-test readerを2batchで測り、current15pass／callsiteだけを外すと14pass＋意図した1fail、Hook0 | 各L2 pairの実input/env/cwd/project/executable/Hook path、single span、他source、byte/mode undoとowned状態を確認。shellの各test用一時fixture名は異なり、wrapper全体や本番Vaultではない。R23GA11 triple・cross9・診断・元witnessの別確認はstrictへ加算しない |
| <!-- PR191:R36:FULL-GATE --> L2全件 | **新しく全7824/7824を実行してPASS**、failed0/broken0、23472 actual Hook入力。2026-10-16T05:28:47.371000+09:00終了。root資格 `cc099a8a813c…`、raw `ad4711135299…` | 旧7827のprojectionではない。旧7459の順序・input/non-oracle fieldsを保持＋新unique365、alias2は別assertion。元R6P38 ALLOWだけを理由付きledgerでUNKNOWNへ変更するため、旧oracle全件不変とは言わない。R23GA10の元ALLOWは保持。source/runner/definitions・whole-owned Git/files/modes stable |
| <!-- PR191:R36:HEAD-CI-GATE --> 新公開head／required CI | **PENDING（この公開前cut時点）** | 同一新headの実CIと実Node版を別に取得し、親f1の成功を持ち越さない |
| <!-- PR191:R36:REVIEW-GATE --> fresh両review・thread | **PENDING（この公開前cut時点）** | 正常full review完了・zero findings・thread処理を別確認。CodeRabbitのstatus successだけでinternal errorをzeroにしない |
| <!-- PR191:R36:L3-GATE --> 必要な実project入口 | **PENDING（この公開前cut時点）** | dispatch/start/finish・判定・owned副作用を別確認。Hook前のAPI/safeguard停止はNOT_EXERCISED。prepare失敗をHook成功にしない |

公開後の同一headの受入状態は [PR #191本文](https://github.com/theosera/obsidian-ai-pipeline/pull/191) と当該headに結合した監査receiptで更新する。この日時付きローカルcutを、その後のCI・レビューの状態更新だけで書き換えることは要しない。strict/解析/Hook DATAの合格から、実秘密・DNS/TLS/認証/transport/実外部通信/被害の成立を推定しない。local Node24.22.0を継続し、Node26は2026年11月以降のowner判断、93依頼終了、広い責務refactorは後続とする。Goalと最終ZIPは別条件で、mergeは行わない。

### 原FAIL・退行・誤前提を後段に残す

最初の旧固定source全7827は **4 FAIL・broken0・23481Hook入力** で終端し、raw `8681024400bf…` / root `589d481ba49a…` を受入に使わず保存した（2026-10-16 05:07:42.784 JST終了）。そのうち **R23GA10 `git am -h` は本修復で作った正常過剰拒否**である。旧ALLOWEDだったqueryのroleにflagsが無いところを参照し、捕捉されたTypeErrorがown-AG UNKNOWNになった。同じ原因はR23GA11のlong helpでもown-AGを余計に止めたが、既存own-EG UNKNOWNがaggregateを既に止めていたため全件FAILには現れなかった。AGの `flags?.includes` への**1文字の精度修復**で、元R23GA10 ALLOWを変更せず回復した。R23GA11もown-AG ALLOWへ回復し、既存own-EG UNKNOWNは保持した。aggregateの緑だけで各Hookの退行を見落とさず、option/query roleと独立guardのmaskを分ける教訓として残す。

残る新規cross R36INT08/09/10は、元12定義/oracleと9matched/3unmatched rawを保持して採用cross9の外へ分けた。INT08/10で期待したown-SG FORBIDDENは既存readOnlyInvocation beforeCommitのUNKNOWNにmaskedだった。INT09も **own-SGのbeforeCommit／先行OpenSSLのUNKNOWN**により新ALLOW期待が不成立で、**own-EGはALLOW**だった。これらを成功値へ書き換えて合格にはせず、独立template31のown-SG F／通常A対照と区別する。旧7827からの受入subset化案は、正常退行が残った時点で未使用STOPとし、修復したv4の全7824を新規実行した。

util-linuxの通常対照はliteral/有限scalarのpriority・mask・option値と通常child、真のqueryを含む。inline値は**同じ語**の既知literalValueのsubstringだけを引き継ぎ、元raw/start/dynamic/provenanceを保持する。未知値やgenerated childへproofを転用しない。私有v2のdeferred nsenter query過剰U3件、v4の既知taskset scalar mask過剰U1件、v5のinline option proof消失による過剰U11件は修復し、原FAILと同一tuple比較を保持した。最後の11件は公開f1 A→私有v5 U→私有v6 Aであり、公開された新しい退行としては数えない。

OpenSSL試作で見つかったglobal query alias／argc0の過剰UNKNOWN、early-dataの分類精度修復も旧sourceの失敗として保存した。currentのOpenSSL逆検証ではobserver全体のinitial/end snapshotを実際に測定して一致を確認したが、旧v2/v3 observerにinitial full snapshotが無かった履歴へ遡及して成功を足さない。新規oracle誤前提、collector/metadata shape/静的出力打切り等の器具事故はruntime退行と分け、監査台帳に原記録を残す。

<!-- PR191:R36:CONTRACT:END -->

<!-- PR191:R35:CONTRACT:BEGIN -->
<a id="r35-current-contract"></a>

## R35: backend・選択された resolver / gateway source の契約

本節は **2026-10-16T03:00:31.624+09:00 JST** の固定source文書cut（rootの全件終端receipt取得後）。公開親は `a09c7c585f186321cfc7aaed05588e99e96efb16`。固定統合sourceは egress `827c4b928ec690f16650cef153c9e5850c2efc6608f69a6bbcbd2316fb75f1ce` / common `6a09eabf30a596495ed05921a2256d499e655c322cd9429890c738160591187d`、secret-git/add-allは親と同一。最終runtime descriptor `9a62a693…` に結合した文書案であり、新headの公開やCIの合格を主張しない。

**全7459/7459件のL2検証PASS、failed0・broken0**。終了は **2026-10-16 02:57:36.522 JST**（UTC `2026-10-15T17:57:36.522Z`）、22377 actual Hook入力・typed ownEG期待1485件。local Node24.22.0 / ABI137で、固定runtime・runner・definitionsと全owned Git/files/modes不変を確認した。旧7272の全定義・順序・fields/input tuple/oracleを保持し、parallel74＋curl103＋cross10のunique187を追加、alias0・oracle緩和0。新head・requiredCI・fresh Codex/CodeRabbit・thread処理・必要L3は **PENDING**。このL2合格を実settings dispatchやnativeの成功へ昇格しない。

ALLOW / FORBIDDEN / UNKNOWN と既存 deny wire を維持する。確認された禁止操作・送信値は FORBIDDEN、必要な backend / 設定 / source / argv が不足すれば UNKNOWN。後者を「実際の漏えいを確認した」と記録しない。新しい不明 source により、別に確定した既存 FORBIDDEN を UNKNOWN へ落とさない。

### 対応範囲・正常対照・閉じる条件

| 対象・固定一次資料 | 修復と判定 | 正常操作の対照・期待 | 通常作業への影響と出口 | 修復の受入 / native 成立の境界 |
|---|---|---|---|---|
| 外部 `parallel`。moreutils 0.70-1 の C / manual と GNU Parallel 20260422 の公式 manual。基底 a09 | 同じ basename が、moreutils の prefix＋job argv と GNU の stdin job / shell template / 暗黙設定を選び得る。選択 backend・設定・source を確定できない外部呼出しは局所 UNKNOWN。引用を戻した名前にも適用し、語の文字列一致だけでは止めない | 印字 DATA、実際の同名ローカル関数との区別を保持。外部 parallel の ordinary job・help・no-job も、両 backend の source 非選択を証明できなければ UNKNOWN。別の独立した禁止操作は FORBIDDEN のまま | 通常の並列処理も止まる。並列性・job・argv・cwd/env を失う直列実行や flag 削除を、同目的の自動代替としない。必要な executable / backend / 版・選択設定・入力・目的を owner へ確認する。`--plain` は将来の候補で、今回の未検証の例外にはしない | 元レビューと GNU stdin の二入力を own-egress が停止し、関数 / DATA と独立 F の対照を保つ。新 edge を一つだけ外す比較を取得する。GNU の全機能・実設置 binary・実 child / transport を認証したとはしない |
| curl interface resolver。curl 8.7.1 `tool_getparam` / `setopt` / `bindlocal` の固定 source。基底 a09 | operation ごとの最後の interface を保持。固定 scalar `if!` は hostname fallback の無い local-interface role、`host!` は forced-host resolver role。後者の対応済みreaderとliteral secret filenameが確定すれば FORBIDDEN。bare interface の選択、未確定filename/producer/argv/contextは UNKNOWN。`ifhost!` は8.9.0で別途調べた互換境界であり、この8.7.1契約では UNKNOWN。後発のlong `=` selector grammarも認証しない | 既知 ordinary・実 query・非選択値・固定 local interface・実 Unix socket の対照を保持。引用された値と、語数を変え得る未引用値を区別する。外側の読取や redirection は別に評価する | 必要な interface / route を削除して別接続へ変えることを自動代替にしない。同じ目的・mode・route・argv・cwd/env を保つ対応済み形式が無ければ、不明点を owner へ | exact original own-egress 停止と last / inactive / scalar 対照、単独 edge の比較を取得する。停止の確認と、OS / resolver / DNS label / socket / 権限 / 実接続の成立を分ける |
| curl IPFS / IPNS gateway。curl 8.7.1 `tool_ipfs` / URLAPI / proxy consumer の固定 source。基底 a09 | active IPFS/IPNS operation だけ CLI → 非空環境値 → IPFS_PATH / HOME の file source を選ぶ。生成された whole URL を、そのまま送信成分の証明にしない。実際に残る scheme / host / port / path と、捨てられる userinfo / fragment を分ける。未検査 file・成分・backend は UNKNOWN | HTTP(S) の既知 ordinary gateway、actual unset / empty fallback / last / next reset、非IPFS / query / early error を対照にする。gateway query はnative parse error、userinfo / fragment は捨てられる。IPFS/IPNS の1〜3 slash有効URLと4 slash / CID無しのearly errorを区別する。scheme省略の ftp/dict/ldap/imap/smtp/pop3 prefix は非HTTP handlerを選ぶため UNKNOWN。rewrite後のprotocol/hostが選ぶproxy contextも評価する | 必要な gateway / file / backend を削除して別経路へ変えることを自動代替にしない。対象・protocol・gateway の選択元・cwd/env / config・目的を owner へ。実 file の本文は検証目的で読まない | exact original own-egress 停止と、選択 / 非選択・proxy・normal 対照、単独 edge 比較を取得する。file 存在・実装 build・認証 / transport・実送信は別の未確認欄に残す |

元レビュー3入力は、現統合sourceで own-egress **UNKNOWN / UNKNOWN / UNKNOWN** に停止する。停止は実通信の成立証拠ではない。比較元では、同じ owned fixture / serialized input / env / cwd / project / Hook executable path で初期 `df463a91`、旧 `03fdb5c`、公開親 `a09c7c5` の3本すべてが ALLOW だった。着手前からの不足という比較であり、実秘密の読取・実外部通信・被害発生の確認ではない。元入力を native 実行していない。

### このcutで閉鎖した有限証拠

| 層・固定統合sourceでの測定 | 現在の結果 | 持ち越さないもの |
|---|---|---|
| L1解析＋filename parity | **518/518 PASS**＝analysis506＋parity12、fail0。actual reporterはSPEC。初回TAP想定collectorのFAILと、raw成功出力をSPECとして再集計した訂正を保持する（receipt `c7b2d8e1…`） | component別の旧source成功数や、collectorの失敗を製品failへ読み替えない。L2全件やL3の証拠でもない |
| 統合source・新edge単独reverse | **30 features / 96 pairs / 576 Hook入力、期待差0・broken0**。curl23/74/444（`ab5d7bf9…`）＋parallel7/22/132（`d225ca0c…`）。各pairで実input/env/cwd/project/executable/Hook pathを揃え、変更は新edgeの1spanだけ、他3sourceと全owned Git/files/modesは不変 | 機能数を脆弱性数へ数えない。複数guardをまとめて外した旧器具の結果を新edge単独の証明にしない |
| reverseの資格 | ownEG sole-stop必要性13 features、allowance precision7、classification precision8、必要性UNPROVEDのcurl **2 features**。さらにparallelの**元入力1 profile**はlate fallbackを外しても既存network-context UNKNOWNが残りmasked | parallelの同じfallback featureは別ordinary witnessでownEG UNKNOWN→ALLOWを確認済み。そのfeatureの資格と、元入力1 profileのUNPROVEDを同じ件数へ合算しない。SG/AGが停止するためfallbackのaggregate ALLOWも主張しない |
| 複合cross対照 | a09／現統合の同一owned条件で**10件・60 Hook入力、事前期待どおり・broken0・stable**。現ownEG ALLOW5／UNKNOWN3／FORBIDDEN2（`99129ba7…`） | 新しいcandidateや期待を後から作り替えて合格にしていない。native child / DNS / transport / 認証 / 被害は未測定 |
| L2全件 | **7459/7459 PASS、failed0・broken0、22377 Hook入力、typed ownEG1485**。旧7272の全定義・順序・ID・command/stdin/cwd/project/env・oracleを保持、187 unique追加・alias0。旧7272カテゴリ差0、旧6450 input fields exact。固定source/runner/definitions・全owned Git/files/modes stable（root資格receipt `6c868f26…`） | 新headCI/fresh/thread/L3はPENDING。旧7272比較は別owned fixture/env/cwd serializationによる同定義比較であり、同一実tupleの因果対照とは呼ばない |

固定sourceの全件資格receiptは `6c868f26f89a71e4522511838097d9626251014e77d22deb4707a2ca46ecc34e`。元3入力はUTF-8で一字も変えず、own-egressがUNKNOWN / UNKNOWN / UNKNOWN（`[判断不能] `）に停止した。raw full出力は18718402 bytes / SHA256 `a83834363c61c0fa3d72c63b237bf79e088053e02f7175613faa643ce6a7fd1c` と結合しており、本文へ巨大入力や全ログを転載しない。旧7272との差0は同定義の別owned fixture比較、先のexact原入力比較・cross10・reverseは各pair内の同一実tuple測定で、証拠の役割を分ける。

逆検証の現root資格は `0d2b391852f489268698c1de15d38dd9cedaca082b33297fd43c6921113b4518`。curl2 featuresの必要性未証明と、別ordinaryでfeatureのownEG必要性を確認済みでも元入力だけmaskedのparallel1 profileを明示するためのmetadata訂正版であり、新実行・count/source変更は無い。strict receipt取得時の全件RUNNING表記はその時点の記録で、現在の全件結果は上の別終端receiptへ結合する。

curlの必要性UNPROVEDはgateway whole-URL成分edgeとinterface scalar/local-only境界edgeで、単独edgeを外しても既存UNKNOWNが残った2 features。分類精度ではforced-host F→U、独立F優先 F→U、未引用の別値からのfalse Fを防ぐ U→F比較を別資格で残す。parallelはregistryのaggregate必要性1 feature、fallbackのownEG必要性1 feature、独立FORBIDDENを守る伝播5 featuresの分類精度である。

`-q` は実際の先頭でcurlrcを止めるが、IPFS/IPNSの暗黙gatewayを無効化しない。空のCLI gatewayはparse error、空の環境値は次のfallbackへ進む。未検査のordinary gateway fileもUNKNOWNとなる。Unix socket / file URL / 実query / URL無し等でこのresolver routeがinactiveな場合でも、別の既存config/payload/stdin/source判定は残る。outer reader/redirectionを同時に未実行とみなさない。

### 試作と採用判断を残す

moreutils だけを分類した私有 v3 は、元の入力を止めたが、GNU の stdin job 二経路を止められなかった。旧 a09 も同じ入力を許可しており、公開した新しい退行とは数えない。独立 QA と公式資料を根拠に、この候補の受入を取り下げ、backend / source 不足の局所 UNKNOWN に置き換えた。旧 v3 の成功・失敗・逆検証を最終 source の証拠へ持ち越さない。広がった通常作業の停止と、新規 prospective 期待の変更は明示して残し、公開親7272入力の期待を都合よく書き換えない。

curl の試作では、未確定 filename 由来の読取を確定 F と見なした新規期待、unquoted glob の query 対照、DTO の NUL 表現、IPFS の alternate slash、scheme guessing、scalar 境界と分類優先順位の不足を別に記録する。器具・新規期待の誤り、未完了の修復、実装で作った退行を同じ件数に合算しない。

### 保証と gate

L1解析、Hookへ渡すDATAのL2、実Claude project settingsのL3、nativeのbackend / 認証 / 通信 / 副作用は別gate。必要な全件・解析・単一edge逆検証は最終固定sourceで取得する。同一新headのrequiredCI、fresh Codex / CodeRabbitの正常完了とzero findings、全thread処理、必要な実入口検証は別途必要である。CodeRabbit の internal error / Review failed をsuccess statusだけでzeroへ数えない。

設定は全Bash egressと既存conditional secret-git / add-allを維持する。ユーザー了承の範囲で局所UNKNOWNを拡張し、止まる通常作業とowner出口をREADME／本節へ明記した。local Node24.22.0を用い、Node26導入は2026年11月以降のowner判断のまま。93への依頼は終了、広い責務リファクタリングは後続、mergeしない。以下のR34以前は当時の取得時刻とsourceを保った履歴である。
<!-- PR191:R35:CONTRACT:END -->

<!-- PR191:R34:CONTRACT:BEGIN -->
<a id="r34-current-contract"></a>

## R34: child・実行source・DNS・認証/環境値の有限契約（公開前・ローカル受入済み）

本節は **2026-10-16T01:32:55.539+09:00 JST** の文書準備cut。公開親は `03fdb5cd6ce537f916648c5db581d2910ecc67b9`、親runtimeは common `487353ab…` / egress `fe3d75e5…` / secret-git `273f6be4…` / add-all `7bb176f3…`。R34の固定統合私有runtimeは egress `c7991eae4c1bc428152005399b90e1a0520b70fac4ca702a2f47893ac7c28352` / common `35e676b42d3efc75ac9ebcc2a451d49ca750212354668a5f516247d48d4dbb19`、secret-git/add-allは親と同一。L1は479/479 PASS、統合単独reverseは33機能137pairs/822Hook入力で閉鎖済みです。**全件7272/7272 PASS**（21816 actual Hook入力、broken0、typed EG期待1298件）を固定統合sourceで取得し、source/runner/definitionsとowned HEAD/refs/index/objects/files/modesの不変を確認しました。公開head/CI/fresh/thread/L3は **PENDING**。L2の合格を実settings dispatchやnativeの成立へ持ち越しません。R33以下のmarker/body/dated記録は全文byte保持した履歴で、旧成功・当時のPENDINGを現在へ読み替えません。

### 対応範囲・結果・停止後の出口

ALLOWは対応条件内でそのguardが停止を要求しない結果、FORBIDDENは既存policyに当たる確定した形式、UNKNOWNは選択されたsource・argv・値の生成元・contextが不足する結果です。後二者は既存deny wireと`[禁止] `/`[判断不能] `で分けます。確定した送信/操作の禁止を新source UNKNOWNで覆いません。一部のguardのALLOWは他guardのALLOW、owner承認、whole commandの安全認証を意味しません。

settingsは変更しません。egressは全Bash、secret-git/add-allは既存`if: "Bash(git *)"`です。HookへcommandをJSON DATAとして渡すL2、実Claude project settingsのdispatch、公式consumerの選択、nativeのfile存在・build/OS・DNS・接続・認証・権限/副作用を別欄に残します。元レビューの危険な入力をnative実行する試験は行いません。

| 守るrole・固定tool/backendとguard親 | 条件／判定・未検査事項 | 正常対照と期待結果 | 止まる通常作業／同目的代替とowner出口 | 現在の受入状態・native成立条件 |
| --- | --- | --- | --- | --- |
| watchのchild argv／既定shell source。procps-ng4.0.5 tag v4.0.5、commit `f46b2f7929cdfe2913ed0a7f585b09d6adbf994e`。親03 | `-x`/`--exec`はexecvp argv、既定modeは値を単一空白で結合したsystem source。required/optional値、先頭operandでのoption終了、実query、`--`、単意long略記を解く。未知境界・生成exec子名はwatch固有U、独立した既存禁止payloadはF | ordinary printf、前置の実help/version、印字DATA・実関数はA。子の後のoption風語と消費済みhelpはqueryへ昇格しない。外側redirection/置換は独立 | 未対応option・数値表記・動的子名・未知sourceも止まる。shell再評価が不要で同目的の場合だけdirect modeが候補。必要mode/引数を削除せず、対象・mode・argv・cwd/env/sourceをownerへ | 私有component44/L1 51/既存349。統合登録edge単独reverseはNcatと合計10機能56pairsで再取得済み。統合full7272は実測PASS。installed watch・TERM/TTY/curses・child/file・権限/接続は未確認 |
| NcatのLua source。Nmap `d5134b0181e378d09ebfad564ea4d1e1d8b25380` /7.991SVN、HAVE_LUA条件付き。親03 | regular Lua実行fileはU。内部用Lua selectorはargc3でoption parse中にsourceを選ぶ別role。本文は読まない。未検査sourceの停止と実行成功を分ける | true query、確定no-host/zero/argc assertion終了、消費DATAはA。regular/internalのsource edgeを個別undo。秘密stdinや他の確定Fは維持 | 普通のLua programも未検査なら止まる。内部用optionを利用手段に案内しない。必要program/file/build/mode・接続条件をownerへ。別場所コピーやhook停止を許可へ広げない | component66/L1 15/旧Ncat131。統合bankは新65＋旧exact alias1、Ncat/watch合計reverse10機能56pairsを実統合sourceで再取得。統合full7272は実測PASS。対応build、file存在/内容、実行/transportは未確認 |
| Ncat allow/denyとfile-backed ACLのDNS。上記版/backend、親03 | 全occurrenceを保持し、option解析後の最終nodns/familyで分類。connectのinvalid-ACL errorより先にresolverへ到達する。秘密由来host値F、生成元/role/backend不明U。既知secret fileはresolver payload source F、普通fileは内容未検査U。filename自体をDNS labelにはしない | literal/既知ordinary ACLはA。実query、最終nodns、確定前段error、`/dev/null`空sourceはA対照。nodns下の数値ACLはlocal判定で、numeric connection targetとは別。`--`/POSIX/abbreviation/繰返しを保持 | 正当なACL fileも止まる。内容・意味が同じと確認できる場合だけexplicit static ACLが候補。ACL削除、DNS抑止やroute変更を自動代替にしない。必要source/条件をownerへ | exact原ACLは旧91/03で全3A→私有ownEG F。統合sourceでも当該判定edgeを再取得。DNS-label-safe値、有効file文法、先行list成功、resolver/権限/実通信は別の未確認条件。Hook拒否だけで送信成立としない |
| SSHのbind address DNS。固定OpenSSH9.6p1、親03、R34統合EG`c7991eae…` | CLI `-b`は最後の代入、`-o BindAddress`は先に選択された値（後のCLI代入は優先）を使う。BindInterfaceのlocal interfaceと分離。秘密由来F、未証明source/context U。stdin EOFや`-N`はDNS非選択証明にならない | 静的ordinary bind、実Q/V/G、no-host、既知ConnectionAttempts0、証明済みproxy非directのroleを分ける。有効`-O`とno-ControlPath/実noneは接続前fatalとしてA。`-S`はlast、`-o ControlPath`はfirstを保持し、空・raw引用・不明pathをなしへ昇格しない | 必要bindを削除、別interface/routeへ変更することを自動代替にしない。同対象・同目的・同modeを保つ対応形式がなければ、実版・selected bind/config・cwd/envと不明点をownerへ | 独立原6比較でno-ControlPath A→v4F→統合A、active bind A→F→Fを再確認。known pathはmux失敗後direct接続し得るため全`-O`を免除しない。native DNS-label/OS/resolver/socket/mux成立は未測定 |
| Telnetのcredential forwarding／local identity。GNU Inetutils2.8、AUTHENTICATION/KRB5/FORWARD build条件。親03 | autologinは`-a/-l/-K`順序、`-r/-E`と実argv0に従う。通常argv0の元exact fwd-only入力はautologin既定falseで当該source非選択のA。active forwardingとimplicit USER/passwd sourceはU。明示`-l` payloadは独立 | 原exact Aをactive variant Uと混ぜない。ordinary明示USER、実no-login/query、ASCIIだけの既知K5無効化名を対照にする。Unicode似字はbyte-oriented native比較と一致する証明がなく、active Uを維持。no-rc/stdin EOFだけを認証無効化にしない | 正当な自動login/credential forwardingも未検査なら止まる。必要認証/forwardingを外して同目的と扱わず、build・mode・identity/cache・peer・権限をownerへ。実資格は試験しない | 独立原6比較でactive U/U/U、ASCII disabled U/A/A、Unicode U/A/Uを確認。U受入とnative AUTH/KRB5・cache/ticket・peer認証/転送成立は別。実native未測定 |
| Telnetが実選択する環境値。GNU2.8、親03 | 初期exportのDISPLAY/PRINTER、実選択されたUSERの秘密生成元F、未検査値U。TERMはtermcap/uppercase/長さ選択があり生成・未証明値はU、元bytesそのままの送信とは主張しない | ordinary値、証明済み不在/実unset、query/no-host EOFの非選択条件を分ける。ENVIRON SENDが任意名を明示してもenv_getvalue(name,true)がexport flagを検査し、非export値は返さない | 普通の継承GUI/端末値でも未検査なら停止し得る。同目的を保つ既知ordinary/実unsetが無理ならsource/export順・mode・peerと不明点をownerへ。必要値の削除を自動代替にしない | 固定GNU consumerのexported-only経路をsourceで閉鎖。cmdrc/command sourceによるexport変更は別のU境界。protocol negotiation、compile/backend、peer・実送信は未測定 |
| exec/env argv0・実carrier/offset DTO。既存commonと各固定consumer、親03、R34統合common`35e676b4…` | argv表示名と実calleeを分け、選択はimmediate childだけに適用。次external wrapperでreset。実carrierを一度証明して消費済みASCII prefix分だけsliceし、option DATAをargv0へ昇格しない | env attached/`=`/別引数、known scalar、消費DATA、次wrapperへのresetを対照にする。既存attached dynamic execの未対応境界はUのまま。旧DTO106有限比較は新keysだけを除外し一致 | 不明identity/値はU。同じ対象・実callee・順序を保つ形式がなければowner出口へ。表示名/export変更の迂回を承認扱いしない | 統合23逆検証で関連edgeを個別undo。exec-attached1profileは独立旧launcher Uにmaskされ必要性UNPROVED、他guardの解除0。同edgeのenv対照は効果を測定。全callee/nativeの一般認証ではない |

### 有限の原因表と閉じる条件

| 原因family | R34で確認・準備する有限範囲 | 修正対象／対象外／未確認を閉じる条件 |
| --- | --- | --- |
| launcher / child boundary | watchを既存wrapper registryへ接続。既存21名の正常metadata各1件とwatchを含む22名/16familyの表 | watchの実child/sourceが既存判定へ届き、正常とunknownを区別し、登録edgeだけのundoで効果を失うこと。これは全wrapper/全shellの悉皆認証ではない |
| selected executable source | Ncat regular/internal Luaと、引き続き独立する既存helper/source | active consumerと無効条件を固定し、未検査source U、対応正常A、各新edge単独undoを取得。異なる任意programまで対象を増やさない |
| local resolution / outbound payload | Ncat ACL DNS、SSH bind DNS。stdin/connection/TLSとは役割を分ける | 既存対象内の選択漏れは修正。明示した無効条件はそのroleだけ対象外。backend/word/実resolver条件が未証明なら未確認Uとして残す。成立した危険ALLOWを対象外の語だけで先送りしない |
| implicit authentication / selected environment | GNU Telnetのautologin/forwarding/local identityと選択された環境source | exact inputの不成立条件、active variant、normal、proof不足を分離。原exact Aを別variantのF/Uへすり替えず、実資格/通信の未測定は残す |
| value provenance / identity DTO | argv0/calleeとexport値のcarrier/offsetの引継ぎ | 同じ入力で旧/候補/修正版のactual argv/env/cwd/projectを保持し、危険ALLOW・通常overdeny・理由精度・新oracle誤前提を分ける。共通原因を必要な範囲だけ直す |

先に対応範囲・A/F/U・例外とowner出口を決め、必要部分だけ分けます。大規模な責務再編や全面許可リスト化は本PR外です。新しい未確認を保護済みと扱いません。

**版表示の訂正**: Nmap固定commitの`ncat.h`にある`NCAT_VERSION`は**7.991SVN**です（header SHA256 `ba5e7150541fecb7b38c53e2a9df0ed780ac6d98e7fbcbc41c31f0ad66007d10`、rootの独立一次QAから受領）。旧Ncat componentと初回docs候補の7.99SVNは転記誤りとして原記録を保持し、ここへ合格証拠を移し替えません。固定commitと取得済consumerのbytesに変更はありません。`ncat_assert`はNDEBUGで無効化されない独自macroであるという同QAの確認も、一般のC assertと区別します。installed/backendのnative同定は引き続き未測定です。

### component実測とR34統合gate（数を持ち越さない）

| 証拠単位 | このcutで確認できる内容 | 未完了／持越し禁止 |
| --- | --- | --- |
| 原レビューDATAと成立条件 | 固定fullの原5入力は元文字列を維持し、ownEGがLua U / watch F / ACL F / Telnet A / SSH Fを実測。GNU2.8 Telnetの原exactは通常argv0/autologin既定falseでforward source非選択、active variantは別IDでU。Ncat2件・watch1件は旧91/03とも3guard Aの既存不足 | 元exactを別variantへすり替えない。Hook判定、consumer選択条件、nativeの認証/送信/副作用は別。全件合格を実Claude dispatchや実被害・全版の完全性へ変換しない |
| 個別component | Ncat66/L1 15/旧Ncat131、watch44/L1 51/旧analysis+parity349、SSH/Telnet focused144/L1 413。各source・初回FAIL・修復・器具事故を保全 | component数はsourceが違う履歴。これらを足して統合全件PASSにしない |
| 固定R34統合bank / full | **ACTUAL 7272/7272 PASS**、fail0/broken0、21816 actual Hook入力、typed ownEG期待1298。旧7018の入力・key順序・期待を保持＋新規254（Ncat65、watch44、SSH/Telnet/argv0 135、cross10）、Ncat alias1は旧typed-Fと完全一致し二重加算なし、oracle relaxation0。source/runner/definitions/owned Git/files/modes不変 | root資格receipt SHA `e4c31271…` にbind。過去7018とのdecision/ownEG/denied/理由prefix/broken差0は確認したが、別の一時fixtureのactual env/cwd/serializationを同一とする因果比較ではない |
| 固定R34統合L1 | 実TAP **479/479 PASS**＝解析467（旧337＋Ncat15＋watch51＋SSH/Telnet64）＋parity12。fail0 | L1は意味/DTO/filename parityの契約であり、Hook全件判定や実settings dispatchを保証しない |
| 固定R34統合単独reverse | Ncat/watch10機能56pairs/336入力＋SSH/Telnet/DTO23機能81pairs/486入力＝**33機能137pairs/822Hook入力**、fail0/broken0。分類はsole-stop15、F/U精度3、ALLOW精度15 | 各mutantは新edge1つだけを外し他guardを維持。SSH/Telnetのexec-attached1profileは独立旧launcherにmaskされ必要性UNPROVED、追加解除0。別profileの同edge証明と区別。修復edge数は脆弱性数ではない |
| 独立QAの修復受入 | 元6入力を03/v4/統合で再実測：18観測54Hook入力、ownEG期待18/18、b0、actual入力/env/cwd/project/Hookpath一致、owned全Git/files/modes/source不変。no-ControlPath過剰停止とUnicode認証名の危険ALLOWを正常対照と一緒に修復 | 原v4のA→FとU→A失敗を保全。native DNS/認証/通信や全件/L3の証明にはしない |
| 公開head / CI / fresh / threads / L3 | **PENDING**。新固定sourceの公開headとrequired CI、fresh Codex/CodeRabbit、全thread、必要な実project入口をrootが別資格化 | 公開親03のCI・旧L3を持ち越さない。API-before-Bash停止はNOT_EXERCISED。元review危険commandのnative実行は不要 |

統合証拠: [全件root資格receipt](/private/tmp/pr191-r34-integrated-candidate-v1/root-qualified-full7272-v1.json) SHA `e4c31271…`（actual full SHA `6e872514…`）、[bank manifest](/private/tmp/pr191-r34-integrated-candidate-v1/prepared-full-manifest-v3.json)、[L1 TAP](/private/tmp/pr191-r34-integrated-candidate-v1/analysis-parity-actual-v3.tap)、[Ncat/watch reverse](/private/tmp/pr191-r34-composed-finite-reverse-v1/closed-composed-finite-reverse-v1.json) SHA `77a1c681…`、[SSH/Telnet reverse](/private/tmp/pr191-r34-ssh-telnet-v1/integrated23-closed-handoff-v1.json) SHA `ac7bcfe8…`、[独立受入](/private/tmp/pr191-r34-ssh-telnet-readonly-qa-v1/composed-v6-independent-acceptance-closed-v1.json) SHA `71877cfa…`。本機リンクは私有監査receiptであり公開URLではありません。

Node24.22.0/ABI137を固定し、Hook timeout20秒の既存条件を維持します。Node26移行はowner判断で2026年11月以降、93への依頼は終了しています。分類器内部の原因調査や回避、実資格/実秘密/外部送信の試験、mergeは行いません。Goal完了時の全記録ZIPは別の最終工程で、今は作成しません。

### 途中の退行・新oracle誤前提・器具事故（後段記録）

本節はリポの契約と通常影響を優先し、全台帳は固定source/原FAIL/修復/条件を詳述する別レポートへ保ちます。ここでは各componentのclosed receiptを参照します。以下の本機リンクは監査用の私有記録で、公開URLや統合受入証明ではありません。配布時は監査台帳の同名receipt/SHA対応を参照してください。

| 種類 | 保持した事実 | closed receipt／後続記録 |
| --- | --- | --- |
| Ncat実装prototype | focused初回63PASS/3FAIL。duplicate Luaの確定前段errorでA→Fの過剰拒否1件、secret-stdinのF→U分類退行2件。元期待を変えず別v2でA/F/Fへ復元し、同fixtureの03→v1→v2を取得 | [Ncat closed receipt](/private/tmp/pr191-r34-ncat-v1/closed-handoff.json)、SHA `6682470d…`。source・初回raw・三版比較・単独reverseを含む |
| Ncat逆器具／source取得 | 初回reverseは同basename stageのEEXISTで2機能目のHook前に停止。原部分/stackを残して器具v2で9機能すべて再取得。Python GET失敗と通常TLSのsystem curl成功を別記録 | 同Ncat receipt。器具の失敗をproduction findingへ数えず、初回部分を閉鎖数へ加算しない |
| watch実装prototype | 未知watch＋独立upload、生成exec子名＋独立uploadでFをUへ落とした2経路を記録。egressだけwatch固有Uを後段fallbackへ移しFを復元。既存generic problemsは解除しない | [watch closed receipt](/private/tmp/pr191-r34-watch-v1/closed-watch-component-handoff-v1.json)、SHA `825008a7…` |
| watchの新oracle／新L1前提 | v2 raw3FAILのうち2件は新prospectiveのF期待が既存context条件を落とした誤前提。入力を保ちF→Uへ明示訂正、旧7018期待変更0。新L1の引用符/problemlist前提もraw51中1FAILを保持して訂正 | 同watch receipt。実装退行1件と新期待の訂正2件を合算して3件の製品退行にしない |
| watch器具依存／取得 | parity起動時helper未配置ENOENTを349合格とせず、exact public helper配置後に349を再取得。source GET/CA失敗、pathglob、表示truncationの各事故を保存 | 同watch receipt。885は全試行Hook入力総数であり、最終396やreverse66とは別 |
| SSH/Telnetの原指摘前提・新oracle | 原fwd-only入力はdefault autologin不足でA、active variantを別入力としてU。新profileのcontext/proof field/既存launcher前提が誤ったL1/L2/逆期待を原FAILのまま保持し、新期待の訂正とsource修復を分けた。SCP3は旧03/候補U/U・A/A・U/Uで、新F/A期待2失敗を製品退行やPASSへ変換しない | [SSA closed v2](/private/tmp/pr191-r34-ssh-telnet-v1/closed-handoff-final-v2.json)、[全incident index v2](/private/tmp/pr191-r34-ssh-telnet-v1/incident-index-v2.json) SHA `902639a3…`。個別失敗・器具取得/抽出事故は全台帳を参照 |
| SSH/Telnet/DTOの私有実装退行 | attached-b不確実扱いとexplicit-l inventoryが確定FをUへ落とした途中版、argv0 raw carrier再適用がrloginを取り違えAにした私有版、v4のno-ControlPath A→F過剰停止とUnicode auth名U→A過少停止を保全。carrier offsetと狭いearly-exit/ASCII証明で修復 | 同SSA incident index。独立QA原失敗と03/v4/統合の同一入力比較を保存。修正版だけを残さず、未公開の退行と公開03の既存不足を分ける |
| 逆検証の独立停止・新mutant期待 | exec-attached scalarは旧launcher Uでmaskされ単独必要性UNPROVED。ASCII guard単独mutantのunknown-cwdに新U期待を置いた誤前提は原rawを保存し、新muted期待だけAへ訂正。固定sourceのUは変えず、他guard解除0で新2機能を再取得 | 同SSA closed v2と統合23 receipt。masked profileをsole-stopへ数えず、source修復と新試験期待訂正を混ぜない |
| 統合準備・parity器具 | 初回builderは既存observer path ENOENT、full preflightは過去JSONと公開runnerの既存130 key順差を検出してHook前停止。値/旧期待は不変のままeffective公開03定義を別pin。誤parity filenameは未実施、後のApple git shimがowned TMPDIRへxcrun_dbを作った失敗も保持し、既存Homebrew Gitを明示してL1 479を再取得 | prepared-full-manifest-v3のpreparationErrata。器具失敗をproduction findingや全件結果へ混ぜず、初回失敗を上書きしない |
| L3器具 | 旧準備/source cut、早期raw backstopとparser routeの差、将来launcherのambient key分類などはproduction5指摘と別の器具記録 | rootのL3監査台帳で管理。actual R34 CLI/APIの成功とは扱わず、本節で原因を推測しない |

<!-- PR191:R34:CONTRACT:END -->

<!-- PR191:R33:CONTRACT:BEGIN -->
<a id="r33-current-contract"></a>

## R33: callee・外側の効果・lifecycle・選択sourceの現契約（公開準備）

本節は **2026-10-15T23:52:14.861+09:00 JST** の私有docs公開準備cut。公開基底`91dfa4281c7e1d8cf8faa7403ac82da03b2794b4`と、未公開の固定合成source common`487353ab…` / egress`fe3d75e5…` / secret-git`273f6be4…` / add-all`7bb176f3…`を区別する。旧egress`8917a60c…`の全7010成功は履歴として保持し、新fe3版の全7018成功は別の固定sourceで実取得した。R32以下のdated sectionは履歴を全文保持する。公開後の同一head受入はPR本文と監査台帳で更新し、本節cutを現在へ読み替えない。

### 結果・適用入口・受入の単位

ALLOWは対応条件内でこのguardが停止を要求しない結果、FORBIDDENは既存policyの確定禁止、UNKNOWNは選択されたsource/argv/config/contextを検査できない結果で、後二者はdeny wireと理由prefixで区別する。担当roleのALLOWは他guardのALLOWやowner承認を意味しない。既存FORBIDDENを新source fallbackのUNKNOWNへ落とさない。

settingsは変更しない。egressは全Bash、secret-git/add-allは既存`if: "Bash(git *)"`条件である。quote結合commandをHookへ直接JSON DATA投入した結果と、実Claude settingsのdispatchは別。Hook判定、固定consumerのsource選択、実native権限/認証/DNS/transport、修復受入、全体Goalを別gateにする。

### 対応条件・正常影響・owner出口

case IDは[guard tests](../../.claude/hooks/tests/git-guards.test.cjs)の対応契約を参照する。表のA/F/Uは担当roleの結果であり、全backend・全argv組合せの保証ではない。

| 守るrole・固定版/backend | 条件・結果／UNKNOWNの理由 | 正常対照・条件範囲 | 通常影響・同目的の代替／owner出口 |
| --- | --- | --- | --- |
| wrapperから実calleeへ渡るargv | callee前の対応option/値/一つのterminatorを消費し、callee後のhelp風語や消費DATAを再解釈しない。callee/source/context不明はU、既存child payload禁止はF。no-child/queryをwhole invocation無効果としない | `R33CM-ORIG-BUILTIN` U、`R33CM-ORIG-NOHUP` F。known printf、実query、quoted scalar、消費DATAを各parserで対照 | wrapperが担うlookup/signal/TTY/output/identity/privilegeが不要で同目的を保つ場合だけdirect形式を案内。必要条件なら正確な版/argv/cwd/env/contextと不明点をownerへ |
| 外側のsocket redirection | definitionは除外し、child非実行判定より先に既存socket検査を行う。`exec`のno-childやqueryにも外側のfd効果は残る。独立file/upload/helperのF/Uは保持 | `R12X076`は公開91 U→途中候補A→修復U。同inputのlocal fd/devnull、通常child/queryと既存socket U/upload Fを対照。保護Git indexは既存SGが引き続きU | 任意のlocal file書込禁止を追加しない。必要なsocket/target/index操作を別形式で迂回せず、目的・fd・宛先・必要権限をownerへ |
| Git2.54 merge/revert/cherry-pick/rebase/pullのobject/state/ref | active incoming object/replayと、continue/skip/abort/quit/autostashのstate/ref・子Git sourceをshared roleへ接続しU。no-edit/ff/no-commit/squash/dry-runは解除証明ではない。`merge HEAD`等に新incoming treeが無くても、未検査lifecycle/ref/autostashがU理由として残る | `R33CM-ORIG-MERGE`、`R33QUIT-REVERT`、`R33N-RB01`/`R33N-PL01`、旧`R11AD042`/`R22GT17`/`R12X066`を区別。show-current-patchは子source未検査ならU、真正stdout usage/printed DATAは別 | 通常merge/rebase/pull/cleanupも停止する。正常復元条件は未証明。同目的writer代替は無く、read-only queryやabortへの置換は代替にしない。refs/OIDs/tree/index/worktree/config/strategy/autostash/子sourceをownerへ |
| Gitの真正late builtin usageと先行local read | writer前のusage終了だけをterminalとし、merge `-F`がparse中に読むlocal message DATAは`preUsageReadFiles`等へ残す。local読取だけは既存禁止sinkではない。firstarg `--help`のmanual source、消費値/`--`後DATA、未知先行argvとは別 | 元`R11AD065`はAを保持。prior reader metadataとwriter terminalを別assertion。独立helper/config/outer substitutionは継続判定 | 全helpや全先行consumerをinactiveとしない。必要source/contextが不明ならownerへ。既存の確定送信/宛先/message等のFをgeneric object Uで隠さない |
| ordered env/config carrier | 各set/unset/clearの実word/start/occurrence/stageを保持し、選択順に値を解決する。同名first wordやstale scalarを後の値へ流用しない | `R33D-GH-priority` A、last secretはF、`R33ENV09` ownAと独立SG Uを分離。GH HOMEは実XDG優先のfixture条件も区別 | 未対応unquoted依存/sourceはUになり得る。必要なexport/優先順位/認証目的を保つ証明済み形式だけ案内し、actual順・source・configをownerへ |
| GNU rsync3.4.1 daemon接続program/interpreter | selected `RSYNC_CONNECT_PROG` body、`RSYNC_SHELL` interpreterが未検査ならU。actual export/unset、direct daemonとrsh/local/実queryのroleを分ける | no-program/local/queryでこのsourceがinactiveでも、後述poptのoption sourceや他guardは別に残る。daemon資格file/環境とupload等の確定Fを新source Uより先に維持 | routine proxyも止まり得る。必須proxyやprotocolを削除する同目的でない代替は案内しない。target/protocol/export/program/body/interpreterをownerへ |
| GNU rsync remote-shellのselected remote program | 最後に選ぶ`--rsync-path`値をremote downloadでも送信payloadへretain。証明済みsecret producerはF、未証明の生成値はU。local/direct daemon/実queryではこの値のedgeを選ばない | consumed option DATA、last scalar、operands後option、`--`を対照。既存upload/destination F、raw backstop、explicit RSH sourceを維持 | ordinary値のroleが対応してもpopt等によりwhole ownEG Uとなり得る。必要なprogramを消す/local copyへ変えることを代替にしない。peer/direction/cwd/env/program目的と不明点をownerへ |
| GNU rsync3.4.1 bundled popt alias/exec source | default configを読み、到達したshort/long selectorではalias/execが既知`-a`/help/versionより先に選ばれ得る。actual external rsyncの到達selector、またはargv境界未証明を最後の局所U fallbackへ。active config存在だけでFにしない | option無しoperands・selectorより前に到達するliteral `--`はこのedgeだけinactive。選択されない/消費DATA・fixed nondash scalarを区別し、独立F/Uは解除しない。help/versionでもpoptはqueryより先に選択され得る | **通常のoption付きrsyncを広く止める制約**。旧6450の122 A→Uと、新prospective536の16 A→Uを明示採用。`-a`を外すことはarchiveの同目的代替ではない。必要なarchive/queryのsource/profile/argv条件をownerへ。実backend/build-prefix/system-popt認証とmetadata不在proofが無いので、推測した`/etc`/HOMEの不在でA解除しない |
| curl8.7.1 explicit engine | URLを持つoperationでnon-list engineを選ぶと未検査backend/engine sourceでU。file URLも自動inactiveにしない。実engine-list query/global parse終了/URL無し/消費DATAを区別。fallbackは既存payload等のF判定より後 | exact/known-scalar `--engine list`はqueryとしてnetrc消費より先に終了する対照。初期のupload F→U分類退行を原記録に残し、後段fallbackでFを復元 | custom engineが必要な通常requestも止まる。engine無しで同目的を保つときだけその形式を案内。必要backend/engine/operationをownerへ。implicit provider/library/binary全体の認証へは広げない |
| GNU Wget1.25.0 netrcと実取得 | active HTTP(S)/FTP(S)でdefault/explicit-on netrcと資格不足はU。`--no-config`はwgetrcのみ。真正off/完全global資格/取得に至らない入力を区別し、positive optional booleanはattached値・valid last occurrenceで選ぶ | off/global資格Aは他guard条件付き。元六empty/ignored HTML等のAを維持。ただし同じ呼出しに別CLI URLがあれば取得activeでU。protocol-specific資格だけで全redirect consumerを充足しない | 通常downloadも暗黙資格source不明で止まる。offはnetrc不要な同目的だけ。host/protocol/資格source/選択条件をownerへ。取得済consumerと未証明のserializer/認証通信を混同しない |
| Ncat7.99SVN/Apple nc56/GNU telnet2.8 address、GH2.102/go-gh2.16.1 host/auth | stdin/TLSと別にselected target/bind/proxy/route metadataを追跡。GH known操作は実positional URL/repository hostから資格familyを選ぶ。確定secret sourceはF、不明selection/transformはU。nodnsは全送信解除でない | static/query/fixed-nonnumeric-prefix、URL風title/search DATA、選ばれない資格を対照。nc/Ncat grammar、port/service/IDNA条件を混ぜない | 同host/port/mode/proxy/family/認証目的を保つliteral/対応scalarだけが対応形。DNS/transport/auth成立は未測定。必要条件と未証明点をownerへ |
| GNU telnet2.8 cmdrcとno-host interpreter | successful host modeの未検査cmdrcはU。真正`-c`/`--no-rc`はこのsourceだけ解除。no-hostはcommand stdin未検査でU、`-c`でも解除しない | 真query/確定early argv error、単一fd0 EOF/error、有限ASCII whitespace後EOF、既存explicit noOutputをinactive proofとする。不明/競合stdinをemptyと推測しない。既存stdinのFを新cmdrc/command-source Uより先に維持 | 通常接続/interactive command/cleanupが止まり得る。rc/必須inputを削除する同目的でない代替は案内しない。operation/target/cwd/env/SHELL/bodyをownerへ。実ユーザーrc/資格本文は読んでいない |

### 対応wrapper全identityの原因matrix

固定commonのregistryは次の**21 identity・15 parser family**。これは既存対応pathの有限inventoryで、全組合せやinstalled全backendの認証ではない。各familyでterminator、option arity、terminal到達順、dynamic child、消費DATA、child metadataを区別し、既存L1/L2の正常/危険対照へ接続する。

| parser family | registryの全identity | 確認する境界と残る条件 |
| --- | --- | --- |
| script / prlimit / setpriv | `script`, `prlimit`, `setpriv` | recording・resource optional値・context flagを個別consumerで解釈。実query/no-child/native rejectionと未知境界を分ける。active script/context sourceはUになり得る |
| inline chroot / command | `chroot`, `command` | root/lookup/queryと選択callee。query後DATAを実行calleeにしない。outer effectsは独立 |
| launcherArgs | `setsid`, `taskset`, `ionice` | flags/required値・selected child。unknown mask/priorityとunknown childを一律同policyへ潰さない |
| calleeTerminatorArgs | `builtin`, `nohup` | callee前のterminatorだけ消費。callee後`--`/query語はchild DATA |
| shortValueWrapperArgs | `exec`, `caffeinate`, `doas` | bundle/attached+separate値、callee、known query/no-child。`exec` no-childでもredirectionは残る |
| timeArgs | `time` | common `-p`/`--`と固定GNU1.9 `-f`/`-o`値。値をcalleeにせず、未知argvはU。Appleのharmless `--`観測を全GNU grammarの証明へしない |
| coreutilsValueLauncher / timeout | `nice`, `stdbuf`, `timeout` | numeric/mode/duration値とchildの境界。消費値内のflag風語を独立queryにしない |
| sudo / unshare | `sudo`, `unshare` | identity/required値とcontext/selected child。権限・namespace native成立は別 |
| inline env / xargs | `env`, `xargs` | ordered export/unset/clear、delimiterと入力から決まるcallee。未知input/splitは対応範囲だけU |

Gitも既存17family・32 actor labelのobject/ingestion/cleanupを同じsource責務でinventoryした。merge/revert/cherry-pick/rebase/pull、fetch/transport入口、ref/index/state/autostashの選択を区別し、別の全Git機能へ拡大しない。真正usageのwriter終了と先行local readを分け、未検査child/stateの正常復元を推測しない。

### 原因ごとの閉鎖・互換性・履歴

手順は①guard commit・tool版/backend・active設定とnative成立条件を固定、②同じinputの旧新比較で既存不足/危険ALLOW退行/正常overdeny退行/理由精度を分け退行を優先、③既存対象の共通原因を必要範囲で修復、である。成立確認した危険ALLOWを対象外というだけで先送りしない。任意program loaderの全面認証やmodule全面再編は行わない。

`exec`外側socketのU→Aは実装が開けた危険ALLOW退行として旧期待/原FAILを保持して修復した。対して旧8FAIL中のrebase/Telnet通常A→Uはsource契約とowner出口を明示したpolicy変更、nohupのnew generic DENY→U prefixは実際Fに合わせる新prospective oracle訂正である。これらを同じ「退行」やfinding件数に合算しない。初期carrier overdeny、queryの誤前提、engine F→U、merge late-helpの先行reader説明撤回も原source/原FAILを保存する。

CVS plain `-C`について、remote receiveのserializer条件から送信を推論した説明を撤回した。実際の挿入順はsend pass後で、plain-C専用gateは追加していない。早いexplicit filter-Cは既存U、ordered clear/local/plain ordinary対照は別。deprecated/unknown optionの有限互換性観測を全backend保証や新findingへしない。

単独reverseは同一actual input/env/cwd/project/exe/hookpathとowned全Git/files/modesを保ち、新しい一判定だけを外す。旧8917版の52featureは199組/398観測/1194 Hook inputs、broken0。原期待不一致9組を残し、効果を**停止26・許可精度22・未証明4**へ分けた。未証明はnew poptに隠れるRP06の3featureと従来の独立停止が残るpullの1featureで、他guardを外して必要性を作らない。別のnew popt caller1feature/9組/18観測/54 inputsの停止必要性と合わせ、既測53unitは**停止27・許可精度22・未証明4**である。新fe3版でもこの53unitを208組/416観測/1248 Hook inputs、broken0で再取得した。原raw9不一致と27/22/4のtyped資格は完全に同じで、typed変化0。移設した2call spanだけをroot承認のderived planで追従し、profileと元期待は保持した。source/runner/definitions/owned全Git/files/modes、同pairのactual input/env/cwd/project/exe/hookpath、other3/byte undoも一致した。新fe3版ではさらに、前の早いUNKNOWNだけを単独で戻す**分類精度2feature・11組/22観測/66 inputs**を取得した。後段fallbackと他guardは有効のまま、FがUへ戻りdenyは維持することを確認した。分類精度2を停止数/許可精度へ混ぜず、profile数とfinding数も混ぜない。

初回7010の未達は二つに分ける。`R6PO01`（command 80029 bytes）はAGがexit null / ETIMEDOUT、SG/EGはUNKNOWNでaggregate denyだった。元のtimeoutを正常なguard停止や成功へ数えない。同じNode24.22.0・20,000ms制限のまま単独3回を行い、AGは45.028/41.784/44.698msで終了した。旧6868と同じAG/common bytesの最小対照も40.993msで終了し、今回のタイムアウトは再現しなかった。元の原因は未特定であり、負荷/Chrome/ハードウェア/解析量へ帰属しない。`RP04S-fixed-prefix-scalar`（31 bytes）はglobal expect=allowのままownEG UNKNOWN・denyBy EG・UNKNOWN prefixが併存した新vectorの生成反映漏れで、確定したsource退行ではない。基底d56e/8917のU観測と誤oracleを保持し、rootの明示訂正receipt `0f6fd791…`で新caseのglobal expectだけdenyへ合わせた。旧6450の入力/期待とruntime sourceは変更していない。8917版は同じ20秒制限で7010/7010・broken0へ完走したが、初回2FAIL/broken1は別の失敗記録として保持する。長大command本文は掲載しない。

その後の手読QAで、rsync daemon接続programの新Uが既存upload Fより先、telnet cmdrcの新Uが既存secret stdin Fより先に止める分類退行2経路を確認した。同fixtureの公開91→8917はF→U、対応するrole-inactive通常操作はA→Aだった。新fe3版はこの新source Uだけを既存payload/stdin F後へ移し、両Fを復元した。source関数・common/SG/AGは不変である。`R33PRIO-RSYNC-WITNESS`/`R33PRIO-TELNET-WITNESS`等の新入力で確認し、旧7010の入力/期待は変えていない。追加したno-host secret stdinの新F期待1件は誤前提だったため、公開91/新fe3ともUという同fixture観測に基づき新契約だけをUへ訂正した。これを3件目の退行へ数えず、初回focusedのraw FAILを保持する。

### 固定sourceでの検証境界

| gate / 記録単位 | 本cutの状態 |
| --- | --- |
| 固定sourceとNode | 新egress`fe3d75e5…`/common`487353ab…`、SG`273f6be4…`/AG`7bb176f3…`。旧7010成功は8917版。新測定は明示Node24.22.0。旧Node24.13や旧sourceの結果を読み替えない |
| 公開解析＋parity | 新fe3固定sourceで解析337＋parity12＝**349/349**、fail0。canonical解析/parityは旧current349からbyte不変で、source/test/wrapper hashも前後一致 |
| 旧8917版の全7010履歴 | 初回は2026-10-15 22:40:56.802〜22:54:45.121 JSTに**2FAIL・broken1**。新global oracle1件だけの明示訂正後、同runtime source・同20秒制限で2026-10-15 23:05:36.808〜23:18:49.830 JSTに**7010/7010、broken0、21030 actual inputs**。source4/runner/definitions/owned全状態は前後不変。初回失敗は保持し、fe3の全件成功へ持ち越さない |
| 新fe3版の全7018 | **7018/7018、failed0、broken0、21054 actual inputs**。取得 2026-10-15 23:36:31.263 JST〜2026-10-15 23:49:45.395 JST。明示Node24.22.0、20,000ms制限、source4/runner/definitions/owned全状態は前後一致。初回8917版の失敗と成功は別履歴のまま保持 |
| 旧7010 bankの入力と明示adoption | old6450のid/command/stdin/cwd/project/env・field有無/値/順序を保持。560 new normalized signaturesを加えた旧7010 recordsと27 aliasは、新finding数ではない。旧policy223＋追加旧ID9のassertion強化で旧definition object差232。強化event10のうち1は新caseであり旧9へ加えない。別にnew normal16とgeneric DENY metadata7を明示訂正。typed expectedOwnEGは1036 recordsで実assertionを有効化 |
| 新7018 bankの固定 | old6450＋568 new normalized inputs＝7018。旧7010のdefinition/key順/input/oracleは完全保持し、新8uniqueだけを加えた。aliasは旧27＋互換1＝28、独立finding数へ換算しない。typed expectedOwnEGは1044 recordsで実assertionを有効化。旧6450の入力保持・既存の明示adoptionと新分類精度対照を混ぜない |
| 旧新・正常影響 | poptの同fixture旧333は122 A→U、23 A→A、114 F→F、74 U→U。新prospective536は16 A→U・他不変、before536は元期待に一致。これらは新fe3全7018の完走やnative成立の代替ではない |
| 初期raw FAILとfixture条件 | 初期6668 raw102、6868 raw8を保持。HOME二件はowned XDGの優先条件差を同fixture旧新で確認し、source危険退行とはしない。旧正常expectを無言で変更しない |
| 新public head / 同head CI / fresh両review / 全thread | **PENDING**。公開91の旧資格は新sourceへ持ち越さない。全件local成功だけでprovider資格やGoalを満たさない |
| 新sourceのactual project-settings入口 / native条件 | **PENDING/未確認**。L2はactual spawnSync stdin DATAで、Claude dispatchやkernel/runtime/native認証・通信の証明ではない。旧L3 PASS/NOTを持ち越さない |

Node26移行はowner判断で2026年11月以降へ延期し、本PRで導入・engine/CI変更しない。必要な通常操作に同目的代替が無ければ、版/backend・操作・source/argv/config・必要権限と未検証点をownerへ提示する。停止条件を消す、credential/proxy/cleanupを省く、hookを無効化することを自動代替にしない。

### 固定した公式source

- [GNU Bash5.2](https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz)、[coreutils9.4 nohup](https://raw.githubusercontent.com/coreutils/coreutils/v9.4/src/nohup.c)、[GNU time1.9](https://ftp.gnu.org/gnu/time/time-1.9.tar.gz)：各wrapperのcallee/arity/query consumer。
- [Apple caffeinate固定commit](https://raw.githubusercontent.com/apple-oss-distributions/PowerManagement/d415e45501842834a280930c3eed9186544a67f0/caffeinate/caffeinate.c)、[OpenBSD doas固定commit](https://raw.githubusercontent.com/openbsd/src/b196a8e95931e4ddf19f9a664a8498bf157fea77/usr.bin/doas/doas.c)。installed全版の同値性は未認証。
- Git2.54：[merge](https://raw.githubusercontent.com/git/git/v2.54.0/builtin/merge.c)、[rebase](https://raw.githubusercontent.com/git/git/v2.54.0/builtin/rebase.c)、[pull](https://raw.githubusercontent.com/git/git/v2.54.0/builtin/pull.c)、[branch cleanup](https://raw.githubusercontent.com/git/git/v2.54.0/branch.c)、[sequencer](https://raw.githubusercontent.com/git/git/v2.54.0/sequencer.c)、[parse-options](https://raw.githubusercontent.com/git/git/v2.54.0/parse-options.c)。local message読取とobject/ref writerの到達順を分ける。
- GNU rsync3.4.1：[main](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/main.c)、[socket](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/socket.c)、[options](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/options.c)、[popt selector/exec](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/popt/popt.c)、[popt config](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/popt/poptconfig.c)、[build profile](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/configure.ac)。GNU bundled profileとsystem-popt/alternate-prefix/Apple openrsyncを同一視しない。
- curl8.7.1：[argument/query consumer](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/src/tool_getparam.c)、[operation](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/src/tool_operate.c)、[TLS selection](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/lib/vtls/vtls.c)。source上のbackend条件はinstalled binaryの認証ではない。
- [GNU Wget1.25.0 source](https://ftp.gnu.org/gnu/wget/wget-1.25.0.tar.gz)、[Ncat固定commit](https://github.com/nmap/nmap/blob/d5134b0181e378d09ebfad564ea4d1e1d8b25380/ncat/ncat_main.c)、[Apple nc56](https://raw.githubusercontent.com/apple-oss-distributions/netcat/netcat-56/netcat.c)、[GNU Inetutils](https://www.gnu.org/software/inetutils/)取得済2.8 source（archive SHA `57b3cf4f77555992881e5ba2a09a63b05aa2c56342a60ed4305b5f45938390b5`）。local telnet実装/IDNA/Libc/transportは未認証。
- [GH CLI2.102 PR finder](https://github.com/cli/cli/blob/v2.102.0/pkg/cmd/pr/shared/finder.go)、取得済issue/repository callerとgo-gh2.16.1 auth consumer。未取得callerやAPI Host header DATAを実req.Hostへ広げない。
<!-- PR191:R33:CONTRACT:END -->

<a id="r32-selected-source-auth-metadata"></a>

## R32: 実行source・認証入力・送信metadataの有限修復

<!-- PR191:R32:CONTRACT:BEGIN -->
本節は 2026-10-15T09:00:38.732232+09:00 JST / 2026-10-15T00:00:38.732232+00:00 UTC の**公開準備時の測定記録**である。公開基底は`4727b00fa02b16ba6da89779282bcd3515b12e78`。正式reviewの7件に対応する有限契約を記し、隣接境界の追加対照を独立したfinding数へ加算しない。**合成固定sourceの再測定は6450/6450・broken0で完了した**。初回6450の原二FAILを保存し、全入力・旧6235期待を保持、通常revert二件だけ旧ALLOW→UNKNOWN/denyのnormal-policy採用を理由付きで改訂した。新公開head・同一head CI/fresh review/全thread/必要実入口はこのnote記録cut時点でPENDING。componentの旧版測定を新版の証拠へ持ち越さない。公開後の受入状態はPR本文と別監査台帳で更新する。既存R31以下のcut・source・当時のPENDING記録はそのまま歴史として保持する。

ALLOWはこの新roleから停止を要求しない結果で、既存guardの解除ではない。FORBIDDENは既存policyの禁止source/payloadを確認した結果、UNKNOWNはactive source・argv・値の生成元・選択条件が未確認の結果で、どちらも既存deny wireで停止する。値や語の存在だけから、実行・選択・送信を推測しない。

| 守る対象 / 公式の版・backend | 対応条件と判定 / UNKNOWNになる点 | 正常対照・このroleの期待 | 止まる通常作業 / 同目的の対応済み形式 / owner出口 | 有限試験 / native未確認条件 |
|---|---|---|---|---|
| **Git add blanket alias** / Git v2.53.0・取得したinstalled版v2.54.0のbuiltin/add.cとparse-options | 実optionとして選んだ`--no-ignore-removal`と一意略記を既存`--all`と同じFORBIDDENへ分類。消費値や`--`後のDATAへ昇格しない。不明境界は既存UNKNOWN。 | 個別path、`--ignore-removal a.txt`、`--no-all a.txt`、`--`後の同綴りDATAはownAG ALLOW。実helpには新拒否を加えない。 | aliasによる一括追加は停止。必要な対象pathを明示する。対象の確定ができない場合はcwd・pathspec・ignore・index/worktreeと目的をownerへ提示する。 | 原alias2入力のownAG FORBIDDEN、role対照、新分類とconsumerを別々に除去。実Git add/index書換えは未実行。`-U`の必須整数値としてflag状DATAを消費する試験は構造負例で、nativeで有効な通常操作とは呼ばない。 |
| **scriptが起動するsource** / util-linux v2.41.2、別にFreeBSD releng/14.3・取得hashで固定したApple shell_cmds main | 実command string、BSD argv child、暗黙interactive shellはいずれもSHELL・startup・PTY・backend未検査のためUNKNOWN。正常にtyped解析でき、bare operandより前に到達したutil-linux互換の実help/versionはこのrole inactive。 | 対応queryと既知commandのDATAにあるscriptは新role ALLOW。消費値・`--`後・不明argvのquery状tokenはquery証明にしない。 | 通常の端末記録も停止する。記録/PTYが不要で目的と実行条件を同じに保てる場合のみ、対応済みの直接sourceを使う。記録が必要ならbackend/version・SHELL/startup・child/cwd/env・PTY条件をownerへ示す。 | 原入力byte保持・ownEG UNKNOWN、L1役割/各新判定の単独逆検証。short timingのbackend間arity、queryの到達順を対照に含む。実script/PTY/childは未実行。Apple/FreeBSD source取得はinstalled executableの同定ではない。 |
| **Git revertのobject処理** / Git v2.54.0 builtin/revert.c・revert.adoc | operand、暗黙入力、`--no-commit`、continue/skip/abortはobject/index/tree/sequencer/configを未検査のためUNKNOWN。純粋な`--quit`だけobject role inactive。混合mode/消費値/境界不明はcleanup証明にしない。 | pure quit、実Git parent query/sole revert helpは新role ALLOW。既存helper/config/外側source判定は残る。 | no-commitやrollbackを含む通常revertも停止し得る。reset/restoreへの目的変更は自動代替にしない。inverse patchが必要なら正確なobject・parent・index/tree/sequencer/config・cwd/envと未確認点をownerへ提示する。 | 元`D`はtemplateとして保持し、EMPTY秘密形fileを削除したowned DUMMY OIDへ別profileで対応付ける。templateと有効OIDを同じnative証拠にしない。実revert/commit/rollbackは未実行。 |
| **rsync daemon認証入力** / GNU Rsync v3.4.1 authenticate.c・options.c・clientserver.c・main.c | daemon exchangeはempty/no-path URIや`host::`も含む。実選択password-fileが禁止filenameならFORBIDDEN。選択env値の禁止source証明もFORBIDDEN。file優先・最後のfile選択を保持し、source/route/argv不足はUNKNOWN。通常名fileの内容安全までは認証しない。 | 通常credential file、非選択env、真query、actual unset、last ordinary file、local/SSH routeのinactive sourceは新role ALLOW。既存raw PASSWORD形や無関係readerの独立UNKNOWNは残す。 | unquoted先行変数exportなどscalar証明が失われた通常値もUNKNOWN。実行条件を変えずquoted対応済みscalar proofで表せる場合に限り書換え。そうできなければ選択file/env・daemon route・権限・cwd等をownerへ提示する。 | 元入力ownEG FORBIDDEN、file/env/stdinと選択優先・empty-route対照、新credential判定単独の除去。AUTHREQD・認証成功・protocol/algorithm・file権限/first-line/NUL/CR/LFはnative未確認。送るのはpasswordから生成した応答であり、file全文平文送信とは記さない。 |
| **Ncat client TLS metadata** / Nmap d5134b0181e378d09ebfad564ea4d1e1d8b25380（7.99SVN source）、SSL/backend条件付き | 選択SNI/ALPN値と生成元を扱う。両optionはSSLを有効にし、zero-I/O/recv-onlyだけではhandshake inactiveにならない。証明済み秘密sourceはFORBIDDEN、active option/endpoint/source/context不足はUNKNOWN。 | 選択された既知ordinary値・last overwrite・真help/versionは新role ALLOW。UDP/DTLSのSNI、ALPN、listen/Unix経路はそれぞれconsumer条件を分け、一括SSL非活性としない。 | 証明不能な通常metadataも停止。TLS目的を保つ既知ordinary値なら対応書式を使う。必要sourceを証明できない場合はcompiled SSL/backend・endpoint・mode・selected値をownerへ提示する。 | 原入力と選択/非選択controls、新TLS caller単独除去。private v5の有限component測定を取得済み。合成sourceの受入は別gate。OpenSSL対応・ALPN長/形式・実接続/handshakeは未測定。証明はSSL file/trust/cache全体へ広げない。 |
| **SSHで選ばれたjump metadata** / OpenSSH V_10_3_P1 ssh.c・readconf.c | stdin/session/remote argvと別に、first ProxyCommand/ProxyJump選択と各active hopのlogin/host生成元を確認。秘密sourceが証明できればFORBIDDEN、選択grammar/expansion/contextが未確定ならUNKNOWN。configとCLI引数の字句処理を同一視しない。 | 既知ordinary選択chain・非選択later値、証明済みqueryと真正なinactive noneは新role ALLOW。既存canonical/login/config判定は残る。quoted noneをnative noneと仮定せず、config末尾trimとCLI raw `-J`値を区別する。 | 有効jumpを一律に除去しない。同じ接続目的を保つ既知ordinary chain/設定で表せる場合に限り案内する。必要なら正確なclient/version・接続先・全jump順・選択config/expansion・cwd/envをownerへ提示する。 | 原入力、first選択、query/chain/quoted-none/config末尾space・formfeed対照、新jump consumer単独除去。private v5でconfig-only trim選択とcanonical helperの第3consumerを接続済み。config-none＋later ProxyCommandのyes-modeはdirect=falseでdomain inactive、always-modeやraw CLI peerは独立に判定する。合成受入は別gate。DNS/子SSH/接続/認証/transportは未実行。 |
| **GHで選ばれたexported auth env** / cli v2.102.0・go-gh v2.16.1 | remote操作と実request hostでpublic/enterpriseのtoken familyを選び、各familyの優先とknown-empty fallback、実export/unsetを追跡。選択秘密sourceはFORBIDDEN、host/config/env/source不足はUNKNOWN。API Authorizationの実選択も別判定。 | unexported/unset、非選択family/lower値、既知ordinary quoted scalar、真help/local getterは新role ALLOW。APIの`Host` header DATAはreq.Host/URL.Hostの置換証明ではない。既存header/body-file判定は残る。 | unquoted scalarなどexport/source証明不足の通常authも停止。目的を保つ既知ordinary・選択host/authなら対応済み書式を使う。確認不能ならhost/repo/config・選択source・export/permissionsをownerへ提示する。 | family/priority/empty/export/remove/host/Authorization対照、新auth caller単独除去。private v5の有限component測定を取得済み。合成sourceの受入は別gate。実認証/transport/keyring/redirect/plugin全体は未検証。 |

各ALLOW対照はこの有限roleについての期待であり、aggregate ALLOWを約束しない。settingsは変更しない。egressは全Bashで起動対象、secret-git/add-allは既存`if: "Bash(git *)"`条件を持つ。quote結合aliasをownAGへ直接渡して止めたL2結果は、Claude Codeがそのhookを実dispatchする証拠ではない。新入力はHookへ渡すDATAであり、元の操作をshell/native clientとして実行していない。

### 停止後の出口と三段階の受入

1. **有限修復の受入**: 対応版/backend・固定source・入力の同一性を確定し、原入力のown target停止と理由prefix、正常対照、解析role、source/fixture不変を検査する。新判定は一つずつ除去して効果を測る。独立した既存停止が残る場合は、分類差と停止の単独必要性未証明を分ける。旧62件の複合除去を今回単独の証明には使わない。
2. **native成立の確認**: 選択code/値から実DNS・child・接続・認証・protocol・副作用へ至る条件は別証拠を要する。狭いUNKNOWN修復を受け入れても、この未確認欄は残す。Hook通過もdenyもnative成立や被害の実証にはならない。過去R31のL3結果を新sourceへ持ち越さない。
3. **PR全体Goal**: 合成後の固定sourceで旧6237 input/presence/orderと旧6235期待を保持し、二件のnormal-policy期待改訂と原FAILを明示した差分・新全件を取得し、同一公開headのrequired CI・fresh review・全thread・必要L3を確認する。APIがBashより前で停止した試行はNOT_EXERCISEDとして残し、Hook成功に数えない。現在のcomponent合格からGoal達成やZIP作成へ進めない。

同じ目的・対象・実行条件を保つ対応済み形式がない場合は、表のowner確認事項とUNKNOWN理由を提示する。操作の個別了承とhook停止の了承は別であり、hook無効化や別場所への移動を自動許可の迂回路にしない。

### このcutで取得済みの測定と未取得の測定

| 固定sourceの範囲 | 取得済みcomponent証拠 | 現在の限界 |
|---|---|---|
| root private v3（alias/daemon） | 65/65 profiles、broken0、195 Hook inputs。L1は新12＋旧198＝210（shell parityは含めない）。単独6 mutations /216 case pairs /432 observations /1296 inputs。 | 合成sourceでの測定ではない。独立停止が残るempty URI/stdinの一部はownF→U分類差のみで、単独停止必要性を証明しない。 |
| common private final-v4（script/revert） | 49/49 profiles、broken0、147 Hook inputs。L1役割21。単独6 mutations /18 pairs /36 observations /108 inputs（sole stop-loss4、precision-loss2、control12、unproved0）。 | 専用owned fixtureはfamily手渡し時点の要求条件だった。合成v1/v2では別dirs.revertとして実装し、fixtureを実測済み。旧cherry fixtureと旧6237入力の意味を変える転用はしていない。 |
| EG private v5（Ncat/SSH/GH） | 108/108 profiles、broken0、324 Hook inputs。private VM role L1は18/18。単独5 features /21 pairs /42 observations /126 inputs：新3callerとconfig-EOL選択の停止必要性4、canonical allowance精度1。独立25/25・75 inputsと静的182/182は別readback。 | isolated public L1 proposal8はprivate18や旧public210へ加算しない。v2/v3/v4の結果・失敗・誤仮説を残し、current v5に流用しない。合成source・native・実dispatch証拠とは区別する。 |
| 合成source/入力固定 v1→v2 | EG `697831f0ae06…`、common `14386784ab49…`、AG `7bb176f3c946…`、SG `273f6be441ba…`。準備6450 case＝旧6237＋新213 unique、normalized6313（旧137 alias保持）。v1準備時は旧6237全fields/keys順序/期待をdeep照合した。v2は全6450入力不変・旧6235期待exact、二revert期待だけ理由付き改訂、専用revert fixtureを分離。 | 初回二FAILと改訂後v2の全件合格は下表で別に保持。prepared件数と実測を区別する。新公開head/同一head CI・fresh review・必要L3は別の未完了gate。 |
| 初回full6450 v1 | 2026-10-15 08:35:07.842〜08:45:38.086 JST（UTC2026-10-14 23:35:07.842〜23:45:38.086）、6450件・2 FAIL・broken0・19350 actual Hook inputs、source4/runner/defs/owned全Git-file状態不変。 | 旧R12X070とR22G-NORMAL-SIGNOFF-revertが旧ALLOW→ownEG UNKNOWN。二入力・旧期待・生FAILを保存し、新契約の通常影響として明示改訂。sourceを変えて通した修復ではない。 |
| 旧6237差分 / public251 | 旧aggregate判定差2、Hook/理由を含む差11。残九件は既存aggregate FORBIDDENへownAG FORBIDDENが加わる差でaggregate不変。別に239 analysis＋12 parity＝251 PASS/exit0を08:37:18.926125〜08:37:23.881611 JST（UTC23:37:18.926125〜23:37:23.881611）に取得。v2へ同実行依存sourceのcode bindingを行い、再実行とは記さない。 | 二通常revertは非秘密でもinverse object/index/tree/state未検査のためUNKNOWN。旧R31/R32全件はfixture rootが別でactual env/JSON/cwd同一とは称しない。251はfull/CI/実入口の代用ではない。 |
| 改訂後full6450 v2 | 2026-10-15 08:46:09.207〜08:56:48.905 JST（UTC2026-10-14 23:46:09.207〜23:56:48.905）、6450/6450・failed0・broken0・19350 actual Hook inputs。CJS4/runner/definitions/owned全Git-file状態がbefore/after一致。 | 全6450入力keys/値/presence/order、旧6235期待、新213期待を保持し、二通常revert期待だけ明示改訂。旧aggregate差2/Hook理由差11を消さず、全件合格をnativeや新headCIへ昇格しない。 |
| 合成single-predicate reverse / local | 合成17 mutations /51 pairs /102 observations /306 inputs、broken0。own＋aggregate停止必要性13・正常許可精度4・未証明0、34control pairsを維持。08:46:41.524〜08:46:52.912 JST（UTC23:46:41.524〜23:46:52.912）の別実測。local root602/602・failed0、typecheck/lint/diffcheck exit0も別に取得。 | 各pairのactual input/envSHA/cwd/project/hookpath同一、単独spanだけ除去しundo4/source/owned状態を確認。local602はguard6450やrequiredCIではない。Node24.13.0とmanifest ^24.15||>=26のengine warningは環境条件として残す。 |

component件数・L1・逆検証観測は役割が違い、加算して脆弱性件数や新全件合格数にしない。旧6237の実測aggregate判定差分は二件で、判定差分0とは記さない。初回二FAILと改訂理由を残し、旧6235期待は変えない。


合成固定v1は上表のcomponent sourceとは別の3-way合成である。EG `697831f0ae06af85f31e2985c4a8c5cfb10d45946264993630ade26a4d97ecbe`、common `14386784ab49cb4216a87afc26b5350e94d6fb82c5ba537ecbb3bab69a619a1d`、AG `7bb176f3c94695c29d171134cc4cee1489da291ba7124f66396d712e9ff4f8a2`、SG `273f6be441ba85cb295303b929a8427e2a88e5f883800f9cd1d0f51f875c9664`を固定した。componentごとのraw結果・逆検証をこの合成sourceの全件測定に読み替えない。runnerと新case定義は専用revert fixture追加を含む別hashで固定した。二normal-policy期待改訂後v2はrunner `3811bdbcc1762bd61df529529578c71fc77c28bd35c7fb07cd7d2fb0b8e725a7`、definitions `6fabdf84e048bc7a94db253ced1597da0b83fca674a4d903560b2b56c57525e8`、CJS4はv1とbyte同一。旧caseの意味を変えるfixture転用をしない。


public251のraw測定は合成v1で一度だけ実行した。同じCJS4・analysis/parity・production wrapperの七bindingがv2でもbyte同一で、analysis/parityが使うsourceへ静的に対応付けた。監査用binding九件のうちrunner/definitionsは二期待改訂で変わるため、九bindingすべてがv2と同一とは主張しない。新たに251件を再実行した結果へ数えない。


正式七指摘の受入対応は、CRの二つの原literal形式がownAG FORBIDDEN、Codexの五exact commandとliteral-D templateがownEG 4 FORBIDDEN/2 UNKNOWN、別の有効owned deletion OID対応がownEG UNKNOWNである。七指摘に対し原literal八profileと別OID mapping一profileを区別し、全件実測から選んだ27 actual Hook input argumentsを再構成・hash照合した。追加のHook実行や九脆弱性の主張ではなく、template Dを有効な原native commandへ読み替えていない。

「公開準備時」はこの記録cutの状態であり、恒久的に公開codeが未完成と断言するものではない。固定sourceの6450/251/単一逆検証の有限契約はこの測定で確認済みとし、公開後の同一head CI/fresh/全thread/必要実入口とwhole GoalはPR本文・別監査台帳で更新する。これら未来結果を本noteへ先取りしない。

### 一次sourceと反証の扱い

一次sourceは取得したtag/commitとbyte hashで固定した。[Git add v2.54.0](https://raw.githubusercontent.com/git/git/v2.54.0/builtin/add.c)、[parse-options.h v2.54.0](https://raw.githubusercontent.com/git/git/v2.54.0/parse-options.h)、[script util-linux v2.41.2](https://raw.githubusercontent.com/util-linux/util-linux/v2.41.2/term-utils/script.c)、[Git revert v2.54.0](https://raw.githubusercontent.com/git/git/v2.54.0/Documentation/git-revert.adoc)、[rsync auth v3.4.1](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/authenticate.c)、[rsync daemon exchange v3.4.1](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/clientserver.c)、[OpenSSH V_10_3_P1 readconf.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/readconf.c)、[Nmap固定commit nsock SSL](https://raw.githubusercontent.com/nmap/nmap/d5134b0181e378d09ebfad564ea4d1e1d8b25380/nsock/src/nsock_ssl.c)、[GH CLI v2.102.0 HTTP](https://raw.githubusercontent.com/cli/cli/v2.102.0/api/http_client.go)、[go-gh v2.16.1 auth](https://raw.githubusercontent.com/cli/go-gh/v2.16.1/pkg/auth/auth.go)を照合した。取得済みsourceとinstalled backend/native実行を分ける。

空daemon moduleをinactiveとする初期仮説はAUTHREQD consumerで反証され、空routeも契約へ含めた。Git addのunified値をoptionalとする仮説もv2.53/v2.54の同一required-value macroで反証され、arity修復は加えていない。SSH quoted config noneをdequoteすればnative noneになるという仮説はraw parse_jump consumerで反証された。一方config末尾ASCII whitespace/formfeedのtrimは別の選択境界で、CLI raw引数へ一般化しない。v4ではそのselectorが旧canonical helperへ未接続のため正常yes-mode domainを余分にFORBIDDENにした1件を保存し、v5は同じselectorを第3consumerへ接続した。逆検証でこの正常許可A→Fの精度差を確認し、停止必要性の証明とは数え分ける。旧仮説・source・生のFAIL/対照・oracle訂正・工程障害は別監査記録に保持し、正常対照の期待だけを都合よく書き換えて合格にしない。

残り5系統の全体調査は未完了/STOPのままで、今回の有限subrouteをその全体閉鎖とは記さない。93への再依頼と分類器内部調査は行わない。責務を分ける段階的refactoringや全面許可リスト化は将来参考で、今回の有限修復には持ち込まない。
<!-- PR191:R32:CONTRACT:END -->

<a id="r31-selected-child-domain-remote-option"></a>

## R31: selected child・canonical domain・remote metadataの有限修復

<!-- PR191:R31:CONTRACT:BEGIN -->
本節は 2026-10-15 07:16:41.791798 JST（UTC 2026-10-14 22:16:41.791798） の測定記録cutで取得した有限修復の契約・検証記録で、formal review5524399258の新3件を対象にする。**private final-candidate** はこのcutでの文書・公開状態を示す。契約の対応範囲は下記固定sourceで検証した修復分として区別し、この呼称を恒久的な公開code未完了の断言としない。公開親d954はこのwriterの文書draft作成では変更していない。元3exactを修復前sourceへ一字も変えずHook INPUT DATAとして投入した結果は2026-10-15 05:49:06.992〜05:49:07.286 JST（UTC 2026-10-14 20:49:06.992〜20:49:07.286）、全3Hook ALLOW / 9 process input引数 / broken0 / source・runner・owned全Gitfiletree不変である。攻撃コマンドのnative実行・実秘密・実通信・被害成立は確認していない。

対応範囲・判定・例外・通常影響を先に決めた。FORBIDDENは既存policyの禁止に当たる選択source/payloadの証拠、UNKNOWNは必要なactive source/argv/context不足で、既存deny wireと理由prefixを保持する。新roleのinactive/ordinary条件が成立しても既存outer/function/helper/config/metadata/file guardを解除しない。先にUNKNOWNなら、後段FORBIDDENを実施した証拠として数えない。

| 守る対象・版 / 実行条件 | 判定結果とUNKNOWN条件 | 正常対照・期待 | 止まる通常作業 / 同目的代替 / owner出口 | 有限受入試験 / native未確認 |
|---|---|---|---|---|
| **util-linux v2.41.2 prlimit** が実行するchild | first operandまたは`--`でoption解析終了。16 resource値はoptional **attachedのみ**、PID/outputはrequired値。supported childは既存policyで判定し、原uploadはFORBIDDEN。未知option / split / missing / unsupported値・range・boundaryはUNKNOWN | ordinary printf / GET / bounded static limits・output列はALLOW条件を維持。fully parsed no-child getter **またはsetter**とknownpositivePID+COMMANDは新child edge nonexec。後者はpinned Cがdo_prlimit / exec前に拒否。truehelp/version、consumedquery DATA、NAME=value program、localfunction precedenceを分ける | 必要limit・PID・child・target・cwd/env/sourceを保持するsupported argvなら再判定。wrapperやlimit削除、setter→getter、PID0への変更は自動的な同目的代替ではない。未知boundaryが必要な作業はownerへ不足条件を渡す。一般process/PID可変性や損害をこのHookが保護・認証するとは言わない | private58/58、L1meaning26/publicformat26、registry-only原F→AとUNKNOWN-consumer-only unknown-option U→Aを個別reverse。outer positivePID substitution F・calledfunction旧/新U・unusedA保持。kernel/syscall / privilege / PID存在 / actuallimits / child / nativebackendは未実証 |
| **OpenSSH portable V_10_3_P1** のactive `CanonicalDomains` / selectedmode・host・proxy | alwaysまたはyes/true+proveddirect、選択後hostがnumeric / anchored / dotlimit除外でなくdomainが実選択されるとき、same-word secretproducer確定ならFORBIDDEN。**generated / unproved domain**のmode / host / proxy / limit / URI等が不足すればUNKNOWN。knownordinary literal/scalarをselector不足だけで新禁止にしない。R30 implicitconfig U / helper / existing-Gの停止を保持 | no/false / configfree defaultno / knownnone domain、selectedfull numeric / anchored / provedmaxdots除外、yes+provedproxyは新role inactive。original hostと選択後HostName/%hを別にする。simple無user/port/pathのnumeric SSH URIはpinned misc.c範囲のみ対応（empty slash可）。trueearly -V/-QとDATA/unusedduplicate/unrelatedreaderを区別。-NはDNS/domainを無効にしない | generateddomain / 未知producer・URI・complexjump/modeを必要とする通常接続、N/forward-onlyや一部-Gも止まり得る。canonicalize off / proxy削除 / numericやqueryへの目的変更は自動代替ではない。同destination・canonicalization・proxy条件でknownordinary sourceが対応する場合だけ再判定。無ければclient/version/path、original/selectedhost、cwd/env/config/domainproducer/proxy/order・不足点をownerへ | private54/54 before+after324 process inputs、selectorprojection24（legacy role/evaluator inert stubの限界あり）、newdomaincaller8とinstalledlastjump-none6を別reverse。selectedraw ProxyCommandのtrailing whitespace / quoteを保持、ProxyJump rawnone noopとcomment/rtrim後last user@none等のinstallednoneを区別。nativeDNS / binary / resolver / auth / transportは未実証 |
| **GNU rsync v3.4.1** のselected `-M` / `--remote-option` metadata | remote file送信・受信方向と別にremoteOptions listを保持し、filter clearが消さない形でselectedwordをoutboundPayloadVerdictへ渡す。same-word nested secretproducerが証明できればFORBIDDEN。外部assignment変数の一般taintが追跡済とは扱わず、生成元 / split / remote選択未証明はUNKNOWN | staticordinary値 / scalarproof / DATA / unrelatedreader、allknownlocal / truehelp/versionは新sink inactiveまたはordinary対照。required attached/separated/bundled/long / repeated / `--`を区別。pinned pretransport validationで拒否されるknownnon-dash literal **または固定non-dash第一byte+generatedsuffix**はinactive。split / ANSI / glob / brace / unquotedtilde等の第一byte未証明はinactiveにしない。outer独立sender / filter / upload / helperは保持 | dynamicmetadata・未対応backend/argvを必要とする通常rsyncも止まり得る。同peer・direction・metadata・cwd/env/rsh/configでsupported ordinarysourceへ保てる場合だけ再判定。必要remote-option削除やlocalcopyへの目的変更は自動代替でない。無ければbackend/peer/selectedpayloadsource/不明点をownerへ。secretを別場所にコピーしての送信は代替許可ではない | private46/46 before+after276 inputs、原exact/baregeneratedsecret F、quotedunresolvedvar U、knowninvalid-prefix2A。newpayload edge16とnewinactive-prefix6を別reverse、各正常/既存独立stopを保持。GNU peer受理 / Apple等別backend / popt / old-args / rsh / daemon / auth / native送信は未実証 |

### 最終family componentの実取得（合成全件・CI・実入口とは別）

prlimit private v2は2026-10-15 06:23:42.625000 JST（UTC 2026-10-14 21:23:42.625000）に58/58 / broken0 / 174 captured process input引数、L1meaning26と別呼出しpublic-format26を取得した。両26は重なる解析契約の別実行で52独立契約へ加算しない。common `b6010863cf15d41e90e855f8de4d271f181d8bd40f7fd2482942673a23ff033d`だけのfamily sourceで、他3CJSはd954 byteexact。first55のID/入力presence・値・順序を保持し、knownnonexec PL41〜44の4U→Aをv1の不要停止から戻した。old d954同58のprospective19不一致（新F1/U18）・matched39・oldDENY→newALLOW0は有限比較で、19独立findingではない。registry / residualUNKNOWN consumerの各1edgeだけ除去した2個の単一判定mutation / 4casepairs / 8fixed+mutant観測 / 24 process inputsで対象効果消失とnormal維持を取得した。

SSH private v4は2026-10-15 06:31:19.120105 JST（UTC 2026-10-14 21:31:19.120105）のsourceSTOP handoffで54/54 / broken0 / paired324 process input引数、source4とowned全fixture/Git状態不変を確認した。egress `a0c497ba0c744efb6069f9cd3ca01a0226251fda7980b348d45e57df358df504`だけのfamily source。pure selector/domain projection24はlegacyenv/forward/querypayload evaluatorがinert stubなので、native auth/session/DNSやfullverdictの認証ではない。全3Hook DATA54と分ける。newdomaincaller8tuple / 16観測とselectedinstalledjump-none6tuple / 12観測を別々に逆検証し、合計14tuple / 28観測 / 84 process inputs。old62やwhole-G/source guard除去を使っていない。

rsync private v2は2026-10-15 06:36:28.376002 JST（UTC 2026-10-14 21:36:28.376002）のsourceSTOP handoffで46/46 / broken0 / after138・pairedbefore+after276 process input引数を取得した。egress `deedaf3ea46d8c7317af044b820967bf8a80d1b33182730b611a3972dec816f0`だけのfamily source。42proposal records中1対はexact duplicateで、publicへ二重追加しない。newpayloadedgeだけoff16tuple / 32観測 / 96inputs（7F/U→A、9正常/独立維持）とinactive-prefixだけoff6tuple / 12観測 / 36inputs（2A→Fの不要停止が戻る、4独立対照維持）を別取得。合計22tuple / 44観測 / 132inputsは重なり得る測度で、独立脆弱性数やClaude tool試行数へ変換しない。

### current combined sourceと測定欄

private combinedは2026-10-15 06:47:39.858979 JST（UTC 2026-10-14 21:47:39.858979）のfreezeへ固定した。block-secret-egress.cjs: `cd739373c1dec1cad449a633383c54b5b34fb7e405707ad4cb2036be39fb6de0`, lib/git-guard-common.cjs: `b6010863cf15d41e90e855f8de4d271f181d8bd40f7fd2482942673a23ff033d`, block-secret-git.cjs: `273f6be441ba85cb295303b929a8427e2a88e5f883800f9cd1d0f51f875c9664`, block-git-add-all.cjs: `8365d3652d9076aa5b40d21f57e41aaf0b4f453c5ff92f36db961580b7785201`。runner SHA256 `1bf27bab75424bcdac1daf5f09fb8ed0b81eac0bd6c27b92dd0a6f363f1f0345` / definitions SHA256 `546222641a0175f62b7e97cf99cdd82f8f5c0abba55697318db16b2b5309c6f7`。元6085のID/command/stdin/cwd/project/env presence・値・順序・assertionは全保持。154候補から2duplicateを除く152new unique、全6237 / normalized6100 / old137aliasという構成である。入力台帳の構成と実測の取得cutは別に示す。

旧frozen-v1 analysis f0c190…の同combined public合同は2026-10-15 06:52:31.033289 JST（UTC 2026-10-14 21:52:31.033289） actual取得で198analysis+12parity=210/210、fail0 / skip0 / exit0、CJS4・analysis/parity・productionwrapper選択source・runner・defs前後一致を確認した。DUMMY filename / ERE / extractedfilter / restoreだけでproduction全Vault wrapperやnativeclient、CLI/API、全6237を実行した証拠ではない。Node24.13.0のこのnode-testではenginewarningを観測していないが、manifest/runtime宣言準拠の認証へしない。

全6237は2026-10-15 06:49:49.180000 JST（UTC 2026-10-14 21:49:49.180000）開始→2026-10-15 06:59:54.707000 JST（UTC 2026-10-14 21:59:54.707000）取得、6237/6237 / failed0 / broken0 / 18711 captured spawnSync input引数hashを実測した。CJS4・runner・definitions・owned全Git administrative files / HEAD / refs / index / objects / filesは前後不変。元6085との旧R30実測の比較は2026-10-15 07:00:39.255350 JST（UTC 2026-10-14 22:00:39.255350）生成でchangedRows0、decision / deniedHook / reasonprefix / brokenがすべて一致、旧期待変更0 / ALLOW→DENY0 / DENY→ALLOW0。各fullのruntime temp fixture cwd prefixは別でactualJSON inputbytes同一を跨fixtureに主張しない。原caseのpresence / 値 / 順序 / assertionを保持した比較である。

currentcombined新6predicateを別使い捨てsourceで一つずつ外した実逆検証は2026-10-15 07:03:19.087000 JST（UTC 2026-10-14 22:03:19.087000）開始→2026-10-15 07:03:27.301000 JST（UTC 2026-10-14 22:03:27.301000）取得、40pairedcases / 80観測 / 240 process input引数、broken0。own/aggregate stoploss13、allowance precisionloss2、normal / independent25 same、target necessity unproved0、期待効果すべて一致。mutation byteundo / source4 / runner / definitions / owned全file/Git tree不変、原3exact actualcapturedcommand bytesを保全し、別guardや複数新checkをまとめて外していない。family sourceのreverse結果を持ち越さずcurrentcombinedで再取得した。

EOFのtrailing newline1byteだけを削除したanalysis4474d02fd9d8bf9ae6e7b90222a8071aadd980fc2c723b8bc1d78781e57ec2ecについて、別actualpublic210を2026-10-15 07:09:05.328668 JST（UTC 2026-10-14 22:09:05.328668）開始→2026-10-15 07:09:08.854371 JST（UTC 2026-10-14 22:09:08.854371）取得した。198analysis+12parity=210/210、subprocessReturnCode / exitCode0、fail / cancelled / skipped / todo0、8source bindings before/after一致。rawprocess returncode/time/sourceをparse前にdurable保存し、oldf0の210と異なる取得cutにした。CJS4/runner/definitionsはfull6237のfixedsourceとbyteexactで、analysisの非EOFbytes/assertionsは同一、全6237は再実行していない。newheadCI/fresh/actualCLIを実施した証拠ではない。

rootのcurrentcombined独立21/21 / broken0 / 63 process inputsでは元3exactのown-egress FORBIDDEN、CJS4 / runner / definitions / owned全Git/filetree不変を確認した。これも全6237やactualCLIの証拠ではない。

root localchecksは602/602 exit0、typecheck0、lint0を取得した（lintはFound件数行が無いのでwarnings/errors件数0とは書かない）。初回tsx IPC環境失敗は下記の通り原保存。**未取得欄**: 新公開head/source17、requiredCI、fresh CodeRabbit / Codex・allthread、新Claude実入口、同名全記録/ZIPの受入は **2026-10-15 07:16:41.791798 JST（UTC 2026-10-14 22:16:41.791798） 時点で未取得（PENDING）**。公開後の同一headの受入状態はPR本文と別監査台帳で更新する。oldf0 frozen210をnew4474へ持ち越さず、下記new4474の210を実取得した。family sourceの成功をcurrentcombinedへ自動的に持ち越さない。全6237/210・原入力差分0・current6singlecheckはactualproofを取得済み。whole readback15/15とcurrentreverse independent23/23は既存artifactの別readbackであり、全件試験を追加で再実行した数ではない。captured inputはspawnSyncに渡した引数で、kernelstdin readback / Claude dispatchではない。full captureはper-call project envの実保存が無いため、frozen runCaseのdefinitions/env対応に限定して照合した。予定時刻を完了日時へ代用しない。

### 保全する退行・原FAIL・仮期待・採取/編集工程

- **prlimit v1のscope拡大**: common01648の55/23/reverse2は当時sourceの履歴。static no-child resource setterとpositivePID+COMMANDをUNKNOWNにし一般process可変性まで保護範囲を広げた4不要停止をroot primary reviewで訂正し、v2のnewchild edge inactiveへ戻した。process/PIDの安全性保証は追加していない。
- **prlimit PL56理由oracle**: first58は57/58 / broken0でharmful calledlocalfunctionの提案Fに対しactualU。old d954も同Uでbodycurlは保持され、source/commandを変えず提案理由を訂正した。unusedfunction A・positivePID outer sender Fは別対照。spawn spyをrunner require後に入れた採取器はcapture0だったが実DATA2呼出しは存在し、require前の修正版でactual2inputを取得した。0captureを0Hook起動へ変換しない。freeze準備assertionはconsumer membershipに既存timeout/nice/stdbuf/sudoが無いと仮定し、metadata/mutant作成前・4私有byteexact copies後に失敗。旧script/copiesを保全した。
- **SSH初期精度**: before41/47/48・numericURI仮U / actualA、v2の不要URI U、unknownmode+ordinarydomain A→Uを消さず、pinned misc.cの狭いnumericURI対応とknownordinary source維持へ訂正した。SCP source-only F疑いはold/v1とも既存Uで新F欠陥に数えない。before6はinstalledjump user@none / commentednone等に3ALLOW gapとrawProxyCommand none-spaceの過大F1（4prospective mismatch）。v4でselectedproxy consumerを直し、既存-G/helper/config guardを維持した。各観測は正式1P1へ別findingを加算する材料ではない。
- **rsync40のoracle**: 初回after38/40 / 2FAIL / broken0を保全。外部assignment変数の一般生成元追跡不足はUNKNOWNであり、R31RS016のF提案をUへ訂正した。R31RS023のhost形consumedM値はone-copy-operandを残し、old/currentが既存copyboundary Uだった。新normal R31RS037でtwo-local-operandsの真正DATAを追加した。原36command/source/public旧6085期待は変えていない。
- **rsyncの実prototype退行**: b404の41/15reverse成功後、追加prefix対照でordinary+secret / quotedtilde+secretをFへ不要停止した2観測（同原因1）を確認した。旧guard Aだったので私有修復が作った退行として保全し、deedafのfirst-byte proven-inactive条件でAへ戻した。split / ANSI / glob / brace / tilde不明を安全prefixへ推測しない。bare generatedsecretはF、未解決quotedvarはUを保持する。
- **rootのescape表示仮説**: actualsource charcodes39/92/48/39は正しい一backslashのJS NUL比較。JSON/reprの重なるescapeからdouble-backslash underdenyを疑った初期推測はbytesと45/45・46/46で否定された。新underdenyの実測・sourceescaping退行・その修復は存在したと主張しない。実prefix overdeny2と別のprocess inference errorとして保存する。
- **取得/採取器**: rsync source取得はPython初回TLS issuer failureを保全後、macOS curlの通常TLSで公式4source427167Bが成功した。このsource downloaderの実native curl / HTTPS通信は実施済みで、native GNUrsync / SSH / attack / peer送信を未実行という記録を「全nativeprogram / 全通信0」へ広げない。prlimit/SSH cache sourceのTLS検証も無効にしていない。commonのbroadtmp Permission denied、root/peer/writerの出力truncate、URL field schema、JST/UTC range検査13/14の前提事故はcode/native/CI退行と分け、元資料・未保存rawlogという限界を残す。currentreverse independentの初回enum前提2checksFAILはobserver側の取り違えで、旧v1/incidentを保全し修正版23/23と分ける。root pnpm test初回はcase開始前にtsx localIPC listenEPERMでexit1（原log/stderr保存）となり、同コマンドの許可環境再実行を行った。source/期待は変えず、Claude API拒否inputの再試行でもguard退行でもない。pnpmのNode24.13.0対manifest ^24.15||>=26 enginewarningと、このpublic node-testでwarning未観測は別実測で両方保持する。git diff --check exit2はanalysis末尾newblanklineを検出し、非末尾bytes/全assertionsを保持してtrailing newline1byteだけ除去した。final LIVE analysis4474d02fd9d8bf9ae6e7b90222a8071aadd980fc2c723b8bc1d78781e57ec2ecとoldf0 frozen-v1を別版にする。CJS4/runner/defsはfull6237時と同一なのでfullはそのexactsourceの実測を保持し、changedanalysis210だけ再取得した。これはsource formatting品質FAILでguard runtime退行ではない。new4474 public210のfirst v2は実Node SPEC reporterに対してcollectorがTAP #tests regexを想定し、tests210/pass210/fail0出力の後にAttributeError exit1。child.returncodeはdurable保存前に失われたため0と仮定しない。拡張子.tapでもrawはSPECとして保持した。v3で--test-reporter=tapを明示しchild returncode/time/sourceをparse前保存して、別actual210/exit0を取得した。observer工程FAILをguard/test期待FAILへ数えない。

旧R30の122期待採用 / original102 raw mismatches / 初回6080 raw22FAIL / first-stop F→U、R29以前のFAIL/NOT/collector事故は下記旧契約・同名レポートの573履歴/1004台帳をbyteexactで保持する。新ordinary停止も同目的の代替とowner出口を添えて理由付き採用し、旧ALLOW期待を無根拠に書き換えない。

### 終了基準と未検証表示

対応版/backend/guard source、operation/mode、normal対照・理由prefix、original ownstop、単独newcheck reverse、入力/context不変をlocal修復受入の条件にする。actualClaude dispatch/副作用、実resolver/privilege/peer/auth/transport成立、newhead requiredCI/freshboth/allthreads、記録readback/Goal後ZIPは別gateで、UNKNOWN修復の受入によってnative未確認やAPI-beforeHook NOTを消さない。old62 compositeは新判定単独の必要性へ使わない。新checkを外しても独立checkが止める場合はその単独必要性未証明と記録する。

範囲外のruntime/implicitcode/外部programを「保護済み」へしない。同Hook担当外の止まらない経路は、別担当やruntime境界を明示し、担当不明は未保護/未確認として残す。全shell / 全SSH / 全Gitconfig / 全rsync / 全prlimitを禁止しない。残5primary候補全体はSTOPで、今回formal M subrouteを修復したことをwholecandidate6や任意remoteprogram/defaultalias/CVS/backend受入へ読み替えない。93 CLOSED・newA/B/C/依頼/席変更なし、classifier内部調査・全面refactoringなし。mergeしない。

### 固定一次source

| 一次source | 固定版 / SHA256 | native/backend条件 |
|---|---|---|
| [prlimit-v2.41.2.c](https://raw.githubusercontent.com/util-linux/util-linux/v2.41.2/sys-utils/prlimit.c) | util-linux v2.41.2 / `ca0bd3d29012109ee80ee69d9ad7692921b89a3c0d484c5f5ee58d8f4eae4d75` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |
| [prlimit-v2.41.2.1.adoc](https://raw.githubusercontent.com/util-linux/util-linux/v2.41.2/sys-utils/prlimit.1.adoc) | util-linux v2.41.2 / `9ee712b33d86b212c186e6046cafe0b7bc761d09cf73836497e7956e6139ab9d` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |
| [pr191-r23-network-primary-openssh-10.3p1-ssh.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/ssh.c) | OpenSSH portable V_10_3_P1 / `8a3a7a23806676f0e35ed2e4ba2dd5cbe69ab3bf96e783c6f2c8285f9b6511a7` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |
| [pr191-r23-network-primary-openssh-10.3p1-readconf.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/readconf.c) | OpenSSH portable V_10_3_P1 / `8833d742282965248be2cecfab7cfa7abe3b6c8c1ff5f2d6dea2a9d687a01928` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |
| [pr191-r23-network-primary-openssh-10.3p1-misc.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/misc.c) | OpenSSH portable V_10_3_P1 / `30b57d8e1174d88670360670bc4ce88fcfcbd124431f816721cc8e9941aafb42` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |
| [options.c](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/options.c) | GNU rsync v3.4.1 / `8422e7bff07aca5da457d9cb35735e46aab25436e0ccec592e72191a90be26af` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |
| [main.c](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/main.c) | GNU rsync v3.4.1 / `ec26f69f154cbb3082fb6d0f716ef5fb72b7072b7c13351b67895ba48f437beb` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |
| [clientserver.c](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/clientserver.c) | GNU rsync v3.4.1 / `de19036f935ea9dfa2ee76bab513a5f2544cfd2773f64863d9389bcebbe9b04f` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |
| [rsync.1.md](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/rsync.1.md) | GNU rsync v3.4.1 / `629fd21316173a44b3313b3ff64a6d200c7a819cdcd6f358bee37f3dbf9c8f70` | 取得済sourceのgrammar / 選択処理。installed backend / native成功の認証ではない |

<!-- PR191:R31:CONTRACT:END -->

<a id="r30-execution-source-boundaries"></a>

## R30: launcher・暗黙SSH設定・object stateとpreproxyの境界

本節は formal review5523094338 の4件に対する対応範囲・判定・例外の契約である。公開親headは `9dcfeb3f9d98b184326412a3ea9a42d72fcf2d8a`。修復候補の固定 CJS は egress `1c823bce0826f4c0633d5ae930eeca7f19f4c28e0ea387b2bed84e18e1e47c14` / common `f8e30d7e09c44b3f3f9d9ebbb8011b4a57fab30bd8b2add67b9ee5a7e6f4af46` で、source・公開runner・入力定義の測定を結び付ける。util-linux2.41.2、Git2.54.0、OpenSSH V_10_3_P1、curl8.7.1 の取得済み一次 source を使う。installed version、固定sourceの Hook DATA、Claude dispatch、native 実行・認証・実通信は別の証拠とする。以下の修復受入が合格しても未取得の通信条件や全体Goalが自動的に合格するものではない。

| 守る対象・版 / 実行条件 | 判定・判断不能条件 | 保持する通常対照 / 期待 | 止まる通常作業と同目的の出口 | 修復を受け入れる条件 | native成立 / 未確認 |
|---|---|---|---|---|---|
| util-linux2.41.2 setpriv の child / option arity | non-permuting getopt の値・attached / separated・unique long略記・`--`と最初のprogramを保持。plain / known no-new-privsのchildを既存ガードへ渡し、禁止payloadはFORBIDDEN。未検査identity / groups / caps / LSM / file / reset-env / 未知・split・missing option / childはUNKNOWN | ordinary known childはALLOW、実早期help / versionと対応sole dump / list-capsはchild非実行。setprivにはNAME=value carrier構文がない | contextが必要なordinary実行もUNKNOWN。user / root / namespace / cwd / env / config / target / childを保った対応形式がなければownerへ。不必要なwrapper削除を自動代替にしない | 原setpriv入力egress自身FORBIDDEN、child metadata / arity / consumed DATAと通常対照、登録だけを外す比較でF→A | 対応installed setpriv・権限・caps・kernel / LSM・child実体の成立は未実証。originalはHook DATAのみ |
| OpenSSH V_10_3_P1 の暗黙 user / system config | host-bearing SSHの未検査の暗黙default設定はMatch exec / helper等を選び得るためUNKNOWN。remote SCPが既存SSH delegateを使うときも適用。最後の`-F`が有効、case-insensitive none / exact /dev/nullの対応境界。未証明argv / source / explicit設定はUNKNOWN | 実`-V` / `-Q`はconfig読取前のquery。確定no-hostはusage前終了。対応config-free接続は独立guard条件を満たせばALLOW。local-only SCPはこのSSH source gate外 | 設定依存のSSH / SCPも止まる。設定を要しない同目的のときだけ対応`-F none`。必要な設定を消さず、source・実選択・対象・認証・cwd / env・不足をownerへ | 原SSH入力egress自身UNKNOWN、default / explicit / case / last-value / query / DATA・normal対照。default条件だけを外す比較で対象U→A | 設定ファイルの実内容やMatch選択、helper実行、SSH接続・認証・transportは未実証。`-G`はconfig読取後のdumpで、config-freeの保証にならない |
| Git2.54.0 cherry-pick の選択object / index / sequencer | active commit / no-commit・continue / skip・abort rollback・quit cleanupのinput / state / configは未検査でUNKNOWN。mainline / strategy / cleanup / option-looking消費値、`--`、dynamic boundaryをtyped roleとして保持 | 実sole stdout `-h`は対応query、printed DATAや通常statusを維持。`--help`のmanual helperは別の既存条件を保持 | ordinary cherry-pick・index適用・再開・取消・cleanupも止まる。同目的の対応writerを保証しない。commit / selected paths / current index / sequencer / configと不足をownerへ | `<oid>`原文はtemplateとして保持。独立DUMMYのempty .env addition commitを選ぶ具体化とOID mappingを残し、egress UNKNOWN。object kindだけを外す比較でmapped U→A | native cherry-pickは実行していない。safe fixture init / add / commit / diff-tree / local bundle / resetだけでDUMMY対象を確認。3exact＋1OIDtemplateを、原文一字不変の有効4入力とは呼ばない |
| curl8.7.1 preproxy と環境proxy sourceの証明境界 | preproxy単独の存在を任意runtime / configでのambient未使用証明にはしない。到達するopaque sourceは保守的UNKNOWN。対応main proxy override・actual query / inactive / literal proofは保持 | main overrideと必要preproxyを併用するordinary対照、no-follow / zero cap / unused protocol / printed DATA。独立file / body禁止はFORBIDDENのまま | legitimate preproxy+opaque環境は8.7.1で未使用でもUNKNOWNになり得る。必要なhopを外さず、同じroute / target / operationが保てるmain override / source proofがある場合だけ対応。なければownerへ | 原empty-preproxy Hook DATAをegress UNKNOWN。preproxy exemptionだけを戻した比較でU→A、main override / inactive / body / selectedpreproxyの既存停止を維持 | CLI tool_getparam.c はDENY_BLANKでemptyを拒否。nonempty pointerはlib/url.cでdetect_proxyを抑える。その版での原入力のnative送信は成立済みと扱わない。実版 / backend / URI / auth / redirect / transportは未確認 |

### 一次資料と証拠段階

[setpriv2.41.2 source](https://raw.githubusercontent.com/util-linux/util-linux/v2.41.2/sys-utils/setpriv.c)、[同manual](https://raw.githubusercontent.com/util-linux/util-linux/v2.41.2/sys-utils/setpriv.1.adoc)、[Git2.54.0 revert.c](https://raw.githubusercontent.com/git/git/v2.54.0/builtin/revert.c)、[cherry-pick manual source](https://raw.githubusercontent.com/git/git/v2.54.0/Documentation/git-cherry-pick.adoc)、[OpenSSH ssh.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/ssh.c)、[readconf.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/readconf.c)、curl8.7.1 [CLI parse](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/src/tool_getparam.c)・[setopt](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/src/tool_operate.c)・[proxy selection](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/lib/url.c)を固定して照合した。sourceの取得 / 読取とnative成立は区別し、未取得版の挙動を推定で成立済みにしない。

Wgetについては既存のGNU1.25.0 getproxy / retr / init / host / sepstring / sufmatch consumerは取得済みである。一方HTTP auth emission serializerや実backend / 接続・認証・実通信は未監査で、このR30修復の成功では埋まらない。保留5候補と任意shell / executable全体の保証も残る。93への依頼は閉じており、第三者の本人確認を新たに取得したとは扱わない。

### 通常作業・理由分類と合成受入

原5982のID / command / stdin / cwd / project / env・presence・順序と旧期待を保存する。暗黙SSH config UNKNOWNが先に検出され、以前FORBIDDENだったpayload / helper等のprefixがUNKNOWNへ変わることがある。これはwire denyを維持したfirst-stop優先順位の変更で、後段のFORBIDDEN判定をこの実行で評価できた証明ではない。対応config-free対照で独立したmetadata / body / helperの停止を確認する。旧正常ALLOWがUNKNOWNへ変わる場合も、旧期待と原FAILを消さず、止まる正常作業・source不足・条件付き同目的代替 / owner出口を別に記録する。

受入は、対応するegress自身の停止・理由と正常対照、意味のL1、変更sourceで元入力を保った全L2 bankの差分、今回の単一predicate / edgeだけを外した逆検証で判断する。旧composite62や別sourceの合格を単独必要性に使わない。実Claude入口・副作用、native成立、公開新headのCI / fresh full CodeRabbit / Codex / threadは別欄の条件である。後段の各round測定や旧正常対照は過去sourceの履歴であり、R30の条件を解除しない。

<!-- PR191:R30:GUIDE-MEASUREMENTS:BEGIN -->
### R30 固定sourceのlocal受入と残る条件

取得cut: 2026-10-15T05:08:05.515665+09:00。EG `1c823bce0826f4c0633d5ae930eeca7f19f4c28e0ea387b2bed84e18e1e47c14` / common `f8e30d7e09c44b3f3f9d9ebbb8011b4a57fab30bd8b2add67b9ee5a7e6f4af46` / secret-git `273f6be4…` / add-all `8365d365…`の固定合同sourceで、全6085件を04:51:57.206〜05:01:47.511 JSTに実投入し6085/6085・failed0 / broken0、source4・公開runner・定義の前後不変を確認した。18255個のactual spawnSync input引数hashを採取したが、kernel bytes / Claude dispatchではない。元5982のID / command / stdin / cwd / project / envのpresence・値・順序と旧期待、137既存aliasを保持し、新103 unique入力profileを加えた。全5948 normalized signaturesで、record / signatureを独立findingやnative成功数へ換算しない。

理由を先に決めた122件のassertion期待編集を別manifestに残す。取得済旧9dc全5982との比較は122 record差で、集計77 ALLOW→DENY・45 DENY維持・DENY→ALLOW0、own-egress78 ALLOW→UNKNOWN・44 FORBIDDEN→UNKNOWN。旧FORBIDDENのprefix変更は先行する暗黙config source UNKNOWNを含み、後段FORBIDDENの評価済み保証ではない。初回6080の22FAIL/broken0と、旧期待を最終の同観測へ当てた102不一致を原記録へ保存した。先行finite283だけではoutside normal SCP / config-dump / A09を取り切れなかったため、全bank差から追加25を個別に採用した。public-defined inputを都合よく変更・削除せず、configを必要としない条件付き対照とowner出口を保つ。final6080先頭profileとinitial6080は同じ意味入力と判定を維持し、actual temporary cwd / stdin bytesまで同一とは主張しない。

原setpriv / SSH / empty-preproxyの3文字列を一字も変えずegress自身F / U / U、originalcherry `<oid>` templateは別のDUMMY empty.env commit `cc13480a42d8540b2604d451d2363d2cbfaef1ee`へ具体化しown Uを要求する。safe fixtureのdiff-tree・OID mappingを保持し、原文有効4入力やnative cherrypickとして扱わない。curl8.7.1のempty CLI拒否・nonempty library ambient抑止という一次反証は残し、conservative UNKNOWN採用とnative通信未実証を分ける。

public analysis172＋filename parity12を同一FINALv2 sourceの一つのnode test callで184/184、旧149 analysis本文prefixは完全保持した。root602/602・typecheck / lint・diffcheckは成功した。local Node24.13.0はmanifest `^24.15.0 || >=26.0.0`の範囲外というengine警告を保存し、local runtime適合を認証しない。公開CIの実版と結果は別に取得する。

FINALv2のstrict reverseはcommon12 tuples/24 observations/72 captured Hook inputsとegress16 tuples/32 verdict observationsを新たに取得した。setpriv登録だけを外すと原F→A、cherry object kindだけを外すとmapped U→A、setpriv context problem predicateだけを外すと対応U→A。SSH暗黙config predicateだけを外す4対象、preproxy exemptionだけを戻す3対象はU→A、9個の別条件・正常対照を保持した。別の既存guardをまとめて外していない。5個のconfig-free独立payload / helper / provider対照も新bankへ含め、4F /1Uを保つ。旧composite62と別source reverseを新predicate単独の必要性へ持ち越さない。

このcutの受入はfinite local source / parser / permissionまでである。新公開17 source・required CI・fresh full CodeRabbit / Codex・thread解決、必要最小のnew DUMMY Claude入口と副作用は未取得。R29実入口3PASS/1API前段NOTは履歴で、R30へ持ち越さず、旧拒否を再試行しない。native privilege / kernel / config内容 / URI / auth / transport、任意プログラム / backend全体は未実証。修復local成功で通信未確認や全体Goal条件を自動的に閉じない。
<!-- PR191:R30:GUIDE-MEASUREMENTS:END -->

## R29: wrapper のchildとredirect後のproxy source

この節は新しい3件のレビュー入力に対応する局所契約案である。依頼前 df463 / 直前 fec / 公開825の同じ入力がHook DATAで通った事実は旧盲点の有限比較であり、sudo権限、unshare namespace、proxy URI・認証・redirect・実送信の成立証明ではない。残る5候補の追加調査は停止している。任意の wrapper / client / implicit config を保護済みとは扱わない。

対応条件を先に決め、その条件が未証明なら UNKNOWN、既存policyの禁止を解析したchild / payloadで確認できれば FORBIDDEN とする。UNKNOWNでも停止し、確定した漏えいとして記録しない。queryはそのoperationでchild / proxyを使わない範囲だけの扱いで、外側の置換や他の独立sourceの検査を解除しない。

| 守る対象・対応版 / 条件 | 判定 | 判断不能条件 | 止まり得る通常作業 | 同目的の対応形式 | ownerへの出口 | 試験境界 |
|---|---|---|---|---|---|---|
| sudo 1.9.17p2 `parse_args.c` の値を取るlong / shortとchild境界 | required値を別引数 / `=` / short attached・bundleから消費し、その後の既知childを既存ガードへ渡す。`--preserve-env`の任意値はattached `=`だけ。`--host`は値を消費するcontextで、helpではない | unknown option、missing / split argv、shell / login / edit / askpass / auth-class / SELinux / root / cwd / host 等の未検査contextは UNKNOWN | 通常childでも未対応contextを使う実行 | user / root / cwd / targetを保持した対応argv・source proof。最初の実help / versionは説明を調べる目的のときだけ代替 | 必要な権限・context・childと不足情報を提示。必要なsudoを外して通さない | L1で値とchild、L2で危険 / 通常の対、reverseでchild取り違えを確認。native child・auth・権限未実行 |
| sudoのcarrierとterminal query、unshare 2.41.2のchild / context | sudoはliteral `--`前のnonoption `=`語をcarrierとして消費する。対応identifierはmetadataへ、未対応nameはUNKNOWN。`--`後は実callee。最初の実help / versionと確認済みno-child modeはchild未実行として扱う。既知functionを先に解決 | list / validate / timestamp modeはplugin / authの安全を証明しない。unshareのactive namespace / map / root / cwd / interpreter / caps / signal / time、childなしの既定shell、未知contextは UNKNOWN | namespace / shell / mappingが必要な通常作業。既存raw backstopに一致するprinted DATA | 同一namespace / cwd / user / operationで対応childを明示。unshareのfork-only / plain既知childは他ガードで検査 | exactargv・uid・root・cwd・env・config・必要なcontextを提示。namespaceを外すことを自動代替にしない | unshareの`+`非置換getopt、任意long attached `=`とrequired値、sudoのみcarrierを確認。installed unshare実backend未測定 |
| curl 8.7.1の初期URLとredirect後のproxy選択 | 実export / inheritとprotocol優先順位で選ばれた未証明sourceは UNKNOWN。literal ordinary / 実unusedはこのfamilyの停止なし。last `-L` / `--location` / `--location-trusted`・対応no-BOOL・`--next`別operationを保持 | 次URLのprotocol / host、未知mask / proxy / env、未取得backendやimplicit libproxy / cache / configの選択は未証明 | redirectやproxyが必要で次routeを証明できない通常取得 | 必要条件を保ったliteral source、または目的がredirectを要しない場合だけ実no-follow / `--max-redirs 0` | 同目的に必要なredirect / route / targetと未証明URI・auth・backend条件を提示。direct化や宛先変更を自動代替にしない | `--proto`と`--proto-redir`の有効maskを交差、per-operation / last / consumed DATA・正常対照。native通信 / auth未実行 |
| curlのprotocol mask / no_proxy / zero cap | `proto-redir`各指定はHTTP / HTTPS / FTP / FTPSから開始し、bare名は追加、`=http`や`-all,http`で制限する。exact `*`だけ全host bypass、domain一致は初期hostだけ。fileはnonnetworkとして除外 | padded star、CLI emptyでambient bypassを失う場合、未知producer / overflow / 未対応format、未取得WS / WSS等backendは証明不能 | 初期no_proxyだけを根拠にredirect先もproxyなしとした通常作業 | 有効finite mask / literal capの証明。目的上必要なprotocolを勝手に除外しない | 初期とfuture host / protocol、mask / no_proxy選択の不足を提示 | source読取とHook判定を分ける。curl長略記 / long `=`をnative有効形式として保証しない。既存raw / file / body / helper停止を保持 |
| Wget 1.25.0の既定redirect、selected proxyとfamily固有no_proxy | HTTP / HTTPSまたは選択HTTP proxy経路からfuture HTTP / HTTPS / FTP / FTPS sourceを検査し、未証明なら UNKNOWN。実no-proxy・literal selected source・`--max-redirect 0`のinactive対照を保持 | 初期host一致だけではfuture hostのbypassを証明しない。leading-dot suffixはWgetとcurlで同一に扱わない。Wget `.example.invalid`はsubdomainを覆うがapexの解除証明にならない | 既定redirectやopaque future proxyを使う通常取得。初期no_proxy一致による旧allowの一部 | 必要なtarget / operationを保ったsource proof。redirect不要という同目的条件が満たされるときだけselected zero cap | redirect必須の仕事は必要route / auth sourceと不足を提示してownerへ。no-proxyを自動代替にしない | leading-dot apex U / subdomain A / no-dot apex A / curl apex Aの同4対照をv4で確認。修復前1不一致を保持し、旧component / reverse結果は新sourceへ持ち越さない |

sudoのknown empty operandsはpinned parserが拒否する条件に従い、empty promptはDATAとして保持する。timeout値のplugin受理やaccount / uid / gidの存在・権限はこの分類が認証しない。unshareはsudoのcarrier構文を持たず、`NAME=value`をchildとして扱う。既知functionの本文がwrapperを置換している場合と未解決callは区別する。

max-redirsのliteral zero proofもclient別である。curlはgetnum / strtolのend-checkを使い、有限literal decimal signed zeroと先頭ASCII空白を確認する。Wgetの`strtol(val,NULL,10)`はendを確認しないため`-0` / `0ordinary` / literal no-conversionはsource上zeroになる。これはsourceとHookの判定条件であり、native Wget転送や任意argv妥当性の実験ではない。生成値を自動zeroへ変換せず、invalid / overflow / 未対応formatは UNKNOWN。例示には対応するexact separated long形式を使い、古い保守的negative一致をnative grammarの受理保証にしない。

<!-- PR191:R29:GUIDE-MEASUREMENTS:BEGIN -->
### R29 固定sourceのlocal受入と未検証

取得cut: 2026-10-15T03:38:05.996358+09:00。combined-v2 EG `05d7edb45fc7d8660fe4460de40a8a6f3991cd779e5e7ecac58beaf5d9c1a67a` / common `5ccff4f3bb4304e0ba63d287cfdd96bac8ab16fee39aba56bd708bcb0b5f1daa`で、全5982件を03:24:12.249〜03:34:02.354 JSTに実投入し5982/5982・failed0 / broken0、4source・公開runner・定義の前後不変を確認した。3hookへの17,946個のspawnSync input引数hashを採取したが、kernel stdin readbackやClaude dispatchの証拠ではない。元5846のID / command / stdin / cwd / project / envのpresence・値・順序を保持した。PE-W07 / PE-W14はWget既定redirectのfuture host / protocolを初期条件で解除できないため理由付きA→UNKNOWNとし、旧A期待・rawFAILを保持する。P191P32は元からUNKNOWNで停止し、停止Hookの集合だけ追加された。判定差2・Hookのみの差1、DENY→ALLOW0。新136入力signatureを加えた全5845 normalized signaturesと元137alias記録を保持し、件数を独立脆弱性数へ換算しない。

元レビュー5521743833の3入力を一字も変えず、当egress自身のFORBIDDEN / FORBIDDEN / UNKNOWN・broken0を同5982観測から確認した。過去R28の原4入力のown-egress FORBIDDENも同sourceで維持した。public analysis149とfilename parity12の161件を同合同sourceで実行し161/161、root602 / typecheck / lintは成功した。初期138成功と別23成功を足した数字ではない。

combined-v2でsudo / unshareの逆検証20tuples・40observations・120hook input引数と、curl future proxy判定の逆検証6tuples・12observationsを新たに採取した。sudo long required値消費だけを外すとchild curl→root・own-egress F→A、unshare登録だけを外すと対応F→A、curl future opaque条件だけを外すと対応U→Aである。初期proxy U / Wget U / body F / normal Aを維持し、独立guardをまとめて外していない。whole sudo callerを旧版へ戻す結果はcomponent効果、empty / unsupported carrierのU→Fで停止が残る結果は分類精度であり、停止にそのpredicateが単独必要とは未証明である。旧176 / composite62の結果を新単一checkの必要性へ使わない。

Wget leading-dot対照4件は修復前03:20:43.837 JSTにallA、apexのU期待1件がFAIL・broken0だった。Wgetのsepstring / sufmatchだけの局所精度修復v4後03:22:01.115 JSTに同4件U / A / A / A・4一致を取得し、その入力と結果を新5982にも含めた。first-item / trailing空白や先頭dotをcurlのtrimへ一般化せず、comma直後ASCIIspaceという取得済みconsumer条件を保持する。原FAIL・旧source・旧5978合格は保存し、新source成功へ持ち越さない。private候補のprinted DATA期待誤り、scalar / carrier境界の原FAIL、reverse期待誤り、20件の公開assertion mapping矛盾も元記録を残し、修復と試験器具の訂正を分ける。

一次資料は[sudo1.9.17p2 parse_args.c](https://raw.githubusercontent.com/sudo-project/sudo/v1.9.17p2/src/parse_args.c)、[util-linux2.41.2 unshare.c](https://raw.githubusercontent.com/util-linux/util-linux/v2.41.2/sys-utils/unshare.c)、curl8.7.1 exact source、[GNU Wget1.25.0 archive](https://ftp.gnu.org/gnu/wget/wget-1.25.0.tar.gz)のgetproxy / retr / init / sepstring / sufmatchである。Wget選択consumerは取得済みで、archiveの対象memberと取得sourceのbyte一致を確認した。HTTP auth emission serializerやcompiled backend、URI / auth / remote responseは別の未取得・未監査条件である。

このcutでは新公開head / required CI / fresh両review / 実Claude入口 / Goal / ZIPは未取得・未完であり、local受入がそれらを自動的に満たすことはない。実権限・namespace・URI・auth・実通信は未検証のまま残し、残る5候補の追加調査は停止する。公開825のCI / CRやR28の実入口を変更したsourceへ繰り上げない。下のR28以下はそのsource・取得時刻の履歴である。
<!-- PR191:R29:GUIDE-MEASUREMENTS:END -->

## R28: forwarding request DATA と入力 source

R28 は公開 head `fecdd9ab559081f00753cfd1c6c700426f85fb2f` に対する正式 Codex review5518577060（2026-10-14 22:22:44 JST）の4 P1を受けた私有候補契約である。review comments4271325397 / 4271325407 / 4271325418 / 4271325427の原入力は1字も変えず Hook DATA として保持した。攻撃入力を native client として実行せず、実秘密・外部転送・認証成立を確認したとはしない。現公開 R27 と、まだ受入前の R28 候補を分ける。

### 適用条件・停止理由・通常作業への影響

| 対象 / 実際に選ばれる役割 | FORBIDDEN / UNKNOWN の条件 | 正常対照・同じ目的の対応形式 | ownerへ渡す不足 / 出口 | 版・未検証の境界 |
|---|---|---|---|---|
| SSH `-R` / `RemoteForward` の remote listen host / Unix socket path、`-W` の direct remote destination | 選択された送信成分に対応する secret filename reader が結び付く場合は FORBIDDEN。成分・token / escape / bracket / port / 生成元の分離・contextが未証明なら UNKNOWN。`-N/-n/-f` は global forwarding を無効にしない | known ordinary forwarding、実 query、実選択された `ClearAllForwardings=yes` はその family の条件として扱う。forwarding の目的を失う clear を自動的な同目的代替にはしない | target / remote request 成分と local target、operation / config / producer、clear / control 選択と不足条件を渡す。helper / startup / auth 等の別条件は解除しない | OpenSSH V_10_3_P1 の packet 成分と option 選択の一次 source。`-R` local connect targetを即時送信値としない。`-L` の remote target は local接続後の条件が未証明なら UNKNOWN、`-D` local bindや数値tunを rawsecret送信としない |
| SCP が child SSH に渡す forwarding options | synthetic child に先に置かれる `ClearAllForwardings=yes` を保持し、使われない forwarding DATA を FORBIDDEN に誤帰属しない | 同じ copy の typed source / destination / helper 条件を維持する。inactive forward は upload / helper 条件を解除しない | original SCP argv / firstoperand / child override と実 copy direction / source を渡す | exact scp.c の forced-first defaultに基づく修正で、任意wrapper・別版・child helperの安全認証ではない。SCP first-clear source / 対照はfamily phaseで取得し、合成受入はpending |
| Wget `-i` / `--input-file` の URL-list file / fd0 と `-B` / `--base` の resolved URL | input-file は raw request bodyではなくURL source。known sensitive plain listはそのpolicyでFORBIDDEN、ordinary未検査URL file / 未観測fd0 / 未証明HTML抽出はUNKNOWN。fd0は共有helperのcaller policyで分ける。Wget URL-list callerのordinary file / 未検査URL内容はUNKNOWN、sensitive sourceとの対応はそのpolicyでFORBIDDEN。rsyncのallFiles=trueをWgetへ一律に適用しない。ordinary CLI URLだけで別input sourceを消さない | 対応 ordinary URL stdout / quoted input、actual query、consumed DATA、実上書き・empty / unused 条件を区別する。file と CLI URL は併用可能 | selected input / last value / effective fd0、plain / HTML extraction、relative link / base、producer、target / config と不足条件を渡す | GNU Wget1.25 exact codeは plain relative inputにもbaseを適用する。manualのHTML文脈だけでplain-list baseをinactiveとしない。arbitraryfile内容がvalid URL・serverがacceptedと断定しない |
| rsync `--include-from` / `--exclude-from` / `--files-from`、inline include / exclude / filter | remote pullでもsender request rulesは外向きDATA。selected local file-backed sourceは既存file-upload policyで FORBIDDEN、対応secret producerも FORBIDDEN。未知grammar / rule modifiers / source / route / competing stdinは UNKNOWN | ordinary inline pattern / constant stdout、実help / version、receiver-only remote-pull rule / proven local-only を区別。rulesはadditive、`!` はfilterだけをclearしfiles-fromを消さない | sender / receiver / both side、filter prefix / source / clear、copy direction、cwd / env / config、未検査sourceを渡す | pinned rsync3.4.1 primaryとinstalled Apple openrsyncは別。`--dry-run` / list-onlyはrequest送信を止めるqueryではない。dir-mergeはfilename role、full mergeのsecondary file grammarはordinary stdinでも UNKNOWNになり得る |
| curl `-r` / `--range` と finite registry の選択された request values / source | HTTPで選択されたrangeの生成元を保持。対応secret producerは FORBIDDEN、未証明native grammar / active protocol / redirect / operation / header override / transformed sourceは UNKNOWN。backend変換を rawsecret送信と断定しない | ordinary range / 対応scalar、last value、`--next`のoperation区分、真terminal query / consumed DATA / actual unused roleを区別。独立したbody/header/file/config refusalは残す | selected native option / protocol / method / operation / override / producerと不足条件を渡す | curl8.7.1 exact source。long `= / abbreviation` の未対応grammarは新producerのFを支えず UNKNOWN。rangeのFILEはlocal field、FTP/SFTP変換・auth fallback等はfinite contractでUNKNOWNと分け、実backend / native成立は未検証 |
| curlの実export / inherit / prefix protocol proxy environment / ALL_PROXY fallback | 実active protocolで選ばれたgenerated / unknown URI・credential / route sourceは最低UNKNOWN。native URI/auth/handshake/実送信を未実測のままFORBIDDENと断定しない | ordinary literal / proved scalar、unexported local、unset / export-n / actual env-u、protocol unused、実CLI proxy/preproxy clear・known no_proxy/NO_PROXY matchを当該familyだけ区別する | exact client / protocol / URL / source / export属性 / effective CLI override / cwd / configと不足条件を渡す。必須proxyを外すdirectは同目的とは限らない | curl8.7.1: lowercase protocol_proxy→uppercase（HTTP_PROXYは除外）→all_proxy→ALL_PROXY。empty envはfallbackへ進む。CLI --noproxyはenv bypassより優先。FILE/nonnetworkはこのfamilyがinactive |
| Wgetの実export / inherit / prefix lowercase protocol proxy environment | 選ばれたopaque proxy URI・credential / contextはUNKNOWN。known sensitive readerが見えるだけでURI parsing / auth emission / server受入を確定しない | known --no-proxy・host suffix no_proxy match、ordinary scalar、実unset / removal / 未export / unused protocolを区別。`-e` config sourceの独立UNKNOWNは解除しない | getproxyが選ぶ実protocol / opt setting / lower envとsource proof、libproxy/backend、生成元・native formatと未確認条件を渡す | exact GNU1.25 getproxy/retr.c＋init/host sourceは取得済み。HTTP auth emission serializerは別途未取得・未監査。Wgetのno_proxyはcurlの'*'/CIDRへ一般化しない |

### 共有 request-data stdin と役割の分離

新しい request-data stdin 判定は、caller が実際に fd0 をURL / sender rule等として使う条件を確認した後だけ呼ぶ。既存 network stdin backstop を一括で置き換えない。最後の fd0 redirection / heredoc が pipelineを置換し、同scope / 同pipeline edgeの最後のproducerを選ぶ。nested substitutionや無関係readerをmain producerと混同しない。stdout discard、printf `-v`、出力に使われないDATAは区別する。

対応printfは既知formatの `%s` / `%%` と有限escapeだけで、実際に出力へ使われる引数を既存 producer判定へ渡す。literal heredoc / here-string / ordinary constantは normal。selectedfile-backed inputをFORBIDDENにするのは、callerがallFiles=trueを指定するrole又は対応secret filename / source policyを証明した場合である。Wgetのordinary未検査URL fileはUNKNOWN、rsync sender filterのallFiles=trueはordinary selected fileもFORBIDDENと区別する。未知format / transformation / multi-stage / function / source / contextは UNKNOWN。literal backslash-zeroの後が非octalまたはendの場合だけNUL対応を追加し、width・`%b`・octal続きへ拡張しない。これは入力bytesのproducer proofで、native senderの実適用や成功の証明ではない。

通常の目的を同じtarget / operation / cwd / env / configで保てる対応literal・query・実inactive/local-onlyだけを代替にする。目的が保てない場合は不足条件をownerへ渡して停止する。secretを別場所へcopy、別client / hook無効化、設定全消去を自動的な同目的出口にはしない。

### 公式照合の範囲と取得段階

current sourceのknown value tablesはcurl137 / Wget80 / rsync35 / SSH21の273 entriesとして列挙した。optionのarityを知って消費できることと、送信role / executable source / unused DATAを認証できることを分ける。全273を一律拒否または全安全とする契約ではなく、未確認entry・implicitconfig・popt alias/exec・任意client/helper/body/runtimeは未認証として残す。

[OpenSSH ssh](https://man.openbsd.org/ssh)、[ssh_config](https://man.openbsd.org/ssh_config)、[V_10_3_P1 channels.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/channels.c)、[GNU Wget manual](https://www.gnu.org/software/wget/manual/wget.html)、[rsync manual](https://download.samba.org/pub/rsync/rsync.1.html)、[curl manual](https://curl.se/docs/manpage.html)を一次参照とする。live manual / installed version / pinned source / native DUMMY / actual Hook DATA / Claude dispatchは別段階である。GNUindividualpage fetch失敗やnative local selectorだけを取得成功・remote transfer証拠に昇格させない。

### 修正前の観測・原FAILと pending受入

独立測定は2026-10-14 22:35:16.321 JST、原4入力をfecdd / df463 / e456 / b6 / edeへ投入した20 observationsが全3ALLOW、broken0、各phaseのsource4は実Git blob bytesと一致した。これらは依頼前からのown-egress盲点であり、新R27退行と数えない。通常4pair / 真query4もcurrentALLOW。RemoteForward/include-fromの2対照と、同じroleのW / inline filter / activebaseの4条件を別取得し、旧public inputs / expectationsは書き換えていない。観測差やassertion数を独立脆弱性数に換算しない。

共有helper v1の33 API assertionsでは4FAILを保持し、v2の同33/33と別exact追加34/34を取得した。v3はliteral DUMMYのNUL bytes6観測と、新sourceのAPI39/39を取得した。v2の未対応NULは正直なUNKNOWNであり、normal3とsecret1の新期待を旧v2へ当てた4差も別保存した。botのtest-definition/source inspection、これらのprivateAPI測定、担当familyのHook DATA、今後の合成全件 / 実入口を混同しない。

R27 exact headのrequired CIは22:07:44.994 JST取得でrun38567973440 / job115865448678 / 実17step success。fullCRは22:11:43.648 JSTにall14/actionable0を取得したが、current-head bypass riskの一般文を別未解決として保持し、22:20:11.457 JSTのauthor clarification撤回を別証拠へ結び付けた。summary本文は未編集、生成由来は未取得、一般安全を認証したとはしない。その後22:22:44 JSTに新Codex4P1が投稿され、22:27:04.390 JSTのsnapshotで139total / 135resolved / 4openを取得した。過去CI / CR0 / 撤回をR28 sourceのfresh both0に持ち越さない。

担当familyの私有phaseはsourceと原recordを付して区別する。SSH privatev3はnew64＋old275の339対照、L1 17、reverse12を取得した。SCP synthetic childのforced-first ClearAllForwardings欠落により、初期v2がinactive generated RemoteForwardをFへ誤帰属したcode精度退行を保存し、23:16:29.517 JSTのv3比較で既存の独立Uへ戻した（aggregatedeny維持、ordinary2はA維持）。この修復を原review4の新ALLOWholeや、fixture前提の訂正と同じ件数にまとめない。

rsync privatev8はnew146/146・old110/110・L1 14・reverse6＋6＋5を取得し、helperv3をbindした。同sourceのliteralNUL正常2は、v2のunsupported-format Uを保存した上で対応した。full-merge `. -` のordinarystdinはsecondary file grammar未確認U、prefix無効の `.- -` / `.+ -` ordinaryはA、selectedfile-backedはallFiles policyFを維持する。literal invalid modifierに消費されたDATAの旧R12X128 Aと独立secretfilename textual Uも保持した。これらはfamily-onlyの測定で、別source・合成source・installed remote native・実dispatchの証明ではない。curl/Wget candidate-v6のfinite consumer表とfamily測定は次項のphaseとして受領した。合成sourceの合格へ持ち越さない。

### family契約と先行private合成v1（歴史cut）

23:49:14.346489 JSTにprivate合成v1を停写し、5709 bankを固定した。元5253のID / command / stdin / cwd / project / env / expectationは完全prefixとして保持し、new456 uniqueを追加、family間のexact duplicate1は同じ入力を再利用した。入力数・assertion数を独立脆弱性数へ換算しない。runner SHA256 `49e4098ef5848fe8b69019ad6fc98461c4992eea8a50b416c08760a034060dc6`、definitions SHA256 `b3f7db5ac2a52c698fe972f6e0ca4e3b5c73cef67310ab1c6e88db694e128f9c`。これは先行v1の取得cutで、下記の最新v3とは別のsource。ここに残す当時のPENDINGを後続sourceの合格へ読み替えない。

| 先行private v1 source（歴史cut） | SHA256 |
|---|---|
| block-secret-egress.cjs | `d7491aee3e7fb7811d55e7a991efad574e468eaba5a9c20a47f3e28464b60073` |
| lib/git-guard-common.cjs | `2f2a2796d55b6e60561f7010d55ee16d7dffc2798e7fd0cca4daade76214cfd8` |
| block-secret-git.cjs | `273f6be441ba85cb295303b929a8427e2a88e5f883800f9cd1d0f51f875c9664` |
| block-git-add-all.cjs | `8365d3652d9076aa5b40d21f57e41aaf0b4f453c5ff92f36db961580b7785201` |

SSHの最終secondary-source条件は、remote streamlocal pathの `%k` をfirst-selected HostKeyAlias / originalhostへ結び付ける。literal `%%` と区別し、他のactive tokenやconditional LocalForwardは必要条件不足のUNKNOWNにする。service-name portの名前解決・変換はrawsecret送信証明へ使わず、今回対応するnumeric port以外はUNKNOWN。ordinary `http` 等のservice名も止まり得る。意味を保つknown numeric portを確認できる場合だけ対応形とし、sourceやservice mappingが目的に必要ならownerへ不足条件を渡す。同tag `ssh -G` とliteral80の無害selector観測はnative forwarding / auth / server acceptanceの保証ではない。

curl rangeの最終条件は、HTTP native request-kindのGET / HEAD / default GETがRange、通常data POST / upload PUTがContent-Range。`--request`文字列だけで別のrequest-kindを証明しない。実際に選ばれた対応custom headerは自動range fieldだけを抑止し、そのheaderの独立payload判定は残す。multipart-only formは自動range branchがinactive、混合・不明body modesはUNKNOWN。FILE rangeはlocal seeking、FTP / SFTP等はHTTP rawheaderの証明を借りずUNKNOWNにする。

Wget input-fileはscalar-lastでCLI URLと合成し、`-`は実fd0、`/dev/null`やproved empty / closedはinactive。ordinary未検査URL fileはUNKNOWN、sensitive plain fileは対応policyでFORBIDDEN。generated HTMLの出力は直ちにURLになったとはせず、未証明link extractionをUNKNOWNにする。baseはplain URL linesとHTMLの両方へ作用する。Fを支える対応範囲はsimple literal relative plain line、またはnarrow literal `<a href="ordinary">text</a>`等の明示subsetだけで、未知HTML / attribute / title / data-href / comments / normalization / secondarybaseはUNKNOWN。known absolute/empty inputはbaseがunused。follow-tags / ignore-tagsはappend vectors、emptyでそのvectorをresetし、ignoreの除外をfollow intersectionより先に適用する。ignored/excluded anchorはbase fieldがinactive、未知vectorはUNKNOWN。privatev5のinactive tag controls2が誤Fになった原A期待 / FAILを保存し、v6で修復した。

#### curl generated / unproved consumerの有限26条件

これらは登録されたvalueがgenerated / unprovedで、実consumerが選択され得る場合だけUNKNOWNにする。ordinary static / 対応scalar・実overwrite / noURL / actualquery / inactive protocolは別条件。全273 entriesや全generated argvの一律禁止ではない。

| consumer群（26 names） | 選択・UNKNOWN条件とinactive対照 |
|---|---|
| proxy / proxy1.0 / socks4 / socks4a / socks5 / socks5-hostname | 共通last-value field。empty proxy / known noproxy `*` はproxy routingだけをinactiveにし、別sourceを消さない |
| preproxy / doh-url / dns-servers / connect-to / resolve | 前3はscalar、connect-to / resolveはappend。scalar後勝ちとempty doh clearを区別し、ordinary additive値で先行未知entryを消さない |
| ipfs-gateway | IPFS / IPNSまたは未知activation。known別protocolではunused |
| ftp-alternative-to-user / ftp-port | FTP(S)または未知/custom redirect activationでUNKNOWN。knownHTTPSとdefaultredirectではunused。fallback command・FTP address変換をrawsecret送信と断定しない |
| aws-sigv4 / haproxy-clientip | HTTP familyの認証・client metadata。generated formatや選択consumerが未証明ならUNKNOWN |
| login-options / sasl-authzid | potential IMAP / POP3 / SMTP / LDAP familyまたは未知redirect。knownHTTPSとdefaultredirectではunused |
| service-name / proxy-service-name | direct negotiate / anyauth選択、proxy routing・mode・auth / inheritedunknownを確認。known absent / disabled selectionはinactive |
| tlsuser / tlspassword / tlsauthtype / proxy-tlsuser / proxy-tlspassword / proxy-tlsauthtype | selected user/password pairとpotential TLS、proxy側はpotentialHTTPS proxy。compiledfeature / backend / auth / format / server acceptanceが未証明のUNKNOWN |

--nextのoperation境界は以前のactive判断を保持し、URLが無い同operationでは後値の選択を続ける。crypto engine/providerの限定loader consumerは取得済みだが、deployed backend / operation / source適用は未確認である。deprecated name・defaultTLS・local binding/filter/transformationなどの残余を安全認証にしない。通常生成route / credential/provider値が新たに止まる影響には、同じtarget / operation / 条件の対応static/knownscalarを確認し、同目的の代替がなければexactconsumer・source・cwd/env/config・未証明条件をownerへ渡す。認証値の置換やguard無効化を自動出口にしない。

Curl/Wget privatev6は23:28:59.939 JSTに227/227・broken0/source4stable、metadata16/16、single-edge5groups×3observationsを取得した。four groupsはrange / URL-list / base F→A、unprovedconsumer U→Aという停止の必要性、selectedstdout groupはnormal A→legacyFという精度であり、devnull A→A / original F→Fの未喪失もそのまま残す。23:31:52.652 JSTに元bankのWget140を同v6へ再投入しownEG / aggregate不変を確認した。new26名で旧bankを検索した0件はselectorの0であり、finding0や旧coverage証明ではない。これらfamily-only、helper39API、nativeDUMMY6を合成5709の合格やnative transport成功へ加算しない。

先行private v1のfamily測定とsource / 5709 bankは歴史phaseとして保全する。最新private v3の全件 / 元5253差分 / 実入口 / 公開CI・fresh受入は次項のPENDINGであり、先行phaseの合格をcarryしない。

### explicit proxy environmentの選択・通常対照

proxy private final-v3はcombined-v2をbasisとする別source（egress SHA256 `558ddd54b58b120b86162b1998efff3bc55b43988450af756286cf4591fa830d`）。原38 Hook DATAを保持し、12 selected opaque env conditionsのownEG / aggregate ALLOWをUNKNOWNへ接続した。curl8条件とWget4条件の観測であり、12独立脆弱性やnative送信12成功という意味ではない。最終50/50は2026-10-15 00:43:57.979 JST、actualcaptured Hook inputs150 / broken0 / source4・runnerstable。metadata12/12は00:45:05.838 JST、新caller反転8tuples / 16 observationsは00:47:06.947 JSTである。これらはproxy private sourceでの局所取得で、最新合成75b204 sourceの全件受入ではない。

curlはactual OperationConfigのproxy / preproxy文字列（empty含む）を先に選び、それが無い時にprotocol lowercase env / uppercase fallback / ALL proxyを探す。lowercase HTTP_PROXY相当は`http_proxy`のみで、uppercase `HTTP_PROXY`をproxy選択と誤認しない。empty envは`curl_getenv`でNULLとなり、upper / ALL fallbackを消さない。no_proxy→NO_PROXYはCLI --noproxy未指定時だけで、known '*' / finite ASCII exact-domain matchはそのfamilyをinactiveにする。CLI empty --noproxyはenv bypassを解除する。IPv6 / CIDR / percent encoding / IDNA / arbitrary normalization / backendを、この有限matchのproofから一般化しない。

Wgetのproxy selectorは未取得ではない。取得済みexact1.25 tarのretr.c1483–1553 getproxy / 1574–1580 no_proxy_match、init.c414–418 / config tableと、追加host.c1018–1043 sufmatchをhashへ結び付けた。use_proxy=false又はhost suffix matchが先にreturnし、HTTP / HTTPS / FTP / FTPSのopt setting又はlowercase getenvを選ぶ。empty値時のHAVE_LIBPROXY fallback、HTTP auth serialization、native URI format / handshake / actual送信は別未検査条件である。live GNU pageの取得失敗とcached exact consumer取得を混同しない。curlのuniversal '*' / CIDR仕様をWgetへ持ち込まない。

反転はcurl callerだけ、Wget callerだけを別copyで外したsingle-edgeで、それぞれoriginal target U→A、他family U、ordinary A、既存body Fを保持した。元df463の62 check-removal器具は2 single legacy＋60 compositeであり、今回の必要性へ加算しない。PE-W10の初prospective A / actual既存execute-config Uは原RAWを残し、新private期待Uを別immutable adoptionへ記録した。proxy v1/v2のFILE URI / empty authorityとnative --no-location・disabledproxyのnormal overdeny FAILも保存し、v3で局所修正した。source / config / argvの別guardを解除するためのproxy clearではない。

### SSH numeric config-dumpの限定precision

OpenSSH V_10_3_P1 ssh.c424–433は数値addressを扱い、CanonicalDomains482–489より前にreturnする。privateSSHv9はeffective Hostname又はdestinationのbytesがfull literalで、percent tokenがなく、`node:net.isIP`が4/6を返す時だけ、config dumpのselected CanonicalDomainsをunusedとして除外する。Hostnameと他のsource / query / argv / context条件は残す。full literal 127.0.0.1 / ::1 / explicit Hostname=127.0.0.1の通常対照はこの条件で通る。short127.1、percent / alias / implicit config / generated host / split / glob / tilde / brace / arbitrary DNSのproofへ拡張しない。

v8 rawと他32 controlsを保持したままv9を別sourceへ修復した。raw numeric edgeは2 observations / 1 FAILであり、初伝達の「2FAIL」はunit訂正として残す。v9 focused12/12＋same32/32 / broken0 / source4stable、metadata8/8、numeric-domain conjunctだけのprecision reverse4tuples / 8 observationsを取得した。reverseは過拒否を戻す精度効果で、security stop必要性とは別である。未知hostのL1がquery binderへ到達するという初harness前提は、実際の先行 -F / source stopを確認して訂正し、原scriptを保持した。native DNS / auth / packet / transportを測定したとはしない。

元5253内のR10EG035はinput / ID / contextを変えず、A→UNKNOWN期待を理由付きで採用した。unknown explicit -o source / hostname / DNS条件がconfig dump以前に未証明であるためで、後ろの-oが前の-Gを消費したという説明ではない。known consumed value、実early V / Q、ordinary query / inactive sourceは個別に保持する。DNS名が目的に必要なら数値IPへの置換を自動出口とせず、same target / operation / source / configの不足をownerへ渡す。

### 未確認の一次role台帳（7行、追加調査停止）

残余台帳v5はproxy2行のprivate修復と、将来未確認5行を分ける。全7行を新findingやnew Hook inputsへ換算しない。Git174（171 catalog / 3 offcatalog）、GH196 builtin leaf / 32 containers、network273 registered value namesも別のinventory unitであり、runtime操作数ではない。userが閉じた93への新依頼 / retry / 3 file作成は行わず、3-file facts / intent / artifacts構造は参照だけとして保持する。

| row / 状態 | 取得済み一次consumerと未確認条件 | 通常作業・終了基準 |
|---|---|---|
| RP01 curl proxy env — private修復、合成/public pending | exact8.7.1 proxy/env consumer取得、上述50/metadata/reverseはprivate558ddd。URI/auth/backend/送信未証明 | actual ordinary / unused / clearの同目的対照を維持。合成source全件・公開CI/freshを別取得する |
| RP02 Wget proxy env — private修復、合成/public pending | exact1.25 getproxy selector取得済み、HTTP auth consumer未取得・未監査。libproxy/SSL buildと実transportは未確認 | lowercase/opt優先と実no-proxyを保持。独立execute/config source Uを残す |
| RP03 curl crypto engine/provider — FUTURE_UNVERIFIED、追加probe停止 | exact8.7.1 tool_getparam / tool_operate / openssl.cの限定loader consumerは取得済み。deployed engine/provider/backend/operationは未認証 | 普通のengine名だけでFにしない。same operationのdefault/inactive sourceと、実active loader/sourceを有限に証明してから判断する |
| RP04 rsync popt defaults/aliases — FUTURE_UNVERIFIED、追加probe停止 | GNU3.4.1 options.cのpoptReadDefaultConfig consumer取得。popt libraryのfile/error/alias仕様とinstalled Apple applicabilityは未確認 | GNU pathをApple binaryへ一般化しない。actual implementation / owned config / inactive roleが証明できなければ対応済としない |
| RP05 rsync implicit CVS/per-directory ignores — FUTURE_UNVERIFIED、追加probe停止 | exact3.4.1 exclude.cでHOME/.cvsignore/CVSIGNOREとsender又はprotocol<29のconditional serializationを確認。current side/protocol / source / Hook/nativeは未取得 | modern receiver elision・local-onlyをfile送信へ誤分類しない。active file-backed/source relationが実条件で立つ時だけpolicy判定する |
| RP06 rsync remote program/options — FUTURE_UNVERIFIED、追加probe停止 | exact main.c / options.cのlocal argument constructionは取得済み。remote interpreter/version/context/actual selected word / executionは未証明 | local / daemon / remote-shellを分ける。ordinary default・consumed DATA・orderingを保ち、実active sourceの不足をownerへ渡す |
| RP07 current/deprecated option/backend compatibility — FUTURE_UNVERIFIED、追加probe停止 | exact8.7.1 parser tableとPARAM_OPTION_UNKNOWN境界は取得済み。newdeployed path/version/build/current consumersは未認証 | recognized nameをnativevalid operationとしない。未対応nameの存在だけで一律拒否せず、actual active conditionを確認する |

Pinned一次参照は[curl8.7.1 lib/url.c](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/lib/url.c)、[tool_operate.c](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/src/tool_operate.c)、[proxy](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/docs/cmdline-opts/proxy.md) / [noproxy](https://raw.githubusercontent.com/curl/curl/curl-8_7_1/docs/cmdline-opts/noproxy.md)、[GNU Wget1.25.0 source archive](https://ftp.gnu.org/gnu/wget/wget-1.25.0.tar.gz)、[OpenSSH V_10_3_P1 ssh.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/ssh.c)、[rsync3.4.1 options.c](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/options.c) / [exclude.c](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/exclude.c) / [main.c](https://raw.githubusercontent.com/RsyncProject/rsync/v3.4.1/main.c)とする。原archive/consumer SHAとactual取得cutを別receiptに保存し、未保存の正確web取得時刻はnullとする。live manual・pinned source・installed binary・native DUMMY・Hook DATA・actual入口を相互に代替しない。

### 最新private合成v3 / 5846 bank — 全件結果PENDING

2026-10-15 01:02:33.777100 JSTにprivate合成v3を停写した。元5253のID / command / stdin / cwd / project / envはexact prefixとして維持し、R10EG035の理由付き期待変更1を別採用した。new593はrecorded signatures（cmd / stdin / cwd / project / env）の区分で、独立finding数や全runtime unique数ではない。runner SHA256 `2ab70a47ae3d977097c242caec8f2ab7250c4da27d17074ddefbaf6e5bb3dba5`、definitions SHA256 `f79acd40ddfc25f7dd12382ff45ff2b2e954493cd192db454308f5702543a451`。

| 最新private v3 source | SHA256 |
|---|---|
| block-secret-egress.cjs | `75b20493c558e73853e05b08e38840979df8f7842da04407c177f3c4378fad34` |
| lib/git-guard-common.cjs | `2f2a2796d55b6e60561f7010d55ee16d7dffc2798e7fd0cca4daade76214cfd8` |
| block-secret-git.cjs | `273f6be441ba85cb295303b929a8427e2a88e5f883800f9cd1d0f51f875c9664` |
| block-git-add-all.cjs | `8365d3652d9076aa5b40d21f57e41aaf0b4f453c5ff92f36db961580b7785201` |

このstage-v4では5846全件結果、same-bank old-head差分、合成sourceでの合同API / reverse、R28 actualCLI入口、新公開head / source17 / requiredCI / fresh both / thread0はPENDINGである。running processやfamily50成功を全件合格へ昇格しない。R27 source-v5の実入口summaryは2026-10-14 21:45:14.386 JST cutで5attempts / PASS1 / NOT4、actualBash dispatch1 / ownedEG UNKNOWN denial1。これはGit refspecの1入口だけで、Wget / SSH / Ncatとterminal-help normalはbefore-hook NOTでありR28 sourceへのdispatch proofではない。旧whole-tool strictFAILも、そのsource / 試行と結果のまま別保存する。拒否後のCLI/API再試行やモデル / trust / hooks変更を行わず、93 CLOSEDを別席の再試行へ読み替えない。

実URI / auth / binary version / compiled backend / DNS / client / server / transportを未検証のまま自動Goal成功にしない。全件取得後はnew stage-v5にactualcut / fixed source / resultsを結び付け、finished stage-v4や過去sourceの記録を後から書き換えない。このdraftではLIVE / Git / GH / external report / FINAL / ZIPの変更を行わない。

### stage-v5: 同private合成v3の実測チェックポイント

stage-v4のPENDING cutと原fileを保持した上で、親の全件結果を新しい取得として読取り確認した。fixed egress SHA256 `75b20493c558e73853e05b08e38840979df8f7842da04407c177f3c4378fad34`、common / secret-git / add-allとrunner / definitionsは前項のprivate合成v3と同一。全5846 Hook DATAは2026-10-15 01:02:33.905→01:11:59.760 JSTに実行され、5846/5846 / failed0 / broken0。source4とrunner / definitionsは前後stable、三HookそれぞれへのspawnSync input argumentのSHAを計17,538件捕捉した。これはkernel stdin bytesのcapture又はClaudeの実dispatchではない。結果JSON SHA256 `2c0d97cafc72246275c587aa90af658030ea3b2e6a557cdb18896c611340a6c9`。

元5253のID / command / stdin / cwd / project / envと順序は完全保持。旧R27実取得5253結果との比較は再実行ではなく、既存old実測とnew実測を同IDで再計算したderived比較（2026-10-15 01:20:42.020214 JST）。aggregate / 担当Hook / reason prefixの差はR10EG035のA→UNKNOWNだけで、D→Aは0、他5252は一致した。旧期待を理由無しにdenyへ替えず、この1adoptionの元ALLOW / 原inputと不足条件を保存する。新593recorded signaturesの追加、assertion数、差分数は独立脆弱性数へ換算しない。

正常14対照は2026-10-15 01:05:32.041→01:05:33.469 JSTに同sourceへ実投入し14/14 ALLOW / broken0 / source4stable。これはcurrent bankのproposed normal controlsで、author / 93の日常作業の実行・確認ACKでもactualCLI / auth / networkでもない。正常14を全5846の別の14unique実行保障へ加算しない。有限独立確認は01:06:39.262 JSTにexisting definitions / preserved private controlsの28 DATA / 84 Hook spawns、28PASS / broken0 / source4stable、material0。original4のownEG FORBIDDEN、selected proxy12のUNKNOWN、numeric-domain unused2とordinary8のALLOW、既存payload2のFORBIDDENをそのfixture / sourceで確認した。28にはpublic bank外のnormal private stringsも含むため、全5846のcoverageやruntime全安全へ昇格しない。

共有stdin判定のfile分類はcaller role別である。rsync sender ruleのallFiles=trueはselected ordinary local file内容も既存file-backed禁止とし、literal heredoc / known constant stdoutはnormalを保つ。Wget URL-listはraw body uploadではなく、ordinary未検査URL file / file-derived URL選択はUNKNOWN、対応sensitive plain source / producerは既存policyでFORBIDDEN。HTML / base / secondaryfile / activeprotocolの未証明は別UNKNOWNであり、共有helperのFを全callerへ一律に当てない。

このチェックポイントは有限local source / component acceptanceである。public L1/API138の同17source再取得は親がLIVE適用後に行う予定で、この段階では未取得。commonのbyte一致を新public測定と呼ばない。R28 actualENTRY、公開current17source binding、required CI、fresh both review / thread0は依然PENDING。R27の4 NOT / source53でのGit入口1PASSは歴史のままで、新sourceへの再試行・carryをしない。native URI / auth / DNS / binary版 / compiled backend / server / transport / allclient runtime proofは未成立。残余tableの2proxy修復と5 FUTURE_UNVERIFIED停止のscopeを拡張せず、userが閉じた93の新task / retry / 3file作成も行わない。全件成功だけからGoal / FINAL / ZIPを自動成立させない。

## R27: 送信値と session / protocol の条件

R27は、公開 `ede1302e` に対する正式Codex review5516746744（2026-10-14 19:49:10 JST）の4 P1と、その送信role・実行mode・選択順を変える有限な対照を扱う。修正と試験は固定した私有sourceで先に行った。4 findingには5 literal入力があり、Wget inline body、SSH SetEnv / SendEnv、Ncat / Telnet認証・login metadata、Git pushのdestination refを分ける。2026-10-14 21:25:03.236937 JSTに私有合成v5を停写した（egress `53cc956d`、common `2f2a2796`、add-all `8365d365`、secret-git `273f6be4`）。bankは5253件＝元5044 input byte保持＋新unique209件である。元期待のうち7件を下記の明示scopeへ理由付きでALLOWからUNKNOWNへ採用し、旧入力 / 旧期待 / 原FAILを保存した。v3の5229 / 7FAIL、v4の5235 / 8FAILは各歴史sourceの結果で、v5の合格へ持ち越さない。固定v5全5253は21:35:06.794 JSTに5253PASS/fail0/broken0/source4stableを取得した。新公開headのCI / fresh review / thread受入はこのlocal結果とは別で、文書更新cutでは未取得である。

### 対応条件・停止理由・通常作業への影響

| 守る対象 / 適用条件 | この境界の判定 | 判断不能になる条件 | 通常作業への影響 | 同じ目的の対応形式 | ownerへ渡す不足 / 出口 | 試験境界 |
|---|---|---|---|---|---|---|
| Wgetのselected inline body / header / User-Agent / Refererとprotocol-selected credentials / URL | 対応active roleに結び付いた秘密filename読取stdoutはFORBIDDEN。ordinary literal / 対応scalar、上書き・reset・unused roleはこの新edgeで停止しない | 未証明producer、split / arity / grammar、methodとbody familyの不整合、未確定target / proxy / config / contextはUNKNOWN | 通常生成bodyや認証値、未知proxy設定も止まり得る。file upload・設定・askpassの旧条件は残る | 同じtarget / method / configで意味を確定できるordinary literal / 対応scalarを使い、実際に無効なfamilyを確認する | 選択body / header名 / credential family、protocol、target、producer、cwd / env / configと未解釈条件を添える。代替が無ければowner判断を求める | 私有family / L1 / 単一edge reverse、最終合成sourceのL2 / normal対照を別取得。literal DUMMY selector観測から実秘密・外部送信・認証成功を作らない |
| Ncatのselected proxy-authと `NCAT_PROXY_AUTH` fallback、Telnetのselected login / environment metadata | 実際に使うprotocol / operation / sourceが対応済みで秘密由来ならFORBIDDEN。known ordinary / unused / 選択から外れた値は独立した旧条件を維持 | proxy / auth / Telnet implementation・選択login・継承値の出所・export / modeを解けなければUNKNOWN。未知envを非秘密として扱わない | stdinを `/dev/null` にしてもargv / env認証値は別に確認するため、通常の生成credentialsやloginも停止し得る | 同じ接続対象・実protocolと認証条件で対応ordinary値を使い、選択されないenvは実unset / env removal等で条件を確認する | CLIとenvの選択優先、consumer、protocol / runtime版、producerを添える。認証入力 / trust fileをraw uploadと混同しない | Hook INPUT DATAのrole / source対照と必要最小実入口を分ける。全socket client・任意protocol / server acceptance / native認証は保証しない |
| SSHのactive sessionに渡すSetEnv / SendEnv、forced PTYで選ばれるTERM | active sessionの対応送信値で秘密由来が証明されればFORBIDDEN。known ordinary / 未export local / actual removal / inactive sessionはこのfamilyの対照 | 構成値・percent / env expansion・未知inheritance・SendEnv pattern / selection・未対応合成producer・session / TTY modeが解けなければUNKNOWN | stdinを止める `-n` だけではsession envを止めない。通常の生成envやPTY TERMも影響する | 同じtarget / session / PTYを維持する対応ordinary値、実export取消・unset / env removal、同目的の実queryを確認する | 選択name / value / producer、export / env操作順、session / PTY、target / configと未知条件を渡す。`-N`への変更は同じ処理目的を満たす場合だけ検討する | same-tag一次sourceのsession条件、L1とown-egress L2、normal対照、reverse、実入口を分ける。原reviewの `-N` をenv送信成立の証拠にしない |
| Git pushのdestination refname / deletion target。local source ref・push-optionとは独立 | 実dst値に結び付いた秘密reader stdoutはFORBIDDEN。ordinary dst / 対応scalarは他のrepo / source / refspec条件を維持 | 未確定src:dstの分割・argv / wildcard / source / context、selected config refspecや明示receive-pack sourceの未検査はUNKNOWN | named remoteでもdst metadataは送信先へ届くため、通常生成branch名 / deletion targetも止まり得る。local srcのUNKNOWNは独立guardの責務 | 同じremote / dstの対応literal / scalarを確認する。push-optionやlocal sourceを変更して代わりの成功を作らない | exact refspecのsrc / dst、選択remote / protocol / config、receive-pack / helper source、producerを渡す | 原入力 / force / delete / 複数refspec / src-only / ordinary対照を別に保持。config fallbackと明示receive-packの選択条件を下記へ限定し、この有限測定から全push安全を称しない |

### exportと選択値を保持する

生成値とexport属性は別の情報として保持する。prefix assignment、実export / `set -a`、継承、後のassignment、`unset` / `export -n` / `env -u` / `env -i`の順序を選択consumerへ渡す。未exportのlocal値をchildへ送られた値としない。既知ordinary literal / 対応scalarの上書きは確認済みの値に置き換えるが、未対応の加工・append・composed sourceで生成元を失った場合はUNKNOWNを保持する。family局所更新がGit identity / pager / startup等の別familyのproofを消したり、任意inheritanceの安全証明になったりしない。 HOME / GIT_CONFIG_GLOBAL等のsemantic root markerは未検査情報であり、generic outbound DATAではopaqueなUNKNOWNとして保持する。family専用SOURCE判定を変更せず、実knownemptyやexplicitordinaryのproofは維持する。内部marker文字列を実送信するordinary値と読み替えない。

Ncatは明示proxyを選ぶconnect modeと対応HTTP / SOCKS4 / SOCKS5を確認する。CLI proxy-authはemptyも含めenvの `NCAT_PROXY_AUTH` fallbackより優先し、重複proxy / type / authはerrorで後勝ちではない。no-proxyではこのauth familyはunused、HTTP proxyserverのlisten authはlocal verificationでありこのoutbound roleに含めない。recv-only / `-z`でもproxy negotiationは残る。未知・非整合なmode / argv / target / sourceはUNKNOWNを維持し、HTTP407 / challenge / schemeやSOCKS5 negotiated method・server acceptanceを実測済みとしない。

GNU Inetutils2.8 Telnetの明示 `-l` / `--user`は後勝ちで、選択USERのENVIRON exportは、後の `-K`によるAUTHENTICATION autologin解除と別である。HOST無しではこのroleの接続は無く、実terminal query・値に消費されたhelp DATA・ordinary / 無関係reader / 後勝ちUSERは別対照にする。implicit USER autologin / defaulttelnetrcや他Telnet / nc実装のauthは残余で、ownerや別guardが不明な範囲を保護済みとしない。sourceが存在するだけでは送信payloadにせず、stdin inactiveだけでargv / env metadataを許可しない。

### SSHのsession envと接続metadataを分ける

OpenSSH V_10_3_P1では実 `-N` がSESSION_TYPE_NONEを選び、session open / callbackを省略する。SetEnv / SendEnvのenv requestはsession setup内にあるため、実 `SessionType=none`、対応する `-W` forwarding、terminal query等のsession inactive条件を解ける場合、このenv familyを送信としない。`-n`はstdinの制御であり、active session envを解除する条件ではない。選択login / destination metadata、ProxyCommand / Match exec / provider / config / remote command等の独立条件は残る。

原reviewの `-n -N -F none -o SetEnv=...` はこの版のsession env経路がinactiveであり、outer shellでreaderが評価されることと、SSHがその値をserverへenv requestとして送ることは別である。active-sessionの別入力を元原入力へすり替えず、実際のserver AcceptEnv / 認証 / session成功 / compiled binary版も未取得の条件として残す。SetEnv directiveのfirst selectionと、その中の同名tokenのfirst valueを保持する。複数generated config tokenの成分spanが解けない場合や、percent / environment expansionはUNKNOWNにする。SendEnvは確認したname patternを順序付きで追加し、negative patternで先行selectionを除去する。name選択と値の出所 / exportは別で、unknownexport・不明なinheritanceが残ればUNKNOWNを保持する。

forced `-tt` のactive PTYはTERMをSendEnvとは別に消費する。単一 `-t` のactual TTY条件をこのHookが証明していないgenerated TERM、またはRequestTTYが未解決で生成TERMを選ぶ可能性が残る場合はUNKNOWNとする。exact force / yesを解けないことをunusedの証明にせず、known ordinary TERM・実 `-T` / no-session / queryは対照として保持する。TTY / native認証 / server受入を実測済みにしない。query / 対応control-operation / no-sessionのinactive対照もこのenv familyだけの証明で、接続metadataやsourceの既存条件は残す。

### Git pushのdst・設定fallback・実行source

対応refspecではdestination成分のproducer spanだけを送信metadataへ結び付け、無関係なlocal source成分のreaderをdstの秘密読取としない。force prefix、delete target、複数refspec、dstを省略したsame-name推定を別roleへ分ける。src:dstの分割・動的な成分境界・argv個数・operation/contextが確定しなければUNKNOWNを保つ。 この版で未登録のstatic push optionが残る場合、新generated metadataのFORBIDDENをUNKNOWNへ下げて停止を保持する。native有効argvを確認していないoptionを確定active操作へ昇格させず、対応flagと既存独立negative条件は残す。source refの既存no-verify / argv / object guardを、このdst分類で解除しない。

明示CLI refspecも選択builtin refsも無い場合だけ、対応する明示 `remote.<選択remote>.push` configuration sourceをfallbackとして選ぶ。別remoteの設定と、実CLIで上書きされたrefspecはこのfallbackで送信値としない。対応 `-c` / `--config-env` / configuration envの選択値もproducer / export / contextを保持し、不明なremote・selected valueはUNKNOWNにする。この接続は暗黙default config全体や全push.default / remote設定を読んだ証明ではない。

明示 `--receive-pack` / `--exec` はdst DATAではなく実行program sourceである。対応default `git-receive-pack` 以外でlocal / SSH / named / 未確定transportが選ぶsourceはUNKNOWN。確定literal HTTP / git URLかつURL rewriteが無い対照では、このprogram familyだけunusedとする。未知rewrite / config-root / transport contextと独立helper条件を保ち、HTTPという名前だけでall sourceを解除しない。同じ目的を保つ対応default programが無ければ、program / source / cwd / env / config / transport条件をownerへ確認する。

### Wgetの値の選択と版の限界

Wget 1.25.0の有限照合ではpost / body / method / scalarの後勝ち、case-insensitive同名headerの後勝ち / empty clear、異なるheaderの保持を区別する。明示User-Agent / Referer / Authorization headerは対応するbuiltin familyだけに作用する。HTTP-specific credentialsはgeneric credentialsより優先し、FTP-specific値はFTPのconsumerへ分ける。generated proxy credentialsの実contextを証明できなければUNKNOWN、実no-proxyはそのfamilyだけのinactive対照である。

body-dataだけでmethodが無い場合やpost-dataとmethod / 別body familyが競合する場合、未対応grammar / option / missing value / splittingは、新producerのFORBIDDEN成立を支えない。実help / versionと、値に消費されたhelp-looking DATA / `--`後のroleを分け、既存file / source / 内側実行の独立条件を残す。literal DUMMY HTTP loopbackのselector観測はHTTP404等の有限観測で、HEAD / spiderという名前だけでbody unusedとしない。Wget以外のclientや全版・暗黙config・proxy / auth / serverの安全認証には広げない。

### 元5044期待の7件を変更する通常影響

7件は既存input / ID / stdin / cwd / project / envを維持したscope採用で、7独立脆弱性や入力書換えではない。egressがUNKNOWNを追加するため、既存AGの対応DATA allowanceが維持されても全体は停止する。原FAIL / old expectationと、同目的のknown-value / default-program正常7対照は別保存する。

| 元ID / 通常作業 | 新しい停止条件 / 同目的の出口 |
|---|---|
| R14EG-wgetdynamicheader / R14EG-wgetdynamicconsumed | attached / separated headerの未知変数値は、消費DATAでも送信headerのname / bytes / sourceが不明なのでUNKNOWN。同target / configで対応literal・既知scalarを確認し、不足があればownerへ渡す |
| R18AGA11 | 実 `--`後の未知one-word refspecも推定dstを選ぶためUNKNOWN。no-verify optionに読み替えず、同remote / refの対応literalを確認する |
| R18AGA13 | `main`に未知suffixを結合した推定dstのbytes / sourceはUNKNOWN。同目的の確定dstまたは対応proofを確認する |
| R18AGA15 / R18AGA16 | receive-pack / execに消費される `--no-veri`というknownliteralはflagではなく選択program。未検査program / source / transport条件はUNKNOWN。同目的を保てる対応default programが無ければowner判断を求める |
| R18AGD08 | explicit dst componentの未知REFはUNKNOWN。local src HEADと混同せず、同dstのknown REF / scalar proofを確認する |

値を印字するだけのDATAと選択された送信値、対応default programと未知customprogramを分ける。ownerへ渡す対象・操作・cwd / env / config / source・不足情報を保ち、copyやhook停止を自動の同目的代替にしない。

### R27の版と検証境界

固定v3の全bank開始後、未解決RequestTTYと生成TERMの取り残し、generic outboundenvへのsemantic root markerの誤ったliteral昇格、新metadataとunknown push flagのcategory精度を有限readbackで確認した。原before input / source / metadata / FAILを保持し、v5で上記UNKNOWN契約へ局所修復した。stored assignmentを後からexportした値でsource freshnessの証明が無い場合は、対応readerらしく見えてもFORBIDDENとせずUNKNOWNを保つ。fresh assignment-after-exportとordinary literalは別の対照である。これはprivate componentの分類契約で、全env加工 / 任意state / 実送信の証明ではない。

Wgetは1.25.0、socketの一次照合はNmap pinned source / 7.99SVN docsとGNU Inetutils2.8、SSHはOpenSSH V_10_3_P1に限定する。Ncat / Telnet installed native operationはこの席で未取得であり、source / manualのconsumer選択をcompiled binary / protocol negotiation / remote ENVIRON acceptanceの成功へ持ち越さない。Git pushのconfig fallback / receive-packは上記のfixedv5選択条件に限定する。固定sourceの全件測定と実入口の結果は下記の取得範囲に限る。公開headのCI / fresh review / thread受入は別に確認する。

秘密由来の証明は対応filename規則・readerとselected valueへの生成元の関係に基づく。ordinary filenameやscalarの許可はファイル内容の安全認証ではない。未証明producerを「秘密ではない」としない。実credentialsをDUMMYに置換することや別場所へのcopyは、同目的を満たす自動の代替経路ではない。

R27の固定v5 source4 / bank5253は上記cutで確定した。21:03 JSTのowner再開後に、global L1 / L2 / reverse / 実CLI / newhead CI / fresh review / threadを各取得source・時刻で別に受ける。後続のfixed-source proofは以下の範囲で取得した。実入口NOTと公開後のCI / fresh / thread未完を、local source成功で埋めない。Wget・socket・root SSH / pushの各私有試験成功はphaseとsourceを付し、別familyや合成sourceへcarryしない。旧R26のCJS4 / 5044 reuse、parity12 / DUMMY25 / native8 / reverse2と同headCI / fullCR0は履歴であり、R27の合格を意味しない。

原R23のwhole-tool SCP strictFAIL（user-default Python guardの干渉）とAPI-before-hook NOT、R24 / R25の未実施negativeは分類を変更しない。API前段の拒否をhook成功に数えず、拒否済み入力の迂回・再試行で件数を増やさない。owner不在・別guard担当不明の範囲を保護済みとせず、任意shell / program / 暗黙設定 / 通信 / 認証 / 全lifecycleを安全とする保証は加えない。module責務の全面refactorはこの席で実施していない。

### R27 fixed-v5で取得した検証と未検証

fixed-v5全5253は21:26:52.058〜21:35:06.794 JSTに5253/5253・failed0/broken0/source4stableを取得した。5253の元5044INPUTは維持し、7旧期待の採用は上記の根拠とnormal7対照に限定する。3hookへの各spawnSync input SHAも記録したが、constructor / 実spawn引数のbytesでありkernel stdin readbackやClaude Codeのdispatch観測ではない。

このsourceの公開契約はanalysis126（元114 prefix保持＋新12）とfilename parity12の138PASS/fail0である。先行v1の125/126はHOME DTO fieldの試験前提誤りでparity未実行、v2のanalysis126成功＋parity dependency-file失敗も原logと共に保持した。v3ではbyte不変09dc wrapper dependencyをcopyして138を実測した。私有停止API6をこの138へ加算した主張はしない。

独立fixed-v5 focused83・L1 metadata12・reverse3 feature（target9 / control21）はsource4stableで別取得した。7旧入力のnewU＋normal7Aをv5で再確認し、knownempty2は21:37:46.147 JSTに後から独立再取得した。83を85へ改名せず、初knownempty説明と後測のchronologyを分ける。family-only Wget57、socket55と各旧source/reverseは、それぞれのphaseとして残す。

新DUMMY実入口は21:44:22.258〜21:45:14.386 JSTの5試行で1PASS / 0FAIL / 4NOT_EXERCISED。fresh local namedoriginへのGit dynamic refspecだけ、exact Bash1・own EG1のUNKNOWN deny・status0、同caseのhookstarts3を確認した。Wget body / SSH SendEnv / Ncat proxy auth / ncathelpはAPI cyber/refusal/api_errorでBash前・ownedHook0、再試行していない。正常helpのeffects=falseは期待markerが現れなかった意味で、状態のmutationではない。全markers absent / 全fixture状態・source4・settings不変で、normal実入口は未検証として残す。1PASSを他4件のdispatchやnative auth / transport成功へ持ち越さない。


同じ5253定義と旧edeのsource4を結び付けた比較では、旧5044は17:50:34.033〜18:06:35.216 JSTのR25実測fixed列をbyte一致で再利用し、新209だけ21:50:59.455〜21:51:20.161 JSTに旧sourceへ実投入した。109の観測差＝100 ALLOW→deny＋9 hook / 理由のみの差、deny→ALLOWは0、broken0。これは独立脆弱性数ではない。元ID / command / stdin / cwd / project / env定義は維持し、literal temporary pathと取得時刻は別である。旧5044のstdin証拠は当時のconstructor計算を実spawn captureへ昇格させず、過去の全ambient environmentも取得済みとはしない。

親は21:48:26.234 JSTに有限private source受入を記録したが、全sender/runtime/lifecycleの安全認証ではない。LIVE適用・新公開head・requiredCI・fresh both / thread0・記録物QA / FINAL / ZIPの受入は別gateである。旧SCP strictFAIL / 過去API前NOTも元source/試行のまま保持する。

## R26: Vault の staged filename 判定 error

R26 は `safe-vault-push-perm.sh` の staged filename collector に限定した条件修復である。公開692d6815のfullCR review5515805932（2026-10-14 18:27:41 JST）、Security Major comment4269035150を受け、first grepがerror・無出力でも後段nonmatchに隠れる経路と、upstream `printf` failureをDUMMYの抽出fragmentで確認した。依頼前df463a91のfilter / assignmentにも同種maskを観測したため、R25が新しく開いた穴とは扱わない。df463の旧filterと現NUL collectorは別sourceで、全wrapperの同値性は証明していない。

| 守る対象 | 判定結果 | 判断不能になる条件 | 通常作業への影響 | 同じ目的の代替・維持する対照 | owner への出口 | 試験する境界 |
|---|---|---|---|---|---|---|
| **Vaultのstaged filename判定とsecret gateの副作用** | 正常な0/1は従来のmatch / nonmatchを維持し、確認済みsecret matchは既存禁止へ。`printf` nonzero、どちらかのgrep status >1、3段のstatus不足はUNKNOWNとして停止 | filenameの検査に必要なproducer / predicateの終了状態を確認できない。既存Git読取失敗 / 不完全NUL / LF filenameも独立して停止 | 普通のfilenameでもtool / PATH / runtime / 読取errorで停止し得る。UNKNOWNでは部分offender一覧を公開せず、このsecret gateでpartial restore / unstageをしない | 同じrepo / staged集合を保ち、producer / grep / 読取条件を直して検査をやり直す。正常match / nonmatch・allowlist・filename規則は維持。他のrepo / copy / hook停止を代替へしない | repo / staged対象、tool version / PATH / LC_ALL、失敗stageとstatus、input境界と不足proofを提示。原因を解消できなければownerが同目的・同条件の対応経路を確認 | success / else両分岐の即時PIPESTATUS、firstgrep無出力error / printf failure / 後段error、late error前のsecret、正常0/1、offender非公開・restore呼出し0・capturecleanup |

3段の`PIPESTATUS`はpipeline直後にsuccess / elseの両分岐で保存する。`pipefail`とpipeline全体のstatus1だけをerror不在の証明にしない。全filenameとNUL境界、各stageの正常性を確認した後だけoffender配列を公開する。確認済みsecretは従来どおり該当名を単一argvでunstageして停止する。ここでのUNKNOWNはwrapperの非zero停止で、CJS PreToolUseのJSON / reason prefixをwrapperへ追加した契約ではない。stage / rebase等の先行wrapper処理まで状態不変だとする説明でもない。

[GNU Bashのpipeline資料](https://www.gnu.org/software/bash/manual/html_node/Pipelines)は、pipefail時のpipeline全体の結果を右側で最後にnonzeroとなったstageのstatusと説明する。[PIPESTATUSの資料](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)は直前のforeground pipeline各commandのstatus配列で、その後のcommandでも更新されることを示す。[GNU grepの終了状態](https://www.gnu.org/s/grep/manual/html_node/Exit-Status.html)では通常0がmatch、1がnonmatch、2等がerrorである。ここでは公式domainのindexed excerpt部分を参照し、0/1とerrorを各stageで分ける契約をinstalled Bash3.2 / grepのDUMMY観測で照合する。現在のGNU文書から全Mac版の挙動を推定しない。

### R26の検証境界

2026-10-14 18:42:13 JSTのnative観測はmacOS Bash3.2.57 / installed BSD grep2.6.0-FreeBSD / Git2.54の固定DUMMY fragmentで、realVault / fullwrapper / commit / push / 実秘密 / 外部通信は実行していない。18:34台のGNU / Bash公式page timeoutは原未取得として保持する。18:57〜58台に公式domainのindexed excerptを別取得したが、direct fullpage openは再び400 / timeoutで、完全なmanual取得やMacのcompiled source確認ではない。private candidateでは既存parity8契約のprefixを保持し、error境界4を加えた12試験を取得した。19:00台の別DUMMY sandboxではlocal bare / clonesでwrapper / installer25試験を取得したが、実Vault / 実外部通信の受入ではない。19:03台のLIVE parity12の取得、変更Vault sourceの公開CI / fresh reviewは各cutの別証拠として確認する。

R25のhistorical128は解析114＋旧parity8＋private denyAPI6である。byte再利用する範囲は変更しないCJS4本 / 公開5044 / 解析114 / private denyAPI6に限定する。変更するpublic parityは旧8契約prefixを保持した12で、旧8の成功はhistoricalのまま保存し、128全体を新predicateの成功へcarryしない。

R26の私有検証cutでは、private09dc sourceのDUMMY sandbox wrapper / installer25PASS（19:00:17取得、isolated HOME / local bare / clones、実Vault / actual user HOME / networkを使わない）、LIVE parity12PASS（19:01〜03台の取得、test completion時刻は独立未取得）を別証拠として確認した。独立immutableca301のDUMMY fragment8/8と、firstgrep / printfの判定を個別に外す2reverse条件は19:02:44に閉鎖した。failure-message-only09dcはcollector / restore部分がca301とbyte一致し、wholefileが同一ではない。途中source / closureの訂正incidentと原phaseを保持し、message変更だけを新native実行へしない。

このcutで新公開headのCI / fresh reviewはまだ未取得で、公開後にexactheadで別確認する。実Vault / 全owner環境でのwrapper運用は未検証である。旧whole-tool SCP strictFAIL / API-before-hook NOTも維持し、任意program / implicitdefault / ownerの実Vault状態をこのcollectorだけで認証しない。

## R25: 送信値と transport source の選択条件

R25 は curl の送信値、Git の protocol が選ぶ proxy / SSH source、SSH の選択された login / destination metadata を、operation・引数の役割・環境の export・設定の選択順と結び付ける。対象は公開 b6a89247 に対する正式 review 5513847977（2026-10-14 15:22:40 JST）の 3 P1 と、その役割を変える有限な対照である。原 3 入力は依頼前 df463a91 / e4560795 / b6a89247 で全 3 hook ALLOW・broken 0 と観測され、依頼前からの担当盲点だった。Hook に渡した DATA であり、実秘密・認証・helper / transport・被害を再現した証拠ではない。

以下は fixed-v3 の有限な条件である。単独の focused 成功、解析、全 bank、実入口、公開後の CI / fresh review は別証拠であり、一つの成功から他の受入を作らない。未担当の副作用は担当 owner と検査範囲を再確認し、担当先も証拠もない処理を保護済みとは扱わない。

| 守る対象 | 判定結果 | 判断不能になる条件 | 通常作業への影響 | 同じ目的の代替・維持する対照 | owner への出口 | 試験する境界 |
|---|---|---|---|---|---|---|
| **curl の選択された送信値** | 同じ source / 語の対応 secret reader が有効な outbound value に入ると証明すれば FORBIDDEN。必要な証明が不足すれば UNKNOWN | 未対応 producer / program / 加工、word の split / file-inline syntax、protocol / operation / redirect / argv / context が未証明。未知 URL や設定は independent source 判定も残る | 生成 body / header / auth / URL と unsupported expansion を使う通常作業も止まり得る | 確認済み literal / 対応 scalar、actual help、消費 DATA、選択されない後勝ち scalar、無関係 reader を維持。target / 認証 / operation が同じ時だけ対応形を検討 | selected role / value / operation / URL、生成 reader / source / span、protocol、cwd / export / config と不足を提示 | 対応 short / exact long、保守照合の unsupported grammar、selected scalar / additive、operation ごとの `--next`、file-inline、protocol active / unused、原入力 / normal / reverse |
| **Git の active protocol proxy / SSH 実行 source** | 対応 operation が選ぶ未検査 helper は UNKNOWN。literal helper 名だけでは本文・副作用を確定できず FORBIDDEN / 実送信を主張しない | named / dynamic repository、明示 rewrite、未知 protocol / config / argv / context、継承された selector の語、helper body / PATH / child source の不足 | git:// proxy や custom SSH wrapper を使う通常の remote read / transfer も停止し得る | 対応する実 query / getter、確定 unused protocol / selector、actual export 解除を保持。必要 helper を消すだけの案や local query は送信目的の万能代替にしない | target の scheme / raw host:port、operation、helper / domain 条件と選択順、実 env / config / child / cwd と不足を提示 | proxy first matching raw domain:port、environment priority、SSH selector priority、export / unset / child、actual query / 消費 DATA / 原入力 / reverse |
| **SSH の選択された login / destination metadata** | 対応 reader と selected word / source / context を証明すれば FORBIDDEN。部分選択や生成元が未証明なら UNKNOWN。stdin / remote command の有無と別に判定 | partial dynamic `user@host`、未知 selected hostname / login、config `%` / `${}` 展開、未検査 producer / boundary / context。部分の生成元を取り出せない場合に未選択 user の F を捏造しない | 動的 login / hostname、config expansion を必要とする通常の SSH も停止し得る | first-selected ordinary user / host、対応 scalar、後続の未選択 `-l` / `-o User`、actual query、無関係 reader を保持。認証対象や必要 user を変える代替を自動採用しない | selected login / host、選択順、生成 source / partial component、認証 / config / env / cwd と不足を提示 | first User / `-l` / user@host、post-host options / remote boundary、`-N` / `-n`、actual query / shadow actor / partial source / 原入力 / reverse |

### 選択と未使用の扱い

curl 8.7.1 に照合した送信 value の表記は 26 で、10 scalar-last と 16 additive に分ける。scalar は request / request-target / user / proxy-user / user-agent / referer / oauth2-bearer / ftp-account / mail-auth / mail-from。additive は data / JSON の各形、form / form-string、header / proxy-header、url / url-query、cookie、mail-rcpt、quote、telnet-option の表記で、alias や field 群を独立脆弱性数へ数えない。役割の分類だけで全 protocol に送られるとは認定しない。

同じ operation の有効な後続 scalar が先の値を置換した場合、その未選択の先行値を payload として FORBIDDEN にしない。additive の寄与は後の ordinary 値で消さず、未知 contribution は UNKNOWN とする。curl の `--next` は先行 URL がある場合に次 operation を作り、先行 operation を捨てない。global setting / variable と operation-local 値を混ぜない。cookie の inline / file は両方 append で、empty cookie file input は engine を有効にする形であり先行 list の reset ではない。

FTP / SMTP / Telnet の値は、固定 curl 8.7.1 の backend と実 consumer の条件で active / unused / UNKNOWN を分ける。確定 unused value はこの新 payload 条件の対象外でも、他の argv / source / file / config / context 条件を解除しない。全 selected URL と actual redirect selection を確認し、1つの見えている HTTPS URL だけで他 URL や未知 target を解除しない。

| 選択された値 / mode | この限定契約での扱い | 不足する保証 |
|---|---|---|
| FTP / FTPS `ftp-account` | 対応 ACCT consumer で active な generated source は既存 producer policyへ。HTTP / HTTPS直結で未使用を証明できる時はこの familyだけ inactive | 実 serverの332応答・認証成功・native bytesは未測定。未知backend / format / contextは UNKNOWN |
| SMTP / SMTPS `mail-from` | upload / MIME body と recipientを伴う MAIL branchの選択が必要。body / recipientを使わない対応command modeでは未使用 | URLがSMTPというだけでFORBIDDENにしない。format / consumer / source不足は UNKNOWN |
| SMTP / SMTPS `mail-auth` | 上記potential MAILに加えて実SASL authused条件が必要で、そのruntime/auth selectionが未証明なら UNKNOWN | optionの存在から認証成功や送信を確定しない。MAIL branch自体が未使用ならこの値だけ inactive |
| SMTP / SMTPS `mail-rcpt` | bodyが無くても recipient-onlyのVRFY / EXPN等の対応consumerに入る。対応source/argv/contextのsecret producerは FORBIDDEN | actualcommand / format / producer不明は UNKNOWN。body欠落だけでrecipientを解除しない |
| FTP / FTPS / SFTP `quote` | 対応backend / stage / opcodeの選択を確認しproducerを判定。未知future FTP、未対応SFTP format / backendは UNKNOWN | FTP pre/post stageを別SFTP実装へ流用しない。nativecommand実行・全SFTP実装の安全は未認証 |
| Telnet `telnet-option` | wholegeneratedkeywordは未証明で UNKNOWN。対応するknown `TTYPE=`等のprefixと選択backend/source/contextが確定したsecret producerは FORBIDDEN | optionkeyword / format、長さ、negotiation / native送信全体を保証しない |

known default `--location` / `-L` だけのcurl8.7.1 redirect maskはHTTP / HTTPS / FTP / FTPSで、SMTP / SMTPS / Telnetを含まない。このmaskが実selected defaultだと証明できれば、HTTPSからのSMTP / Telnet familyはinactive。FTP / quoteは将来FTPへの選択が未検査なので UNKNOWNを維持する。custom `--proto-redir`、未知mask / target、sourceで変わる選択は UNKNOWNで、defaultと仮定しない。実 full separated long `--location-trusted`、short `-L`、後続の actual ARG_BOOL `--no-location` と、optionに消費された同じ文字列を区別する。

HTTP以外の他generated value roleについて、この有限調査でactual consumerを証明できない場合は UNKNOWNに限定する。全curlを許可した保証ではなく、role名だけを全protocolの確定payloadへ昇格させない。form / query / cookie等のfile syntaxとliteral DATAも区別し、名前の一致だけでraw body uploadとしない。既存のactual first literal `-q` / `--disable`、明示config / netrc / ETag / cacheの独立条件を保持する。

Git の proxy は明示 git://、SSH source は確定 SSH / scp-like repository と対応 active operation の組で選ぶ。clone / fetch / fetch-pack / pull / ls-remote と既存 push の typed transport source を結び付ける。既知 HTTPS / Git の local-file URL / absolute / `./` / `../` は当該 transport family の unused 対照で、他の Git source / cookie / header 等の解除証明ではない。`core.gitProxy` は順序を保った最初の matching domain を使い、raw hostname:port が必要な比較で port を落とさない。config の known `none` / empty / domain 不一致と、実 `GIT_PROXY_COMMAND` の優先 / known empty を分ける。環境の `none` は executable 名で、config `none` と同じ解除ではない。

actual prefix / export / 継承の known-empty `GIT_PROXY_COMMAND` は `core.gitProxy` より優先する。independent argv / config / contextのUNKNOWNを先に維持した上で、他のpositive SSH selectorがない場合だけ、このproxy source familyをinactiveにする。remote名でprotocolが不明でも、この確定empty優先を理由なくUNKNOWNに戻さない。未 export local empty、SSHpositive、明示 unknown config root、unknownargvはUNKNOWNを保持する。emptyの解除は他のobject / cookie / header / helper等を解除しない。

この条件の修復中に、known-empty proxyのordinary2入力が旧b6 ALLOWから私有v4 UNKNOWNへ変わる通常退行を17:26:37 JSTに確認した。原A期待・2FAIL/sourceを保持し、privatev5でremote aliasのprotocolunknownよりempty優先を先に条件化し、normal2と独立boundary4を追加して再取得した。公開元4821の期待を変えて正常を装った修正ではない。

SSH transport source は実 `GIT_SSH_COMMAND` → `core.sshCommand` → `GIT_SSH` の優先を保持し、empty も未認証 source として扱う。prefix / export / 継承 / unset / `export -n` / `env -u` の順序と child transfer を保持し、未 export の shell local を選択 source にしない。partial 初期 seed は他 family の UNKNOWN を消さない。実 `ls-remote --get-url`、config getter / status と、option に消費される query-looking DATA を分ける。fetch-pack は通常 mode の git_connect / proxy consumerへ同じ positive selectorを結び付け、実option prefixは最初のdestinationまで、以後のflag-looking refはDATAとして扱う。proven prefixのdiag-url / stateless-rpcはこの transport familyだけinactiveで、旧argv / stdin / operationのUNKNOWNは残る。driver / direct entrypointも同じ役割に従う。明示 `--upload-pack` / `--exec` sourceは既存operation source担当のUNKNOWNを維持する。入口を接続したことはhelper body / arbitrary ref / PATH / implicitdefault / 全Gitcommandの安全保証ではない。

SSH は first-selected user を保持する。OpenSSH 10.3p1 の CLI `-l`、command-line `-o User`、parsed destination username は、user 未設定の時に選ばれる。host 後の option も実 remote command の前まで読む。`-N` は remote command の抑止で、`-n` は stdin の抑止であり、選択 login / host metadata の検査を省略する条件ではない。今回の metadata 修復は既存 stdin predicate / `-W` forwarding 条件を変更する契約ではない。

known `-V` / `-Q` / `-G` query の metadata 送信は inactive と分けるが、`-G` の config / Match exec と既存 provider / ProxyCommand / source 条件は独立する。resolved ordinary function body は外部 SSH actor にしない。unresolved shadow / 外部 actor を呼ぶ body まで許可証明へ一般化しない。SCP の synthetic SSH endpoint は、SCP の実 metadata 全体を証明した意味ではなく、既存 SCP / SSH helper / provider / config / payload 条件を保持する。

### curl 8.7.1 の native grammar と新 producer 判定

固定8.7.1のlong optionはexact name / separated valueで照合する。installed `/usr/bin/curl` 8.7.1のordinary no-URL query8（2026-10-14 17:00:51 JST）では、`--data=DUMMY`、`--user-a=DUMMY`、`--user-a DUMMY`、`--location-t` はexit2/stdout0で受理されず、shortattached `-dDUMMY`、full separated `--data DUMMY`、actual `--no-location`、full `--location-trusted` はhelp/version exit0だった。native query / compiler / protocol / senderは別scopeであり、8送信成功ではない。

actual terminalqueryはこの対応grammarとactual ARG_BOOLを使い、valueを消費するlong/shortと、unsupported `--no-help` / `--no-version` / `--no-manual` 等をqueryへ昇格させない。値付きshortのattached formは対応する。unknown source / split / arity / contextが残る場合はUNKNOWNとし、単にhelpという語があるだけで全sourceを許可しない。

既存negative classifierがlong略記や`--long=value`を保守的に照合することは、nativeのwell-formed argv認証ではない。新outbound producer edgeがsecret sourceを得ても、そのlong grammarがこの版で未対応ならFORBIDDENをUNKNOWNへ下げ、停止は保持する。対応separated long / shortのselected payloadでsource / role / contextを確認した場合のFORBIDDENは維持する。legacy file / raw / config / sourceの独立した停止をこの補正でまとめて解除しない。

途中のprivate108入力では、unsupported long `--data=...` のCP04が新producerのFORBIDDENになり、正式な実operation / argv未対応というUNKNOWN契約へ理由を訂正した。元same108/原F期待/1FAILを保持し、新CP04だけ根拠付きF→Uを採用、新unsupported略記CP110を別unique対照に追加した。native grammarの無効と、Hookがstopを出すことと、実送信 / 被害を混ぜない。

### HTTP header の実 consumer と getter

正式 P2 4267445818 の「generic header がより specific な値で置換される」という前提は、Git 2.54.0 / libcurl 8.7.1 の isolated config と literal DUMMY loopback で別に確認した。generic LOW の後に exact HIGH を置く実 HTTP は LOW と HIGH、同 `git config --get-urlmatch` の getter は HIGH を返した。逆順なら実 HTTP は HIGH、同 rank の反復は両方、explicit empty reset は先行 list を消す。この 4 ordinary request は HTTP404 / Git exit128 であり、repository 操作成功や review witness / real secret の送信ではない。

HTTP callback の nonempty append / empty clear と、getter callback の accepted value ごとの reset は違う。better URL rank だけを理由に先行 accepted HTTP header を無条件 clear する変更は採用しない。該当 input の UNKNOWN を保持して、root は有限 source / native 根拠付きで当該 P2 の返信・thread 解決を行った。原 formal finding の記録は残し、Code Review 新規 0 や他の 3 P1 修復完了を意味しない。全 Git 版 / wildcard / percent / HTTPS / implicit config の native 保証は増やさない。

### R25 の版と検証境界

一次照合は [curl 8.7.1 option parser](https://github.com/curl/curl/blob/curl-8_7_1/src/tool_getparam.c) / [operation](https://github.com/curl/curl/blob/curl-8_7_1/src/tool_operate.c) / [value / list helper](https://github.com/curl/curl/blob/curl-8_7_1/src/tool_paramhlp.c)、[Git 2.54.0 connect.c](https://github.com/git/git/blob/v2.54.0/connect.c) / [HTTP consumer](https://github.com/git/git/blob/v2.54.0/http.c) / [URL matcher](https://github.com/git/git/blob/v2.54.0/urlmatch.c) / [config getter](https://github.com/git/git/blob/v2.54.0/builtin/config.c)、[OpenSSH V_10_3_P1 ssh.c](https://github.com/openssh/openssh-portable/blob/V_10_3_P1/ssh.c) に限定する。installed binary、source version、ordinary native と Hook INPUT DATA の範囲を区別し、compiled source attestation、任意 program / implicit default config / 認証 / transport / 全 runtime の安全認証にはしない。

R25 fixed-v3 は2026-10-14 17:46:59 JSTに sourceを停写した（egress `8248ae48`、common `7078920b`、add-all `8365d365`、secret-git `273f6be4`）。新bank定義5044は原4821のID / command / stdin / cwd / project / env / 旧期待を全保持する。新私有期待のCP04理由F→Uと新CP110追加、empty proxy normal/boundary6の追加は原入力 / 原FAIL / 採用根拠を別保存する。古い私有v1〜v5、合成v1 / v2の成功をv3へ持ち越さない。

17:52:44 JSTにこの sourceの公開解析114 / filename parity8 / private停止API6の128契約を別取得した。root602 / typecheck / lint / duplicate、全5044 same-bank比較、私有metadata、single-edge reverse、実入口、公開head CI / fresh / threadはそれぞれ取得source・時刻を付して別gateで判断する。この記録時点の全5044比較は採取中だったため、後続のfixed-source proofに沿って結果を追記し、128成功から全bank成功を先に宣言しない。

2026-10-14 18:06:35.216 JSTに、固定v3の同一5,044入力・期待を旧公開b6と同一fixtureで比較し、修正側5,044/5,044・failed0、両側broken0、source4前後不変を取得した。旧4,821入力・期待は変更していない。旧sourceとのassertion差112はaggregate ALLOW→deny111と、aggregateを変えないhook / 理由差1で、独立脆弱性数ではない。Hook stdinのhashは共通runnerの同じconstructorから計算したもので、process stdinを別途captureした証拠ではない。原正式4入力も17:59:08.173 JSTにcommand bytesを変えず再投入し、egress自身のU / F / U / F・broken0を確認した。

単一edge reverseはcurl5feature/15観測（stop loss4 / scalar allowance精度1）、SSH4feature（stop loss3 / F→UでDENYが残る分類精度1）、Git8feature（stop loss5 / normal精度2 / child必要性未証明1）、curl unsupportedgrammarのcategory1（U→FになってDENY保持）を別に記録する。合計18featureは18脆弱性や18停止必要性証明ではない。normal対照 / 他guardの独立停止を保持し、必要性が不明なedgeのため他guardをまとめて外さない。sourceが変われば同edgeの証拠を再取得し、旧phaseの数を新sourceへ無条件加算しない。

2026-10-14 17:45:09 JSTの合成v2 sourceに対する新DUMMY実入口6試行は、ordinary SSHの1PASS、APIcyber前段で止まった5NOT_EXERCISED、FAIL0だった。SSHだけexact Bash1回 / owned3hooks / egress ALLOW / ssh stubの期待markerを観測し、HEAD / refs / index / objects / file等は不変。negative3とnormal Git/curl2はBash / hook0で入口未検証、各1回で再試行しない。v2のこの結果を新v3のdispatch成功へ持ち越さず、1normalからnegative成功を作らない。R23のdefaultPython SCP whole-tool strictFAILとAPIcyberNOT、R24のnegative2NOTも原source / scopeのまま保持する。

2026-10-14 18:07:48.432 JSTには、新v3に対する独立した正常query `c''url -q --no-location --help` を1回だけ試行し、exact Bash1回 / owned egress1hookのALLOW / curl stubの期待markerを観測した。HEAD / refs / index / objects / trackedfile、private4 / LIVE4 / 設定は不変だった。実観測はegress1hookであり、事前想定の3hookへ増やした記録にはしない。helpという別operationでの正常機能・入口確認であり、以前APIが拒否したsender / readerの再試行や代替実行ではない。compiledhelp動作は別のnative ordinary資料に限り、この1queryの成功をnegative3やnormal Git/curl2のdispatch成功へ昇格させない。

公開後のrequiredCI、両fresh review、全thread、Goalの判定は、公開headと取得時刻を確認したPR本文・監査記録を参照する。旧b6のCI / fullCR0は当時の有効な履歴で、変更したsourceの成功ではない。この節のlocal/私有cutを最新公開状態へ無条件持ち越さず、過去の処理中 / 未取得を恒久的なcurrent表示にしない。任意program / implicitdefault / 認証 / transport / 全runtimeの安全認証、module責務refactor実施、sourceの安全保証やmerge承認ではない。

個別操作の了承とhook停止・別コピー先実行の了承は別である。対象 / 操作 / source / export / config / cwd / 必要なhelperやmetadataと不足をownerへ提示する。担当owner / 証拠のない副作用を保護済みとは扱わない。API前段の拒否を再試行・書換え・hook無効化で成功へ変えず、caseごとのactual hook list、owned decisionとmarker / HEAD / refs / index / objects / 必要fileのbefore / afterを保存する。

## R24: Git HTTP metadata の選択と生成元

R24 は、active HTTP operation が選ぶ `http.extraHeader` / `http.userAgent` と、実際に export / 継承された `GIT_HTTP_USER_AGENT` の生成元を検査する。2026-10-14 13:56:09 JST の同じ numbered header 2入力を使った比較では、依頼前 df463a91、e4560795、R23 公開 03a05771 のいずれも egress 自身は ALLOW で、secret-git だけが停止した。この担当 egress の旧盲点を、他の conditional guard の停止だけで修復済みとはしない。新入力の実 dispatch、native 攻撃の成立、実秘密の読取や被害はこの Hook DATA の観測から確定しない。

対象は実 Git identity、対応 argv / option arity、repository、HTTP operation と selected command-scope config の組合せである。`-c`、`--config-env`、実 export を保った `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` と PARAMETERS / root の既存境界を保持する。query の option 値や `--` 後の DATA を、実 query と取り違えない。対応する実 `ls-remote --get-url`、remote getter、network を起動しない submodule mode、確定 non-HTTP、未使用 selector は区別するが、既存の helper / source / context / cookie 条件も残る。

| 守る対象 | 判定結果 | 判断不能になる条件 | 通常作業への影響 | 同じ目的の代替・維持する対照 | owner への出口 | 試験する境界 |
|---|---|---|---|---|---|---|
| **選択された HTTP header DATA** | 送信に使う語・同じ source 内の関連 secret reader・context・active selection を証明した場合は FORBIDDEN。必要な証明が不足すれば UNKNOWN | 未追跡 producer、複数 argv へ変わり得る語、未検査 command-scope config、URL scope / rewrite / destination / argv が不明。unscoped 生成値と見えていない URL-specific config の優先順を証明できない場合も UNKNOWN | 動的 header、unsupported carrier / scope を必要とする通常の HTTP query / transfer も停止し得る | 確認済み非秘密 literal / 対応 scalar DATA と、選択されない scope / 実 query を維持。同じ対象・認証・操作を保てる場合だけ対応形式へ変更 | operation / target、selected key と語、生成 source / reader、cwd / exported env / config 優先順、残る不足を提示 | numbered / `-c` / `--config-env`、実 export / removal、append / reset、scope、query / 消費 DATA、原入力 |
| **選択された User-Agent DATA** | 同じ payload proof で秘密由来を確認すれば FORBIDDEN。出所や選択条件が未証明なら UNKNOWN | 継承された nonempty 値の生成元、未対応 child への carrier、opaque scope / target、実 export を確定できない場合 | 既存の custom User-Agent を継承した HTTP 作業や、未証明の生成値を使う作業が停止し得る | ordinary literal / 対応 scalar、未 export / 実 export 解除、実 query を区別。実 environment override は UA だけに適用し、header / cookie を解除しない | 値と実 export、親子の source / mode、優先される setting、target と不足を提示 | config scalar の最後の値、environment priority、partial seed、child / 未使用対照、独立 family |
| **HTTP metadata の persistent writer** | この2 family の未証明な生成値を保存する操作は、将来の selection が未検査なので UNKNOWN。直ちに HTTP 送信したという FORBIDDEN にはしない | 保存する生成元と将来 consumer が未証明。未知 key / file writer 全体はこの限定 gate で保護済みとは扱わない | 動的 header / User-Agent の設定保存も停止し得る | ordinary literal / empty の保存と getter はこの新 writer gate の対象外。既存の設定・helper guard は維持し、生成目的が必要なら単なる削除で代替しない | key / scope / producer、将来 consumer、必要な設定値と不足を提示 | setter / getter / 実 query、literal / generated / empty、単一 edge、別 family の保持 |

### 値の優先順と対応範囲

`http.extraHeader` は selected list であり、後続の nonempty 値は追加する。後の値だけを見て先行 payload を捨てない。selected empty 値は、その時点の選択済み list を reset する。generic empty による既知 explicit list の reset を、見えていない全 config / cookie / helper family の解除証明にはしない。

`http.userAgent` は selected scalar である。実 prefix / export / 継承された `GIT_HTTP_USER_AGENT` が config より優先する。この override で消せるのは superseded UA の selection uncertainty だけで、unknown header、cookie、config key / root、global argv、内側の実行 source は独立して残る。active config の選択が未検査なら、同じ語の関連 secret reader を確認しても UNKNOWN を保ち、確定した selection の FORBIDDEN と区別する。任意の stored `--config-env` carrier は、対応する child export / producer proof がなければ ordinary に見えても UNKNOWN。実 prefix carrier は、元の値の raw / start と生成元を保持する。

URL selection は literal scheme / host / normalized port / path の slash 境界 / user の対応範囲に限る。percent encoding、wildcard scope、malformed / opaque destination、明示 rewrite は未対応。既定の repository / global / system config 内容全体は検査済みとしない。正確な HTTP metadata key に対する引用済み単一語の `-c` 値では、payload の不確定と argv / key の確定を分けるが、他の dynamic global operand を一律許可しない。

secret reader proof は既存 `outboundPayloadVerdict` の有限な形式を再利用する。同じ source / 語の span / substitution scope と実行順を保ち、対応する `cat` / `head` / `tail` / `base64` / `xxd` / `sed` / `grep` / `awk` の file / input と引数を検査する。実行 path は対応する `/usr/bin/` / `/bin/` または既存の context 条件が必要で、関数・任意 helper、未対応 program text / option / redirection や加工を「非秘密」と扱わない。秘密 filename の関連読取と送信する語の関係を証明できない場合は UNKNOWN。別 statement の無関係な reader は、この payload の証拠にしない。

同目的の代替は、対象・認証・操作を維持できる確認済み literal / scalar 形式がある場合だけ採用する。metadata や生成元が目的に必要で対応形式がない場合は、target / operation / cwd / export / config priority / producer と不足を owner に示す。個別操作の了承と hook の停止の了承は別であり、コピー先での実行を自動的な代替にしない。ordinary child でも既存 Bash source が UNKNOWN の形式は引き続き停止し、child 全般の安全を証明したとはしない。

### R24 の版と検証境界

一次仕様は [Git 2.54 config](https://git-scm.com/docs/git-config/2.54.0)、[v2.54.0 http.c](https://github.com/git/git/blob/v2.54.0/http.c)、[v2.54.0 urlmatch.c](https://github.com/git/git/blob/v2.54.0/urlmatch.c) に照合した。別の DUMMY native 観測は Git 2.54.0 / arm64 / libcurl 8.7.1 の隔離 config と loopback receiver に限る。7対照で append / reset / UA priority を確認したが、応答は全 HTTP 404 / Git exit128 であり、repository 操作の成功・実 witness の送信・production config・他の Git / shell / runtime 版の保証ではない。

2026-10-14 14:24:34 JST の fixed-v1 source（common `3ea53e77`、egress `fc5d7a18`、add-all / secret-git は R23 と同じ）に対する私有 L2 は64/64、解析17/17、旧 Git 条件71/71、単一 edge reverse8を別々に取得した。64入力の egress 結果は ALLOW35 / UNKNOWN25 / FORBIDDEN4で、通常対照10入力は egress ALLOWでも既存 secret-git 単独の UNKNOWNが残る。reverse は担当 egress の停止消失5 / aggregate停止消失4、許可精度2、独立 Bash停止が残る child の必要性未証明1を区別し、8本すべての停止必要性が証明されたとはしない。

2026-10-14 14:33:58 JST の同 fixed source / Claude Code 2.1.299 に対する DUMMY 実入口3試行は、ordinary header の1 PASS / 0 FAIL / 2 NOT_EXERCISED。通常対照だけで実3 hook dispatch・egress ALLOW・Git stub の期待markerを確認し、他の対象状態は不変だった。numbered header reader と exported User-Agent reader の2試行は APIcyber拒否で Bash / hook前に停止し、dispatch 0・対象状態不変である。この2件の実入口停止は未検証として残し、再試行・入力の書換えをしない。user-default hookを有効にし、元の matcher / if / timeoutを保持した untrusted DUMMY workspace の観測であり、production lifecycle / plugin / native sender / 実秘密や通信を再現したものではない。API起動前の試験器準備エラーは、この3 actual trial や hook の合格へ加算しない。

上記は fixed-v1 の履歴である。独立18入力の確認で、明示 unknown config root を伴う2入力が契約の UNKNOWN に対し FORBIDDENとなった停止理由の精度不足を保持した。2026-10-14 14:38:26 JST の fixed-v2（egress `b5ea0756`、他3 sourceはv1と同じ）では unknown config selectionを確定payloadより優先する局所修復を行った。停止を保持したこの訂正を、ALLOW漏れの新規発生や v1全試験のv2合格としない。v1の64 / 17 / 71 / reverse8と実入口1 PASS / 2 NOTを、新 sourceの受入へ持ち越さない。

fixed-v2に対する同じ独立18入力は14:41:44 JSTに不一致0、通常headerの新しいDUMMY実入口1試行は14:42:19 JSTにPASSを取得した。この新しい通常対照だけで実3 hook dispatch / egress ALLOW / 期待stub markerを確認し、他の対象状態は不変だった。v1のnegative2 NOTを再試行せず、新normalをnegativeのdispatch証拠にしない。全公開bank、API契約、required checks、公開headのCI / fresh reviewはこの有限対照と別に取得する。

同fixed-v2で新66/66（egress ALLOW35 / UNKNOWN27 / FORBIDDEN4）、私有解析18/18、旧Git条件71/71、公開解析95 / parity8 / 停止API6の109契約を再取得した。reverse9は担当停止消失5 / aggregate停止消失4、通常許可精度2、UNKNOWNからFORBIDDENへ変わってDENYが残る理由精度1、独立Bash停止が残るchild必要性未証明1を分ける。14:44:29 JSTの全4821入力は4821/4821・broken0・source / runner不変。旧4755の入力・旧期待を全保持し、新66を追加した。同じ4821を旧03aへ渡した比較のassert不一致26、aggregate差17（8 ALLOW→DENY / 9 DENY→ALLOW）、hook / 理由のみの差18は重なる測度であり、脆弱性数ではない。14:44:43 JSTのlocal root602 / typecheck / lint / duplicate2も成功し、local Node24.13のengine警告は保持する。

この有限なlocal sourceの受入と、公開headのrequired CI・両fresh review・thread・Goalの完了は別である。旧head03aのCI / full CodeRabbit0を変更sourceへ持ち越さない。元 input / ID / cwd / project / envと原FAIL・精度不足・fixture / collector訂正を残し、L1 / L2 / reverse / L3と公開後のCI / fresh reviewを別証拠にする。L3のAPI前段停止とR23のuser-default hookによるwhole-tool strict FAILは担当hook成功へ読み替えず、今回の新入力の実dispatchへ持ち越さない。全shell / 設定 / runtime / production lifecycleの安全認証とせず、negative2実入口未検証を解消したとも記録しない。

## R23: 修正の条件・結果・例外

R23 は、公開 head `e4560795a6804987e0dd49e959146a8836a7fa3a` に対する正式 review 5512447678（2026-10-14 11:42:53 JST）の 4 P1 と、同じ役割の有限な source selector を修復する。原 4 入力は、同日 11:51:12 JST の固定 e456 と 12:02:25 JST の依頼前 df463a91 で、全 3 hook が ALLOW・broken 0 だった。これは hook に渡した DATA の判定であり、native 実行・実秘密の読取・通信・被害の証拠ではない。旧 parser の引用認識不足と、新しい source 分類の取り残しを原因の層として分ける。R22 の有限な予定修復が完了しても、未発見経路がないことや fresh review の指摘 0 を保証しない。

下表の inactive / 許可対照は、その新しい停止条件を適用しない範囲である。既存の secret・index・hook・source・context・生成元の判定も残る。対応していない処理を保護済みと扱わない。同じ目的・対象・実行条件を維持できる対応形を先に検討し、無理なら owner へ不足を示す。個別操作への了承から、hook の停止や別の場所にコピーした実行を自動的には許可しない。

| 守る対象 | 判定結果 | 判断不能になる条件 | 通常作業への影響 | 同じ目的の代替・維持する対照 | owner への出口 | 試験する境界 |
|---|---|---|---|---|---|---|
| **Git am の mailbox / Maildir / stdin / resume による commit** | active な入力、`--reject`、continue / resolved / skip / retry / allow-empty は UNKNOWN | patch が作る path・object・commit metadata を未検査。公開 filename も安全証明ではない。mode・argv・source が不明な場合も UNKNOWN | 通常の公開 mailbox の適用や再開も停止する | 単独 abort / quit、show-current-patch（省略 / raw / diff）、実 stdout `-h` は新 writer 条件では inactive。quiet だけとの併用まで。混合 mode・未知の略記・不足 arity・未証明の dynamic は UNKNOWN。cleanup / query は適用や再開の代替ではない | patch / mailbox / source、追加 path、対象 branch、cwd / env / config、必要な apply / resume の目的と不足を提示 | mailbox / Maildir / stdin / resume、消費 DATA と実 query、元入力と正常対照、停止前後の HEAD / refs / index / objects |
| **Git HTTP が選ぶ cookie file** | active HTTP の未検査 selected file は UNKNOWN。生 file 全送信を確認した FORBIDDEN とはしない | file format・server match・URL scope・有効設定の選択が未検査。generic empty だけでは既存の URL scope 設定を解除した証明にならない。既知 URL と完全一致する scope の selected known empty は、この family だけ inactive。明示 root・不明な PARAMETERS・URL rewrite・dynamic があれば解除しない | 公開 cookie file を使う通常の HTTP query / transfer も停止する | getter / status、確定 non-HTTP、実 `ls-remote --get-url`、remote get-url / show -n 等では未使用 cookie を区別する。必要な cookie 認証を単に消した形を同目的の代替にはしない | HTTP operation / target、selected key / file / URL scope、必要な format / server 条件、cwd / env / config と不足を提示 | `-c` / `--config-env`、URL scope と generic 値、空値と優先順、実 HTTP / non-HTTP、getter / 消費 DATA、元入力 |
| **cookie 設定の persistent writer と export された環境設定** | 明示 known cookie の将来 source writer は empty / unset / unset-all / local / global を含め UNKNOWN | 将来の HTTP consumer と cookie source が未検査。COUNT / PARAMETERS / config root は実 export と scope を保持して判定 | cookie 設定の保存や、明示 alternate Git config を使う作業が停止し得る | getter / 未使用 consumer、非 export / 実 export 解除を区別する。既知 count が 32 以下で key も既知の non-cookie 設定を、この理由で UNKNOWN にしない。egress の許可と、既存 secret-git が止める全 hook の結果を分ける | key / value / scope、将来の consumer、実 export、COUNT / PARAMETERS / root と不足を提示 | prefix / export / local / 解除、known non-cookie 対照、URL scope writer、既存 family の情報を保持する partial merge、単一 edge の反転 |
| **SCP / SSH が実際に選ぶ command / config / program / provider** | 対応する禁止 payload を確認すれば FORBIDDEN。残る active command や未検査 config / program / library は UNKNOWN | helper は copy の方向と独立して動く。literal を解析できても、shell / callee / PATH / startup / functions の副作用を認証したことにならない。未知の remote / local、config、activation も UNKNOWN | 通常の ProxyCommand 等の helper、alternate config、接続 program / provider も停止する | SCP が先に置く PermitLocalCommand=no / RemoteCommand=none、先勝ちで未使用の値、確定 local copy、legacy `-O` で未使用の `-D` を区別する。proxy が必要なら helper を消した形を同目的の代替にしない | source の種類と選択順、copy / 接続 mode、target、helper body / config / library、user shell / cwd / env と不足を提示 | forwarded `-o` / 先勝ち / ProxyJump 競合、`-F` / `-S` / `-D`、provider と環境、実 query / 消費 DATA、元入力と普通の helper、単一 edge |
| **curl の selected ETag / file 由来の送信入力** | 既知 file role は既存 policy の FORBIDDEN、source / argv 境界が不明なら UNKNOWN | file bytes・format・実送信成功を検査しない。公開名や special file も file payload。8.7.1 の ETag filename `-` は stdin と仮定しない | 公開 ETag cache file を使う conditional request も停止する。empty ETag は upstream が拒否する形式であり、成功する許可代替ではない | 同じ header・目的を対応する確認済み非秘密の inline DATA で保てる場合だけ再検査する。file 入力自体が必要なら owner へ | operation / URL / header、selected file と生成元、format / 用途、cwd / env / config と不足を提示 | singleton の後勝ち、`--next` / `-:`、消費 DATA と実 query、未知 arity、empty / `-` / special file、元入力・公開 file・reverse |
| **curl の file 由来の --alt-svc / --hsts 接続・cache source** | 明示 nonempty selected file は UNKNOWN。生 file の body 送信として FORBIDDEN にしない | cache 内容・route・protocol・target を未検査。未知 selector / argv も UNKNOWN | 公開 cache file を使う通常接続や、cache を永続化する作業も停止する | known empty はこの local file 入力だけ inactive。memory cache・応答・接続全体の安全証明ではない。cache の永続化が目的なら、empty への置換は同目的の代替にならない | cache file / 選択順 / operation / URL、必要な route / protocol / persistence、config / env と不足を提示 | 後勝ち / next / 空値 / 消費 DATA / 実 terminal query、既知 no-URL の非 activation、未証明の protocol 別例外を作らない、単一 edge と正常対照 |

### SCP / rsync の path と selected source

SCP と rsync の remote / local 判定に、Git の `file://` を local とする規則を流用しない。それぞれの colon / URI / 明示 local path の規則に従う。SCP の colon は path separator より前に現れるかを区別し、bracketed IPv6 と先頭 colon の filename DATA を保持する。`./` や absolute path の後の colon は local と判定する。`file:///…` は SCP / rsync では host `file` を選ぶ形で、Git の local-file URL ではない。それぞれの `scp://` / `rsync://` は対応する host / port / module 条件が必要で、未対応 scheme・不正な URI・dynamic な path は UNKNOWN。rsync の remote shell / files-from / askpass 等も、実際に選ばれる copy mode と source の条件を保持する。

SCP の既存 raw 一致を精度修正する範囲は、既知 external SCP、確定 argv / context、単一 statement、2 個以上の実 operand、redirect / pipeline / heredoc / 追加実行 / 未知 launcher / function source がない確認済み受信または local copy に限る。SFTP、未知の方向、実 upload、他の raw pattern と後段の helper / payload / source 判定は残る。通常の受信が許可されることは、別の active ProxyCommand も許可される意味ではない。

SSH config の command / scalar は選択順を保つ。先行 non-none ProxyJump は後続 ProxyCommand を選ばず、先行 literal `none` は後続 command を抑止した証明にならない。SCP の `-F` は後勝ちで、known `none` / `/dev/null` はその config source だけの対照。`-S` は接続 program、`-D` は SFTP mode の direct server。最初の SCP operand 以降の option-looking bytes は filename DATA である。PKCS11Provider / SecurityKeyProvider の先勝ちと、SSH の direct `-I` による選択を分ける。known `none` と SecurityKeyProvider=`internal` は該当 library source だけの対照であり、認証 file 全体の安全証明ではない。

SSH `-V` / `-Q` は config 読込前に終了する。一方 `-G` は config を読むため、接続 helper / provider が inactive でも selected `-F` / Match exec の source を別に判定する。

### curl 8.7.1 の file の役割と版の境界

upstream 8.7.1 の ARG_FILE 23 件は filename を取る表記であり、全 23 件が生 file の body を送る意味ではない。認証・trust・output・cache を送信 payload と混同しない。以下は有限に照合した役割で、未担当の内容・実装・認証・接続まで保護済みとはしない。

| 役割 | option・範囲 | この修復の境界 |
|---|---|---|
| outbound payload / auth file | upload-file / etag-compare / netrc-file | 既存 file payload policy と追加 ETag source。既知 file は FORBIDDEN、未知 source は UNKNOWN。file bytes / credential format / 実送信成功は未確認 |
| config source | config | 独立した selected config の UNKNOWN 条件を保持 |
| local output | dump-header / etag-save / output / stderr / trace / trace-ascii | 新 payload / cache 入力には分類しない。filesystem 全体の安全認証ではない |
| client authentication | cert / key / proxy-cert / proxy-key | TLS 認証の表現で、生 file の body ではない。identity / key / credential の有効性は未確認 |
| local trust / reference | cacert / capath / crlfile / proxy-cacert / proxy-capath / proxy-crlfile | TLS trust の参照で、生 file の body ではない。trust policy / file 内容 / native TLS は未確認 |
| local transport / entropy | abstract-unix-socket / unix-socket / random-file | socket / entropy の役割で、生 file の body ではない。native / transport 条件は未確認 |
| embedded file payload（ARG_FILE の表記外） | data / data-ascii / data-binary / json / header / proxy-header の `@`、data-urlencode / query / form の file syntax、cookie file、送信に使う variable file | 既存の有限 syntax と生成元を保持。data-raw と literal form / header の DATA は別に扱い、他の policy も残す |
| connection cache（ARG_STRG） | alt-svc / hsts | ARG_FILE 23 件とは別の selected file source の UNKNOWN。公式比較で未担当だった 2 selector を追加し、4 review 指摘へ加算しない |
| local metadata / output / reference 等 | time-cond / write-out / cookie-jar / pinnedpubkey / pubkey 等 | mtime / output / reference と生 file の body を分ける。全 option format / effect / 認証の保証ではない |

singleton は operation ごとに後勝ちとし、`--next` / `-:` の先行 operation を捨てない。実 help / manual / version と、他の option に消費された query-looking DATA を区別する。curlrc の解除には、既存の実 first literal `-q` / `--disable` 条件が必要である。明示 `--config` と未知 context は独立して残る。

照合した一次資料は [Git config 2.54.0](https://git-scm.com/docs/git-config/2.54.0)、[Git am 2.54.0](https://git-scm.com/docs/git-am/2.54.0)、[OpenSSH 10.3p1 SCP](https://github.com/openssh/openssh-portable/blob/V_10_3_P1/scp.c) / [path parser](https://github.com/openssh/openssh-portable/blob/V_10_3_P1/misc.c) / [SSH config parser](https://github.com/openssh/openssh-portable/blob/V_10_3_P1/readconf.c)、[curl 8.7.1 option parser](https://github.com/curl/curl/blob/curl-8_7_1/src/tool_getparam.c) / [operation](https://github.com/curl/curl/blob/curl-8_7_1/src/tool_operate.c) である。query metadata は Apple `/usr/bin/curl` 8.7.1、SSH OpenSSH_10.3p1 / LibreSSL 3.3.6 と報告する。companion SSH の版は、Apple SCP build 全体の認証ではない。installed rsync は openrsync protocol 29 / rsync 2.6.9 互換であり、照合した [OpenBSD upstream source](https://github.com/openbsd/src/blob/master/usr.bin/rsync/main.c) は取得時の内容と blob `26063fcf343b7f45ee03acfe0e9042e8a23911c6` で固定しているが、Apple binary の attestation ではない。Apple patch・build feature・user shell・default config・native helper を保証しない。

### R23 の検証境界

固定 global-v2（2026-10-14 12:55:40 JST）の最終4755入力は同日13:20:45 JSTに4755/4755・broken 0・source4 / runner不変。旧4569のID / cmd / stdin / cwd / project / envを全保持し、Git71＋network115の新186入力を追加した。旧期待の初回全比較は4不一致で原結果を残し、active amと未検査ProxyCommandの4 ALLOW→UNKNOWNを理由付きで採用した。同4755を旧e456へ投入した新期待との差83、観測差84（aggregate72＝ALLOW→deny66 / deny→ALLOW6、hook / reasonだけ12）は重なる測度で、脆弱性件数ではない。公開解析91・filename parity8・private停止API6の105契約、root602試験・typecheck・lint・package重複確認も、この固定sourceで別取得したlocal結果である。

実Claude Code入口のplanned DUMMY7試行は5 PASS / 1 strict FAIL / 1 NOT_EXERCISED。inline ETagはcurl stubの期待markerだけ変わり、ETag file / cookie / am / cacheはegress自身が停止して対象状態は不変。actual hook listはcaseごとに異なり、全試行の3 hook dispatchとはしない。通常SCP受信はowned CJSがALLOWでも別のuser-default hookが実toolを止めたためstrict FAILを保持した。関連default Pythonのrule / message / 同じJSON DATAのDENYは帰属を支持するが、唯一の名前付きruntime traceとは別である。このPRでuser-global設定を修復 / 無効化せず、whole-tool正常成功へ改名しない。active SCP helperはBash / hook前のAPIcyber拒否でNOT_EXERCISED、再試行しない。別のcommand identity準備query1 PASSを修復7試行に加算しない。native transport / 実秘密読取は行っていない。

R23の全受入は未完了で、新公開head・required CI・両fresh review・threadはlocal検証と別に取得する。e456 / df463の原4判定、R22の4569入力・102契約・旧L3成功を変更sourceへ持ち越さない。L1解析、担当hook自身のL2（原入力 / variant / 正常対照）、単一edge reverse、実入口L3を別証拠として扱う。API前段の拒否をhook成功へ数えず、unit3 hookの判定を実3 hook dispatchと読み替えない。DUMMY marker、HEAD / refs / index / objects / 必要fileのbefore / after、原FAIL・過剰拒否・fixture訂正を保存する。

## R22: GH と shell の source と操作の境界

R22 は公式仕様に照らし、operation identity、option が消費する値、送信 payload / metadata、選択する program / config / startup source を分けて判定する。既存の FORBIDDEN は確定した file-upload policy や関連 secret reader に適用し、必要な source・argv・mode・context を確認できない範囲は UNKNOWN として停止する。通常の認証 credential を任意の file 送信へ分類せず、query / local registration という名前だけで選択 source の検査を省略しない。

各行の対応形は、その境界で停止を追加しない条件である。既存の literal secret、cwd / env / config、index / filename、別の実行 source 等の判定も満たす必要がある。別の場所や別ツールへコピーして実行することは、対応済みの代替ではない。

| 守る対象 | 判断不能条件・禁止との区別 | 止まる通常作業 | 対応代替・維持する対照 | owner への出口 | 検証する境界 |
|---|---|---|---|---|---|
| **GH 本文 / file / stdin**: Issue / PR comment、review / merge / revert、Discussion、agent-task、既存 Release / set / workflow / key 群 | 当該 operation の file 役割に結び付いた確定 file は FORBIDDEN。未知の filename / stdin / argv / input source は UNKNOWN。公開 file も既存 upload 禁止の範囲。GPG 等で任意の `.env` が有効な key として受理されるとは主張しない | 公開 artifact、body-file、attachment、未知 stdin による投稿・登録 | 同じ内容・対象・目的を表せる対応 literal / scalar 本文、対応する literal fd0 source の条件で再検査する。file / stdin を単なる表示 query に替えることは投稿の代替にならない | operation、repo / target、payload bytes の役割、file / fd0 source、cwd / env / config と不足を提示する | file / `-` / field `@file`、redirection / pipeline、literal fd0 と未知 source、実 help / 消費 DATA、担当 hook の理由分類 |
| **GH 送信 scalar**: API field / header / endpoint、query / repo / host、title / name / URL 等 | 実送信 word と同じ生成元に対応 secret reader が結び付けば FORBIDDEN。不明な producer / stdout / word 数 / export / context は UNKNOWN。別 statement の無関係 reader は payload の証拠にしない | 変数や外部 program で生成する本文、query、header、repo / host metadata | 同じ値・用途・条件を保つ確認済みの literal / 単一語 scalar proof があれば再検査する。shell local と child に継承された値、実 unset / overwrite を区別する | DATA の用途、生成元、送信先、export / scope、argv / config と不足を提示する | supported reader、secret / ordinary input、無関係 reader、quoted scalar の語数と生成元、prefix / export / 非 export / 解除 |
| **GH の selected program / implicit body**: editor / browser、template / recover / fill、alias / extension / Copilot、interactive 入力 | 実選択される body / helper / context が未検査なら UNKNOWN。shell alias の登録と invoke、extension / Copilot に渡る `--help` と GH 自身の help は別。未使用 GH_EDITOR / browser / pager の存在だけを停止根拠にしない | editor / browser での投稿、Git message からの fill、custom extension / alias、interactive input | 同じ投稿内容を対応する explicit body / title に表し、template / recover / fill / helper が目的に不要な場合だけ再検査する。`browse --no-browser` は URL 出力を目的とする場合の対照 | 選択 source、operation / mode、body / template / recovery、program / config、不足を提示する | actual web / editor flag、unused selector、registration / getter / invoke、DATA の consumed help、known builtin alias と未知 body |
| **GH の明示 alternate config root**: GH_CONFIG_DIR、XDG_CONFIG_HOME、HOME 等 | child に実際に渡る明示 root が config / active operation の source を選び、その内容を検査できなければ UNKNOWN。既定 inherited root を保持することは、その全設定が安全と確認した意味ではない。空値・非 export・実 unset と選択優先を区別する | 別 HOME / config root を使う query / 投稿、wrapper、skill local validation | 同じ host / repo / 認証 / config 条件を保てる対応指定がある場合だけ再検査する。単に root を消して異なる設定へ切り替えることを自動的な代替にしない。local config getter は別の対応対照 | root、実 export、選択される config、operation、target / 認証 / env と不足を提示する | explicit / default inherited / empty / local-only、prefix / export / export解除、上位 root / override、local getter と active operation |
| **GH pager の selection と JSON** | pageable operation が選ぶ未検査 program は UNKNOWN。GH_PAGER の存在（空も含む）が config pager、PAGER より優先する。`--json` は pager を使わない証明ではない。実 TTY / helper 起動は別の成立条件 | custom pager を使う list / view / diff / status / search、JSON query | helper なしで同じ出力を読めるなら、選択された既知の空 pager / `cat` と対応 argv を使う形を検討する。下位 PAGER が未使用であることと selected GH_PAGER の安全条件を区別する | operation / output、TTY、GH_PAGER / config / PAGER の優先、選択 program と不足を提示する | GH_PAGER present / empty / cat、PAGER fallback、config priority、JSON mode、selected / unselected、実 unset / export解除 |
| **GH helper / connection config writer**: pager / editor / browser / api_host / http_unix_socket | 未検査の将来 source / connection を選ぶ persistent writer は UNKNOWN。直後の query で GH_PAGER=cat にしても、先行した未知 global pager writer の停止条件は消えない。単なる config 値を実 helper 起動や payload 送信確定とはしない | custom pager / editor / browser や接続設定の保存 | 同じ目的なら確認済み literal 空 / cat の pager、helper を選ばない ordinary config key、local getter 等を対照にする。2.102.0 の host-scoped pager と global pager を区別する | 保存する key / value の役割、scope、後続 consumer、必要 program / connection と不足を提示する | writer / getter / printed DATA / unused definition、host option 消費、空 / cat、unknown value、後続 override と将来 effect |
| **PR create の implicit push / fork** | supplied body / title だけでは branch / Git metadata / push / fork context を確認できず UNKNOWN。対応する既知・非空の actual `--head` が implicit push / fork を省く条件となる。PR create の `--dry-run` だけでは push を省く証明にならない | current branch からの普通の PR 作成、未 push branch の投稿、fill / recovery を伴う作成 | 同じ repo / head / base / body / title を保つ対応 explicit head の形式があれば再検査する。別 branch や単なる PR view は同目的の代替としない | repo / head / base、必要な Git source / helper / push / fork、body / title と不足を提示する | actual `--head` / consumed head DATA、empty / unknown head、body / title / fill、dry-run、no-head と同対象 head 対照 |
| **skill publish の actual nonpublish mode** | 実 `--dry-run` / `--fix` は publish を行わないので、upload と一律に FORBIDDEN にしない。ただし explicit alternate root 等の独立 source / context が未知なら UNKNOWN。option 値や印字 DATA 内の dry-run はこの条件を解除しない | 明示 config root を伴う local validation / fix、未知 config / source 条件での作業 | ordinary nonpublish / default-root 対照を維持する。未使用 GH_EDITOR / GH_PAGER / PAGER は presence だけで拒否しない。active publish と同じ目的なら validation への置換を送信代替と説明しない | directory、actual mode、root / config / source、必要な publish または local fix の目的を提示する | dry-run / fix / false flag、ordinary と root override、inactive helper、active publish、local source guard の順序 |
| **GH の未知 operation / argv / active context**: auth、attestation、Codespace、Git を選ぶ operation 等 | installed builtin identity と option arity を確定できない場合は UNKNOWN。未検査の auth input / selected artifact / remote copy / shell / Git helper も独立 UNKNOWN。認証 credential を file upload FORBIDDEN へ読み替えない | Codespace transfer / remote shell、authentication、extension install、repo clone / fork 等 | 実 terminal query、既知 builtin alias、local registration / getter 等を当該 role の対照にする。query を transfer / authentication の代替として案内しない | operation、source / destination、local / remote operands、auth / config / helper、forwarded argv と不足を提示する | separate / equals / short bundle / attached / `--`、auth の `-h` hostname 消費、actual help と consumed `--help`、外部 forward、無効形式 |
| **child shell startup / prompt / imported function source** | login の profile / logout、active debugger、interactive bashrc / rcfile、interactive stdin reader の prompt / callback、未知 import body / identity / mode は UNKNOWN。zsh / fish の system startup / config / autoload、ksh / mksh の固有 mode を Bash と同じ規則で許可しない | login shell、custom rcfile / debugger、prompt を読む wrapper、import function、zsh / fish の普通の起動 | 同じ目的・環境を対応 literal `bash -c` source に表せる場合だけ再検査する。actual --norc は対象 bashrc / rcfile の条件、--noprofile は profile の条件で、logout / prompt 等の全解除ではない。zsh -f / fish --no-config も全 source 非選択の証明にしない | interpreter / version、login / interactive / privileged / POSIX / reader mode、startup / prompt / function source、argv / env を提示する | source 選択順、actual mode と消費値、first Bash terminal help / version、unused rcfile / prompt、known function definition と call、quoted fd0 / unknown fd0 |
| **ENV / BASH_ENV の実選択** | child へ渡る非空・未知 source と actual mode の組合せを確認する。BASH_ENV は対応 Bash の非 interactive / 非 privileged / 非 POSIX mode、ENV は対象 shell の interactive 条件と Bash の POSIX 条件で選択を判定する。export / mode が不明なら非選択を推定しない | startup file に依存する wrapper / interactive shell、動的 export や未知 startup filename | 不要な startup source を実 per-call unset / 非 export / 確定空値で解除し、同じ目的・他条件を保てる場合だけ再検査する。regular Bash の未使用 ENV と noninteractive の未使用 prompt を維持する。necessary initialization を削除して目的が変わるなら owner へ | shell / version / mode、実 export / scope、startup word / body と必要な初期化を提示する | regular Bash と POSIX Bash、interactive / noninteractive / privileged、empty / unset / export解除 / prefix / inherited、再 export / child、mode の先行 effects |

### Git の実行・server・object・将来設定 source

| 条件 | own EG 判定・役割 | 保持する対照と通常影響 | 同目的の対応形式／owner出口 |
|---|---|---|---|
| upload-pack/upload-archive/receive-pack/http-backend/cvsserver/gitweb/instaweb の active server | repo/object inventory・要求・network/config/source未検査 UNKNOWN。公開repoのserverも停止 | genuine stdout usageを保持。server literal pathを安全な本文証明にしない | listenerやCGIを起動せず対応queryで目的を保てなければ owner に対象repo・source・要求・destinationを確認 |
| p4/svn/cvsexportcommit/archimport/cvsimport/quiltimport の active foreign-SCM operation | external childrepo/config/source/transport未検査 UNKNOWN。import/downloadをlocal送信Fと断定しない | printed literal DATA、genuine terminal usageを保持。通常同期も停止し得る | 対応済みlocalqueryで同目的を保てなければ owner にSCM/source/操作/contextを確認 |
| bisect run、merge-index、for-each-repo、submodule foreach、rebase --exec、clone/fetch/fetch-pack/archive/ls-remote の selected upload-pack/exec | argv-selected program/shell本文とchild repo context未検査 UNKNOWN。literal callbackも本文認証ではない | consumed required values・known scalar・unused controlを保つ。未知 method/argvは限定 UNKNOWN。通常 callback や recursive repo作業が停止 | sourceを選ばない対応queryで同目的を保てなければ owner に実program/argv/source/contextを確認 |
| mergetool/history/verify-commit/verify-tag/gui/citool/gitk/scalar/sh-i18n/sh-setup、manual viewer | active tool/UI/signature/viewer/internal script context未検査 UNKNOWN | mergetool actual tool-help・真正stdout usage・help-a情報query保持。GUI、署名検証、manual表示にも影響 | 対応済みsource-free queryで同目的を保てなければ owner にhelper/input/configを確認 |
| commit -S/--gpg-sign、merge/pull signing/verify-signatures | selected signature helper/context未検査 UNKNOWN | ordered no-gpg-sign/no-verify-signatures、message DATA '-S'等は保持。署名・検証を必要とする通常操作が止まる | 署名要件を変えず対応可能か確認。owner判断なしで署名条件を落とさない |
| hook run、interpret-trailers active transformation | selected hook/trailer command/body/context未検査 UNKNOWN | typed hook list、ordered trailer parse/only-input query、consumed --parse DATAを保持 | queryで同目的を保てなければ owner にhook/trailer設定とbodyを確認 |
| commit-tree generated object | known producer secret source／secret message fileは既存policy FORBIDDEN。未証明選択・tree/identity/object inventoryは UNKNOWN | -m stored bytesと-p/-F object/file selectorを分ける。known ordinarymessageでも未検査object contextを安全認証しない | 対応済み通常commit形式で同目的を保てなければ owner に生成bytes・source・parent/tree・identityを確認 |
| mktree/index-pack/unpack-objects/update-ref/write-tree/read-tree/replay と未対応 update-index input | object/ref/index/input context未検査 UNKNOWN | update-index --add staticordinary pathsは own EG ALLOW、secret pathsは既存policy FORBIDDEN。show-index-version truequery保持 | 対応済みpath/query形式を検討。inventoryを証明できなければ owner確認 |
| standalone grep -O、positive diff/textconv、gc.recentObjectsHook、merge driver/custom strategy、submodule !update | 当該operationで選ばれる callback/source 未検査 UNKNOWN。commit存在の有無とは独立 | unused keys、no-textconv、builtin strategy、explicit submodule checkout/merge/rebase/none、cherry-pick/revert -s signoffを保持。通常変換/GC/mergeも停止し得る | helperを使わず同条件を保てる形式がなければ owner に当該source・operation・repo/env/configを確認 |
| typed Git config setter/delete/rename が選ぶ将来 helper source | 指定された core editor/pager/hooksPath/fsmonitor/askpass、sequence.editor、credential.helper、pager.*、diff.* command/textconv/external、filter.*、tar.*command、gc hook、trailer cmd/command、hook command/event、merge driver、gpg program、submodule update の future selection/fallback 未検査 UNKNOWN。即native実行／送信とは断定しない | getter、ordinary key、意味を証明した fsmonitor false、pager empty/cat/false、credential.helper empty reset、hook event empty reset、builtin submodule update保持。unsupported emptyのdisableを推測しない。通常設定保存・cleanupが止まる | 既存 getterで確認し、同条件の対応disableで目的を保てなければ owner にkey・scope・future operation・fallback/contextを確認。security hook bypassの承認へ転用しない |


### 公式の最終照合で補った identity / authentication 境界

`gh auth setup-git` は Git credential-helper 設定の persistent writer、`gh auth refresh` は browser / AuthFlow / scope / credential update と条件付き Git credential setup を選ぶ。両操作の active context は UNKNOWN とし、実 help と printed DATA は区別する。credential 使用を任意 file 送信の FORBIDDEN と読み替えない。通常の認証更新・Git 認証設定も停止するため、同じ host / scope / storage / helper 条件を保持した対応形にできなければ、必要な設定変更と未検査 source を owner へ確認する。根拠は cli/cli v2.102.0 の [setup-git](https://github.com/cli/cli/blob/v2.102.0/pkg/cmd/auth/setupgit/setupgit.go) と [refresh](https://github.com/cli/cli/blob/v2.102.0/pkg/cmd/auth/refresh/refresh.go) であり、実 native 認証・通信を行った証拠ではない。

Git の固定 inventory にない operation を ALLOW と同一視しない。driver の未対応 subcommand、または実行される直接 `git-*` の identity / source を解釈できなければ UNKNOWN とする。既知 function body の解析、Git 自身の真正 stdout usage / version、known builtin、印字 DATA は別に保つ。未知 helper に `--help` を付けても、helper 本文が実行されない証明にはならない。 新しい operation / source の分類は、実行主体として解釈した Git identity に適用する。通常の検索引数（例: `grep -rn git http-backend`）や印字 DATA の語を Git 実行へ昇格しない。従来の不透明 wrapper / 危険操作の保守的な判定は別に維持する。通常の custom alias / 外部 Git helper（例: 未検査の Git LFS による `git lfs ls-files`）や、新しい Git 版で増えた未対応操作も停止し得る。同じ操作を対応 builtin で表せる場合だけ再検査し、そうできなければ alias / helper body、argv、version、cwd / env / config、対象と未検査点を owner へ提示する。任意 program 全体を監査済みとはしない。

### 正常対照と拒否後の扱い

`--help` という文字列の存在は actual terminal query の証明ではない。例えば auth login の `-h` は hostname 値を消費し、その値が `--help` でも GH help とは扱わない。一方、対応する GH 自身の実 help、Bash の確認済み first literal help / version、印字 DATA、未使用の関数定義は別の対照とする。真の terminal query でも、それより前に外側 shell が評価する substitution / redirection 等の独立条件は残る。

既知 literal の filename / program 名は、その body・config・destination の安全証明ではない。input が local または query というだけで、その内部 source 全体が確認済みになるわけでもない。既存 raw backstop や別 hook が先に停止する場合は、担当 guard と返った理由も区別する。

止まった操作を対応済み形式で表せない場合は、表の operation / target / cwd / env / config / source / destination と不明点を owner に確認する。個別操作の了承は hook 無効化・変更の了承とは別である。対応形への書換えは同じ目的・対象・条件を保つ場合に限り、別の送信 tool、別 directory、単なる表示への変更を勝手な出口としない。

### 公式仕様と有限 inventory の版境界

Git の公式2.54 catalogは実行操作152と文書/interface19、補充server3の174行を区分した。さらに [http-push](https://git-scm.com/docs/git-http-push) / [http-fetch](https://git-scm.com/docs/git-http-fetch) の protocol helper と namespace 不明の境界を別に照合する。catalog 行数、直接入力数、native 成立、脆弱性数は足し合わせない。

GH の名前・option arity は installed **2.102.0** の **196 built-in entrypoints / 32 containers / 228 role entries / 56 built-in aliases** を固定して照合した。228 は operation-role 表の項目数で、196 と足した操作数や脆弱性数ではない。未知の stored alias / extension body、任意の生成値、全 argv / config 組合せを認証する inventory ではない。個別に取得した priority page と installed reference による全 inventory は別の証拠である。

公式の [GH API](https://cli.github.com/manual/gh_api)、[Issue comment](https://cli.github.com/manual/gh_issue_comment)、[PR review](https://cli.github.com/manual/gh_pr_review)、[PR create](https://cli.github.com/manual/gh_pr_create)、[skill publish](https://cli.github.com/manual/gh_skill_publish)、[environment](https://cli.github.com/manual/gh_help_environment) を operation / input の役割へ対応付ける。current web manual を installed binary の全 runtime / helper 成立証明へは使わない。

pager の順序は official cli/cli **v2.102.0** の [issue list](https://github.com/cli/cli/blob/v2.102.0/pkg/cmd/issue/list/list.go#L209-L216)、[IOStreams](https://github.com/cli/cli/blob/v2.102.0/pkg/iostreams/iostreams.go#L217-L220)、[command setup](https://github.com/cli/cli/blob/v2.102.0/internal/ghcmd/cmd.go#L388-L394) に照合する。issue list は pager 起動処理の後に JSON exporter へ分岐し、IOStreams は選択 pager が空 / cat または stdout 非 TTY のとき起動しない。source の順序と、当該実行での TTY・通信・helper 起動成功は別に確認する。

shell は [GNU Bash startup](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)、[interactive behavior](https://www.gnu.org/software/bash/manual/html_node/Interactive-Shell-Behavior.html)、[Zsh files](https://zsh.sourceforge.io/Doc/Release/Files.html)、[Fish](https://fishshell.com/docs/current/cmds/fish.html) と installed 版の無害 marker / mode 観測を区別する。Bash3.2 / 5.3 の有限観測を別 interpreter や任意環境へ一般化しない。fresh page 取得失敗、installed upstream manual、旧取得の extract はそれぞれ記録し、URL の記載だけを全文取得成功としない。

### R22 の検証状態と必要な証拠

最終候補 **v10** の4 sourceを **2026-10-14 10:26:59 JST** に固定し、以下を取得した。公開 head の required CI / 両 fresh review / thread は、PR本文と監査記録で同 head・取得時点を別に確認する。旧headの成功を持ち越さない。

- **L1 / API:** 公開解析88、production filename parity8、別の私有deny API6の **102/102** が成功。私有Git metadata / policy契約 **45/45** も同じ4 sourceで成功した。これらは重なる境界を異なる層から確認する測定であり、独立脆弱性数やnative実行回数へ合算しない。
- **L2:** **4569/4569** が **10:30:36 JST** に成功、broken0、4 source / 固定public runner不変。元4208の ID / command / stdin / cwd / project / envを保持し、unique361を追加した。旧期待は別の原定義に保存し、変更57件の採用理由を記録した。同じ4569入力・現在の期待を固定026へ渡した **10:30:31 JST** の比較は232 assertion差。observable差255の内訳は実decision219（ALLOW→deny202、deny→ALLOW17）とhook / reasonのみ36であり、重なる集計を脆弱性数として足さない。元4208の旧期待は固定026ですべて一致した。初期6レビューの正確なcommandも保持し、own egressが2 UNKNOWN / 4 FORBIDDENで停止した。
- **私有対照:** Git249/249（原205＋function8＋namespace24＋identity6＋同原因role6）がbroken0 / source不変で成功。GH / shellの原199観測に、期待付き通常・停止対照86を加えた285入力も、期待付き86すべて一致した。観測だけの199を199 PASSとして扱わない。
- **reverse:** Git38のうち37で分類への寄与、1でmetadata変化だけを確認した。own停止消失31、aggregate停止消失28。独立SG / AGが残る3件、FORBIDDEN→UNKNOWNの精度1件、通常DATAの許可精度5件、metadataのみ1件は、当該条件単独の停止必要性を証明したものではない。通常対照はown38 / aggregate37の許可を維持し、残る1件は独立egress source UNKNOWNを保持する。別のGH / shell14条件はown停止消失と正常許可をすべて確認した。異なるphaseの同じedgeを追加件数として重ねない。
- **L3:** CLI **2.1.296** の新DUMMY6試行は **10:30:41 JST** に **5 PASS / 0 FAIL / 1 NOT_EXERCISED**、source不変。literal GH fd0は許可とlocal stub markerのみの期待変化、公開file投稿はFORBIDDEN、auth refresh / Git LFS / direct unknown Git helperはUNKNOWNを実dispatchで確認した。停止した4件はHEAD / refs / index / objects / file / helper / sink marker不変。通常 `grep -rn git http-backend` はAPI cyber safeguardがBash / hook前で停止し、hook0・全状態不変のNOT_EXERCISEDである。再試行・迂回せず、L2でのALLOWと実入口未確認を分ける。native auth / sender / server / helper / 実秘密は使用していない。

一時候補でのsyntax failure、function-prefix sourceを落としたALLOW、役割を取り残したALLOW、通常DATAの誤拒否、理由精度の不一致、fixture / processor前提の訂正を、修正前の原結果とsource別に監査記録へ残した。旧sourceでの同入力観測がない候補を新導入の退行と断定しない。公式inventoryの照合と上記有限測定は、任意Bash / helper本文、implicit owner設定、native認証・通信、全OS / 版 / argv組合せの安全認証ではない。広い責務分割のリファクタリングは今回行わない。


## R21: 修正の条件・結果・例外

公開 head `35145135458da162f3e4faa778074bf3fb284439` への fresh Codex review は、2026-10-14 **07:24:12 JST** に P1 5件を返した。**07:32:09 JST** の全ページ取得では thread **122 / resolved 117 / open 5**、CodeRabbit 0 / Codex 5、PR は OPEN / BLOCKED、auto-merge なしである。CodeRabbit の同 head full review は完了して指摘0だった。以下は修正前に決めた条件に、対照試験で確認した境界を追補したものである。新 source のローカル試験と、新 head の required CI / 両 fresh review / thread 解決は別の証拠として取得する。

| 対象・停止条件 | 結果と理由 | 維持する例外・DATA | 通常作業への影響と owner への出口 |
|---|---|---|---|
| **Git `send-email` の送信 source** | 確定した file / directory payload は既存 file 送信禁止の FORBIDDEN。revision selector、未検査 argv / source / SMTP・sendmail・validate helper / destination は UNKNOWN。`--dry-run` は外部送信を実施しないが、その他の処理を検査できる保証ではない | 確認した sole `-h` usage。option が消費する `-h` DATA や revision を file と混同しない。dump / alias 展開も無条件の安全 getter としない | 通常の公開 patch 送信も停止する。表示 query は送信の代替ではない。送信が必要なら recipient、payload、cwd、config、helper、mode と不明点を owner へ |
| **GH `workflow run` の JSON stdin・typed field・generated input** | `--json` の fd0 と `-F` / `--field key=@file` を既存 payload 判定へ接続する。確定 file input と関連 secret reader は FORBIDDEN。未検査 stdin / field / source / argv は UNKNOWN。`-f` / `--raw-field` は `@` を file 構文として解かないが、生成値の出所は検査する | 対応する既知 ordinary literal / scalar field と、証明した単一 quoted fd0 heredoc / known here-string、実 help、printed DATA。literal stdout pipeline は、この追加判定では source proof に対応せず UNKNOWN。repo / ref / workflow selector の消費値は input と混同しない。ordinary filename も file upload 禁止の対象 | 公開 JSON / file による workflow input も停止する。同じ値・目的・条件を保つ対応 inline input で表せる場合だけ再検査。file / 未知 stdin や interactive input が必要なら workflow、ref、repo、input source を owner へ |
| **active Git `filter-branch` の argv-selected source と history context** | setup / 各 filter は shell source。revision / cwd / refs / index / helper の実行条件を検査できない active rewrite は UNKNOWN。静的 `:` filter だけで history rewrite の安全を証明しない | 確認した sole `-h` usage。filter が消費した `-h` / `--help` DATA を query としない | 通常の公開履歴の filter も停止する。同目的の対応 writer 代替はない。rewrite 対象、backup、全 filter source / context と不明点を owner へ |
| **active Git `daemon` の repository server** | serve directory、object / ref inventory、service / helper / config、公開条件が未検査の repository egress として UNKNOWN。default server や `--export-all` の有無を含む active server が対象 | 確認した sole `-h` usage。base path / listen / access-hook 等の消費値や directory を query としない | 通常の公開 repository server も停止する。同目的の対応 server 代替はない。serve 対象、protocol、bind / auth、access / service / config と不明点を owner へ |
| **Bash の active PS4 / xtrace source** | stored PS4 と trace / promptvars の mode・順序・scope を追跡する。実 trace 前に選ばれる未検査 prompt source は UNKNOWN。単なる PS4 の存在だけで全 Bash を停止しない。BASH_XTRACEFD の変更は source 展開の解除ではない | unused PS4、確認した static prompt、実 disable / promptvars off、local / export / child の選択を区別。`set +x` / unset / reset 自身は旧 active PS4 で trace され得るため、後続の解除を先取りしない。版不明の `local -` による option 復元は証明しない | 動的 trace prompt、未確定 shell mode、PS4 / trace / promptvars を変更する登録済み trap callback の未対応状態も停止し得る。ordinary echo callback、trap query / reset と印字 DATA を区別する。確認した static prompt で同じ目的を満たせる場合だけ再検査。必要な未知 prompt / mode は source、shell / version、env、function scope と不明点を owner へ |

停止後に対応済み形式で目的を満たせなければ、表の対象・操作・実行条件を添えて owner に確認する。個別操作の了承を hook 無効化の了承へ広げず、別の場所や別ツールからの実行を自動的に許可された代替経路としない。secret-git / add-all の conditional Git 入口と全 Bash egress の設定は維持し、egress 自身の停止と実 dispatch を別々に測る。

### 修正前の分類漏れと有限の調査範囲

5指摘の正確な入力は GH の2形式を含む6本である。元の command を変えず、`3514513` / `df463a91` / `4f0ff562` / `387688f` の固定 source に Hook INPUT DATA として渡した24行は、すべて全3 hook ALLOW、own egress ALLOW、broken0、各 source 前後不変だった。これは4 snapshot の同じ6入力であり、24独立脆弱性や実通信・被害の確認ではない。この有限比較では、6経路は修正が新設した穴としては観測していない。

`g''it daemon --export-all .` は common parser が `git` / `daemon` / `--export-all` / `.` を正しく取り出していた。不足は egress の server 操作分類である。[Git daemon の公式仕様](https://git-scm.com/docs/git-daemon)では `--export-all` が `git-daemon-export-ok` を不要にする。この flag 自体は Git の想定動作であり、公開対象の objects / refs をガードが検査できないことを UNKNOWN の理由とする。未追跡の working-tree file がそのまま公開されるとの主張はしない。

悉皆調査は、固定した Git 版の operation 一覧と、対応 option / mode / source の範囲を決めれば分類漏れを点検できる。任意 Bash、外部 helper、環境設定、生成値の全組合せを確認済みとはしない。read / write / send / server / executable-source の役割を保ち、担当がないものを保護済みと記録しない。今回の修正は5条件と必要な正常対照に限定し、責務を分割する広いリファクタリングは別作業とする。

[Git send-email](https://git-scm.com/docs/git-send-email)、[filter-branch](https://git-scm.com/docs/git-filter-branch)、[GH workflow run](https://cli.github.com/manual/gh_workflow_run)、[GNU Bash](https://www.gnu.org/s/bash/manual/bash.html) の一次仕様と、installed 版の marker / usage 観測を区別する。macOS Bash 3.2 / 5.3 で PS4 36観測、Git / GH sole usage 4観測、隔離 DUMMY filter setup 1観測の合計41観測を取得した。41 PASS と集計しない。PS4 の `set +x` 自身が旧 source を展開し、promptvars off は両版で marker0だった。Bash3.2 の `local -` 非対応2形は stderr 診断があり、exit0だけで復元成功としない。DUMMY filter の marker は成立し、HEAD / refs / index / objects / status は前後一致した。native sender / server / GH dispatch、実秘密は実行していない。

### R21 の検証状態

最終 v4 の固定 source は common `7f797e63fa52cdf9e8896eef578771496e389e1b47397939c9dd7f30e1ca06f8` / egress `0d3d9b478800a72029bf963d1c6db3a7b877262ac6a9b163b3a7d32831d6c047`。add-all / secret-git は R20 と同じ hash である。初回 freeze、ANSI unknown sentinel の訂正前 v1、間接参照 printf の訂正前 v2、GH stdin / callback の訂正前 v3 を保存し、その成功を v4 へ持ち越さない。

- **L1 / API:** 公開解析80、filename parity8、別実行の私有 deny API6 は94/94。私有 metadata30/30も v4 で成功した。初回 parity の誤 filename による85件実行と、v3 の93件結果は原記録を残し、最終94件に加算しない。
- **L2:** 旧4124の ID / command / stdin / cwd / project / env と期待を変更せず、新 unique84を加えた**4208/4208**が **2026-10-14 08:12:01 JST** に成功した。broken0、4 source / 固定 public runner 不変。固定351へ同じ4208入力・期待を渡した08:11:59 JSTの比較は50 assertion差、実decision差49、hook / reasonのみの差1で、脆弱性数ではない。旧4124の期待は両sourceですべて一致した。元レビュー6 commandとclean contextを保持し、egress自身が2 FORBIDDEN / 4 UNKNOWNで停止した。send-emailの実在file対照はdirty / a.txtの別入力であり、cleanに.envがない前提を実secret送信成立と混同しない。
- **reverse:** 使い捨て v4 コピーの単一edge反転14試行は14/14、broken0、元source不変。拒否の必要性11、普通literal stdin許可の必要性1、分類精度2を分ける。stat proofと@-役割の2試行は別のUNKNOWN停止が残るため、拒否必要性は未証明として記録する。normal controlsと他の独立ガードを保持した。
- **L3:** v4の新DUMMY2試行は **08:10:09 JST** に2 PASS / 0 FAIL / 0 NOT、source不変。typed field @- のordinary here-stringはegress、quoted JSON heredocは全3 hookの実dispatchと許可を確認し、GH local stubの期待marker以外のHEAD / refs / index / objects / files / markersは不変だった。実GH workflow dispatch / authentication / transportは行っていない。追加のfile-backed @- 1試行はAPI cyber refusalでBash / hook前に停止し、状態不変だった。再試行せずNOT_EXERCISEDとして残し、egressの実dispatch成功へ数えない。v3の5試行 / 4 PASS / 1 PS4 API cyber refusal NOTは履歴であり、v4へ加算しない。PS4の拒否は再試行せず、v4のPS4 / callback実dispatchは未確認として残す。

候補版のPS4 writer3 / ANSI unknown / 間接参照printf / 登録callbackの漏れ、stat branchのfs import欠落による実在a.txtのFORBIDDEN→UNKNOWN、clean.env / public.patch不存在の試験前提、GH @- unknownをFORBIDDENとした理由精度、ordinary here-string / JSON heredocの過剰拒否も保存した。登録callbackは固定351でも通過した旧取り残しであり、候補版が新しく実通信を可能にしたとの主張はしない。採取器の全環境値過剰記録は最小contextへ訂正し、runnerの実行開始時と終了時whole-file SHAの違いは、CASES外の実行コード同一性と最終固定runnerの再取得で分離した。

旧 R20 の4124件、80契約、3実入口PASSは履歴であり、変更 source の証拠には持ち越さない。新 head の required CI、両 fresh review の指摘0、未解決 thread0を別に要求し、merge は行わない。

## R20: 修正の条件・結果・例外

R19 公開 head `387688f25e9a23b7cbb37f49060df1d8f1583545` への fresh Codex review は、2026-10-14 **06:29:21 JST** に P1 4件と P2 1件を返した。06:30:33 JST の全ページ取得では thread **117 / resolved 112 / open 5**、CodeRabbit 0 / Codex 5、PR は OPEN / BLOCKED、auto-merge なしである。以下は、修正前に決めた対応範囲・結果・例外である。新 source の試験、公開後の CI と両 fresh review、thread の状態は別に取得し、旧 head の成功を持ち越さない。

| 対象・停止条件 | 結果と理由 | 維持する例外・DATA | 通常作業への影響と owner への出口 |
|---|---|---|---|
| **active `chroot` launcher** | root / uid / cwd / executable と子の実行条件を検査できず UNKNOWN。実際の root 権限や子の起動成功を推定しない | 対応する先頭の実 terminal help / version。子の引数に現れる `--help` を launcher の query とせず、外側 shell の展開も独立して検査する | 公開ファイルを使う通常の chroot も停止する。別 root へ移すことは同じ実行条件の代替ではない。root / uid / cwd / 子 argv と不明点を owner へ |
| **Git の active pager selector**: 同じ入力で選択する `GIT_PAGER` / `core.pager` / `PAGER` と、pager を使う operation / paging mode | 選択された未検査 helper は UNKNOWN。TTY 条件が不明なら、実行されないと推定しない。selector の存在だけで全 Git を停止しない | 対応する実 `-P` / `--no-pager`、unused operation / getter、実 unset / `env -u`、prefix / export / 継承の選択と上書き順序。消費された `--no-pager` DATA は解除ではない | custom pager を使う log 等も停止する。同目的の出力を helper なしで読める場合だけ actual disable と対応 argv で再検査。pager が必要なら operation / TTY / env / config / source を owner へ |
| **GH `secret set` / `variable set` の body・env-file・stdin** | 確定した file-backed payload は既存 file-upload policy の FORBIDDEN。secret 由来の body も FORBIDDEN。生成元や argv / stdin が未検査なら UNKNOWN。空の body が stdin を選ぶ条件も区別する。secret の実 `--no-store` は payload を保存しない別 mode なので未検査の local 暗号化処理として UNKNOWN、file 送信確定とはしない | 対応する既知 ordinary literal / scalar body、実 help / list / query、repo / org / environment / app / visibility 等の消費 DATA。先頭 `-R` / `--repo` の値も DATA として消費し、既存対応群の payload 分類へ渡す。独立した context / raw 条件は残る | 公開 env-file と未知 stdin による登録、未検査の no-store 処理も停止する。同じ目的・値・条件を保つ確認済み inline DATA の対応形式がある場合だけ再検査。file / stdin / 暗号化処理自体が必要なら owner へ |
| **Git `imap-send` の送信 stdin** | 同じ pipeline / redirection で結び付いた secret filename 入力は FORBIDDEN。未検査 mail input、設定・destination・認証 source は UNKNOWN。mbox の有効性や実 IMAP 通信は認証しない | 実 stdout usage 等の対応 terminal query。無関係な reader を送信 source とせず、消費 DATA と実 option を区別する | 通常の公開 mail 送信も、必要条件を検査できない範囲では停止する。表示 query は同目的の送信代替ではない。mail source / destination / 認証 / cwd / env / config と不明点を owner へ |
| **commit identity の export 属性と選択 source** | 値の生成元と外部 Git へ渡る export 属性を分ける。選択された secret 由来値は FORBIDDEN、export target / field 優先 / child source の証明不足は UNKNOWN。未 export の親 shell local を Git identity としない | literal / 対応 scalar、実 export / export解除 / unset / allexport、prefix、scope と非 local の関数更新を区別。`EMAIL` は既定 config による fallback 選択が未証明なら secret 由来の使用を確定せず UNKNOWN | 動的 export target、未知 fallback、未対応 child の値生成は停止し得る。同じ identity と実行条件を保持する対応指定で表せる場合だけ再検査し、source / export / config の不明点を owner へ |

### 修正前の取り残しと、公開修正が生んだ過剰停止

新 P1 4件の正確な入力は、`df463a91` / `4f0ff56` / `5d50164` / `387688f` の固定 source へ DATA として渡すと、4入力×4 head の16件すべてで全3 hook が ALLOW、broken 0 だった。この有限比較では、4経路は今回の修正が新設した穴ではなく、以前から未分類だった実行・送信経路である。chroot の権限、pager の TTY、GH の書込権限、IMAP 設定・通信の成功や被害を確認したという意味ではない。

一方、`GIT_AUTHOR_NAME="$(cat .env)"; git commit -m ordinary` は、旧 `5d50164` では ALLOW、R19 公開 source では egress FORBIDDEN となった。未 export の shell local を Git へ渡る identity と誤認した公開退行であり、R20 で値と export 属性を分けて修復する。隔離 DUMMY の read-only `git var` では、未 export / export解除は configured name、export / allexport / prefix は assigned name を選ぶことを照合した。初期 child / EMAIL / export target 対照の不一致と、私有記録の上書き・再取得も監査記録へ残し、最終 source の成功へ書き換えない。

filename parity の P2 は、Linux にない `en_US.UTF-8` を試験 caller に強制して Bash 起動 warning を比較した試験器の問題である。production の `LC_ALL=C` と filename 規則は変更せず、caller は保証された C を基準に、`locale -a` で利用可能な optional locale だけを実行する。不在 variant は diagnostic で記録し、stderr の空出力を要求する検査を緩めない。Mac native 8/8 と C/POSIX 限定の controlled inventory 8/8 を、Linux native での再現や全 locale の保証と区別する。

[Git の pager 仕様](https://git-scm.com/docs/git-var)は `GIT_PAGER` / `core.pager` / `PAGER` の優先と shell 解釈を示す。[GH secret set](https://cli.github.com/manual/gh_secret_set) / [variable set](https://cli.github.com/manual/gh_variable_set) は body、stdin、dotenv file の入力経路を持つ。[Git imap-send](https://git-scm.com/docs/git-imap-send) は stdin の mailbox を送る。新しい版の `--list` も IMAP 通信を行うので、local stdout help と同じ許可 query にはしない。これらの仕様と、実機版・DUMMY fixture で測った事実は区別する。

### R20 の検証状態

最終凍結 source は common `e3d49e812554ef688dda96af418f0c0a4fb953e534bdc088611f204fc5674d60` / egress `4719d0798abd44250d290b567cb91d260c78b038a2634197c56aa8c779067d28`。add-all / secret-git は下記 R19 の hash と同じである。途中 export-state の直接45件 / 私有 L1 24件 / reverse 10試行は、追加 P1 修正後の source の新測定へ持ち越さない。関数非 local merge の reverse は独立した context 停止が残り、単一 edge の必要性未証明として記録する。

- **L1 / API:** 公開解析66・filename parity8・私有deny API6の80契約が成功。私有 API6 は公開解析へ加算しない。新 P1 に関する私有 parser / provenance 20契約と export 24契約も、同じ最終 source で成功した。初回の80契約指定は私有APIのfilenameを誤り74だけを実行したため、原出力を残し正しい6を含めて再取得した。
- **L2:** 旧4021入力・旧期待は、固定387 sourceでは4021一致、最終 sourceでは4018一致・3不一致、broken0・source不変。R7SG19 / R7SG21はactive pagerのALLOW→UNKNOWN、R19Xenv-EMAILは未知fallback選択のFORBIDDEN→UNKNOWNで、入力を変えず根拠付きで期待を更新した。新105入力の own-hook 対照は105/105、重複3入力はaliasとして残しunique102を公開suiteへ追加し、別preamble variantを保持したままIMAPの元レビュー入力1件も追加した。**最終統合4124件は2026-10-14 07:07:30 JSTに4124/4124、broken0・source不変。** 同じ4124入力・期待を387へ渡すと57のassertion不一致。実decision差46・hook / reasonだけの差15は別の集計で、脆弱性件数ではない。
- **L3:** CLIの新DUMMY5試行は06:57:57 JSTに3 PASS / 0 FAIL / 2 NOT_EXERCISED、source不変。chrootとGH stdinはegressだけがdispatchされ停止、imap-sendは全3 hookがdispatchされegress UNKNOWNで停止し、いずれもHEAD / refs / index / objects / file / markerは不変。pagerと未export identityはAPI cyber refusalでBash / hook前に停止、再試行せず未検証として残す。identityの予定commit条件がfalseだったことを、望まない副作用が発生した意味にしない。両NOTの状態も不変だった。旧sourceの実入口成功を、この2項目へ持ち越さない。

最終 source の新 P1 reverse 8試行と export reverse 10試行も期待を維持した。新 P1 の target effect は8、有限対照でのaggregate拒否への必要性は6で、precisionの作用と区別する。export target effectは9で、関数非local更新は独立したcontext停止のため必要性未証明のままである。

公開後の同じ head の required CI、両 fresh review、thread 解決はPR本文・監査記録で確認する。ローカル測定だけで受入・goal達成とはしない。

## R19: 修正の条件・結果・例外

公開 head `5d50164a1774df4c75f472a1f2873e21d207c186` の取得履歴は、2026-10-13 **23:52:57 JST** に required CI 成功、review thread **112 / resolved 103 / open 9**（CodeRabbit Major 2、Codex P1 7）、PR は OPEN / BLOCKED、auto-merge なしである。以下はこの9指摘と同じ原因の近接経路に対応する修正条件と固定sourceの測定である。CI / fresh review / threadは公開後のheadと取得時点をPR本文・監査記録で別に確認し、本節のローカル成功だけで全greenとはしない。9指摘には GH key の2形式と Git helper の2形式があるため、正確な再現入力は11件となる。

各行の ALLOW は、その行の境界で停止を追加しない条件である。既存の index / filename、hook、editor、cwd / env / config / source、raw backstop の独立した条件を残す。raw backstop が先に停止すれば、解析側の FORBIDDEN があっても返る理由は UNKNOWN になり得る。

| 対象・停止条件 | 結果と理由 | 維持する例外・DATA | 通常作業への影響と owner への出口 |
|---|---|---|---|
| **add / stage の実 pathspec と cwd / source**: 先行 `cd` / `pushd` 等で cwd が変わり、静的な絶対 `-C` で再指定していない、または `unknownContextBefore` が残る | active / unsafe pathspec は UNKNOWN。確認した一括 option / root は既存どおり FORBIDDEN | 実 stdout help、対象のない対応 option、option が消費した DATA を active path としない。静的な絶対 `-C` と後続の確定 `-C` は cwd の再指定に使えるが、未知 source / environment の証明は回復しない | `cd sub; git add a.txt` も停止する。同じ repository・file を確認して対応する絶対 `git -C` で表せる場合だけ再検査する。source 等が不明なら対象・cwd・argv と不明点を owner へ |
| **legacy `git config` の最初の operand**: key 後の `--get` / `--list` は DATA。例: `git config core.fsmonitor ./x.sh --get; git commit -m m` | config write を read-only とせず、commit 前の writer として UNKNOWN。helper の実起動を確認した判定ではない | option 領域の実 getter、対応する `config get` / `list`、消費 value / pattern を維持。commit がない単独 config write は、この pre-commit 条件だけでは停止しない | 通常の identity 設定と commit の連結にも影響する。同目的の設定・commit を個別に検査できる場合だけ分け、後続 commit の index を再確認する。必要な先行処理を検査できなければ owner へ |
| **`git mktag` の object 書込み**: stdin の tag object は staged filename 検査の対象外 | 公開 message / object も UNKNOWN。内容・入力 object・実行条件を検査できない | 実 stdout usage `git mktag -h` を維持 | 通常の tag object 作成も停止する。同目的の対応 writer 代替はない。入力 object・message・cwd / env / config / source と不明点を owner へ |
| **Wget `--load-cookies` の選択 file** | 確定した file / argv / context は既存の file 送信禁止で FORBIDDEN。未証明の file / source / argv は UNKNOWN | `--user-agent=--load-cookies` 等の消費 DATA、`--save-cookies` の出力と区別。既存の実 `--no-config` 条件も必要 | 公開 cookie file も停止する。同じ目的・条件を保つ確認済み非秘密 inline DATA の対応形式がある場合だけ再検査し、file 入力自体が必要なら owner へ |
| **GH `ssh-key add` / `repo deploy-key add` の file / stdin payload** | 確定した key-file は既存の全 file-upload 禁止で FORBIDDEN。file 未確定、引数省略・`-` による未検査 stdin は UNKNOWN | 対応する実 help / list、title / type / repository の消費 DATA を維持 | 通常の公開鍵 upload も禁止範囲に含む。公開鍵を許可するには別の policy と検証条件が必要で、秘密 filename の例外や個別操作承認から許可を推定しない。file / stdin 登録に同目的の対応代替はなく owner へ |
| **Git の active `core.fsmonitor` / `tar.<format>.command`**: fsmonitor は対応 index 消費・更新操作、archive は実 format / output filename の選択を確認 | active fsmonitor 値 / 未確定 config-env、選択 archive command / 未確定 format は UNKNOWN。`rm` / `mv` / `am` も index 読取や条件付き処理で callback を起動し得る操作として対象 | 最後の確定 fsmonitor 値が `false` / `no` / `off` / `0` の disabled 条件、対応する非 index query・getter・実 stdout help、未使用 archive format / 実 list を区別。消費値の `--list` は option としない | `/usr/bin/true` を指定した status と `core.fsmonitor=true` も UNKNOWN。通常の rm / mv / am にも影響する。helper を呼ばない同目的・同条件の対応形にできる場合だけ再検査し、helper が必要なら対象・selector・source と不明点を owner へ |
| **remote rsync の実 `--files-from`**: remote operand がある場合、両方向で local file の要求 filename が相手へ渡る | 確定した local filename list は既存の outbound file 禁止で FORBIDDEN。stdin `-`、remote list `:`、未知 file / argv / source は UNKNOWN | 完全 local copy、実 help / version、`--out-format=--files-from` 等の消費 DATAを区別。remote destination / RSH 条件も独立 | remote download でも公開 filename list は停止する。local copy は同じ目的の場合だけ対応例となり、remote transfer の代替とはしない。remote file list が必要なら owner へ |
| **commit の message / author / date / trailer の生成元**: 値の役割と元の source span を保持し、その値を作る reader / stdout を関連付ける | 関連する対応 reader の secret filename operand は FORBIDDEN。未証明の変数・producer・stdout / argv / context は UNKNOWN。staged path とは別の commit object DATA 判定 | literal / 対応する既知 quoted scalar、確認した literal stdout / 非秘密 filename readerを維持。message の単一 quoted fd0 heredoc `cat` は引数・別 redirection / pipeline がない対応形。消費値と実 `--` 後の operand、無関係な先行 readerを区別 | 未証明の MSG と AUTHOR、内側で cd / status / export を伴う未対応生成も停止する。内側 cd が外側 cwd を変えるとの判定ではない。同じ目的・bytes・条件を保つ literal / 対応 proof にできる場合だけ再検査し、できなければ owner へ |
| **commit が選ぶ identity env / config の生成値**: 同じ入力の `GIT_AUTHOR_NAME` / `GIT_AUTHOR_EMAIL` / `GIT_AUTHOR_DATE`、対応する3つの `GIT_COMMITTER_` 名、選択された `EMAIL` fallback、`-c` / `--config-env` の user / author / committer name・email | 選択値に結び付いた secret reader は FORBIDDEN。選択 source / scalar を証明できなければ UNKNOWN。単なる env 存在や全 Git config を一律停止しない | prefix / 永続代入の元の word、対応 literal / scalar proof、実 unset / env unset、上書き順序と field ごとの優先を保持。author / date option が対応 env field を上書きし、未使用 query の値は commit DATA にしない | 変数から作る identity / config-env にも影響する。確認済みの同じ identity・条件を対応 literal / scalar で指定できる場合だけ再検査し、必要な生成処理・設定を検査できなければ owner へ |
| **nameref による選択 identity の証明喪失** | 既存の nameref taint により、すでに保持している identity source word を未証明にして UNKNOWN。参照先や実漏えいを推測しない | identity が選択されていない nameref はこの追加条件の対象外。新しい literal prefix の identity は、その invocation 自身の値の証明を回復する | 間接変数で identity を更新する通常処理も停止し得る。同じ値・目的を確認できる直接の対応指定へ表せなければ、参照先・source・条件と不明点を owner へ |
| **curl `--netrc-file` の明示 credential file** | 確定した nonempty filename / argv / context は既存の outbound file 禁止で FORBIDDEN。未証明の filename / source / argv は UNKNOWN | option が消費した `--netrc-file` という DATA と区別。実 first literal `-q` / `--disable` は必要。`--no-netrc` は明示 file の選択を消さない | 通常の credential file 利用も停止する。同じ目的・条件を保つ確認済み非秘密 inline DATA の対応形式がある場合だけ再検査し、file 入力自体が必要なら owner へ |
| **curl `-n` / `--netrc` / `--netrc-optional` の暗黙 file 選択** | 実 argv / context で有効な選択は、既定 `.netrc` からの credential 入力として既存の file 送信禁止で FORBIDDEN。選択・argv / source が未確定なら UNKNOWN | `--no-netrc` と `--no-netrc-optional` は対応する各 flag だけを解除する。両 flag は別々に追跡し、消費 DATA、実 terminator / 対応 terminal query を区別。`-A-n` は user-agent DATA | 既定 credential file を使う通常 request も停止する。`.netrc` の存在・内容・認証 header の成立を確認した判定ではない。file に依存しない同目的・同条件の対応形がなければ source・宛先・設定を owner へ |

### commit object の DATA と selector

message と trailer は複数の値を保持する。author / date は最後の scalar を選択し、env / config も実際の順序と field の優先で使われる値を選ぶ。選択した word は option / assignment の既知 carrier だけを外し、`raw` / `start` と producer の scope / order を保って既存の payload provenance 判定へ渡す。literal prefix がある生成値も、それだけで非秘密とはしない。この追跡は同じ入力で選択した値の経路に限り、既定 config file や実行環境内の任意 identity 値の内容を包括的に監査するものではない。

| 役割 | R19 の扱い |
|---|---|
| `-m` / `--message`、`--trailer`、`--author`、`--date` と選択 identity env / config | object に入る値の生成元を検査する。secret filename 読取が対応する値と結び付けば FORBIDDEN、未証明なら UNKNOWN。author / date / trailer として有効な bytes であることや実際の object 保存・送信は確認していない |
| commit の `-C` / `-c` による reuse / reedit-message、fixup 等の既存 object selector | object の選択と編集条件を既存の担当へ残す。selector の文字列を、新しく読んだ file bytes と同一視しない。Git global `-c key=value` とは役割が異なる |
| `mktag` / hash-object 等の未検査 object writer | 入力 object / 内容・副作用を検査できないため UNKNOWN。公開入力でも自動許可せず、対応 query は同目的の writer 代替とはしない |
| literal / 証明済みの scalar identity、無関係な reader と静的 metadata、消費された option-like DATA | この生成元の境界では停止を追加しない。他の index・writer・helper・raw 条件は残る |

[Git commit の仕様](https://git-scm.com/docs/git-commit)は author / date / message / trailer を区別する。Git の [mktag](https://git-scm.com/docs/git-mktag)、[core.fsmonitor](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corefsmonitor)、[archive](https://git-scm.com/docs/git-archive) の仕様と、ガードが未検査 source を UNKNOWN にする採用条件は分ける。`rm` / `mv` / `am` の callback 条件は、Git の index 読取が fsmonitor を調整する [read-cache](https://github.com/git/git/blob/master/read-cache.c) と、必要に応じて callback を呼ぶ [fsmonitor](https://github.com/git/git/blob/master/fsmonitor.c) の経路に基づく潜在実行条件であり、この検証で helper を実行した観測ではない。

[curl の netrc 仕様](https://curl.se/docs/manpage.html#-n)と、確認した installed curl 8.7.1 の [実装](https://github.com/curl/curl/blob/curl-8_7_1/src/tool_operate.c)では optional flag、required flag、明示 netrc file を別々に扱う。`--netrc-optional --no-netrc` は optional を残し、`--netrc --no-netrc-optional` は required を残す。`--netrc-file ordinary.txt --no-netrc` も file 選択を残す。各解除を行って選択がなくなった対照と、option に消費された印字 DATA を維持する。

### R19 で修復した通常対照と残る独立条件

追加64対照は成功したが、拡張した84対照の初回では2件の通常対照が過剰停止した。`VALUE=ordinary; export VALUE; git --config-env=user.name=VALUE commit -m ordinary` は純粋な export の後に path proof が失われ、known scalar を UNKNOWN とした。選択 config-env に既存の未 taint の scalar value proof を使うよう修正した。`read -p GIT_AUTHOR_NAME VALUE` は prompt DATA を identity の代入先と誤認したため、実 read target の役割だけを新しい identity source 無効化へ使うよう修正した。期待を書き換えて隠さず、元の失敗を保存して再検査した。

後者の完全な対照 `export GIT_AUTHOR_NAME=ordinary; read -p GIT_AUTHOR_NAME VALUE <<< ordinary; git commit -m ordinary` は、修正後に egress が ALLOW となる一方、既存 secret-git の先行 writer 条件は UNKNOWN のままである。これは旧版でも残っていた独立した停止であり、全3 hook の ALLOW としない。nameref 経由の更新で旧 identity literal を保持してしまった実装上の穴も別に検出し、選択 identity の proof を無効化する修正・fresh prefix と未選択 nameref の対照を加えた。

元の quoted heredoc message（N06）は維持する。未証明 message / author、active fsmonitor、内側 context を伴う生成値は、同じ入力を保持して UNKNOWN への方針変更として記録する。既存の raw backstop は残り、対応する parsed DATA でも UNKNOWN が先に出る形がある。個別 operation の owner approval を hook 無効化の承認へ広げず、別場所へのコピー、実行名の変形、別ツール経由を承認済みの出口にしない。

### R19 の証拠と未取得の測定

最終凍結4 source は以下で固定する。旧 source の測定をこの組へ持ち越さない。

| module | SHA-256 |
|---|---|
| add-all | `88d0c56bb53168c5c6aa5a4361644e44f21f84c4a2ce88d7f33b5942384e0fd8` |
| secret-git | `273f6be441ba85cb295303b929a8427e2a88e5f883800f9cd1d0f51f875c9664` |
| egress | `fc24f905fc33a699a79f78c08ab74ddc3145b4671f4e41240e94a7b3c19b17aa` |
| common | `33515814a05a63fed6565c5f03ab19e1b697916349f7b5bdd256d981a992f86e` |

- **L1（意味・metadata）:** 最終 source の既存解析45契約と、私有の source / role / priority / consumption / nameref / netrc / index-operation 契約14件が、それぞれ成功した。私有14は内部 analyzer の定義を変えず、私用コピーの input dispatcher と最後の exit だけを置き換えて metadata を取り出した検査である。公開解析へR19の10契約を追加した55・filename parity 8・L2 deny API 6の一括69契約が成功し、旧59契約の途中測定も保持し、deny API 6を L1 へ加算しない。これらを直接入力 suite の件数へ加算しない。
- **L2（permission・理由・担当）:** 最終4 source に旧3834入力・旧期待を渡した比較（2026-10-14 **05:38:48.185 JST**）は **3821一致 / 13不一致、broken 0、source hash 不変**。13件とも旧 ALLOW が egress 自身の UNKNOWN になった。最終 source の追加私有87入力は **87/87、broken 0、source不変**（05:36:31.406 JST）。公開9指摘の正確な11入力・通常対照と、拡張した12入力・通常対照は、私用 source の一つの原因 edge だけを反転して拒否が外れることを確認した。各 reverse は broken 0・必要性未証明0であり、他の guard をまとめて外した結果ではない。さらに最終4sourceの使い捨てコピーでconfig first-operandとadd-contextのedgeを個別に外した14対照を取得し、正確な2入力だけがALLOWへ戻り、getter / independent絶対-C / static禁止 / ordinaryの対照を維持した（05:53:09.735 JST）。**旧入力の期待13件を採用し、新規187入力（add / stage 25、config 14、egress 61、extension 87）を加えた統合suiteは、05:48:39.125 JSTに4021/4021・broken 0・source不変。旧3834のID / command / stdin / cwd / project / envは保持した。同じ4021入力を公開5dへ渡すと96の期待不一致、broken 0・source不変。実判定差は92件、担当hook・理由等だけの差は9件で、96のassertion不一致と区別する。** 私有87の ALLOW は egress 境界の対照であり、read prompt 対照の既存 secret-git 停止は別に保持する。
- **L3（実入口・副作用）:** **最終 R19 source のCLI 2.1.296実入口は、独立したDUMMY fixtureの2試行で2 PASS、FAIL / NOT_EXERCISED 0、source不変。** `git mktag < public.tag` は正確なBashと3 hookが起動し、egress自身がUNKNOWNで停止、HEAD / refs / index / object database / DUMMY file / markerは不変。`MSG=ordinary; git commit -m "$MSG"` は正確なBashと3 hookが許可し、予定のa.txt commit、commit/treeの2objectだけを追加、事前の未追跡状態と他のfile / markerを維持した。最初のsandboxed4試行は150秒・code143、公開protocolのAPI retryとBash前停止で4 NOT_EXERCISED。通信可能な別batchではconfig入力がAPI cyber refusalで1 NOT_EXERCISED、通常commitは試験器が事前のuntracked curlhome/を許容せずstrict FAILだった。元のFAILを保存し、期待を事前状態の維持へ修正して上記2試行を新たに取得した。API停止や旧traceの再解釈を新PASSに加算しない。 curl の解除条件は空の dummy netrc と隔離 HOME の local `file://` / `--libcurl` で5組の option 設定を照合した。外部通信・本物の認証・secret・Git helper の実行ではなく、L3 へ加算しない。旧 source の全3 hook dispatch や PASS / FAIL / NOT_EXERCISED は持ち越さない。**CI / fresh review / threadの受入は、PR本文・監査記録の同一公開headと取得時点で別に確認する。ローカル測定だけでgoal達成とはしない。**

旧期待から UNKNOWN を採用する13 ID は **N28、N35、SC09、SC11、P191P12、P191P14、P191P15、P191P16、P191P26、P191P36、S4G24、R11P057、R12X046**。内訳は未証明 MSG の6形式、未証明 AUTHOR（P191P15）の1形式、active 外部 fsmonitor の1形式、内側で cd / Git status / export を使う未対応 context / stdout producer の5形式である。command / stdin / cwd / project / env の入力は正確に保持し、変更するのは `expect`・required egress `denyBy`・UNKNOWN prefix の期待だけとする。5生成形式も通常操作への追加制限として採用したもので、secret reader の禁止や外側 cwd の変更を実証した対照ではない。不一致13を独立した脆弱性・漏えい件数にしない。全ケース成功・全 green は、この旧期待との比較や局所的な契約の成功から主張しない。

途中 R19 の初回比較（05:15:30.026 JST）は add-all `200a0e6a` / secret-git `273f6be4` / egress `f11b2ded` / common `59905f15` に対する **3822一致 / 12不一致**だった。author の境界と近接経路を加えた最終 source の13不一致と区別する。config 14入力 / reverse 8対照、add / stage 25入力、旧 egress / common の61入力は途中測定として保存し、最終4021件の成功へ加算しない。R18 の3834 / 59契約 / reverse18も、下記の旧 source に対する履歴のまま残す。

履歴比較では、正確な `cd sub; git add ../sub/..` 入力は df / f2 / 4f / 5ea / 724 / 5d の6 source すべてで ALLOW だったため preexisting と記録する。一方、正確な config writer-before-commit 入力は `df463a91` で deny、直後の `3e8bbcaadd9950e6e4e4601238efadffbda33710` と後続15 head で ALLOW、broken 0だったため regression と記録する（2026-10-14 00:20:07 JST）。isolated DUMMY の native config write / readback と cwd の native `ls-files` は意味の照合であり、helper・commit・add / stage・外部送信の成立確認ではない。

測定の識別子は `pr191-r12-full-r19-extended-existing-3834.json`、`pr191-r19-extension-final.json`、`pr191-r19-extension-exact-verify.json`、`pr191-r19-extension-reverse.json`、`pr191-r19-extension-l1.json`、`pr191-r19-extension-manifest.json`。最終 source、取得時刻、途中失敗、processor の訂正を付した実測と、未取得の統合 / 実入口 / CI / review を分けて追跡する。

## 誰が、どの入口を担当するか

`PreToolUse(Bash)` の入力を共通 parser `.claude/hooks/lib/git-guard-common.cjs` で読む。引用・escape・選ばれた source を解析するが、解析対象のコマンドを試しに実行して安全性を決めることはしない。

| 設定の入口記述 | 担当 | 対応範囲と限界 |
|---|---|---|
| `Bash`、`if: "Bash(git *)"` の記述 | `block-secret-git.cjs` | add / commit、index、対象 repository、commit 前の検査条件。R19 の config first-operand はこの writer 判定に反映 |
| 同じ `Bash(git *)` の記述 | `block-git-add-all.cjs` | 一括 add、解析した no-verify option、hook path の変更。R19 の add / stage path と cwd / source の条件も担当 |
| すべての `Bash` | `block-secret-egress.cjs` | 対応する upload・送信先・ネットワーク入力・実行 source と、解析した Git の対応経路。R19 の client file / 暗黙 netrc、active helper、mktag、commit metadata の生成値は egress 自身が停止を担当。common は typed argv / identity source / config 順序と object 判定を共有 |
| Read / Write / Edit | この 3 本の担当なし | 別の permission rules が設定された対象だけを担当する。これらの hook による保護ではない |
| MCP | この 3 本の担当なし | 接続先と別の permission / owner approval gate が必要。担当が確認できない経路は未被覆 |
| 起動後の子プログラム内部・任意の設定ファイル内の処理 | 個別の hook は付かない | 選択して解析する source 以外を包括的に検査しない。担当が確認できない処理は未被覆 |

設定の `if` 記述だけから、任意の入力での実 dispatch を推測しない。旧 a464 時点の CLI 2.1.296 の実入口 3 例では、引用した `g''it` の例も含めて全 3 wrapper が起動した。条件付き 2 本が省略されたという証拠ではない。この観測を R11 / R12 / R13 の新 source、全変形入力や他版へ一般化せず、対応する変形経路は常時 Bash の egress 自身の停止も fixture の `denyBy` で確認する。hook に直接 JSON を渡す fixture 自体は dispatch の証明ではなく、L3 の代表実測と分ける。

方式は全面的な command allowlist ではない。危険な操作を検出する条件と、その近傍で必要情報を確認できなければ止める条件を置く。任意の Bash、external executable の実体、呼び出したプログラム内部をすべて評価できるとはしない。

## PR #191 の停止条件と通常作業への影響

各行の ALLOW 対照も、その行に示した条件下での判定である。他の禁止や UNKNOWN があれば停止する。過去 round の curl / Wget 対照を現在の入力へ使う場合は、R14 の既定設定抑止条件も満たす必要がある。curl の実 first literal `-q` / `--disable`、Wget の実 `--no-config` がない GET・inline DATA・help / version を、この表だけで ALLOW としない。path は基本的に filename policy であり、ファイル内容を秘密でないと証明する検査ではない。同じ入力に禁止形が見えても、先行する raw backstop などが UNKNOWN で停止すれば理由は `[判断不能] ` になる。表は常に `[禁止] ` が返ることを約束しない。

先行する理由分類計画の 27 群を、PR の先行 round と R10 の条件群にまとめ、R11 の新しい 4 条件群と、その後の限定監査で採用した merge file / stash の 2 群を区別して加える。先行群には、main 由来の policy / raw backstop と、本 PR で追加した解析・停止条件を併記する。すべての禁止規則を本 PR で新設したという意味ではない。R10 / R11 行にも、既存の secret inventory へ新しい入力経路を結び付けた条件が含まれる。

R11 の file query、grep pager、commit message source、notes/tag route の方針は、それぞれの実装前の担当指示で決めた。scope plan JSON は後から集約した記録であり、集約時刻を最初の方針決定時刻に読み替えない。merge file / stash は、別の限定監査で dummy native の保存経路と旧 source の許可を確認した後に、通常作業への影響と停止範囲を決めて追加した。R12 も対応範囲・ALLOW / FORBIDDEN / UNKNOWN・停止後の出口を先に定め、下表の追加条件と精度修正を実装に割り当てた。全 Git writer の一括禁止や全面的な Bash allowlist へ広げたものではない。

表の L1 / L2 は確認する試験項目と既存対照を示す。理由 prefix の assertion がない古い対照まで分類を自動検証済みとはしない。L3 の代表実測と、各行の未測定範囲は後述する。

| 守る対象 | 対応範囲・必要条件 | FORBIDDEN / UNKNOWN | 止まる通常作業 | 対応済みの代替・出口 | L1: 意味・metadata | L2: permission と理由 | L3: 実入口・副作用 |
|---|---|---|---|---|---|---|---|
| PR 先行群: commit の対象 index / 履歴 | 単一の active commit、対応する argv / pathspec、実行前の対象 repository の staged NUL 読取と必要な ls-files 照合。inline staging、複数 commit、combined write、pipeline / background / group setup、先行の任意副作用、対象 plumbing は検査を迂回し得る | 対象を確定して読取に成功した secret filename は FORBIDDEN。index が検査後に変わり得る形、`commit -a` / patch、未検査 stream / plumbing、未知 commit argv は UNKNOWN | add と commit の連結、`commit -am`、interactive commit、複数 commit、history import、commit 前の file 更新 | 非秘密の同じ変更を literal file の add と単独 commit に分け、各段階で検査する。import / ref 操作自体が必要なら owner へ | commit option / 消費値、active vs help、invocation order / group / pipeline | newline staged secret の S4G14 deny と ordinary spaced file 対照。A10 複数 commit deny / N08 commit 後の read pipeline allow。DC04 は理由も確認 | R11 未測定† |
| PR 先行群: repository / cwd / index と実行先の一致 | 対応する Git 実行名、静的 `-C`、通常 index / config / pathspec env。先行 cd、git-dir / work-tree、PATH / FPATH / source / function による探索変更、未知 wrapper / xargs / find 追加 argv を追跡。commit 前に起動し得る指定 diff / pager helper も区別 | 検査対象と実行対象・index・helper が一致すると確認できなければ UNKNOWN。env 名の存在だけで秘密混入を確定しない | cd と commit の連結、別 index の commit、PATH 差替え、未知 wrapper、helper を使った read と commit の連結 | 同じ対象を確認して静的 `git -C <dir>` と単独 commit にする。副作用のある別 operation は分離し再検査。別 index / executable が必要なら owner へ | invocation ごとの env / cd / PATH、helper option arity、wrapper incomplete | 静的 -C / identity・date DATA allow と target env deny。R7SG09 helper 前置 deny / R7SG14 実 `--no-ext-diff` 対照、R7SG17 実 no-pager 対照 | R11 未測定† |
| PR 先行群: 保存・再評価される実行 source | 選択した alias / trap、算術の再評価、prompt、positional executable、shell `-c` / stdin、eval、Git credential shell helper 等の対応 source を解析。query / reset / message / trailing argv は DATA と分ける。任意 script file 内部は読んで保証しない | source 内の確認済み禁止はその禁止の分類。不明 source / arity / 値の proof / recursion / depth は UNKNOWN。source の登録・出現だけで実送信成立を断定しない | 変数 source の interpreter、一般的な script wrapper、関数 / source 後の Git、複雑な arithmetic / prompt を持つ通常 script | 同目的を対応する直接 command / 確認済み source に表せる場合だけ置換。source や script 内部が必要なら対象と不明条件を owner へ | alias / trap script 選択、shell source boundary、positional scope、arithmetic / prompt の proof | alias / trap query・reset、literal printf / echo、既知 numeric allow と未知 source deny。N06 heredoc message allow。L1 の alias / trap / shell 契約も参照 | R11 未測定† |
| PR 先行群: committed hook と明示 staging の維持 | 実 no-verify option（commit の短縮 `-n` 等を含む）、static core.hooksPath key の set / unset / override、actual blanket option / path。getter と option 消費値は区別 | 解析した no-verify、確定 protected key の変更・削除、包括追加は FORBIDDEN。raw hit、config editor、未知 key / section、実 option と証明できない語は UNKNOWN | hook path 変更、config 編集、一括 add。raw backstop では検索 / message / consumed DATA だけでも止まることがある | hook を維持し個別 literal file を stage。設定確認は対応 getter。同目的に hook の差替え・無効化が必要なら、個別操作承認で代替せず owner へ | actual option / value / operand、config action / key、actualBlanket | DC01 包括追加 / DC02 no-verify 禁止、DC11 hooksPath getter allow。L1 の `--chmod -A` / negation / `--` 後 DATA 対照 | R11 未測定† |
| PR 先行群: 明示送信と opaque client 設定 | curl / wget、gh gist、scp / rsync の actual remote destination、nc / ncat reverse-shell option など既存対応形。upload option と consumed DATA、ローカル copy を分ける。opaque config / SFTP session / batch / launcher / incomplete argv は中を実行・読取して補わない | static executable / argv / context で確認した明示 upload・remote copy・reverse shell 等は禁止形で FORBIDDEN。config / execute / batch / 未確定 payload・実行先は UNKNOWN | 公開 file の転送、custom client config、SFTP、一般 launcher。文字列に option 名を書くだけでも raw 停止はあり得る | 対応する非秘密 inline DATA / read-only query が同目的ならその形式へ。file 転送や opaque config 自体が目的なら対応済み代替はなく owner へ | executable / operand と option value、file provenance / upload mode | DC05 parsed file upload 禁止、DC08 opaque curl config 判断不能、DC12 literal header GET allow。remote copy / query / local copy の既存対照 | R11 未測定† |
| PR 先行群: literal credential pattern | 引用・escape を戻した literal word が既存 token / key / client secret inventory に当たるかを確認。filename policy と別。raw 文字列だけの candidate は別扱い | cooked literal の禁止 pattern 一致は FORBIDDEN。credential の有効性や実漏えいを証明した意味ではない。raw-only candidate、DATA / コメント / 共起を区別できない停止は UNKNOWN | token に見える test 値や log / message、例示 command。literal の存在禁止は表示 DATA でも適用する | 非秘密の placeholder で同じ test / 説明目的を保てる場合に置換。実 credential 値が必要なら別場所へのコピーで回避せず owner へ | cooked word / raw、実行名 / DATA、既存 literal inventory | parsed literal pattern deny と普通 placeholder allow。DC09 は送信形を印字するだけの raw DATA 停止が判断不能である対照 | R11 未測定† |
| PR 先行群: 入力・依存部品・検査の成立 | JSON object の hook payload、読める command / cwd、共通 lib、閉じた構文と depth、対象 repository の index / ls-files / alias 検査が成立すること | 不正 input、lib 不在、例外、parse / 読取失敗は UNKNOWN。空 index / 安全な source と推定しない。空 command は別途の無出力対照 | 不正 payload を渡す統合、壊れた hook 配置、repository 外や読取に失敗する commit、深い script | 正しい payload / dependency / 対象 repository を復旧して同じ operation を再検査。復旧できないときは不足情報を owner へ。hook を外さない | malformed source で problems / metadata 不足を確認。payload / dependency 契約を分離 | Q30 null / Q31 array deny と N55 empty object 対照、正常単独 commit allow。lib 不在を isolated copy で検査する API 契約も参照 | R11 の正常 status 1 例†。不正 input / 依存・検査失敗は未測定 |
| R10: add / stage に混入する秘密・一括対象 | 実 subcommand と option arity、literal path / 証明した値。cwd と静的 `-C` から判断する root 条件 | secret filename、証明した `-A` / `--all`、対象 root 等は FORBIDDEN | 秘密を含む add、一括 add | 確認済みの非秘密ファイルだけを literal に列挙。秘密の追加という目的には許可代替なし | option / path、`literalValue` / `literalPath` を分離 | secret / broad deny と ordinary / template allow。変形入口は egress deny も必要 | 旧 a464 secret add 停止 1 例†。R11 は未測定 |
| R10: 実行時に変わる add / stage の対象 | 正確に引用した単純変数の bounded proof、単一静的 loop。未知 PATH / PWD / OTHER、複数 loop、active glob、tilde、magic、file 入力は展開しない | 検査不能な対象は UNKNOWN。静的 magic / file 入力も未対応 | 変数経由の add、`'*.ts'`、`--pathspec-from-file`、別 cwd に依存する path | 同じ対象を確認し個別 literal path にする。元の cwd / 対象を確認できなければ owner へ | 動的語、glob / tilde、loop scope、消費値 | UNKNOWN deny と proven ordinary allow。message / option value を path にしない | R11 の `.e?v` add 停止 1 例†。他 path / proof 条件は未測定 |
| R10: Git の別設定から起動する helper と書込み | HOME / XDG_CONFIG_HOME の代入・解除、`env -i` を追跡。異なる config root を使う Git write / helper-capable read | 設定と helper 実行を確認できず UNKNOWN。値を戻しても未証明なら停止継続 | 別 HOME 下の add / commit / push、単独 status / diff / log、manual help、pager が動き得る query | 同目的を通常 repository / env で実行できると確認した場合だけ通常 env に戻す。限定 query / stdout usage は次節 | invocation ごとの env、pager、help kind、getter arity | ROOT write / read / manual deny、scalar query / stdout allow、multi query の `-P` 対照 | R11 未測定† |
| R10: ANSI-C 引用で作る command / argv | 対応 escape を decode し実 argv として再判定。復元不能な Git / network argv、ANSI-C 実行名の Git writer は保守的停止 | decode 後の禁止は FORBIDDEN。復元不能や writer の直接 guard 経路が確認できない形は UNKNOWN | byte escape の引数・実行名を使う通常操作 | 同じ argv を確認済みの通常 literal にする。未知 byte の意味を確認できなければ owner へ | decoded text、`ansiCUnknown`、option 消費位置 | encoded upload deny、literal DATA / getter / help 対照。復元不能は UNKNOWN | R11 未測定† |
| R10 / R11: API / client の file upload | parsed curl / wget upload option、gh api `--input` / `--field` の file 入力。R11 では curl `--url-query` の `@file` / `name@file` と file-backed expansion を追加。`+raw` / `name=value` 内の `@` は DATA。GET でも file / stream 形は停止 | 静的 argv / context が確認できた file-upload は FORBIDDEN。opaque config、query / field の未知 prefix、複数語化・追加 argv、展開 source 不明は UNKNOWN | 公開 file の API upload、file body、file から作る URL query | 同目的の file-input 形式は未対応。確認済み非秘密 inline field / query だけで目的を満たす場合に対応 DATA。それ以外は owner へ | field / raw-field、query の `+` / `=` / `@` 優先、option arity、file provenance | 既存 file/data 対照と R11EG001/002 file deny、R11 の `+raw` / `name=value` allow・unknown prefix / argv deny 対照。新 source の統合結果は別記 | R11 未測定† |
| R10: stdin を送る network client の入力 | 同じ pipeline ID と先行 order の producer / 入力 redirect を、stdin を消費する nc / ncat / telnet / ssh に関連付ける。visible operand と限定 script を検査 | source / sink の identity・cwd / context も確認できた secret filename 入力は FORBIDDEN。未知 producer / executable / PATH / cwd / source / 動的入力、単なる file + network 共起は UNKNOWN | 複雑な sed / awk、任意 filter、source / PATH 変更後 reader の送信 pipe | 同目的を非秘密 operand と対応 script で表せる場合だけ書換え。literal DATA は file 読取と区別。不明なら owner へ | pipeline / order、file と program / 検索語、stdin 消費 mode | secret / unknown producer deny、public reader / literal DATA allow、query / receive-only 対照 | R11 未測定† |
| R10: SSH がローカルで実行する source | argv 境界と選択順、ProxyCommand / KnownHostsCommand / LocalCommand（明示的に無効な形を除く）。明示 `-F` の未知 config は読まない | source 内の parsed 禁止は FORBIDDEN。動的 source、未解決 `%` 等の展開、未知 `-F` は UNKNOWN | custom SSH config、通常 proxy command、未知 config の `-G` 確認 | 設定不要と確認済みの場合だけ `-F none` / `/dev/null`。対応 static source、確実な `-Q` / `-V` はその目的で使用。不明なら owner へ | option / remote command DATA、first option / last `-F`、query 境界 | upload source / unknown config deny、disabled / DATA / proven query allow。`-G` を blanket allow にしない | R11 未測定† |
| R10: Git の送信先 mapping | parsed remote action、宛先を変える config、push の argv / env / transport。動的 action を実行して調べない | 静的 remote add / set-url、exact protected key の書込・削除、実際の external repository operand は FORBIDDEN。section / include / transport の不明な効果、動的 action / destination は UNKNOWN | 変数で action を切替える作業、送信先の変更 | getter 確認は対応済み。変更・送信が目的なら対象と条件を owner へ。固定文字列にしても禁止変更は許可されない | remote action / 消費値、push 宛先 | parsed destination write deny、UNKNOWN action deny、get-url 等の対照 | R11 未測定† |
| R11: commit message / template の file source | 対応する単一の `-F` / `--file` / `-t` / `--template` literal filename。選択・argv・cwd / env 等の他条件も充足。filename を検査し、内容は読んで認証しない | 対応した単一 active source の secret filename は FORBIDDEN。stdin / FD、未知 path、shell glob、複数 source、inline / reused message や negative file flag との未対応 override は UNKNOWN | 動的 message file、stdin-fed commit、多数 file / template の選択。秘密名 file を message にする作業 | 対象内容が確認済みの非秘密で、同目的の対応 inline `-m` または単一 literal filename にできる場合のみ書換え。source 選択自体が必要なら owner へ | `messageFiles` と選択不明、実 file value vs `-m` DATA。file source に Git pathspec 展開を適用しない | R11P001 secret file deny / R11P043 public filename allow、R11P015 unknown path deny、P034/035 override UNKNOWN、N06 と inline DATA 対照 | R11 の単一 `.env` file 停止 1 例†。他 source / override は未測定 |
| R11: notes / tag の object / ref と source | 対応する static notes list/show/get-ref、tag no-arg / explicit list / help を query として区別。更新・削除・signing・external verifier は staged 検査の範囲外。file source の選択は単一対応形だけを確定 | 対応 writer の単一 selected secret filename は FORBIDDEN。public file / inline message の更新も含め、全更新・未対応 verifier・未知 mode/source、query + file flag 混在は UNKNOWN | 通常の release tag 作成・削除・署名・検証、public notes の追加・編集・merge・remove、file message を持つ tag | 同目的の writer 代替は未対応。query はその読取目的でのみ使う。更新自体が必要なら owner に対象・操作・cwd / env / config / source を確認。承認を hook 無効化へ広げない | `parseGitObjectRoute` の mode / action / consumed value と file 選択。DUMMY-only native で object 保存の意味を照合 | R11OBJ01 selected secret deny、OBJ09/21/24/25 通常更新・検証 UNKNOWN、OBJ33/34 mixed query UNKNOWN、OBJ42/44/45/50 query allow 対照 | R11 の notes file 停止 1 例†。tag file は NOT_EXERCISED、他 query / writer は未測定 |
| R11: commit 前の grep file-opening pager | active commit 以前の Git grep argv。実 `-O` / `--open-files-in-pager` の optional attached value、default / explicit、後置 negation、required value、first bare operand / `--` を区別 | helper の副作用と検査後の index 維持を確認できず UNKNOWN。pager option 自体を新 FORBIDDEN にしない。動的 argv / glob で選択が不明な場合も UNKNOWN | pager で matching file を開いて同じ Bash 内で commit する作業、option になり得る裸の動的検索語 | 検索結果を読む同目的なら pager を選ばない対応 grep。scalar 検索語は `-e "$PATTERN"` の DATA 形式。pager 自体が必要なら owner に対象・操作・cwd / env / config / source を確認 | `grepPagerEffect` と order、default / explicit / reset、consumed DATA。harmless native marker で意味を照合 | R11SG01 helper 前置 UNKNOWN / SG25 ordinary grep allow、SG32 後置 disable・SG34 global -P default 対照、OBJ59/62 egress 経路、standalone / after-commit 対照 | NOT_EXERCISED†。API safeguard で Bash / hook 前に停止。hook deny は未測定 |
| R11 限定監査: merge message の file source | 実 `-F` / `--file` の option arity と、単一対応 literal filename の選択。消費される `-m` / strategy 等の DATA と区別し、cwd / env 等の他条件も確認 | 対応した単一 selected secret filename は FORBIDDEN。stdin / FD、未知 path・argv / context、複数 source・未対応 override は UNKNOWN。file source のない普通の merge はこの追加停止の対象外 | file message を使う merge、動的 `-F`、複数 message source の選択 | 同じ内容・目的と非秘密性を確認した対応 inline `-m` / 単一 literal filename にできる場合のみ書換え。source 自体が必要なら owner に対象・操作・cwd / env / config / source を確認 | merge の actual file value / DATA と filesystem source 選択。dummy で tree にない file 内容が message に保存される意味を照合 | selected secret FORBIDDEN / unknown source UNKNOWN と ordinary public filename / inline merge 対照。追加 source の統合結果は別記 | R11 の単一 `.env` file 停止 1 例†。他 source / override は未測定 |
| R11 限定監査: stash の tree / object / ref と working state | 対応 static list / show / actual help を読取と区別。default / push / save / create / store / import、drop / clear / apply / pop / branch 等の snapshot・更新・未対応 action は staged 検査の範囲外 | snapshot の対象内容、object / ref / index / working tree の影響を検査できず UNKNOWN。既知 `-a` でも実秘密の保存確定を意味しない。その他の未対応 action / argv も UNKNOWN | 通常の stash push / save、退避の apply / pop、stash 作成・管理・削除。public な変更だけの stash も停止 | 同目的の writer / snapshot 代替は未対応。list / show は読取目的だけ。必要な操作は owner に input / tree / ref の対象・操作・cwd / env / config / source と未確認内容を渡す。hook 無効化の承認と分ける | actual action / option 消費値 / help。dummy の ignored file 保存経路と list / show の境界を照合 | snapshot / mutating / unsupported action UNKNOWN と static list / show / help 対照。追加 source の統合結果は別記 | R11 の `stash -a` 停止 1 例†。他 action / query は未測定 |

### R12 の追加条件と精度修正

FD / device 行以外の担当条件は常時 Bash の egress でも検査する。FD / device の区別は secret-git の index 維持条件の修正であり、他の guard の停止を解除しない。試験欄は確認すべき対照を示す。R12 source の全 suite・API 契約・実入口の結果は、この方針を決めた時点では未取得である。

| 守る対象 | 対応範囲・必要条件 | FORBIDDEN / UNKNOWN | 止まる通常作業 | 対応済みの代替・owner への出口 | L1: 意味・metadata | L2: permission と理由 | L3: 実入口・副作用 |
|---|---|---|---|---|---|---|---|
| config writer の送信先 / 実行 source | 実 action・key と消費値を区別。対応 getter、確定した非 protected key の setter は対照 | writer の key / action / argv が未確定なら UNKNOWN。確定した禁止 destination key の変更は従来の FORBIDDEN | 変数で key / action を選ぶ設定変更 | 同目的・同じ非 protected key と確認できた場合だけ対応 static setter。変更先 / action 自体が不明、または禁止なら対象・操作・cwd / env / config を owner へ | config action / key / option arity と DATA | dynamic writer UNKNOWN / static public setter・getter・消費値 DATA 対照。egress 必須 | R12 未測定 |
| push が選ぶ include 設定 | 実 `-c include.path=...` / `includeIf.*.path` や対応 config-env を、未読の config source として扱う | include の transport / helper 効果を確認できず UNKNOWN | include を明示した通常 push | 同目的が通常の確認済み設定で満たせる場合だけその条件へ。include 自体が必要なら source と宛先・env / config を owner へ | global config の選択と push operand / refspec | include UNKNOWN / public config DATA・getter 対照。既に停止する exact 入力は防御条件の明示であり、新穴と数えない | R12 未測定 |
| commit の index と redirection | 確定 literal の `>&` + digits / `-` は FD 複製 / close。正確な `/dev/null` と対応出力 operator は通常 file の書込みと区別 | 実 file `>1` / `&>1`、未確定・展開 target、対応外の read/write `<>` 等は UNKNOWN。FD / null 自体はこの条件の停止対象外 | 未知 target、普通の出力 file を伴う commit。従来の FD / null 過剰停止を縮小 | 同目的に FD 操作 / null 出力が適する場合だけ対応 literal へ。実 file 書込みが必要なら対象・順序・index 効果を owner へ | redirection operator、literal / expansion、FD と filename の区別 | `2>&1` / `>&-` / `/dev/null` 対照と `>1` / `&>1` / unknown target UNKNOWN。group 等の別停止を維持 | R12 未測定 |
| Git editor / sequencer の実行 source | editor を起動し得る対応 operation と実 option を検査。既定 / config / EDITOR / VISUAL / GIT_EDITOR 等の selector も対象。消費値・query / help は別役割 | 起動抑止を証明できない editor-capable operation、実 editor 設定の変更・削除 / config edit は UNKNOWN。selector の存在だけで実送信を確定しない | 引数なし commit、普通の merge、reedit / template / interactive / sequencer、branch description 編集 | 同目的を保つ場合だけ対応 nonediting commit / 実 merge `--no-edit` 等へ。editor そのものが必要なら対象・argv・選択 source・cwd / env / config を owner へ | `editorMayRun`、option arity / order、selector scope と consumed DATA | default / explicit editor UNKNOWN、実抑止 / 対応 message / query / unused selector DATA 対照。egress 必須 | R12 未測定 |
| Bash の native network channel | 実 redirection の `/dev/tcp` / `/dev/udp` と socket を選び得る未確定 target を検査。read / write / FD を区別しても channel は未対応 | 秘密 filename の有無によらず UNKNOWN。単に pathname を印字する DATA はこの条件の対象外 | Bash socket の read / write / FD 接続 | 必要な read / transfer の条件を owner へ。別 client / tool への変更だけで保護済みとしない。単なる表示が目的なら対応 literal DATA | 実 redirection と DATA、target proof | literal / dynamic socket UNKNOWN、印字 DATA・ordinary file 対照 | R12 未測定。実 network 接続を試験のために起動しない |
| mapfile / readarray callback source | 実 `-C` callback と value arity を検査。`-d` / `-n` / `-u` / `-c` 等の消費値や actual help は別役割 | literal callback も内部と副作用が未対応で UNKNOWN。callback を選び得る未知 argv も UNKNOWN | callback を使う通常 array reader | 同じ目的を満たす場合だけ callback-free 対応形式へ。callback が必要なら source・入力・副作用条件を owner へ | callback option vs delimiter / count / help DATA | `-C` UNKNOWN / callback-free・消費値・help 対照。egress 必須 | R12 未測定 |
| heredoc の body / suffix source 境界 | delimiter の unquoted backslash + LF は両方を除去し、引用された delimiter とは判定しない。他の引用・escape・body 条件を保持 | 境界や選択 source が不明な protected route は既存 UNKNOWN。line continuation 自体を新禁止にしない | malformed / 未対応境界を持つ protected script。対応 continuation の通常入力を保つ | 同じ delimiter / body / suffix の意味を保つ対応形式へ。意味を確定できなければ source と不明境界を owner へ | delimiter text / quotedness、body 展開、後続 invocation の保存 | continuation の後続禁止を取りこぼさず、対応 body DATA / 後続 ordinary command を過剰停止しない | R12 未測定 |
| shell が選ぶ executable | どの実行位置でも active glob / brace / tilde による executable 選択を停止。quoted literal executable と argument 側の展開は別役割 | filesystem を列挙して推測せず UNKNOWN。Git らしい綴りの有無に限定しない | `/usr/bin/g?t`、brace / tilde で実行名を作る通常 command | 実体と同じ目的を確認した対応 literal executable へ。解決できなければ実行対象・cwd / env / argv を owner へ | executable expansion marker、wrapper 位置、quoted literal / argument DATA | active executable UNKNOWN / quoted literal・argument 対照。egress 必須 | R12 未測定 |
| remote rsync の local helper | actual `-e` / `--rsh` / RSYNC_RSH と remote / local operand を確認。download でも helper は local 実行 source | helper を選ぶ remote rsync、または helper / remote 条件が未確定なら UNKNOWN。確認済み local-only copy の未使用 selector はこの条件の対象外 | custom RSH での download / remote query、未知 operand | 同目的を満たす確認済み local copy の場合だけ対応形式へ。remote helper 自体が必要なら source・対象・argv・cwd / env / config を owner へ | helper selector scope、option arity と consumed DATA、remote operand | remote helper UNKNOWN / local unused helper・actual help / version 対照。egress 必須 | R12 未測定 |

### R13 の追加条件と精度修正

対応範囲・判定・通常作業への影響・出口を担当への指示で先に定め、その後に実装を分けた。scope JSON と refinement の記録は後から集約したものもあり、その記録時刻を最初の方針決定時刻と読み替えない。pre-commit config の identity-only 案は、既存の表示 DATA を維持する条件へ候補段階で修正した。表の試験欄は検査する役割と対照であり、R13 の全 suite / API / L3 の合格数ではない。

| 守る対象 | 対応範囲・必要条件 | FORBIDDEN / UNKNOWN | 止まる通常作業 | 対応済みの代替・owner への出口 | L1: 意味・metadata | L2: permission と理由 | L3: 実入口・副作用 |
|---|---|---|---|---|---|---|---|
| coproc の非同期 source と副作用 | 元の command 位置の unquoted reserved word としての実 coproc。simple / optional name / group を通常 argv DATA と区別 | Git らしい文字列の有無や benign body によらず UNKNOWN。async の実行条件・source は未対応 | 普通の coprocess job、array reader を並列にする script | 同目的・同条件を保つ場合だけ対応 synchronous 形式。async 自体が必要なら source・対象・cwd / env / config・副作用を owner へ | reserved marker と quoted / help / array assignment DATA | actual coproc UNKNOWN / 印字・help・inert array DATA 対照。egress 必須 | 実 coproc 1 回を UNKNOWN で停止。egress のみ起動、DUMMY 状態・object inventory 不変 |
| command wrapper の child と argv | 実 `command` の認識済み option の後の `--` を消費し child を解析。実 `-v` / `-V` は nonexecuting query | literal `--` 自体は新 UNKNOWN / 禁止ではない。復元 child の既存禁止・UNKNOWN を適用 | この精度修正による新しい一律停止なし。child 自身の禁止操作は停止 | 同目的の literal child / 対応 argv を維持。不明条件が残れば対象と source を owner へ | terminator、`-p` / query、child name / args | reconstructed Git / curl 禁止と ordinary / query DATA 対照。egress 担当も確認 | `command -- git status --short` 1 回成功。egress のみ起動、状態・object inventory 不変 |
| 動的 executable の実行 identity | 未確定 scalar / named-array element・tuple / slice / indirect expansion は一般評価しない。既存 proven positional tuple / scalar の対応 proof は維持 | すべての unresolved dynamic executable は UNKNOWN。raw Git / network らしい綴りに限定しない | ordinary command を変数・named array から起動する script | 同じ executable / argv と確認できる場合だけ対応 literal へ。一般 array / source が必要なら対象・argv・cwd / env / config を owner へ | dynamicName と cardinality、proven positional、assignment / printf argument DATA | named-array / scalar executable UNKNOWN / literal DATA・proven positional 対照。egress 必須 | named-array 実行 1 回を UNKNOWN で停止。3 本起動、DUMMY 状態・object inventory 不変 |
| hash-object の object database | 実 `-w` の全 object 書込みと、書込みを選び得る不明 argv。`-t` / `--path` の消費値、`--`、stdin / literally と static hash-only / actual help を区別 | blob / tree / commit / tag、公開入力を含む全 write / unknown mode は UNKNOWN | 通常の blob 保存、stdin object 作成、raw object writer | no-write hashing は write と目的が異なり自動代替にしない。必要な write は input / object 対象・argv・cwd / env / config / source を owner へ | object route mode、actual write vs consumed DATA / operand | write / unknown UNKNOWN、static no-write / help 対照。secret-git と egress 必須 | `git hash-object -w a.txt` 1 回を UNKNOWN で停止。3 本起動、未登録の新しい DUMMY 内容を用い object inventory 不変 |
| difftool の external source | active difftool は extcmd / 既定 tool / env / config を含む外部 source。確定 actual help は別役割 | ordinary difftool も内部と副作用を検査できず UNKNOWN | 公開 file 同士の通常 difftool、既定 tool の diff viewer | 同目的・同条件を保てる場合だけ helper を呼ばない対応 diff。viewer が必要なら source・対象・cwd / env / config を owner へ | active / terminal と option arity | active difftool UNKNOWN / static actual help・ordinary diff 対照。egress 必須 | active difftool 1 回を UNKNOWN で停止。3 本起動、marker / 状態不変。同 revision 対照なので逃げた場合の helper 起動は実証しない |
| curl cookie の local file 入力 | 実 `-b` / `--cookie` の nonempty かつ `=` を含まない値は filename。empty / inline key=value と consumed DATA を区別 | 確定した対応 argv / context の file-upload は FORBIDDEN。未知 prefix / source / cardinality は UNKNOWN | 公開 cookie file の利用、動的 cookie input | 同目的・同条件を保つ確認済み非秘密 inline DATA の場合だけ対応形式。file input 自体が必要なら source・target・env / config を owner へ | option value、empty / `=` / file、variable provenance | cookie file FORBIDDEN / unknown UNKNOWN / empty・inline・消費値 DATA 対照 | R13 の実入口は未測定。L1 補助 / 直接入力と区別 |
| network client の生成 argv と curl 境界 | incomplete な curl / wget / gh は未見の argv / payload を含む。curl actual boundary の bare dynamic prefix・語分割 / glob / brace も検査不能 | visible upload flag がなくても incomplete client は UNKNOWN。curl の未確定 option / URL role・追加 argv も UNKNOWN | xargs / find で生成する普通の query、bare `$URL` / `$OPTIONS`、展開 argv の client | 同目的・条件を保つ場合だけ直接の対応 fixed argv。対応 option の quoted scalar DATA 等は対照。生成条件が必要なら source・対象・argv・cwd / env / config を owner へ | incomplete marker、actual option vs consumed scalar、terminator / cardinality | generated query UNKNOWN / direct query・quoted header DATA・固定 https scalar prefix・実 `--` 後 quoted scalar URL 対照。egress 必須 | R13 の実入口は未測定。L1 補助 / 直接入力と区別 |
| rsync / scp の実 destination | option value を消費して残る actual operands の最後を宛先とする。shared rsync long / short value arity を揃え cardinality を確認 | 確定 remote destination の禁止は FORBIDDEN。未知 destination / operand 数・未対応 option / missing value は UNKNOWN | 変数 / split source・destination の copy、未対応 copy option | 同目的が確認済み local copy の場合だけ対応 literal argv。remote transfer 自体が必要なら対象・宛先・argv・helper・cwd / env / config を owner へ | actual last operand、trailing option value、colon-shaped consumed DATA | unknown destination / cardinality UNKNOWN / known remote FORBIDDEN / local・消費値 DATA 対照。RSH 条件も独立 | R13 の実入口は未測定。L1 補助 / 直接入力と区別 |
| commit に関わる Git config の実行条件 / index | pre-commit と当該 commit の `-c` / `--config-env` key を共有 API で検査。対応 display key、6 identity、実 stdout usage は例外。旧 whole-chain key 条件も独立 | 対応外 / 不明 key は UNKNOWN。false / unused / 設定 query という名称だけでは効果なしと推定しない | 未対応設定を伴う query と commit、configured commit。post-commit 移動だけでも旧条件で停止し得る | 同目的・条件を保つ対応 unconfigured / supported-key 形式へ。分離するなら後の index を再検査。設定自体が必要なら対象・source・cwd / env / config を owner へ | key vs value / env、pre-commit order、stdout vs manual help | unsupported config UNKNOWN / display・6 identity・stdout 対照。alias / include / hook / root 等は維持。egress 必須 | 対応 color 設定 + inline commit 1 回成功。3 本起動、a.txt のみと期待する tree / commit objects を記録 |

pipeline の filename 判定は参照できた operand に基づく。任意 reader の内部、実行時 cwd / 設定 / filesystem のすべてを解決した証明ではない。通常名や `/bin` / `/usr/bin` の対応 reader でも、内容が非秘密だと認証する検査ではない。SSH や API client の parsed name の判定も、任意 executable の実体と内部動作を認証するものではない。

既存の no-verify / hooksPath、commit 前の状態変化、未検査の plumbing、literal token / key の禁止や raw backstop も維持する。たとえば parsed no-verify、secret add、包括追加は FORBIDDEN、commit に影響する任意の先行処理や未読の fast-import stream は UNKNOWN と区別する。この表の条件組を、未対応の外部 executable / config 内部や別入口の保護証明に拡張しない。

## 対応している具体的な条件

### add / stage の literal proof

通常は、追加するファイルを確認して個別に指定する。

```bash
git add -- README.md docs/security/git-command-guards.md
git add -- 'ordinary file.txt'
P=a.txt; git add "$P"
for P in a.txt; do git add "$P"; done
```

変数 proof は、値を追跡できる単純 literal 代入と、正確に引用した `"$NAME"` / `"${NAME}"` の対応範囲に限る。単一の静的 loop は body の scope だけで扱う。条件分岐・未実行関数・source・eval・read・複数要素などで証明が崩れる入力を、一般 shell evaluator で補わない。filenameのテンプレート例外はfinal basenameの `.env.example` だけで、`secrets/` や `.env.local/` 等の保護対象ancestorの判定を維持する。templateをuploadする操作は既存policyのまま例外にしない。

引用した glob も Git が展開するため、引用だけで literal とはしない。Git が扱う backslash escape は対応範囲で literal path に戻す。`git add --chmod "$MODE" a.txt` の MODE など、対応する option の消費値は追加対象と区別する。ただし複数 argv に変わり得る値や、空の attached value により次の語を消費し得る曖昧な形は UNKNOWN になる。

未知の `"$PWD/a.txt"` を単に `a.txt` へ置換したり、escape を機械的に削除したりしない。実際の repository / cwd / 対象を確認して同じファイルを指定する。dummy native proof では `"$PWD/\."` と repository 外の `/` は Git がエラーを返した例であり、一括 stage の成立証拠として扱わない。無効な literal が hook を通る対照も、操作の成功や安全の承認ではない。

### config root と query / help

変更・解除した HOME / XDG_CONFIG_HOME や `env -i` の下では、見かけ上の読取も helper を起動し得る。Git の [公式 git-config 文書](https://git-scm.com/docs/git-config)は、`core.fsmonitor` に hook command を指定できること、`diff.external` が外部 command を使うこと、`core.pager` が shell で解釈されることを説明している。この仕様が、status / diff / log を単独でも UNKNOWN とする根拠である。

その config root 条件下で維持する例外は、他の禁止・不明条件がないことに加えて、次の範囲に限る。

- pager を強制しない対応済み scalar config getter。たとえば `git config --get user.name` / `git config get user.name`。
- config list / multi getter は、明示した `git -P` / `--no-pager` で pager を止める対応形式。`git -P config --list` や `git -P config --get-all user.name` は対照となる。
- `git version` の引数なし、または単独 `--build-options`。global version も stdout で終わる対応形式。
- stdout usage と確定する実際の `-h`、単独 global `git --help`。subcommand の `--help` や `git --help <command>` は manual viewer を起動し得るので例外にしない。
- 対応する global stdout query。`--html-path` / `--man-path` / `--info-path` / 単独 `--exec-path`、`--list-cmds=...` のように、検査した query が stdout で終わる形式。

いずれも実際の option と消費値を区別し、forced pager がないことを確認する。`-C --no-pager` の directory value は pager を止める flag ではない。通常環境の status / diff / log は、それぞれの他の条件を満たす対照として維持する。値を元に戻したように見える command でも、config root の proof が回復したとは決めつけない。

### SSH と file / DATA

`ssh -F custom-config -G host` も、選んだ config の `Match exec` を実行し得るため、未知 config の query を安全とはしない。静的な `-F none` / `-F /dev/null` と確定した argv、config を読む前に終了する確実な `-Q` / `-V` は対照である。`-F` を選ばない従来の `-G` 対照の維持も、全設定ファイルが安全という保証ではない。IdentityFile 等の DATA、host 後の実際の remote command に渡された DATA と、ローカルで実行する source は区別する。

gh api の `-F 'key=@file'` は file / stream 入力だが、`-f 'key=@file'` は raw literal value である。header / jq / message / 検索語に書かれた option 名も、そのまま実 option として扱わない。これらの DATA 対照は、literal secret 値の存在禁止を解除しない。

alias / trap、算術による再評価、prompt 展開、shell source などの既存対応も、選択した source だけを検査する。不明 source や recursion / depth の限界は UNKNOWN。既知の数値や literal DATA の対照を、任意プログラムの安全性へ一般化しない。

### R11 の message source / notes / tag

commit の `-F` / `--file` と `-t` / `--template` は、[Git の file / template option](https://git-scm.com/docs/git-commit)が選ぶ source として扱う。対応する単一の確定 filename が secret inventory に当たれば FORBIDDEN、public filename の対応形は他条件を満たせば ALLOW となる。後者は file が存在する、内容が非秘密である、Git が成功するという認証ではない。内容を読み込んで許可判定を補わない。

`-F -` などの stdin、`/dev/stdin` / FD path、未解決の変数・shell glob / brace / tilde 展開、複数 file / template、inline / reused message との選択や override の未対応な組合せは UNKNOWN。`--no-file` / `--no-template` があるだけで先の source を安全に消したとは判断しない。これらの flag と file source を組み合わせる入力は、source 選択を未対応として止める。file source のない対応 `-m` DATA、N06 の heredoc message は別の対照として維持する。

message file は Git pathspec ではない。引用して shell 展開を止めた `"public*.txt"` は、この入口では literal filename の対照となり、add の quoted glob と同じ扱いにはしない。対応 proof で値が確定した単純変数も、選択を確認できる範囲で扱う。未知 `-F "$FILE"` などの source を通常 filename や inline DATA へ直す場合は、同じ内容・目的と非秘密性を確認してからにする。

[git-notes](https://git-scm.com/docs/git-notes) と [git-tag](https://git-scm.com/docs/git-tag) は、message を持つ object / ref を作れる。dummy native proof では、DUMMY_ONLY の `.env` file から note と annotated tag に文字列が保存された。これは staged file inventory の外にある経路の意味の確認であり、実秘密の保存・漏えいや guard の実入口の成立を測定したものではない。

このため、対応 writer の単一 selected secret filename を FORBIDDEN とするだけではなく、通常の public notes の追加・編集・copy・merge・remove・prune、release tag の作成・削除・signing、および未対応の外部 verifier を UNKNOWN として止める。public file や `-m` DATA に変えても writer は対応済みにならない。query に file / writer flag を混ぜた入力も、確認済みの禁止と決めつけず UNKNOWN にする。

通常の環境で他条件を満たす standalone static `git notes list` / `show HEAD` / `get-ref`、`git tag` の引数なし / explicit list、対応 help は読取対照である。たとえば `git tag --list 'release-*'` は tag 作成と区別する。すべての query option、commit との任意の組合せ、config / verifier の内部まで対応した説明ではない。必要な notes / tag 更新と同目的の writer 代替はないため、owner に対象・操作・cwd / env / config / source を確認する。

### R11 の限定監査: merge file / stash

[git-merge の `-F` / `--file`](https://git-scm.com/docs/git-merge/2.54.0)は、message を file から取り込む。限定した dummy native proof では、tree と staged inventory にない `.env` の DUMMY marker が merge commit の message に保存された。これを受け、実 file option の単一対応 source に commit と同じ filename policy を適用する。secret filename は FORBIDDEN、stdin / FD・未解決 path・複数 source / override・argv / context 不明は UNKNOWN。R11 の file-source 条件だけでは、普通の file source のない merge と対応 inline `-m` を止めなかった。R12 は独立した editor 条件を加えるため、これらも実 `--no-edit` 等で起動抑止を確認できなければ UNKNOWN となる。public filename や inline DATA を通すことは、file 内容・merged tree・履歴全体の安全認証ではない。

[git-stash](https://git-scm.com/docs/git-stash/2.54.0)は working state を stash entry に保存し、`--all` は ignored / untracked file も取り込む。dummy proof では、ignored かつ index にない `.env` の DUMMY marker が stash object に保存された。snapshot 入力は staged 検査の外にあるため、default / push / save / create / store / import を UNKNOWN とする。drop / clear / apply / pop / branch 等も ref / index / working tree への影響が未対応であり UNKNOWN。既知 `-a` や通常の public snapshot が停止しても、実秘密を保存したと断定した意味ではない。

対応 static `git stash list` / `show` と実 help は、他の条件を満たす読取対照である。snapshot / 更新・管理を同目的で置き換える対応済みの writer はない。必要なら owner に input / tree / ref の対象、操作、cwd / env / config、source と未確認内容を渡す。この限定追加は、merge / rebase / cherry-pick / revert / am などの全 writer を一律に止める方針ではなく、それらの tree / history や任意 child program 内部を保護済みとする方針でもない。

### R11 の grep pager / curl query

[git-grep の `-O` / `--open-files-in-pager`](https://git-scm.com/docs/git-grep)は、検索の出力を表示するだけでなく matching file を pager で開く。optional pager value は attached のときだけ value で、次の裸の語は pattern / operand となる。実 option、`-e` 等の消費値、first bare operand / `--`、後置 `--no-open-files-in-pager` を区別する。`-h needle` は filename 抑制、quiet は出力抑制であり、これらだけで file-opening helper は無効にならない。

dummy Git 2.54.0 の harmless-marker proof では、captured stdout でも helper が動いた。値なしの既定 `-O` は実 global `git -P grep ...` で無効になったが、明示 `-O<helper>` / `--open-files-in-pager=<helper>` は `-P` があっても動いた。scope は active commit 以前に helper が起動し得る条件の UNKNOWN であり、standalone grep pager の全禁止ではない。通常 grep、確定した消費値 / disable、commit 後の helper はこの停止条件の対照として維持する。他の禁止・UNKNOWN や任意 helper 内部の保証を解除する説明ではない。

[curl の `--url-query`](https://curl.se/docs/manpage.html#--url-query)は `@file` / `name@file` で file 入力を作れるため、確定した対応 argv / context では file-upload として FORBIDDEN にする。先頭 `+raw` や `name=value` の中の `@` は file 入力とはしない。quoted scalar の固定 `+` / `=` と、未解決 prefix・複数 argv に展開し得る値を区別し、後者は UNKNOWN。file-backed variable が query に流れる対応 expansion も検査する。literal GET / inline query は file 入力条件の対照であり、現在は R14 の first literal `-q` / `--disable` と他条件も必要になる。file-input 自体が必要なら owner gate が必要である。

### R12 の editor と helper selector

Git の editor 起動条件と、message file の filename 条件を別に判定する。editor の値が command 文字列に現れなくても、既定値や設定で選ばれる外部処理の内部は検査できない。そのため対応 operation が editor-capable なら、起動しないと確認できる argv がない限り UNKNOWN とする。EDITOR / VISUAL の明示だけを止めて既定 editor を許す方針ではない。

commit では実 `-m` / `--message`、`-F` / `--file`、`-C` / `--reuse-message` の対応 source、実 `--no-edit`、対応 dry-run / help が editor 条件の対照になる。実 `-e` / `--edit`、`-c` / `--reedit-message`、template / fixup / squash 等は選択順と起動可能性を検査し、起動抑止を証明できなければ停止する。未知 / missing / 展開 argv は保守的に editor-capable のままとする。message file・staged inventory・no-verify 等の独立した禁止や UNKNOWN は残る。たとえば public `-F` の filename 条件を満たしても、実 `--edit` を加えれば editor 条件で停止する。

merge は message DATA があっても editor を起動し得るため、通常の `git merge topic` や `git merge -m 'public message' topic` も UNKNOWN となる。同じ目的に editor が不要と確認できる場合は、対応する実 `--no-edit` と確定 argv の形式へ書き換えられる。`-m '--no-edit'`、strategy の消費値、`--` 後の ref は抑止 flag ではない。後続 `--edit` や不明 argv があれば抑止したと判断しない。この判断は merged tree / history や arbitrary child program を検査済みにするものではない。

その他の対応 family も、interactive / edit-todo / continuation 等の sequencer、revert の編集、branch `--edit-description`、add / stage の edit / interactive / patch 等を選ぶ条件を停止する。対応する noninteractive / nonediting 対照があることを、rebase / cherry-pick / revert / am 等すべての writer や全引数の安全認証へ一般化しない。

helper selector の env は名前と役割を追跡し、値を通常の message / DATA と混ぜない。prefix 代入、対応 `env` wrapper、persistent assignment / export と選択した child scope で EDITOR / VISUAL / RSYNC_RSH を引き継ぎ、既存 GIT_* の追跡も維持する。shell の persistent `unset` だけでは条件分岐等を含む実行状態の消去を証明したと扱わない。認識した per-invocation `env -u` / clear はその呼出しの selector を更新するが、selector を消しても既定 editor の起動抑止にはならない。selector 名の印字や対応 option の消費値は DATA と区別する。

実 `core.editor` / `sequence.editor` の setter・削除、これらの section に影響する未対応変更、config editor は UNKNOWN。削除も fallback source を選び得る。対応 static getter、非 protected key の setter、editor を起動しない query の未使用 selector は他条件を満たす対照である。helper source そのものが必要な作業には対応済みの同目的代替を保証せず、owner に対象・操作・argv・source・cwd / env / config と未確認内容を渡す。

### R12 の callback / socket / remote shell

mapfile / readarray の実 `-C` は callback source であり、literal な `printf` 等でも内部と副作用は対応範囲外として UNKNOWN とする。callback-free reader、actual help と `-d` / `-n` / `-u` / `-c` 等に消費される DATA を、callback の実 option と区別する。callback-free にすると目的が変わる場合は機械的に削除しない。

Bash `/dev/tcp/<host>/<port>` / `/dev/udp/<host>/<port>` は実 redirection で接続を作れる。network executable がなく、read / write / FD のどの形でも、また secret filename が見えなくても、この channel は UNKNOWN とする。target が動的で socket を選び得る場合も停止する。`printf` 等で pathname を表示する DATA は実 redirection ではない。普通の file redirection を許す別条件も、network channel の許可には広げない。

remote rsync は download でも `-e` / `--rsh` / RSYNC_RSH が選ぶプログラムを local で起動し得る。実 helper を選ぶ remote operation または選択条件が不明なら UNKNOWN。remote / local operand と option arity を確認でき、helper が使われない local-only copy はこの条件の停止対象外である。default remote shell / 選ばれたプログラム内部まで安全と認証した結果ではない。remote transfer の既存禁止も独立して適用する。

### R12 の shell 境界と redirection の精度

実行名の active glob / brace / tilde 展開は、Git / network らしい綴りかどうかに関係なく UNKNOWN とする。filesystem を調べて展開先を推測する allow は追加しない。正確に引用された literal 実行名や argument 側の展開は別の役割で検査し、引用するだけで任意 executable の実体が安全と認証されるわけではない。

heredoc delimiter の unquoted backslash + LF は shell と同じく両方を除去する。この continuation を delimiter の引用と誤認せず、body 展開と後続 invocation の境界を保持する。他の引用 / escape の規則を一律に変えず、未完 heredoc を一律新禁止にする修正でもない。選択した source の禁止・UNKNOWN は従来どおり判定する。

secret-git の index 維持条件では、literal `2>&1` / `>&-` は FD 複製 / close であり、普通の file を開く `>1` / `&>1` と区別する。正確な literal `/dev/null` は対応 output operator に限り、この file-write 条件の対照にする。変数・glob / brace / tilde・未知 ANSI-C target や `/dev/../dev/null` のような別表記を、その例外へ正規化しない。`<>/dev/null` は read/write 形として未対応である。group redirection、commit 前の別副作用、source / config / index の不明条件はそれぞれ残る。

動的 config writer の key / action は、送信先や helper 設定を選び得るため UNKNOWN とする。確定した protected destination key の禁止、対応 static public setter / getter、option に消費される DATA は分ける。push の明示 include source を UNKNOWN とする条件は egress の担当を明示する追加防御である。review で示された exact `git -c include.path=... push ...` は旧 source の共通解析でも既に全 guard が停止しており、その例を新しい抜け穴の成立証拠とは扱わない。

### R13 の coproc / command / 動的 executable

coproc は元の unquoted command 位置で予約語として選ばれる場合を止める。非同期 body の source / 実行先 / 副作用が未対応であるため、benign な単純 command、名前付き、group のいずれも UNKNOWN とする。`help coproc`、印字、quoted argument、実行しない array initializer の DATA を予約語と混同しない。同期形式へ変更すると並列性や入出力が変わる場合は、同目的の代替として自動採用しない。

`command -- git ...` では実 `--` を wrapper の terminator として消費し、その後の child と argv を既存 policy で判定する。`-p` 等の認識済み wrapper option と、nonexecuting `-v` / `-V` query を区別する。`--` 自体を禁止する修正ではなく、通常の literal child の過剰停止と protected child の取りこぼしを直す。同じ文字列が printf / message の消費値なら child command ではない。

未確定 dynamic executable は綴りの推測で許可しない。named array tuple / element / slice / indirect expansion や scalar の一般状態・argv 数は証明できず UNKNOWN。assignment と、literal printf の argument に渡した array DATA は実行名と別の役割で扱う。既存の対応 proof で解決した positional executable tuple / scalar は維持するが、それを一般 named-array evaluator へ広げない。

### R13 の object writer と difftool

[git-hash-object の `-w`](https://git-scm.com/docs/git-hash-object)は object database に実際に書き込む。blob を含む全 write、`--stdin` の write、または write 選択が未確定な argv を UNKNOWN とする。staged inventory にない object 内容・対象・実行条件は確認できない。`-t` / `--path` の消費値や `--` 後の filename を実 `-w` と混同せず、対応 static no-write query / actual help は区別する。no-write の hash 計算は保存操作と目的が異なるため、writer を止めたときの自動代替にはしない。hash-only が通ることも、filter / object 内容や任意設定内部の安全認証ではない。

active `git difftool` は、明示 extcmd がなくても既定 tool / env / config による外部 source を選べるため UNKNOWN とする。ordinary public file の viewer も停止し、対応 static actual help は別役割とする。対応 diff を案内できるのは、helper が不要で同じ対象・目的・実行条件を維持できる場合に限る。viewer 自体が必要なら owner に外部 source と対象・条件を渡す。

### R13 の cookie / client argv / copy destination

[curl の `-b` / `--cookie`](https://curl.se/docs/manpage.html#-b)では、nonempty で `=` のない実値を local filename として扱う。`-` は stdin 入力、empty は cookie engine のみ、inline `key=value` は DATA と区別する。確定した対応 argv / context の file-input 形は既存の upload 禁止として FORBIDDEN、未知 prefix / file provenance / 引数個数は UNKNOWN。ファイルが存在する、有効 cookie が送られるという成立確認ではない。macOS curl 8.7 の native 照合で未対応だった `--cookie=...` の形を、同版で file 読取が成立した証拠にはしない。

xargs / find 等による incomplete curl / wget / gh は、見えていない argv が option・payload を追加できるため、visible upload flag がなくても UNKNOWN とする。普通の generated query も停止し、direct な対応 fixed query は別対照である。見えている argv に help と書かれていても、incomplete な実 client を一律 query と推定しない。

curl の actual argv 境界で bare な未知 `$URL` / `$OPTIONS` 等は、option と URL の役割を選び得るため UNKNOWN。語分割 / glob / brace による追加 argv も停止する。対応 `--header "$H"` の quoted scalar 消費値、固定 https prefix の scalar URL、実 `--` 後の quoted scalar URL は、この新しい境界条件の対照である。quoted scalar を通すことは、値・宛先・内容や default client 設定の安全認証ではない。他の file-input 禁止や source / context の UNKNOWN は独立して残る。

rsync / scp は option value を除いた actual operands の最後を destination として判定する。未知 source / destination の語分割や expansion、missing value、未対応 option、引数個数が不明なら UNKNOWN。rsync の trailing `--block-size` 等の value を宛先と誤認せず、colon-shaped option DATA と actual remote destination を区別する。確定した remote destination は既存の禁止、確認済み local destination は他条件下の対照である。remote RSH の local helper 条件も独立して適用する。

### R13 の pre-commit config と既存 whole-chain 条件

shared `preCommitConfigKey` は、Git の `-c` / `--config-env` の key と value / env 名を区別する。consumer は active commit より前と当該 commit の順序で検査する。例外は対応する `core.quotePath` / `color.*` / `advice.*`、user / author / committer の各 name / email、実 terminal stdout usage である。表示 key を維持する根拠は、[Git 公式 config 文書](https://git-scm.com/docs/git-config)の pathname quoting・色・optional advice の役割と、既存対応条件である。初期 identity-only 案のまま既存 display DATA をさらに止める方針は採用していない。

その他 / 不明 key は UNKNOWN。false 値、未使用に見える helper、read query の名称だけから実行効果・index 維持を証明しない。対応 metadata の value に helper 名が書かれたときは、それを key や executable source と混同しない。API の例外は global permission ではなく、alias / include / hook / root / target / env / source の独立した停止を解除しない。

旧 common には staging / commit を含む Bash 全体の key 条件もある。consumer が pre-commit order を見ることと、この旧条件は別であり、対応外 `-c` を commit 後に移すだけでは許可にならない。review の exact `git -c diff.external=./x.sh diff; git commit -m m` は df / c7 / d684 の全 3 guard でも停止していた。R13 ではこの例を新穴と数えず、config key と env の分類・共有 API・担当理由の整合を明確にする。設定を外す / operation を分離する出口も、同目的・同条件を保てる場合だけであり、後続 commit の index は改めて検査する。

## 停止したときの出口

まず、禁止対象が確定したのか、必要情報が不足したのかを理由と入力から確認する。UNKNOWN は、危険な操作が成立したと断定した記録ではない。

同じ目的を、確認済みの literal file、通常の repository / env、対応済みの argv / source で保てる場合だけ、その形式に書き換える。別の設定 root、file-upload、custom config そのものが目的に必要なら、別 operation へ勝手に置き換えず、対象・cwd・env / config・外部プログラム条件・不明点を owner に渡す。対応範囲を追加する場合は、許可条件と禁止・UNKNOWN・通常作業の対照を揃える。

個別 operation の owner approval は、hook の無効化や guard 回避の承認ではない。別の場所へのコピー、実行名の引用・変形、別ツール経由の実行も、承認済みの代替にはならない。担当のない経路へ移しただけで、未被覆が解消したと扱わない。

## R14: executable source と既定 client 設定の境界

R14 は formal review の8入力を、元の df463a9 と既存公開 head にも直接渡して比較した後、対応範囲・結果・例外を決めてから実装した。7入力は旧版から未停止であり、GIT_ASKPASS の1入力だけは本作業で旧拒否が失われていた。直接 hook の拒否履歴を、実際の authentication / file upload / 漏出成立の実測へ読み替えない。

| 守る対象 | 必要条件 / UNKNOWN | 影響する通常作業 | 対応済みの形式・出口 | 確認する対照 |
|---|---|---|---|---|
| 選択した local shell 関数の実行 source | original unquoted function 構文の定義と実 call を区別し、対応 brace / subshell body を独立 scope で検査。未対応 body / conditional definition / search の変更や既存関数を選ぶ mediated source は UNKNOWN | 複雑な関数や eval / trap / alias 経由の関数 call | 同じ目的を直接の対応 source に表せる場合だけ書換え。関数の実行条件自体が必要なら owner へ | 未使用 definition・quoted / printed DATA・普通の対応 body、call positionals / env、reserved `time` と外部 wrapper の役割 |
| shell stdin / file / FD source | literal `-c` と、pipeline がなく redirection / heredoc が合計1つだけの literal here-string / quoted heredoc を検査。parser の original FD proof が default / literal 0 を確定すること。pipeline / interactive stdin、script filename、dot / source、非0 FD・allocated / unknown FD・競合入力は UNKNOWN | script file の実行、pipeline で生成した shell、複数 FD の通常 script | 同目的の literal source が確認済みなら対応 `bash -c '…'` 等へ。file source が必要なら内容と条件を owner へ | known context の Bash の実 first literal `--help` / `--version` は未使用 child source と区別。later flag は証明にせず、外側の expansion / redirection は検査 |
| eval の executable source | concat 前の各 actual argv の bytes と語数・境界を確認。未確定 dynamic / split / glob / brace / unknown ANSI-C source は UNKNOWN | 変数から組み立てる eval | 同目的の直接 command / 対応 literal source に表せる場合だけ書換え | literal eval、消費する DATA、単一語の proof がある known bytes、ANSI-C の不明 decode を区別 |
| child Bash startup source | 選ばれた BASH_ENV の filename / expansion / 本文を未検査なら UNKNOWN。literal `-c :` でも startup は先に動き得る | startup file を使う Bash wrapper | 同目的に startup が不要なら actual per-call `env -u BASH_ENV` と対応 source。必要なら owner へ | 実 first help/version、prefix / export / declaration / inherited positive selector、print DATA、conditional unset |
| 認証・接続 helper source | active GIT_ASKPASS / SSH_ASKPASS / core.askPass の authentication-capable Git、Wget の実 `--use-askpass`、SCP の実 `-S`、selected SSH_ASKPASS の SSH / SCP / SFTP / remote-shell rsync は UNKNOWN | push・remote query・認証付き download・custom connection helper | helper が使われないと証明できる対応 local query / local-only copy / daemon route / terminal query を区別。必要な auth / helper 自体に同目的代替がなければ owner へ | download 方向でも helper を検査。option-looking consumed DATA、per-call removal、Wget の実 `--no-config` と完全な対応 argv 下で実 `--use-askpass` がない unused WGET_ASKPASS / SSH_ASKPASS を区別 |
| curl の implicit config | actual first literal argv が正確な `-q` / `--disable` で、他の argv / context 条件を満たすこと。later / consumed / unknown prefix は抑止証明にならず UNKNOWN。明示 config も UNKNOWN | 普通の GET と help / version、CURL_HOME / HOME / XDG 等の default config | default config が目的に不要なら `curl -q https://example.invalid`、query は `curl -q --version`。必要なら config・file source・対象条件を owner へ | first / later `-q`、DATA・既定設定 root・明示設定・file upload の独立禁止 |
| Wget の implicit config | actual option role の `--no-config` と完全な対応 argv が必要。消費値 / 未知 option / cardinality では証明せず UNKNOWN。明示 config も UNKNOWN | 普通の download と help / version、WGETRC / HOME の default config | default config が不要なら `wget --no-config https://example.invalid`、query は `wget --no-config --version`。必要なら owner へ | no-config を header / output の値と混同しない。実 use-askpass、unknown option、native help/version の config load |

関数の本文と定義時の redirection / heredoc expansion は、選択された call で検査する。未使用の定義を実行した扱いにはしない。一方、定義後の既存 Git context / positional taint / whole-chain 条件は維持し、`git` 関数の shadow は引き続き UNKNOWN とする。original reserved `time` が直接 local 関数を選ぶ場合は本文を検査し、`command` / `builtin` や外部 `env` / launcher の child は local 関数 call と推定しない。

FORBIDDEN と UNKNOWN の理由は独立して確認する。見えている禁止形が先に停止する場合もある。ALLOW 対照は、その行の条件だけで任意 executable / env / config 全体を安全認証する意味ではない。通常の環境で helper 名が見えないことも、すべての実行時 selector が不在という証明にはしない。hook process の既知 positive selector は名前だけを seed し、値や credential を記録しない。

これらの source 条件は常時 Bash の egress 自身が担当する。formal review の8入力すべてで、local L2 の `denyBy` に egress を必須とする。conditional Git guard の union が停止したことだけで実 dispatch が成立したとは記録しない。試験は解析 metadata・判定と理由 / required guard・実際の CLI 入口と副作用の3層に分ける。R14 の凍結 source の実測を次段落に記載する。R13 の3250件・6試行を新 source の結果に持ち越さない。

2026-10-13 **17:16:02 JST** の R14 凍結 source 直接入力 suite は **3498/3498、broken0、source不変**。公開 f2f8 の3250 IDとcommand / stdin / cwd / project / env入力をすべて保持し、3042定義は不変、208期待だけをALLOWからUNKNOWN / egress必須へ変更した（implicit client config 196、未検査のshell source 12）。248入力を追加した。同じ3498入力に対する旧f2f8は **307 decision不一致、reason-only0、broken0、source不変**、取得は17:16:01 JSTである。不一致は独立脆弱性・漏出の件数ではない。L1公開解析契約 **33/33**、deny API / lib不在契約 **6/6**。個別のprivate metadata assertion 144/144やnative DUMMY観測は、この33件へ加算しない。

R14のactual CLI 2.1.296は **17:14:43 JSTまでの8試行 / 実入口確認6 PASS / 0 FAIL / 2 NOT_EXERCISED**。ordinary関数body、`curl -q --version`、`wget --no-config --version` は正常tool result。pipeline stdin shell、script filename shell、default configを抑止していない `curl --version` は actual egressのUNKNOWN denyで停止した。正常関数例は3本、残る実施例はegressのみが起動した。この代表測定を任意入力のdispatchへ一般化しない。全試行でHEAD / refs / index / status / DUMMY `.env` / a.txt / helper markers / object database inventoryは不変。BASH_ENV startupとCURL_HOME default configの2例はAPI safeguard（cyber refusal）がBashより前で止めたため、guard自身のdeny成功ではない。これらとauth helperのactual入口は未測定のまま分ける。nativeのoffline credential helper / file:// / local-copy / config-load観測は別層であり、実送信・secret・Wget authentication challengeは実行していない。

sourceは common `51202716`、egress `0df0b5c4`、secret `a78a0acd`、add-all `210a9bcb`で固定。original PreToolUse matcher / if / timeout、permission denyを保持し、user defaultsは有効。trust変更、model override、permission / hook bypassは使用していない。untrusted DUMMY workspaceのproject Skill allowは無視され得る。production SessionStart / PostToolUse / Stop / pluginと本番全lifecycleは再現していない。通常作業の例が通ることも、任意program内部・default SSH設定・すべてのruntime envの安全認証ではない。

## R15: startup / exported function / outbound DATA の境界

R15 は R14 公開 head `4f0ff562` への fresh review の 7 指摘（Codex 6、CodeRabbit 1）を入口とする。対応範囲・3 種類の結果・止まる通常作業・出口を先に定め、選択した source と outbound DATA に局所的な fail-closed を加える。正式指摘の 6 command は、旧 df463a9・f2f8・4f0ff562 の全 3 hook に直接渡すといずれも ALLOW だった。これは旧版からの直接判定の抜けであり、実漏えいの測定ではない。別途、`f() { …; }; export -f f; bash -c f` の直接判定は、旧 f2f8 の停止が R14 で失われていた。未使用の関数定義を deferred source と分けた修正から、child に export する source への結び付きが欠けた退行である。同じ source の群として修復し、witness 数を独立した脆弱性の件数と数えない。

| 守る対象 | 必要条件と判定 | 止まる通常作業 | 対応する形式・出口 | 対照と試験 |
|---|---|---|---|---|
| ENV / BASH_ENV startup source | positive ENV と interactive / 未確定な対象 shell mode は UNKNOWN。noninteractive・実 terminal query・privileged 条件を別に確認する。Bash の POSIX / privileged / interactive 条件も startup 選択の役割で扱い、SHELLOPTS / POSIXLY_CORRECT 等が未確認なら非実行を推定しない | ENV で初期化する interactive shell、startup file を使う wrapper | 同目的に startup が不要なら、実 per-call `env -u ENV` / `env -u BASH_ENV` と対応 literal source を検討する。必要な初期化・interactive mode 自体を削除して目的が変わるなら owner へ | 正の prefix / inherited env、実 `-i` / `-p` / POSIX mode、consumed DATA / query、後続 child の再選択。installed shell で一例の marker が出ないことを全環境の非実行証明にしない |
| child が import / export する function source | 明示 `export -f` / function attribute、`set -a` / `set -o allexport` の自動 export、modern `BASH_FUNC_name%%` / known legacy header の potential import を名前だけで追跡する。選択した child callee の本文・選択が検査できなければ UNKNOWN。名前自体が未確定で選択を確認できない child も UNKNOWN | child Bash が親の function を使う wrapper、環境で関数を渡す script、allexport script | 同じ目的を対応する直接 source に表せる場合だけ書換え。実 `env -i` で import が不要になる場合は、環境消去が変える他条件も再確認。attribute 解除の出現だけでは既に追跡した export の不在を証明しない。function import 自体が必要なら owner へ | 既知の未使用 export と child `-c ':'`、query / attribute removal と新 export の区別、local / transient env scope、env clear、privileged child と nested nonprivileged re-import。関数本文や環境値を log に保存しない |
| GNU timeout / nice / stdbuf が実行する child | nice の `-n` / `--adjustment`、stdbuf の `-i` / `-o` / `-e` と `--input` / `--output` / `--error` の値を、attached / separated と実 `--` の役割で消費する。timeout は正確な `-s` / `--signal` と `-k` / `--kill-after` の attached / separated 値、対応する flag、literal duration、実 `--` を読んでから child を検査する。missing / dynamic / unknown / abbreviated option、未知 duration は UNKNOWN。signal 値や child argv の `--help` は actual timeout query と別 | `timeout --sig …` 等の省略形、生成 duration / options / buffering mode を使う launcher | 同じ意味になる正確な `timeout --signal TERM 5 <対応 command>` 等へ。duration は対応 literal の数値と単位 `s` / `m` / `h` / `d` にする。動的 option の意味を確定できなければ owner へ | separated signal / kill interval、attached / short、query / consumed DATA、duration・child の境界。GNU が受け付ける unique abbreviation も、この parser では未対応 |
| 単独 Git が選ぶ外部 helper | active operation の positive `diff.external` / GIT_EXTERNAL_DIFF、textconv / filter / hook / pager / include selector は、source 内部・実行条件を検査できず UNKNOWN。commit 前に限らず検査する。実 `--no-ext-diff` / `--no-textconv` と実 query の役割は区別 | custom diff・textconv・filter・pager を使う standalone read / write。読取り command 名だけでは許可しない | helper が目的に不要なら actual disable flag と対応 argv / cwd / env / config で同じ目的を保てる場合だけ書換え。必要な helper 自体に代替がなければ owner へ | external diff を選ばない ordinary log、format / grep / pattern の quoted scalar DATA、local getter / stdout query、消費値の disable。未知 argv / context は未使用の証明にならない |
| gh の file-backed outbound DATA | 共通 operation / payload role 分類で Release upload / create の asset と edit の notes file と Issue 本文の `--body-file` / `-F` を扱う。`file#label` は実 file 部分、本文 `-` は stdin source となる。確定した file payload は既存 file-upload policy の FORBIDDEN。本文 / notes の `-` が選ぶ未検査 stdin source は UNKNOWN。公開 artifact も同じ禁止範囲。operation / option arity / operands / context が未確定なら UNKNOWN | 通常の release asset 公開、public build artifact の upload、file / stdin 由来の Issue 本文 | query の `view` / `list` / actual help は別目的の対照。asset 転送と同目的の対応済み代替はないため、対象・file source・release / repo・cwd / env / config を owner へ | asset / 本文 file / stdin、`-R` / `--repo`・tag・literal body の消費値、actual help・query・print DATA、missing / dynamic operands。query を投稿や upload の代替としない |
| SSH remote command の outbound DATA | `-n` / `-f` は stdin を止める条件であり、remote command の展開結果を送らない証明ではない。同じ payload word に結び付く対応 reader の secret filename operand と確定 source / argv / context は FORBIDDEN。未知 producer / stdout / source / context は UNKNOWN | 変数・command substitution で組み立てる remote command、custom filter の出力を送る SSH | 同目的を確認した非秘密 literal DATA / 対応 reader と確定 source にできる場合だけ書換え。生成や source 自体が必要で不明点が残れば owner へ | stdin と remote argv の独立判定、query / receive-only、印字 DATA、無関係の reader、unknown program / process substitution。ファイル名の共起だけで payload 内容を推定しない |
| Git push option の outbound DATA | actual `-o` / `--push-option` と対応 `push.pushOption` の DATA source を、repository / ref / index と別に検査する。関連 secret filename reader と確定 source / argv / context は FORBIDDEN。未知 source や未確定 destination / transport は UNKNOWN | 動的な push option、file 内容を push option にする server hook 連携 | 必要でない option を除いても同じ目的を保てる場合だけ再検査。必要な DATA が非秘密 literal で条件を満たす形は対照。source / transport 自体が必要なら owner へ | named remote の意味だけで DATA を許可しない。quoted `$OPTION` も安全値の証明ではなく、dynamic repository が option になり得る形は FORBIDDEN と断定しない |
| Vault wrapper の staged filename 読取と parity | canonical `SECRET_PATH_RE` は変更せず、shell copy の `.env?backup` / bare `secrets` / explicit whitespace 等を同期。Git `--name-only -z` の全 record と byte 数を読み、読取失敗・partial NUL・LF filename は何も unstage せず判断不能で停止する | 非秘密の LF を含む filename、staged 名前を読めない状態。通常の case / subdir / whitespace 名は predicate の対照で照合する | 完全な filename 読取と同じ対象を復旧して再検査する。LF 名や復旧できない source / 状態は owner に対象・操作・条件を確認する。別の場所へコピーして gate を回避しない | [専用 parity test](../../.claude/hooks/tests/secret-path-parity.test.cjs) は raw NUL reader、predicate、失敗前の unstage 不実行を確認する。full wrapper / 本番 Vault / push の試験とは分ける |

これらの shell / Git / outbound 条件は、常時 `Bash` の egress 自身が停止を担当する。条件付き secret-git / add-all の union だけで対応済みとせず、L2 の required guard と L3 の実 dispatch を別に測る。`.claude/settings.json` の `if: "Bash(git *)"`、全 Bash matcher、permission deny はこの変更で書き換えない。Vault wrapper は別入口の staged gate であり、PreToolUse 3 本による保護と混同しない。

source / cwd / env / config / helper と argv の必要情報を確認できない操作には `[判断不能]`、確認した policy 禁止には `[禁止]` を示す。secret filename を扱う reader と sink の関連を確認しても、実 file 内容・認証・送信成立を確認した意味ではない。process substitution の filename provenance も内容の証明にならず UNKNOWN とする。既知の未使用 source や consumed DATA が通る対照は、その担当条件だけの判定であり、任意プログラム・既定 config 全体の安全認証には広げない。

terminal help / version の例外は、original argv の query role と invocation context の両方を確認できる場合に限る。関数定義後の保守的な context 条件は維持するため、既知の未使用 export と `bash --help` を組み合わせても UNKNOWN で停止する場合がある。native Bash の help が本文を実行しなかった観測と、この停止を別に記録する。`R15EF19` は公開4f0ff562とR15候補がUNKNOWN、旧df463a9・f2f8がALLOWの通常作業制限であり、R15で新設した禁止や実漏えいの証明ではない。

追加の独立検証資料で報告された Release create asset / Issue 本文 file / nice / stdbuf long option は、当席でも公開 4f と修正前 candidate の全 3 hook が ALLOW と確認した。user 提供の Linux native 証拠と当席の macOS 測定を区別し、実秘密・実外部送信・任意プログラムの安全保証とはしない。追加判定を一つずつ外す disposable source の reverse verification は、危険入力・正常対照の試験とは別に取得する。別の独立判定が停止を維持する場合、単独判定の必要性は未証明と記録し、保護をまとめて無効化しない。

SSH / push-option は共通の値の生成元判定を使う。既存 state が確認できる quoted scalar の exact literal proof を一般の invocation にも渡す。読取・未対応加工・以前の処理で taint が残る変数は「非秘密」にしない。無関係な reader と静的な SSH command / literal `ci.skip` は別の対照として許可するが、同じ reader の後の変数代入だけで既存の taint が消えたとは扱わず、proof が確立しない変数 operand は UNKNOWN になる。

**R15 の確定ローカル測定（2026-10-13 19:40:57 JST）:** common `addb1e95` / egress `079e4f0d` の固定 source で直接 guard suite **3764/3764、broken 0、hash 不変**。旧3498件の ID / command / stdin / cwd / project / env はすべて保持し、3490定義は不変、5件の ALLOW→UNKNOWN と3件の UNKNOWN→FORBIDDEN理由分類だけを根拠付きで変更、266件を追加した。同じ3764入力を公開4fへ渡すと150件の判定 / 担当hook差と3件の理由だけの差、broken 0。差を独立した脆弱性や実漏えい件数とはしない。公開 L1 **45/45**、deny / dependency API **6/6**、別のfilename parity / NUL reader契約 **8/8**。disposable sourceで ENV、child import、Git helper、GH file payload、SSH remote argv、push payload、timeout / nice / stdbuf arity、autoexport の判定を個別に外し、対応witnessがALLOWへ戻ることと正常・関連対照の維持を確認した。initial inherited outer functionとRelease edit notes fileも単独edge reversalを確認した。

**R15 の実入口（2026-10-13 19:42:17 JST）:** CLI2.1.296、新sourceの **10試行 / 8実入口PASS / 0FAIL / 2NOT_EXERCISED**。explicit export / autoexportの選択はUNKNOWN、unused exportとtimeout / nice / stdbuf printf controlsはALLOW、Release create assetとIssue本文fileはFORBIDDEN。HEAD / refs / index / status / DUMMY files / helper markers / object inventoriesは不変。diff helperとpush optionはAPI safeguardがBash / hookより前に止めたためPASSに含めない。旧1ef6sourceの途中7試行 / 4PASS / 3NOT_EXERCISED（ENV、Release upload、SSH argv）は別の履歴で、新sourceへ持ち越さない。拒否済み3例はbypass retryせず、新sourceのauth/startup/SSH・upload-specific L3は未測定。fixtureのGH / SSHはnetworkなしのlocal marker stub、timeout / nice / stdbufはinstalled GNU9.11へのsymlink。original PreToolUse matcher / if / timeout・permission denyとuser defaultsを保持し、trust / model / bypass変更なし。production lifecycle / plugin / full trusted session、実外部送信やOpenSSH transportを再現した結果ではない。

新headのrequired CIとfresh review / thread状態はPRで別に取得する。旧R14結果やprivate focused / harmless native数を新統合suite・実CLIの成功数へ加算しない。

## R16: GH scalar の生成元と試験器具の可搬性

R15 の file / stdin 分類だけでは、Issue / PR 本文や Release notes に `$(cat …)` で読んだ値を渡す経路が残っていた。公開4fと5eaの全3hookで正確な3入力がALLOWだったことを当席で確認した。これは旧版から残る同じ値の生成元の不足であり、実送信・実秘密の読取を測った結果ではない。

識別できた GH write operation の body / notes / title は、SSH / push-option と同じ `outboundPayloadVerdict` で、対象wordに結び付くproducer・scope・order・source・contextを検査する。秘密filenameを読むproducerと確定した送信wordが結び付けばFORBIDDEN。未対応加工・stdout・taint・sourceが残ればUNKNOWN。repo / tag / assignee / label等の別役割は本文payloadと分けるが、quoted scalarで語数が保たれるだけでは値の生成元の証明にせず、既存のexact literal proofを要求する。確定literalと対応する既知変数は許可する。無関係なreaderと静的本文は許可対照であり、必要のない読取まで送信との関連を推定しない。

通常の生成本文・titleや動的repo等は、生成元を確定できなければ停止する。同じ目的と条件を保てる対応literal / exact scalar proofへ表せる場合だけ書換え、必要な生成処理や対象を変えてしまう場合はownerへ操作・対象・cwd・env/config/sourceと不明点を渡す。file optionの既存FORBIDDENと未検査stdinのUNKNOWNは独立に保持する。対応していない任意のGHプログラム・alias・外部処理を安全と認証したものではない。

CodeRabbitが追加指摘した試験器具の固定 `/private/tmp` / `/usr/bin/git` は、`os.tmpdir()`とテストprocessのPATHから解決したGitへ変更した。Gitのglobal/system設定はDUMMY fixtureで隔離し、stubは実行pathを正しく引用する。macOSの通常環境8/8と、空白・apostropheを含む別PATH / TMPDIRの8/8、Git shimの実使用と引用roundtripを確認した。Linuxでこの席が実行した結果ではない。production wrapper / Vault作業自体は起動していない。

R16の固定source（common `addb1e95` / egress `5233b213`）は2026-10-13 20:06:20 JSTに **3795/3795、broken 0、hash不変**。旧3764定義の入力・期待値をすべて保持し31件を追加した。同じ3795入力で旧5eaは18判定差、理由だけの差0、broken 0。公開L1 45 / deny API 6 / filename parity 8も全59契約が成功。3つの正確なGH生成値witnessはegress自身がFORBIDDENで停止し、共通value edgeだけを外すとALLOWへ戻った。literal / file / stdin / metadata対照を維持した。差は独立した漏えい件数ではない。

新sourceのCLI2.1.296は **5試行 / 4実入口PASS / 0FAIL / 1NOT_EXERCISED**。literal本文とexact scalar本文は許可され、networkを使わないGH stubのDUMMY markerだけが期待どおり増えた。file本文はFORBIDDEN、未確定selector sourceはUNKNOWNで停止し、HEAD / refs / index / status / DUMMY files / object inventories / 他markersは不変。秘密filenameの生成本文1例はAPI safeguardがBash / hookより前に止めたためguard成功へ加えない。実GH送信・auth・server・production全lifecycleは測っていない。R15の10試行 / 8PASSを新sourceへ持ち越さない。新head CI / fresh reviewは別に取得する。

## R18: no-verify の実 option と未確定 argv の境界

R18 の変更対象は、既存の非commit側の no-verify scanner である。commit の `-n` と長い no-verify option、read-only の DATA、raw backstop は既存の役割を維持する。scanner は shell parser が保持した word の見かけだけでなく、NUL を含まない string の `literalValue` と `dynamicMaySplit === false` の値の証明も使う。実 option を読める、split / glob / brace 等で追加 argv にならない条件に限り、引用を戻した値で option・消費値・terminator の役割を決める。たとえば `OPT=--no-veri; git push origin "$OPT"` のような prior assignment は、既知の単一語が hook 回避 option になる入力として扱う。`OPT=… git push … "$OPT"` という同じ command の prefix assignment は、argument 展開がその新値を見る証明にはならないため、この例の代わりに使わない。

| 条件 | no-verify 判定 | 通常作業への影響・出口 |
|---|---|---|
| 実 option の役割で確認した `--no-veri` 等の guarded no-verify 形 | FORBIDDEN / `[禁止]` | hook を維持して同じ操作を行う。hook 回避を含む目的に対応する代替はない |
| push / merge 等で未解決の argv が hook 回避 option・terminator・別の境界を選び得る | UNKNOWN / `[判断不能]` | quoted `"$REF"` も、単一語というだけでは option でない証明にならない。同じ ref・対象・実行条件を保てる literal、または対応する既知値の証明へ書き換えられる場合だけ再検査する |
| literal または値の証明がある、実 option terminator `--` | この後の operand を no-verify option としない | DATA の中に `--` が見えるだけでは terminator の証明にしない。他の target / source / payload 条件は残る |
| 対応する option が消費する、確認した単一語 DATA | no-verify option と混同しない | DATA の綴りが option に見えても、実役割を保つ。他の message / helper / push-option DATA の検査は別に必要 |
| 未解決の短い attached `-o"$VALUE"` と、長い `--push-option="$VALUE"` | 前者は空値で裸の `-o` になり次の語を消費し得るため UNKNOWN。後者は `=` が value slot を固定するため、この scanner では DATA | 同じ値・option の役割を保てる正確な長い形式、または非空の既知値の証明を検討する。push option の outbound DATA の検査を解除する例外ではない |
| 消費値が語分割・glob / brace 等で追加 argv を作り得る | UNKNOWN / `[判断不能]` | 最初の語が option に消費されても、余分な語が hook 回避 option になり得る。単一語を保ち同じ値を確認できる対応形式がなければ owner へ |
| config / branch / remote / add / stage の未解決値 | これらの built-in は no-verify hook 回避を提供しないため、この未知値の条件では新しく停止しない | 既存の設定・action・path 等の担当条件に残す。確認した明示 no-verify の禁止は維持し、他のガードの ALLOW や保護成立を推定しない |

これは no-verify の境界に対する局所的な fail-closed であり、全 push や全 shell の一括禁止を加えるものではない。通常の `git push origin "$REF"` でも未解決値が `--no-veri` を選び得るため停止する場合がある。実 `--` を置く対応形式を検討する場合も、その位置・対象・目的が同じであることを確認し、cwd / env / config / source / transport、他の protected operation の判定を解除しない。既存の raw backstop が UNKNOWN で先に停止する形も維持するため、表の FORBIDDEN を必ず最初の理由として返す約束ではない。

同じ目的を対応形式にできなければ、対象・操作・argv・cwd・env / config / source と未確認点を owner に渡す。個別操作の了承を hook 無効化の了承へ広げず、別場所へのコピーや別ツール経由を承認済みの代替にしない。担当は既存の add-all module の no-verify 判定であり、設定の conditional Git 入口と全 Bash egress の担当関係は変更しない。必要な egress 自身の停止と実 dispatch は、新 source の L2 / L3 で別に確認する。

**R18 の直接入力測定（2026-10-13 23:09:38 JST）:** 新 source の統合 suite は **3834/3834、broken 0、hash 不変**。source は add-all `215ca77a`、common `addb1e95`、egress `5233b213`、secret `a78a0acd`。旧3795件の入力を保持し、3793定義は不変、39件を追加した。最初の比較で旧期待との不一致が28対照あり、26対照の候補過剰停止は既存の DATA / 非hook回避 operation の役割を保つよう修復した。`EGN16` / `EGN18` の2対照は、未解決 push argv が option を選び得るため、ALLOW から UNKNOWN へ採用方針を変更した。公開 L1 45・filename parity 8と別実行の deny API 6が成功し、使い捨て source の単一判定を外す18対照も成功した。既知値の option 判定だけを外すと正確な witness が通り、未確定語の判定だけを外すと対応する UNKNOWN 入力が通る。静的な禁止・正常対照・他の独立した判定は保持した。比較の差を独立した脆弱性・実漏えいの件数にしない。CI / fresh review は公開後に別に取得する。

**R18 の実入口:** CLI2.1.296、同じ固定 source で、未確定 push argv は実際の全3 hook dispatch と add-all の UNKNOWN、保護対象の状態不変を確認した。既知 ref と消費値 DATA の2正常対照は exact Bash・全3 hook ALLOW・Git push の local DUMMY marker を確認したが、最初の試験は予期しない GH marker により FAIL と記録した。追加 trace（23:23:29 JST）は Claude 自身の `gh pr view --json url` を、呼出し元と4引数の hash で特定した。この特定の metadata query だけを fixture の期待値へ加え、保存済み2対照を23:32:12 JSTに再評価した結果は PASS。元の FAIL を保存し、再実行の成功と数えない。その他の marker、HEAD / refs / index / status / DUMMY files / object database は不変である。実 Git push / GH / transport は起動せず、stub はローカル DUMMY 応答だけを返す。正確な既知 no-verify witness は API safeguard が Bash / hook より前に停止したため NOT_EXERCISED。再評価後に行った正常対照の追加試行も、Bash dispatch 前に時間上限へ達したものは NOT_EXERCISED として別に残す。trust / model / bypass の変更は行わない。上記 R16 の結果は履歴であり、R18 の試験結果へ持ち越さない。

## 試験を 3 層に分ける

上記の条件ごとに L1 の意味、L2 の ALLOW / FORBIDDEN / UNKNOWN と担当、L3 の実 dispatch と副作用を別々に確認する。新しい source の結果を取得するまで、過去の合格数や dispatch を持ち越さない。

### R13 の測定欄

2026-10-13 14:15:51 JST の凍結 source 直接入力 suite は **3250/3250、broken 0、source hash 不変**。公開 d6844f7 の 2860 ID と command / stdin / cwd / project をすべて保持し、22 定義の期待だけを ALLOW から UNKNOWN / egress 必須へ変更した（未確定 executable 12、未確定 curl URL 境界 8、生成された incomplete curl argv 2）。2838 定義は不変、390 件を追加した。同じ 3250 入力に対する旧 d684 の結果は、最終期待で再評価して decision / 担当 hook 不一致 **215**、理由だけの不一致 **1**、broken 0、source 不変。旧 source の実行時刻は 14:06:09 JST であり、期待の再評価は別時刻である。case の不一致数を独立した脆弱性や実漏えいの件数としない。L1 公開解析契約は **25/25**、deny API / lib 不在契約は **6/6**。

14:07:48 JST の CLI 2.1.296 による最終 source L3 は **6 試行 / 6 PASS / 0 FAIL / 0 NOT_EXERCISED**。上表の 2 正常実行と 4 UNKNOWN 停止を、fresh independent DUMMY fixture ごとに actual Bash / hook dispatch と結果から確認した。negative は HEAD / refs / index / status、DUMMY file / helper marker に加え、object database の file 名・内容 hash も不変。hash-object の input は staged object と異なる未登録 DUMMY 内容を使った。正常 commit は a.txt のみと期待する tree / commit objects を追加した。difftool は同 revision なので actual deny を証明するが、逃げた場合に helper が呼ばれるとは証明しない。

source は common `71a6fed4`、secret `a78a0acd`、add-all `210a9bcb`、egress `a868934b` で固定。元の PreToolUse matcher / if / timeout と permission deny を保持し、user defaults を有効にした。trust 変更、model override、bypass は使用しない。DUMMY workspace は未 trust、project Skill allow は無視され得る。production lifecycle hooks / project plugin と fully trusted session は再現していない。cookie / xargs / rsync の R13 実入口と実 network 接続は未測定。DUMMY native と直接入力を L3 に加えず、file:// の照合を実 network 送信の証明にもしない。新 head の CI / fresh review は公開後に別に取得する。

### R12 の凍結 source に対する測定履歴

2026-10-13 13:10:20 JST の直接入力 suite は **2860/2860、broken 0、source hash 不変**。旧 c7 の 2530 ID と command / stdin / cwd / project をすべて保持し、editor 条件で 37 定義の期待を ALLOW から UNKNOWN / egress 必須に変更した。2493 定義は不変、330 件を追加した。通常形式の actual no-edit 対照 20 件も含む。L1 公開解析 API は **20/20**、deny API / lib 不在の契約は **6/6**。同じ 2860 入力を c7 に渡すと decision / 担当 hook 不一致 180、理由だけの不一致 0。初回並列比較の timeout 1 件は履歴に保持し、c7 の単独追試と最終追加 22 件を別測定で補完した集計では broken 0。case 不一致を独立した漏えい件数とはしない。

最初の並列比較では 80k alias key の `R6PO01` が c7 と候補で 20 秒の runner timeout に当たった。単独候補の追試では約 5.5 秒で UNKNOWN、必要な network 形を先に見る同値の判定順序へ変更した後は約 123 ms で同じ UNKNOWN となった。最終 full は timeout なし。途中の候補 full は source 変更中だったため最終の証拠にしない。config edit の actual help 4 対照と Bash の `[[ ... ]]` 1 対照で生じた候補過剰停止も修正し、旧 ALLOW の期待を維持した。

13:10:26 JST の CLI 2.1.296 の新 source L3 は **6 試行 / 実入口を確認した 5 PASS / 0 FAIL / 1 NOT_EXERCISED**。ordinary commit `2>&1` は exact Bash 1 回で a.txt だけを commit した（HEAD 変化は期待する副作用）。heredoc continuation と status は正常 tool result で状態不変。default commit editor、mapfile callback、実行名 glob は actual egress の `[判断不能]` で停止し、HEAD / refs / index / status、DUMMY `.env` と helper markers は不変だった。callback / glob では egress のみが起動したが、Git 引用変形で条件付き 2 本が省略されるという一般的な dispatch 証明にはしない。

rsync custom RSH の 1 試行は API `[cyber]` が Bash / hook 起動前に拒否したため **NOT_EXERCISED**。hook 停止の成功とは扱わず、model 変更や bypass retry は行っていない。FD 8、parser 22、editor / callback / RSH の DUMMY native 17 の意味照合は別の L1 補助測定であり、socket の実 network 接続は試験していない。

source は common `df5b9b91`、secret `031e9e5b`、add-all `210a9bcb`、egress `88fac8aa` で固定。DUMMY fixture は original PreToolUse matcher / if / timeout と permission deny を保持し、user defaults を除外する flags と permission bypass は使用しなかった。workspace は未 trust と CLI が表示し、project Skill allow 2 項目は無視された。trust 設定は変更せず、production SessionStart / PostToolUse / Stop / project plugin と本番全 lifecycle は再現していない。旧 6e5 source での 2 試行は source 変更を検知して打ち切った履歴であり、新 source の PASS に持ち越さない。

### R11 の測定履歴

| 層 | 確認するもの | R11 の証拠と限界 |
|---|---|---|
| **L1: 意味・parser metadata** | command と DATA、option arity、path proof、scope / order / pipeline、env / config、source 選択 | [git-guard-analysis.test.cjs](../../.claude/hooks/tests/git-guard-analysis.test.cjs) は R11 の凍結 common `0f0d102a` で **16/16**。file source、grep pager、notes/tag と query 境界の契約を含む。harmless Bash / dummy Git / `SSH -G` 等の native proof は意味の照合を助けるが、入力・版・fixture の範囲だけであり L3 ではない |
| **L2: permission decision と理由** | hook JSON の deny / 無出力、担当 hook、FORBIDDEN / UNKNOWN の理由 prefix、例外や壊れた出力 | R11 の全 3 hook への直接入力 suite は **2530/2530、broken 0、source hash 不変**。decision・`denyBy`・broken と任意の `expectReasonPrefixes` assertion を確認する。理由 prefix を指定していない case まで分類を自動検証したとはしない。共通 deny API と isolated lib 不在 fallback の契約は **6/6**。同じ 2530 入力を公開 a464 に渡すと判定 / 担当 hook 不一致 202、理由だけの不一致 0、broken 0 |
| **L3: Claude Code の実入口と副作用** | 実際の PreToolUse dispatch、設定の `if` / 全 Bash matcher、deny が対象 operation を止めること。副作用の検査は別に記録 | **R11 は DUMMY 8 試行のうち実入口を確認した 6/6 PASS、2 NOT_EXERCISED†**。status は正常 tool result、commit / notes / merge の `.env` file 入力は `[禁止]`、stash `-a` / glob add は `[判断不能]` の PreToolUse error。各回の対象 HEAD / refs / index / status、DUMMY file / marker は不変。tag file と grep-before-commit は API safeguard が Bash 前に止めたため hook deny と数えない |

† root が 2026-10-13 11:31:26 JST に取得した R11 の実入口結果は、CLI 2.1.296 と valid HEAD / divergent topic を持つ disposable DUMMY repository に対する 8 試行である。実入口を確認した入力は `git status --short`、`g''it commit -F .env`、`g''it notes add -F .env HEAD`、`g''it merge --no-ff --no-edit -F .env topic`、`g''it stash -a`、`git add -- .e?v` の各 1 回。egress の起動と negative の deny、実際の tool result / error、対象状態の不変を分けて確認した。

元の Bash matcher / `if` / timeout と permission deny list を保持し、wrapper は guard JSON を転送した。user default hooks を有効に保ち、hook / permission を迂回する flag は使用していない。production SessionStart は再現していない。開始・終了の hash は common `0f0d102a`、secret `a69ef8f3`、add-all `210a9bcb`、egress `73373a12` で不変だった。全 3 wrapper が引用 Git の例でも起動したため、条件付き 2 本の省略は実証していない。任意 child program、全 argv / env / config、curl query、他 operation family の実入口まで確認した結果ではない。

tag file と grep-before-commit の 2 試行は Claude API の `[cyber]` safeguard が Bash tool call より前に停止し、hook は起動していない。これらは **NOT_EXERCISED** であり、hook の拒否・保護成立・6 件の PASS に加えない。model 変更や bypass retry は行っていない。直接入力 fixture の成功も、この 2 経路の L3 を補う証明にはならない。

旧 a464 の観測は別の履歴である。2026-10-13 09:59:43 JST の CLI 代表 3/3 は status、引用 Git の secret add、glob add で、common `b804deaf` / egress `817f0db7` 等の旧 source に対する index 不変と `.env` 非 stage を確認した。2026-10-13 10:06 JST の旧全 guard suite は 2168/2168、broken 0 だった。これらを R11 source の実測へ持ち越さない。

2026-10-13 11:26:55 JST の最終ローカル比較では、R11 candidate の 2530 件がすべて pass し、source hash は不変だった。旧 2168 件の command / ID は保持し、`P191P13` の未知 `git commit -F"$FILE"` だけを deny / egress 必須へ期待変更、残り 2167 定義は不変、362 件を追加した。公開 a464 と同じ入力の 202 不一致は、採用した停止方針や担当条件を含む試験の差であり、202 件の秘密漏えい成立や独立した security gap を証明した数ではない。この 2026-10-13 11:26:55 JST の取得時点では公開 a464 の CI pass を取得済み、同 head の fresh 4 P1 は未解決で、新 candidate の CI / review は未確認、全 green は未達だった。新 head の CI と review はローカル結果とは別の測定として PR 上で確認する。

```bash
node --test .claude/hooks/tests/git-guard-analysis.test.cjs
node --test .claude/hooks/tests/secret-path-parity.test.cjs
node .claude/hooks/tests/git-guards.test.cjs
node .claude/hooks/tests/git-guards.test.cjs --hooks-dir /path/to/hooks --json
```

runner は disposable repository を用意し、case の command を hook の JSON 入力として渡す。case に書かれた upload や危険な operation を試しに実行しない。case 数と結果は実行した suite の出力を参照し、古い PR 本文や別時点の数値を現在の結果として使わない。

関連: [過去の層別測定](secret-guard-layers.md)、[CLAUDE.md の Secrets 境界](../../CLAUDE.md#secrets--sensitive-files--never-commit)。
