# Bash の Git / secret ガード

この文書は PR #191 の保護範囲、R19 / R20 / R21 / R22 / R23 / R24 / R25 の修正条件、拒否されたときの対応を説明する。目的は、秘密の履歴への混入、対象の一括追加、hook の回避、未検査のファイル送信や送信先・実行 source の変更を防ぐことである。コマンド全体や任意の外部プログラムの安全を認証するものではない。各 round の取得時刻・source を付した測定は履歴として残し、新しい source の確認へ持ち越さない。

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

変数 proof は、値を追跡できる単純 literal 代入と、正確に引用した `"$NAME"` / `"${NAME}"` の対応範囲に限る。単一の静的 loop は body の scope だけで扱う。条件分岐・未実行関数・source・eval・read・複数要素などで証明が崩れる入力を、一般 shell evaluator で補わない。`.env.example` は filename のテンプレート例外だが、それを upload する操作まで例外になるわけではない。

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
