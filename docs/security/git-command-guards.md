# Bash の Git / secret ガード

この文書は PR #191 の R12 で採用した保護範囲と、拒否されたときの対応を説明する。目的は、秘密の履歴への混入、対象の一括追加、hook の回避、未検査のファイル送信や送信先・実行 source の変更を防ぐことである。コマンド全体や任意の外部プログラムの安全を認証するものではない。R11 の取得時刻・source を付した測定は履歴として残し、R12 の実測と区別する。

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

## 誰が、どの入口を担当するか

`PreToolUse(Bash)` の入力を共通 parser `.claude/hooks/lib/git-guard-common.cjs` で読む。引用・escape・選ばれた source を解析するが、解析対象のコマンドを試しに実行して安全性を決めることはしない。

| 設定の入口記述 | 担当 | 対応範囲と限界 |
|---|---|---|
| `Bash`、`if: "Bash(git *)"` の記述 | `block-secret-git.cjs` | add / commit、index、対象 repository、commit 前の検査条件 |
| 同じ `Bash(git *)` の記述 | `block-git-add-all.cjs` | 一括 add、解析した no-verify option、hook path の変更 |
| すべての `Bash` | `block-secret-egress.cjs` | 対応する upload・送信先・ネットワーク入力・実行 source と、解析した Git の対応経路 |
| Read / Write / Edit | この 3 本の担当なし | 別の permission rules が設定された対象だけを担当する。これらの hook による保護ではない |
| MCP | この 3 本の担当なし | 接続先と別の permission / owner approval gate が必要。担当が確認できない経路は未被覆 |
| 起動後の子プログラム内部・任意の設定ファイル内の処理 | 個別の hook は付かない | 選択して解析する source 以外を包括的に検査しない。担当が確認できない処理は未被覆 |

設定の `if` 記述だけから、任意の入力での実 dispatch を推測しない。旧 a464 時点の CLI 2.1.296 の実入口 3 例では、引用した `g''it` の例も含めて全 3 wrapper が起動した。条件付き 2 本が省略されたという証拠ではない。この観測を R11 / R12 の新 source、全変形入力や他版へ一般化せず、対応する変形経路は常時 Bash の egress 自身の停止も fixture の `denyBy` で確認する。hook に直接 JSON を渡す fixture 自体は dispatch の証明ではなく、L3 の代表実測と分ける。

方式は全面的な command allowlist ではない。危険な操作を検出する条件と、その近傍で必要情報を確認できなければ止める条件を置く。任意の Bash、external executable の実体、呼び出したプログラム内部をすべて評価できるとはしない。

## PR #191 の停止条件と通常作業への影響

各行の ALLOW 対照も、その行に示した条件下での判定である。他の禁止や UNKNOWN があれば停止する。path は基本的に filename policy であり、ファイル内容を秘密でないと証明する検査ではない。同じ入力に禁止形が見えても、先行する raw backstop などが UNKNOWN で停止すれば理由は `[判断不能] ` になる。表は常に `[禁止] ` が返ることを約束しない。

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

[curl の `--url-query`](https://curl.se/docs/manpage.html#--url-query)は `@file` / `name@file` で file 入力を作れるため、確定した対応 argv / context では file-upload として FORBIDDEN にする。先頭 `+raw` や `name=value` の中の `@` は file 入力とはしない。quoted scalar の固定 `+` / `=` と、未解決 prefix・複数 argv に展開し得る値を区別し、後者は UNKNOWN。file-backed variable が query に流れる対応 expansion も検査する。普通の literal GET / inline query 対照は維持するが、file-input 自体が必要なら owner gate が必要である。

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

## 停止したときの出口

まず、禁止対象が確定したのか、必要情報が不足したのかを理由と入力から確認する。UNKNOWN は、危険な操作が成立したと断定した記録ではない。

同じ目的を、確認済みの literal file、通常の repository / env、対応済みの argv / source で保てる場合だけ、その形式に書き換える。別の設定 root、file-upload、custom config そのものが目的に必要なら、別 operation へ勝手に置き換えず、対象・cwd・env / config・外部プログラム条件・不明点を owner に渡す。対応範囲を追加する場合は、許可条件と禁止・UNKNOWN・通常作業の対照を揃える。

個別 operation の owner approval は、hook の無効化や guard 回避の承認ではない。別の場所へのコピー、実行名の引用・変形、別ツール経由の実行も、承認済みの代替にはならない。担当のない経路へ移しただけで、未被覆が解消したと扱わない。

## 試験を 3 層に分ける

R12 は上記の条件ごとに L1 の意味、L2 の ALLOW / FORBIDDEN / UNKNOWN と担当、L3 の実 dispatch と副作用を別々に確認する。方針決定時点の R12 全 suite・API 契約・L3 は未取得だった。後から取得した R12 の結果と、取得時刻・source を固定した R11 の履歴を以下に分ける。

### R12 の凍結 source に対する測定

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
node .claude/hooks/tests/git-guards.test.cjs
node .claude/hooks/tests/git-guards.test.cjs --hooks-dir /path/to/hooks --json
```

runner は disposable repository を用意し、case の command を hook の JSON 入力として渡す。case に書かれた upload や危険な operation を試しに実行しない。case 数と結果は実行した suite の出力を参照し、古い PR 本文や別時点の数値を現在の結果として使わない。

関連: [過去の層別測定](secret-guard-layers.md)、[CLAUDE.md の Secrets 境界](../../CLAUDE.md#secrets--sensitive-files--never-commit)。
