# Bash の Git / secret ガード

この文書は PR #191 の R15 までに採用した保護範囲と、拒否されたときの対応を説明する。目的は、秘密の履歴への混入、対象の一括追加、hook の回避、未検査のファイル送信や送信先・実行 source の変更を防ぐことである。コマンド全体や任意の外部プログラムの安全を認証するものではない。R11 / R12 / R13 / R14 の取得時刻・source を付した測定は履歴として残し、R15 の新 source の確認へ持ち越さない。

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
