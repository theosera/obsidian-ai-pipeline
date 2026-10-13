# Bash の Git / secret ガード

この文書は PR #191 の R10 候補で固定した保護範囲と、拒否されたときの対応を説明する。目的は、秘密の履歴への混入、対象の一括追加、hook の回避、未検査のファイル送信や送信先の変更を防ぐことである。コマンド全体や任意の外部プログラムの安全を認証するものではない。

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

設定の `if` 記述だけから、任意の入力での実 dispatch を推測しない。今回の CLI 2.1.296 の実入口 3 例では、引用した `g''it` の例も含めて全 3 wrapper が起動した。条件付き 2 本が省略されたという証拠ではない。この観測を全変形入力や他版へ一般化せず、対応する変形経路は常時 Bash の egress 自身の停止も fixture の `denyBy` で確認する。hook に直接 JSON を渡す fixture 自体は dispatch の証明ではなく、L3 の代表実測と分ける。

方式は全面的な command allowlist ではない。危険な操作を検出する条件と、その近傍で必要情報を確認できなければ止める条件を置く。任意の Bash、external executable の実体、呼び出したプログラム内部をすべて評価できるとはしない。

## PR #191 の停止条件と通常作業への影響

各行の ALLOW 対照も、その行に示した条件下での判定である。他の禁止や UNKNOWN があれば停止する。path は基本的に filename policy であり、ファイル内容を秘密でないと証明する検査ではない。同じ入力に禁止形が見えても、先行する raw backstop などが UNKNOWN で停止すれば理由は `[判断不能] ` になる。表は常に `[禁止] ` が返ることを約束しない。

分類計画の 27 群を、PR の先行 round からの条件群と R10 で対応した条件群にまとめる。先行群には、main 由来の policy / raw backstop と、本 PR で追加した解析・停止条件を併記する。すべての禁止規則を本 PR で新設したという意味ではない。R10 行にも、既存の secret inventory へ新しい入力経路を結び付けた条件が含まれる。

表の L1 / L2 は確認する試験項目と既存対照を示す。理由 prefix の assertion がない古い対照まで分類を自動検証済みとはしない。L3 の代表実測と、各行の未測定範囲は後述する。

| 守る対象 | 対応範囲・必要条件 | FORBIDDEN / UNKNOWN | 止まる通常作業 | 対応済みの代替・出口 | L1: 意味・metadata | L2: permission と理由 | L3: 実入口・副作用 |
|---|---|---|---|---|---|---|---|
| PR 先行群: commit の対象 index / 履歴 | 単一の active commit、対応する argv / pathspec、実行前の対象 repository の staged NUL 読取と必要な ls-files 照合。inline staging、複数 commit、combined write、pipeline / background / group setup、先行の任意副作用、対象 plumbing は検査を迂回し得る | 対象を確定して読取に成功した secret filename は FORBIDDEN。index が検査後に変わり得る形、`commit -a` / patch、未検査 stream / plumbing、未知 commit argv は UNKNOWN | add と commit の連結、`commit -am`、interactive commit、複数 commit、history import、commit 前の file 更新 | 非秘密の同じ変更を literal file の add と単独 commit に分け、各段階で検査する。import / ref 操作自体が必要なら owner へ | commit option / 消費値、active vs help、invocation order / group / pipeline | newline staged secret の S4G14 deny と ordinary spaced file 対照。A10 複数 commit deny / N08 commit 後の read pipeline allow。DC04 は理由も確認 | 未測定† |
| PR 先行群: repository / cwd / index と実行先の一致 | 対応する Git 実行名、静的 `-C`、通常 index / config / pathspec env。先行 cd、git-dir / work-tree、PATH / FPATH / source / function による探索変更、未知 wrapper / xargs / find 追加 argv を追跡。commit 前に起動し得る指定 diff / pager helper も区別 | 検査対象と実行対象・index・helper が一致すると確認できなければ UNKNOWN。env 名の存在だけで秘密混入を確定しない | cd と commit の連結、別 index の commit、PATH 差替え、未知 wrapper、helper を使った read と commit の連結 | 同じ対象を確認して静的 `git -C <dir>` と単独 commit にする。副作用のある別 operation は分離し再検査。別 index / executable が必要なら owner へ | invocation ごとの env / cd / PATH、helper option arity、wrapper incomplete | 静的 -C / identity・date DATA allow と target env deny。R7SG09 helper 前置 deny / R7SG14 実 `--no-ext-diff` 対照、R7SG17 実 no-pager 対照 | 未測定† |
| PR 先行群: 保存・再評価される実行 source | 選択した alias / trap、算術の再評価、prompt、positional executable、shell `-c` / stdin、eval、Git credential shell helper 等の対応 source を解析。query / reset / message / trailing argv は DATA と分ける。任意 script file 内部は読んで保証しない | source 内の確認済み禁止はその禁止の分類。不明 source / arity / 値の proof / recursion / depth は UNKNOWN。source の登録・出現だけで実送信成立を断定しない | 変数 source の interpreter、一般的な script wrapper、関数 / source 後の Git、複雑な arithmetic / prompt を持つ通常 script | 同目的を対応する直接 command / 確認済み source に表せる場合だけ置換。source や script 内部が必要なら対象と不明条件を owner へ | alias / trap script 選択、shell source boundary、positional scope、arithmetic / prompt の proof | alias / trap query・reset、literal printf / echo、既知 numeric allow と未知 source deny。N06 heredoc message allow。L1 の alias / trap / shell 契約も参照 | 未測定† |
| PR 先行群: committed hook と明示 staging の維持 | 実 no-verify option（commit の短縮 `-n` 等を含む）、static core.hooksPath key の set / unset / override、actual blanket option / path。getter と option 消費値は区別 | 解析した no-verify、確定 protected key の変更・削除、包括追加は FORBIDDEN。raw hit、config editor、未知 key / section、実 option と証明できない語は UNKNOWN | hook path 変更、config 編集、一括 add。raw backstop では検索 / message / consumed DATA だけでも止まることがある | hook を維持し個別 literal file を stage。設定確認は対応 getter。同目的に hook の差替え・無効化が必要なら、個別操作承認で代替せず owner へ | actual option / value / operand、config action / key、actualBlanket | DC01 包括追加 / DC02 no-verify 禁止、DC11 hooksPath getter allow。L1 の `--chmod -A` / negation / `--` 後 DATA 対照 | 未測定† |
| PR 先行群: 明示送信と opaque client 設定 | curl / wget、gh gist、scp / rsync の actual remote destination、nc / ncat reverse-shell option など既存対応形。upload option と consumed DATA、ローカル copy を分ける。opaque config / SFTP session / batch / launcher / incomplete argv は中を実行・読取して補わない | static executable / argv / context で確認した明示 upload・remote copy・reverse shell 等は禁止形で FORBIDDEN。config / execute / batch / 未確定 payload・実行先は UNKNOWN | 公開 file の転送、custom client config、SFTP、一般 launcher。文字列に option 名を書くだけでも raw 停止はあり得る | 対応する非秘密 inline DATA / read-only query が同目的ならその形式へ。file 転送や opaque config 自体が目的なら対応済み代替はなく owner へ | executable / operand と option value、file provenance / upload mode | DC05 parsed file upload 禁止、DC08 opaque curl config 判断不能、DC12 literal header GET allow。remote copy / query / local copy の既存対照 | 未測定† |
| PR 先行群: literal credential pattern | 引用・escape を戻した literal word が既存 token / key / client secret inventory に当たるかを確認。filename policy と別。raw 文字列だけの candidate は別扱い | cooked literal の禁止 pattern 一致は FORBIDDEN。credential の有効性や実漏えいを証明した意味ではない。raw-only candidate、DATA / コメント / 共起を区別できない停止は UNKNOWN | token に見える test 値や log / message、例示 command。literal の存在禁止は表示 DATA でも適用する | 非秘密の placeholder で同じ test / 説明目的を保てる場合に置換。実 credential 値が必要なら別場所へのコピーで回避せず owner へ | cooked word / raw、実行名 / DATA、既存 literal inventory | parsed literal pattern deny と普通 placeholder allow。DC09 は送信形を印字するだけの raw DATA 停止が判断不能である対照 | 未測定† |
| PR 先行群: 入力・依存部品・検査の成立 | JSON object の hook payload、読める command / cwd、共通 lib、閉じた構文と depth、対象 repository の index / ls-files / alias 検査が成立すること | 不正 input、lib 不在、例外、parse / 読取失敗は UNKNOWN。空 index / 安全な source と推定しない。空 command は別途の無出力対照 | 不正 payload を渡す統合、壊れた hook 配置、repository 外や読取に失敗する commit、深い script | 正しい payload / dependency / 対象 repository を復旧して同じ operation を再検査。復旧できないときは不足情報を owner へ。hook を外さない | malformed source で problems / metadata 不足を確認。payload / dependency 契約を分離 | Q30 null / Q31 array deny と N55 empty object 対照、正常単独 commit allow。lib 不在を isolated copy で検査する API 契約も参照 | 正常入口 3 例†。不正 input / 依存・検査失敗の実入口は未測定 |
| R10: add / stage に混入する秘密・一括対象 | 実 subcommand と option arity、literal path / 証明した値。cwd と静的 `-C` から判断する root 条件 | secret filename、証明した `-A` / `--all`、対象 root 等は FORBIDDEN | 秘密を含む add、一括 add | 確認済みの非秘密ファイルだけを literal に列挙。秘密の追加という目的には許可代替なし | option / path、`literalValue` / `literalPath` を分離 | secret / broad deny と ordinary / template allow。変形入口は egress deny も必要 | secret add 停止 1 例†。包括追加 / stage 等は未測定 |
| R10: 実行時に変わる add / stage の対象 | 正確に引用した単純変数の bounded proof、単一静的 loop。未知 PATH / PWD / OTHER、複数 loop、active glob、tilde、magic、file 入力は展開しない | 検査不能な対象は UNKNOWN。静的 magic / file 入力も未対応 | 変数経由の add、`'*.ts'`、`--pathspec-from-file`、別 cwd に依存する path | 同じ対象を確認し個別 literal path にする。元の cwd / 対象を確認できなければ owner へ | 動的語、glob / tilde、loop scope、消費値 | UNKNOWN deny と proven ordinary allow。message / option value を path にしない | glob add 停止 1 例†。変数 / magic / file 等は未測定 |
| R10: Git の別設定から起動する helper と書込み | HOME / XDG_CONFIG_HOME の代入・解除、`env -i` を追跡。異なる config root を使う Git write / helper-capable read | 設定と helper 実行を確認できず UNKNOWN。値を戻しても未証明なら停止継続 | 別 HOME 下の add / commit / push、単独 status / diff / log、manual help、pager が動き得る query | 同目的を通常 repository / env で実行できると確認した場合だけ通常 env に戻す。限定 query / stdout usage は次節 | invocation ごとの env、pager、help kind、getter arity | ROOT write / read / manual deny、scalar query / stdout allow、multi query の `-P` 対照 | 未測定† |
| R10: ANSI-C 引用で作る command / argv | 対応 escape を decode し実 argv として再判定。復元不能な Git / network argv、ANSI-C 実行名の Git writer は保守的停止 | decode 後の禁止は FORBIDDEN。復元不能や writer の直接 guard 経路が確認できない形は UNKNOWN | byte escape の引数・実行名を使う通常操作 | 同じ argv を確認済みの通常 literal にする。未知 byte の意味を確認できなければ owner へ | decoded text、`ansiCUnknown`、option 消費位置 | encoded upload deny、literal DATA / getter / help 対照。復元不能は UNKNOWN | 未測定† |
| R10: API / client の file upload | parsed curl / wget upload option、gh api の `--input` と `-F` / `--field` の `@file` / `@-`。GET 指定でも file / stream 形は停止 | 静的 argv / context が確認できた file-upload 操作は FORBIDDEN。opaque config、動的 typed field の先頭・複数語化・追加 argv が不明なら UNKNOWN | 公開ファイルの API upload、file body の request | 同目的の file-upload 形式は未対応。非秘密 literal field だけで目的を満たす場合は対応 inline DATA。それ以外は owner へ | field / raw-field、option arity と値 | file 形 deny、inline typed / raw-field / header / jq DATA allow。理由を分離 | 未測定† |
| R10: stdin を送る network client の入力 | 同じ pipeline ID と先行 order の producer / 入力 redirect を、stdin を消費する nc / ncat / telnet / ssh に関連付ける。visible operand と限定 script を検査 | source / sink の identity・cwd / context も確認できた secret filename 入力は FORBIDDEN。未知 producer / executable / PATH / cwd / source / 動的入力、単なる file + network 共起は UNKNOWN | 複雑な sed / awk、任意 filter、source / PATH 変更後 reader の送信 pipe | 同目的を非秘密 operand と対応 script で表せる場合だけ書換え。literal DATA は file 読取と区別。不明なら owner へ | pipeline / order、file と program / 検索語、stdin 消費 mode | secret / unknown producer deny、public reader / literal DATA allow、query / receive-only 対照 | 未測定† |
| R10: SSH がローカルで実行する source | argv 境界と選択順、ProxyCommand / KnownHostsCommand / LocalCommand（明示的に無効な形を除く）。明示 `-F` の未知 config は読まない | source 内の parsed 禁止は FORBIDDEN。動的 source、未解決 `%` 等の展開、未知 `-F` は UNKNOWN | custom SSH config、通常 proxy command、未知 config の `-G` 確認 | 設定不要と確認済みの場合だけ `-F none` / `/dev/null`。対応 static source、確実な `-Q` / `-V` はその目的で使用。不明なら owner へ | option / remote command DATA、first option / last `-F`、query 境界 | upload source / unknown config deny、disabled / DATA / proven query allow。`-G` を blanket allow にしない | 未測定† |
| R10: Git の送信先 mapping | parsed remote action、宛先を変える config、push の argv / env / transport。動的 action を実行して調べない | 静的 remote add / set-url、exact protected key の書込・削除、実際の external repository operand は FORBIDDEN。section / include / transport の不明な効果、動的 action / destination は UNKNOWN | 変数で action を切替える作業、送信先の変更 | getter 確認は対応済み。変更・送信が目的なら対象と条件を owner へ。固定文字列にしても禁止変更は許可されない | remote action / 消費値、push 宛先 | parsed destination write deny、UNKNOWN action deny、get-url 等の対照 | 未測定† |

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

## 停止したときの出口

まず、禁止対象が確定したのか、必要情報が不足したのかを理由と入力から確認する。UNKNOWN は、危険な操作が成立したと断定した記録ではない。

同じ目的を、確認済みの literal file、通常の repository / env、対応済みの argv / source で保てる場合だけ、その形式に書き換える。別の設定 root、file-upload、custom config そのものが目的に必要なら、別 operation へ勝手に置き換えず、対象・cwd・env / config・外部プログラム条件・不明点を owner に渡す。対応範囲を追加する場合は、許可条件と禁止・UNKNOWN・通常作業の対照を揃える。

個別 operation の owner approval は、hook の無効化や guard 回避の承認ではない。別の場所へのコピー、実行名の引用・変形、別ツール経由の実行も、承認済みの代替にはならない。担当のない経路へ移しただけで、未被覆が解消したと扱わない。

## 試験を 3 層に分ける

| 層 | 確認するもの | 現在の証拠と限界 |
|---|---|---|
| **L1: 意味・parser metadata** | command と DATA、option arity、path proof、scope / order / pipeline、env / config、source 選択 | [git-guard-analysis.test.cjs](../../.claude/hooks/tests/git-guard-analysis.test.cjs) の最新 metadata 契約は 11/11（test source `de8be4c`、common `b804deaf`）。harmless Bash / dummy Git / `SSH -G` 等の native proof も意味の照合を助ける。対象入力・版・fixture の範囲だけであり L3 ではない |
| **L2: permission decision と理由** | hook JSON の deny / 無出力、担当 hook、FORBIDDEN / UNKNOWN の理由 prefix、例外や壊れた出力 | 全 3 hook の直接入力に decision・`denyBy`・broken と任意の `expectReasonPrefixes` assertion を実装。API 契約 6/6（共通 lib 不在の 3 hook を含む）、理由分類の代表対照 11/11。egress の 154 対照は分類前後で decision 不変、禁止 37 / 判断不能 35 / allow 82。focused 対照 30/30 |
| **L3: Claude Code の実入口と副作用** | 実際の PreToolUse dispatch、設定の `if` / 全 Bash matcher、deny が対象 operation を止めること。副作用の検査は別に記録 | **代表 3/3†**。CLI 2.1.296 の disposable dummy repository で、普通の status が正常 tool result、secret add が `[禁止]`、glob add が `[判断不能]` の PreToolUse error。3 例とも index before / after が不変で `.env` は stage されなかった |

† root が 2026-10-13 09:59:43 JST に取得した L3 の代表入力は、`git status --short`、`g''it add -- .env`、`git add -- .e?v` の各 1 回である。元の Bash matcher / `if` / timeout と permission deny list を複製し、観測 wrapper は guard JSON をそのまま転送した。user default settings / hooks を有効に保ち、hook / permission を迂回する flag は使用していない。production SessionStart は再現していない。egress wrapper は全例で起動し、negative 2 例で deny を返した。全 3 wrapper が引用 Git の例でも起動しており、`if` による省略は実証していない。

この実測は開始・終了の source hash が一致する common `b804deaf` / egress `817f0db7` 等の候補に対する 3 例だけである。副作用の実測は、その disposable index の不変と `.env` の非 stage に限る。表の他の停止経路、全 argv / env / config、任意の child program の副作用まで確認したことにはならない。直接入力 fixture とこの実入口観測も分ける。

上記は理由分類導入時点と、その後の限定更新で root / egress owner が取得した実測である。2026-10-13 10:06 JST の全 guard suite は 2168/2168、broken 0、検査対象 source hash は不変だった。旧 1717 件の入力は保持し、12 件の期待を保守的な停止へ変更、1705 件の定義は不変である。追加 fixture の repository-root 対照 1 件は、単体測定の本番 cwd から統合試験の disposable cwd に合わせた。CI とレビューは、このローカル結果とは別に GitHub の対象 head で確認する。

```bash
node --test .claude/hooks/tests/git-guard-analysis.test.cjs
node .claude/hooks/tests/git-guards.test.cjs
node .claude/hooks/tests/git-guards.test.cjs --hooks-dir /path/to/hooks --json
```

runner は disposable repository を用意し、case の command を hook の JSON 入力として渡す。case に書かれた upload や危険な operation を試しに実行しない。case 数と結果は実行した suite の出力を参照し、古い PR 本文や別時点の数値を現在の結果として使わない。

関連: [過去の層別測定](secret-guard-layers.md)、[CLAUDE.md の Secrets 境界](../../CLAUDE.md#secrets--sensitive-files--never-commit)。
