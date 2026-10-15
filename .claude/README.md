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
| `.env` / `.env.*` | API キー、DB URL | `.env.example` 以外は機密 |
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
