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

`block-secret-git.cjs` と `block-git-add-all.cjs` の設定には `if: "Bash(git *)"` の記述があり、`block-secret-egress.cjs` は全 Bash 入力を対象にする。共通 parser で引用・escape・選ばれた実行 source を検査し、確定できない pathspec、設定 root、送信先や実行 source は該当経路を fail-closed とする。設定の記述と実際の dispatch 測定を分ける。旧 a464 の CLI 2.1.296 測定では、引用 Git の例も含めて全 3 wrapper が起動した。

従来許可されていた未知の変数 / glob による add、環境の消去・差替えを伴う Git の書込みなども拒否される場合がある。許可する入力、安全な書換え、対応範囲と test command は [Git ガードの説明](../docs/security/git-command-guards.md)を参照する。

R11 では、通常の release tag 作成・削除・署名・検証と notes 更新も `[判断不能]` で停止する。対応 static query は別扱いだが、同目的の writer 代替は未対応である。commit の `-F` / `-t` と merge の実 `-F` / `--file` は単一対応 literal filename を検査し、未知 path・stdin / FD・複数 source / override は停止する。単一 public filename の許可は内容の安全認証ではない。commit 前の grep pager と curl `--url-query` の file 入力にも制限がある。必要な更新・source を対応形式にできなければ、対象と条件を owner に確認する。

通常の stash push / save / apply / pop や作成・管理・削除も、input / object / ref / index / working tree の効果が staged 検査の範囲外のため `[判断不能]` で停止する。対応 static list / show / actual help は読取対照であり、同目的の snapshot / writer 代替は未対応である。必要な操作は input / tree / ref の対象・操作・cwd / env / config / source と未確認内容を owner に渡し、個別操作承認を hook 無効化の承認に広げない。

R12 の実行 source 条件では、既定 editor も含めて editor の起動を抑止したと確認できない対応 Git 操作を `[判断不能]` とする。単独 `git commit`、普通の merge、editor を選ぶ `-e` / reedit / template / interactive / sequencer 等が影響を受ける。commit の対応 `-m` / `-F` / `-C`、実 `--no-edit` / dry-run / help と、merge の実 `--no-edit` は、それぞれ editor 条件の対照である。他の source / index / argv 条件を解除せず、消費値としての `--no-edit` を抑止 flag にしない。EDITOR / VISUAL / GIT_EDITOR 等の selector と `core.editor` / `sequence.editor` の変更・削除も実行 source の役割で扱う。

同じ R12 で、どの実行名でも active glob / brace / tilde 展開を検査不能として止め、実際の mapfile / readarray `-C` callback、Bash `/dev/tcp` / `/dev/udp` redirection、remote rsync の `-e` / `--rsh` / RSYNC_RSH も停止する。download でも helper はローカルで動き得る。callback-free 読取、単なる印字 DATA、helper が使われないと確認した local rsync は別の対照である。動的 Git config writer の key / action と、push が選ぶ include 設定も UNKNOWN とする。正確な literal `>&1` / `>&-` の FD 操作と `/dev/null` 出力は index への file 書込みと区別し、`>1` / `&>1`、未知 target や group の別条件は引き続き停止する。

R13 は、実 coproc の非同期 source、未確定の動的 executable（named array tuple / element、scalar 等）、hash-object の全 `-w` object database 書込み、active difftool の外部 source を UNKNOWN とする。引数のない query / actual help、literal 実行名の DATA、既に対応する proven positional executable は別の対照である。`command --` は実 option terminator を正しく消費して child executable を検査する精度修正であり、新しい一律禁止ではない。`command -v` / `-V` の query は実行と区別する。

network 側では incomplete な curl / wget / gh の生成 argv、curl の bare dynamic option / URL・語分割 / glob / brace、rsync / scp の未確定 destination / operand 数を UNKNOWN とする。直接の対応 query、確定 local copy、curl の対応 option が消費する quoted scalar DATA 等は別扱い。curl `-b` / `--cookie` の nonempty かつ `=` を含まない実値は file 入力であり、確定 argv / context の file-upload 禁止を適用する。empty / inline `key=value` と、option 名を印字する DATA を file 入力にしない。

commit 前と当該 commit の Git `-c` / `--config-env` は、対応する `core.quotePath` / `color.*` / `advice.*`、user / author / committer の name / email、実 stdout terminal usage を除き UNKNOWN とする。旧 common の staging / commit を含む Bash 全体に対する key 条件も独立して残るため、未対応 override を commit 後へ移すだけでは許可にならない。false 値・未使用に見える key・設定 query の名前だけで効果がないとは推定しない。既存 alias / include / hook / root 等の停止も解除しない。

試験結果は、その source で取得した L1 / L2 / L3 の記録で確認する。下記ガイドの R11 / R12 測定や過去の CLI dispatch の成功を、R13 の新しい条件の実測として持ち越さない。

停止理由の `[禁止]` は確認した policy 禁止、`[判断不能]` は対象・設定・source などの必要情報不足を表す。raw pattern の一致だけで実際の秘密送信を確認したとは扱わない。無出力も操作全体の安全認証や owner 承認ではなく、範囲外の経路を保護済みと記録しない。対応済みの代替がない操作は対象・実行条件・不明点を owner に確認し、hook の無効化や別の場所での実行を自動的な代替にしない。

## settings.local.json (gitignore 対象)

個人マシン固有の上書き設定 (例: 自分の vault path や local model endpoint)。
**commit しない**。`.gitignore` で除外済み。
