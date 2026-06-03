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
| `ts-coding-conventions` | このリポの TypeScript を書く/直す前 | AI-native 規約の発火用サマリ (原本は `docs/ai-coding-conventions.md`) |
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

## settings.local.json (gitignore 対象)

個人マシン固有の上書き設定 (例: 自分の vault path や local model endpoint)。
**commit しない**。`.gitignore` で除外済み。
