# Gmail MCP ローカルセットアップ注意点 (Google Cloud Console)

`/sec-mode`（週次 LLM 脅威レポート取込）を**ローカルの Claude Code CLI** で回すには、
Gmail を MCP 経由で読む / `processed` ラベルを付ける必要がある。その際の Google Cloud
Console + MCP セットアップで実際にハマった落とし穴を記録する。Security-only mode /
Default mode どちらの運用でも参照可。

> Trust Boundary は `docs/security/llm-sec-report-consumption.md` が正典。本ドキュメントは
> **認証基盤のセットアップ手順**のみを扱う（レポート本文の取扱いには言及しない）。

## 推奨構成（検証済み）

- **MCP サーバ**: [`taylorwilsdon/google_workspace_mcp`](https://github.com/taylorwilsdon/google_workspace_mcp)
  を `uvx` で stdio 起動（MIT / テレメトリ無し / egress は Google API のみ / 自分の OAuth
  クライアントを使う）。
- **登録（local scope, git に入らない）**:
  ```sh
  claude mcp add --scope local gmail \
    --env GOOGLE_CLIENT_SECRET_PATH="/path/outside/repo/_mcp_readonly/claude_gmail_mcp.json" \
    -- uvx workspace-mcp --permissions gmail:organize
  ```
- **権限**: `--permissions gmail:organize` 単体（読取 + ラベル操作、送信なし）。

## 落とし穴チェックリスト

1. **プロジェクトを1つに統一する**
   OAuth クライアント（`client_secret.json` の `project_id`）・**Gmail API 有効化**・
   **OAuth テストユーザー追加** は **すべて同一 GCP プロジェクト**で行う。複数プロジェクトに
   分散すると認証が通らない。確認:
   ```sh
   python3 -c "import json;d=json.load(open('<path>/claude_gmail_mcp.json'))['installed'];print(d.get('project_id'), d['client_id'][:24])"
   ```

2. **OAuth クライアント種別を用途で使い分ける**
   - ローカル stdio MCP → **「デスクトップ」型**（loopback リダイレクトを使うので
     リダイレクト URI 登録不要）。
   - claude.ai / Claude Desktop の**カスタムコネクタ（リモート）** → **「ウェブ アプリケーション」型**
     ＋ リダイレクト URI `https://claude.ai/api/mcp/auth_callback`。

3. **テストユーザー登録は必須**
   公開ステータス「テスト中」/ ユーザー種別「外部」では、**テストユーザーに登録した
   アカウントのみ認可可能**。レポート受信アドレスを必ずテストユーザーに追加する。
   未登録だと `access_denied`（アプリ未確認）で弾かれる。

4. **API の使い分け**
   - stdio サーバ（`google_workspace_mcp`）が使うのは標準 **Gmail API (`gmail.googleapis.com`)**。
   - Google 公式リモート **Gmail MCP API (`gmailmcp.googleapis.com`)** は claude.ai の
     カスタムコネクタ専用で、CLI の `claude mcp add` 経路とは別物。CLI 目的なら前者を有効化する。

5. **API Key は不要**
   OAuth 方式では API Key を使わない。Client ID / Secret（JSON 内）のみで動く。API Key は
   この用途では放置 / 削除可（攻撃面を増やさない）。

6. **認証情報の置き場**
   - `client_secret.json` は**リポジトリ外**（例 `~/dev/_mcp_readonly/`）に **`chmod 600`** で1か所。
   - **`.zshrc` に値を重複コピーしない**（平文コピーを増やさない）。`GOOGLE_CLIENT_SECRET_PATH`
     でファイルを指すだけでよい。
   - **`.mcp.json`（project scope = git 追跡され得る）に secret やマシン固有絶対パスを書かない**。
     個人用は `--scope local`（`~/.claude.json`）に置く。必要なら `.mcp.json` を `.gitignore` する。
   - OAuth 認可後のユーザートークン（`token` / `refresh_token` / `client_secret` を含む）は
     `~/.google_workspace_mcp/credentials/` に **平文 JSON（ファイル権限のみ。アプリ層の暗号化は無い）**
     として自動保存される。「暗号化されている」と誤認しないこと。`refresh_token` は長期有効な機密なので、
     ディレクトリを `chmod 700` で保護し、**バックアップやファイルシステムアクセスも secret として扱う**。
     より堅牢にするなら暗号化バックエンド（例: GCS backend）へ切り替える。

7. **MCP パッケージは実在確認してから入れる**
   `npx -y <name>` の前に必ず `npm view <name>` で実在を確認する。
   **`@modelcontextprotocol/server-gmail` は存在しない**（もっともらしいが実在しない
   ハルシネーション名）。公式 `@modelcontextprotocol` scope に Gmail サーバは無い。
   未検証名を `npx -y` で走らせるのは infostealer / slopsquatting の典型リスク。

8. **`google_workspace_mcp` のフラグは排他に注意**
   `--permissions` は `--tools` / `--read-only` と**相互排他**。Gmail 最小権限は
   `--permissions gmail:organize` **単体**（= 読取 + ラベル、送信なし）。`--read-only` は
   ラベル付与（書込）まで無効化するので、`processed` ラベル運用には使えない。

9. **OAuth 2.1 では認証は自動**
   `start_google_auth` は legacy（OAuth 2.0）で、OAuth 2.1 有効時は無効。通常は Gmail ツールを
   呼べば自動で認可プロンプト（認可 URL）が出るので、手動認証は不要。

## 接続確認

```sh
claude mcp get gmail        # Status: ✓ connected / Args: workspace-mcp --permissions gmail:organize
# claude 起動後 /mcp で gmail の tool 一覧を確認:
#   ✓ read 系 (search_gmail_messages / get_gmail_message_content / get_gmail_thread_content / list_gmail_labels ...)
#   ✓ label 系 (manage_gmail_label / modify_gmail_message_labels / batch_modify_gmail_message_labels)
#   ✗ send / draft 系が無いこと（= organize 最小権限が効いている証拠）
```

## See also

- `docs/security/llm-sec-report-consumption.md` — レポート消費の完全契約 / Trust Boundary
- `docs/security/llm-sec-weekly-automation.md` — Level 1 自動取込（GitHub Actions）
