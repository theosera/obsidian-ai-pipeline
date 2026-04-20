# obsidian-ai-pipeline (X Bookmarks Sync)

X API を使って、認可したユーザー本人のブックマークを取得し、Obsidian Vault に Markdown 保存する pnpm workspace 構成です。

## 前提
- Node.js 20+
- pnpm 9+
- X Developer Portal で OAuth 2.0 (Authorization Code + PKCE) を有効化

## Workspace 構成
- `apps/auth`: ローカル認証サーバー (`/auth/login`, `/auth/callback`)
- `apps/sync`: 同期・提案・承認 CLI
- `packages/core`: 共有ロジック（X API, PKCE, markdown, grouping, path resolver）
- `data`: token 保存
- `analysis`: proposal 出力

## X Developer Portal 設定
- OAuth 2.0 Type: Authorization Code Flow with PKCE
- Scope: `tweet.read users.read bookmark.read offline.access`
- Redirect URI 例: `http://localhost:3000/auth/callback`

## .env 作成
```bash
cp .env.example .env
```
必須:
- `X_CLIENT_ID`
- `X_REDIRECT_URI`
- `OBSIDIAN_VAULT_PATH`

任意:
- `X_CLIENT_SECRET`（サーバー利用では Basic 認証ヘッダに対応）

## インストール
```bash
pnpm install
```

## 認証
```bash
pnpm --filter auth dev
# or
pnpm dev:auth
```
ブラウザで `http://localhost:3000/auth/login` を開いて認証します。成功すると `data/tokens.json` に保存されます。

## 同期
```bash
pnpm --filter sync sync
# or
pnpm sync
```
実行内容:
- `data/tokens.json` を読み込み
- 期限切れなら refresh token で更新
- `/2/users/me` 取得
- `/2/users/{id}/bookmarks` 全取得（pagination, max_results=100）
- `/2/users/{id}/bookmarks/folders` + `/folders/{folder_id}` 取得
- Markdown を 1投稿1ファイルで保存
- `_index.md` 生成

## 保存先
基本ルート: `OBSIDIAN_VAULT_PATH/X_Bookmarks`

- grouping 未適用:
  - `X_Bookmarks/<child-folder>/<YYYY-Qn or YYYY-MM>/post.md`
- grouping 適用済み:
  - `X_Bookmarks/<parent-folder>/<child-folder>/<YYYY-Qn or YYYY-MM>/post.md`

`folderPostCount` しきい値:
- `< 10`: フラット（日時フォルダ無し）
- `>= 10`: quarterly (`YYYY-Qn`)
- `>= 20`: monthly (`YYYY-MM`)

## proposal（提案モード）
```bash
pnpm propose:grouping
```
生成物:
- `analysis/x_folder_grouping_proposal.md`（ユーザー向け提案レポート）
- `analysis/x_folder_grouping_proposal_data.json`（内部データ）

この段階では **x_folder_mapping.json は更新しません**。

### grouping の考え方
- フォルダ名を `space`, `_`, `-` で token 化
- prefix: 先頭 token 一致
- suffix: 末尾 token 一致
- 条件:
  - 3フォルダ以上
  - token長 >= 2
  - stopword 除外
  - 部分一致禁止（token 完全一致のみ）
- `YYYY-Qn`, `YYYY-MM` は解析前に suffix 除去

## approve（承認反映）
```bash
pnpm approve:grouping
```
提案確認後にのみ実行してください。`x_folder_mapping.json` が生成されます。

## 実行コマンド（要件）
```bash
pnpm install
pnpm --filter auth dev
pnpm --filter sync sync
pnpm propose:grouping
pnpm approve:grouping

# shortcuts
pnpm dev:auth
pnpm sync
pnpm propose:grouping
pnpm approve:grouping
```

## よくあるエラー
- `Missing required environment variable`: `.env` 未設定
- `Token file not found`: 先に auth 実行が必要
- `Token exchange failed`: Redirect URI / Scope / Client ID 不一致
- `X API request failed (401/403)`: token失効や権限不足
- `Missing folder stats file`: `pnpm sync` 未実行で proposal した

## セキュリティ
- `.env` はコミットしない
- `data/tokens.json` はコミットしない
- エラーは原因が分かる形で標準エラーへ出力

## x_folder_mapping.json の扱い
- 正式成果物
- proposal/approve の承認フロー後に更新
- 将来 apply 処理への入力として利用

## optional（今回未必須）
- 既存ファイルの自動再編成（移動）
- grouping apply 自動化

