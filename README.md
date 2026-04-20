# Obsidian AI Pipeline

> **⚠️ 注意: 個人用ワークフローツール**
> このリポジトリは私自身の Obsidian Vault 構造に特化した個人用自動化ツールです。**汎用の OSS プロダクトとして設計されていません。**
> AI 駆動の自律型ファイル分類パイプラインの設計リファレンスとして公開しています。

OneTab からエクスポートした URL リストを読み込み、Web ページを自動取得・抽出・AI 分類して Obsidian Vault へ保存する自動化パイプラインです。

---

## アーキテクチャ概要

```
OneTab.txt（URL一覧） または X API ブックマーク
    │
    ├─ evaluatePolicy()      サイトポリシー判定（skip / review / auto）
    │
    ├─ [実行前確認]           処理件数・出力先を表示 → ユーザー [y/n] 確認
    │
    ├─ fetcher.ts            Playwright でヘッドレスブラウザ取得
    ├─ extractor.ts          Readability + Turndown で Markdown 化
    │
    ├─ classifier.ts         2段階 AI 分類
    │   ├─ snippets参照       _分析コンテキスト/snippets_YYYYMMDD.xml（最新版自動解決）
    │   ├─ Fast Pass         軽量モデル（Haiku / ローカル LLM）
    │   └─ Smart Pass        高性能モデル（Sonnet / GPT-4o）エスカレーション
    │
    ├─ router.ts             公開日付 + 記事数閾値による動的フォルダルーティング
    │   └─ folder_rules.json  sync-rules.ts で snippets から自動同期可能
    │
    ├─ [分類結果レポート生成]  context/分類結果レポート/OneTab分類結果レポート-YYYYMMDD.md
    │
    ├─ [承認確認]            Obsidian でレポート確認後 → y / e / q で操作
    │
    └─ storage.ts            Vault へ .md を保存（7段階パストラバーサル防御）
```

## 主要機能

- **自動 Web フェッチ**: Playwright によるヘッドレスブラウザで SPA・動的ページも確実に取得
- **2段階ユーザー確認**: 実行前（件数・出力先の表示）と分類完了後（レポート確認）の 2 回、承認を求める
- **2段階 AI 分類 (Fast / Smart Pass)**:
  - Fast Pass: 軽量モデル（Haiku、ローカル LLM）で既存フォルダへ高速分類（コスト最小）
  - Smart Pass: confidence < 0.7 のとき高性能モデル（Sonnet、GPT-4o）へ自動エスカレーション
  - snippets 参照: `_分析コンテキスト/snippets_YYYYMMDD.xml`（最新版を自動解決）を `historical_rules` としてプロンプトへ注入
- **動的フォルダルーティング**: 記事数の閾値に応じてフラット → 四半期 → 月別へ自動昇格、既存ファイルも引越し
- **snippets→folder_rules 自動同期** (`pnpm run sync-rules`): snippets の日付パターンからルールを推定し `folder_rules.json` へマージ
- **セキュリティ強化**:
  - 7段階パストラバーサル防御（URL デコード迂回 / 絶対パス拒否 / Unicode NFC 正規化 / `..` 即時拒否 / symlink 解決検証）
  - プロンプトインジェクション緩和（`sanitizeUntrustedText` + `<untrusted_content>` デリミタ + システムポリシープロンプト）
  - AI 出力パスの検証（`validateClassificationResult`）
- **dry-run モード**: `--dry-run` フラグでファイル移動をスキップし安全確認
- **Vault Root 外部化**: `pipeline_config.json` または環境変数 `VAULT_ROOT` で設定、ハードコードなし
- **中断リカバリ**: レポートファイルから API コスト $0 で処理を再開（`rescue-from-report.ts`）

---

## 環境要件

| ツール | バージョン |
|---|---|
| Node.js | v18+ （推奨: v22） |
| pnpm | v9+ （推奨: v10、`packageManager` で固定） |
| tsx | `pnpm install` で自動インストール |
| Playwright Chromium | `pnpm exec playwright install chromium` |
| API キー | Anthropic / OpenAI / Gemini のいずれか（またはローカル LLM） |

---

## セットアップ

```bash
cd pipeline
pnpm install
pnpm exec playwright install chromium
```

> pnpm は [Corepack](https://nodejs.org/api/corepack.html) で `corepack enable` から導入できます。本リポジトリは `package.json` の `packageManager` フィールドで pnpm のバージョンを固定しています。

---

## 実行コマンド

### 初回設定ウィザード

```bash
pnpm start -- --config
```

プロバイダー（`local` / `anthropic` / `openai` / `gemini`）、Vault Root パス、使用モデルを対話形式で設定。
設定は `pipeline_config.json` に保存され、次回以降はスキップされます。

### フォルダルール同期（snippets → folder_rules）

```bash
pnpm run sync-rules
```

`context/_分析コンテキスト/` 内の最新 `snippets_YYYYMMDD.xml` を解析し、日付パターンから monthly / quarterly ルールを推定して `folder_rules.json` へマージします（昇格のみ・降格なし）。snippets を更新したら実行してください。

### 通常実行

```bash
pnpm start ../context/_分析コンテキスト/OneTab_YYYYMMDD.txt
```

実行前に処理件数・レポート出力先を表示し `[y/n]` で確認します。分類完了後は `context/分類結果レポート/` にレポートが生成されるので、**Obsidian でレポート内容を確認してから** `[y/e/q]` で承認・修正・キャンセルを選択してください。

### dry-run（ファイル書き込みなし）

```bash
pnpm start ../context/_分析コンテキスト/OneTab_YYYYMMDD.txt --dry-run
```

### X (Twitter) ブックマークの取り込み

X API v2 経由で**ログイン中アカウントのブックマークを取得**し、fetcher/extractor と Classifier をスキップして**専用フォルダへ一括集約**します。

- **保存先**: `Clippings/X-Bookmarks/`（既存記事とは完全に別系統）
  - 環境変数 `X_BOOKMARKS_FOLDER` で上書き可能
  - Router の日付昇格ルール（QUARTERLY=10 / MONTHLY=20）に従い、件数が増えると `Clippings/X-Bookmarks/2026-Q2` のようなサブフォルダへ自動再編成
- **Classifier を通さない**: 短いツイート本文に対する AI 分類は不経済かつノイズ源になるため、固定ルーティング
- **重複排除**: 既存 URL と同じツイートは `knownUrls` により自動スキップ

トークンは他の API キーと同様に `~/.zshrc` で永続化します（下の **API キーの設定** 参照）。

```bash
# 全件取得
pnpm start -- --x-bookmarks

# 件数制限（テスト用）
pnpm start -- --x-bookmarks --x-limit=20 --dry-run
```

> App-only Bearer では `/2/users/:id/bookmarks` は 403 になります。必ず**ユーザーアクセストークン**を使用してください。
> ツイートは `x.com` ドメインですが、`--x-bookmarks` モードでは `evaluatePolicy` の `manual_skip` を**意図的にバイパス**します（API 経由なのでスクレイプ規約には抵触しません）。

### 中断からの再開（API コスト $0）

```bash
pnpm start -- --rescue "../context/分類結果レポート/OneTab分類結果レポート-YYYYMMDD.md"
```

### セキュリティテスト

```bash
pnpm test
```

### 複数記事のナレッジ統合

```bash
pnpm exec tsx merge-articles.ts "../Engineer/AGENT_assistant_VibeCoding/ClaudeCode/2026-Q1"
```

---

## 対話型レビューコマンド

分析フェーズ完了後、`Command [y/e/q]:` プロンプトが表示されます。

| キー | 動作 |
|---|---|
| `y` | 全件承認して Vault へ保存 |
| `e` | 特定記事のフォルダパスを手動修正 |
| `q` | キャンセル（Vault への書き込みなし） |

---

## ファイル構成

```
pipeline/
├── index.ts              メインパイプライン（エントリポイント）
├── config.ts             設定管理（Vault Root / dry-run / ウィザード）
├── fetcher.ts            Playwright Web フェッチ
├── extractor.ts          Readability + Turndown 抽出
├── x_bookmarks.ts        X API v2 経由でのブックマーク取り込み
├── classifier.ts         AI 分類エンジン（Fast / Smart Pass）
├── router.ts             動的フォルダルーティング
├── sync-rules.ts         snippets→folder_rules 自動同期
├── storage.ts            Vault 保存（セキュリティ防御層）
├── types.ts              型定義
├── merge-articles.ts     複数記事のナレッジ統合
├── rescue-from-report.ts レポートからの中断再開
├── fix_agentic_move.ts   フォルダ移行スクリプト
├── reorganize_agents.ts  エージェント関連ファイル再編成
├── test_runner.ts        統合テストランナー（security/classifier/router/storage）
├── test/                 テストスイート（67項目）
│   ├── helpers.ts        共通ヘルパー（TestRunner）
│   ├── security.ts       ensureSafePath / safeRename / getVaultRoot
│   ├── classifier.ts     ruleBasedClassify (structural) + getBestMatch
│   ├── router.ts         getRoutedPath（ルール/日付境界/例外）
│   └── storage.ts        escapeFrontmatter + saveMarkdown e2e
├── folder_rules.json     動的フォルダルール永続化
├── reports/              内部ログ（failed_onetab 等）
├── tsconfig.json
├── package.json
├── scripts/              旧JS版アーカイブ（参照用・実行非推奨、詳細は scripts/README.md）
├── utils/
│   └── rename_vault.cjs  Vault 一括リネームユーティリティ
└── docs/
    ├── walkthrough.md    詳細ウォークスルー
    ├── commands.md       コマンドリファレンス
    ├── implementation_plan.md
    └── task.md

context/                  ← pipelineの入出力ディレクトリ
├── _分析コンテキスト/      スナップショット（snippets_YYYYMMDD.xml, OneTab_YYYYMMDD.txt）
├── _ルールベースコンテキスト/ 分類ルール参考ドキュメント
├── 分類結果レポート/       AI分類レポート出力先（Obsidianで確認・承認）
└── vault_tree_history/   Vaultツリースナップショット
```

---

## API キーの設定

```bash
# Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export OPENAI_API_KEY="sk-proj-..."

# Google Gemini
export GEMINI_API_KEY="AIza..."

# X (Twitter) API — --x-bookmarks モードで使用
# OAuth 2.0 User Context のアクセストークン (bookmark.read / tweet.read / users.read スコープ)
export X_USER_BEARER_TOKEN="..."
```

`~/.zshrc` への追記を推奨します。`source ~/.zshrc` 後に `pnpm start -- --x-bookmarks` で取り込みが走ります。

> **X_USER_BEARER_TOKEN の取得方法**: X Developer Portal で OAuth 2.0 Client を作成し、`bookmark.read` / `tweet.read` / `users.read` スコープ付きで User Access Token を取得します。App-only の Bearer Token では bookmarks エンドポイントは 403 になります。

---

## 再利用について

パスや分類ルールが私の Vault 構造にハードコードされている箇所があります。
別環境で使う場合は `pipeline_config.json` の `vaultRoot` と `folder_rules.json` を調整してください。
AI プロンプト設計・Playwright フェッチロジック・TypeScript 構造のリファレンスとして自由に参照ください。

---

## 関連リポジトリ

- **[obsidian-ai-pipeline](https://github.com/theosera/obsidian-ai-pipeline)** — パイプライン単体の公開リポジトリ（設計リファレンス）
- **obsidian-vault-skills** (private) — Vault 全体の管理リポジトリ（本ファイルが含まれる）

---

## X Bookmarks Workspace (new)

このリポジトリには、既存パイプラインに加えて X ブックマーク同期用の pnpm workspace も追加しています。
本機能は **Claude 実装と Codex 実装の対照実験** として、同一リポジトリ内で共存できるように分離しています。

- `apps/auth`: OAuth2 PKCE 認証 (`/auth/login`, `/auth/callback`)
- `apps/sync`: 同期 / proposal / approve CLI
- `packages/core`: 共通ロジック
- Codex 側の保存先既定値: `Clippings/X-Bookmarks-codex`
- Codex 側の認可ポート既定値: `3838` (`X_REDIRECT_URI=http://localhost:3838/auth/callback`)

### セットアップ

```bash
cp .env.example .env
pnpm install
```

### 実行コマンド

```bash
pnpm --filter auth dev
pnpm --filter sync sync
pnpm propose:grouping
pnpm approve:grouping

# shortcut
pnpm dev:auth
pnpm sync
```

### proposal / approve の流れ

1. `pnpm propose:grouping` で `analysis/x_folder_grouping_proposal_codex_YYYYMMDD.md` を生成
2. 内容を確認
3. `pnpm approve:grouping` 実行後に `x_folder_mapping.json` を生成

> 注意: proposal段階では mapping を確定せず、フォルダ移動も行いません。

#### Codex 側の起動方法

```bash
# 1) 認証サーバー起動 (Codex側ポート: 3838)
pnpm dev:auth

# 2) 認証
# http://localhost:3838/auth/login をブラウザで開く

# 3) 同期
pnpm sync

# 4) 提案・承認
pnpm propose:grouping
pnpm approve:grouping
```

補足:
- Codex 側は `data/tokens.json` を利用します（Claude 側 token ファイルは参照しません）。
- Codex 側は提案レポートを `analysis/x_folder_grouping_proposal_codex_YYYYMMDD.*` 形式で出力します。
