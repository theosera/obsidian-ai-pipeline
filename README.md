# Obsidian AI Pipeline

> **⚠️ 注意: 個人用ワークフローツール**
> このリポジトリは私自身の Obsidian Vault 構造に特化した個人用自動化ツールです。**汎用の OSS プロダクトとして設計されていません。**
> AI 駆動の自律型ファイル分類パイプラインの設計リファレンスとして公開しています。

OneTab からエクスポートした URL リストを読み込み、Web ページを自動取得・抽出・AI 分類して Obsidian Vault へ保存する自動化パイプラインです。

---

## アーキテクチャ概要

```
OneTab.txt（URL一覧） または X ブックマーク (Playwright)
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

### X (Twitter) ブックマークの取り込み（Playwright スクレイピング）

X 公式 API はフォルダ内ツイート取得の公開エンドポイントが無く、Basic tier ($100/月) でもフォルダ一覧が 20 件で打ち切られます。本パイプラインは公式 API を使わず、**`fetcher.ts` の永続 Chromium セッションを流用した Playwright スクレイピング**でブックマークを取得します（認証 Token 不要・コスト $0）。

- **フォルダ構造保持**: X 側のブックマークフォルダ階層を Vault 側に反映
- **保存先**: `Clippings/X-Bookmarks/<X側フォルダ名>/`（環境変数 `X_BOOKMARKS_FOLDER` で上書き可）
- **強制親フォルダ機能**: `<vault>/__skills/pipeline/x_forced_parents.json` に登録したキーワードを「単語境界マッチ」で含む X フォルダは、自動的に親フォルダ配下に階層化される
- **共通キーワード自動検出**: 3 つ以上のフォルダに共通する単語を検出し、`<vault>/__skills/context/分類結果レポート/x_folder_grouping_proposal_YYYYMMDD.md` に提案レポートを出力
- **SQLite メタデータキャッシュ** (`<vault>/__skills/pipeline/x_bookmarks.db`): 取得済みツイートIDで差分スクレイプ（既知ツイート 3 件連続でフォルダのスクロール終了）
- **Classifier をスキップ**: 短いツイート本文に AI 分類は不経済なため固定ルーティング
- **Router 日付昇格は適用**: `QUARTERLY=10 / MONTHLY=20` 閾値で `Claude Code/Tips/2026-Q2/` のように自動細分化

#### 初回セットアップ (X ログイン)

`fetcher.ts` の永続 Chromium データディレクトリ (`.chromium-data/`) に X のログイン状態を一度だけ手動で保存します。

```bash
# fetcher.ts 内の `headless: true` を一時的に `headless: false` に変更し、
# 任意の X ページを開いてログイン → セッションが ./chromium-data に保存される
# その後 headless: true に戻して通常実行
```

将来的には専用ヘルパースクリプトを用意予定。

#### 強制親フォルダの設定例

```jsonc
// <vault>/__skills/pipeline/x_forced_parents.json
[
  "Claude Code",
  "Obsidian",
  "MCP",
  "AI Agent"
]
```

この設定下での挙動:

| X 側フォルダ名 | Vault 階層 |
|---|---|
| `Claude Code` | `Clippings/X-Bookmarks/Claude Code/` |
| `Claude Code Tips` | `Clippings/X-Bookmarks/Claude Code/Tips/` |
| `Claude Code Hooks` | `Clippings/X-Bookmarks/Claude Code/Hooks/` |
| `Obsidian Plugins` | `Clippings/X-Bookmarks/Obsidian/Plugins/` |
| `MCP連携` | `Clippings/X-Bookmarks/MCP/連携/` |
| `LangChain` | `Clippings/X-Bookmarks/LangChain/`（マッチなし） |

部分一致は禁止（`AI` キーワードは `AIRI` にマッチしない）。複数キーワードが同時マッチする場合は**より長いキーワードを優先**します。

#### 共通キーワード提案の運用

スクレイプ実行時、強制親で吸収されなかったフォルダ群から共通キーワードを自動検出し、`x_folder_grouping_proposal_YYYYMMDD.md` を生成します。提案を承認する場合の選択肢:

1. **強制親に昇格**: `x_forced_parents.json` にキーワードを追加 → 次回以降のスクレイプで自動階層化
2. **個別マッピング**: `<vault>/__skills/pipeline/x_folder_mapping.json` に明示マップを追記
   ```jsonc
   { "AI Tools": "AI/Tools", "AI Ethics": "AI/Ethics" }
   ```

#### 実行コマンド

```bash
# 全件取得（差分スクレイプ：DB 既知ツイートをスキップ）
pnpm start -- --x-bookmarks

# 件数制限 + dry-run（書き込みなし）
pnpm start -- --x-bookmarks --x-limit=20 --dry-run
```

> ツイートは `x.com` ドメインですが、`--x-bookmarks` モードでは `evaluatePolicy` の `manual_skip` を**意図的にバイパス**します。
> X UI は仕様変更が頻繁です。スクレイパーが壊れた場合は `x_bookmarks_scraper.ts` の `SELECTORS` / `extractTweetsScript` / `extractFoldersScript` を最新の DOM 構造に追従させてください。

#### 今後の拡張 (Phase 2 以降)

- フォルダ件数 50 超で LLM サブカテゴリ提案 → 承認フロー → 自動再分類
- フォルダ単位の `_INDEX.md` 自動生成（要約 + 件数 + 最終更新）
- `--x-bookmarks-rebuild-db`: .md frontmatter から DB を再構築する CLI

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
├── x_bookmarks_scraper.ts  X ブックマーク Playwright スクレイパー
├── x_folder_mapper.ts      X フォルダ名 → Vault 階層パスの 2 層マッピング
├── x_bookmarks_db.ts       SQLite メタデータキャッシュ（差分スクレイプ用）
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
├── test/                 テストスイート
│   ├── helpers.ts        共通ヘルパー（TestRunner）
│   ├── security.ts       ensureSafePath / safeRename / getVaultRoot
│   ├── classifier.ts     ruleBasedClassify (structural) + getBestMatch
│   ├── router.ts         getRoutedPath（ルール/日付境界/例外）
│   ├── storage.ts        escapeFrontmatter + saveMarkdown e2e
│   └── x_bookmarks.ts    フォルダマッパー / SQLite DB / ツイート変換
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
```

`~/.zshrc` への追記を推奨します。

> **X (Twitter) ブックマーク取り込みは API トークン不要です**。`fetcher.ts` の永続 Chromium セッション (`.chromium-data/`) に X ログイン状態を保存して使用します。詳細は上記 [X (Twitter) ブックマークの取り込み](#x-twitter-ブックマークの取り込みplaywright-スクレイピング) を参照。

---

## 再利用について

パスや分類ルールが私の Vault 構造にハードコードされている箇所があります。
別環境で使う場合は `pipeline_config.json` の `vaultRoot` と `folder_rules.json` を調整してください。
AI プロンプト設計・Playwright フェッチロジック・TypeScript 構造のリファレンスとして自由に参照ください。

---

## 関連リポジトリ

- **[obsidian-ai-pipeline](https://github.com/theosera/obsidian-ai-pipeline)** — パイプライン単体の公開リポジトリ（設計リファレンス）
- **obsidian-vault-skills** (private) — Vault 全体の管理リポジトリ（本ファイルが含まれる）
