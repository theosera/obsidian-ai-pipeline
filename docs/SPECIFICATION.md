# 詳細仕様

このドキュメントは [Obsidian AI Pipeline](../README.md) の詳細仕様をまとめたものです。実行コマンドのリファレンスは [実行コマンドリファレンス](cli-reference.md) を参照してください。

---

## 🧪 X ブックマーク取得の対照実験 (Claude vs Codex)

本リポジトリには X (Twitter) ブックマーク取得の **2 つの独立実装** が共存します。Claude と Codex に同じ要件で並行実装させ、設計・保守性・実行結果を比較する対照実験として運用中です。

**両実装は import グラフが交わらない独立サブツリー**として維持され、実行時の出力先・認可ポート・レポートファイル名を分離することで同居できます。

### 実装の所在とエントリポイント

| 実装 | 配置 | 設計思想 | 起動コマンド |
|---|---|---|---|
| **Claude 側** | リポジトリ直下 (`x_bookmarks_api.ts` / `x_auth_server.ts` / `hands_on_generator.ts` / `x_folder_mapper.ts` / `x_bookmarks_db.ts` / `x_session_*.ts`) | フラット構成、既存 `index.ts` / `router.ts` / `storage.ts` と統合、SQLite メタキャッシュで差分同期、UUID session_id で X↔Vault の drift 追跡、Claude Code CLI でハンズオン生成 | `pnpm start -- --x-auth` / `--x-bookmarks` / `--x-pick` / `--x-sync-folders` / `--hands-on=...` |
| **Codex 側** | `apps/auth/` + `apps/sync/` + `packages/core/*` (pnpm workspace) | workspace 構成、`.md` を source of truth、`packages/core` に共通化、grouping 提案→承認の2段階フロー | `pnpm dev:auth` / `pnpm sync` / `pnpm propose:grouping` / `pnpm approve:grouping` |

### 衝突回避ルール（同居・同時運用のための規約）

#### 出力先の棲み分け

| 資源 | Claude 側 | Codex 側 |
|---|---|---|
| ブックマーク .md | `Clippings/X-Bookmarks-claude/` | `Clippings/X-Bookmarks-codex/` |
| OAuth トークン | `<vault>/__skills/pipeline/x_tokens.json` | `data/tokens.json` (repo-relative) |
| 共通キーワード提案レポート | `x_folder_grouping_proposal_claude_YYYYMMDD.md` | `x_folder_grouping_proposal_codex_YYYYMMDD.md` |
| SQLite メタキャッシュ | `<vault>/__skills/pipeline/x_bookmarks.db` | (未使用) |

環境変数で出力先を切り替えてください:

```bash
# Claude 側で --x-bookmarks を実行する際
export X_BOOKMARKS_FOLDER="Clippings/X-Bookmarks-claude"
```

#### 認可・ポートの分離

| 項目 | Claude 側 | Codex 側 |
|---|---|---|
| `X_AUTH_PORT` | `3737` | `3838` |
| `X_REDIRECT_URI` | `http://localhost:3737/auth/callback` | `http://localhost:3838/auth/callback` |

X Developer Portal で **App を 2 つ作って別 Client ID を割り当てる**のが最もクリーン（レート制限も別枠になる）。予算を絞るなら共有も可能ですが、**両者の同時起動は避けて**ください (`/bookmarks` 180/15分、folder 系 50/15分の枠を取り合う)。

#### ソースレベルの独立性

両者の import グラフは交わりません:

- Claude 側: ルートの `index.ts`, `config.ts`, `types.ts`, `storage.ts`, `router.ts` を参照
- Codex 側: `packages/core/src/config/env.ts`, `types/shared.ts`, `fs/file-utils.ts` など自前のユーティリティを使用
- 共通ユーザー設定 `x_forced_parents.json` / `x_folder_mapping.json` のみ**意図的に共有**（ユーザー手動メンテ）

### 比較観点

- **起動までの工程数**: Claude は `--x-auth` 1コマンドで完了、Codex は workspace filter 経由（`pnpm dev:auth` → `pnpm sync`）
- **出力の一貫性**: 同一ツイートが両実装で同じ階層に落ちるか
- **レート制限耐性**: 429 のハンドリング、バックオフ戦略
- **コード量・保守性**: フラット vs workspace の読みやすさ
- **テストカバレッジ**: 各実装の単体テスト件数と粒度
- **機能差分**: Claude 側のみハンズオン生成 (`--hands-on`) を持つ

検証結果は `<vault>/__skills/context/分類結果レポート/` に両実装が生成するレポートを見比べてください。

### Codex 側の起動方法 (pnpm workspace)

Codex 側実装は pnpm workspace 配下に独立しています。初回セットアップ:

```bash
# 1. 依存インストール (ルートで workspace 全体)
pnpm install

# 2. .env を Codex 用に設定
#    X_CLIENT_ID / X_CLIENT_SECRET / X_REDIRECT_URI=http://localhost:3838/auth/callback
#    OBSIDIAN_VAULT_PATH=/absolute/path/to/vault

# 3. 認可サーバ (別ターミナル)
pnpm dev:auth                   # = pnpm --filter auth dev
#   → ブラウザで http://localhost:3838/auth/login (ポート上書き時)

# 4. 同期
pnpm sync                       # = pnpm --filter sync sync

# 5. grouping 提案 → 承認
pnpm propose:grouping
pnpm approve:grouping
```

grouping の 2 段階フロー:

1. `pnpm propose:grouping` で `analysis/x_folder_grouping_proposal_codex_YYYYMMDD.md` / `.json` を生成
2. 内容を Obsidian で確認
3. `pnpm approve:grouping` 実行で `x_folder_mapping.json` が確定生成

> **注意**: proposal 段階では mapping を確定せず、フォルダ移動も行いません。承認ステップを明示的に実行するまで副作用なし。

保存先は Codex 側の実装では `OBSIDIAN_VAULT_PATH/X_Bookmarks/<child>/<YYYY-Qn|YYYY-MM>/post.md` (fold 数閾値で `< 10` フラット / `>= 10` quarterly / `>= 20` monthly)。**対照実験として Claude 側と出力フォルダを分けたい場合は、`OBSIDIAN_VAULT_PATH` を Codex 専用ルート (例: `/path/to/vault/Clippings/X-Bookmarks-codex/..`) に切り替えるか、`packages/core` 側の path resolver を Codex ブランチ内で上書きしてください**。

Codex 側の詳細仕様 (grouping トークナイズ規則、提案/承認フロー) は `apps/sync/src/propose-grouping.ts` と `packages/core/src/x-folder-grouping/` を参照。

---

## ファイル構成

```
pipeline/
├── index.ts              メインパイプライン（エントリポイント）
├── config.ts             設定管理（Vault Root / dry-run / ウィザード）
├── fetcher.ts            Playwright Web フェッチ
├── extractor.ts          Readability + Turndown 抽出
├── x_bookmarks_api.ts      X API v2 ラッパ (OAuth + folders/bookmarks 取得)
├── x_auth_server.ts        OAuth 2.0 PKCE 認可サーバ (--x-auth)
├── hands_on_generator.ts   X ブックマーク群 → Claude CLI でハンズオン生成
├── prompts/hands_on.md     ハンズオン生成プロンプトテンプレート
├── x_folder_mapper.ts      X フォルダ名 → Vault 階層パスの 2 層マッピング
├── x_folder_tree.ts        --x-pick 用 Tree ビルダ + ASCII レンダラ
├── x_interactive_picker.ts --x-pick 用 番号パーサ + 対話ループ
├── x_session_registry.ts   X folder ↔ Vault の session_id レジストリ (DB + marker file)
├── x_session_sync.ts       Sync Phase (X 側 / Vault 側 / .md 単位 の drift 検出と整合)
├── x_session_ai.ts         orphan_on_x の AI 判定ループ (Claude / local LLM)
├── x_bookmarks_db.ts       SQLite メタデータキャッシュ（差分同期用）+ folder_sessions
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
