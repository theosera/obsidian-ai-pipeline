# 詳細仕様

このドキュメントは [Obsidian AI Pipeline](../README.md) の詳細仕様をまとめたものです。実行コマンドのリファレンスは [実行コマンドリファレンス](cli-reference.md) を参照してください。

---

## X ブックマーク取得

X (Twitter) ブックマークを取得し、Vault 内にグループページ + Dataview テーブルとして整理します。実装は `x-bookmarks/` ディレクトリ (`api_client.ts` / `tokens.ts` / `types.ts` / `folder_*.ts` / `session_*.ts` / `summarizer.ts` / `hands_on_generator.ts` 等) にまとまっており、既存の `index.ts` / `pipeline/` / `router.ts` / `storage.ts` と統合されています。

> 過去には Codex による pnpm workspace 実装 (`apps/*` + `packages/core`) を並走させた対照実験を行っていましたが、比較目的を終えたため Codex 側実装はリポジトリから削除しました。本仕様は現行のフラット実装のみを記述します。

### エントリポイント

| 用途 | コマンド |
|---|---|
| OAuth 認可 | `pnpm start -- --x-auth` |
| ブックマーク同期 | `pnpm start -- --x-bookmarks` |
| フォルダ選択取得 | `pnpm start -- --x-pick` |
| フォルダ同期 | `pnpm start -- --x-sync-folders` |
| ハンズオン生成 | `pnpm start -- --hands-on=...` |

### 設計の要点

- **差分同期**: SQLite メタキャッシュ (`<vault>/__skills/pipeline/x_bookmarks.db`) を起点に、新規分のみ取得・整理する。
- **drift 追跡**: UUID `session_id` で X 側フォルダ ↔ Vault 階層の対応を記録し、移動・削除を検出する。
- **認可**: OAuth 2.0 PKCE 認可サーバはデフォルト port `3737` (`X_AUTH_PORT` で上書き、redirect は `http://localhost:3737/auth/callback`)。X Developer Portal で App を作成し Client ID を割り当てる。`/bookmarks` は 180/15分、folder 系は 50/15分のレート制限。
- **トークン**: `<vault>/__skills/pipeline/x_tokens.json` (機密、`.gitignore` 済)。
- **出力先**: base は `X_Bookmarks/` (`X_BOOKMARKS_FOLDER` で上書き)。
- **ユーザー設定**: `x_forced_parents.json` (強制親フォルダ) / `x_folder_mapping.json` (承認済みマッピング) で階層化を制御する。

---

## ファイル構成

```
pipeline/
├── index.ts              メインパイプライン（エントリポイント）
├── config.ts             設定管理（Vault Root / dry-run / ウィザード）
├── fetcher.ts            Playwright Web フェッチ
├── extractor.ts          Readability + Turndown 抽出
├── x-bookmarks/            X ブックマーク機能 (pipeline/ と並ぶ feature ディレクトリ)
│   ├── types.ts            X API v2 共有型 (ApiBookmark / XPost / XMedia*)
│   ├── tokens.ts           OAuth トークン永続化 + 期限判定 + refresh
│   ├── api_client.ts       X API v2 ラッパ (OAuth + folders/bookmarks 取得)
│   ├── auth_server.ts      OAuth 2.0 PKCE 認可サーバ (--x-auth)
│   ├── hands_on_generator.ts X ブックマーク群 → Claude CLI でハンズオン生成
│   ├── folder_mapper.ts    X フォルダ名 → Vault 階層パスの 2 層マッピング
│   ├── folder_tree.ts      --x-pick 用 Tree ビルダ + ASCII レンダラ
│   ├── interactive_picker.ts --x-pick 用 番号パーサ + 対話ループ
│   ├── session_registry.ts X folder ↔ Vault の session_id レジストリ (DB + marker file)
│   ├── session_sync.ts     Sync Phase (X 側 / Vault 側 / .md 単位 の drift 検出と整合)
│   ├── session_ai.ts       orphan_on_x の AI 判定ループ (Claude / local LLM)
│   ├── folder_invariant.ts フォルダ数保存則チェック
│   ├── rule_deriver.ts     vault 構造から x_forced_parents.json を自動推定
│   ├── summarizer.ts       AI 要約 (200 字日本語 / cloud・local 切替)
│   ├── json_export.ts      .x_bookmarks.json への Dataview 互換エクスポート
│   ├── group_page_writer.ts group MD の sentinel-bounded 書き換え (idempotent)
│   ├── group_page_template.ts dataviewjs テーブル付き group MD テンプレ
│   ├── migrate_legacy.ts   旧パス Clippings/X-Bookmarks/ → _Archived/ 移行
│   ├── video_frames.ts     動画キーフレーム抽出 (ffmpeg + opt-in)
│   └── db.ts               SQLite メタデータキャッシュ（差分同期用）+ folder_sessions
├── prompts/hands_on.md     ハンズオン生成プロンプトテンプレート
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
