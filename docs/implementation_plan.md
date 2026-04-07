# 目的
Obsidian Web Clipperの動作を再現し、OneTabからのURLリストを元に完全なMarkdown記事としてVaultへ保存する自動化パイプラインの構築。

## User Review Required
> [!IMPORTANT]
> - **言語選定**: 過去ログではPythonとNode.jsの両案がありましたが、Obsidian Web Clipperと同等の抽出（Readability + Turndown）を忠実に再現しやすく、非同期処理に強い **Node.js (JavaScript/TypeScript)** での実装を提案します。
> - **APIキー**: Claudeによる分類フォールバックを利用する場合、`ANTHROPIC_API_KEY` の環境変数設定が必要です。APIキーのご準備は可能でしょうか？
> - **Playwrightのブラウザ**: 初回実行時にChromium等のブラウザバイナリのダウンロードが発生します。Macへのインストールを進めてよろしいでしょうか？
> - **作業ディレクトリ**: ご指定の `__skills` 配下に新しく `pipeline` というディレクトリを作成し、そこにコードをまとめる形でよろしいでしょうか？ (例: `__skills/pipeline/package.json`)

## Proposed Changes

作業ディレクトリ: `/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026/__skills/pipeline`

### [NEW] package.json
必要なライブラリ：
- `playwright`: ページフェッチ、SPAレンダリング用
- `@mozilla/readability`: 本文抽出
- `jsdom`: Readability用のDOM構築
- `turndown`: HTML -> Markdown変換
- `@anthropic-ai/sdk`: 分類ロジック用API

### [NEW] index.js 
CLIのエントリーポイント。OneTab.txtの読み込みとパースを行う。

### [NEW] fetcher.js
Playwrightを制御し、指定されたURLからレンダリング後のHTMLを取得する。将来的な認証状態(`storageState`)の読み込みもサポートできる構造にする。

### [NEW] extractor.js
JSDOMを用いてHTMLをパースし、不要な要素（広告、ナビゲーション）をクレンジングしたのち、Readabilityで主記事を抽出。最後にTurndownでMarkdownへ変換する。

### [NEW] classifier.js
第一段階としてURLやタイトルからルールベース（ハードコードされたロジック）で分類先Vaultディレクトリを決定。判定が難しいもののみ、Claude APIをコールして判断する。

### [NEW] storage.js
 Vaultの適切な場所（YYYY-MMやYYYY-Qn）にフロントマター付きのMarkdownファイルを保存する。

## Verification Plan

### Automated Tests
- サンプルの OneTab.txt (3〜5 URL程度) を用意して実行する。
- `zenn.dev` (SPA), `gihyo.jp` (静的), `x.com` (自動除外対象) などを混ぜて動作分岐を確認。

### Manual Verification
- 実際にVaultの該当ディレクトリにフロントマター付きの完全な `.md` ファイルが生成されているかを確認する。
- 本文がWeb Clipper使用時と同等程度に正しく抽出されているか確認する。
