# 💻 Obsidian Web Clipper パイプライン コマンド一覧

このドキュメントでは、本パイプラインで利用する実行コマンドや、操作時のインタラクティブ・コマンドについてまとめています。

## 1. ターミナル実行コマンド
ターミナル上で処理本体（`__skills/pipeline` ディレクトリ）に移動してから実行するコマンドです。

### 通常実行
OneTabからエクスポートしたURLリストを読み込み、記事のフェッチからAIによる分類までを自動で実行します。
```bash
node index.js <処理したいOneTab.txtのパス>

# （例）
node index.js ../context/OneTab.txt
```

### 設定ウィザードの呼び出し（`--config`）
AIプロバイダー（Local, Anthropic, OpenAI, Gemini 等）や、Step1(軽量モデル)・Step2(高性能モデル)で使用するモデルの構成設定ウィザードを立ち上げます。
※二回目以降はこの設定が自動で保持されますが、使いたいAIを変えたい時に使用します。
```bash
node index.js ../context/OneTab.txt --config
```

### プロセス中断時の一括復旧・取得スクリプト (Rescue Command)
`node index.js` が中断したりタイムアウトで終わってしまった場合でも、既に生成された「分類結果レポート（マークダウン）」さえあれば、AI推論をスキップ（API課金ゼロ）して高速に記事取得と保存を再開できます。
```bash
node rescue-from-report.js <分類結果レポートのパス>

# （例）
node rescue-from-report.js "reports/OneTab分類結果レポート-20260402.md"
```

### 複数記事のナレッジ統合・軽量化（マージ機能）
指定したVaultフォルダ内に溜まった複数のマークダウン記事を、高性能AI（Sonnet等）が読み込み、コードや著者の苦労などの文脈を残したまま「1つのハンズオン・知見ガイド」に圧縮します。
```bash
node merge-articles.js "対象フォルダの絶対/相対パス"

# （例）
node merge-articles.js "../Engineer/AGENT_Development_Kit/2026-Q1"
```

---

## 2. 対話インタフェース中のコマンド (CLI メニュー)
`node index.js` の分析フェーズが完了し、レポート（マークダウン形式）が `reports/` 下に生成されると、以下のプロンプトが表示されユーザー指示待ちになります。
\`Command [y/e/q]:\`

ここで使用できる操作キーは以下の通りです：

* `y` **(Approve: 承認と保存)**
  生成されたレポートの分類結果をすべて了承し、抽出したMarkdownファイル本文をObsidianのVault内へ正式に作成・保存します。
* `e` **(Edit: パスの個別修正)**
  AIの提案した分類先を部分的に上書き修正します。押下後、「直したい記事のID番号」と「新しいVault上のフォルダパス」を直接入力することで、ファイルの保存先ピンポイントで書き換えることができます。
* `q` **(Quit: キャンセルと終了)**
  安全にプロセスの中断・破棄を行います。ここで終了すればVaultの内部へは一切のファイルが作成されません（自動生成されたレポートのみが確認用として一時フォルダに残ります）。

---

## 3. 環境・インフラ関連コマンド

### APIキーの設定（環境変数）
設定ウィザードで各APIプロバイダーを指定した場合、ターミナルに対してシステム環境変数として対応するAPIキーをエクスポートしておく必要があります。
*(※毎回入力するのが手間な場合は `~/.zshrc` 等への追記を推奨します)*

```bash
# Anthropic (Claude) を選択した場合
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI (ChatGPT) を選択した場合
export OPENAI_API_KEY="sk-proj-..."

# Google Gemini を選択した場合
export GEMINI_API_KEY="AIza..."
```

### ヘッドレスブラウザ層の修復
何らかの環境変化により `Executable doesn't exist` などのエラーが発生し、HTML取得用ブラウザ(Playwright)が起動できなくなった場合の修復コマンドです。（※本プロジェクトディレクトリ直下で実行）

```bash
pnpm exec playwright install chromium
```
