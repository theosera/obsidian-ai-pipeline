# YouTube Transcript Analyzer (Chrome拡張)

YouTube 動画の字幕を抽出し、Anthropic API で要約・構造化して Obsidian 用マークダウンを生成する Chrome 拡張です。

> ⚠️ **個人用途前提のツールです。配布・共有は想定していません。**

---

## ⚠️ セキュリティ上の注意: API キーの取扱について

この拡張機能は **Anthropic API を直接ブラウザから呼び出します** (`anthropic-dangerous-direct-browser-access: true`)。これは意図的な設計判断であり、以下の脅威モデルを **認識した上で** 採用しています。

### 脅威モデル (個人用途での想定)

| リスク | 該当度 | 備考 |
|---|:---:|---|
| Web ページから API キーが読まれる | ❌ なし | Service worker は page context から完全隔離 |
| 他の Chrome 拡張から読まれる | ❌ なし | `chrome.storage.local` は拡張ごとに scope が隔離 |
| ネットワーク傍受で漏洩 | ❌ なし | HTTPS (TLS) 通信 |
| **ローカルマルウェアがディスクから読む** | ⚠️ あり | `chrome.storage.local` は Chrome プロファイル配下の平文ファイル |
| **Chrome プロファイルを誤って共有** | ⚠️ あり | プロファイル書き出しやバックアップ経由で流出しうる |
| **他ユーザーにこの拡張を配布** | ❌ 想定外 | 配布ユーザーが自分のキーを入力する必要があり、↑のリスクを転嫁する |

### なぜ SDK の警告をバイパスしているのか

`@anthropic-ai/sdk` は `dangerouslyAllowBrowser: true` や同等ヘッダーを要求します。これは **通常の SPA デプロイ** (静的ファイル配信 + 不特定多数のエンドユーザー) を想定した保護で、具体的には以下を防ぐためです。

1. DevTools の Network タブで API キーが誰にでも見える
2. XSS 経由でページスクリプトからキーが盗まれる
3. キーがクライアントにハードコードされて配布される

**Chrome 拡張の Service Worker は (1) (2) に該当しません** (page context と完全に分離されているため)。(3) については、この拡張はストアに公開しておらず、ユーザー自身が `chrome.storage.local` に手動入力する設計です。

### 採用条件 (自己責任)

この拡張を使う場合、以下を理解・承諾していることが前提です。

- ✅ **信頼できるマシン** でのみ使用する (マルウェア感染のない個人 PC)
- ✅ **Chrome プロファイルを他人と共有しない**
- ✅ **この拡張を他人に配布しない** (配布する場合は API キーをハードコードせず、受け手が自前で入力する旨を明記すること)
- ✅ API キーが漏洩した疑いがある場合は **即座に Anthropic コンソールで revoke** する

### 将来的な緩和策 (現状は採用せず)

- **バックエンドプロキシ**: 自前のサーバーで API キーを保持し、拡張からプロキシを叩く。個人ツールには過剰。
- **OAuth**: Anthropic は現時点で提供していない
- **起動ごとの入力**: 毎回入力を要求することで永続化を避ける。UX が著しく悪化する
- **OS キーチェーン連携**: Chrome 拡張からは直接アクセスできない

---

## セットアップ

```bash
cd chrome-extension
pnpm install
pnpm build
```

`dist/` ができたら Chrome で以下を実行:

1. `chrome://extensions/` を開く
2. 「デベロッパーモード」を有効化
3. 「パッケージ化されていない拡張機能を読み込む」→ `dist/` を選択
4. 拡張機能アイコンを右クリック → 「オプション」で API キー (`sk-ant-...`) を入力

## 使い方

YouTube 動画ページで拡張機能アイコンをクリック → 「分析」ボタンで実行 → 生成されたマークダウンをダウンロードまたはコピー。

## アーキテクチャ

```text
src/
├── background/
│   ├── service-worker.ts    Message routing, orchestration
│   ├── ai-client.ts         Anthropic REST API (fetch)
│   └── markdown-generator.ts
├── content/
│   ├── content-script.ts    Video ページで動作
│   ├── video-metadata.ts    og: tags / LD+JSON / DOM fallback
│   └── transcript-extractor.ts
├── popup/                   Browser action UI
├── options/                 Settings page (API キー入力)
└── shared/
    ├── config.ts            chrome.storage.local ラッパー
    ├── constants.ts         エンドポイント・モデル ID
    ├── prompts/             system prompt & user prompt
    ├── frontmatter.ts       Obsidian 用 YAML 生成
    ├── sanitize.ts          制御文字除去
    └── types.ts
```
