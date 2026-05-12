# Obsidian AI Pipeline

> **⚠️ 注意: 個人用ワークフローツール**
> このリポジトリは私自身の Obsidian Vault 構造に特化した個人用自動化ツールです。**汎用の OSS プロダクトとして設計されていません。**
> AI 駆動の自律型ファイル分類パイプラインの設計リファレンスとして公開しています。

OneTab からエクスポートした URL リストを読み込み、Web ページを自動取得・抽出・AI 分類して Obsidian Vault へ保存する自動化パイプラインです。

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

### X (Twitter) ブックマークの取り込み（X API v2 + OAuth 2.0 PKCE）

X API v2 はフォルダ一覧・フォルダ内ポストの公式エンドポイントを持ちます。本パイプラインは **OAuth 2.0 Authorization Code Flow with PKCE** でユーザー認可トークンを取得し、以下のエンドポイントから取得します:

- `GET /2/users/:id/bookmarks` — 全ブックマーク
- `GET /2/users/:id/bookmarks/folders` — フォルダ一覧
- `GET /2/users/:id/bookmarks/folders/:folder_id` — フォルダ内ポスト

**機能**:

- **フォルダ構造保持**: X 側のブックマークフォルダ階層を Vault 側に反映
- **保存先**: `<vault>/X_Bookmarks/<X側フォルダ名>/`（環境変数 `X_BOOKMARKS_FOLDER` で上書き可。旧 `Clippings/X-Bookmarks/` から移行する場合は `pnpm start -- --x-migrate-legacy`）
- **1 グループ 1 MD + テーブルビュー**: 1 ツイート 1 MD ではなく、各グループフォルダに 1 枚の `<group>.md` を置き、`<vault>/X_Bookmarks/.x_bookmarks.json` を Dataview の `dv.io.load()` で読み込んでテーブル描画する。**Dataview コミュニティプラグインがインストール済みであること**を前提とする
- **AI 要約列 (`ai_summary`)**: テーブルの `summary` 列は `x_bookmarks_summarizer.ts` が SQLite `bookmarks.ai_summary` を埋めることで populate される。**1 行 200 グラフェム以内・日本語・改行なし** の制約 (`truncateSummary` で ZWJ 絵文字・サロゲートペアを割らずに切詰)。`ai_summary IS NULL` の行のみ対象 (既存要約は不変)。失敗行は NULL のまま残り次回 sync で自動再挑戦
- **要約 provider / model は分類フェーズと独立** (`pipeline_config.json::xSummary`): 初回 `--x-bookmarks` 実行時に対話ウィザードが起動し、cloud / Anthropic Haiku 4.5 (推奨デフォルト) / OpenAI gpt-4o-mini / Gemini 2.5 Flash / local LM Studio から選択。永続化された設定の再選択は `--x-summary-reconfig`、全件再生成 (モデル変更後の reflow) は `--x-resummarize-all`
- **実行モード自動切替**: provider=local なら **batch** モード (10 件 = 1 プロンプトの順次)、cloud なら **inline** モード (1 件 = 1 呼出の 3 並列)。Local の単発推論オーバーヘッドと cloud の長文 hallucination リスクを両方避ける設計
- **強制親フォルダ機能**: `<vault>/__skills/pipeline/x_forced_parents.json` に登録したキーワードを「単語境界マッチ」で含む X フォルダは、自動的に親フォルダ配下に階層化される。`pnpm start -- --x-derive-rules` で現在の vault 構造から自動推定可能 (.bak を残して提案 diff を出力)
- **共通キーワード自動検出**: 3 つ以上のフォルダに共通する単語を検出し、`<vault>/__skills/context/分類結果レポート/x_folder_grouping_proposal_YYYYMMDD.md` に提案レポートを出力
- **SQLite メタデータキャッシュ** (`<vault>/__skills/pipeline/x_bookmarks.db`): 取得済みツイートID で差分同期（既知ツイート 3 件連続でページング打ち切り・API コール節約）。`.x_bookmarks.json` は SQLite から再生成される派生ファイル
- **フォルダ数保存則**: X 側 distinct フォルダ数 == `X_Bookmarks/` 直下のリーフ数 (集約解除時)。sync 末尾でアサーション、不一致は警告
- **Classifier をスキップ**: 短いツイート本文に AI 分類は不経済なため固定ルーティング

#### 初回セットアップ (OAuth 認証)

1. **X Developer Portal** で OAuth 2.0 App を作成し、以下を控える:
   - Client ID
   - Client Secret（Confidential Client の場合）
   - Redirect URI: `http://localhost:3737/auth/callback`
2. `.env` に設定:
   ```bash
   X_CLIENT_ID=...
   X_CLIENT_SECRET=...
   X_REDIRECT_URI=http://localhost:3737/auth/callback
   X_AUTH_PORT=3737
   ```
3. 認可フロー起動:
   ```bash
   pnpm start -- --x-auth
   ```
   ブラウザで X の認可画面が開くので許可 → `<vault>/__skills/pipeline/x_tokens.json` にトークンが保存される（`scope: tweet.read users.read bookmark.read offline.access`）。以降は refresh_token で自動更新されるため再認証不要。

**レート制限**（pay-per-use 枠）:
- `/bookmarks` — 180 req / 15分
- `/bookmarks/folders`, `/bookmarks/folders/{id}` — 各 50 req / 15分
- 同一 UTC 日内の同 Post の再取得は dedup されて課金対象外

**コスト配慮**: pay-per-use なので毎回全件フェッチせず、DB キャッシュで差分同期する設計。

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
| `Claude Code` | `X_Bookmarks/Claude Code/` |
| `Claude Code Tips` | `X_Bookmarks/Claude Code/Tips/` |
| `Claude Code Hooks` | `X_Bookmarks/Claude Code/Hooks/` |
| `Obsidian Plugins` | `X_Bookmarks/Obsidian/Plugins/` |
| `MCP連携` | `X_Bookmarks/MCP/連携/` |
| `LangChain` | `X_Bookmarks/LangChain/`（マッチなし） |

部分一致は禁止（`AI` キーワードは `AIRI` にマッチしない）。複数キーワードが同時マッチする場合は**より長いキーワードを優先**します。

#### 共通キーワード提案の運用

- **保存先**: `X_Bookmarks/`（既存記事とは完全に別系統）
  - ※この節は既存パイプラインの `--x-bookmarks` モードについての説明です。workspace 版（`apps/sync`）の既定値は `Clippings/X-Bookmarks-codex` です。
  - 環境変数 `X_BOOKMARKS_FOLDER` で上書き可能
  - Router の日付昇格ルール（QUARTERLY=10 / MONTHLY=20）に従い、件数が増えると `X_Bookmarks/Claude Code/2026-Q2` のようなサブフォルダへ自動再編成
- **Classifier を通さない**: 短いツイート本文に対する AI 分類は不経済かつノイズ源になるため、固定ルーティング
- **重複排除**: 既存 URL と同じツイートは `knownUrls` により自動スキップ

1. **強制親に昇格**: `x_forced_parents.json` にキーワードを追加 → 次回以降のスクレイプで自動階層化
2. **個別マッピング**: `<vault>/__skills/pipeline/x_folder_mapping.json` に明示マップを追記
   ```jsonc
   { "AI Tools": "AI/Tools", "AI Ethics": "AI/Ethics" }
   ```

#### 実行コマンド

```bash
# 初回認証（ブラウザで X の認可）
pnpm start -- --x-auth

# 全件取得（差分同期: DB 既知ツイートをスキップ）
pnpm start -- --x-bookmarks

# 件数制限 + dry-run（書き込みなし）
pnpm start -- --x-bookmarks --x-limit=20 --dry-run

# Stage 1 でフォルダ一覧を表示 → 対話選択 → Stage 2 で本文取得
pnpm start -- --x-pick
pnpm start -- --x-pick --x-limit=10 --dry-run

# vault フォルダ構造から x_forced_parents.json を自動推定 (.bak を残して y/N 確認)
pnpm start -- --x-derive-rules

# 旧 Clippings/X-Bookmarks/ を _Archived/ に退避 (新パス X_Bookmarks/ への一度きり移行)
pnpm start -- --x-migrate-legacy
```

#### `--x-pick`（フォルダ対話選択モード）

`--x-bookmarks` が「全フォルダ自動」なのに対し、`--x-pick` は **2 段階フロー**で取得対象を絞り込めます。`--x-bookmarks` を含意するので併記不要です。

**Stage 1 (フォルダ一覧表示・低コスト)**:

`/2/users/:id/bookmarks/folders` のみ叩いて、X 側のフラットなフォルダ群を **2 階層 Tree** に再構築して表示します。`/bookmarks/folders/:id` (本文取得) は走らないので Stage 1 のコストは小さい。

Tree 構築ルール（[x_folder_tree.ts](x_folder_tree.ts)）:

| Tier | グルーピング条件 | 例 |
|---|---|---|
| 1 (forced) | `x_forced_parents.json` のキーワードに単語境界マッチ | `Claude Code Tips` → 親 `Claude Code` |
| 2 (approved) | `x_folder_mapping.json` の親パス先頭セグメント | `AI Tools` (`AI/Tools`) → 親 `AI` |
| 3 (dynamic) | 残ったフォルダから 3 件以上の共通キーワードを自動検出 | `Foo Tools/Foo Ethics/Foo Agents` → 親 `Foo` |
| 4 (orphan) | どの親にも入らないフォルダを `(その他)` でまとめ | `LangChain` |
| 5 (unfiled) | X 側のどのフォルダにも未割当のブックマーク（仮想） | `_Unfiled` |

表示例:

```text
🔖 X ブックマークフォルダ (合計 8 フォルダ)

[1] Claude Code  (強制親, 3)
    ├─ [1.1] Claude Code
    ├─ [1.2] Claude Code Tips
    └─ [1.3] Claude Code Hooks

[2] Foo  (動的検出, 3)
    ├─ [2.1] Foo Tools  (= Foo/Tools)
    ├─ [2.2] Foo Ethics (= Foo/Ethics)
    └─ [2.3] Foo Agents (= Foo/Agents)

[3] (その他)  (未グルーピング, 1)
    └─ [3.1] LangChain

[4] _Unfiled  (フォルダ未割当)
```

**Stage 2 (選択 → 本文取得)**:

| 入力 | 動作 |
|---|---|
| `1` | グループ [1] 配下の全サブフォルダ |
| `1.2` | サブフォルダ [1.2] のみ |
| `1, 3.1, 4` | 複合指定（カンマ区切り） |
| `1-3` | グループ範囲指定 |
| `all` | 全フォルダ + Unfiled |
| `q` | 中止 |

選択後は `/2/users/:id/bookmarks/folders/:id` を選んだフォルダだけ叩きます。Unfiled が選ばれていない場合は `/2/users/:id/bookmarks` のコールも省略するので **Pay-per-use コストを最小化**できます。

> 動作確認の典型フロー:
> 1. `pnpm start -- --x-pick --x-limit=10 --dry-run` で Tree を確認しつつ書き込みは止める
> 2. 想定したフォルダだけ拾えていることを確認
> 3. `--dry-run` を外して本番取得

#### Folder Session 追跡 (Sync Phase)

各 X ブックマークコマンド (`--x-pick` / `--x-bookmarks`) の先頭で **Sync Phase** が走ります（`--no-sync` で抑止可）。X 側 folder ID と Vault フォルダ実体を **永続 session_id** で紐付けて、X 側の rename / 削除 / Vault 側の再編に追従します。

**3 層で session_id を保持**（[x_session_registry.ts](x_session_registry.ts)）:

| 層 | 場所 | 役割 |
|---|---|---|
| 1 | SQLite `folder_sessions` テーブル | canonical (source of truth) |
| 2 | 各 Vault フォルダの `_session.json` | Vault 移動追跡 (Obsidian で動かしても紐付け保持) |
| 3 | `.md` frontmatter `session_id:` | ファイル単位の出自追跡 (個別 .md 移動の検知) |

X ブックマーク .md は以下のような frontmatter を持つ:

```yaml
---
title: "Foo Bar (@foo): tweet body..."
source: "https://x.com/foo/status/12345"
created: 2026-05-08
tags:
  - "clippings"
session_id: "7a3f2b18-9c4e-4d1a-b7e6-3f2a8d6e9b12"
x_folder_id: "1789012345"
x_tweet_id: "12345"
x_folder_name: "Claude Code/Tips"
---
```

`session_id` は当該 .md が属する X folder session の UUID。Obsidian で別フォルダにドラッグしても、次回 sync で frontmatter を読んで「移動された」ことが検知され、新親フォルダの session に再 bind される。

**Sync Phase の動作**（[x_session_sync.ts](x_session_sync.ts)）:

```
1. <vault>/Clippings/X-Bookmarks-claude/ を再帰走査して全 _session.json を収集
2. /2/users/:id/bookmarks/folders で X 側 folder ID を全列挙
3. 4 軸の drift を検出:
   ├─ X 側に新規 folder       → UUID 発行 + DB row + marker 作成
   ├─ X 側で folder 削除      → orphan_on_x → AI 判定ループへ
   ├─ Vault フォルダ移動      → DB.vault_path を新パスに更新
   └─ .md ファイル移動        → frontmatter session_id ≠ 親 marker session_id
                                 → bookmarks 行と .md frontmatter を再 bind
4. 親フォルダ決定は「**出現頻度多いキーワード優先**」(Tier 1 + Tier 3)
```

**X 側でフォルダを削除した場合 (orphan_on_x)**: AI が状況を判断して推奨を出します。

```
⚠️  X 側で削除されたフォルダを検出: "OldProject"
   session_id: 7a3f...
   Vault: Clippings/X-Bookmarks-claude/OldProject
   配下 .md: 30 件 / 最新更新: 2026-04-22T03:14:00.000Z
🤖 AI 判定中...
   AI 推奨: 保持
   理由: 30 日以内に新しい .md が追加されており参照価値が高い。
操作を選択 ([k]eep 推奨) [k=保持 / a=アーカイブ / s=スキップ次回再判定]:
```

| 入力 | 動作 |
|---|---|
| `k` (Enter) | 保持。`status=orphaned_on_x` をマークするだけで Vault は無傷 |
| `a` | `_archived/{session_id}/` へ退避。`status=archived` |
| `s` | スキップ。次回 sync で再判定 |

AI バックエンドは Claude Code CLI (デフォルト) または環境変数で差し替え:

```bash
export X_SESSION_AI_BIN=/path/to/local-llm-cli   # local LLM 使用
export X_SESSION_AI_DISABLE=true                  # AI を呼ばずに常に "keep" 推奨
```

**手動 Sync 実行**: `pnpm start -- --x-sync-folders`（Vault を再編した直後など）

**Sync をスキップ**: `pnpm start -- --x-pick --no-sync`（cron で速度優先したい場合）

> ツイートは `x.com` ドメインですが、`--x-bookmarks` モードでは `evaluatePolicy` の `manual_skip` を**意図的にバイパス**します。
> access_token が期限切れの場合は refresh_token で自動更新されます。refresh_token も失効した場合は `--x-auth` で再認証してください。

#### 動画キーフレーム抽出 (opt-in)

ツイートに動画 (video / animated_gif) が埋め込まれている場合、`X_VIDEO_FRAMES=true` で起動すると ffmpeg で等間隔キーフレームを 4 枚抽出し、`.md` 末尾に `## キーフレーム` セクションとして埋め込みます。

```bash
# 前提: ffmpeg がインストールされていること
ffmpeg -version

# opt-in で動画フレーム抽出を有効化
X_VIDEO_FRAMES=true pnpm start -- --x-bookmarks --x-limit=10
```

挙動:

- **保存先**: `<vault>/_attachments/x-bookmarks/<post_id>/frame-{NN}.webp` (idempotent — 既に存在すれば再生成しない)
- **動画長**: 60 秒超は skip (要点把握目的のため)
- **ファイルサイズ**: 30MB 超は skip
- **抽出方式**: Tier 0 等間隔サンプル (動画長を 5 等分し 1/5, 2/5, 3/5, 4/5 の地点)
- **失敗時**: `## キーフレーム 取得失敗 (理由)` を本文に出力し、本文保存は継続
- **ffmpeg 不在時**: skip 警告のみ。本文は通常通り保存される
- **OFF時**: 本セクションは生成されず、従来挙動と同等

機能フラグなので、まず `--x-limit=5` で挙動確認することを推奨します。

### X ブックマーク群からハンズオン生成（Claude Code OAuth）

Vault に蓄積した X ブックマーク群を素材に、Claude Code CLI (OAuth サブスク枠) でハンズオン .md を生成します。API キー課金不要。

前提:
- ローカルに [Claude Code](https://claude.ai/code) CLI がインストール済み & OAuth 認証済み (`claude --version` が通る)
- 対象フォルダが既に `--x-bookmarks` 実行によって Vault + DB に投入済み

```bash
# Claude Code フォルダのポスト群からハンズオン生成
pnpm start -- --hands-on="X_Bookmarks/Claude Code"

# 期間絞り込み
pnpm start -- --hands-on="X_Bookmarks/Claude Code" --since=2026-04-01

# dry-run: プロンプトのみ .prompt.txt に出力（claude を呼ばない）
pnpm start -- --hands-on="X_Bookmarks/Claude Code" --dry-run
```

生成先: `<vault>/Permanent Note/09_X_Bookmarks/<folder>-YYYYMMDD.md`

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

> **X (Twitter) ブックマーク取り込みは OAuth 2.0 PKCE ベースです**。`X_CLIENT_ID` / `X_CLIENT_SECRET` を `.env` に設定し、`pnpm start -- --x-auth` で初回認可してください。詳細は上記 [X (Twitter) ブックマークの取り込み](#x-twitter-ブックマークの取り込みx-api-v2--oauth-20-pkce) を参照。

---

## 再利用について

パスや分類ルールが私の Vault 構造にハードコードされている箇所があります。
別環境で使う場合は `pipeline_config.json` の `vaultRoot` と `folder_rules.json` を調整してください。
AI プロンプト設計・Playwright フェッチロジック・TypeScript 構造のリファレンスとして自由に参照ください。

---

## 関連リポジトリ

- **[obsidian-ai-pipeline](https://github.com/theosera/obsidian-ai-pipeline)** — パイプライン単体の公開リポジトリ（設計リファレンス）
- **obsidian-vault-skills** (private) — Vault 全体の管理リポジトリ（本ファイルが含まれる）

