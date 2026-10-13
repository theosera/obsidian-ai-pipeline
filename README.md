# Obsidian AI Pipeline

> **⚠️ 注意: 個人用ワークフローツール**
> このリポジトリは私自身の Obsidian Vault 構造に特化した個人用自動化ツールです。**汎用の OSS プロダクトとして設計されていません。**
> AI 駆動の自律型ファイル分類パイプラインの設計リファレンスとして公開しています。

OneTab からエクスポートした URL リストを読み込み、Web ページを自動取得・抽出・AI 分類して Obsidian Vault へ保存する自動化パイプラインです。

---

## ドキュメント

| ドキュメント | 内容 |
|---|---|
| 本 README | 導入・アーキテクチャ・主要機能・環境要件・セットアップ・基本実行コマンド |
| [docs/cli-reference.md](docs/cli-reference.md) | 実行コマンドリファレンス（フォルダルール同期 / X ブックマーク取り込み / ハンズオン生成 / 中断再開 / ナレッジ統合 / 対話型レビュー） |
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | 詳細仕様（X ブックマーク取得 / ファイル構成） |
| [docs/tool-use.md](docs/tool-use.md) | Tool Use (Function Calling) 実行レイヤー（最小権限 / Vault サンドボックス / Human-in-the-Loop 承認） |
| [docs/security/git-command-guards.md](docs/security/git-command-guards.md) | Claude Code の Bash / Git ガード（許可する形式・fail-closed の範囲・拒否されたときの書換え） |

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
  - Claude Code の Bash / Git ガード: shell の引用・escape と実行 source を解析し、対応済み条件の充足、禁止操作の確認、判断不能を区別する。後二者は停止し、理由を `[禁止]` / `[判断不能]` と示す。対象や実行条件を確定できない変数・glob による add や設定を差し替えた Git も fail-closed とする（対応範囲、代替、owner 確認、試験3層: [Git ガード](docs/security/git-command-guards.md)）
    - 通常の release tag 作成・削除・署名・検証、notes 更新、stash push / pop や管理も、検査範囲外の object / ref / working state 操作として `[判断不能]` で停止する。commit `-F` / `-t` と merge `-F` の source、commit 前の grep pager、curl の query file 入力にも制限がある。対応する query / literal DATA と、同目的の writer 代替がない場合の owner 確認は上記ガイドを参照する。
    - R12 では、既定の editor も含め、未検査の editor が起動し得る Git 操作を `[判断不能]` で停止する。普通の merge も実際の `--no-edit` と確定 argv が必要となる。commit の対応 `-m` / `-F` / `-C`、実 `--no-edit` / dry-run 等は editor を起動しない条件だけの対照であり、index・message source 等の別条件も満たす必要がある。実行名の glob / brace / tilde、mapfile / readarray の実 `-C` callback、Bash の実 `/dev/tcp` / `/dev/udp` redirection、remote rsync の明示 remote-shell helper は同じく停止する。一方、literal の FD 複製・close と正確な `/dev/null` 出力は、index を書き換える redirection と区別する。通常作業への影響と同目的の代替条件は上記ガイドに記載する。
    - R13 では、実 coproc、未確定の動的実行名、hash-object の全 object 書込み、active difftool を `[判断不能]` で停止する。xargs 等から curl / wget / gh へ渡る未知 argv、curl の未確定 option / URL と追加 argv、rsync / scp の未確定な宛先・引数個数も同じ扱いになる。curl の実 cookie file 入力は、確定した対応条件では `[禁止]`。commit に関わる Git の `-c` / `--config-env` は、対応する表示・identity key と実 stdout usage 等の条件を満たす必要がある。通常の array executable・公開 object 作成・difftool・生成 query 等にも影響するため、同目的の対応形式がなければ対象と実行条件を owner に確認する。
    - R14 では、呼び出した shell 関数の本文を検査し、未検査の shell stdin / script file / dot・source、確定しない eval source、child Bash の BASH_ENV、Git / SSH / SCP / SFTP / remote-shell rsync / Wget が選ぶ認証・接続 helper を `[判断不能]` で停止する。curl は実 first literal 引数の正確な `-q` / `--disable`、Wget は実 `--no-config` で既定設定を無効化した対応 argv が必要となり、通常の GET・download・help / version にも影響する。使われない関数定義や印字 DATA、確認した local query / local copy を区別し、既存の Git context / 関数 shadow 条件は維持する。R14 の凍結 source は直接入力3498件と解析33件で確認し、CLI実入口は8試行中6件で確認、2件はBash前に停止したため未実施とする。過去 round の結果は持ち越さない。対応条件と代替・owner 確認は上記ガイドを参照する。
    - R15 では、interactive shell の ENV、child が選ぶ imported / exported function（`set -a` 等の自動 export を含む）、単独 Git 操作の active 外部 helper を `[判断不能]` で停止する。未使用の既知関数や、external diff を呼ばない通常の log の DATA は区別する。GNU timeout / nice / stdbuf は実 option の値・duration / buffering mode・child を分け、未知 / 省略形 option は停止する。共通 gh payload 分類は Release upload / create asset と edit notes file と Issue 本文 file / stdin を扱い、公開 artifact も既存の file-upload 禁止に含む。SSH `-n` でも remote command の展開結果を検査し、Git push option の DATA も named remote / ref / index と別に検査する。対応する source・argv・context で secret filename 読取が payload に結び付けば `[禁止]`、source や送信先を確定できなければ `[判断不能]` となる。Vault wrapper の filename predicate と NUL 読取も同期し、通常の LF を含む filename は判断不能で停止する。代替と通常作業への影響は上記ガイドに記載する。R14 の数値は履歴であり、R15 の全 suite / CLI 実入口 / CI の結果には持ち越さない。
    - R16ではGH本文 / notes / titleの生成値もSSH / push-optionと共通に追跡する。quoted scalarの語数確認と、送信値の生成元の確認は分ける。関連secret readerは禁止、未追跡の生成値 / selectorは判断不能、対応literal / exact scalar proofは許可。通常影響と出口はガイドのR16節へ記載する。
    - R18では、Git の no-verify 判定に対応する既知の単一語の値も使う。実 option と確認した hook 回避は禁止し、未知の argv が hook 回避 option を選び得る場合や、消費値が複数 argv に展開し得る場合は判断不能で止める。通常の `git push origin "$REF"` も、REF の意味を確認できなければ影響を受ける。実 `--` と対応 option の単一語 DATA は区別するが、未解決の短い attached `-o"$VALUE"` は空値で境界が変わり得るため停止する。config / branch / remote / add / stage の未知値は、既存の設定・action・path の担当で扱い、この境界だけでは新しく一律停止しない。同じ対象・条件を保てる literal / 値の証明を検討し、対応形式にできない場合は owner へ確認する。全 push の一括禁止ではなく、他の source / cwd / env / config 条件も残る。測定・代替の詳細は上記ガイドのR18節を参照する。
  - security-guidance プラグイン（公式）: Claude Code が書くコードを編集時 / ターン終了時 / commit 時の 3 層で自動セキュリティレビュー。`.claude/claude-security-guidance.md` で本リポの脅威モデルをレビュー観点に注入（詳細・既存防御との棲み分け: `docs/security/security-guidance-plugin.md`）
- **dry-run モード**: `--dry-run` は Vault へ一切書き込まない（分類レポート・失敗ログは Vault 外の一時ディレクトリへ出力し、スナップショット / `folder_rules.json` 昇格の永続化も抑止）。実行前後で Vault ツリーが不変であることをテストで保証
- **Vault Root 外部化**: `pipeline_config.json` または環境変数 `VAULT_ROOT` で設定、ハードコードなし
- **中断リカバリ**: `pnpm start -- --rescue <レポート>.md` でレポートファイルから API コスト $0 で保存を再開（`rescue-from-report.ts` / `--dry-run` 併用可）
- **週次 LLM 脅威レポート取込・該当性レビュー** (`/sec-mode` → `/sec-review`): Gmail 取込 + injection ゲート + DB 取込 → 本リポ該当性レビュー（詳細フローは `docs/security/` / `docs/threat_reports.md`）

---

## 環境要件

| ツール | バージョン |
|---|---|
| Node.js | v24.15+（24.x）または v26+（v25 は非対応: jsdom の engines に合わせる） |
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

基本的な実行コマンドを以下に示します。応用的なコマンド（フォルダルール同期 / X ブックマーク取り込み / ハンズオン生成 / 中断再開 / ナレッジ統合 / 対話型レビュー）は [実行コマンドリファレンス](docs/cli-reference.md) を参照してください。

### 初回設定ウィザード

```bash
pnpm start -- --config
```

プロバイダー（`local` / `anthropic` / `openai` / `gemini`）、Vault Root パス、使用モデルを対話形式で設定。
設定は `pipeline_config.json` に保存され、次回以降はスキップされます。

### 通常実行

```bash
pnpm start ../context/_分析コンテキスト/OneTab_YYYYMMDD.txt
```

実行前に処理件数・レポート出力先を表示し `[y/n]` で確認します。分類完了後は `context/分類結果レポート/` にレポートが生成されるので、**Obsidian でレポート内容を確認してから** `[y/e/q]` で承認・修正・キャンセルを選択してください。

### dry-run（ファイル書き込みなし）

```bash
pnpm start ../context/_分析コンテキスト/OneTab_YYYYMMDD.txt --dry-run
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

> **X (Twitter) ブックマーク取り込みは OAuth 2.0 PKCE ベースです**。`X_CLIENT_ID` / `X_CLIENT_SECRET` を `.env` に設定し、`pnpm start -- --x-auth` で初回認可してください。詳細は [実行コマンドリファレンス](docs/cli-reference.md) の「X (Twitter) ブックマークの取り込み」節を参照。

---

## 再利用について

パスや分類ルールが私の Vault 構造にハードコードされている箇所があります。
別環境で使う場合は `pipeline_config.json` の `vaultRoot` と `folder_rules.json` を調整してください。
AI プロンプト設計・Playwright フェッチロジック・TypeScript 構造のリファレンスとして自由に参照ください。

---

## 関連リポジトリ

- **[obsidian-ai-pipeline](https://github.com/theosera/obsidian-ai-pipeline)** — パイプライン単体の公開リポジトリ（設計リファレンス）
- **obsidian-vault-skills** (private) — Vault 全体の管理リポジトリ（本ファイルが含まれる）
