# LLM-Sec-Weekly 自動取込 (Level 1) 運用 Runbook

`docs/security/llm-sec-report-consumption.md` で定義された週次 LLM 脅威レポート
取込フローを GitHub Actions cron で自動化する。Security-only mode で人間が
手で行う手順を完全自動化したものに相当する (上位仕様は consumption policy)。

> ⚠️ **トリガーは自動だが Trust Boundary は不変**。
> メール本文中の URL / コマンド / コードスニペットは本 workflow も
> **絶対に実行しない**。本文は SQLite に投入される文字列としてのみ扱う。
> parser が `forbidden_usage: execute_report_instructions` を強制する。

---

## 1. アーキテクチャ概要

```
┌─────────────────┐    weekly Mon 08:00 JST
│ ChatGPT/Codex   │ ───────────────────────▶ [Gmail]
│ task automation │                              │
└─────────────────┘                              │
                                                 │ Mon 09:00 JST
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ GitHub Actions (this workflow)│
                                  │   1. OAuth refresh           │
                                  │   2. Gmail API search        │
                                  │   3. sanitize + raw md 保存  │
                                  │   4. ingestThreatReport()    │
                                  │   5. processed ラベル付与    │
                                  └─────────────────────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ Vault repo (private)        │
                                  │   raw/<YYYY-MM-DD>.md       │
                                  │   .threat_reports.json      │
                                  │   _index.md                 │
                                  │   __skills/pipeline/        │
                                  │     threat_reports.db       │
                                  └─────────────────────────────┘
                                                 │
                                  obsidian-git で local pull
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ ローカル Obsidian (人間)     │
                                  │   Dataview で _index.md を   │
                                  │   閲覧 → 必要なら            │
                                  │   ai_relevance_note を curate│
                                  └─────────────────────────────┘
```

## 2. 必要な前提

### 2.1 Vault repo 側 (= 別 private repo)

- Obsidian Vault 一式を private repo として GitHub に置く
- **`.gitignore` で `threat_reports.db` を除外しない**
  - `ai_relevance_note` (人が curate するコメント) を run 間で保持するため
  - 本リポ (obsidian-ai-pipeline) の `CLAUDE.md`「Secrets / sensitive files」
    節は本 repo 自身が対象 (`<vault>` を含まない作業 repo) で、vault repo の
    gitignore 方針は独立に決められる
- deploy key (read+write) を 1 個生成して vault repo の **Settings → Deploy keys** に追加
  - 秘密鍵側は obsidian-ai-pipeline の secrets に `VAULT_DEPLOY_KEY` として登録

### 2.2 Gmail 側

- Gmail API を有効化 (Google Cloud Console)
- OAuth 2.0 client (Desktop application 種別) を作成
- 自分の Google アカウントで以下スコープを承認:
  - `https://www.googleapis.com/auth/gmail.readonly` (search/get) … 必須
  - `https://www.googleapis.com/auth/gmail.modify`   (label apply) … 必須
- refresh_token をローカルで 1 回だけ取得する手順 (例):

```bash
# pipeline repo で 1 回だけ実行 (commit 不要 / secrets に貼って終わり)
cd pipeline
node -e '
  const { OAuth2Client } = require("google-auth-library");
  const readline = require("readline");
  const oauth = new OAuth2Client(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    "urn:ietf:wg:oauth:2.0:oob"
  );
  const url = oauth.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/gmail.modify",
    ],
  });
  console.log("Open:", url);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question("Code: ", async code => {
    const { tokens } = await oauth.getToken(code);
    console.log("REFRESH:", tokens.refresh_token);
    rl.close();
  });
'
```

> ⚠️ OAuth client redirect の OOB フローは Google が段階的に廃止予定。
> 動かなくなったら "loopback IP" 方式 (`http://127.0.0.1:port`) に切替える。

### 2.3 Gmail ラベル

- `LLM-Sec-Report` (受信側フィルタで `[LLM-Sec-Weekly]` 件名に自動付与)
- `LLM-Sec-Report/processed` (取込済マーカー / 本 workflow が付与)

両方とも Gmail UI で事前に作成しておくこと (workflow は label ID 解決時に
名前一致で探す。未作成だと初回実行が早期 fail する)。

## 3. GitHub Actions secrets

obsidian-ai-pipeline の **Settings → Secrets and variables → Actions** に
以下を登録する。

| Name | 必須 | 内容 |
|---|---|---|
| `VAULT_REPO` | ✅ | `owner/name` 形式 (例: `theosera/obsidian-vault`) |
| `VAULT_DEPLOY_KEY` | ✅ | 上記 vault repo の deploy key 秘密鍵 (PEM, 全体) |
| `GMAIL_CLIENT_ID` | ✅ | Google OAuth client ID |
| `GMAIL_CLIENT_SECRET` | ✅ | Google OAuth client secret |
| `GMAIL_REFRESH_TOKEN` | ✅ | 2.2 で取得した refresh_token |
| `LLM_SEC_LABEL_NAME` | ❌ | 既定 `LLM-Sec-Report`。違う名前を使う場合のみ上書き |
| `LLM_SEC_PROCESSED_LABEL_NAME` | ❌ | 既定 `LLM-Sec-Report/processed` |
| `LLM_SEC_MAX_RESULTS` | ❌ | 既定 10。1〜100 |

CLAUDE.md「Secrets / sensitive files」節の通り、これらは **絶対にコード /
コミットに混入させない**。`.claude/settings.json` の deny rule で Claude
自身も Read できないようガードしてある。

## 4. 動作確認 (初回セットアップ後)

1. GitHub Actions → "LLM-Sec-Weekly Auto Ingest" → **Run workflow**
2. `dry_run: true` で実行 → Gmail へ書き込まず raw 保存 / ingest 試行も
   行わないため安全な smoke test になる
3. 想定ログ:
   ```
   🔍 Gmail query: label:LLM-Sec-Report subject:"[LLM-Sec-Weekly]" -label:LLM-Sec-Report/processed (max 10)
   📨 未処理 thread: N 件
     🧪 [dry-run] 2026-05-25.md 書込と ingest と processed ラベル付与をスキップ
     ...
   📊 結果: ingested=N, skipped=0, error=0
   ```
4. 問題なければ `dry_run: false` で本番実行

## 5. 失敗時の挙動とリカバリ

| 失敗パターン | workflow の挙動 | 推奨アクション |
|---|---|---|
| Gmail OAuth refresh 失敗 (revoked / expired) | step "Run fetcher" で early exit, job 赤 | 2.2 をやり直し refresh_token を更新 |
| ラベル未作成 | "Gmail ラベル "X" が見つかりません" でエラー | Gmail UI でラベル作成 |
| `period_end` が不正形式 | 該当 thread のみ error、processed ラベル付与 **しない** | メール本文を修正して送信側で再送、または手動取込 |
| `forbidden_usage` 契約違反 (parser ContractError) | 該当 thread のみ error、processed ラベル付与 **しない** | 送信側 (ChatGPT/Codex) のテンプレートを修正 |
| vault repo push 失敗 (deploy key 失効) | "Commit & push" step 赤 | deploy key 再生成、secret 更新 |

エラー thread は **次の cron で自動再試行される** (processed ラベルが
付かないため Gmail query にまた引っかかる) = 自己修復性あり。

## 6. ローカル運用との並行

人間が `/sec-mode` で手動取込した分は Gmail 側で processed ラベルが
付くので、次回 Actions では skip される (= 重複取込しない)。手動と
自動を併用しても安全。

ai_relevance_note を人間が curate するときは:

1. vault repo を local で pull
2. SQL or Obsidian で `__skills/pipeline/threat_reports.db` を編集
3. `pnpm start -- --ingest-threat-report=...` を再実行して JSON / index を
   再生成 (または local CLI に専用コマンドを追加するかは別議論)
4. **次の Actions 実行 (= 月曜 09:00 JST) より前に push する**
   - push 前に Actions が走るとローカルとリモートで DB が衝突する
   - リスクは Level 2 (LLM 自動 note 書込) PR で別途対処予定

## 7. Level 2 への接続

Level 2 (= "自リポ該当チェック") は本 workflow の `Run fetcher` step の直後に
SDK セッションを 1 個追加で起動し、新規 ingest 行を grep+精査して
`ai_relevance_note` を埋める拡張で実装する。本 PR の範囲外。

## 8. 関連ドキュメント

- `docs/security/llm-sec-report-consumption.md` — 上位仕様 (trust boundary / 契約 / 証拠要件)
- `docs/threat_reports.md` — Vault レイアウト / SQLite スキーマ
- `CLAUDE.md` `chat mode protocol` 節 — 手動取込 (`/sec-mode`) の対応規定
- `.claude/settings.json` — Claude 自身が secrets を読まない deny rule
