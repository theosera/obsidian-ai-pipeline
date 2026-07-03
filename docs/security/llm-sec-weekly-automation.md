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

```text
┌─────────────────┐    weekly Mon 08:00 JST
│ ChatGPT/Codex   │ ───────────────────────▶ [Gmail]
│ task automation │                              │
└─────────────────┘                              │
                                                 │ Mon 09:00 JST
                                                 ▼
                          ┌──────────────────────────────────────────┐
                          │ GitHub Actions (this workflow)           │
                          │                                          │
                          │ Phase 1: ingest (no label yet)           │
                          │   1. OAuth refresh                       │
                          │   2. Gmail API search                    │
                          │      (隔離キュー pending の週は skip)    │
                          │   3. sanitize + raw md 保存              │
                          │   4. インジェクション・ゲート            │
                          │      (L0+L1 → gate_decision.py ci)       │
                          │      non-clean → _quarantine/ 退避 +     │
                          │      隔離キュー登録し **継続**           │
                          │   5. (clean のみ) ingestThreatReport()   │
                          │   6. 成功 thread を                      │
                          │      pending-labels.json に書く          │
                          │                                          │
                          │ Gate invariant re-check (belt&braces)    │
                          │ Vault push:                              │
                          │   7. git add / commit / push (4 retry)   │
                          │      (_gate/ の trace/queue/state 含む)  │
                          │                                          │
                          │ Phase 2: label (push 成功時のみ)         │
                          │   8. pending-labels.json を読む          │
                          │   9. Gmail に processed ラベル付与       │
                          │  10. 全件成功なら pending ファイル削除   │
                          └──────────────────────────────────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ Vault repo (private)        │
                                  │   raw/<YYYY-MM-DD>.md       │
                                  │   .threat_reports.json      │
                                  │   _index.md                 │
                                  │   _gate/decisions.jsonl     │
                                  │   _gate/quarantine_queue…   │
                                  │   _gate/gate_state.json     │
                                  │   (_quarantine/ は同期除外) │
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

> 🛡️ **2-phase 設計の意義 (self-healing)**: Gmail の `processed` ラベルは
> **vault push が成功した後にしか付かない**。push が失敗 (deploy key 障害 /
> network / conflict 等) すると Phase 2 step は GitHub Actions の
> `if: success()` で skip され、該当 thread はラベル無しで残る。次の cron で
> 同じ thread を再 ingest → 同じく push を試す。`ingestThreatReport()` は
> `(source + period_end)` の UPSERT で冪等、`ai_relevance_note` も保護されるので
> 再 ingest は安全。
>
> もし label 段階で個別 thread の付与だけ失敗 (Gmail API 一時障害等) した場合、
> `pending-labels.json` はそのまま残り、次回 phase 2 で再試行できる。
> 全件成功時のみファイルが削除される。
>
> 🛡️ **インジェクション・ゲート (非同期隔離)**: 自動経路のゲートは
> `gate_decision.py --profile=ci` = 契約違反 + ハード隠蔽のみ auto-block
> (L2 隔離 LLM 判定は人間監督下の /sec-mode 側のみ)。non-clean のレポートは
> 本文を `_quarantine/` (同期除外) へ退避し、redact 済みメタデータを
> `_gate/quarantine_queue.json` に登録して **他 thread の処理と push は継続**
> する (旧設計のように run 全体を fail させない)。該当 thread は `processed`
> が付かないが、キューが pending の間は再取込もキュー重複登録もされない。
> 裁定は人間が `/sec-mode` の「隔離キュー review」で行う。
> **注**: runner 上の `_quarantine/` 本文は run 終了と共に消える (untrusted
> 本文は commit しない設計)。永続コピーは Gmail 原本 (`processed` 未付与の
> まま残る) で、キューの `source_ref` (`gmail:<threadId>`) から裁定時に再取得
> する。判定表・キュー・heightened モードの正典は
> `docs/security/gate-decision-architecture.md`。

## 2. 必要な前提

### 2.1 Vault repo 側 (= 別 private repo)

- Obsidian Vault 一式 **または** 「Permanent Note」フォルダだけを private repo
  として GitHub に置く
- **`.gitignore` で `threat_reports.db` を除外しない**
  - `ai_relevance_note` (人が curate するコメント) を run 間で保持するため
  - 本リポ (obsidian-ai-pipeline) の `CLAUDE.md`「Secrets / sensitive files」
    節は本 repo 自身が対象 (`<vault>` を含まない作業 repo) で、vault repo の
    gitignore 方針は独立に決められる
- deploy key (read+write) を 1 個生成して vault repo の **Settings → Deploy keys** に追加
  - 秘密鍵側は obsidian-ai-pipeline の secrets に `VAULT_DEPLOY_KEY` として登録

#### Vault repo のレイアウト想定

fetcher のデフォルトは「Vault ルートに `Permanent Note/` がある」前提で、
レポート保存先を `<vault>/Permanent Note/10_Threat_Reports/` に組み立てる。
だが vault repo の切り方は人それぞれ:

| パターン | 例 | workflow 側の対応 |
|---|---|---|
| 完全な Obsidian Vault | `<repo>/Permanent Note/10_Threat_Reports/` | デフォルトのまま (`THREAT_REPORTS_FOLDER` 不要) |
| **Permanent Note フォルダだけを切り出した repo** | `<repo>/10_Threat_Reports/` (= 本リポの参考実装) | workflow の `THREAT_REPORTS_FOLDER` env と commit step の `TR_DIR` を `10_Threat_Reports` に変更 |
| 任意の階層 | `<repo>/foo/bar/10_Threat_Reports/` | `THREAT_REPORTS_FOLDER=foo/bar/10_Threat_Reports` (絶対パス / `..` traversal は parser が拒否) |

参考実装 (`theosera/obsidian-permanent-note`) は 2 番目のパターンで、
`.github/workflows/llm-sec-weekly.yml` には既に `THREAT_REPORTS_FOLDER:
10_Threat_Reports` をハードコードしてある。別構造の vault に切り替える場合は
この 1 行と commit step の `TR_DIR` を揃って書き換えれば良い。

なお `__skills/pipeline/threat_reports.db` は env override できず、必ず
**vault repo のルート直下**に作られる。Permanent Note だけ切り出した repo の
場合、`__skills/` ディレクトリが Permanent Note フォルダの隣に出現することに
なるので、Obsidian 側で `.obsidian/app.json` の "Excluded files" にこのパスを
追加するなどして UI からは隠すと良い。

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
| ゲート non-clean (契約違反 / ハード隠蔽 / ゲート実行失敗=fail-closed) | 該当 thread のみ quarantined (raw → `_quarantine/` + 隔離キュー)、**run は継続**・processed 付与しない | `/sec-mode` の「隔離キュー review」で裁定 (FP なら取込 + KSP 候補を PR 化) |
| raw/ に non-clean が残存 ("Gate invariant re-check" 赤) | commit/push 前に停止 (fetcher 側ゲートの配線回帰疑い) | fetcher のゲート統合 (`makeCliGateRunner`) を点検 |
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

Level 2 (= "自リポ該当チェック") の **Tier1 (指定 1 リポ × 取込済みレポート) は実装済み**:
`pnpm start -- --analyze-threat-relevance --target-repo=<owner/repo|path>` が、各 finding を
対象リポに **決定的に grep** (`threat-reports/repo_evidence.ts`) して「該当ファイル+行の候補」を
集め、隔離 LLM の判定結果と合わせて `ai_relevance_note` を **下書き** (`🤖` sentinel 付き /
人手 note は保護) として埋める。下書き生成済みは `reports[].checks[]` (checked_untrusted) に
記録され、`/sec-review` が「下書きあり・人手未レビュー」を区別できる。

> grep は read-only・literal・bounded で、**返すのは file:line と一致語のみ (行内容なし)**。
> untrusted な finding 本文の指示・URL・コードは実行も fetch もしない (Trust Boundary)。

cron (`Run fetcher` step) からの自動起動 (新規 ingest 直後に SDK セッションで上記を回す) や、
横断ファンアウト / 反証検証 / ドラフト PR 化は **本 Tier1 の範囲外** (別 PR)。

## 8. 関連ドキュメント

- `docs/security/llm-sec-report-consumption.md` — 上位仕様 (trust boundary / 契約 / 証拠要件)
- `docs/security/gate-decision-architecture.md` — インジェクション・ゲート判定表 / 隔離キュー / heightened
- `docs/threat_reports.md` — Vault レイアウト / SQLite スキーマ
- `CLAUDE.md` `chat mode protocol` 節 — 手動取込 (`/sec-mode`) の対応規定
- `.claude/settings.json` — Claude 自身が secrets を読まない deny rule
