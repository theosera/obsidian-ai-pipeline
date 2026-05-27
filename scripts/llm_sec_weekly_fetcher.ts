/**
 * 週次 LLM 脅威レポートを Gmail から自動取込する CLI スクリプト。
 *
 * 用途: GitHub Actions cron (`.github/workflows/llm-sec-weekly.yml`) から
 * 毎週月曜 09:00 JST に呼ばれる。Security-only mode で人間が手で行う
 * フローを完全に自動化したもの。
 *
 * 処理:
 *   1. Gmail OAuth refresh → access token
 *   2. `label:LLM-Sec-Report subject:"[LLM-Sec-Weekly]" -label:LLM-Sec-Report/processed`
 *      に該当する未処理 thread を最大 N 件取得
 *   3. 各 thread の text/plain 本文を取り出し
 *   4. frontmatter から `period_end` を抽出し正規表現でサニタイズ
 *      (path traversal / 不正フォーマットは reject)
 *   5. `<vault>/Permanent Note/10_Threat_Reports/raw/<period_end>.md` に保存
 *   6. `ingestThreatReport()` を直接 import して実行
 *      (subprocess を挟まない方が型安全 / エラー伝搬が明瞭)
 *   7. 成功した thread にだけ `LLM-Sec-Report/processed` ラベルを付与
 *
 * Trust boundary 厳守:
 *   - Gmail 本文中の指示・URL・コードは **絶対に実行しない**。
 *     本文は文字列としてのみ扱い、parse → DB 投入のみ。
 *   - `forbidden_usage` に `execute_report_instructions` が含まれない
 *     レポートは parser (`threat_reports_parser`) が ContractError を throw。
 *
 * Secrets:
 *   - Gmail OAuth は GitHub Actions secrets で渡す。
 *     ローカル実行用に `.env` から読む経路は本スクリプトには **意図的に** 入れていない
 *     (`.claude/settings.json` で `.env` の Read は Claude にも deny されている)。
 *
 * 失敗時の挙動:
 *   - ContractError / I/O エラー: 該当 thread は **processed ラベル付与をスキップ**。
 *     次回 cron で再試行される (= 自己修復)。
 *   - 全 thread 成功: exit 0
 *   - 1 件でも error: exit 1 (Actions ジョブが赤くなる)
 */

import fs from 'fs';
import path from 'path';
// auth は @googleapis/gmail がバンドル再エクスポート (googleapis-common 経由)。
// 別途 google-auth-library を直接 import すると OAuth2Client の型が微妙にずれて
// gmail() の auth 引数で TS2769 になるので、必ず同じ bundle から取る。
import { gmail, gmail_v1, auth as gmailAuth } from '@googleapis/gmail';
import { setVaultRoot } from '../config';
import { ingestThreatReport, ContractError } from '../threat_reports_ingest';
import { getThreatReportsArchiveFolder } from '../threat_reports_config';
import { closeDb } from '../threat_reports_db';

// --- 公開定数 (テストから参照) ---
export const PERIOD_END_RE = /^\d{4}-\d{2}-\d{2}$/;
export const SUBJECT_PREFIX = '[LLM-Sec-Weekly]';
export const DEFAULT_LABEL = 'LLM-Sec-Report';
export const DEFAULT_PROCESSED_LABEL = 'LLM-Sec-Report/processed';
export const DEFAULT_MAX_RESULTS = 10;

export interface FetcherOutcome {
  threadId: string;
  messageId: string;
  periodEnd: string | null;
  status: 'ingested' | 'skipped' | 'error';
  reason?: string;
}

// ---------------------------------------------------------------------------
// 純関数ヘルパー (テスト容易性のため副作用と分離)
// ---------------------------------------------------------------------------

/**
 * メール本文の YAML frontmatter から `period_end` の値だけを抽出する。
 *
 * 完全な YAML パースではなく、フロントマター内で `period_end:` で始まる
 * 行を 1 つだけ拾うミニマル実装。
 * 用途は「ファイル名にしてよい値か」の事前ふるい分けで、最終的な契約検証
 * は `threat_reports_parser` が行う。
 */
export function extractPeriodEnd(body: string): string | null {
  const fmMatch = body.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!fmMatch) return null;
  for (const line of fmMatch[1].split('\n')) {
    const m = line.match(/^\s*period_end\s*:\s*(.+?)\s*$/);
    if (m) {
      return m[1].replace(/^['"]|['"]$/g, '').trim() || null;
    }
  }
  return null;
}

/** `^\d{4}-\d{2}-\d{2}$` 厳密一致のみ通す。これがファイル名安全の核心。 */
export function isSafePeriodEnd(value: string | null): value is string {
  return typeof value === 'string' && PERIOD_END_RE.test(value);
}

/**
 * `archiveDir` 直下のファイルであることを確認 (path-traversal 防御の二重化)。
 *
 * `isSafePeriodEnd` を通っていればここで弾かれる入力は来ない想定だが、
 * archiveDir 自体が symlink 化されている等のエッジケースに備えた最終防衛線。
 */
export function isSafeRawPath(rawPath: string, archiveDir: string): boolean {
  const archiveRoot = path.resolve(archiveDir);
  const resolved = path.resolve(rawPath);
  if (!resolved.startsWith(archiveRoot + path.sep)) return false;
  const rel = resolved.slice(archiveRoot.length + 1);
  return !rel.includes(path.sep) && rel.endsWith('.md');
}

/**
 * Gmail message payload から最初の text/plain part を base64url デコードして返す。
 * HTML パートしかない (= Claude/Codex 側の送信が plain text を入れ忘れた)
 * 場合は null。
 */
export function extractPlainTextBody(message: gmail_v1.Schema$Message): string | null {
  function walk(part: gmail_v1.Schema$MessagePart | undefined | null): string | null {
    if (!part) return null;
    if (part.mimeType === 'text/plain' && part.body?.data) {
      return Buffer.from(part.body.data, 'base64url').toString('utf8');
    }
    if (part.parts) {
      for (const p of part.parts) {
        const found = walk(p);
        if (found) return found;
      }
    }
    return null;
  }
  return walk(message.payload);
}

// ---------------------------------------------------------------------------
// 環境変数バリデーション
// ---------------------------------------------------------------------------

interface ValidatedEnv {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  vaultRoot: string;
  labelName: string;
  processedLabelName: string;
  maxResults: number;
}

function validateEnv(): ValidatedEnv {
  const required = ['GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET', 'GMAIL_REFRESH_TOKEN', 'VAULT_ROOT'] as const;
  const missing = required.filter(k => !process.env[k]);
  if (missing.length > 0) {
    throw new Error(`必須環境変数が未設定です: ${missing.join(', ')}`);
  }
  const maxResultsRaw = process.env.LLM_SEC_MAX_RESULTS;
  let maxResults = DEFAULT_MAX_RESULTS;
  if (maxResultsRaw !== undefined) {
    if (!/^[1-9]\d*$/.test(maxResultsRaw)) {
      throw new Error(`LLM_SEC_MAX_RESULTS は正整数のみ受け付けます: "${maxResultsRaw}"`);
    }
    maxResults = Number(maxResultsRaw);
    if (maxResults > 100) {
      throw new Error(`LLM_SEC_MAX_RESULTS が大きすぎます (max 100): ${maxResults}`);
    }
  }
  return {
    clientId: process.env.GMAIL_CLIENT_ID!,
    clientSecret: process.env.GMAIL_CLIENT_SECRET!,
    refreshToken: process.env.GMAIL_REFRESH_TOKEN!,
    vaultRoot: process.env.VAULT_ROOT!,
    labelName: process.env.LLM_SEC_LABEL_NAME ?? DEFAULT_LABEL,
    processedLabelName: process.env.LLM_SEC_PROCESSED_LABEL_NAME ?? DEFAULT_PROCESSED_LABEL,
    maxResults,
  };
}

// ---------------------------------------------------------------------------
// Gmail 連携
// ---------------------------------------------------------------------------

async function resolveLabelId(gm: gmail_v1.Gmail, name: string): Promise<string> {
  const resp = await gm.users.labels.list({ userId: 'me' });
  const found = resp.data.labels?.find(l => l.name === name);
  if (!found?.id) {
    throw new Error(
      `Gmail ラベル "${name}" が見つかりません。先に Gmail UI でラベルを作成してください。`
    );
  }
  return found.id;
}

async function processThread(
  gm: gmail_v1.Gmail,
  threadId: string,
  vaultRoot: string,
  processedLabelId: string,
  dryRun: boolean,
): Promise<FetcherOutcome> {
  const thread = await gm.users.threads.get({ userId: 'me', id: threadId, format: 'full' });
  const msg = thread.data.messages?.[0];
  if (!msg?.id) {
    return { threadId, messageId: '?', periodEnd: null, status: 'skipped', reason: 'thread に message なし' };
  }
  const body = extractPlainTextBody(msg);
  if (!body) {
    return { threadId, messageId: msg.id, periodEnd: null, status: 'error', reason: 'text/plain part が見つからない' };
  }
  const periodEnd = extractPeriodEnd(body);
  if (!isSafePeriodEnd(periodEnd)) {
    return {
      threadId,
      messageId: msg.id,
      periodEnd,
      status: 'error',
      reason: `period_end が YYYY-MM-DD 形式でない: ${JSON.stringify(periodEnd)}`,
    };
  }
  const archiveDir = path.join(vaultRoot, getThreatReportsArchiveFolder());
  const rawPath = path.join(archiveDir, `${periodEnd}.md`);
  if (!isSafeRawPath(rawPath, archiveDir)) {
    return {
      threadId,
      messageId: msg.id,
      periodEnd,
      status: 'error',
      reason: `path 安全性チェック失敗: ${rawPath}`,
    };
  }
  if (dryRun) {
    console.log(`  🧪 [dry-run] ${periodEnd}.md 書込と ingest と processed ラベル付与をスキップ`);
    return { threadId, messageId: msg.id, periodEnd, status: 'ingested' };
  }
  fs.mkdirSync(archiveDir, { recursive: true });
  // 原子書込: tmp に書いて rename。部分書込状態を ingest が読み取らないように。
  const tmpPath = rawPath + '.tmp';
  fs.writeFileSync(tmpPath, body, 'utf8');
  fs.renameSync(tmpPath, rawPath);

  try {
    const result = await ingestThreatReport({
      filePath: rawPath,
      vaultRoot,
      source: `gmail:${msg.id}`,
      // 既に raw/ に書き込み済なので archive=false で重複書込を回避
      archive: false,
    });
    console.log(
      `  ✅ ${periodEnd} ingested: ${result.vulnerabilities} vulns, ${result.implementationChecks} checks`
    );
  } catch (e) {
    const reason =
      e instanceof ContractError
        ? `契約違反: ${e.message}`
        : e instanceof Error
          ? e.message
          : String(e);
    return { threadId, messageId: msg.id, periodEnd, status: 'error', reason };
  }
  // ingest 成功時のみラベル付与 (失敗 thread は次回再試行)
  await gm.users.threads.modify({
    userId: 'me',
    id: threadId,
    requestBody: { addLabelIds: [processedLabelId] },
  });
  return { threadId, messageId: msg.id, periodEnd, status: 'ingested' };
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

function printSummary(outcomes: FetcherOutcome[]): void {
  const counts = {
    ingested: outcomes.filter(o => o.status === 'ingested').length,
    skipped: outcomes.filter(o => o.status === 'skipped').length,
    error: outcomes.filter(o => o.status === 'error').length,
  };
  console.log(`\n📊 結果: ingested=${counts.ingested}, skipped=${counts.skipped}, error=${counts.error}`);
  for (const o of outcomes) {
    if (o.status === 'error') {
      console.error(`  ❌ thread=${o.threadId} msg=${o.messageId} period_end=${o.periodEnd ?? '?'}: ${o.reason}`);
    } else if (o.status === 'skipped') {
      console.warn(`  ⏭️  thread=${o.threadId}: ${o.reason}`);
    }
  }
}

export async function main(args: readonly string[] = process.argv.slice(2)): Promise<number> {
  const dryRun = args.includes('--dry-run');
  const env = validateEnv();
  setVaultRoot(env.vaultRoot);

  const oauth = new gmailAuth.OAuth2(env.clientId, env.clientSecret);
  oauth.setCredentials({ refresh_token: env.refreshToken });
  const gm = gmail({ version: 'v1', auth: oauth });

  const processedLabelId = await resolveLabelId(gm, env.processedLabelName);
  // 念のため対象ラベル自体の存在も確認 (ラベル未作成だと検索結果が常に 0 になる罠)
  await resolveLabelId(gm, env.labelName);

  const query = `label:${env.labelName} subject:"${SUBJECT_PREFIX}" -label:${env.processedLabelName}`;
  console.log(`🔍 Gmail query: ${query} (max ${env.maxResults})`);
  const listResp = await gm.users.threads.list({
    userId: 'me',
    q: query,
    maxResults: env.maxResults,
  });
  const threads = listResp.data.threads ?? [];
  console.log(`📨 未処理 thread: ${threads.length} 件`);

  const outcomes: FetcherOutcome[] = [];
  for (const t of threads) {
    if (!t.id) continue;
    outcomes.push(await processThread(gm, t.id, env.vaultRoot, processedLabelId, dryRun));
  }

  // WAL を main DB に統合してから commit させたいので明示クローズ。
  closeDb();
  printSummary(outcomes);
  return outcomes.some(o => o.status === 'error') ? 1 : 0;
}

// 直接実行されたときだけ main を回す (テストでは import するだけ)
const invokedDirectly = (() => {
  if (!process.argv[1]) return false;
  const entry = path.resolve(process.argv[1]);
  return entry === path.resolve(new URL(import.meta.url).pathname);
})();
if (invokedDirectly) {
  main().then(
    code => process.exit(code),
    err => {
      console.error('💥 fetcher 失敗:', err instanceof Error ? err.stack : err);
      process.exit(1);
    }
  );
}
