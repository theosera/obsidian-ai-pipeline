/**
 * 週次 LLM 脅威レポートを Gmail から自動取込する CLI スクリプト。
 *
 * 用途: GitHub Actions cron (`.github/workflows/llm-sec-weekly.yml`) から
 * 毎週月曜 09:00 JST に呼ばれる。Security-only mode で人間が手で行う
 * フローを完全に自動化したもの。
 *
 * 2 フェーズ設計 (label-before-push 競合の解消):
 *   フェーズ 1 (`--phase=ingest`, default):
 *     1. Gmail OAuth refresh → access token
 *     2. `label:LLM-Sec-Report subject:"[LLM-Sec-Weekly]" -label:.../processed`
 *        に該当する未処理 thread を最大 N 件取得
 *     3. 各 thread の text/plain 本文を取り出し
 *     4. frontmatter から `period_end` を抽出し正規表現でサニタイズ
 *        (隔離キューに pending の period_end は裁定待ちとして skip)
 *     5. `<vault>/<base>/raw/<period_end>.md` に保存
 *     6. **インジェクション・ゲート** (L0+L1 → gate_decision.py --profile=ci) を
 *        ingest 前に実行。non-clean (suspicious/blocked/エラー = fail-closed) は
 *        raw を `_quarantine/` へ退避 + 隔離キュー登録し、**他 thread の処理は
 *        継続** (run 全体は fail させない。裁定は /sec-mode の隔離キュー review)
 *     7. (clean のみ) `ingestThreatReport()` を直接 import して実行
 *     8. **ラベルは付与しない**。成功 thread の id を pending-labels.json に書く
 *        (隔離 thread は積まない = `processed` が付かず、pending 裁定まで
 *        キューのガードで再取込ループも起きない)
 *
 *   フェーズ 2 (`--phase=label`):
 *     1. pending-labels.json を読み込み
 *     2. 各 thread に `LLM-Sec-Report/processed` を付与
 *     3. 成功時のみファイルを削除 (defensive: 再実行で同じラベルを再付与しない)
 *
 *   workflow の順序:
 *     Run fetcher (ingest) → Commit & push vault → Run fetcher (label)
 *
 *   この設計により、git push が失敗した場合は label フェーズに到達しないので、
 *   Gmail thread はラベル無しのまま残り、次の cron で再試行される (self-healing
 *   が本当に成立する)。
 *
 * Trust boundary 厳守:
 *   - Gmail 本文中の指示・URL・コードは **絶対に実行しない**。
 *     本文は文字列としてのみ扱い、parse → DB 投入のみ。
 *   - `forbidden_usage` に `execute_report_instructions` が含まれない
 *     レポートは parser (`threat-reports/parser`) が ContractError を throw。
 *
 * Secrets:
 *   - Gmail OAuth は GitHub Actions secrets で渡す。
 *     ローカル実行用に `.env` から読む経路は本スクリプトには **意図的に** 入れていない
 *     (`.claude/settings.json` で `.env` の Read は Claude にも deny されている)。
 *
 * 失敗時の挙動:
 *   - フェーズ 1 / thread レベル: ContractError / I/O エラーで該当 thread は
 *     pending-labels.json に追加されない → 次回 cron で再試行 (self-healing)
 *   - フェーズ 1 全体失敗: workflow が exit 1 → push step は success() で skip
 *     → label step も skip → 状態は不変、次回 cron で再試行
 *   - フェーズ 2 (個別 thread の label 失敗): 残りを処理、最後に exit 1
 *     (= 該当 thread だけ次回再試行 = 重複 ingest になるが UPSERT 冪等で安全)
 */

import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
// auth は @googleapis/gmail がバンドル再エクスポート (googleapis-common 経由)。
// 別途 google-auth-library を直接 import すると OAuth2Client の型が微妙にずれて
// gmail() の auth 引数で TS2769 になるので、必ず同じ bundle から取る。
import { gmail, gmail_v1, auth as gmailAuth } from '@googleapis/gmail';
import { setVaultRoot } from '../config';
import { ingestThreatReport, ContractError } from '../threat-reports/ingest';
import { getThreatReportsArchiveFolder, getThreatReportsBaseFolder } from '../threat-reports/config';
import { closeDb } from '../threat-reports/db';

// --- 公開定数 (テストから参照) ---
export const PERIOD_END_RE = /^\d{4}-\d{2}-\d{2}$/;
export const SUBJECT_PREFIX = '[LLM-Sec-Weekly]';
export const DEFAULT_LABEL = 'LLM-Sec-Report';
export const DEFAULT_PROCESSED_LABEL = 'LLM-Sec-Report/processed';
export const DEFAULT_MAX_RESULTS = 10;
/** フェーズ間で受け渡すファイルのデフォルトパス (cwd 相対)。 */
export const DEFAULT_PENDING_LABELS_FILE = 'pending-labels.json';
/** ゲート出力 (trace / queue / state) を置く vault 内サブディレクトリ。 */
export const GATE_SUBDIR = '_gate';
/** non-clean レポート本文の退避先 (vault 側で git/iCloud 同期除外)。 */
export const QUARANTINE_SUBDIR = '_quarantine';

// fileURLToPath: `new URL(...).pathname` はスペース/非 ASCII を %-encode したまま
// 返すため、そうしたパス配下の checkout でスクリプト解決が壊れる (PR #116 レビュー)。
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCANNER_SCRIPT = path.join(
  REPO_ROOT, '.claude/skills/scan-threat-report/scripts/scan-threat-report.py');
const GATE_SCRIPT = path.join(
  REPO_ROOT, '.claude/skills/scan-threat-report/scripts/gate_decision.py');

export interface FetcherOutcome {
  threadId: string;
  messageId: string;
  periodEnd: string | null;
  status: 'ingested' | 'skipped' | 'quarantined' | 'error';
  reason?: string;
}

/** インジェクション・ゲート 1 回分の結果。`error` は fail-closed で隔離扱い。 */
export interface GateResult {
  verdict: 'clean' | 'suspicious' | 'blocked' | 'error';
  /** redact 済みの 1 行要約 (payload 全文は含めない)。 */
  detail: string;
}

/**
 * ゲート実行関数。テストでは stub を注入する (本番は `makeCliGateRunner`)。
 * `sourceRef` は原本参照 (例: `gmail:<threadId>`) — decision record / 隔離キューに
 * 保存され、CI 隔離で本文が runner と共に消えた後の再取得に使う。
 */
export type GateRunner = (rawPath: string, sourceRef?: string) => GateResult;

/** ゲート subprocess の上限時間。untrusted 本文で hang しても週次バッチを止めない。 */
const GATE_EXEC_TIMEOUT_MS = 60_000;

/** フェーズ 1 → フェーズ 2 に橋渡しする 1 thread 分の情報。 */
export interface PendingLabel {
  threadId: string;
  /** ログ用 (label 付与には不要だが、phase 2 の出力でどの週かを示すため保持)。 */
  periodEnd: string;
  /** ログ用。 */
  messageId: string;
}

export interface PendingLabelsFile {
  /** 書き出した時刻 (ISO8601)。phase 2 で stale 検知に使えるよう保持。 */
  written_at: string;
  threads: PendingLabel[];
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
 * は `threat-reports/parser` が行う。
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
// インジェクション・ゲート (L0+L1 → gate_decision.py --profile=ci)
// ---------------------------------------------------------------------------

/** execFileSync が throw した unknown から exit status / stdout を安全に取り出す。 */
function execError(e: unknown): { status: number | null; stdout: string; message: string } {
  const status = typeof (e as { status?: unknown }).status === 'number'
    ? (e as { status: number }).status
    : null;
  const stdout = typeof (e as { stdout?: unknown }).stdout === 'string'
    ? (e as { stdout: string }).stdout
    : '';
  return { status, stdout, message: e instanceof Error ? e.message : String(e) };
}

/**
 * 本番のゲート実行: L1 スキャナ → gate_decision.py (ci プロファイル)。
 *
 * - 固定引数の `execFileSync` のみ (untrusted 本文をシェルに展開しない)。
 * - trace / queue / state は `<vault>/<base>/_gate/` 配下 (redact 済み固定
 *   ファイルのみ。gate_decision.py 自身が書く)。
 * - ci プロファイルは L2 (隔離 LLM 判定) を持たない = 契約違反 + ハード隠蔽
 *   のみ auto-block (旧 workflow pre-scan と同義。詳細は
 *   docs/security/gate-decision-architecture.md §6)。
 * - scanner exit 1 は「signal あり」の正常系 (stdout に JSON が出ている)。
 *   それ以外の失敗と gate exit 4 は fail-closed で `error` (= 隔離)。
 */
export function makeCliGateRunner(vaultRoot: string): GateRunner {
  const gateDir = path.join(vaultRoot, getThreatReportsBaseFolder(), GATE_SUBDIR);
  return (rawPath: string, sourceRef?: string): GateResult => {
    let l1Json: string;
    try {
      // timeout: hang した subprocess は SIGTERM で殺され execError 経由の
      // fail-closed (`error` → 隔離) に落ちる (status=null / signal=SIGTERM)。
      l1Json = execFileSync('python3', [SCANNER_SCRIPT, '--json', rawPath], {
        encoding: 'utf8',
        timeout: GATE_EXEC_TIMEOUT_MS,
      });
    } catch (e) {
      const err = execError(e);
      if (err.status === 1 && err.stdout.length > 0) {
        l1Json = err.stdout;
      } else {
        return { verdict: 'error', detail: `L1 scanner 実行失敗: ${err.message}` };
      }
    }
    try {
      execFileSync(
        'python3',
        [
          GATE_SCRIPT, 'decide', '--l1', '-', '--profile', 'ci',
          '--body', rawPath,
          '--state', path.join(gateDir, 'gate_state.json'),
          '--trace-out', path.join(gateDir, 'decisions.jsonl'),
          '--queue', path.join(gateDir, 'quarantine_queue.json'),
          ...(sourceRef ? ['--source-ref', sourceRef] : []),
        ],
        { input: l1Json, encoding: 'utf8', timeout: GATE_EXEC_TIMEOUT_MS }
      );
      return { verdict: 'clean', detail: '' };
    } catch (e) {
      const err = execError(e);
      // gate_decision.py の非 --json 出力は redact 済み 1 行サマリ (payload なし)。
      const detail = err.stdout.trim().split('\n')[0] || err.message;
      if (err.status === 2) return { verdict: 'suspicious', detail };
      if (err.status === 3) return { verdict: 'blocked', detail };
      return { verdict: 'error', detail }; // exit 4 / spawn 失敗 = fail-closed
    }
  };
}

/**
 * ゲートを実行し、non-clean なら raw を隔離ディレクトリへ移す。
 *
 * 隔離キュー / 判断トレースへの記録は gate_decision.py 側が済ませているため、
 * ここでは本文ファイルの退避だけを行う (redact 済みメタデータは vault に
 * commit され、本文は同期除外の `_quarantine/` に残る)。
 */
export function gateAndRoute(
  rawPath: string,
  quarantineDir: string,
  gate: GateRunner,
  sourceRef?: string
): { action: 'ingest' } | { action: 'quarantine'; verdict: GateResult['verdict']; detail: string } {
  const result = gate(rawPath, sourceRef);
  if (result.verdict === 'clean') return { action: 'ingest' };
  fs.mkdirSync(quarantineDir, { recursive: true });
  fs.renameSync(rawPath, path.join(quarantineDir, path.basename(rawPath)));
  return { action: 'quarantine', verdict: result.verdict, detail: result.detail };
}

/**
 * 隔離キューで pending の period_end 一覧を返す (再取込ループ防止ガード)。
 *
 * 隔離済み thread は `processed` ラベルが付かないため次 cron でも検索に
 * 出てくる。ここで pending の period_end を skip しないと、毎週 raw 書込 →
 * 隔離 → キュー重複登録を繰り返す。キューが無い/壊れている場合は空扱い
 * (ゲート自体は毎回走るので安全側に倒れる)。
 */
export function readQuarantinePendingPeriodEnds(vaultRoot: string): Set<string> {
  const queuePath = path.join(
    vaultRoot, getThreatReportsBaseFolder(), GATE_SUBDIR, 'quarantine_queue.json');
  if (!fs.existsSync(queuePath)) return new Set();
  try {
    const parsed = JSON.parse(fs.readFileSync(queuePath, 'utf8')) as {
      items?: Array<{ period_end?: unknown; status?: unknown }>;
    };
    return new Set(
      (parsed.items ?? [])
        .filter(i => i.status === 'pending' && typeof i.period_end === 'string')
        .map(i => i.period_end as string)
    );
  } catch {
    return new Set();
  }
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

/**
 * GitHub Actions の `env:` ブロックは未設定 secret も **空文字** として
 * 注入してくる。`??` は undefined しか捕えないので、`""` がそのまま通って
 * 「ラベル名が空」「MAX_RESULTS が正整数 regex に失敗」で workflow が
 * 落ちる罠を避けるため、ここで空文字を undefined に正規化する。
 */
export function envOrUndefined(name: string): string | undefined {
  const v = process.env[name];
  return v === undefined || v === '' ? undefined : v;
}

function validateEnv(): ValidatedEnv {
  const required = ['GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET', 'GMAIL_REFRESH_TOKEN', 'VAULT_ROOT'] as const;
  const missing = required.filter(k => !envOrUndefined(k));
  if (missing.length > 0) {
    throw new Error(`必須環境変数が未設定です: ${missing.join(', ')}`);
  }
  const maxResultsRaw = envOrUndefined('LLM_SEC_MAX_RESULTS');
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
    clientId: envOrUndefined('GMAIL_CLIENT_ID')!,
    clientSecret: envOrUndefined('GMAIL_CLIENT_SECRET')!,
    refreshToken: envOrUndefined('GMAIL_REFRESH_TOKEN')!,
    vaultRoot: envOrUndefined('VAULT_ROOT')!,
    labelName: envOrUndefined('LLM_SEC_LABEL_NAME') ?? DEFAULT_LABEL,
    processedLabelName: envOrUndefined('LLM_SEC_PROCESSED_LABEL_NAME') ?? DEFAULT_PROCESSED_LABEL,
    maxResults,
  };
}

// ---------------------------------------------------------------------------
// Gmail 連携
// ---------------------------------------------------------------------------

/**
 * Gmail OAuth の refresh 失敗 (`invalid_grant`) を検出する。
 *
 * `invalid_grant` は Google OAuth サーバが refresh token を拒否した合図
 * (= revoke / 失効) で、**コード修正では直らない** (token 再生成 + secret 更新が必要)。
 * google-auth-library は GaxiosError の `response.data.error` に `invalid_grant`
 * を載せる。ネットワーク経路差で構造が変わっても拾えるよう message 文字列も見る。
 */
export function isInvalidGrantError(e: unknown): boolean {
  const err = e as { response?: { data?: { error?: unknown } }; message?: unknown };
  if (err?.response?.data?.error === 'invalid_grant') return true;
  return typeof err?.message === 'string' && err.message.includes('invalid_grant');
}

/**
 * `invalid_grant` 時に CI ログだけで原因と復旧手順が分かる実行可能メッセージ。
 * 恒久対策 (OAuth app を publish) を必ず併記する — Testing publishing status の
 * ままだと refresh token は発行 7 日で失効し、毎週この step で落ちるため。
 */
const OAUTH_REAUTH_HINT =
  'Gmail OAuth の refresh token が失効/revoke されています (invalid_grant)。' +
  ' 復旧: docs/security/llm-sec-weekly-automation.md §2.2 の手順で refresh_token を' +
  ' 再生成し、GitHub Actions secret `GMAIL_REFRESH_TOKEN` を更新してください。' +
  ' 恒久対策: Google Cloud Console で OAuth app の publishing status を' +
  ' "Testing" → "In production" にしてください (Testing のままだと refresh token は' +
  ' 発行 7 日で失効し、毎週この step で失敗します)。';

/**
 * 認証を要する Gmail 呼び出しを実行し、`invalid_grant` だけ実行可能な
 * メッセージに翻訳して再送する (元 error は `cause` で保持 = stack を失わない)。
 * それ以外の error はそのまま透過する。
 */
export async function withOAuthErrorHint<T>(op: () => Promise<T>): Promise<T> {
  try {
    return await op();
  } catch (e) {
    if (isInvalidGrantError(e)) throw new Error(OAUTH_REAUTH_HINT, { cause: e });
    throw e;
  }
}

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

/**
 * フェーズ 1: 1 thread を取込む。**ラベルは付与しない** (= phase 2 の責務)。
 *
 * 返り値の `status === 'ingested'` の thread だけが pending-labels.json に
 * 積まれ、後の phase 2 で label される (vault push 成功後のみ)。
 */
async function processThread(
  gm: gmail_v1.Gmail,
  threadId: string,
  vaultRoot: string,
  dryRun: boolean,
  gate: GateRunner,
  quarantinePending: ReadonlySet<string>,
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
  if (quarantinePending.has(periodEnd)) {
    return {
      threadId,
      messageId: msg.id,
      periodEnd,
      status: 'skipped',
      reason: '隔離キューに pending — 人間の裁定待ち (再取込・キュー重複登録をしない)',
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
    console.log(`  🧪 [dry-run] ${periodEnd}.md 書込とゲートと ingest と pending-labels.json への記録をスキップ`);
    return { threadId, messageId: msg.id, periodEnd, status: 'ingested' };
  }
  fs.mkdirSync(archiveDir, { recursive: true });
  // 原子書込: tmp に書いて rename。部分書込状態を ingest が読み取らないように。
  const tmpPath = rawPath + '.tmp';
  fs.writeFileSync(tmpPath, body, 'utf8');
  fs.renameSync(tmpPath, rawPath);

  // ★ インジェクション・ゲート: ingest が DB/JSON/index に何か書く前に検査。
  // non-clean は本文を _quarantine/ へ退避して継続 (run 全体は fail させない)。
  // ルーティング自体の例外 (rename の EXDEV / permission 等) も 1 thread の
  // error に閉じ込め、残りの thread の処理を継続する (バッチ全体を中断しない)。
  try {
    const gateOutcome = gateAndRoute(
      rawPath,
      path.join(vaultRoot, getThreatReportsBaseFolder(), QUARANTINE_SUBDIR),
      gate,
      `gmail:${threadId}`
    );
    if (gateOutcome.action === 'quarantine') {
      return {
        threadId,
        messageId: msg.id,
        periodEnd,
        status: 'quarantined',
        reason: `ゲート ${gateOutcome.verdict}: ${gateOutcome.detail}`,
      };
    }
  } catch (e) {
    return {
      threadId,
      messageId: msg.id,
      periodEnd,
      status: 'error',
      reason: `ゲート・ルーティング失敗 (fail-closed / raw は ingest しない): ${
        e instanceof Error ? e.message : String(e)
      }`,
    };
  }

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
  // 重要: ここでラベルを付けない。pending-labels.json に積み、phase 2 で
  // vault push 成功後に付与する。push 失敗時の永久 skip を回避する設計。
  return { threadId, messageId: msg.id, periodEnd, status: 'ingested' };
}

// ---------------------------------------------------------------------------
// pending-labels.json 入出力 (フェーズ間の橋渡し)
// ---------------------------------------------------------------------------

/** outcomes から「label 待ち」リストを抽出する純関数 (テスト容易性のため分離)。 */
export function buildPendingLabels(outcomes: readonly FetcherOutcome[]): PendingLabel[] {
  return outcomes
    .filter((o): o is FetcherOutcome & { periodEnd: string } => o.status === 'ingested' && o.periodEnd !== null)
    .map(o => ({ threadId: o.threadId, periodEnd: o.periodEnd, messageId: o.messageId }));
}

/**
 * pending-labels.json を atomic 書き出し。空配列の場合は **既存ファイルを削除**
 * (= phase 2 で「label すべきものが無い」とすぐ判定できる)。
 */
export function writePendingLabels(filePath: string, threads: PendingLabel[]): void {
  if (threads.length === 0) {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    return;
  }
  const payload: PendingLabelsFile = {
    written_at: new Date().toISOString(),
    threads,
  };
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

/** pending-labels.json を読み込む。存在しなければ空 (= label 対象なし)。 */
export function readPendingLabels(filePath: string): PendingLabel[] {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, 'utf8');
  const parsed = JSON.parse(raw) as Partial<PendingLabelsFile>;
  if (!Array.isArray(parsed.threads)) {
    throw new Error(`pending-labels.json の形式不正: "threads" 配列がない (file: ${filePath})`);
  }
  return parsed.threads.filter(
    (t): t is PendingLabel =>
      typeof t?.threadId === 'string' && typeof t.periodEnd === 'string' && typeof t.messageId === 'string'
  );
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

function printSummary(outcomes: FetcherOutcome[]): void {
  const counts = {
    ingested: outcomes.filter(o => o.status === 'ingested').length,
    quarantined: outcomes.filter(o => o.status === 'quarantined').length,
    skipped: outcomes.filter(o => o.status === 'skipped').length,
    error: outcomes.filter(o => o.status === 'error').length,
  };
  console.log(
    `\n📊 結果: ingested=${counts.ingested}, quarantined=${counts.quarantined}, ` +
      `skipped=${counts.skipped}, error=${counts.error}`
  );
  for (const o of outcomes) {
    if (o.status === 'error') {
      console.error(`  ❌ thread=${o.threadId} msg=${o.messageId} period_end=${o.periodEnd ?? '?'}: ${o.reason}`);
    } else if (o.status === 'quarantined') {
      console.warn(
        `  🛡️  thread=${o.threadId} period_end=${o.periodEnd ?? '?'}: ${o.reason} ` +
          `(→ _quarantine/ + 隔離キュー。/sec-mode の「隔離キュー review」で裁定)`
      );
    } else if (o.status === 'skipped') {
      console.warn(`  ⏭️  thread=${o.threadId}: ${o.reason}`);
    }
  }
}

function buildGmailClient(env: ValidatedEnv): gmail_v1.Gmail {
  const oauth = new gmailAuth.OAuth2(env.clientId, env.clientSecret);
  oauth.setCredentials({ refresh_token: env.refreshToken });
  return gmail({ version: 'v1', auth: oauth });
}

function getPendingLabelsPath(): string {
  return envOrUndefined('PENDING_LABELS_FILE') ?? DEFAULT_PENDING_LABELS_FILE;
}

/**
 * フェーズ 1: 未処理メールを取得 → vault に raw md / DB / JSON / index を書き出し
 * → 成功 thread を pending-labels.json に積む。**ラベルは付与しない**。
 */
export async function runIngestPhase(args: readonly string[]): Promise<number> {
  const dryRun = args.includes('--dry-run');
  const env = validateEnv();
  setVaultRoot(env.vaultRoot);

  const gm = buildGmailClient(env);

  // ラベル自体の存在確認 (未作成だと検索結果が常に 0 になる罠を早期検知)。
  // 最初の認証付き呼び出しでもあるため、OAuth refresh 失敗 (invalid_grant) は
  // ここで実行可能なメッセージに翻訳される。
  await withOAuthErrorHint(async () => {
    await resolveLabelId(gm, env.labelName);
    await resolveLabelId(gm, env.processedLabelName);
  });

  const query = `label:${env.labelName} subject:"${SUBJECT_PREFIX}" -label:${env.processedLabelName}`;
  console.log(`🔍 Gmail query: ${query} (max ${env.maxResults})`);
  const listResp = await gm.users.threads.list({
    userId: 'me',
    q: query,
    maxResults: env.maxResults,
  });
  const threads = listResp.data.threads ?? [];
  console.log(`📨 未処理 thread: ${threads.length} 件`);

  const gate = makeCliGateRunner(env.vaultRoot);
  const quarantinePending = readQuarantinePendingPeriodEnds(env.vaultRoot);
  const outcomes: FetcherOutcome[] = [];
  for (const t of threads) {
    if (!t.id) continue;
    outcomes.push(await processThread(gm, t.id, env.vaultRoot, dryRun, gate, quarantinePending));
  }

  // WAL を main DB に統合してから commit させたいので明示クローズ。
  closeDb();
  printSummary(outcomes);

  // dry-run でも pending は書かない (実際の ingest が無いため次 phase で label
  // すべきものも無い)。本番では成功した thread だけを phase 2 に渡す。
  const pending = dryRun ? [] : buildPendingLabels(outcomes);
  const pendingPath = getPendingLabelsPath();
  writePendingLabels(pendingPath, pending);
  if (pending.length > 0) {
    console.log(`📝 ${pending.length} 件を ${pendingPath} に書き出し (phase 2 で label 予定)`);
  } else {
    console.log(`📭 pending-labels.json は空 / 削除済 (label 対象なし)`);
  }

  return outcomes.some(o => o.status === 'error') ? 1 : 0;
}

/**
 * フェーズ 2: pending-labels.json を読んで、各 thread に `processed` ラベルを
 * 付与する。vault push 成功後にのみ workflow から呼ばれる想定。
 *
 * VAULT_ROOT は不要 (DB を触らないため) だが、validateEnv の責務を変えると
 * テストや他経路への影響が大きいので「必須環境変数」を共通化したまま
 * label phase でも要求する。workflow 側は両 phase で同じ env を渡す。
 */
export async function runLabelPhase(): Promise<number> {
  const env = validateEnv();
  const pendingPath = getPendingLabelsPath();
  const pending = readPendingLabels(pendingPath);
  if (pending.length === 0) {
    console.log(`📭 ${pendingPath} に label 対象なし (skip)`);
    return 0;
  }
  console.log(`🏷️  ${pending.length} 件に "${env.processedLabelName}" ラベルを付与開始`);

  const gm = buildGmailClient(env);
  const processedLabelId = await withOAuthErrorHint(() =>
    resolveLabelId(gm, env.processedLabelName)
  );

  let failed = 0;
  for (const t of pending) {
    try {
      await gm.users.threads.modify({
        userId: 'me',
        id: t.threadId,
        requestBody: { addLabelIds: [processedLabelId] },
      });
      console.log(`  ✅ labeled thread=${t.threadId} period_end=${t.periodEnd}`);
    } catch (e) {
      failed++;
      const reason = e instanceof Error ? e.message : String(e);
      console.error(`  ❌ label 失敗 thread=${t.threadId} period_end=${t.periodEnd}: ${reason}`);
    }
  }

  if (failed === 0) {
    // 全件成功時のみファイルを消す (= 部分失敗時は再実行できるよう温存)。
    // 部分失敗で残った場合、次回 phase 1 で同じ thread が再 ingest されるが、
    // UPSERT 冪等なので安全 (= 重複 ingest 経路だが結果は同じ)。
    fs.unlinkSync(pendingPath);
    console.log(`🧹 ${pendingPath} 削除`);
  }

  console.log(`\n📊 label 結果: 成功=${pending.length - failed}, 失敗=${failed}`);
  return failed > 0 ? 1 : 0;
}

/**
 * エントリポイント。`--phase=label` で label フェーズ、それ以外は ingest フェーズ。
 */
export async function main(args: readonly string[] = process.argv.slice(2)): Promise<number> {
  const phase = args.find(a => a.startsWith('--phase='))?.split('=')[1] ?? 'ingest';
  if (phase === 'label') return runLabelPhase();
  if (phase === 'ingest') return runIngestPhase(args);
  console.error(`Unknown --phase value: "${phase}" (allowed: ingest | label)`);
  return 1;
}

// 直接実行されたときだけ main を回す (テストでは import するだけ)
const invokedDirectly = (() => {
  if (!process.argv[1]) return false;
  const entry = path.resolve(process.argv[1]);
  return entry === path.resolve(fileURLToPath(import.meta.url));
})();
if (invokedDirectly) {
  main().then(
    code => process.exit(code),
    err => {
      console.error('💥 fetcher 失敗:', err instanceof Error ? err.stack : err);
      // 翻訳した error は元 error を cause に持つ (invalid_grant 等)。原因 stack も出す。
      if (err instanceof Error && err.cause) {
        console.error('   ↳ cause:', err.cause instanceof Error ? err.cause.stack : err.cause);
      }
      process.exit(1);
    }
  );
}
