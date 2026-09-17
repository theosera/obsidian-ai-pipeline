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
 *     3. thread 内で **Subject が `[LLM-Sec-Weekly]` で始まる message だけ**を
 *        対象に text/plain 本文を取り出し (Gmail 検索は thread 単位でヒットする
 *        ため、選別条件を message 単位に効かせ直さないと選別を通っていない本文を
 *        ingest しうる。同一 thread に 2 通目が来ても取りこぼさない)
 *     4. frontmatter から `period_end` を抽出し正規表現でサニタイズ
 *        (隔離キューに pending の **thread** (`source_ref`) は裁定待ちとして skip。
 *        period_end 単位で skip すると、未来の週を騙る 1 通で以後その週の正規
 *        レポートを恒久的に塞げてしまう)
 *     5. untrusted 本文はまず `<vault>/<base>/_staging/<period_end>.md` に置く
 *        (raw/ への昇格は clean 判定の後。隔離判定が既存 raw を消せない設計)
 *     6. **インジェクション・ゲート** (L0+L1 → gate_decision.py --profile=ci) を
 *        ingest 前に実行。non-clean (suspicious/blocked/エラー = fail-closed) は
 *        staging を `_quarantine/` へ退避 + 隔離キュー登録し、**他 thread の処理は
 *        継続** (run 全体は fail させない。裁定は /sec-mode の隔離キュー review)
 *     7. (clean のみ) `raw/<period_end>.md` へ昇格してから
 *        `ingestThreatReport()` を直接 import して実行。既存 raw と内容が違う
 *        場合は上書きせず隔離 (untrusted 入力に archive を消させない)
 *     8. **ラベルは付与しない**。成功 message と決定論的失敗 (terminal) の id を
 *        pending-labels.json に書く (隔離 message は積まない = `processed` が
 *        付かず、pending 裁定までキューのガードで再取込ループも起きない)
 *
 *   フェーズ 2 (`--phase=label`):
 *     1. pending-labels.json を読み込み
 *     2. 各 **message** に `LLM-Sec-Report/processed` を付与 (thread 単位で付けると
 *        同一 thread の 2 通目が黙って恒久 skip されるため)
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
 *   - フェーズ 1 / message レベル: I/O エラー等の一過性失敗は pending-labels.json
 *     に追加されない → 次回 cron で再試行 (self-healing)。text/plain 欠落 /
 *     period_end 不正 / 契約違反のような **決定論的失敗は terminal** として
 *     ラベルを付け、再試行を打ち切る (窓 = maxResults を永久に占有させない)
 *   - フェーズ 1 は **個別 message の失敗では非 0 を返さない**。exit 1 にすると
 *     後続 step が `success()` 条件で丸ごと skip され、取り込めた健全なレポート
 *     まで runner ごと破棄される (次 cron で同じ楔を打ち直す) ため、thread 単位の
 *     失敗は `::error::` 注釈で可視化するに留める
 *   - フェーズ 1 全体失敗 (env / OAuth / ラベル解決): throw して exit 1
 *     → push step は success() で skip → label step も skip → 状態は不変
 *   - フェーズ 2 (個別 thread の label 失敗): 残りを処理、最後に exit 1
 *     (= 該当 thread だけ次回再試行 = 重複 ingest になるが UPSERT 冪等で安全)
 */

import { execFileSync } from 'child_process';
import crypto from 'crypto';
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
/**
 * ゲート判定前の untrusted 本文を置く一時領域。
 *
 * raw/ に直接書いてからゲートすると、(a) 隔離判定の rename が既に archive 済みの
 * 同名レポートを消してしまい (workflow の `git add -f raw/` がその削除を stage して
 * push する)、(b) 同じ週を騙るメール 1 通で過去の正規レポートを破壊できる。
 * clean 判定を通ったものだけを raw/ へ昇格させることでこの経路を塞ぐ。
 * workflow は raw/ ・ JSON ・ _index.md ・ _gate/ ・ DB だけを add するので、
 * ここに残骸が出ても commit されない (各経路で必ず片付ける)。
 */
export const STAGING_SUBDIR = '_staging';
/** 隔離キュー JSON の schema 識別子 (gate_decision.py の QUEUE_SCHEMA と一致)。 */
export const QUARANTINE_QUEUE_SCHEMA = 'quarantine-queue@1';
/** period_end の未来許容幅 (日)。送信遅延 / タイムゾーン差の余裕を見て 2 週間。 */
export const PERIOD_END_FUTURE_HORIZON_DAYS = 14;
/** thread 一覧のページング上限 (API 濫用と無限ループの防止)。 */
export const MAX_THREAD_LIST_PAGES = 10;

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
  /**
   * 決定論的失敗 (再試行しても必ず同じ結果になる) か。
   * true の error は `processed` ラベルを付けて終端させる — さもないと
   * 固定サイズの検索窓 (maxResults) を永久に占有し、正規レポートを押し出す。
   */
  terminal?: boolean;
  /** ゲートに渡した原本参照 (`gmail:<threadId>[#...]`)。隔離裁定の追跡用。 */
  sourceRef?: string;
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
 * 未来の週を騙る (または暦として存在しない) `period_end` を弾く多層防御。
 *
 * `period_end` は untrusted 本文由来なのに、ファイル名・隔離キューのキー・
 * decision_id の一部になる。遠い未来の週を名乗るメールを取り込ませると、
 * 後から届く**その週の正規レポート**と衝突させられる。形式 (`PERIOD_END_RE`) を
 * 通った後の追加ふるいなので、ここでは暦としての妥当性も見る。
 * `new Date()` は `2026-02-31` のような非実在日を黙って繰り上げる (→ 03-03) ため、
 * ISO 文字列への往復比較で確かめる。
 */
export function isPeriodEndTooFarInFuture(periodEnd: string, now: Date = new Date()): boolean {
  const parsed = new Date(`${periodEnd}T00:00:00Z`);
  const t = parsed.getTime();
  if (Number.isNaN(t) || parsed.toISOString().slice(0, 10) !== periodEnd) return true;
  return t - now.getTime() > PERIOD_END_FUTURE_HORIZON_DAYS * 24 * 60 * 60 * 1000;
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

/** Gmail message から取り出した本文と、その「代替表現」の有無。 */
export interface MessageBodyParts {
  /** 最初の text/plain part (無ければ null)。ゲートも ingest もこれだけを見る。 */
  plain: string | null;
  /** 同じ message に text/html part があるか (= Gmail の見た目と乖離しうる)。 */
  hasHtml: boolean;
  /** 本文候補 (`text/*` かつ data 有り) の part 数。1 なら乖離の余地なし。 */
  bodyPartCount: number;
}

/**
 * Gmail message payload を走査し、最初の text/plain part と代替表現の有無を返す。
 *
 * ゲートに掛かるのは **text/plain だけ**なのに、隔離を裁定する人間は
 * `source_ref` を頼りに Gmail の原本を開き、そこで見るのは text/html 側。
 * 両者が食い違っていても気付けないので、乖離の可能性 (`hasHtml` /
 * `bodyPartCount`) を呼び出し側へ持ち上げ、`--source-ref` の fragment に載せる。
 */
export function extractBodyParts(message: gmail_v1.Schema$Message): MessageBodyParts {
  let plain: string | null = null;
  let hasHtml = false;
  let bodyPartCount = 0;
  function walk(part: gmail_v1.Schema$MessagePart | undefined | null): void {
    if (!part) return;
    const mime = part.mimeType ?? '';
    if (mime.startsWith('text/') && part.body?.data) {
      bodyPartCount++;
      if (mime === 'text/plain' && plain === null) {
        plain = Buffer.from(part.body.data, 'base64url').toString('utf8');
      } else if (mime === 'text/html') {
        hasHtml = true;
      }
    }
    for (const p of part.parts ?? []) walk(p);
  }
  walk(message.payload);
  return { plain, hasHtml, bodyPartCount };
}

/**
 * Gmail message payload から最初の text/plain part を base64url デコードして返す。
 * HTML パートしかない (= Claude/Codex 側の送信が plain text を入れ忘れた)
 * 場合は null。`extractBodyParts` の薄いラッパ。
 */
export function extractPlainTextBody(message: gmail_v1.Schema$Message): string | null {
  return extractBodyParts(message).plain;
}

/** message の `Subject` ヘッダを取り出す (無ければ null)。 */
export function extractSubject(message: gmail_v1.Schema$Message): string | null {
  for (const h of message.payload?.headers ?? []) {
    if (typeof h.name === 'string' && h.name.toLowerCase() === 'subject') {
      return typeof h.value === 'string' ? h.value : null;
    }
  }
  return null;
}

/**
 * thread の中から「週次レポート本体」として扱う message を選ぶ。
 *
 * Gmail 検索は **thread 単位**でヒットするため、`subject:"[LLM-Sec-Weekly]"` に
 * 一致したのが thread 内の別 message (返信・転送) という状況があり得る。
 * 選別条件を message 単位に効かせ直さないと、唯一の選別フィルタを通っていない
 * 本文を ingest してしまう。また 1 通目だけを見る実装だと、同一 thread に
 * まとまった 2 通目の週次レポートが**エラーも出ないまま恒久的に落ちる**ため、
 * 一致する message は全件返す。
 */
export function selectReportMessages(
  thread: gmail_v1.Schema$Thread | undefined | null
): gmail_v1.Schema$Message[] {
  return (thread?.messages ?? []).filter(
    m => !!m.id && (extractSubject(m) ?? '').trimStart().startsWith(SUBJECT_PREFIX)
  );
}

/** 隔離キューのガードが突き合わせるキー (fragment を除いた thread 同一性)。 */
export function threadSourceRef(threadId: string): string {
  return `gmail:${threadId}`;
}

/**
 * `--source-ref` の値を組み立てる。
 *
 * base は `gmail:<threadId>` (= 再取込ループ防止ガードの比較キー)。
 * 「本文のどの part を / thread 内のどの message をゲートしたか」は fragment
 * (`#text-plain-of-2,msg=<id>`) に載せる。隔離キューのエントリだけを見て
 * 人間が原本のどこを見ればよいか分かるようにするため。
 */
export function buildSourceRef(
  threadId: string,
  messageId: string,
  bodyPartCount: number,
  reportMessageCount: number
): string {
  const fragment: string[] = [];
  if (bodyPartCount > 1) fragment.push(`text-plain-of-${bodyPartCount}`);
  if (reportMessageCount > 1) fragment.push(`msg=${messageId}`);
  const base = threadSourceRef(threadId);
  return fragment.length > 0 ? `${base}#${fragment.join(',')}` : base;
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
 * 本文を隔離ディレクトリへ退避し、実際に置いたパスを返す。
 *
 * 同名が既にある場合 (同じ週を騙る別メールが続けて隔離された等) は連番を付ける。
 * 上書きすると先に隔離した証拠が消え、裁定できなくなるため。
 */
export function quarantineBody(srcPath: string, quarantineDir: string): string {
  fs.mkdirSync(quarantineDir, { recursive: true });
  const base = path.basename(srcPath);
  let dest = path.join(quarantineDir, base);
  for (let n = 1; fs.existsSync(dest) && n <= 100; n++) {
    dest = path.join(quarantineDir, `${base}.${n}`);
  }
  fs.renameSync(srcPath, dest);
  return dest;
}

/**
 * ゲートを実行し、non-clean なら staging 本文を隔離ディレクトリへ移す。
 *
 * 判断トレース / 隔離キューへの記録は gate_decision.py 側が済ませているため、
 * ここでは本文ファイルの退避だけを行う (redact 済みメタデータは vault に
 * commit され、本文は同期除外の `_quarantine/` に残る)。ただし verdict が
 * `error` (exit 4 / spawn 失敗 / timeout) のときは gate_decision.py が
 * queue_add に到達していないので、キュー登録は**呼び出し側**が補う必要がある。
 */
export function gateAndRoute(
  stagedPath: string,
  quarantineDir: string,
  gate: GateRunner,
  sourceRef?: string
): { action: 'ingest' }
  | { action: 'quarantine'; verdict: GateResult['verdict']; detail: string; quarantinedPath: string } {
  const result = gate(stagedPath, sourceRef);
  if (result.verdict === 'clean') return { action: 'ingest' };
  return {
    action: 'quarantine',
    verdict: result.verdict,
    detail: result.detail,
    quarantinedPath: quarantineBody(stagedPath, quarantineDir),
  };
}

/** staging から raw/ への昇格結果。`conflict` は既存と内容が違う (上書きしない)。 */
export type PromoteResult = 'promoted' | 'identical' | 'conflict';

/**
 * ゲート clean の本文を `raw/<period_end>.md` へ昇格する。
 *
 * 既存ファイルがある場合:
 *   - 内容が同一 → 何もしない (`identical`)。push 失敗で label が付かず次 cron が
 *     同じ本文を再処理する self-healing 経路がここを通るので、失敗にしてはいけない。
 *   - 内容が違う → **上書きしない** (`conflict`)。untrusted メール 1 通で既に
 *     archive 済みのレポートを差し替えられる経路を塞ぐ (呼び出し側が隔離へ回す)。
 */
export function promoteStagedRaw(stagedPath: string, rawPath: string): PromoteResult {
  if (fs.existsSync(rawPath)) {
    if (fs.readFileSync(rawPath, 'utf8') !== fs.readFileSync(stagedPath, 'utf8')) {
      return 'conflict';
    }
    fs.unlinkSync(stagedPath);
    return 'identical';
  }
  fs.mkdirSync(path.dirname(rawPath), { recursive: true });
  fs.renameSync(stagedPath, rawPath);
  return 'promoted';
}

/**
 * ingest に失敗した本文を `raw/` から退避する (テスト容易性のため分離)。
 *
 * ★ `promoted` = **この run が raw/ を作った**ときだけ触る。`identical` は
 * 自己修復経路で既存ファイルと同内容だっただけなので、他 run の成果物を
 * 消さないために何もしない。
 *
 * 削除ではなく隔離 + キュー登録にするのは、`quarantineBody` の設計と同じ理由:
 * 証拠を消すと人間が裁定できなくなる。
 */
export function discardFailedPromotion(args: {
  promotion: PromoteResult;
  rawPath: string;
  quarantineDir: string;
  queuePath: string;
  periodEnd: string;
  sourceRef: string;
  reason: string;
}): 'quarantined' | 'skipped' {
  if (args.promotion !== 'promoted') return 'skipped';
  let quarantinedPath = '(退避失敗)';
  try {
    quarantinedPath = quarantineBody(args.rawPath, args.quarantineDir);
  } catch (e) {
    console.error(`::error::ingest 失敗本文の raw/ からの退避に失敗: ${errText(e)}`);
    removeIfExists(args.rawPath);
  }
  appendQuarantineQueueEntry(args.queuePath, {
    periodEnd: args.periodEnd,
    file: quarantinedPath,
    sourceRef: args.sourceRef,
    verdict: 'error',
    reason: args.reason,
  });
  return 'quarantined';
}

/** fetcher が自前で隔離キューへ積む 1 件分の入力。 */
export interface FetcherQueueEntry {
  periodEnd: string;
  /** 退避先の本文パス (裁定時に人間が開く)。 */
  file: string;
  sourceRef: string;
  /** `error` (ゲート実行失敗) / `conflict` (既存 raw と不一致)。 */
  verdict: string;
  reason: string;
}

/**
 * 隔離キューへ fetcher 由来のエントリを 1 件追記する (失敗しても throw しない)。
 *
 * gate_decision.py の queue_add は verdict が suspicious/blocked のときだけ走る。
 * exit 4 / spawn 失敗 / timeout (= fetcher 側 verdict `error`) と、既存 raw との
 * 内容衝突は **キューに 1 件も載らない**ため、(a) 人間の裁定対象から漏れ、
 * (b) 再取込ループ防止ガード (`source_ref`) も噛まず毎 run 隔離を繰り返す。
 * ここで最小のエントリを補完してその穴を塞ぐ。
 * 壊れた / 別 schema のキューは**上書きしない** (人手データを壊さない)。
 */
export function appendQuarantineQueueEntry(queuePath: string, entry: FetcherQueueEntry): boolean {
  try {
    let items: Array<Record<string, unknown>> = [];
    if (fs.existsSync(queuePath)) {
      const parsed = JSON.parse(fs.readFileSync(queuePath, 'utf8')) as {
        schema?: unknown; items?: unknown;
      };
      if (parsed.schema !== QUARANTINE_QUEUE_SCHEMA || !Array.isArray(parsed.items)) {
        console.error(
          `::error::隔離キューの schema が想定外のため fetcher 由来エントリを追記できません: ${queuePath}`
        );
        return false;
      }
      items = parsed.items as Array<Record<string, unknown>>;
    }
    // idempotent: 同じ原本が pending のまま残っているなら二重登録しない
    // (gate_decision.py の queue_add も period_end + source_ref で同じガードを行う)。
    const key = normalizeSourceRef(entry.sourceRef);
    if (items.some(it => it.status === 'pending' &&
        typeof it.source_ref === 'string' && normalizeSourceRef(it.source_ref) === key)) {
      return false;
    }
    const ts = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const compact = ts.replace(/[-:TZ]/g, '');
    // ★ 秒精度の時刻だけでは id が衝突する。同じ period_end を名乗る別スレッドが
    // 同一 run で積まれると decision_id が完全一致し、queue_id は下 4 桁 (= 分秒)
    // しか使わないので **時刻が違っても**衝突する。衝突すると `--resolve` が
    // 曖昧になり、人間の裁定が別の本文に付きうる。
    // gate_decision.py の decision_id が body_sha の先頭 4 桁を持つのと同じ形で、
    // 原本 (thread) の同一性を id に織り込む。
    const srcDisc = crypto.createHash('sha1').update(key).digest('hex').slice(0, 4);
    const decisionId = `fetcher-${entry.periodEnd}-${compact}-${srcDisc}`;
    items.push({
      queue_id: `q-${entry.periodEnd}-${decisionId.slice(-4)}`,
      period_end: entry.periodEnd,
      file: entry.file,
      source_ref: entry.sourceRef,
      decision_id: decisionId,
      verdict: entry.verdict,
      reasons: [entry.reason],
      queued_at: ts,
      source: 'fetcher',
      status: 'pending',
      adjudicated_at: null,
      adjudication_note: null,
      ksp_candidate: null,
    });
    fs.mkdirSync(path.dirname(queuePath), { recursive: true });
    const tmp = queuePath + '.tmp';
    fs.writeFileSync(
      tmp, JSON.stringify({ schema: QUARANTINE_QUEUE_SCHEMA, items }, null, 2) + '\n', 'utf8');
    fs.renameSync(tmp, queuePath);
    return true;
  } catch (e) {
    console.error(
      `::error::隔離キューへの追記に失敗: ${e instanceof Error ? e.message : String(e)}`);
    return false;
  }
}

/** `gmail:<threadId>#...` の fragment を落として thread 同一性だけを取り出す。 */
function normalizeSourceRef(ref: string): string {
  return ref.split('#')[0];
}

/**
 * 隔離キューで pending の `source_ref` 一覧を返す (再取込ループ防止ガード)。
 *
 * 隔離済み thread は `processed` ラベルが付かないため次 cron でも検索に
 * 出てくる。ここで skip しないと、毎週 本文書込 → 隔離 → キュー重複登録を
 * 繰り返す。
 *
 * ガードのキーは **原本 (thread) の同一性**であって period_end ではない。
 * period_end は untrusted 本文が名乗る値なので、わざと non-clean にした数通で
 * 未来の月曜を名乗らせるだけで、その週の正規レポートを恒久的に (しかも
 * `skipped` = 成功扱いのまま) 塞げてしまう。
 * キューが無い/壊れている場合は空扱い (ゲート自体は毎回走るので安全側)。
 */
export function readQuarantinePendingSourceRefs(vaultRoot: string): Set<string> {
  const queuePath = path.join(
    vaultRoot, getThreatReportsBaseFolder(), GATE_SUBDIR, 'quarantine_queue.json');
  if (!fs.existsSync(queuePath)) return new Set();
  try {
    const parsed = JSON.parse(fs.readFileSync(queuePath, 'utf8')) as {
      items?: Array<{ source_ref?: unknown; status?: unknown }>;
    };
    return new Set(
      (parsed.items ?? [])
        .filter(i => i.status === 'pending' && typeof i.source_ref === 'string')
        .map(i => normalizeSourceRef(i.source_ref as string))
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

/** 例外から表示用メッセージを取り出す。 */
function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** 残骸を残さないための best-effort 削除 (失敗しても処理は続ける)。 */
function removeIfExists(filePath: string): void {
  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch { /* 残骸削除の失敗は握り潰す (commit 対象外パスのため実害なし) */ }
}

/**
 * 未処理 thread を `maxResults` 件まで取得する (nextPageToken 追従つき)。
 *
 * `threads.list` は 1 回の応答で maxResults 未満しか返さないことがあり、
 * 隔離・恒久エラーの thread は `processed` が付かず窓に残り続けるため、
 * 1 ページ固定だと正規レポートが窓の外へ押し出されても誰も気付けない。
 * 上限までページを追い、まだ残っている (= 取りこぼし) 事実を呼び出し側へ返す。
 */
export async function listUnprocessedThreads(
  gm: gmail_v1.Gmail,
  query: string,
  maxResults: number
): Promise<{ threads: gmail_v1.Schema$Thread[]; truncated: boolean }> {
  const threads: gmail_v1.Schema$Thread[] = [];
  let pageToken: string | undefined;
  for (let page = 0; page < MAX_THREAD_LIST_PAGES; page++) {
    const resp = await gm.users.threads.list({
      userId: 'me',
      q: query,
      maxResults: maxResults - threads.length,
      ...(pageToken ? { pageToken } : {}),
    });
    threads.push(...(resp.data.threads ?? []));
    pageToken = resp.data.nextPageToken ?? undefined;
    if (!pageToken || threads.length >= maxResults) break;
  }
  return {
    threads: threads.slice(0, maxResults),
    truncated: threads.length >= maxResults && !!pageToken,
  };
}

/**
 * フェーズ 1: 1 thread を取込む。**ラベルは付与しない** (= phase 2 の責務)。
 *
 * Subject 条件に一致する message を全件処理し、message ごとに outcome を返す。
 * `status === 'ingested'` と決定論的失敗 (`terminal`) だけが pending-labels.json
 * に積まれ、後の phase 2 で label される (vault push 成功後のみ)。
 */
async function processThread(
  gm: gmail_v1.Gmail,
  threadId: string,
  vaultRoot: string,
  dryRun: boolean,
  gate: GateRunner,
  quarantinePendingRefs: ReadonlySet<string>,
): Promise<FetcherOutcome[]> {
  // ガードは **thread の同一性** で判定する (period_end ではない — 未来の週を
  // 騙る隔離済みメールに正規レポートを塞がせないため)。API 呼び出しより前に
  // 判定できるので Gmail quota も節約になる。
  if (quarantinePendingRefs.has(threadSourceRef(threadId))) {
    return [{
      threadId,
      messageId: '?',
      periodEnd: null,
      status: 'skipped',
      sourceRef: threadSourceRef(threadId),
      reason: '隔離キューに pending — 人間の裁定待ち (再取込・キュー重複登録をしない)',
    }];
  }
  const thread = await gm.users.threads.get({ userId: 'me', id: threadId, format: 'full' });
  const messages = selectReportMessages(thread.data);
  if (messages.length === 0) {
    return [{
      threadId,
      messageId: '?',
      periodEnd: null,
      status: 'skipped',
      reason: `Subject が "${SUBJECT_PREFIX}" で始まる message が thread に無い`,
    }];
  }
  const outcomes: FetcherOutcome[] = [];
  for (const msg of messages) {
    outcomes.push(
      await processMessage(threadId, msg, messages.length, vaultRoot, dryRun, gate));
  }
  return outcomes;
}

/** フェーズ 1: thread 内の 1 message を取込む (ゲート → 昇格 → ingest)。 */
async function processMessage(
  threadId: string,
  msg: gmail_v1.Schema$Message,
  reportMessageCount: number,
  vaultRoot: string,
  dryRun: boolean,
  gate: GateRunner,
): Promise<FetcherOutcome> {
  const messageId = msg.id!;
  const parts = extractBodyParts(msg);
  const sourceRef = buildSourceRef(threadId, messageId, parts.bodyPartCount, reportMessageCount);
  const at = { threadId, messageId, sourceRef };
  if (parts.plain === null) {
    // 送信側が plain text を入れ忘れている = 何度取り直しても同じ (terminal)。
    return {
      ...at,
      periodEnd: null,
      status: 'error',
      terminal: true,
      reason: parts.hasHtml
        ? 'text/plain part が見つからない (text/html のみ — 送信側に plain text を入れさせること)'
        : 'text/plain part が見つからない',
    };
  }
  const body: string = parts.plain;
  const periodEnd = extractPeriodEnd(body);
  if (!isSafePeriodEnd(periodEnd)) {
    return {
      ...at,
      periodEnd,
      status: 'error',
      terminal: true,
      reason: `period_end が YYYY-MM-DD 形式でない: ${JSON.stringify(periodEnd)}`,
    };
  }
  if (isPeriodEndTooFarInFuture(periodEnd)) {
    return {
      ...at,
      periodEnd,
      status: 'error',
      terminal: true,
      reason: `period_end が未来すぎる / 実在しない日付 (許容 +${PERIOD_END_FUTURE_HORIZON_DAYS}日): ${periodEnd}`,
    };
  }
  const archiveDir = path.join(vaultRoot, getThreatReportsArchiveFolder());
  const rawPath = path.join(archiveDir, `${periodEnd}.md`);
  if (!isSafeRawPath(rawPath, archiveDir)) {
    return {
      ...at,
      periodEnd,
      status: 'error',
      terminal: true,
      reason: `path 安全性チェック失敗: ${rawPath}`,
    };
  }
  if (dryRun) {
    console.log(`  🧪 [dry-run] ${periodEnd}.md 書込とゲートと ingest と pending-labels.json への記録をスキップ`);
    return { ...at, periodEnd, status: 'ingested' };
  }
  const baseDir = path.join(vaultRoot, getThreatReportsBaseFolder());
  const quarantineDir = path.join(baseDir, QUARANTINE_SUBDIR);
  const queuePath = path.join(baseDir, GATE_SUBDIR, 'quarantine_queue.json');
  // untrusted 本文は staging に置く。raw/ に直接書くと、隔離判定の rename が
  // 同名の既存レポートを消し、workflow の `git add -f raw/` がその削除を stage
  // して push してしまう (メール 1 通で archive を破壊できる)。
  const stagingDir = path.join(baseDir, STAGING_SUBDIR);
  const stagedPath = path.join(stagingDir, `${periodEnd}.md`);
  fs.mkdirSync(stagingDir, { recursive: true });
  // 原子書込: tmp に書いて rename。部分書込状態をゲートが読み取らないように。
  const tmpPath = stagedPath + '.tmp';
  fs.writeFileSync(tmpPath, body, 'utf8');
  fs.renameSync(tmpPath, stagedPath);

  // ★ インジェクション・ゲート: ingest が DB/JSON/index に何か書く前に検査。
  // non-clean は本文を _quarantine/ へ退避して継続 (run 全体は fail させない)。
  // ルーティング自体の例外 (rename の EXDEV / permission 等) も 1 message の
  // error に閉じ込め、残りの処理を継続する (バッチ全体を中断しない)。
  try {
    const gateOutcome = gateAndRoute(stagedPath, quarantineDir, gate, sourceRef);
    if (gateOutcome.action === 'quarantine') {
      if (gateOutcome.verdict === 'error') {
        // gate_decision.py は suspicious/blocked のときしか queue_add しない。
        // exit 4 / spawn 失敗 / timeout はキューに載らないので fetcher が補う
        // (載らないと裁定対象から漏れ、ガードも噛まず毎 run 隔離を繰り返す)。
        appendQuarantineQueueEntry(queuePath, {
          periodEnd,
          file: gateOutcome.quarantinedPath,
          sourceRef,
          verdict: 'error',
          reason: gateOutcome.detail || 'gate 実行失敗 (fail-closed)',
        });
      }
      return {
        ...at,
        periodEnd,
        status: 'quarantined',
        reason: `ゲート ${gateOutcome.verdict}: ${gateOutcome.detail}`,
      };
    }
  } catch (e) {
    removeIfExists(stagedPath);
    return {
      ...at,
      periodEnd,
      status: 'error',
      reason: `ゲート・ルーティング失敗 (fail-closed / raw は ingest しない): ${errText(e)}`,
    };
  }

  // ゲート clean のときだけ raw/ へ昇格する。
  let promotion: PromoteResult;
  try {
    promotion = promoteStagedRaw(stagedPath, rawPath);
  } catch (e) {
    removeIfExists(stagedPath);
    return { ...at, periodEnd, status: 'error', reason: `raw/ への昇格に失敗: ${errText(e)}` };
  }
  if (promotion === 'conflict') {
    // 既に archive 済みの週と内容が食い違う = untrusted 入力による差し替え要求。
    // 黙って上書きせず隔離 + キュー登録し、人間の裁定に回す。
    let quarantinedPath = '(退避失敗)';
    try {
      quarantinedPath = quarantineBody(stagedPath, quarantineDir);
    } catch (e) {
      console.error(`::error::衝突本文の隔離に失敗: ${errText(e)}`);
      removeIfExists(stagedPath);
    }
    appendQuarantineQueueEntry(queuePath, {
      periodEnd,
      file: quarantinedPath,
      sourceRef,
      verdict: 'conflict',
      reason: `raw/${periodEnd}.md が既存で内容が異なる (上書きしない)`,
    });
    return {
      ...at,
      periodEnd,
      status: 'quarantined',
      reason: `既存 raw/${periodEnd}.md と内容が異なるため上書きせず隔離 (人間の裁定待ち)`,
    };
  }

  try {
    const result = await ingestThreatReport({
      filePath: rawPath,
      vaultRoot,
      source: `gmail:${messageId}`,
      // 既に raw/ に書き込み済なので archive=false で重複書込を回避
      archive: false,
    });
    console.log(
      `  ✅ ${periodEnd} ingested: ${result.vulnerabilities} vulns, ${result.implementationChecks} checks`
    );
  } catch (e) {
    // ★ ingest が失敗した本文は「正典」ではない。この run が昇格させた raw/ を
    // 残すと llm-sec-weekly.yml が `git add -f .../raw/` でそのまま commit/push し
    // (ゲートは clean なので raw/ 不変条件チェックも素通りする)、後から届いた
    // 訂正版が promoteStagedRaw で `conflict` 扱いになり恒久的に隔離され続ける。
    // terminal でラベルが付くので原本はもう取り直されない = 自動復旧しない。
    // `identical` (自己修復経路で既存と同内容だった) のときは **この run の産物では
    // ない**ので触らない。証拠は消さず隔離 + キューへ回して人間の裁定に載せる。
    discardFailedPromotion({
      promotion,
      rawPath,
      quarantineDir,
      queuePath,
      periodEnd,
      sourceRef,
      reason: `ingest 失敗のため raw/ へ残さず退避: ${errText(e)}`,
    });
    // 契約違反は本文が変わらない限り必ず再発する = terminal。
    return {
      ...at,
      periodEnd,
      status: 'error',
      terminal: e instanceof ContractError,
      reason: e instanceof ContractError ? `契約違反: ${e.message}` : errText(e),
    };
  }
  // 重要: ここでラベルを付けない。pending-labels.json に積み、phase 2 で
  // vault push 成功後に付与する。push 失敗時の永久 skip を回避する設計。
  return { ...at, periodEnd, status: 'ingested' };
}

// ---------------------------------------------------------------------------
// pending-labels.json 入出力 (フェーズ間の橋渡し)
// ---------------------------------------------------------------------------

/**
 * outcomes から「label 待ち」リストを抽出する純関数 (テスト容易性のため分離)。
 *
 * 取込成功に加えて **決定論的失敗 (`terminal`)** も積む。何度取り直しても同じ
 * 結果になる message (text/plain 欠落 / period_end 不正 / 契約違反) を無ラベルで
 * 残すと、固定サイズの検索窓 (`maxResults`) を永久に占有し、正規レポートを窓の
 * 外へ押し出す。失敗自体は printSummary の `::error::` 注釈で可視化される。
 * 隔離 (`quarantined`) は積まない — 人間の裁定後に再取込したいため。
 */
export function buildPendingLabels(outcomes: readonly FetcherOutcome[]): PendingLabel[] {
  const pending: PendingLabel[] = [];
  for (const o of outcomes) {
    if (o.status === 'ingested' && o.periodEnd !== null) {
      pending.push({ threadId: o.threadId, periodEnd: o.periodEnd, messageId: o.messageId });
    } else if (o.status === 'error' && o.terminal === true && o.messageId !== '?') {
      pending.push({
        threadId: o.threadId,
        periodEnd: o.periodEnd ?? 'unknown',
        messageId: o.messageId,
      });
    }
  }
  return pending;
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

/**
 * 実行結果サマリ。個別失敗の可視化 (`::error::` 注釈) はここが唯一の経路なので、
 * 注釈書式の回帰を検知できるようテストから呼べる形で export する。
 */
export function printSummary(outcomes: FetcherOutcome[]): void {
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
  // 個別 message の失敗では run を落とさない (= 健全な thread の commit を
  // 巻き添えにしない) 代わりに、GitHub Actions の注釈で loud に出す。
  // ここが唯一の可視化経路なので、静かに済ませてはいけない。
  for (const o of outcomes) {
    const at = `thread=${o.threadId} msg=${o.messageId} period_end=${o.periodEnd ?? '?'}`;
    if (o.status === 'error') {
      console.error(
        `::error::週次レポートの取込に失敗 (${at}): ${o.reason}` +
          (o.terminal
            ? ' [terminal: processed ラベルを付けて再試行を打ち切る — 送信側を直して再送すること]'
            : ' [次回 cron で再試行]')
      );
    } else if (o.status === 'quarantined') {
      console.warn(
        `::warning::ゲート non-clean で隔離 (${at} source_ref=${o.sourceRef ?? '?'}): ${o.reason} ` +
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
  const { threads, truncated } = await listUnprocessedThreads(gm, query, env.maxResults);
  console.log(`📨 未処理 thread: ${threads.length} 件`);
  if (truncated) {
    // 窓が埋まった = 取りこぼしがある。隔離/恒久エラーの thread が窓を占有して
    // 正規レポートを押し出している可能性があるので、静かに切り捨てない。
    console.error(
      `::error::未処理 thread が上限 ${env.maxResults} 件に達し、取得しきれていません。` +
        ' 隔離キュー (/sec-mode の「隔離キュー review」) を裁定するか、' +
        ' LLM_SEC_MAX_RESULTS を見直してください。'
    );
  }

  const gate = makeCliGateRunner(env.vaultRoot);
  const quarantinePendingRefs = readQuarantinePendingSourceRefs(env.vaultRoot);
  const outcomes: FetcherOutcome[] = [];
  for (const t of threads) {
    if (!t.id) continue;
    outcomes.push(
      ...(await processThread(gm, t.id, env.vaultRoot, dryRun, gate, quarantinePendingRefs)));
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

  // 個別 message の失敗で run 全体を落とさない。exit 1 にすると後続 step
  // (gate 再チェック / vault commit & push / label 付与) が `success()` 条件で
  // 丸ごと skip され、**取り込めた健全なレポートまで runner ごと破棄**される
  // (ラベルも付かないので、次の cron が同じ楔を打ち直して永久に進まない)。
  // run 全体の失敗 (env / OAuth / ラベル解決) は既に throw して非 0 になる。
  // thread 単位の失敗は printSummary の `::error::` 注釈で CI に可視化済み。
  return 0;
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
      // thread 単位ではなく **message 単位**で label する。thread ごと label すると、
      // 同じ thread に後から届いた 2 通目の週次レポートまで `processed` 扱いになり、
      // エラーも出ないまま恒久的に取り込まれなくなる (検索クエリは thread 単位で
      // ヒットするので、未 label の message が 1 つでも残れば次 run で拾える)。
      await gm.users.messages.modify({
        userId: 'me',
        id: t.messageId,
        requestBody: { addLabelIds: [processedLabelId] },
      });
      console.log(`  ✅ labeled msg=${t.messageId} (thread=${t.threadId}) period_end=${t.periodEnd}`);
    } catch (e) {
      failed++;
      const reason = e instanceof Error ? e.message : String(e);
      console.error(
        `::error::label 失敗 msg=${t.messageId} (thread=${t.threadId}) period_end=${t.periodEnd}: ${reason}`);
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
