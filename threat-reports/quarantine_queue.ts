/**
 * 隔離 (quarantine) の責務: non-clean 本文の退避と、隔離キュー JSON の入出力。
 *
 * ★ ここは「取込の入口 (Gmail fetcher)」ではなく「脅威レポート側」が持つ責務である。
 * 隔離キューの schema `quarantine-queue@1` は gate_decision.py の QUEUE_SCHEMA と
 * 一致させる契約で、人間の裁定 (`/sec-mode` の隔離キュー review) がこれを読む。
 * 取込元が Gmail 以外になってもこの契約は変わらないため、fetcher の中に置くと
 * 「誰が契約を持つか」が入口の実装に紐づいてしまう。
 *
 * `scripts/llm_sec_weekly_fetcher.ts` から振る舞いを変えずに移した (2026-10-18)。
 * 旧 import 経路を壊さないため、fetcher 側は同じ名前を再公開している。
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { getThreatReportsBaseFolder } from './config';

/** ゲート出力 (trace / queue / state) を置く vault 内サブディレクトリ。 */
export const GATE_SUBDIR = '_gate';
/** 隔離キュー JSON の schema 識別子 (gate_decision.py の QUEUE_SCHEMA と一致)。 */
export const QUARANTINE_QUEUE_SCHEMA = 'quarantine-queue@1';

/**
 * 本文を隔離ディレクトリへ退避し、実際に置いたパスを返す。
 *
 * 同名が既にある場合 (同じ週を騙る別メールが続けて隔離された等) は連番を付ける。
 * 上書きすると先に隔離した証拠が消え、裁定できなくなるため。
 */
export class QuarantineCapacityError extends Error {
  constructor(filename: string) {
    super(`quarantine collision が 100 件を超えたため上書きせず停止: ${filename}`);
    this.name = 'QuarantineCapacityError';
  }
}

export function quarantineBody(srcPath: string, quarantineDir: string): string {
  fs.mkdirSync(quarantineDir, { recursive: true });
  const srcBase = path.basename(srcPath);
  // Vault 内の quarantine に executable Markdown を残さない。
  // legacy/staging .md は .md.txt へ変換し、重複連番も拡張子の前へ入れて
  // `*.md.txt` 終端を常に維持する。
  const inertBase = srcBase.endsWith('.md.txt')
    ? srcBase
    : srcBase.endsWith('.md') ? `${srcBase}.txt` : `${srcBase}.md.txt`;
  const suffix = '.md.txt';
  const stem = inertBase.slice(0, -suffix.length);
  let dest = path.join(quarantineDir, inertBase);
  for (let n = 1; fs.existsSync(dest); n++) {
    if (n > 100) {
      throw new QuarantineCapacityError(inertBase);
    }
    dest = path.join(quarantineDir, `${stem}.${n}${suffix}`);
  }
  fs.renameSync(srcPath, dest);
  return dest;
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
