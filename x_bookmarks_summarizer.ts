/**
 * X ブックマーク AI 要約プロデューサー。
 *
 * 設計:
 *   - SQLite の `bookmarks.ai_summary` 列を埋めるバッチ処理
 *   - `--x-bookmarks` sync 末尾でインライン実行 (JSON エクスポート/ group MD 生成の前)
 *   - 既に埋まっている行はスキップ (`ai_summary IS NULL` のみ対象)
 *   - `--x-resummarize-all` 指定時は事前に全件クリアしてから走る
 *
 * 出力仕様:
 *   - **日本語 200 文字以内**
 *   - 改行禁止 (Dataview テーブルの 1 行に収める)
 *   - 前置きなし (「以下の投稿は...」等を入れない)
 *
 * プロバイダ:
 *   `classifier.ts::askAIText` を経由。Local / Anthropic / OpenAI / Gemini の
 *   どれかが `AI_PROVIDER` で選ばれ、各プロバイダの fast モデル
 *   (Haiku 4.5 / GPT-5.4 mini / Gemini 3.1 Flash-Lite 等) が使われる。
 *   失敗時は当該行を NULL のまま残し次行に進む (要約は best-effort)。
 *
 * 並列度:
 *   3 並列 (`classifier` の 5 より控えめ — レート制限保険)。
 */

import { askAIText } from './classifier';
import { getDb, XBookmarksDb } from './x_bookmarks_db';

const SYSTEM_PROMPT = [
  '与えられた X (Twitter) のポスト本文を日本語で要約してください。',
  '制約:',
  '1. 200 文字以内 (厳守)',
  '2. 改行は使わず一行で出力',
  '3. 「このポストは」「要約:」などの前置きは付けず、要約本文のみ',
  '4. ハッシュタグ・URL・絵文字は要点で必要なら残してよい',
  '5. 推測や追加情報を加えず、原文の内容に忠実に',
].join('\n');

const MAX_SUMMARY_CHARS = 200;
const DEFAULT_CONCURRENCY = 3;

export interface SummarizeStats {
  pending: number;
  succeeded: number;
  failed: number;
}

interface SummarizeOptions {
  db?: XBookmarksDb;
  /** 並列数。デフォルト 3。 */
  concurrency?: number;
  /** テスト注入用: askAIText の代わりに使う関数。 */
  callAi?: (prompt: string, system: string) => Promise<string | null>;
  /** 進捗ログを抑止 (テスト用) */
  silent?: boolean;
  /**
   * `--x-resummarize-all` 用: 全行の ai_summary を NULL に戻してから要約する。
   * **クリアと再要約を同じ関数呼び出し内で行うことが重要** — 早期 (sync 開始前)
   * にクリアしてしまうと、ユーザーが confirmation で中止した場合や処理対象が
   * 0 件だった場合に summary が消えるだけで再生成されない事故になる。
   */
  resummarizeAll?: boolean;
}

/**
 * グラフェムクラスタ単位で安全に 200 文字に切り詰める。
 * `slice()` は UTF-16 code unit ベースなのでサロゲートペアを割る危険があり、
 * 絵文字や合成文字を含む X ポストでは事故になる。`Array.from` で
 * code-point 化してから join する。
 */
export function truncateSummary(text: string, max: number = MAX_SUMMARY_CHARS): string {
  if (!text) return '';
  // 改行・タブを 1 つのスペースに圧縮
  const flat = text.replace(/[\r\n\t]+/g, ' ').replace(/  +/g, ' ').trim();
  const codePoints = Array.from(flat);
  if (codePoints.length <= max) return flat;
  return codePoints.slice(0, max).join('');
}

/**
 * 単一ポストを要約。失敗時 null。テストから直接叩けるよう export。
 */
export async function summarizeOnePost(
  text: string,
  options: { callAi?: (prompt: string, system: string) => Promise<string | null> } = {}
): Promise<string | null> {
  const call = options.callAi ?? ((p, s) => askAIText(p, s, 'fast', 400));
  const raw = await call(text, SYSTEM_PROMPT);
  if (!raw) return null;
  const truncated = truncateSummary(raw);
  return truncated || null;
}

/**
 * `bookmarks.ai_summary IS NULL` の行を一括で要約。
 * sync 末尾から呼ばれる。失敗は warn ログのみで止めない。
 */
export async function summarizePendingBookmarks(
  options: SummarizeOptions = {}
): Promise<SummarizeStats> {
  const db = options.db ?? getDb();
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  const callAi = options.callAi;
  const silent = options.silent ?? false;

  // 全件再要約: ここで NULL に戻す (この関数の中で再生成までやり切るので
  // ユーザー中止や 0 件処理で「クリアだけされて再生成されない」事故が起きない)
  if (options.resummarizeAll) {
    const cleared = db.clearAllAiSummaries();
    if (!silent) {
      console.log(`🧹 --x-resummarize-all: ${cleared} 件の ai_summary をクリア → 再要約します`);
    }
  }

  const pending = db.listPendingAiSummaries();
  const stats: SummarizeStats = { pending: pending.length, succeeded: 0, failed: 0 };
  if (pending.length === 0) {
    if (!silent) console.log('🤖 AI 要約待ちの bookmark はありません。');
    return stats;
  }
  if (!silent) {
    console.log(`🤖 AI 要約を ${pending.length} 件 (並列度 ${concurrency}) で生成します...`);
  }

  // バッチ並列処理: chunk 内は Promise.all で並列、chunk 間は順次。
  for (let i = 0; i < pending.length; i += concurrency) {
    const chunk = pending.slice(i, i + concurrency);
    const results = await Promise.all(
      chunk.map(async row => {
        const text = (row.note_tweet_text ?? row.tweet_text ?? '').trim();
        if (!text) return { tweet_id: row.tweet_id, ok: false };
        const summary = await summarizeOnePost(text, callAi ? { callAi } : undefined);
        if (summary) {
          db.setAiSummary(row.tweet_id, summary);
          return { tweet_id: row.tweet_id, ok: true };
        }
        return { tweet_id: row.tweet_id, ok: false };
      })
    );
    for (const r of results) {
      if (r.ok) stats.succeeded++;
      else stats.failed++;
    }
    if (!silent) {
      const done = Math.min(i + concurrency, pending.length);
      console.log(`   ... ${done}/${pending.length} (成功 ${stats.succeeded} / 失敗 ${stats.failed})`);
    }
  }

  return stats;
}
