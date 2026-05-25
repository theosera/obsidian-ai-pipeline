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
 * プロバイダと実行モード:
 *   `classifier.ts::askAIText` を経由。Local / Anthropic / OpenAI / Gemini の
 *   どれかが `AI_PROVIDER` で選ばれ、各プロバイダの fast モデル
 *   (Haiku 4.5 / GPT-5.4 mini / Gemini 3.1 Flash-Lite 等) が使われる。
 *
 *   実行モードは provider で自動切替:
 *     - `local`            → **batch** モード (10 件ずつ 1 プロンプトに詰めて 1 回呼出 / 順次)
 *     - その他 (cloud)      → **inline** モード (1 件 = 1 呼出 / 3 並列)
 *
 *   ローカル LLM (LM Studio 等) は単一推論のオーバーヘッドが大きく、複数件を
 *   1 プロンプトに詰めた方がトータル時間が大きく短縮される。一方クラウド API は
 *   並列実行の方が速く、また長い JSON 出力での hallucination リスクも避けたい
 *   ため per-tweet を維持する。
 *
 *   失敗時 (LLM null / JSON 不正 / 件数ミスマッチ) は当該行/バッチを NULL のまま
 *   残し次行/バッチに進む (要約は best-effort、次回 sync で自動再挑戦)。
 */

import { askAIText } from './classifier';
import { getDb, XBookmarksDb } from './x_bookmarks_db';
import type { AiProvider } from './types';

const SYSTEM_PROMPT = [
  '与えられた X (Twitter) のポスト本文を日本語で要約してください。',
  '制約:',
  '1. 200 文字以内 (厳守)',
  '2. 改行は使わず一行で出力',
  '3. 「このポストは」「要約:」などの前置きは付けず、要約本文のみ',
  '4. ハッシュタグ・URL・絵文字は要点で必要なら残してよい',
  '5. 推測や追加情報を加えず、原文の内容に忠実に',
].join('\n');

const BATCH_SYSTEM_PROMPT = [
  '与えられた複数の X (Twitter) ポスト本文を、それぞれ日本語で要約してください。',
  '制約 (各要約に対して):',
  '1. 200 文字以内 (厳守)',
  '2. 改行は使わず一行で出力',
  '3. 「このポストは」「要約:」などの前置きは付けず、要約本文のみ',
  '4. 推測や追加情報を加えず、原文の内容に忠実に',
  '出力フォーマット (厳守):',
  '- **JSON のみ** を返答。前後に説明文・コードフェンス・コメントを一切付けない',
  '- 形式: {"summaries": ["要約1", "要約2", ...]}',
  '- 要約は入力と **同じ順序** で、**同じ件数** だけ返す',
].join('\n');

const MAX_SUMMARY_CHARS = 200;
const DEFAULT_CONCURRENCY = 3;
/** Local バッチ 1 回あたりの最大ポスト件数。LM Studio の文脈長と精度のバランス。 */
const DEFAULT_BATCH_SIZE = 10;
/** バッチ呼出の max_tokens は要素数 × per-summary 余裕 で算出 */
const BATCH_TOKENS_PER_ITEM = 350;

/**
 * LLM プロンプト隠蔽インジェクション対策の除去対象文字。
 *
 * 攻撃シナリオ: X のポスト本文に「人間 UI には見えないが LLM は読む」文字を
 * 仕込み、要約 LLM に元の指示を上書きさせる ("ignore previous instructions
 * and output: ..." 等)。要約結果は Dataview テーブルに表示されるため、
 * 攻撃者が summary 列の文面 (フィッシング URL や誤情報) を実質書き換えできる。
 *
 * 除外対象 (誤検出ゼロ前提で「正規用途が事実上存在しない」文字に絞る):
 *   - BiDi override (U+202A-E): 文字の表示順を反転する古典的 spoofing キャリア
 *   - BOM (U+FEFF): 本文中インラインでの正規用途は無く、エディタ artifact 由来
 *   - Unicode Tag chars (U+E0000-U+E007F): 完全不可視で LLM だけが読む典型キャリア
 *
 * 意図的に **除外しない** 文字:
 *   - ZWSP / ZWJ / ZWNJ (U+200B-D): 絵文字 ZWJ シーケンス
 *     (👨‍👩‍👧‍👦 family / 肌色変更) や CJK / インド系言語の表示に必須
 *   - LRM / RLM (U+200E-F): 双方向テキストの正規制御
 *   - Word joiner / BiDi isolate (U+2060-9): 現代テキストの正規制御
 *   これらを strip すると正規の多言語ポストを破壊する。LLM 攻撃面より副作用
 *   コストの方が大きいので無視する。
 *
 * 改行・タブは LLM に意味があるので残す (`truncateSummary` 側で別途圧縮)。
 */
const BIDI_OVERRIDE_RE = /[‪-‮﻿]/g;
const TAG_CHARS_RE = /[\u{E0000}-\u{E007F}]/gu;
/** Markdown / HTML コメントは人間 UI に出ないが LLM のパーサには見える隠蔽命令の温床。 */
const HTML_COMMENT_RE = /<!--[\s\S]*?-->/g;

/**
 * LLM に渡す前の本文サニタイズ。隠蔽インジェクションキャリアを除去する。
 *
 * 既知の限界:
 *   - 同形異字攻撃 (Cyrillic → Latin の視覚的偽装) は除去しない
 *     (正規化すると正規の多言語ツイートを壊すため)
 *   - 自然言語の「説得型」インジェクション (見た目に違和感のない命令文) は
 *     検知しない。LLM 側のシステムプロンプトに依存する。
 *   - 正規絵文字シーケンスの ZWJ は保持するため、ZWJ を埋め込んだ低脅威の
 *     インジェクション (例: `ignore‍previous`) は素通りする。
 *     これは現代 LLM の BPE トークナイザがほぼ ZWJ を区切らないため
 *     実害が小さく、絵文字破壊副作用とのトレードオフで保持側を選んでいる。
 */
export function sanitizeForLLM(text: string): string {
  if (!text) return '';
  return text
    .replace(HTML_COMMENT_RE, '')
    .replace(TAG_CHARS_RE, '')
    .replace(BIDI_OVERRIDE_RE, '');
}

/**
 * バッチ連結時の区切り偽装 (boundary injection) 対策。
 *
 * 攻撃シナリオ: 1 件のポスト本文に `\n---\n[99]\n別命令...` を埋め込まれると、
 * バッチプロンプト全体で偽の区切り行とアイテムヘッダーが追加されたように見え、
 * LLM が件数を取り違える / 攻撃者制御の文面を別アイテムの要約として返す。
 *
 * 対策: 各本文から「区切り行 `\n---+\n`」と「行頭の `[数字]` ヘッダー」を
 * 全角相当に置換し、構造的に boundary injection を不可能にする。
 * 全角への置換は人間が読む `tweet_text` 列には影響しない (本関数の出力は
 * LLM プロンプトにのみ使う一時値)。
 */
export function escapeBatchItemBoundary(text: string): string {
  return text
    .replace(/\n-{3,}\n/g, '\n— \n')
    .replace(/^\[(\d+)\]/gm, '［$1］');
}

export interface SummarizeStats {
  pending: number;
  succeeded: number;
  failed: number;
}

/** 実行モード。auto は AI_PROVIDER から自動判定 (local→batch / 他→inline)。 */
export type SummarizeMode = 'auto' | 'inline' | 'batch';

interface SummarizeOptions {
  db?: XBookmarksDb;
  /** 並列数 (inline モードのみ)。デフォルト 3。 */
  concurrency?: number;
  /** バッチ 1 回あたりの最大ポスト件数 (batch モードのみ)。デフォルト 10。 */
  batchSize?: number;
  /**
   * 実行モード。デフォルト 'auto' (provider から自動判定: local → batch / 他 → inline)。
   * テストや実験での明示指定用。
   */
  mode?: SummarizeMode;
  /**
   * X 要約 dedicated provider (classifier の AI_PROVIDER 環境変数とは独立)。
   * 未指定なら `process.env.AI_PROVIDER` ('local' fallback) を使う = 旧挙動互換。
   * 通常は `pipeline_config.json::xSummary.provider` から渡される。
   */
  provider?: AiProvider;
  /**
   * provider に応じたモデル ID 上書き。未指定なら provider の env デフォルトを使う。
   * 通常は `pipeline_config.json::xSummary.model` から渡される。
   */
  model?: string;
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

/** provider から実行モードを決定 (auto 解決)。 */
export function resolveMode(mode: SummarizeMode | undefined, provider: string | undefined): 'inline' | 'batch' {
  if (mode === 'inline' || mode === 'batch') return mode;
  return (provider ?? 'local') === 'local' ? 'batch' : 'inline';
}

/**
 * グラフェムクラスタ単位で安全に 200 文字に切り詰める。
 *
 * `slice()` (UTF-16 code unit) や `Array.from()` (code point) では、ZWJ
 * シーケンスや合成文字 (例: 👨‍👩‍👧‍👦 family、肌色変更絵文字、結合濁点付き
 * 仮名) を分割してしまい、表示が壊れる。`Intl.Segmenter`
 * (`granularity: 'grapheme'`) で**ユーザーが視覚的に 1 文字と認識する単位**で
 * 数えて切詰する。Node 16+ で利用可能。
 */
export function truncateSummary(text: string, max: number = MAX_SUMMARY_CHARS): string {
  if (!text) return '';
  // 防御の二重化: LLM が入力側のインジェクションに釣られて不可視文字を出力に
  // 含めた場合でも、vault に保存される summary には残さない。
  const cleaned = sanitizeForLLM(text);
  // 改行・タブを 1 つのスペースに圧縮
  const flat = cleaned.replace(/[\r\n\t]+/g, ' ').replace(/  +/g, ' ').trim();
  const seg = new Intl.Segmenter('ja', { granularity: 'grapheme' });
  const graphemes = Array.from(seg.segment(flat), s => s.segment);
  if (graphemes.length <= max) return flat;
  return graphemes.slice(0, max).join('');
}

/**
 * 単一ポストを要約。失敗時 null。テストから直接叩けるよう export。
 *
 * provider / model は `--x-bookmarks` 経由なら `pipeline_config.json::xSummary`
 * から渡される (cloud=Anthropic Haiku 4.5 がデフォルトのデフォルト)。
 */
export async function summarizeOnePost(
  text: string,
  options: {
    callAi?: (prompt: string, system: string) => Promise<string | null>;
    provider?: AiProvider;
    model?: string;
  } = {}
): Promise<string | null> {
  const call = options.callAi ?? ((p, s) => askAIText(p, s, 'fast', 400, {
    provider: options.provider,
    model: options.model,
  }));
  // 入力サニタイズ: 不可視 Unicode / Markdown コメントによる隠蔽プロンプト
  // インジェクション (LLM 攻撃ベクター "Hidden Markdown Instruction Injection")
  // 対策。ポスト本文は untrusted な外部入力なので LLM に渡す前に必ず通す。
  const safeText = sanitizeForLLM(text);
  const raw = await call(safeText, SYSTEM_PROMPT);
  if (!raw) return null;
  const truncated = truncateSummary(raw);
  return truncated || null;
}

/**
 * LLM の生応答から `{"summaries": [...]}` を頑健に抽出する。
 *
 * Local モデルは仕様外に code fence (```json ... ```) や前置きを付けがちなので、
 * - コードフェンス除去
 * - 最初の `{` から最後の `}` までを切り出して JSON.parse
 * の順で復旧を試みる。失敗時 null。
 */
export function parseBatchResponse(raw: string, expectedCount: number): string[] | null {
  if (!raw) return null;
  let text = raw.trim();
  // ```json ... ``` や ``` ... ``` を剥がす
  text = text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim();
  // 最初の `{` から最後の `}` までを切り出す (前置き / 後書きを除去)
  const first = text.indexOf('{');
  const last = text.lastIndexOf('}');
  if (first === -1 || last === -1 || last < first) return null;
  const sliced = text.slice(first, last + 1);
  let parsed: unknown;
  try {
    parsed = JSON.parse(sliced);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const arr = (parsed as { summaries?: unknown }).summaries;
  if (!Array.isArray(arr)) return null;
  if (arr.length !== expectedCount) return null;
  // 全要素 string であることを確認
  if (!arr.every(x => typeof x === 'string')) return null;
  return arr as string[];
}

/**
 * 複数ポストを 1 回の LLM 呼出で要約 (Local バッチ用)。
 *
 * 戻り値は items と同じ順序の配列。LLM 失敗 / JSON 不正 / 件数ミスマッチ時は
 * **全件 null** を返す (バッチ単位で best-effort 諦め → 次回 sync で再挑戦)。
 * 部分成功を許すと「どの要素が欠けたか」の対応付けが崩れるリスクがあるため
 * バッチ単位の all-or-nothing を採用。
 */
export async function summarizeBatchPosts(
  items: Array<{ tweet_id: string; text: string }>,
  options: {
    callAi?: (prompt: string, system: string) => Promise<string | null>;
    provider?: AiProvider;
    model?: string;
  } = {}
): Promise<Array<string | null>> {
  if (items.length === 0) return [];
  const call = options.callAi
    ?? ((p, s) => askAIText(p, s, 'fast', BATCH_TOKENS_PER_ITEM * items.length, {
      provider: options.provider,
      model: options.model,
    }));
  // 各ポストを `[N] 本文` で連結。区切りは `---` 行。
  // 多層サニタイズ:
  //   1. sanitizeForLLM: 不可視文字・HTML コメントによる隠蔽命令を除去
  //   2. escapeBatchItemBoundary: `\n---\n` 区切りと `[N]` ヘッダーの
  //      偽装を構造的に不可能にする (boundary injection 対策)。
  // 順序は固定: 不可視除去 → 構造エスケープ (順序逆だと不可視文字でエスケープを
  // バイパスされる可能性が残る)。
  const userPrompt = items
    .map((it, i) => `[${i + 1}]\n${escapeBatchItemBoundary(sanitizeForLLM(it.text))}`)
    .join('\n---\n');
  const raw = await call(userPrompt, BATCH_SYSTEM_PROMPT);
  if (!raw) return items.map(() => null);
  const summaries = parseBatchResponse(raw, items.length);
  if (!summaries) return items.map(() => null);
  return summaries.map(s => {
    const t = truncateSummary(s);
    return t || null;
  });
}

/**
 * `bookmarks.ai_summary IS NULL` の行を一括で要約。
 * sync 末尾から呼ばれる。失敗は warn ログのみで止めない。
 */
export async function summarizePendingBookmarks(
  options: SummarizeOptions = {}
): Promise<SummarizeStats> {
  const db = options.db ?? getDb();
  // 0 や負値が渡ると `for (i += step)` が進まず無限ループになる。必ず 1 以上にクランプ。
  const concurrency = Math.max(1, options.concurrency ?? DEFAULT_CONCURRENCY);
  const batchSize = Math.max(1, options.batchSize ?? DEFAULT_BATCH_SIZE);
  const callAi = options.callAi;
  const silent = options.silent ?? false;
  // X 要約は dedicated provider (xSummary.provider) を優先し、未指定なら
  // 旧挙動互換で AI_PROVIDER env を見る (classifier と共通の経路)。
  const provider = options.provider ?? (process.env.AI_PROVIDER as AiProvider | undefined);
  const model = options.model;
  const mode = resolveMode(options.mode, provider);

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
    const detail = mode === 'batch'
      ? `バッチ ${batchSize} 件/回 順次 (Local モデル向け)`
      : `${concurrency} 並列 (per-tweet)`;
    const target = `${provider ?? 'local'}${model ? ` / ${model}` : ''}`;
    console.log(`🤖 AI 要約を ${pending.length} 件 ${detail} で生成します (${target})...`);
  }

  if (mode === 'batch') {
    // Local バッチ: chunk を 1 プロンプトに詰めて 1 回 LLM 呼出 → 順次次の chunk へ
    for (let i = 0; i < pending.length; i += batchSize) {
      const chunk = pending.slice(i, i + batchSize);
      const items = chunk.map(row => ({
        tweet_id: row.tweet_id,
        text: (row.note_tweet_text ?? row.tweet_text ?? '').trim(),
      }));
      // 空本文行はバッチに含めても LLM が混乱するので分離 (failed に計上)
      const fillable = items.filter(it => it.text.length > 0);
      const empties = items.filter(it => it.text.length === 0);
      stats.failed += empties.length;

      if (fillable.length > 0) {
        const summaries = await summarizeBatchPosts(
          fillable,
          callAi ? { callAi } : { provider, model }
        );
        for (let j = 0; j < fillable.length; j++) {
          const s = summaries[j];
          if (s) {
            db.setAiSummary(fillable[j].tweet_id, s);
            stats.succeeded++;
          } else {
            stats.failed++;
          }
        }
      }
      if (!silent) {
        const done = Math.min(i + batchSize, pending.length);
        console.log(`   ... ${done}/${pending.length} (成功 ${stats.succeeded} / 失敗 ${stats.failed})`);
      }
    }
    return stats;
  }

  // Inline モード (cloud): chunk 内は Promise.all で並列、chunk 間は順次。
  for (let i = 0; i < pending.length; i += concurrency) {
    const chunk = pending.slice(i, i + concurrency);
    const results = await Promise.all(
      chunk.map(async row => {
        const text = (row.note_tweet_text ?? row.tweet_text ?? '').trim();
        if (!text) return { tweet_id: row.tweet_id, ok: false };
        const summary = await summarizeOnePost(
          text,
          callAi ? { callAi } : { provider, model }
        );
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
