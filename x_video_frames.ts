/**
 * X ブックマーク動画 → キーフレーム webp 抽出。
 *
 * 設計思想:
 *   - opt-in (`X_VIDEO_FRAMES=true` のときだけ動作)
 *   - graceful degrade: ffmpeg 不在 / DL 失敗 / size 超過は本文保存を妨げない
 *   - idempotent: 同じ post_id でフレーム既存なら DL/抽出スキップ
 *   - Tier 0 (等間隔サンプル): 重要度推論なし、動画長を均等分割した時刻で frame 取得
 *
 * 保存パス:
 *   <vault>/_attachments/x-bookmarks/<post_id>/source.mp4   (一次・抽出後に削除)
 *   <vault>/_attachments/x-bookmarks/<post_id>/frame-NN.webp (抽出結果・vault 内に永続)
 *
 * source.mp4 はフレーム抽出後に best-effort で削除する (vault 内 disk leak 回避)。
 * frame-NN.webp は意図的に vault 内に残し、Obsidian の preview から参照される。
 *
 * Markdown 埋め込み:
 *   ## キーフレーム (動画 0:18)
 *   ![[_attachments/x-bookmarks/123/frame-01.webp|360]] _0:01_
 *   ...
 */

import fs from 'fs';
import path from 'path';
import { spawn, spawnSync } from 'child_process';
import { getVaultRoot } from './config';
import type { XMediaResponse, XMediaVariant } from './x_bookmarks_api';

// API 型を再 export (呼び出し側の便宜)
export type XMedia = XMediaResponse;
export type XVideoVariant = XMediaVariant;

export interface VideoFrameResult {
  /** 抽出済みフレーム情報。skipped !== undefined のときは空配列。 */
  frames: Array<{
    /** 絶対パス (ローカル fs アクセス用) */
    absolutePath: string;
    /** Vault ルート相対 (.md の Wikilink で使う) */
    vaultRelative: string;
    /** タイムスタンプ秒 (ヘッダ表示用) */
    timestampSec: number;
  }>;
  /** 動画長(秒)。skipped でも判明していれば返す。 */
  durationSec?: number;
  /** スキップ理由。本文保存は継続される。 */
  skipped?:
    | 'feature_disabled'
    | 'no_video_variant'
    | 'no_duration'
    | 'too_long'
    | 'too_large'
    | 'download_failed'
    | 'ffmpeg_missing'
    | 'ffmpeg_failed'
    | 'already_exists';
  /** ユーザー向け補足メッセージ (skip 理由の詳細) */
  message?: string;
}

export interface ExtractFramesOptions {
  /** 動画長の上限 (秒)。超過したら skip。既定 60 */
  maxDurationSec?: number;
  /** 抽出フレーム数。等間隔サンプル。既定 4 */
  frameCount?: number;
  /** 動画 mp4 のサイズ上限 (MB)。HEAD で確認できれば事前 skip。既定 30 */
  maxSizeMb?: number;
  /** ログ出力フック */
  logger?: (msg: string) => void;
  /** vault ルート override (テスト用)。無ければ getVaultRoot() */
  vaultRoot?: string;
  /** ffmpeg バイナリパス override (テスト用) */
  ffmpegPath?: string;
}

const DEFAULT_OPTS = {
  maxDurationSec: 60,
  frameCount: 4,
  maxSizeMb: 30,
};

/**
 * 環境変数で feature が有効か判定。
 * `X_VIDEO_FRAMES=true` (または `1`) で opt-in、それ以外は OFF。
 */
export function isVideoFramesEnabled(): boolean {
  const v = (process.env.X_VIDEO_FRAMES ?? '').trim().toLowerCase();
  return v === 'true' || v === '1';
}

/**
 * media[] から動画 (type === 'video' or 'animated_gif') を 1 件選ぶ。
 * 複数あれば最初の 1 件のみ。Phase A スコープでは「主動画 1 本のみ」を扱う。
 */
export function pickVideoMedia(media: XMedia[] | undefined): XMedia | undefined {
  if (!media || media.length === 0) return undefined;
  return media.find(m => m.type === 'video' || m.type === 'animated_gif');
}

/**
 * variants[] から最高 bit_rate の URL を選ぶ。
 * animated_gif は variants がなく url を直に持つ場合がある。
 */
export function pickBestVariantUrl(media: XMedia): string | undefined {
  if (media.variants && media.variants.length > 0) {
    const sorted = [...media.variants].sort(
      (a, b) => (b.bit_rate ?? 0) - (a.bit_rate ?? 0)
    );
    return sorted[0]?.url;
  }
  // animated_gif fallback
  return undefined;
}

/**
 * Tier 0: 動画長を frameCount+1 等分し、その境界で frame を抽出する。
 * 例: duration=20s, frameCount=4 → [4, 8, 12, 16] 秒
 */
export function computeSampleTimestamps(durationSec: number, frameCount: number): number[] {
  if (durationSec <= 0 || frameCount <= 0) return [];
  const out: number[] = [];
  for (let i = 1; i <= frameCount; i++) {
    out.push((durationSec * i) / (frameCount + 1));
  }
  return out;
}

function formatTimestamp(sec: number): string {
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${m}:${s.toString().padStart(2, '0')}`;
}

/**
 * ffmpeg バイナリ存在確認。`ffmpeg -version` が exit 0 で返るかで判定。
 */
function ffmpegAvailable(ffmpegPath: string): boolean {
  try {
    const r = spawnSync(ffmpegPath, ['-version'], { stdio: 'ignore' });
    return r.status === 0;
  } catch {
    return false;
  }
}

// X CDN は UA 無しの bot を弾くことがあるので HEAD/GET 両方に同じ UA を付与。
const FETCH_UA = 'obsidian-ai-pipeline/1.0 (+https://github.com/theosera/obsidian-ai-pipeline)';
const HEAD_TIMEOUT_MS = 10_000;
const GET_TIMEOUT_MS = 60_000;

/**
 * 動画 URL を mp4 として保存。
 *
 * - HEAD で Content-Length が返ればサイズ事前 cap。HEAD が 4xx/5xx/timeout でも GET を継続。
 * - GET は AbortSignal で timeout、ストリーミング読み込みで `maxSizeMb` を逐次チェック
 *   (Content-Length 不在の悪性応答での memory blowup を防ぐ)。
 * - 失敗時は destPath を delete してから throw (呼び出し側 graceful skip 用)。
 */
async function downloadVideo(
  url: string,
  destPath: string,
  maxSizeMb: number
): Promise<void> {
  const maxBytes = maxSizeMb * 1024 * 1024;

  // HEAD pre-check (失敗は GET に進む。ただし「サイズ超過」エラーだけは伝播)
  try {
    const head = await fetch(url, {
      method: 'HEAD',
      headers: { 'User-Agent': FETCH_UA },
      signal: AbortSignal.timeout(HEAD_TIMEOUT_MS),
    });
    const len = head.headers.get('content-length');
    if (len && Number(len) > maxBytes) {
      throw new Error(`video size ${(Number(len) / 1024 / 1024).toFixed(1)}MB exceeds ${maxSizeMb}MB cap`);
    }
  } catch (e: any) {
    if (/exceeds.*cap/.test(String(e?.message))) throw e;
    // HEAD timeout / 405 / 4xx は GET で再試行
  }

  const res = await fetch(url, {
    headers: { 'User-Agent': FETCH_UA },
    signal: AbortSignal.timeout(GET_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${url}`);
  }
  if (!res.body) {
    throw new Error('empty response body');
  }

  // ストリーミング読み込み: 1 chunk ごとに累計サイズチェック → 上限超過なら中断
  const writer = fs.createWriteStream(destPath);
  const reader = res.body.getReader();
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        // 上限超過: reader/writer を破棄、partial file 削除
        try { await reader.cancel(); } catch { /* noop */ }
        throw new Error(
          `video streaming exceeded ${maxSizeMb}MB cap (received ${(received / 1024 / 1024).toFixed(1)}MB)`
        );
      }
      writer.write(Buffer.from(value));
    }
    await new Promise<void>((resolve, reject) => {
      writer.end((err: NodeJS.ErrnoException | null | undefined) => err ? reject(err) : resolve());
    });
  } catch (e) {
    // partial file をクリーンアップ
    try { writer.destroy(); } catch { /* noop */ }
    if (fs.existsSync(destPath)) {
      try { fs.unlinkSync(destPath); } catch { /* noop */ }
    }
    throw e;
  }
}

/**
 * ffmpeg で 1 frame webp を生成。timeoutMs 内に終わらなければ kill。
 * 戻り値は子プロセス exit code (0 が成功)。
 */
async function extractOneFrame(
  ffmpegPath: string,
  inputMp4: string,
  timestampSec: number,
  outWebp: string,
  timeoutMs = 15_000
): Promise<number> {
  return new Promise((resolve) => {
    const proc = spawn(ffmpegPath, [
      '-y',
      '-ss', String(timestampSec),
      '-i', inputMp4,
      '-frames:v', '1',
      '-vf', "scale='min(720,iw)':-2",
      '-c:v', 'libwebp',
      '-quality', '75',
      outWebp,
    ], { stdio: 'ignore' });

    const timer = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch { /* noop */ }
      resolve(124); // timeout
    }, timeoutMs);

    proc.on('exit', (code) => {
      clearTimeout(timer);
      resolve(code ?? -1);
    });
    proc.on('error', () => {
      clearTimeout(timer);
      resolve(-1);
    });
  });
}

/**
 * 既に抽出済みフレームがあれば再生成をスキップ。
 * frame-01.webp が存在し、かつ frameCount 個揃っているかをチェック。
 */
function alreadyExtracted(dir: string, frameCount: number): boolean {
  for (let i = 1; i <= frameCount; i++) {
    const p = path.join(dir, `frame-${String(i).padStart(2, '0')}.webp`);
    if (!fs.existsSync(p)) return false;
  }
  return true;
}

/**
 * メイン API: ツイート 1 件分の動画キーフレームを抽出する。
 *
 * 失敗時は `skipped` フィールドにエラー種別を入れて返す (例外を投げない)。
 * 呼び出し側 (tweetToApiBookmark など) は `result.frames` を使い、
 * `skipped` があれば本文に「フレーム取得失敗」セクションを出すか判断する。
 */
export async function extractFramesFromTweetVideo(
  postId: string,
  videoUrl: string,
  durationMs: number,
  options: ExtractFramesOptions = {}
): Promise<VideoFrameResult> {
  const opts = { ...DEFAULT_OPTS, ...options };
  const log = opts.logger ?? (() => {});
  const vaultRoot = opts.vaultRoot ?? getVaultRoot();
  const ffmpegPath = opts.ffmpegPath ?? 'ffmpeg';

  if (!isVideoFramesEnabled()) {
    return { frames: [], skipped: 'feature_disabled' };
  }

  // duration_ms が API から返らない video もある。等間隔サンプルが計算できないので
  // この場合は明示的に skip 表示 (silently skip ではなく失敗を本文上で見えるように)
  if (!durationMs || durationMs <= 0) {
    return {
      frames: [],
      skipped: 'no_duration',
      message: 'API が duration_ms を返さなかったため等間隔サンプルが計算できません',
    };
  }

  const durationSec = durationMs / 1000;
  if (durationSec > opts.maxDurationSec) {
    return {
      frames: [],
      durationSec,
      skipped: 'too_long',
      message: `${durationSec.toFixed(1)}s > ${opts.maxDurationSec}s cap`,
    };
  }

  const safePostId = postId.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
  const attachDir = path.join(vaultRoot, '_attachments', 'x-bookmarks', safePostId);
  const vaultRelDir = path.posix.join('_attachments', 'x-bookmarks', safePostId);

  // idempotent skip: 既に全フレーム揃っていれば再 DL/抽出しない
  if (alreadyExtracted(attachDir, opts.frameCount)) {
    log(`   ⏭️  キーフレーム既存: ${vaultRelDir}`);
    const timestamps = computeSampleTimestamps(durationSec, opts.frameCount);
    return {
      frames: timestamps.map((t, i) => ({
        absolutePath: path.join(attachDir, `frame-${String(i + 1).padStart(2, '0')}.webp`),
        vaultRelative: path.posix.join(vaultRelDir, `frame-${String(i + 1).padStart(2, '0')}.webp`),
        timestampSec: t,
      })),
      durationSec,
      skipped: 'already_exists',
    };
  }

  if (!ffmpegAvailable(ffmpegPath)) {
    return {
      frames: [],
      durationSec,
      skipped: 'ffmpeg_missing',
      message: `ffmpeg バイナリが見つかりません (path=${ffmpegPath}). brew install ffmpeg などで導入してください`,
    };
  }

  fs.mkdirSync(attachDir, { recursive: true });
  const sourceMp4 = path.join(attachDir, 'source.mp4');

  // source.mp4 は extraction 用の一時ファイル。終了時 (成功/失敗どちらも)
  // best-effort で削除して vault 内 disk leak を防ぐ。
  const cleanupSource = () => {
    if (fs.existsSync(sourceMp4)) {
      try { fs.unlinkSync(sourceMp4); } catch { /* best-effort */ }
    }
  };

  try {
    log(`   📥 動画 DL: ${videoUrl.split('?')[0]} → ${sourceMp4}`);
    await downloadVideo(videoUrl, sourceMp4, opts.maxSizeMb);
  } catch (e: any) {
    const msg = String(e?.message ?? e);
    cleanupSource();
    return {
      frames: [],
      durationSec,
      skipped: /exceeds.*cap/.test(msg) ? 'too_large' : 'download_failed',
      message: msg,
    };
  }

  const timestamps = computeSampleTimestamps(durationSec, opts.frameCount);
  const frames: VideoFrameResult['frames'] = [];
  for (let i = 0; i < timestamps.length; i++) {
    const t = timestamps[i];
    const fileName = `frame-${String(i + 1).padStart(2, '0')}.webp`;
    const outPath = path.join(attachDir, fileName);
    log(`   🎞️  frame ${i + 1}/${timestamps.length} @ ${formatTimestamp(t)}`);
    const code = await extractOneFrame(ffmpegPath, sourceMp4, t, outPath);
    if (code !== 0 || !fs.existsSync(outPath)) {
      // 部分成功で frames を返すと renderKeyFramesSection が「成功」と
      // 解釈してしまい、本文上で抽出失敗が見えなくなる。失敗時は frames を
      // 空配列で返し、呼び出し側で必ず「取得失敗」見出しが出るようにする。
      // (ディスクに残った partial frame は次回 alreadyExtracted=false で
      //  再抽出のリトライ対象になる)
      cleanupSource();
      return {
        frames: [],
        durationSec,
        skipped: 'ffmpeg_failed',
        message: `frame ${i + 1} extraction failed (exit=${code})`,
      };
    }
    frames.push({
      absolutePath: outPath,
      vaultRelative: path.posix.join(vaultRelDir, fileName),
      timestampSec: t,
    });
  }

  // 全フレーム抽出成功: source.mp4 はもう不要なので削除して vault 内 disk leak 回避
  cleanupSource();
  return { frames, durationSec };
}

/**
 * フレーム結果を Markdown セクションに整形する。
 * 抽出成功時:
 *   ## キーフレーム (動画 0:18)
 *   ![[_attachments/.../frame-01.webp|360]] _0:01_
 *   ...
 * 抽出失敗時:
 *   ## キーフレーム (取得失敗: <reason>)
 * `frames` 空かつ `skipped === 'feature_disabled'` の場合は空文字を返す
 * (本文に何も追記しない)。
 */
export function renderKeyFramesSection(result: VideoFrameResult): string {
  if (result.skipped === 'feature_disabled') return '';
  if (result.frames.length === 0) {
    const dur = result.durationSec ? ` (${formatTimestamp(result.durationSec)})` : '';
    const reason = result.skipped ?? 'unknown';
    const detail = result.message ? `: ${result.message}` : '';
    return `\n\n## キーフレーム${dur} 取得失敗 (${reason}${detail})\n`;
  }
  const dur = result.durationSec ? formatTimestamp(result.durationSec) : '?';
  const lines = result.frames.map(f => {
    const ts = formatTimestamp(f.timestampSec);
    return `![[${f.vaultRelative}|360]] _${ts}_`;
  });
  return `\n\n## キーフレーム (動画 ${dur})\n\n${lines.join('\n')}\n`;
}

/** テスト用 export */
export const __test = {
  computeSampleTimestamps,
  pickVideoMedia,
  pickBestVariantUrl,
  isVideoFramesEnabled,
  formatTimestamp,
  alreadyExtracted,
  renderKeyFramesSection,
};
