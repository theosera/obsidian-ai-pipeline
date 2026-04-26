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
 *   <vault>/_attachments/x-bookmarks/<post_id>/source.mp4   (一次)
 *   <vault>/_attachments/x-bookmarks/<post_id>/frame-NN.webp (抽出結果)
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

/**
 * 動画 URL を mp4 として保存。HEAD で size 取得できれば事前 cap。
 * 失敗時は file は残さず例外を伝播する (呼び出し側で graceful skip)。
 */
async function downloadVideo(
  url: string,
  destPath: string,
  maxSizeMb: number
): Promise<void> {
  // HEAD でサイズチェック (X CDN は Content-Length を返す)
  try {
    const head = await fetch(url, { method: 'HEAD' });
    const len = head.headers.get('content-length');
    if (len && Number(len) > maxSizeMb * 1024 * 1024) {
      throw new Error(`video size ${(Number(len) / 1024 / 1024).toFixed(1)}MB exceeds ${maxSizeMb}MB cap`);
    }
  } catch (e: any) {
    // HEAD 不可な CDN もあるので失敗は警告のみ。GET は試行する。
    if (/exceeds.*cap/.test(String(e?.message))) {
      throw e;
    }
  }

  const res = await fetch(url, {
    headers: {
      // X CDN は UA 無しの bot を弾くことがあるので User-Agent を付与
      'User-Agent': 'obsidian-ai-pipeline/1.0 (+https://github.com/theosera/obsidian-ai-pipeline)',
    },
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${url}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxSizeMb * 1024 * 1024) {
    throw new Error(`video size ${(buf.length / 1024 / 1024).toFixed(1)}MB exceeds ${maxSizeMb}MB cap`);
  }
  fs.writeFileSync(destPath, buf);
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

  try {
    log(`   📥 動画 DL: ${videoUrl.split('?')[0]} → ${sourceMp4}`);
    await downloadVideo(videoUrl, sourceMp4, opts.maxSizeMb);
  } catch (e: any) {
    const msg = String(e?.message ?? e);
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
      return {
        frames,
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
