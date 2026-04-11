import { extractVideoMetadata } from './video-metadata';
import {
  getCaptionTracks,
  getAvailableLanguages,
  selectBestTrack,
  fetchTranscript,
  segmentsToFullText,
} from './transcript-extractor';
import type { Message, VideoInfoPayload, TranscriptPayload } from '../shared/types';

/**
 * YouTube動画ページのContent Script。
 * service workerからのメッセージに応答して動画情報とトランスクリプトを返す。
 */

let cachedTracks: ReturnType<typeof getCaptionTracks> | null = null;

function resetCache(): void {
  cachedTracks = null;
}

/** ページがYouTube動画ページかどうかを判定 */
function isVideoPage(): boolean {
  return window.location.pathname === '/watch' && !!new URL(window.location.href).searchParams.get('v');
}

/** メッセージハンドラー */
chrome.runtime.onMessage.addListener(
  (message: Message, _sender, sendResponse: (response: Message) => void) => {
    if (!isVideoPage()) {
      sendResponse({ type: 'VIDEO_INFO_RESULT', payload: null });
      return true;
    }

    if (message.type === 'GET_VIDEO_INFO') {
      handleGetVideoInfo().then(sendResponse);
      return true; // 非同期レスポンスを示す
    }

    if (message.type === 'EXTRACT_TRANSCRIPT') {
      handleExtractTranscript().then(sendResponse);
      return true;
    }

    return false;
  }
);

async function handleGetVideoInfo(): Promise<Message<VideoInfoPayload | null>> {
  try {
    const metadata = extractVideoMetadata();
    const tracks = getCaptionTracks();
    cachedTracks = tracks;

    const bestTrack = selectBestTrack(tracks);
    if (bestTrack) {
      metadata.language = bestTrack.languageCode;
    }

    return {
      type: 'VIDEO_INFO_RESULT',
      payload: {
        metadata,
        hasTranscript: tracks.length > 0,
        availableLanguages: getAvailableLanguages(tracks),
      },
    };
  } catch (e) {
    console.error('[YT Transcript] 動画情報取得失敗:', e);
    return { type: 'VIDEO_INFO_RESULT', payload: null };
  }
}

async function handleExtractTranscript(): Promise<Message<TranscriptPayload | null>> {
  try {
    const tracks = cachedTracks || getCaptionTracks();
    const bestTrack = selectBestTrack(tracks);

    if (!bestTrack) {
      return {
        type: 'TRANSCRIPT_RESULT',
        payload: null,
      };
    }

    const segments = await fetchTranscript(bestTrack);
    const fullText = segmentsToFullText(segments);

    return {
      type: 'TRANSCRIPT_RESULT',
      payload: {
        segments,
        language: bestTrack.languageCode,
        fullText,
      },
    };
  } catch (e) {
    console.error('[YT Transcript] トランスクリプト取得失敗:', e);
    return { type: 'TRANSCRIPT_RESULT', payload: null };
  }
}

// YouTube SPA遷移を検知してキャッシュをリセット
document.addEventListener('yt-navigate-finish', () => {
  resetCache();
});

// 初期化ログ
if (isVideoPage()) {
  console.log('[YT Transcript Analyzer] Content script loaded on video page');
}
