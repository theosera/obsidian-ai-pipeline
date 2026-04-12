import { analyzeTranscript } from './ai-client';
import { buildMarkdownFile } from './markdown-generator';
import { loadConfig } from '../shared/config';
import type {
  Message,
  AnalyzePayload,
  DownloadPayload,
} from '../shared/types';

/**
 * Service Worker: Chrome拡張のバックグラウンドプロセス。
 * content script ↔ popup 間のメッセージルーティングとAPI呼び出しを担当。
 */

// --- Message Routing ---

chrome.runtime.onMessage.addListener(
  (message: Message, sender, sendResponse: (response: Message) => void) => {
    handleMessage(message, sender).then(sendResponse);
    return true; // 非同期レスポンスを示す
  }
);

async function handleMessage(
  message: Message,
  _sender: chrome.runtime.MessageSender,
): Promise<Message> {
  switch (message.type) {
    case 'GET_VIDEO_INFO':
      return forwardToContentScript(message);

    case 'EXTRACT_TRANSCRIPT':
      return forwardToContentScript(message);

    case 'ANALYZE_TRANSCRIPT':
      return handleAnalyze(message.payload as AnalyzePayload);

    case 'DOWNLOAD_MD':
      return handleDownload(message.payload as DownloadPayload);

    default:
      return { type: 'ANALYSIS_ERROR', payload: { error: `未知のメッセージタイプ: ${message.type}` } };
  }
}

/** アクティブなYouTubeタブのcontent scriptにメッセージを転送 */
async function forwardToContentScript(message: Message): Promise<Message> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];

  if (!tab?.id || !tab.url?.includes('youtube.com/watch')) {
    return {
      type: 'VIDEO_INFO_RESULT',
      payload: null,
    };
  }

  try {
    const response = await chrome.tabs.sendMessage(tab.id, message);
    return response;
  } catch (e) {
    console.error('[Service Worker] content script通信失敗:', e);
    return {
      type: message.type === 'GET_VIDEO_INFO' ? 'VIDEO_INFO_RESULT' : 'TRANSCRIPT_RESULT',
      payload: null,
    };
  }
}

/** トランスクリプトをAI分析してマークダウンを生成 */
async function handleAnalyze(payload: AnalyzePayload): Promise<Message> {
  try {
    const config = await loadConfig();

    if (!config.apiKey) {
      return {
        type: 'ANALYSIS_ERROR',
        payload: { error: 'APIキーが設定されていません。設定画面からAnthropicのAPIキーを入力してください。' },
      };
    }

    const analysis = await analyzeTranscript(
      payload.transcript.fullText,
      config,
    );

    const { markdown, filename } = buildMarkdownFile(
      payload.metadata,
      payload.transcript,
      analysis,
      config.includeRawTranscript,
    );

    return {
      type: 'ANALYSIS_RESULT',
      payload: { markdown, filename, analysis },
    };
  } catch (e) {
    const errorMessage = e instanceof Error ? e.message : '不明なエラーが発生しました';
    console.error('[Service Worker] 分析失敗:', e);
    return {
      type: 'ANALYSIS_ERROR',
      payload: { error: errorMessage },
    };
  }
}

/** マークダウンファイルをダウンロード */
async function handleDownload(payload: DownloadPayload): Promise<Message> {
  try {
    const blob = new Blob([payload.markdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);

    await chrome.downloads.download({
      url,
      filename: payload.filename,
      saveAs: true,
    });

    // Blob URLは後でクリーンアップされる
    setTimeout(() => URL.revokeObjectURL(url), 60000);

    return {
      type: 'ANALYSIS_RESULT',
      payload: { success: true },
    };
  } catch (e) {
    const errorMessage = e instanceof Error ? e.message : 'ダウンロード失敗';
    return {
      type: 'ANALYSIS_ERROR',
      payload: { error: errorMessage },
    };
  }
}

// Service Worker 起動ログ
console.log('[YT Transcript Analyzer] Service worker loaded');
