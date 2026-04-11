import { FAST_MODEL_CHAR_THRESHOLD, MODELS, MODEL_PRICING } from '../shared/constants';
import { loadConfig } from '../shared/config';
import type {
  Message,
  VideoInfoPayload,
  TranscriptPayload,
  VideoMetadata,
} from '../shared/types';

// --- DOM Elements ---

const noVideoEl = document.getElementById('no-video') as HTMLDivElement;
const videoInfoEl = document.getElementById('video-info') as HTMLDivElement;
const videoTitleEl = document.getElementById('video-title') as HTMLHeadingElement;
const videoChannelEl = document.getElementById('video-channel') as HTMLSpanElement;
const videoDurationEl = document.getElementById('video-duration') as HTMLSpanElement;
const videoLangEl = document.getElementById('video-lang') as HTMLSpanElement;

const noTranscriptEl = document.getElementById('no-transcript') as HTMLDivElement;
const preAnalysisEl = document.getElementById('pre-analysis') as HTMLDivElement;
const estimateModelEl = document.getElementById('estimate-model') as HTMLSpanElement;
const estimateCostEl = document.getElementById('estimate-cost') as HTMLSpanElement;
const analyzeBtnEl = document.getElementById('analyze-btn') as HTMLButtonElement;

const analyzingEl = document.getElementById('analyzing') as HTMLDivElement;
const analysisDoneEl = document.getElementById('analysis-done') as HTMLDivElement;
const resultModelEl = document.getElementById('result-model') as HTMLSpanElement;
const resultTokensEl = document.getElementById('result-tokens') as HTMLSpanElement;
const previewEl = document.getElementById('preview') as HTMLDivElement;
const downloadBtnEl = document.getElementById('download-btn') as HTMLButtonElement;
const copyBtnEl = document.getElementById('copy-btn') as HTMLButtonElement;

const errorStateEl = document.getElementById('error-state') as HTMLDivElement;
const errorMessageEl = document.getElementById('error-message') as HTMLParagraphElement;
const retryBtnEl = document.getElementById('retry-btn') as HTMLButtonElement;

const settingsLinkEl = document.getElementById('settings-link') as HTMLAnchorElement;

// --- State ---

let currentMetadata: VideoMetadata | null = null;
let currentTranscript: TranscriptPayload | null = null;
let currentMarkdown: string = '';
let currentFilename: string = '';

// --- Helpers ---

function showState(state: 'no-video' | 'video-info'): void {
  noVideoEl.hidden = state !== 'no-video';
  videoInfoEl.hidden = state !== 'video-info';
}

function showSubState(
  sub: 'no-transcript' | 'pre-analysis' | 'analyzing' | 'analysis-done' | 'error',
): void {
  noTranscriptEl.hidden = sub !== 'no-transcript';
  preAnalysisEl.hidden = sub !== 'pre-analysis';
  analyzingEl.hidden = sub !== 'analyzing';
  analysisDoneEl.hidden = sub !== 'analysis-done';
  errorStateEl.hidden = sub !== 'error';
}

async function sendMessage<T = unknown>(message: Message): Promise<Message<T>> {
  return chrome.runtime.sendMessage(message);
}

// --- Initialization ---

async function init(): Promise<void> {
  // 動画情報を取得
  const videoInfoResponse = await sendMessage<VideoInfoPayload | null>({
    type: 'GET_VIDEO_INFO',
    payload: null,
  });

  const videoInfo = videoInfoResponse.payload as VideoInfoPayload | null;

  if (!videoInfo || !videoInfo.metadata.videoId) {
    showState('no-video');
    return;
  }

  // 動画情報を表示
  showState('video-info');
  currentMetadata = videoInfo.metadata;
  videoTitleEl.textContent = videoInfo.metadata.title;
  videoChannelEl.textContent = videoInfo.metadata.channel;
  videoDurationEl.textContent = videoInfo.metadata.duration || '';
  videoLangEl.textContent = videoInfo.availableLanguages.length > 0
    ? `字幕: ${videoInfo.availableLanguages.join(', ')}`
    : '字幕なし';

  if (!videoInfo.hasTranscript) {
    showSubState('no-transcript');
    return;
  }

  // トランスクリプトを先行取得
  const transcriptResponse = await sendMessage<TranscriptPayload | null>({
    type: 'EXTRACT_TRANSCRIPT',
    payload: null,
  });

  currentTranscript = transcriptResponse.payload as TranscriptPayload | null;

  if (!currentTranscript) {
    showSubState('no-transcript');
    return;
  }

  // コスト見積もりを表示
  await updateCostEstimate();
  showSubState('pre-analysis');
}

async function updateCostEstimate(): Promise<void> {
  if (!currentTranscript) return;

  const config = await loadConfig();
  const charCount = currentTranscript.fullText.length;
  const isJapanese = /[\u3000-\u9fff]/.test(currentTranscript.fullText);
  const tokensPerChar = isJapanese ? 1.5 : 0.4;
  const estimatedInputTokens = Math.ceil(charCount * tokensPerChar) + 500;

  const useSmartModel = !config.autoSelectModel || charCount > FAST_MODEL_CHAR_THRESHOLD;
  const selectedModelId = useSmartModel ? config.smartModel : config.fastModel;
  const modelInfo = MODEL_PRICING[selectedModelId] || (useSmartModel ? MODELS.smart : MODELS.fast);
  const inputCost = (estimatedInputTokens / 1_000_000) * modelInfo.inputPricePer1M;
  const outputCost = (4000 / 1_000_000) * modelInfo.outputPricePer1M;

  estimateModelEl.textContent = modelInfo.label;
  estimateCostEl.textContent = `推定コスト: $${(inputCost + outputCost).toFixed(4)}`;
}

// --- Event Handlers ---

analyzeBtnEl.addEventListener('click', async () => {
  if (!currentMetadata || !currentTranscript) return;

  const config = await loadConfig();
  if (!config.apiKey) {
    showSubState('error');
    errorMessageEl.textContent = 'APIキーが設定されていません。設定画面で入力してください。';
    return;
  }

  showSubState('analyzing');

  const response = await sendMessage<{
    markdown?: string;
    filename?: string;
    analysis?: { model: string; inputTokens: number; outputTokens: number };
    error?: string;
  }>({
    type: 'ANALYZE_TRANSCRIPT',
    payload: {
      metadata: currentMetadata,
      transcript: currentTranscript,
    },
  });

  if (response.type === 'ANALYSIS_ERROR') {
    const errorPayload = response.payload as { error: string };
    showSubState('error');
    errorMessageEl.textContent = errorPayload.error;
    return;
  }

  const result = response.payload as {
    markdown: string;
    filename: string;
    analysis: { model: string; inputTokens: number; outputTokens: number };
  };

  currentMarkdown = result.markdown;
  currentFilename = result.filename;

  // 結果サマリー表示
  resultModelEl.textContent = result.analysis.model;
  resultTokensEl.textContent = `${result.analysis.inputTokens.toLocaleString()} in / ${result.analysis.outputTokens.toLocaleString()} out`;

  // プレビュー（先頭500文字）
  const previewText = currentMarkdown.slice(0, 500);
  previewEl.textContent = previewText + (currentMarkdown.length > 500 ? '...' : '');

  showSubState('analysis-done');
});

downloadBtnEl.addEventListener('click', async () => {
  if (!currentMarkdown || !currentFilename) return;

  await sendMessage({
    type: 'DOWNLOAD_MD',
    payload: { markdown: currentMarkdown, filename: currentFilename },
  });
});

copyBtnEl.addEventListener('click', async () => {
  if (!currentMarkdown) return;

  try {
    await navigator.clipboard.writeText(currentMarkdown);
    copyBtnEl.textContent = 'コピーしました';
    setTimeout(() => {
      copyBtnEl.textContent = 'クリップボードにコピー';
    }, 2000);
  } catch {
    copyBtnEl.textContent = 'コピー失敗';
    setTimeout(() => {
      copyBtnEl.textContent = 'クリップボードにコピー';
    }, 2000);
  }
});

retryBtnEl.addEventListener('click', () => {
  if (currentTranscript) {
    showSubState('pre-analysis');
  } else {
    init();
  }
});

settingsLinkEl.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

// --- Start ---

init();
