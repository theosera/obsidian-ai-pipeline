import { ANTHROPIC_API_URL, ANTHROPIC_VERSION, FAST_MODEL_CHAR_THRESHOLD, MODELS, MODEL_PRICING } from '../shared/constants';
import { SYSTEM_PROMPT, buildUserPrompt } from '../shared/prompts/transcript-analysis';
import type { AnalysisResult, ExtensionConfig } from '../shared/types';

/**
 * Anthropic REST APIを直接呼び出してトランスクリプトを分析する。
 * ブラウザ環境のため @anthropic-ai/sdk は使わず fetch を使用。
 * パイプラインの classifier.ts:303-320 のパターンを踏襲。
 */
export async function analyzeTranscript(
  transcriptText: string,
  config: ExtensionConfig,
): Promise<AnalysisResult> {
  const model = selectModel(transcriptText, config);
  const userPrompt = buildUserPrompt(transcriptText);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120_000); // 2分タイムアウト

  let response: Response;
  try {
    response = await fetch(ANTHROPIC_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': config.apiKey,
        'anthropic-version': ANTHROPIC_VERSION,
        'anthropic-dangerous-direct-browser-access': 'true',
      },
      body: JSON.stringify({
        model,
        max_tokens: 8192,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: userPrompt }],
      }),
      signal: controller.signal,
    });
  } catch (e) {
    clearTimeout(timeoutId);
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new Error('APIリクエストがタイムアウトしました（2分）。再試行してください。');
    }
    throw e;
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    if (response.status === 401) {
      throw new Error('API認証エラー: APIキーが無効です。設定画面で正しいキーを入力してください。');
    }
    if (response.status === 429) {
      throw new Error('APIレート制限: しばらく待ってから再試行してください。');
    }
    throw new Error(`API呼び出し失敗 (${response.status}): ${errorBody.slice(0, 200)}`);
  }

  const data = await response.json();

  const textContent = data.content?.find(
    (block: { type: string }) => block.type === 'text'
  );

  if (!textContent?.text) {
    throw new Error('AIからの応答が空です。');
  }

  return {
    markdown: textContent.text,
    model,
    inputTokens: data.usage?.input_tokens || 0,
    outputTokens: data.usage?.output_tokens || 0,
  };
}

/**
 * 二段階モデル選択: パイプラインの思想に従い、
 * 短いトランスクリプトにはFastモデル、長いものにはSmartモデルを使用。
 */
function selectModel(transcriptText: string, config: ExtensionConfig): string {
  if (!config.autoSelectModel) {
    // 手動選択モードでは smartModel を使用
    return config.smartModel || MODELS.smart.id;
  }

  const charCount = transcriptText.length;
  if (charCount <= FAST_MODEL_CHAR_THRESHOLD) {
    return config.fastModel || MODELS.fast.id;
  }
  return config.smartModel || MODELS.smart.id;
}

/**
 * トランスクリプトの推定トークン数とコストを計算する。
 * 日本語テキストは平均1文字≈1.5トークンとして概算。
 */
export function estimateCost(transcriptText: string, config: ExtensionConfig): {
  model: string;
  modelLabel: string;
  estimatedInputTokens: number;
  estimatedCost: string;
} {
  const model = selectModel(transcriptText, config);
  const isJapanese = /[\u3000-\u9fff]/.test(transcriptText);
  const tokensPerChar = isJapanese ? 1.5 : 0.4;
  const estimatedInputTokens = Math.ceil(transcriptText.length * tokensPerChar) + 500; // +system prompt

  const modelInfo = MODEL_PRICING[model] || (model === MODELS.fast.id ? MODELS.fast : MODELS.smart);
  const inputCost = (estimatedInputTokens / 1_000_000) * modelInfo.inputPricePer1M;
  const outputEstimate = 4000; // 概算出力トークン
  const outputCost = (outputEstimate / 1_000_000) * modelInfo.outputPricePer1M;

  return {
    model,
    modelLabel: modelInfo.label,
    estimatedInputTokens,
    estimatedCost: `$${(inputCost + outputCost).toFixed(4)}`,
  };
}
