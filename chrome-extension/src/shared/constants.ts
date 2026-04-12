export const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';
export const ANTHROPIC_VERSION = '2023-06-01';

export const MODELS = {
  fast: {
    id: 'claude-haiku-4-5-20251001',
    label: 'Claude Haiku 4.5 (Fast)',
    inputPricePer1M: 1.00,
    outputPricePer1M: 5.00,
  },
  smart: {
    id: 'claude-sonnet-4-6',
    label: 'Claude Sonnet 4.6 (Smart)',
    inputPricePer1M: 3.00,
    outputPricePer1M: 15.00,
  },
} as const;

/** モデルIDから価格情報を取得するルックアップテーブル */
export const MODEL_PRICING: Record<string, { label: string; inputPricePer1M: number; outputPricePer1M: number }> = {
  'claude-haiku-4-5-20251001': { label: 'Claude Haiku 4.5', inputPricePer1M: 0.25, outputPricePer1M: 1.25 },
  'claude-sonnet-4-6': { label: 'Claude Sonnet 4.6', inputPricePer1M: 3.00, outputPricePer1M: 15.00 },
  'claude-opus-4-6': { label: 'Claude Opus 4.6', inputPricePer1M: 15.00, outputPricePer1M: 75.00 },
};

/** 短い動画のトランスクリプト文字数の閾値 (これ以下ならFastモデル) */
export const FAST_MODEL_CHAR_THRESHOLD = 5000;

/** トランスクリプトの最大文字数制限 */
export const MAX_TRANSCRIPT_LENGTH = 100_000;

/** 日本語キャプション言語コード優先順 */
export const LANGUAGE_PRIORITY = ['ja', 'ja-JP', 'en', 'en-US', 'en-GB'];

export const STORAGE_KEYS = {
  API_KEY: 'anthropic_api_key',
  CONFIG: 'extension_config',
} as const;