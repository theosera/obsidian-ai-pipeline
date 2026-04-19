import { STORAGE_KEYS, MODELS } from './constants';
import type { ExtensionConfig } from './types';

/**
 * chrome.storage.local から拡張設定を読み込む。
 * service-worker.ts と popup.ts の両方から使用される共通ユーティリティ。
 */
export async function loadConfig(): Promise<ExtensionConfig> {
  const result = await chrome.storage.local.get([STORAGE_KEYS.API_KEY, STORAGE_KEYS.CONFIG]);
  const config = result[STORAGE_KEYS.CONFIG] || {};
  return {
    apiKey: result[STORAGE_KEYS.API_KEY] || '',
    fastModel: config.fastModel || MODELS.fast.id,
    smartModel: config.smartModel || MODELS.smart.id,
    autoSelectModel: config.autoSelectModel !== false,
    includeRawTranscript: config.includeRawTranscript !== false,
  };
}
