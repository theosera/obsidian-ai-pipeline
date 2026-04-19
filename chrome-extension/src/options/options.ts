import { STORAGE_KEYS } from '../shared/constants';
import type { ExtensionConfig } from '../shared/types';

const form = document.getElementById('options-form') as HTMLFormElement;
const apiKeyInput = document.getElementById('api-key') as HTMLInputElement;
const autoSelectModel = document.getElementById('auto-select-model') as HTMLInputElement;
const fastModelSelect = document.getElementById('fast-model') as HTMLSelectElement;
const smartModelSelect = document.getElementById('smart-model') as HTMLSelectElement;
const includeRawTranscript = document.getElementById('include-raw-transcript') as HTMLInputElement;
const saveStatus = document.getElementById('save-status') as HTMLSpanElement;

/** 保存済み設定を読み込んでフォームに反映 */
async function loadSettings(): Promise<void> {
  const result = await chrome.storage.local.get([STORAGE_KEYS.API_KEY, STORAGE_KEYS.CONFIG]);
  const config = result[STORAGE_KEYS.CONFIG] || {};

  if (result[STORAGE_KEYS.API_KEY]) {
    apiKeyInput.value = result[STORAGE_KEYS.API_KEY];
  }

  autoSelectModel.checked = config.autoSelectModel !== false;
  includeRawTranscript.checked = config.includeRawTranscript !== false;

  if (config.fastModel) fastModelSelect.value = config.fastModel;
  if (config.smartModel) smartModelSelect.value = config.smartModel;
}

/** フォーム送信ハンドラ */
form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const apiKey = apiKeyInput.value.trim();

  // APIキーの簡易バリデーション
  if (apiKey && !apiKey.startsWith('sk-ant-')) {
    showStatus('APIキーの形式が正しくありません（sk-ant-...で始まる必要があります）', 'error');
    return;
  }

  const config: Omit<ExtensionConfig, 'apiKey'> = {
    fastModel: fastModelSelect.value,
    smartModel: smartModelSelect.value,
    autoSelectModel: autoSelectModel.checked,
    includeRawTranscript: includeRawTranscript.checked,
  };

  await chrome.storage.local.set({
    [STORAGE_KEYS.API_KEY]: apiKey,
    [STORAGE_KEYS.CONFIG]: config,
  });

  showStatus('設定を保存しました', 'success');
});

function showStatus(message: string, type: 'success' | 'error'): void {
  saveStatus.textContent = message;
  saveStatus.className = `status ${type}`;
  setTimeout(() => {
    saveStatus.textContent = '';
    saveStatus.className = 'status';
  }, 3000);
}

loadSettings();
