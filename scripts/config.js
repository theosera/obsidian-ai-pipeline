import fs from 'fs';
import path from 'path';
import readline from 'readline';

const CONFIG_PATH = path.join('/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026', '__skills', 'pipeline', 'pipeline_config.json');

const DEFAULTS = {
  local: { fast: 'local-model', smart: 'local-model' },
  anthropic: { fast: 'claude-haiku-4-5-20251001', smart: 'claude-sonnet-4-6' },
  openai: { fast: 'gpt-4o-mini', smart: 'gpt-4o' },
  gemini: { fast: 'gemini-2.5-flash', smart: 'gemini-2.5-pro' }
};

export function loadConfig() {
  if (fs.existsSync(CONFIG_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch (e) {
      return null;
    }
  }
  return null;
}

export function saveConfig(config) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
}

export async function runConfigWizard(ask) {
  let localRl = null;
  if (!ask) {
    localRl = readline.createInterface({ input: process.stdin, output: process.stdout });
    ask = (q) => new Promise(resolve => localRl.question(q, resolve));
  }

  console.log('\n=== 🤖 AI Provider & Model Configuration ===');
  console.log('1. local (LM Studio - Default 127.0.0.1:1234)');
  console.log('2. anthropic (Claude)');
  console.log('3. openai (ChatGPT)');
  console.log('4. gemini');
  
  let providerInput = await ask('Select AI Provider [1-4] (default 1): ');
  let providerChoice = providerInput.trim()[0]; // 環境によってターミナルのエコーで '44' のように二重入力される問題への対策
  
  let provider = 'local';
  if (providerChoice === '2') provider = 'anthropic';
  else if (providerChoice === '3') provider = 'openai';
  else if (providerChoice === '4') provider = 'gemini';

  const defaultFast = DEFAULTS[provider].fast;
  const defaultSmart = DEFAULTS[provider].smart;

  let fastModel = await ask(`\nStep 1 Task Model (used for finding existing folders)\nPress Enter for default [${defaultFast}]: `);
  if (!fastModel.trim()) fastModel = defaultFast;

  let smartModel = await ask(`\nStep 2 Task Model (used for proposing new folders + deep reasoning)\nPress Enter for default [${defaultSmart}]: `);
  if (!smartModel.trim()) smartModel = defaultSmart;

  const config = {
    provider,
    fastModel: fastModel.trim(),
    smartModel: smartModel.trim()
  };

  saveConfig(config);
  if (localRl) localRl.close();
  console.log('✅ Configuration successfully saved to pipeline_config.json\n');
  return config;
}

export function applyConfigToEnv(config) {
  if (!config) return;
  process.env.AI_PROVIDER = config.provider;
  
  if (config.provider === 'anthropic') {
    process.env.ANTHROPIC_FAST_MODEL = config.fastModel;
    process.env.ANTHROPIC_SMART_MODEL = config.smartModel;
  } else if (config.provider === 'openai') {
    process.env.OPENAI_FAST_MODEL = config.fastModel;
    process.env.OPENAI_SMART_MODEL = config.smartModel;
  } else if (config.provider === 'gemini') {
    process.env.GEMINI_FAST_MODEL = config.fastModel;
    process.env.GEMINI_SMART_MODEL = config.smartModel;
  } else {
    process.env.LOCAL_AI_FAST_MODEL = config.fastModel;
    process.env.LOCAL_AI_SMART_MODEL = config.smartModel;
  }
}
