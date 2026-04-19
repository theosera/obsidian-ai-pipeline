import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';
import { PipelineConfig } from './types';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_PATH = path.join(__dirname, 'pipeline_config.json');

const DEFAULTS: Record<string, { fast: string; smart: string }> = {
  local: { fast: 'local-model', smart: 'local-model' },
  anthropic: { fast: 'claude-haiku-4-5-20251001', smart: 'claude-sonnet-4-6' },
  openai: { fast: 'gpt-4o-mini', smart: 'gpt-4o' },
  gemini: { fast: 'gemini-2.5-flash', smart: 'gemini-2.5-pro' }
};

// ---------------------------------------------------------------------------
// Vault Root（設定ファイル化: 全モジュールが getVaultRoot() で参照する）
// ---------------------------------------------------------------------------
let _vaultRoot: string | null = null;

export function setVaultRoot(root: string): void {
  _vaultRoot = path.resolve(root);
}

export function getVaultRoot(): string {
  if (_vaultRoot) return _vaultRoot;
  if (process.env.VAULT_ROOT) {
    _vaultRoot = path.resolve(process.env.VAULT_ROOT);
    return _vaultRoot;
  }
  throw new Error(
    'VAULT_ROOT が設定されていません。\n' +
    '以下のいずれかで設定してください:\n' +
    '  1. pnpm start -- --config で設定ウィザードを実行\n' +
    '  2. 環境変数 VAULT_ROOT を設定'
  );
}

// ---------------------------------------------------------------------------
// Dry-Run モード（renameSync 一括移動を安全にプレビュー）
// ---------------------------------------------------------------------------
let _dryRun = false;

export function setDryRun(enabled: boolean): void {
  _dryRun = enabled;
  if (enabled) {
    console.log('\n🔍 [DRY-RUN] ドライランモードが有効です。ファイルの移動は行われません。\n');
  }
}

export function isDryRun(): boolean {
  return _dryRun;
}

// ---------------------------------------------------------------------------
// Config persistence
// ---------------------------------------------------------------------------
export function loadConfig(): PipelineConfig | null {
  if (fs.existsSync(CONFIG_PATH)) {
    try {
      const config: PipelineConfig = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      if (config.vaultRoot) {
        setVaultRoot(config.vaultRoot);
      }
      return config;
    } catch (e) {
      return null;
    }
  }
  return null;
}

export function saveConfig(config: PipelineConfig): void {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
}

export async function runConfigWizard(ask?: (q: string) => Promise<string>): Promise<PipelineConfig> {
  let localRl: readline.Interface | null = null;
  let askFunc = ask;

  if (!askFunc) {
    localRl = readline.createInterface({ input: process.stdin, output: process.stdout });
    askFunc = (q: string) => new Promise<string>(resolve => localRl!.question(q, resolve));
  }

  // --- Vault Root ---
  console.log('\n=== 📂 Obsidian Vault Root Configuration ===');
  const currentVault = _vaultRoot || process.env.VAULT_ROOT || '';
  let vaultRootInput = await askFunc(
    `Obsidian Vault のルートパス${currentVault ? ` (default: ${currentVault})` : ''}: `
  );
  let vaultRoot = vaultRootInput.trim() || currentVault;
  if (!vaultRoot) {
    console.error('Vault Root は必須です。');
    process.exit(1);
  }

  if (!fs.existsSync(vaultRoot)) {
    console.warn(`⚠️ 指定されたパスが見つかりません: ${vaultRoot}`);
    const proceed = await askFunc('それでも続行しますか？ [y/N]: ');
    if (proceed.toLowerCase() !== 'y') {
      process.exit(1);
    }
  }

  setVaultRoot(vaultRoot);

  // --- AI Provider ---
  console.log('\n=== 🤖 AI Provider & Model Configuration ===');
  console.log('1. local (LM Studio - Default 127.0.0.1:1234)');
  console.log('2. anthropic (Claude)');
  console.log('3. openai (ChatGPT)');
  console.log('4. gemini');

  let providerInput = await askFunc('Select AI Provider [1-4] (default 1): ');
  let providerChoice = providerInput.trim()[0]; // 環境によってターミナルのエコーで '44' のように二重入力される問題への対策

  let provider: PipelineConfig['provider'] = 'local';
  if (providerChoice === '2') provider = 'anthropic';
  else if (providerChoice === '3') provider = 'openai';
  else if (providerChoice === '4') provider = 'gemini';

  const defaultFast = DEFAULTS[provider].fast;
  const defaultSmart = DEFAULTS[provider].smart;

  let fastModel = await askFunc(`\nStep 1 Task Model (used for finding existing folders)\nPress Enter for default [${defaultFast}]: `);
  if (!fastModel.trim()) fastModel = defaultFast;

  let smartModel = await askFunc(`\nStep 2 Task Model (used for proposing new folders + deep reasoning)\nPress Enter for default [${defaultSmart}]: `);
  if (!smartModel.trim()) smartModel = defaultSmart;

  const config: PipelineConfig = {
    vaultRoot,
    provider,
    fastModel: fastModel.trim(),
    smartModel: smartModel.trim()
  };

  saveConfig(config);
  if (localRl) localRl.close();
  console.log('✅ Configuration successfully saved to pipeline_config.json\n');
  return config;
}

export function applyConfigToEnv(config: PipelineConfig | null): void {
  if (!config) return;

  if (config.vaultRoot) {
    setVaultRoot(config.vaultRoot);
  }

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
