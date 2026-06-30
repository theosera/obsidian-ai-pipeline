import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';
import { PipelineConfig, XSummaryConfig, ThreatRelevanceConfig, AiProvider } from './types';

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

export function setVaultRoot(root: string | null): void {
  _vaultRoot = root === null ? null : path.resolve(root);
}

/**
 * 現在の vault root (未設定なら null) を例外なく覗く。
 * テストが getVaultRoot() に依存せず save → mutate → restore できるようにするため
 * (getVaultRoot は未設定時に throw する / 解決後の値しか返さないため save/restore に不向き)。
 */
export function peekVaultRoot(): string | null {
  return _vaultRoot;
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
// X ブックマーク Vault 内ベースフォルダ
//
// 旧パス `Clippings/X-Bookmarks` は 2026-05 のテーブルビュー化リファクタで
// 廃止され、`X_Bookmarks` 直下に集約された (詳細は plan
// `wobbly-percolating-yeti.md`)。レガシーから移行する場合は
// `pnpm start -- --x-migrate-legacy` で `_Archived/` に退避する。
// `X_BOOKMARKS_FOLDER` 環境変数で上書き可能 (テスト・特殊環境用)。
// ---------------------------------------------------------------------------
const X_BOOKMARKS_BASE_DEFAULT = 'X_Bookmarks';

export function getXBookmarksBaseFolder(): string {
  return process.env.X_BOOKMARKS_FOLDER || X_BOOKMARKS_BASE_DEFAULT;
}

// ---------------------------------------------------------------------------
// パイプライン用 SQLite DB のディレクトリ
//
// threat_reports.db / x_bookmarks.db (+ WAL/SHM sidecar) を置くディレクトリ。
// 既定は `<vault>/__skills/pipeline` だが、`PIPELINE_DB_DIR` で上書きできる。
//
// 動機: vault を iCloud / クラウドファイル同期下に置くと、SQLite の sidecar
// (-wal/-shm) が本体 .db と独立同期され DB が desync/巻き戻りする (恒久対策の
// 経緯は docs/threat_reports.md / PR #112)。DB だけを同期対象外のパスへ逃がす
// 運用を可能にするためのノブ。
//
// 重要: この DB は vault repo に **git-tracked** される設計 (人手フィールド保持 +
// CI が ingest 結果をコミット → ローカルへ pull)。完全に vault 外へ向けると CI と
// ローカルで DB が分裂する。git 追跡を保ったまま iCloud 同期だけ避けたい場合は、
// **vault 作業コピー内の `.nosync` フォルダ** (例 `<vault>/__skills/pipeline.nosync`)
// を指すこと (macOS iCloud Drive は `.nosync` 付きを同期除外する)。CI は本変数を
// 設定しないので、CI 側のパスは常に既定のまま (vault repo にコミットされ続ける)。
// ---------------------------------------------------------------------------
export function getPipelineDbDir(): string {
  const override = process.env.PIPELINE_DB_DIR?.trim();
  const dir = override ? path.resolve(override) : path.join(getVaultRoot(), '__skills', 'pipeline');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
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
    } catch {
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
  const vaultRootInput = await askFunc(
    `Obsidian Vault のルートパス${currentVault ? ` (default: ${currentVault})` : ''}: `
  );
  const vaultRoot = vaultRootInput.trim() || currentVault;
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

  const providerInput = await askFunc('Select AI Provider [1-4] (default 1): ');
  const providerChoice = providerInput.trim()[0]; // 環境によってターミナルのエコーで '44' のように二重入力される問題への対策

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

// ---------------------------------------------------------------------------
// X ブックマーク AI 要約 専用の provider / model 選択
//
// classifier (分類フェーズ) とは独立した設定。理由:
//   - 分類は long context / smart 推論が要るがローカルでも回せる
//   - X 要約は 1 行 200 字の軽量タスクで、cloud 廉価 fast モデルが品質/速度バランス◎
// よってデフォルトのデフォルトは **cloud / Anthropic Haiku 4.5** とし、
// 初回 `--x-bookmarks` 実行時にウィザードで他選択肢へ切り替え可能にする。
// 永続化先は pipeline_config.json (`xSummary` キー)。
// ---------------------------------------------------------------------------

export interface XSummaryPreset {
  /** 1 行表示用ラベル ("cloud / Anthropic Haiku 4.5 (推奨)" 等) */
  label: string;
  provider: AiProvider;
  model: string;
}

/**
 * 表示順がそのまま CLI の番号選択肢になる。**先頭がデフォルトのデフォルト**
 * (Enter 即時確定 = anthropic + haiku 4.5)。
 *
 * モデル ID は `DEFAULTS` (分類用の fast / smart プリセット) と意味的に揃えるが、
 * 「X 要約はあくまで fast 軽量タスク」という設計のため fast 系のみを採用 (Sonnet
 * 等の smart は除外)。将来モデルを増やすときはここに 1 行追加すれば CLI に反映される。
 */
export const X_SUMMARY_PRESETS: XSummaryPreset[] = [
  {
    label: 'cloud / Anthropic Haiku 4.5  (推奨・デフォルト)',
    provider: 'anthropic',
    model: 'claude-haiku-4-5-20251001',
  },
  {
    label: 'cloud / OpenAI gpt-4o-mini',
    provider: 'openai',
    model: 'gpt-4o-mini',
  },
  {
    label: 'cloud / Gemini 2.5 Flash',
    provider: 'gemini',
    model: 'gemini-2.5-flash',
  },
  {
    label: 'local / LM Studio (LOCAL_AI_URL)',
    provider: 'local',
    model: 'local-model',
  },
];

/** ウィザード未実行時に使う最終フォールバック (= 先頭プリセット)。 */
export const DEFAULT_X_SUMMARY: XSummaryConfig = {
  provider: X_SUMMARY_PRESETS[0].provider,
  model: X_SUMMARY_PRESETS[0].model,
};

/**
 * 保存済み xSummary を返す。未設定なら null (= ウィザード未実行)。
 * 呼出側は null を見たらウィザード起動 → 結果を `saveConfig` で永続化する。
 */
export function getXSummaryConfig(config: PipelineConfig | null): XSummaryConfig | null {
  return config?.xSummary ?? null;
}

/**
 * 初回 `--x-bookmarks` 実行時に呼ばれる対話ウィザード。
 * 番号 1〜N でプリセット選択、空 Enter は先頭 (= 推奨デフォルト) を採用。
 *
 * 永続化は呼出側責務 (返り値を `saveConfig({ ...config, xSummary })` する想定)。
 * テストでは `ask` を注入して入力をシミュレートする。
 *
 * カスタムモデル ID 指定モード:
 *   選択後に "Use custom model id? (y/N)" を出して、yes なら provider はそのまま
 *   model だけ自由入力させる (preset に無い checkpoint 等を指したいケース用)。
 *   空入力なら preset の model を使う。
 */
/**
 * provider/model プリセット選択ウィザードの共通実装。
 * 番号選択 (Enter=先頭) + 任意の custom model ID 上書き。stdin 二重入力ガード付き。
 * xSummary / threatRelevance の両ウィザードが薄いラッパとして共有し、
 * 二者がドリフトしないようにする (DRY — CodeRabbit #77)。
 */
async function runPresetWizard<T extends { label: string; provider: AiProvider; model: string }>(
  presets: T[],
  ui: { title: string; intro: string; savingLabel: string },
  ask?: (q: string) => Promise<string>
): Promise<{ provider: AiProvider; model: string }> {
  let localRl: readline.Interface | null = null;
  let askFunc = ask;
  if (!askFunc) {
    localRl = readline.createInterface({ input: process.stdin, output: process.stdout });
    askFunc = (q: string) => new Promise<string>(resolve => localRl!.question(q, resolve));
  }

  console.log(`\n${ui.title}`);
  console.log(`${ui.intro}\n`);
  presets.forEach((p, i) => {
    console.log(`  ${i + 1}. ${p.label}`);
  });
  console.log('');

  const raw = await askFunc(
    `番号で選択してください [1-${presets.length}] (Enter=1 デフォルト): `
  );
  // 環境によって stdin が二重入力されることがあるため先頭 1 文字だけ採用 (config wizard と同様)
  const choice = raw.trim()[0] ?? '';
  let idx = 0; // デフォルト: 先頭プリセット
  if (choice) {
    const parsed = parseInt(choice, 10);
    if (Number.isInteger(parsed) && parsed >= 1 && parsed <= presets.length) {
      idx = parsed - 1;
    } else {
      console.warn(`⚠️  不正な入力 "${raw.trim()}" — デフォルト (${presets[0].label}) を使用します。`);
    }
  }
  const preset = presets[idx];

  // カスタム model ID を任意で許可 (preset の provider は保持)
  const customRaw = await askFunc(
    `\n${preset.label} を選択しました。\nモデル ID を上書きしますか? (Enter=${preset.model} をそのまま使用): `
  );
  const customModel = customRaw.trim();
  const config = {
    provider: preset.provider,
    model: customModel || preset.model,
  };

  if (localRl) localRl.close();
  console.log(`✅ ${ui.savingLabel}: provider=${config.provider} / model=${config.model}\n`);
  return config;
}

export async function runXSummaryWizard(
  ask?: (q: string) => Promise<string>
): Promise<XSummaryConfig> {
  return runPresetWizard(X_SUMMARY_PRESETS, {
    title: '=== 🤖 X ブックマーク AI 要約のモデル選択 ===',
    intro: 'cloud と local を自由に選択できます (1 件 = 1 行 200 字の軽量タスク)。',
    savingLabel: 'X 要約の設定を保存します',
  }, ask);
}

// ---------------------------------------------------------------------------
// 脅威レポート「自リポ該当性」判定 専用の provider / model 選択 (Level 2 検知)
//
// 選定基準は **ベンダではなく「reasoning 可能な smart 階層」**。判定の精度は
// モデルに依存せず構造 (trusted repo profile + 厳格スキーマ + unclear fallback +
// 人手レビュー) で担保するため、ここはあくまで「差し替え可能なノブ」。
// 永続化先は pipeline_config.json (`threatRelevance` キー)。
// ---------------------------------------------------------------------------

export interface ThreatRelevancePreset {
  label: string;
  provider: AiProvider;
  model: string;
}

/**
 * 表示順 = CLI 番号選択肢。**先頭がデフォルトのデフォルト**。
 * xSummary (fast 軽量タスク) と違い、こちらは「該当性推論」= smart 階層を採用する。
 * 各ベンダの smart モデルと、ローカル OSS 推論モデルを並べる (ベンダ固定にしない)。
 */
export const THREAT_RELEVANCE_PRESETS: ThreatRelevancePreset[] = [
  {
    label: 'cloud / Anthropic Sonnet 4.6  (推奨・デフォルト)',
    provider: 'anthropic',
    model: DEFAULTS.anthropic.smart,
  },
  {
    label: 'cloud / OpenAI gpt-4o',
    provider: 'openai',
    model: DEFAULTS.openai.smart,
  },
  {
    label: 'cloud / Gemini 2.5 Pro',
    provider: 'gemini',
    model: DEFAULTS.gemini.smart,
  },
  {
    label: 'local / OSS 推論モデル (LOCAL_AI_URL — model ID は上書き入力)',
    provider: 'local',
    model: 'local-model',
  },
];

/** ウィザード未実行時の最終フォールバック (= 先頭プリセット)。 */
export const DEFAULT_THREAT_RELEVANCE: ThreatRelevanceConfig = {
  provider: THREAT_RELEVANCE_PRESETS[0].provider,
  model: THREAT_RELEVANCE_PRESETS[0].model,
};

/** 保存済み threatRelevance を返す。未設定なら null (= ウィザード未実行)。 */
export function getThreatRelevanceConfig(config: PipelineConfig | null): ThreatRelevanceConfig | null {
  return config?.threatRelevance ?? null;
}

/**
 * 初回 `--analyze-threat-relevance` 実行時に呼ばれる対話ウィザード。
 * `runXSummaryWizard` と同形 (番号選択 + 任意の custom model ID)。
 * ローカル OSS 推論モデルを使う場合は custom model ID 入力でチェックポイントを指す。
 */
export async function runThreatRelevanceWizard(
  ask?: (q: string) => Promise<string>
): Promise<ThreatRelevanceConfig> {
  return runPresetWizard(THREAT_RELEVANCE_PRESETS, {
    title: '=== 🛡️ 脅威レポート 該当性判定のモデル選択 (Level 2 検知) ===',
    intro: '「reasoning 可能な smart 階層」を選んでください (cloud / ローカル OSS 推論モデル可)。',
    savingLabel: '該当性判定の設定を保存します',
  }, ask);
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
