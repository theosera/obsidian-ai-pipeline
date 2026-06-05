export interface ArticleData {
  url: string;
  title?: string;
  content?: string; // HTML content or markdown
  textContent?: string; // Raw text without formatting
  excerpt?: string;
  date?: string;
  siteName?: string;
  // X (Twitter) ブックマーク経由でのみ設定される。
  // xFolderName: 既にマッパーで Vault 階層パスへ変換済みの相対パス（例: "Claude Code/Tips"）
  // xTweetId:    SQLite メタデータキャッシュの主キー
  xFolderName?: string;
  xTweetId?: string;
}

export interface ClassificationResult {
  proposedPath: string;
  isNewFolder: boolean;
  isNewFolderRequired?: boolean;
  confidence?: number;
  reasoning: string;
  trendReasoning?: string;
  diffReasoning?: string;
}

export interface ProcessingResult {
  id?: number;
  status: 'success' | 'failure';
  url: string;
  title?: string;
  reason?: string;
  policy?: string;
  classification?: ClassificationResult;
  articleContext?: ArticleData;
}

export interface FolderRules {
  quarterPrefixes: string[];
  lastUpdated: string;
  [key: string]: any;
}

export type AiProvider = 'local' | 'openai' | 'anthropic' | 'gemini';

/**
 * X ブックマーク AI 要約 (`x-bookmarks/summarizer`) 専用の provider / model 選択。
 *
 * 分類フェーズの classifier とは独立した設定。デフォルトのデフォルトは
 * cloud=Anthropic + Haiku 4.5 で、初回 `--x-bookmarks` 実行時に対話ウィザード
 * (`runXSummaryWizard`) が presets から選ばせて pipeline_config.json に永続化する。
 * 再選択は `--x-summary-reconfig` を付けて起動する。
 */
export interface XSummaryConfig {
  provider: AiProvider;
  model: string;
}

/**
 * 週次 LLM 脅威レポートの「自リポ該当性」判定 (`threat_reports_relevance`) 専用の
 * provider / model 選択 (Level 2 検知)。
 *
 * classifier / xSummary とは独立。選定基準は **ベンダではなく「reasoning 可能な
 * smart 階層」** (`taskType: 'smart'`)。クラウドでもローカル OSS 推論モデルでも
 * 基準を満たせば可。`runThreatRelevanceWizard` が presets から選ばせ
 * pipeline_config.json (`threatRelevance` キー) に永続化する。再選択は
 * `--threat-relevance-reconfig`。判定の精度は**モデルではなく構造**
 * (trusted repo profile + 厳格スキーマ + unclear fallback + 人手レビュー) で担保する。
 */
export interface ThreatRelevanceConfig {
  provider: AiProvider;
  model: string;
}

export interface PipelineConfig {
  vaultRoot: string;
  provider: AiProvider;
  fastModel: string;
  smartModel: string;
  /** 未設定なら初回 `--x-bookmarks` 実行時にウィザードで埋める。 */
  xSummary?: XSummaryConfig;
  /** 未設定なら初回 `--analyze-threat-relevance` 実行時にウィザードで埋める。 */
  threatRelevance?: ThreatRelevanceConfig;
}
