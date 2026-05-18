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
 * X ブックマーク AI 要約 (`x_bookmarks_summarizer`) 専用の provider / model 選択。
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

export interface PipelineConfig {
  vaultRoot: string;
  provider: AiProvider;
  fastModel: string;
  smartModel: string;
  /** 未設定なら初回 `--x-bookmarks` 実行時にウィザードで埋める。 */
  xSummary?: XSummaryConfig;
}
