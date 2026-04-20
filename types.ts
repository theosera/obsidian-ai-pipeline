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

export interface PipelineConfig {
  vaultRoot: string;
  provider: 'local' | 'openai' | 'anthropic' | 'gemini';
  fastModel: string;
  smartModel: string;
}
