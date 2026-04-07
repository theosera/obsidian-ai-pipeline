export interface ArticleData {
  url: string;
  title?: string;
  content?: string; // HTML content or markdown
  textContent?: string; // Raw text without formatting
  excerpt?: string;
  date?: string;
  siteName?: string;
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
  provider: 'local' | 'openai' | 'anthropic' | 'gemini';
  fastModel: string;
  smartModel: string;
}
