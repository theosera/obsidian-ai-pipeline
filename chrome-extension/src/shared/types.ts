// --- YouTube Data Types ---

export interface TranscriptSegment {
  text: string;
  start: number;
  duration: number;
}

export interface VideoMetadata {
  videoId: string;
  title: string;
  channel: string;
  publishedDate: string;
  url: string;
  description: string;
  duration: string;
  language: string;
}

export interface AnalysisResult {
  markdown: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
}

// --- Extension Config ---

export interface ExtensionConfig {
  apiKey: string;
  fastModel: string;
  smartModel: string;
  autoSelectModel: boolean;
  includeRawTranscript: boolean;
}

export const DEFAULT_CONFIG: Omit<ExtensionConfig, 'apiKey'> = {
  fastModel: 'claude-haiku-4-5-20251001',
  smartModel: 'claude-sonnet-4-6',
  autoSelectModel: true,
  includeRawTranscript: true,
};

// --- Chrome Runtime Messaging ---

export type MessageType =
  | 'GET_VIDEO_INFO'
  | 'VIDEO_INFO_RESULT'
  | 'EXTRACT_TRANSCRIPT'
  | 'TRANSCRIPT_RESULT'
  | 'ANALYZE_TRANSCRIPT'
  | 'ANALYSIS_PROGRESS'
  | 'ANALYSIS_RESULT'
  | 'ANALYSIS_ERROR'
  | 'DOWNLOAD_MD';

export interface Message<T = unknown> {
  type: MessageType;
  payload: T;
}

export interface VideoInfoPayload {
  metadata: VideoMetadata;
  hasTranscript: boolean;
  availableLanguages: string[];
}

export interface TranscriptPayload {
  segments: TranscriptSegment[];
  language: string;
  fullText: string;
}

export interface AnalyzePayload {
  metadata: VideoMetadata;
  transcript: TranscriptPayload;
}

export interface AnalysisErrorPayload {
  error: string;
}

export interface DownloadPayload {
  markdown: string;
  filename: string;
}
