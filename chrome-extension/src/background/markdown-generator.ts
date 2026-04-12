import { generateFrontmatter, generateFilename } from '../shared/frontmatter';
import type { VideoMetadata, TranscriptPayload, AnalysisResult } from '../shared/types';

/**
 * AI分析結果からObsidian互換のマークダウンファイルを組み立てる。
 * パイプラインの storage.ts の frontmatter 構造を踏襲。
 */
export function buildMarkdownFile(
  metadata: VideoMetadata,
  transcript: TranscriptPayload,
  analysis: AnalysisResult,
  includeRawTranscript: boolean,
): { markdown: string; filename: string } {
  const frontmatter = generateFrontmatter(metadata);
  const filename = generateFilename(metadata.title);

  let body = analysis.markdown;

  // トークン使用量をフッターに追加
  body += `\n\n---\n\n`;
  body += `> [!info] 分析メタデータ\n`;
  body += `> - **モデル**: ${analysis.model}\n`;
  body += `> - **入力トークン**: ${analysis.inputTokens.toLocaleString()}\n`;
  body += `> - **出力トークン**: ${analysis.outputTokens.toLocaleString()}\n`;
  body += `> - **言語**: ${transcript.language}\n`;
  body += `> - **動画時間**: ${metadata.duration || '不明'}\n`;

  // 生トランスクリプトをObsidianの折りたたみcalloutで追加
  if (includeRawTranscript && transcript.fullText) {
    body += `\n\n> [!note]- 生トランスクリプト\n`;
    // callout内の各行を > で囲む
    const lines = transcript.fullText.split(/[。！？\n]/).filter(l => l.trim());
    for (const line of lines) {
      body += `> ${line.trim()}\n`;
    }
  }

  return {
    markdown: frontmatter + body,
    filename,
  };
}
