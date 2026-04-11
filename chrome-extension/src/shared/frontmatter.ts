import { VideoMetadata } from './types';
import { escapeFrontmatter } from './sanitize';

/**
 * Obsidian互換のYAML frontmatterを生成する。
 * パイプラインの storage.ts:155-166 のフォーマットを踏襲。
 * タグは "clippings" ではなく "youtube-transcript" を使用。
 */
export function generateFrontmatter(video: VideoMetadata): string {
  const today = new Date().toISOString().split('T')[0];
  const description = video.description
    ? escapeFrontmatter(video.description.slice(0, 200))
    : '';

  return `---
title: "${escapeFrontmatter(video.title)}"
source: "${escapeFrontmatter(video.url)}"
author:
  - "[[${escapeFrontmatter(video.channel)}]]"
published: ${video.publishedDate || today}
created: ${today}
description: "${description}"
tags:
  - "youtube-transcript"
---

`;
}

/**
 * ダウンロード用の安全なファイル名を生成する。
 * パイプラインの storage.ts:144-149 の命名規則を踏襲。
 */
export function generateFilename(title: string): string {
  const today = new Date().toISOString().split('T')[0];
  const mmDd = today.substring(5); // MM-DD

  const safeTitle = (title || '')
    .replace(/[\x00-\x1f\x7f]/g, '')
    .replace(/[\/\\*?:"<>|／＼]/g, '')
    .trim()
    .slice(0, 100) || 'Untitled';

  return `${safeTitle}_${mmDd}.md`;
}
