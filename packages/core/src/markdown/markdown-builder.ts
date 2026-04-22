import type { XAuthor, XPost } from "../types/shared.js";

function escapeYaml(input: string): string {
  return input.replace(/"/g, '\\"');
}

const X_SELF_HOSTS = new Set([
  "x.com",
  "twitter.com",
]);

function isXSelfLink(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  // match exact host or any subdomain (mobile.twitter.com, www.x.com, ...)
  if (X_SELF_HOSTS.has(host)) return true;
  for (const self of X_SELF_HOSTS) {
    if (host.endsWith(`.${self}`)) return true;
  }
  return false;
}

// Resolve entities.urls[] to unique expanded URLs, dropping self-links
// (x.com / twitter.com and their subdomains). Hostname-based match avoids
// false positives like https://box.com/file being dropped for containing
// "x.com/" as a substring.
export function expandedExternalLinks(post: XPost): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of post.entities?.urls ?? []) {
    const url = entry.expanded_url || entry.url;
    if (!url) continue;
    if (isXSelfLink(url)) continue;
    if (seen.has(url)) continue;
    seen.add(url);
    out.push(url);
  }
  return out;
}

export function buildBookmarkMarkdown(params: {
  post: XPost;
  author?: XAuthor | undefined;
  bookmarkFolder: string;
  syncedAt: string;
}): string {
  const authorName = params.author?.name ?? "Unknown Author";
  const username = params.author?.username ?? "unknown";
  const postUrl = `https://x.com/${username}/status/${params.post.id}`;
  const links = expandedExternalLinks(params.post);
  const linksSection = links.length > 0
    ? `\n## 含まれるリンク\n${links.map((u) => `- ${u}`).join("\n")}\n`
    : "";

  return `---
title: "${escapeYaml(`${authorName} - ${params.post.id}`)}"
source: "X"
post_id: "${params.post.id}"
author_name: "${escapeYaml(authorName)}"
author_username: "${escapeYaml(username)}"
author_id: "${params.post.author_id}"
post_url: "${postUrl}"
bookmark_folder: "${escapeYaml(params.bookmarkFolder)}"
post_created_at: "${params.post.created_at}"
synced_at: "${params.syncedAt}"
tags:
  - x
  - bookmark
---

# ${authorName} (@${username})

> ${params.post.text.replace(/\n/g, "\n> ")}

- URL: ${postUrl}
- Post ID: ${params.post.id}
- 投稿日: ${params.post.created_at}
- 保存フォルダ: ${params.bookmarkFolder}
${linksSection}
## Metrics
- Likes: ${params.post.public_metrics.like_count}
- Replies: ${params.post.public_metrics.reply_count}
- Reposts: ${params.post.public_metrics.retweet_count}
- Quotes: ${params.post.public_metrics.quote_count}
`;
}

export function buildFolderIndexMarkdown(params: {
  folderName: string;
  sourceRoot: string;
  generatedAt: string;
  posts: Array<{ fileName: string; postId: string; authorDisplay: string; url: string }>;
}): string {
  const lines: string[] = [];
  lines.push("---");
  lines.push(`title: \"${params.folderName} Index\"
source: \"X\"
generated_at: \"${params.generatedAt}\"`);
  lines.push("---", "");
  lines.push(`# ${params.folderName} Index`, "");
  lines.push(`- Source Root: ${params.sourceRoot}`);
  lines.push(`- Total Posts: ${params.posts.length}`, "");
  for (const post of params.posts) {
    lines.push(`- [${post.authorDisplay} (${post.postId})](${post.fileName}) - ${post.url}`);
  }
  return lines.join("\n") + "\n";
}
