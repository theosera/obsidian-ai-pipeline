import type { XAuthor, XPost } from "../types/shared.js";

function escapeYaml(input: string): string {
  return input.replace(/"/g, '\\"');
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
