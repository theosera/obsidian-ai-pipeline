import fs from "node:fs/promises";
import path from "node:path";
import {
  buildBookmarkMarkdown,
  buildFolderIndexMarkdown,
  ensureDir,
  fileExists,
  loadEnvConfig,
  loadTokens,
  readJsonFile,
  refreshAccessToken,
  resolveXBookmarkSaveDirectory,
  sanitizeFileName,
  saveTokens,
  writeJsonFile,
  XApiClient,
  type FolderMapping,
  type XAuthor,
  type XPost,
  type XTokenSet
} from "@obsidian-ai-pipeline/core";

interface FlattenedPost {
  post: XPost;
  author?: XAuthor;
}

const repoRoot = path.resolve(process.cwd(), "../..");
const config = loadEnvConfig(repoRoot);

async function ensureValidTokens(tokens: XTokenSet): Promise<XTokenSet> {
  if (!tokens.expires_at) return tokens;
  const expiresAt = new Date(tokens.expires_at).getTime();
  const bufferMs = 60 * 1000;
  if (Date.now() + bufferMs < expiresAt) return tokens;

  if (!tokens.refresh_token) {
    throw new Error("Access token expired and refresh_token is missing.");
  }

  const refreshed = await refreshAccessToken(config, tokens.refresh_token);
  await saveTokens(config.tokensPath, refreshed);
  return refreshed;
}

function flattenPages(pages: Awaited<ReturnType<XApiClient["getBookmarksAll"]>>): FlattenedPost[] {
  const results: FlattenedPost[] = [];
  for (const page of pages) {
    const authorMap = new Map((page.includes?.users ?? []).map((u) => [u.id, u]));
    for (const post of page.data ?? []) {
      const author = authorMap.get(post.author_id);
      results.push(author ? { post, author } : { post });
    }
  }
  return results;
}

async function savePost(params: {
  folderName: string;
  item: FlattenedPost;
  mapping?: FolderMapping;
  folderPostCount: number;
  syncedAt: string;
}): Promise<{ fileName: string; postId: string; authorDisplay: string; url: string; directory: string }> {
  const folder = params.folderName || "root";
  const date = new Date(params.item.post.created_at || new Date().toISOString());
  const directory = resolveXBookmarkSaveDirectory({
    vaultPath: config.obsidianVaultPath,
    sourceRoot: config.xBookmarksRoot,
    childFolderName: folder,
    postDate: date,
    folderPostCount: params.folderPostCount,
    ...(params.mapping && { mapping: params.mapping })
  });
  await ensureDir(directory);

  const authorName = params.item.author?.name ?? "Unknown Author";
  const authorUsername = params.item.author?.username ?? "unknown";
  const basename = sanitizeFileName(`${authorName}-${params.item.post.id}`);
  const fileName = `${basename}.md`;
  const filePath = path.join(directory, fileName);

  const markdown = buildBookmarkMarkdown({
    post: params.item.post,
    ...(params.item.author && { author: params.item.author }),
    bookmarkFolder: folder,
    syncedAt: params.syncedAt
  });
  await fs.writeFile(filePath, markdown, "utf-8");

  return {
    fileName,
    postId: params.item.post.id,
    authorDisplay: `${authorName} (@${authorUsername})`,
    url: `https://x.com/${authorUsername}/status/${params.item.post.id}`,
    directory
  };
}

async function loadMapping(): Promise<FolderMapping | undefined> {
  const mappingPath = path.resolve(repoRoot, "x_folder_mapping.json");
  if (!(await fileExists(mappingPath))) {
    return undefined;
  }
  return readJsonFile<FolderMapping>(mappingPath);
}

async function run(): Promise<void> {
  const tokens = await ensureValidTokens(await loadTokens(config.tokensPath));
  const client = new XApiClient(config, tokens);
  const me = await client.getMe();
  const mapping = await loadMapping();
  const syncedAt = new Date().toISOString();

  const folders = await client.getBookmarkFolders(me.id);
  const folderCounts: Record<string, number> = {};
  const folderResults: Array<{
    folderName: string;
    entries: Array<{
      fileName: string;
      postId: string;
      authorDisplay: string;
      url: string;
      directory: string;
    }>;
  }> = [];

  for (const folder of folders) {
    const pages = await client.getBookmarksByFolder(me.id, folder.id);
    const items = flattenPages(pages);
    folderCounts[folder.name] = items.length;

    const entries = [];
    for (const item of items) {
      entries.push(
        await savePost({
          folderName: folder.name,
          item,
          ...(mapping && { mapping }),
          folderPostCount: items.length,
          syncedAt
        })
      );
    }
    folderResults.push({ folderName: folder.name, entries });
  }

  const allPages = await client.getBookmarksAll(me.id);
  const allItems = flattenPages(allPages);
  if (allItems.length > 0) {
    const rootEntries = [];
    for (const item of allItems) {
      rootEntries.push(
        await savePost({
          folderName: "root",
          item,
          ...(mapping && { mapping }),
          folderPostCount: allItems.length,
          syncedAt
        })
      );
    }
    folderResults.push({ folderName: "root", entries: rootEntries });
    folderCounts.root = allItems.length;
  }

  const statsPath = path.resolve(repoRoot, "analysis", "x_folder_stats.json");
  await writeJsonFile(statsPath, {
    generated_at: syncedAt,
    user_id: me.id,
    folders: folderCounts
  });

  for (const result of folderResults) {
    const folderDir =
      result.entries[0]?.directory ??
      resolveXBookmarkSaveDirectory({
        vaultPath: config.obsidianVaultPath,
        sourceRoot: config.xBookmarksRoot,
        childFolderName: result.folderName,
        postDate: new Date(),
        folderPostCount: folderCounts[result.folderName] ?? 0,
        ...(mapping && { mapping })
      });
    await ensureDir(folderDir);
    const index = buildFolderIndexMarkdown({
      folderName: result.folderName,
      sourceRoot: config.xBookmarksRoot,
      generatedAt: syncedAt,
      posts: result.entries
    });
    await fs.writeFile(path.join(folderDir, "_index.md"), index, "utf-8");
  }

  console.log(`Synced ${allItems.length} total bookmarks for @${me.username}`);
}

run().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : error);
  process.exit(1);
});