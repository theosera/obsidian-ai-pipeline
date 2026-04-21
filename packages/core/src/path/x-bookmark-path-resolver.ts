import path from "node:path";
import type { FolderMapping } from "../types/shared.js";

function toQuarter(date: Date): string {
  const month = date.getUTCMonth() + 1;
  const q = Math.floor((month - 1) / 3) + 1;
  return `${date.getUTCFullYear()}-Q${q}`;
}

function toMonth(date: Date): string {
  const month = `${date.getUTCMonth() + 1}`.padStart(2, "0");
  return `${date.getUTCFullYear()}-${month}`;
}

export function resolveDateBucket(params: {
  postDate: Date;
  folderPostCount: number;
  quarterlyThreshold?: number;
  monthlyThreshold?: number;
}): string | undefined {
  const quarterlyThreshold = params.quarterlyThreshold ?? 10;
  const monthlyThreshold = params.monthlyThreshold ?? 20;

  if (params.folderPostCount >= monthlyThreshold) {
    return toMonth(params.postDate);
  }
  if (params.folderPostCount >= quarterlyThreshold) {
    return toQuarter(params.postDate);
  }
  return undefined;
}

export function resolveXBookmarkSaveDirectory(params: {
  vaultPath: string;
  sourceRoot: string;
  childFolderName?: string;
  postDate: Date;
  folderPostCount: number;
  mapping?: FolderMapping;
}): string {
  const child = params.childFolderName?.trim() || "root";
  const segments = [params.vaultPath, params.sourceRoot];
  const group = params.mapping?.groups.find((g) => g.children.includes(child));

  if (group) {
    segments.push(group.parent_folder, child);
  } else {
    segments.push(child);
  }

  const bucket = resolveDateBucket({
    postDate: params.postDate,
    folderPostCount: params.folderPostCount
  });
  if (bucket) {
    segments.push(bucket);
  }

  return path.join(...segments);
}
