import path from "node:path";
import type { FolderMapping } from "../types/shared.js";
import { resolveForcedParent } from "../x-folder-grouping/forced-parents.js";

// Strip path separators / traversal tokens / control chars from a single
// path segment so a malicious or broken entry in x_forced_parents.json
// (e.g. "A/B", "../../tmp") cannot escape the intended sourceRoot.
// Mirrors the Claude-side `sanitizeFolderName` in x_folder_mapper.ts.
function sanitizeSegment(segment: string): string {
  // Split on path separators, drop `..` within each piece (so "../../etc"
  // → ["", "", "etc"] → "etc"), then rejoin with `-` so something like
  // "A/B" collapses to "A-B" instead of traversing into a subdirectory.
  const cleaned = segment
    .replace(/[\x00-\x1f\x7f]/g, "")
    .split(/[/\\]/)
    .map((piece) => piece.replace(/\.\.+/g, ""))
    .filter((piece) => piece.length > 0)
    .join("-")
    .replace(/[*?:"<>|／＼]/g, "")
    .trim()
    .normalize("NFC")
    .slice(0, 80);
  return cleaned || "_Unfiled";
}

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
  childFolderName?: string | undefined;
  postDate: Date;
  folderPostCount: number;
  mapping?: FolderMapping | undefined;
  forcedParents?: readonly string[] | undefined;
}): string {
  const child = params.childFolderName?.trim() || "root";
  const segments = [params.vaultPath, params.sourceRoot];

  // Tier 1: x_forced_parents.json — shared user keyword list.
  // Takes precedence over FolderMapping, matching the Claude-side
  // flat implementation's (mapFolderToVaultPath) priority order.
  const forced =
    params.forcedParents && params.forcedParents.length > 0
      ? resolveForcedParent(child, params.forcedParents)
      : null;

  if (forced) {
    // Sanitize: x_forced_parents.json is user-maintained, so defensively
    // strip separators / traversal / control chars before pushing to
    // path.join to prevent sourceRoot escape.
    segments.push(sanitizeSegment(forced.parent));
    if (forced.child) segments.push(sanitizeSegment(forced.child));
  } else {
    // Tier 2: approved FolderMapping (generated via propose/approve flow)
    const group = params.mapping?.groups.find((g) => g.children.includes(child));
    if (group) {
      segments.push(group.parent_folder, child);
    } else {
      segments.push(child);
    }
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
