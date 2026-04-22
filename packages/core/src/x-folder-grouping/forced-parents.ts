import fs from "node:fs";
import path from "node:path";

const FORCED_PARENTS_FILENAME = "x_forced_parents.json";

/**
 * Load the shared forced-parent keyword list.
 *
 * The file lives at `<vaultPath>/__skills/pipeline/x_forced_parents.json` —
 * the same location the Claude-side flat implementation
 * (`x_folder_mapper.ts`) reads from — so both sides observe the identical
 * user-maintained keyword set (per README "意図的に共有" note). Kept sync
 * to match Claude's loadForcedParents() and simplify testing; this is a
 * one-shot startup read so async gives no real benefit.
 *
 * Tolerates missing / malformed files by returning `[]` instead of throwing.
 */
export function loadForcedParents(vaultPath: string): string[] {
  const file = path.join(vaultPath, "__skills", "pipeline", FORCED_PARENTS_FILENAME);
  if (!fs.existsSync(file)) return [];
  try {
    const raw = fs.readFileSync(file, "utf-8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (s): s is string => typeof s === "string" && s.trim().length > 0
    );
  } catch {
    return [];
  }
}

function escapeRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Word-boundary regex that treats non-ASCII-alphanumeric as boundary, so
// "MCP" matches "MCP連携" (Japanese adjacent is a boundary) but "AI" does
// NOT match "AIRI" (consecutive ASCII letter).
function boundaryRegex(keyword: string): RegExp {
  return new RegExp(
    `(?<![A-Za-z0-9])${escapeRegex(keyword)}(?![A-Za-z0-9])`,
    "i"
  );
}

export function hasWordBoundaryMatch(folderName: string, keyword: string): boolean {
  if (!keyword.trim()) return false;
  return boundaryRegex(keyword).test(folderName);
}

function stripKeyword(folderName: string, keyword: string): string {
  return folderName
    .replace(boundaryRegex(keyword), "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * If any `forcedParents` keyword appears in the folder name at a word
 * boundary, return { parent: keyword, child: remainder }. Otherwise null.
 *
 * Semantics match the Claude-side flat implementation
 * (`x_folder_mapper.ts:mapFolderToVaultPath` Tier 1):
 *   - case-insensitive match
 *   - longer keyword wins (so "Claude Code" beats "Code" for
 *     "Claude Code Tips" → parent="Claude Code", child="Tips")
 *   - remainder whitespace collapsed
 *   - exact match returns child=""
 */
export function resolveForcedParent(
  folderName: string,
  forcedParents: readonly string[]
): { parent: string; child: string } | null {
  const trimmed = folderName.trim();
  if (!trimmed || forcedParents.length === 0) return null;
  const sorted = [...forcedParents]
    .filter((k) => k.trim().length > 0)
    .sort((a, b) => b.length - a.length);
  for (const keyword of sorted) {
    if (hasWordBoundaryMatch(trimmed, keyword)) {
      return { parent: keyword, child: stripKeyword(trimmed, keyword) };
    }
  }
  return null;
}
