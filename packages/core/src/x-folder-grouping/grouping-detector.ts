import type {
  FolderGroupingAnalysis,
  FolderGroupingProposal,
  MatchType,
  SkippedCandidate
} from "../types/shared.js";
import { tokenizeFolderName } from "./tokenizer.js";
import { isStopword } from "./stopwords.js";

interface TokenMap {
  token: string;
  folders: Set<string>;
  matchType: MatchType;
}

function parentFolderNameFromToken(token: string): string {
  if (!token) return "Group";
  return token.length <= 3 ? token.toUpperCase() : token[0].toUpperCase() + token.slice(1);
}

function detectForPosition(folderNames: string[], matchType: MatchType): {
  proposals: FolderGroupingProposal[];
  skipped: SkippedCandidate[];
} {
  const tokenMaps = new Map<string, TokenMap>();
  const skipped: SkippedCandidate[] = [];

  for (const folder of folderNames) {
    const tokens = tokenizeFolderName(folder);
    const token = matchType === "prefix" ? tokens[0] : tokens[tokens.length - 1];
    if (!token) {
      skipped.push({ token: "", match_type: matchType, folders: [folder], reason: "empty token" });
      continue;
    }

    if (!tokenMaps.has(token)) {
      tokenMaps.set(token, { token, folders: new Set(), matchType });
    }
    tokenMaps.get(token)?.folders.add(folder);
  }

  const proposals: FolderGroupingProposal[] = [];

  for (const [token, value] of tokenMaps.entries()) {
    const folders = [...value.folders].sort((a, b) => a.localeCompare(b));

    if (token.length < 2) {
      skipped.push({ token, match_type: matchType, folders, reason: "token length < 2" });
      continue;
    }
    if (isStopword(token)) {
      skipped.push({ token, match_type: matchType, folders, reason: "stopword" });
      continue;
    }
    if (folders.length < 3) {
      skipped.push({ token, match_type: matchType, folders, reason: "only 2 folders matched or less" });
      continue;
    }

    proposals.push({
      parent_folder: parentFolderNameFromToken(token),
      match_type: matchType,
      token,
      children: folders,
      reason: [
        `${folders.length} folders share the same ${matchType === "prefix" ? "leading" : "trailing"} token`,
        "token length >= 2",
        "token is not a stopword"
      ],
      confidence: Math.min(1, 0.5 + folders.length * 0.1)
    });
  }

  return { proposals, skipped };
}

export function detectFolderGroupings(params: {
  folderNames: string[];
  sourceRoot: string;
  generatedAt?: string;
}): FolderGroupingAnalysis {
  const names = [...new Set(params.folderNames.map((n) => n.trim()).filter(Boolean))];
  const prefix = detectForPosition(names, "prefix");
  const suffix = detectForPosition(names, "suffix");

  const allProposals = [...prefix.proposals, ...suffix.proposals];
  const deduped = new Map<string, FolderGroupingProposal>();

  for (const proposal of allProposals) {
    const key = `${proposal.match_type}:${proposal.token}`;
    const existing = deduped.get(key);
    if (!existing) {
      deduped.set(key, proposal);
      continue;
    }
    // ambiguous collision
    const merged = [...new Set([...existing.children, ...proposal.children])].sort((a, b) =>
      a.localeCompare(b)
    );
    deduped.set(key, { ...existing, children: merged });
  }

  return {
    generated_at: params.generatedAt ?? new Date().toISOString(),
    source_root: params.sourceRoot,
    analyzed_folder_count: names.length,
    proposals: [...deduped.values()].sort((a, b) => b.children.length - a.children.length),
    skipped: [...prefix.skipped, ...suffix.skipped]
  };
}
