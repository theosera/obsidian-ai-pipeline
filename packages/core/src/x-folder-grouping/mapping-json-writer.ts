import path from "node:path";
import type { FolderGroupingAnalysis, FolderMapping } from "../types/shared.js";
import { writeJsonFile } from "../fs/file-utils.js";

export async function writeFolderMapping(params: {
  analysis: FolderGroupingAnalysis;
  repoRoot?: string;
}): Promise<FolderMapping> {
  const mapping: FolderMapping = {
    version: 1,
    generated_at: new Date().toISOString(),
    source_root: params.analysis.source_root,
    groups: params.analysis.proposals.map((proposal) => ({
      parent_folder: proposal.parent_folder,
      match_type: proposal.match_type,
      token: proposal.token,
      children: [...new Set(proposal.children)]
    }))
  };

  const repoRoot = params.repoRoot ?? process.cwd();
  const mappingPath = path.resolve(repoRoot, "x_folder_mapping.json");
  await writeJsonFile(mappingPath, mapping);
  return mapping;
}

export async function writeProposalData(params: {
  analysis: FolderGroupingAnalysis;
  repoRoot?: string;
  fileName?: string;
}): Promise<string> {
  const repoRoot = params.repoRoot ?? process.cwd();
  const filePath = path.resolve(repoRoot, "analysis", safeAnalysisFileName(params.fileName));
  await writeJsonFile(filePath, params.analysis);
  return filePath;
}

function safeAnalysisFileName(fileName?: string): string {
  const fallback = "x_folder_grouping_proposal_data.json";
  const raw = (fileName ?? fallback).trim();
  const base = path.basename(raw);
  if (!base || base === "." || base === "..") {
    return fallback;
  }
  const normalized = base.replace(/[^A-Za-z0-9._-]/g, "_");
  return normalized || fallback;
}
