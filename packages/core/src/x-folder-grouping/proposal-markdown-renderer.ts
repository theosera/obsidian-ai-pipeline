import type { FolderGroupingAnalysis } from "../types/shared.js";

export function renderGroupingProposalMarkdown(analysis: FolderGroupingAnalysis): string {
  const lines: string[] = [];
  lines.push("# X Folder Grouping Proposal Report", "");
  lines.push(`- Generated at: ${analysis.generated_at}`);
  lines.push(`- Source root: ${analysis.source_root}`);
  lines.push(`- Analyzed folders: ${analysis.analyzed_folder_count}`);
  lines.push("- Algorithm: token boundary split by space/underscore/hyphen, exact prefix/suffix token matching");
  lines.push("");

  if (analysis.proposals.length === 0) {
    lines.push("No valid proposals were found.", "");
  }

  analysis.proposals.forEach((proposal, index) => {
    lines.push(`## Proposal ${index + 1}`);
    lines.push(`- Parent candidate: ${proposal.parent_folder}`);
    lines.push(`- Match type: ${proposal.match_type}`);
    lines.push(`- Token: ${proposal.token}`);
    lines.push("- Children:");
    for (const child of proposal.children) {
      lines.push(`  - ${child}`);
    }
    lines.push(`- Count: ${proposal.children.length}`);
    lines.push("- Proposed path:");
    for (const child of proposal.children) {
      lines.push(`  - ${analysis.source_root}/${proposal.parent_folder}/${child}/<YYYY-Qn or YYYY-MM>/post.md`);
    }
    lines.push("- Reason:");
    proposal.reason.forEach((reason) => lines.push(`  - ${reason}`));
    lines.push(`- Confidence: ${proposal.confidence.toFixed(2)}`);
    lines.push("- Notes: Proposal only. No folder move or mapping apply is executed.");
    lines.push("");
  });

  lines.push("### Skipped candidates");
  if (analysis.skipped.length === 0) {
    lines.push("- None");
  } else {
    for (const skipped of analysis.skipped) {
      lines.push(
        `- token: ${skipped.token || "(empty)"}, match_type: ${skipped.match_type}, folders: ${skipped.folders.length}, reason: ${skipped.reason}`
      );
    }
  }

  lines.push("");
  lines.push("## Approval");
  lines.push("Run `pnpm approve:grouping` after reviewing this proposal.");
  lines.push("Approval generates x_folder_mapping.json only after explicit user action.");

  return lines.join("\n") + "\n";
}
