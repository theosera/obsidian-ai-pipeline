import fs from "node:fs/promises";
import path from "node:path";
import {
  loadEnvConfig,
  fileExists,
  readJsonFile,
  writeFolderMapping,
  type FolderGroupingAnalysis
} from "@obsidian-ai-pipeline/core";

const repoRoot = path.resolve(process.cwd(), "../..");
const config = loadEnvConfig(repoRoot);

async function findLatestProposalDataFile(): Promise<string> {
  const analysisDir = path.resolve(repoRoot, "analysis");
  const files = await fs.readdir(analysisDir);
  const prefix = `x_folder_grouping_proposal_${config.proposalPrefix}_`;
  const candidates = files
    .filter((file) => file.startsWith(prefix) && file.endsWith(".json"))
    .sort((a, b) => b.localeCompare(a));
  if (candidates.length === 0) {
    throw new Error(
      `No proposal data found with prefix ${prefix}. Run pnpm propose:grouping first.`
    );
  }
  return path.join(analysisDir, candidates[0] as string);
}

async function run(): Promise<void> {
  const proposalDataPath = await findLatestProposalDataFile();
  if (!(await fileExists(proposalDataPath))) {
    throw new Error(
      `Missing proposal data: ${proposalDataPath}. Run pnpm propose:grouping before approval.`
    );
  }

  const analysis = await readJsonFile<FolderGroupingAnalysis>(proposalDataPath);
  const mapping = await writeFolderMapping({ analysis, repoRoot });

  console.log(`Approved ${mapping.groups.length} grouping proposals.`);
  console.log(`Mapping file generated: ${path.resolve(repoRoot, "x_folder_mapping.json")}`);
}

run().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : error);
  process.exit(1);
});
