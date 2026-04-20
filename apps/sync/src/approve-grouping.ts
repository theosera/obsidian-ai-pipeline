import "dotenv/config";
import path from "node:path";
import {
  fileExists,
  readJsonFile,
  writeFolderMapping,
  type FolderGroupingAnalysis
} from "@obsidian-ai-pipeline/core";

const repoRoot = path.resolve(process.cwd(), "../..");

async function run(): Promise<void> {
  const proposalDataPath = path.resolve(repoRoot, "analysis", "x_folder_grouping_proposal_data.json");
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
