import "dotenv/config";
import path from "node:path";
import fs from "node:fs/promises";
import {
  detectFolderGroupings,
  loadEnvConfig,
  renderGroupingProposalMarkdown,
  writeProposalData,
  readJsonFile,
  fileExists
} from "@obsidian-ai-pipeline/core";

const repoRoot = path.resolve(process.cwd(), "../..");
const config = loadEnvConfig(repoRoot);

async function loadFolderNamesFromStats(): Promise<string[]> {
  const statsPath = path.resolve(repoRoot, "analysis", "x_folder_stats.json");
  if (!(await fileExists(statsPath))) {
    throw new Error(
      `Missing folder stats file: ${statsPath}. Run pnpm sync once before propose:grouping.`
    );
  }

  const stats = await readJsonFile<{ folders: Record<string, number> }>(statsPath);
  return Object.keys(stats.folders).filter((name) => name !== "root");
}

async function run(): Promise<void> {
  const folderNames = await loadFolderNamesFromStats();
  const analysis = detectFolderGroupings({
    folderNames,
    sourceRoot: config.sourceRoot
  });

  const proposalMarkdown = renderGroupingProposalMarkdown(analysis);
  const mdPath = path.resolve(repoRoot, "analysis", "x_folder_grouping_proposal.md");
  await fs.mkdir(path.dirname(mdPath), { recursive: true });
  await fs.writeFile(mdPath, proposalMarkdown, "utf-8");

  const dataPath = await writeProposalData({ analysis, repoRoot });

  console.log(`Proposal written: ${mdPath}`);
  console.log(`Internal proposal data written: ${dataPath}`);
  console.log("No mapping file was generated. Run pnpm approve:grouping after approval.");
}

run().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : error);
  process.exit(1);
});
