// @ts-nocheck
import fs from 'fs';
import path from 'path';
import { ruleBasedClassify } from './classifier.js';
import { loadFolderRules, saveFolderRules, getRoutedPath } from './router.js';
import { loadConfig, getVaultRoot, setDryRun, isDryRun } from './config.js';
import { safeRename } from './storage.js';

// コンフィグからVAULT_ROOTを読み込む
const config = loadConfig();
if (!config) {
  console.error('pipeline_config.json が見つかりません。先に pnpm start -- --config を実行してください。');
  process.exit(1);
}

// --dry-run サポート
if (process.argv.includes('--dry-run')) {
  setDryRun(true);
}

const VAULT_ROOT = getVaultRoot();

// Search Targets
const TARGET_FOLDERS = [
  path.join(VAULT_ROOT, 'Engineer/AGENT_assistant_VibeCoding'),
  path.join(VAULT_ROOT, 'Engineer/_AIエージェント要件定義'),
  path.join(VAULT_ROOT, 'Engineer/Agent_Skills'),
  path.join(VAULT_ROOT, 'Engineer/_MCP'),
  path.join(VAULT_ROOT, 'Engineer/AGENT_Development_Kit/A2A')
];

function collectMarkdownFiles(dir) {
  let results = [];
  try {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      const fullPath = path.join(dir, item);
      if (fs.statSync(fullPath).isDirectory()) {
        results = results.concat(collectMarkdownFiles(fullPath));
      } else if (fullPath.endsWith('.md')) {
        results.push(fullPath);
      }
    }
  } catch(err) { }
  return results;
}

const allFiles = [];
TARGET_FOLDERS.forEach(dir => {
  allFiles.push(...collectMarkdownFiles(dir));
});

console.log(`[Reorganize] Found ${allFiles.length} files to remap...`);

const folderAnalysis = {};
const rules = loadFolderRules();

let countVibe = 0;
let countAgentic = 0;

for (const filePath of allFiles) {
  const content = fs.readFileSync(filePath, 'utf8');
  let title = '';
  let source = '';
  let publishedDate = null;

  const titleMatch = content.match(/^title:\s*"?([^"]*)"?/m);
  if (titleMatch) title = titleMatch[1];

  const sourceMatch = content.match(/^source:\s*"?([^"]*)"?/m);
  if (sourceMatch) source = sourceMatch[1];

  const dateMatch = content.match(/^(?:date|published):\s*"?(\d{4}-\d{2}-\d{2})"?/m);
  if (dateMatch) {
    publishedDate = dateMatch[1];
  } else {
    publishedDate = fs.statSync(filePath).birthtime.toISOString().split('T')[0];
  }

  const fileName = path.basename(filePath);
  if (!title) title = fileName.replace('.md', '');

  let newBaseCat = ruleBasedClassify(source, title);
  if (!newBaseCat || newBaseCat === '__EXCLUDED__') {
     newBaseCat = 'Engineer/AGENT_assistant_VibeCoding/Other_Agents';
  }

  if (newBaseCat.includes('AgenticEngineering')) countAgentic++;
  if (newBaseCat.includes('VibeCoding')) countVibe++;

  if (!folderAnalysis[newBaseCat]) {
    folderAnalysis[newBaseCat] = { pendingFiles: [] };
  }

  folderAnalysis[newBaseCat].pendingFiles.push({ filePath, fileName, publishedDate });
}

// Create directories and apply router logic dynamically
for (const [baseCat, data] of Object.entries(folderAnalysis)) {
  let totalCount = data.pendingFiles.length;

  let currentRule = rules[baseCat] || 'none';
  let newRule = currentRule;

  if (currentRule !== 'monthly') {
     if (totalCount >= 20) newRule = 'monthly';
     else if (totalCount >= 10 && currentRule !== 'quarterly') newRule = 'quarterly';
  }

  if (newRule !== currentRule) {
      console.log(`[Threshold] '${baseCat}' rule upgraded to: ${newRule} (${totalCount} articles)`);
      rules[baseCat] = newRule;
  }

  // Physically move files
  let tempRule = { [baseCat]: newRule };
  data.pendingFiles.forEach(fileMeta => {
     let routedRel = getRoutedPath(baseCat, fileMeta.publishedDate, tempRule);
     let newAbsoluteDir = path.join(VAULT_ROOT, routedRel);

     if (!isDryRun() && !fs.existsSync(newAbsoluteDir)) {
        fs.mkdirSync(newAbsoluteDir, { recursive: true });
     }

     let targetPath = path.join(newAbsoluteDir, fileMeta.fileName);
     if (fileMeta.filePath !== targetPath) {
        safeRename(fileMeta.filePath, targetPath);
     }
  });
}

if (!isDryRun()) {
  saveFolderRules(rules);
}

// Cleanup (dry-run時はスキップ)
function cleanupEmpty(dir) {
  if (isDryRun()) return;
  if (!fs.existsSync(dir)) return;
  const items = fs.readdirSync(dir);
  for (const item of items) {
    const full = path.join(dir, item);
    if (fs.statSync(full).isDirectory()) {
      cleanupEmpty(full);
      try { fs.rmdirSync(full); } catch(e) {}
    }
  }
}

TARGET_FOLDERS.forEach(d => cleanupEmpty(d));

console.log(`\n[Reorganize Complete]`);
console.log(`📊 Category Distribution:`);
console.log(`- 🟣 Vibe Coding: ${countVibe} files`);
console.log(`- 🔵 Agentic Engineering: ${countAgentic} files`);
if (isDryRun()) {
  console.log(`\n🔍 [DRY-RUN] 上記は実際の移動を行っていません。`);
} else {
  console.log(`Empty/old folders cleared. Folder thresholds saved. ✅`);
}
