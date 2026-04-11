// @ts-nocheck
import fs from 'fs';
import path from 'path';
import { fetchRenderedHtml, closeBrowser } from './fetcher.js';
import { extractAndConvert } from './extractor.js';
import { saveMarkdown, updateVaultTreeSnapshot, ensureSafePath } from './storage.js';
import { loadConfig } from './config.js';

// コンフィグからVAULT_ROOTを読み込む
const config = loadConfig();
if (!config) {
  console.error('pipeline_config.json が見つかりません。先に npm run start -- --config を実行してください。');
  process.exit(1);
}

async function main() {
  const args = process.argv.slice(2);
  const reportPath = args[0];

  if (!reportPath || !fs.existsSync(reportPath)) {
    console.error('Usage: node rescue-from-report.js <path-to-markdown-report>');
    process.exit(1);
  }

  console.log(`Starting Rescue Mode from Report: ${reportPath}`);
  const content = fs.readFileSync(reportPath, 'utf8');
  const lines = content.split('\n');

  let currentFolder = null;
  const targetItems = [];

  // Parse Markdown Report
  for (let line of lines) {
    line = line.trim();
    // Match Folder Header: ### Engineer/LLM ✨(新規提案) or ### Engineer/LLM
    if (line.startsWith('### ')) {
      let folderName = line.replace(/^###\s+/, '').trim();
      // Strip out the new folder badge if present
      folderName = folderName.replace(/✨\(新規提案\)/, '').trim();
      currentFolder = folderName;
      continue;
    }

    const linkMatch = line.match(/^- \[\d+\] \[(.*?)\]\((.*?)\)/);
    if (linkMatch && currentFolder) {
      const title = linkMatch[1];
      const url = linkMatch[2];
      const safeFolder = ensureSafePath(currentFolder);
      targetItems.push({
        url,
        title,
        folder: safeFolder
      });
    }
  }

  if (targetItems.length === 0) {
    console.log('No valid classification links found in the report.');
    process.exit(1);
  }

  console.log(`\nFound ${targetItems.length} items to rescue and save.`);
  console.log('AI Classification will be SKIPPED (saving API costs).');
  console.log('Proceeding to Web Fetch and Direct Vault Save...\n');

  let successCount = 0;
  const CONCURRENCY_LIMIT = 5;

  for (let i = 0; i < targetItems.length; i += CONCURRENCY_LIMIT) {
    const chunkItems = targetItems.slice(i, i + CONCURRENCY_LIMIT);

    const mappedPromises = chunkItems.map(async (item, indexInChunk) => {
      const globalIndex = i + indexInChunk + 1;

      try {
        const html = await fetchRenderedHtml(item.url);
        const article = extractAndConvert(html, item.url);

        saveMarkdown(article, item.folder);
        console.log(`[${globalIndex}/${targetItems.length}] ${item.title.substring(0, 30)}... ✅ Saved to ${item.folder}`);
        return true;
      } catch (err) {
        console.log(`[${globalIndex}/${targetItems.length}] ${item.title.substring(0, 30)}... ❌ Failed: ${err.message}`);
        return false;
      }
    });

    const chunkResults = await Promise.all(mappedPromises);
    for (const isSuccess of chunkResults) {
      if (isSuccess) successCount++;
    }
  }

  await closeBrowser();

  if (successCount > 0) {
     updateVaultTreeSnapshot();
     console.log(`\n🎉 Rescue Complete! ${successCount}/${targetItems.length} articles successfully saved to Vault.`);
     console.log(`\n## 💸 APIトークン使用量と概算コスト`);
     console.log(`- **AI推論スキップ (Rescue Mode)**: Input 0 tokens, Output 0 tokens (約 $0.0000)`);
     console.log(`\n**💰 Total Estimated Cost: $0.0000**\n`);
  }
  process.exit(0);
}

main();
