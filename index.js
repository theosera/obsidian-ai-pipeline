import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { fetchRenderedHtml, closeBrowser } from './fetcher.js';
import { extractAndConvert } from './extractor.js';
import { classifyArticle, tokenUsageMetrics } from './classifier.js';
import { saveMarkdown, updateVaultTreeSnapshot, getKnownUrls } from './storage.js';
import { loadConfig, runConfigWizard, applyConfigToEnv } from './config.js';
import { loadFolderRules, updateThresholds, getRoutedPath } from './router.js';

const VAULT_ROOT = '/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026';
const REPORTS_DIR = path.join(VAULT_ROOT, '__skills', 'pipeline', 'reports');

if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

function evaluatePolicy(url) {
  const skipList = ['google.com/search', 'x.com', 'youtube.com', 'chatgpt.com', 'grok.com', 'gemini.google.com'];
  if (skipList.some(s => url.includes(s))) return 'manual_skip';

  const reviewList = ['note.com', 'wired.jp'];
  if (reviewList.some(s => url.includes(s))) return 'public_review';
  
  // Future: specify explicit login_auto domains if needed
  // For now, Playwright always uses persistent profile, so it inherently acts as login_auto.
  return 'public_auto';
}

const PRICING_MILLION_TOKENS = {
  'gpt-4o': { in: 5.00, out: 15.00 },
  'gpt-4o-mini': { in: 0.15, out: 0.60 },
  'gemini-2.5-flash': { in: 0.075, out: 0.30 },
  'gemini-2.5-pro': { in: 1.25, out: 5.00 },
  'claude-haiku-4-5-20251001': { in: 0.25, out: 1.25 },
  'claude-3-5-haiku-20241022': { in: 0.25, out: 1.25 },
  'claude-sonnet-4-6': { in: 3.00, out: 15.00 },
  'claude-3-7-sonnet-20250219': { in: 3.00, out: 15.00 },
  'claude-opus-4-6': { in: 15.00, out: 75.00 }
};

function generateReport(results, usageData = {}) {
  let successResults = results.filter(r => r.status === 'success');
  let newFolders = successResults.filter(r => r.classification.isNewFolder);
  let reviewItems = successResults.filter(r => r.policy === 'public_review');
  
  let report = `# OneTab分類結果レポート\n\n`;
  report += `## 📊 実行サマリー\n`;
  report += `- **総取得件数:** ${successResults.length}件\n`;
  report += `- **新規提案フォルダ数:** ${newFolders.length}件\n`;
  report += `- **要レビュー(note/wired等):** ${reviewItems.length}件\n\n`;

  // === 💸 Token Usage & Cost ===
  if (Object.keys(usageData).length > 0) {
    report += `## 💸 APIトークン使用量と概算コスト\n`;
    let totalCost = 0;
    for (const [model, stats] of Object.entries(usageData)) {
       const rates = PRICING_MILLION_TOKENS[model] || { in: 0, out: 0 };
       const costIn = (stats.input / 1000000) * rates.in;
       const costOut = (stats.output / 1000000) * rates.out;
       const modelCost = costIn + costOut;
       totalCost += modelCost;
       
       report += `- **${model}**: Input ${stats.input.toLocaleString()} tokens, Output ${stats.output.toLocaleString()} tokens `;
       if (modelCost > 0) report += `(約 $${modelCost.toFixed(4)})\n`;
       else report += `(Local or Rate Unknown)\n`;
    }
    report += `\n**💰 Total Estimated Cost: $${totalCost.toFixed(4)}**\n\n`;
  }
  
  report += `## 📁 分類結果詳細\n\n`;
  
  // Group by folder
  let groups = {};
  for (let res of successResults) {
    let folder = res.classification.proposedPath;
    if (!groups[folder]) groups[folder] = [];
    groups[folder].push(res);
  }

  for (let [folder, items] of Object.entries(groups)) {
    let isNew = items[0].classification.isNewFolder;
    report += `### ${folder} ${isNew ? '✨(新規提案)' : ''}\n`;
    
    // For new folders, add reasoning block at the top
    if (isNew) {
      if (items[0].classification.trendReasoning) report += `> **対応トレンド**: ${items[0].classification.trendReasoning}\n`;
      if (items[0].classification.diffReasoning) report += `> **既存との違い**: ${items[0].classification.diffReasoning}\n\n`;
    }

    for (let item of items) {
      const reviewBadge = item.policy === 'public_review' ? ' ⚠️[要完全性チェック]' : '';
      report += `- [${item.id}] [${item.title || 'No Title'}](${item.url})${reviewBadge}\n`;
      if (item.classification.reasoning && !isNew) {
         report += `  - *理由: ${item.classification.reasoning}*\n`;
      }
    }
    report += `\n`;
  }

  return report;
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
const askQuestion = (q) => new Promise(resolve => rl.question(q, resolve));

async function interactiveReviewLoop(results, reportMdPath) {
  let reviewing = true;

  while (reviewing) {
    // Regenerate report visually in short form for terminal, or advise checking the file.
    console.log(`\n=========================================`);
    console.log(`Report generated at: ${reportMdPath}`);
    console.log(`Type [y] to Approve all & save, [e] to Edit a classification, [q] to Quit/Abort.`);
    
    const cmd = (await askQuestion('Command [y/e/q]: ')).toLowerCase();

    if (cmd === 'y') {
      console.log('\n🚀 Approved! Proceeding to save files to Vault...');
      for (const res of results) {
        if (res.status === 'success') {
          try {
            const savedPath = saveMarkdown(res.articleContext, res.classification.proposedPath);
            console.log(` ✅ Saved: ${savedPath}`);
          } catch (e) {
            console.error(` ❌ Error saving ${res.url}: ${e.message}`);
          }
        }
      }
      console.log('🎉 All files saved.');
      updateVaultTreeSnapshot(); // Update to capture any newly created folders
      reviewing = false;
    } else if (cmd === 'e') {
      const idStr = await askQuestion('Enter the item ID (e.g., 1): ');
      const itemId = parseInt(idStr, 10);
      const target = results.find(r => r.id === itemId);

      if (target) {
        console.log(`Current Path: ${target.classification.proposedPath}`);
        const newPath = await askQuestion('Enter new folder path (leave empty to cancel): ');
        if (newPath.trim() !== '') {
          target.classification.proposedPath = newPath.trim();
          target.classification.isNewFolder = false; // Disable new folder badging manually overridden
          console.log(`Updated!`);
          
          // Re-write the report file
          const newReportMd = generateReport(results, tokenUsageMetrics);
          fs.writeFileSync(reportMdPath, newReportMd, 'utf8');
        }
      } else {
        console.log('Item ID not found.');
      }
    } else if (cmd === 'q') {
      console.log('Aborted execution.');
      reviewing = false;
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  const isConfigMode = args.includes('--config');
  const filePath = args.find(a => !a.startsWith('--'));

  let config = loadConfig();

  // If no config found or user explicitly requests config, run wizard
  if (!config || isConfigMode) {
    if (!filePath && !isConfigMode) {
      console.error('Usage: node index.js <path-to-onetab.txt> [--config]');
      process.exit(1);
    }
    config = await runConfigWizard(askQuestion);
    if (isConfigMode && !filePath) {
      console.log('Configuration finished. Exiting.');
      process.exit(0);
    }
  }

  // Apply to process.env dynamically
  applyConfigToEnv(config);

  console.log('\n======================================================');
  console.log(`🤖 AI Provider: ${config.provider}`);
  console.log(`🔹 Step 1 Model (Fast): ${config.fastModel}`);
  console.log(`🔸 Step 2 Model (Smart): ${config.smartModel}`);
  console.log('💡 Run with `--config` anytime to change these settings.');
  console.log('======================================================\n');

  // Update vault tree snapshot at startup to capture any manual user changes
  updateVaultTreeSnapshot();

  if (!filePath) {
    console.error('Usage: node index.js <path-to-onetab.txt>');
    process.exit(1);
  }

  const content = fs.readFileSync(filePath, 'utf-8');
  const allLines = content.split('\n').filter(l => l.trim() !== '');

  // Parse lines and pre-filter skips so they don't consume parallel slots
  const parsedEntries = [];
  const failures = [];
  
  // Index existing URLs to avoid duplicates
  console.log(`\n🔍 Indexing existing articles in the Vault...`);
  const knownUrls = getKnownUrls();
  console.log(`Found ${knownUrls.size} unique URLs already saved.\n`);

  for (let i = 0; i < allLines.length; i++) {
    const line = allLines[i];
    const pipeIdx = line.indexOf(' | ');
    if (pipeIdx === -1) continue;
    const url = line.substring(0, pipeIdx).trim();
    const title = line.substring(pipeIdx + 3).trim();

    const checkUrl = url.endsWith('/') ? url.slice(0, -1) : url;
    if (knownUrls.has(checkUrl)) {
      console.log(`[${i + 1}/${allLines.length}] ${title.substring(0, 30)}... Skipped (Duplicate in Vault)`);
      failures.push({ url, title, reason: 'Duplicate: Already exists in Vault' });
      continue;
    }

    const policy = evaluatePolicy(url);
    if (policy === 'manual_skip') {
      console.log(`[${i + 1}/${allLines.length}] ${title.substring(0, 30)}... Skipped (manual_skip)`);
      failures.push({ url, title, reason: 'Site Policy: manual_skip' });
    } else {
      parsedEntries.push({ url, title, policy });
    }
  }

  console.log(`Starting Phase 3 Pipeline... found ${parsedEntries.length} fetchable URLs (${failures.length} skipped).`);
  console.log(`Performing content fetching and classification (This may take several minutes...)`);
  
  const results = [];
  let idCounter = 1;

  const CONCURRENCY_LIMIT = 5;
  for (let i = 0; i < parsedEntries.length; i += CONCURRENCY_LIMIT) {
    const chunkEntries = parsedEntries.slice(i, i + CONCURRENCY_LIMIT);
    
    const mappedPromises = chunkEntries.map(async (entry, indexInChunk) => {
      const globalIndex = i + indexInChunk + 1;
      const { url, title, policy } = entry;

      try {
        const html = await fetchRenderedHtml(url);
        const article = extractAndConvert(html, url);
        const finalTitle = article.title || title;

        const classification = await classifyArticle(url, finalTitle, article.textContent);
        
        if (classification.proposedPath === '__EXCLUDED__') {
          console.log(`[${globalIndex}/${parsedEntries.length}] ${finalTitle.substring(0, 30)}... Skipped (Excluded by Rule)`);
          return { failure: true, url, title: finalTitle, reason: 'RuleBased Exclusion' };
        } else {
          console.log(`[${globalIndex}/${parsedEntries.length}] ${finalTitle.substring(0, 30)}... => ${classification.proposedPath}`);
          return { 
            success: true, 
            data: {
              url, 
              title: finalTitle, 
              policy, 
              classification,
              articleContext: { ...article, url }
            }
          };
        }
      } catch (err) {
        console.log(`[${globalIndex}/${parsedEntries.length}] ${title.substring(0, 30)}... Failed: ${err.message}`);
        return { failure: true, url, title, reason: err.message };
      }
    });

    const chunkResults = await Promise.all(mappedPromises);
    for (const res of chunkResults) {
      if (!res) continue;
      if (res.failure) {
        failures.push({ url: res.url, title: res.title, reason: res.reason });
      } else if (res.success) {
        results.push({
          id: idCounter++,
          status: 'success',
          ...res.data
        });
      }
    }
  }

  // Close browser contexts
  await closeBrowser();

  const dateStr = new Date().toISOString().split('T')[0].replace(/-/g, '');
  
  // Output Failures to failure log
  if (failures.length > 0) {
    const failedContent = failures.map(f => `${f.url} | ${f.title}`).join('\n');
    const failedPath = path.join(REPORTS_DIR, `failed_onetab_${dateStr}.txt`);
    fs.writeFileSync(failedPath, failedContent, 'utf8');
    console.log(`\n⚠️ Saved ${failures.length} failed/skipped items to ${failedPath}`);
  }

  if (results.length === 0) {
    console.log('\nNo items were successfully processed. Exiting.');
    process.exit(0);
  }

  // ==========================================
  // Router Phase: Automatically upgrade folder hierarchies (Thresholds)
  // and append Dates based on Original Article Published Date!
  // ==========================================
  const currentRules = loadFolderRules();
  const updatedRules = updateThresholds(results, currentRules);

  for (const res of results) {
    if (res.status === 'success') {
      const baseCat = res.classification.proposedPath;
      const pubDate = res.articleContext.date; 
      const finalRoutedPath = getRoutedPath(baseCat, pubDate, updatedRules);
      
      // Override proposedPath so the report generation and interactive UI 
      // work identically but show the correct strict date folder.
      res.classification.proposedPath = finalRoutedPath;
    }
  }

  // Generate Report
  const reportMd = generateReport(results, tokenUsageMetrics);
  const reportPath = path.join(REPORTS_DIR, `OneTab分類結果レポート-${dateStr}.md`);
  fs.writeFileSync(reportPath, reportMd, 'utf8');

  // Interactive Loop
  await interactiveReviewLoop(results, reportPath);

  rl.close();
  process.exit(0);
}

main();

