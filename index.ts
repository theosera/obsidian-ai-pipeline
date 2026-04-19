import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { fetchRenderedHtml, closeBrowser } from './fetcher';
import { extractAndConvert } from './extractor';
import { classifyArticle, tokenUsageMetrics } from './classifier';
import { saveMarkdown, updateVaultTreeSnapshot, getKnownUrls, ensureSafePath, getVaultFolders } from './storage';
import { loadConfig, runConfigWizard, applyConfigToEnv, getVaultRoot, setDryRun } from './config';
import { loadFolderRules, updateThresholds, getRoutedPath, stripDateSuffix } from './router';
import { syncRulesFromSnippets } from './sync-rules';
import { ArticleData, ClassificationResult, ProcessingResult } from './types';
import { scrapeBookmarksByFolder, ScrapedBookmark } from './x_bookmarks_scraper';
import {
  loadForcedParents,
  loadApprovedMappings,
  mapFolderToVaultPath,
  detectCommonKeywords,
  writeGroupingProposal,
} from './x_folder_mapper';
import { getDb, closeDb } from './x_bookmarks_db';

/**
 * X API ブックマーク専用のベースフォルダ。
 * 通常記事の Classifier によるフォルダ分類とは別系統で、
 * すべての X ブックマークをここに集約する（混入防止・監査容易化）。
 *
 * 環境変数 X_BOOKMARKS_FOLDER で上書き可能。
 * Router の閾値 (QUARTERLY=10 / MONTHLY=20) を超えると、
 * 自動で `Clippings/X-Bookmarks/2026-Q2` のような日付サブフォルダへ昇格する。
 */
const X_BOOKMARKS_BASE_FOLDER = process.env.X_BOOKMARKS_FOLDER || 'Clippings/X-Bookmarks';

/**
 * 1 本の処理対象。通常の OneTab URL は preFetched=undefined で、
 * fetcher/extractor を通して HTML → ArticleData に変換する。
 * X ブックマークなど API 経由で既に構造化済みのソースは preFetched に
 * ArticleData を詰めておけば、後段はそのまま Classifier に流れる。
 */
type ParsedEntry = {
  url: string;
  title: string;
  policy: string;
  preFetched?: ArticleData;
};

function evaluatePolicy(url: string): string {
  const skipList = ['google.com/search', 'x.com', 'youtube.com', 'chatgpt.com', 'grok.com', 'gemini.google.com'];
  if (skipList.some(s => url.includes(s))) return 'manual_skip';

  const reviewList = ['note.com', 'wired.jp'];
  if (reviewList.some(s => url.includes(s))) return 'public_review';
  
  // Future: specify explicit login_auto domains if needed
  // For now, Playwright always uses persistent profile, so it inherently acts as login_auto.
  return 'public_auto';
}

const PRICING_MILLION_TOKENS: Record<string, { in: number, out: number }> = {
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

/**
 * 日付サブフォルダ (`/YYYY-Qn` or `/YYYY-MM`) を剥がしたベースカテゴリが
 * 既に Vault に存在するなら「新規ジャンルではない」(= router が自動付与した
 * 日付サブフォルダにすぎない) と判定する。
 *
 * これにより、レポートの ✨(新規提案) は純粋な新カテゴリだけに限定され、
 * 既にルールベースで承認済みの日付サブフォルダは「新規」扱いされない。
 */
function isGenuinelyNewFolder(proposedPath: string, vaultFolders: string[]): boolean {
  const base = stripDateSuffix(proposedPath);
  // 日付 suffix がなかった (= proposedPath そのまま) ならベース判定に意味がない
  if (base === proposedPath) return true;
  // ベースが既存なら「新規」ではない
  return !vaultFolders.includes(base);
}

function generateReport(results: ProcessingResult[], usageData: Record<string, any> = {}): string {
  let successResults = results.filter(r => r.status === 'success');
  const vaultFolders = getVaultFolders();

  // classifier が isNewFolder=true でも、日付サブフォルダで親カテゴリが既存なら新規扱いしない
  for (const r of successResults) {
    if (r.classification?.isNewFolder && r.classification.proposedPath) {
      if (!isGenuinelyNewFolder(r.classification.proposedPath, vaultFolders)) {
        r.classification.isNewFolder = false;
      }
    }
  }

  let newFolders = successResults.filter(r => r.classification?.isNewFolder);
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
  let groups: Record<string, ProcessingResult[]> = {};
  for (let res of successResults) {
    if (!res.classification) continue;
    let folder = res.classification.proposedPath;
    if (!groups[folder]) groups[folder] = [];
    groups[folder].push(res);
  }

  for (let [folder, items] of Object.entries(groups)) {
    let isNew = items[0].classification!.isNewFolder;
    report += `### ${folder} ${isNew ? '✨(新規提案)' : ''}\n`;
    
    // For new folders, add reasoning block at the top
    if (isNew) {
      if (items[0].classification!.trendReasoning) report += `> **対応トレンド**: ${items[0].classification!.trendReasoning}\n`;
      if (items[0].classification!.diffReasoning) report += `> **既存との違い**: ${items[0].classification!.diffReasoning}\n\n`;
    }

    for (let item of items) {
      const reviewBadge = item.policy === 'public_review' ? ' ⚠️[要完全性チェック]' : '';
      report += `- [${item.id}] [${item.title || 'No Title'}](${item.url})${reviewBadge}\n`;
      if (item.classification!.reasoning && !isNew) {
         report += `  - *理由: ${item.classification!.reasoning}*\n`;
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

/**
 * stdin が閉じられた (EOF / パイプ終了) 後にも安全に呼べる質問ヘルパー。
 * - rl.close() / stdin close 後は rl.question が ERR_USE_AFTER_CLOSE で throw するため、
 *   その場合は空文字を resolve してフローに「入力なし」を伝える。
 * - インタラクティブループ側で空文字 = quit 扱いに正規化する。
 */
let rlClosed = false;
rl.on('close', () => { rlClosed = true; });

const askQuestion = (q: string): Promise<string> => new Promise(resolve => {
  if (rlClosed) {
    resolve('');
    return;
  }
  try {
    rl.question(q, (answer) => resolve(answer ?? ''));
  } catch {
    resolve('');
  }
});

async function interactiveReviewLoop(results: ProcessingResult[], reportMdPath: string): Promise<void> {
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
        if (res.status === 'success' && res.articleContext && res.classification) {
          try {
            const savedPath = saveMarkdown(res.articleContext, res.classification.proposedPath);
            console.log(` ✅ Saved: ${savedPath}`);
            // X ブックマーク経由なら SQLite メタデータキャッシュにも反映 (差分スクレイプ用)
            const ax = res.articleContext as ScrapedBookmark;
            if (res.policy === 'x_bookmark' && ax.xTweetId) {
              try {
                getDb().upsertBookmark({
                  tweetId: ax.xTweetId,
                  url: ax.url,
                  tweetText: ax.textContent,
                  createdAt: ax.date,
                  xFolderName: ax.xFolderName,
                  vaultPath: savedPath,
                });
              } catch (dbErr: any) {
                console.warn(`   ⚠️  DB upsert 失敗 (続行): ${dbErr.message}`);
              }
            }
          } catch (e: any) {
            console.error(` ❌ Error saving ${res.url}: ${e.message}`);
          }
        }
      }
      console.log('🎉 All files saved.');
      updateVaultTreeSnapshot(); // Update to capture any newly created folders
      closeDb();
      reviewing = false;
    } else if (cmd === 'e') {
      const idStr = await askQuestion('Enter the item ID (e.g., 1): ');
      const itemId = parseInt(idStr, 10);
      const target = results.find(r => r.id === itemId);

      if (target && target.classification) {
        console.log(`Current Path: ${target.classification.proposedPath}`);
        const newPath = await askQuestion('Enter new folder path (leave empty to cancel): ');
        if (newPath.trim() !== '') {
          const safePath = ensureSafePath(newPath.trim());
          if (safePath !== newPath.trim()) {
            console.log(`[Security] パスがサニタイズされました: "${newPath.trim()}" -> "${safePath}"`);
          }
          target.classification.proposedPath = safePath;
          target.classification.isNewFolder = false;
          console.log(`Updated!`);
          
          // Re-write the report file
          const newReportMd = generateReport(results, tokenUsageMetrics);
          fs.writeFileSync(reportMdPath, newReportMd, 'utf8');
        }
      } else {
        console.log('Item ID not found or already excluded.');
      }
    } else if (cmd === 'q') {
      console.log('Aborted execution.');
      reviewing = false;
    } else if (cmd === '' && rlClosed) {
      // stdin EOF: 非対話環境（パイプ実行等）。レポートは既に生成済みなので、
      // Vault への保存はスキップして安全に終了する。
      // 後で `pnpm start -- --rescue <reportPath>` で API コスト 0 で再開可能。
      console.log('\n⚠️ stdin が閉じられました（非対話実行）。');
      console.log(`   レポートは生成済み: ${reportMdPath}`);
      console.log('   レビュー後、以下で Vault への保存を実行できます:');
      console.log(`   pnpm start -- --rescue "${reportMdPath}"`);
      reviewing = false;
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  const isConfigMode = args.includes('--config');
  const isDryRunMode = args.includes('--dry-run');
  const isSyncRulesMode = args.includes('--sync-rules');
  const isXBookmarksMode = args.includes('--x-bookmarks');
  const xLimitArg = args.find(a => a.startsWith('--x-limit='));
  const xLimit = xLimitArg ? parseInt(xLimitArg.split('=')[1], 10) : undefined;
  const filePath = args.find(a => !a.startsWith('--'));

  if (isDryRunMode) {
    setDryRun(true);
  }

  let config = loadConfig();

  // If no config found or user explicitly requests config, run wizard
  if (!config || isConfigMode) {
    if (!filePath && !isConfigMode && !isXBookmarksMode) {
      console.error('Usage: tsx index.ts <path-to-onetab.txt> [--config] [--dry-run]');
      console.error('       tsx index.ts --x-bookmarks [--x-limit=N] [--dry-run]');
      process.exit(1);
    }
    config = await runConfigWizard(askQuestion);
    if (isConfigMode && !filePath && !isXBookmarksMode) {
      console.log('Configuration finished. Exiting.');
      process.exit(0);
    }
  }

  // Apply to process.env dynamically
  applyConfigToEnv(config);

  // --sync-rules: snippets.xml → folder_rules.json を同期して終了
  if (isSyncRulesMode) {
    syncRulesFromSnippets();
    process.exit(0);
  }

  console.log('\n======================================================');
  console.log(`🤖 AI Provider: ${config?.provider}`);
  console.log(`🔹 Step 1 Model (Fast): ${config?.fastModel}`);
  console.log(`🔸 Step 2 Model (Smart): ${config?.smartModel}`);
  console.log('💡 Run with `--config` anytime to change these settings.');
  console.log('======================================================\n');

  // 分類結果レポートの出力先: context/分類結果レポート/
  const REPORTS_DIR = path.join(getVaultRoot(), '__skills', 'context', '分類結果レポート');
  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }
  // パイプライン内部ログ（failed 等）の出力先: pipeline/reports/
  const INTERNAL_LOGS_DIR = path.join(getVaultRoot(), '__skills', 'pipeline', 'reports');
  if (!fs.existsSync(INTERNAL_LOGS_DIR)) {
    fs.mkdirSync(INTERNAL_LOGS_DIR, { recursive: true });
  }

  // Update vault tree snapshot at startup to capture any manual user changes
  updateVaultTreeSnapshot();

  if (!filePath && !isXBookmarksMode) {
    console.error('Usage: tsx index.ts <path-to-onetab.txt>');
    console.error('   or: tsx index.ts --x-bookmarks [--x-limit=N]');
    process.exit(1);
  }

  const parsedEntries: ParsedEntry[] = [];
  const failures: { url: string; title: string; reason: string }[] = [];

  // Index existing URLs to avoid duplicates
  console.log(`\n🔍 Indexing existing articles in the Vault...`);
  const knownUrls = getKnownUrls();
  console.log(`Found ${knownUrls.size} unique URLs already saved.\n`);

  if (isXBookmarksMode) {
    // ==========================================
    // X (Twitter) Playwright スクレイピングでブックマークを取得し、
    // フォルダ構造を保持したまま Vault にマッピングする。
    // fetcher/extractor をスキップして Classifier に直接流し込む。
    // ==========================================
    console.log('🔖 X Playwright スクレイピングでブックマークを取得します...');
    const db = getDb();
    const knownTweetIds = db.getKnownTweetIds();
    const forcedParents = loadForcedParents();
    const approvedMap = loadApprovedMappings();
    console.log(`🔖 強制親フォルダキーワード: ${forcedParents.length > 0 ? forcedParents.join(', ') : '(未設定)'}`);
    console.log(`🔖 既知ツイートID: ${knownTweetIds.size} 件 (DB キャッシュ)`);

    let bookmarks: ScrapedBookmark[];
    try {
      bookmarks = await scrapeBookmarksByFolder({ maxItems: xLimit, skipKnownIds: knownTweetIds });
    } catch (e: any) {
      console.error(`❌ X ブックマーク取得失敗: ${e.message}`);
      process.exit(1);
    }

    // 共通キーワード提案レポート (未マッチフォルダのみ対象)
    const folderNamesRaw = [...new Set(bookmarks.map(b => b.xFolderName))];
    const proposals = detectCommonKeywords(folderNamesRaw, forcedParents);
    if (proposals.length > 0) {
      const reportPath = writeGroupingProposal(proposals);
      console.log(`📋 共通キーワード提案レポート: ${reportPath}`);
      console.log(`   → 親フォルダとして承認するなら x_forced_parents.json に追記してください。`);
    }

    for (let i = 0; i < bookmarks.length; i++) {
      const bm = bookmarks[i];
      const url = bm.url;
      const title = bm.title || `X post ${i + 1}`;
      const checkUrl = url.endsWith('/') ? url.slice(0, -1) : url;
      if (knownUrls.has(checkUrl)) {
        console.log(`[${i + 1}/${bookmarks.length}] ${title.substring(0, 40)}... Skipped (Duplicate in Vault)`);
        failures.push({ url, title, reason: 'Duplicate: Already exists in Vault' });
        continue;
      }

      // X 側フォルダ名 → Vault 階層パスに変換 (Tier 1: 強制親 / Tier 2: 承認済みマップ / Tier 3: そのまま)
      const vaultSubPath = mapFolderToVaultPath(bm.xFolderName, forcedParents, approvedMap);
      // 後段の Classifier バイパス側でこのパスを参照する
      bm.xFolderName = vaultSubPath;

      // X ブックマークは evaluatePolicy をバイパス（x.com は通常 manual_skip）
      parsedEntries.push({ url, title, policy: 'x_bookmark', preFetched: bm });
    }
  } else {
    const content = fs.readFileSync(filePath!, 'utf-8');
    const allLines = content.split('\n').filter(l => l.trim() !== '');

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
  }

  // ==========================================
  // 実行前ユーザー確認（フェッチ開始前）
  // ==========================================
  console.log(`\n📋 処理予定: ${parsedEntries.length} 件 / スキップ: ${failures.length} 件`);
  console.log(`📁 分類結果レポート出力先: ${REPORTS_DIR}`);
  if (isDryRunMode) console.log('🧪 dry-run モード: Vault へのファイル書き込みはスキップされます。');
  if (isXBookmarksMode) console.log('🔖 X ブックマークモード');
  const preConfirm = (await askQuestion('\nパイプラインを実行しますか？ [y/n]: ')).toLowerCase().trim();
  if (preConfirm !== 'y') {
    console.log('キャンセルしました。');
    await closeBrowser();
    rl.close();
    process.exit(0);
  }

  console.log(`\nStarting Phase 3 Pipeline... found ${parsedEntries.length} fetchable URLs (${failures.length} skipped).`);
  console.log(`Performing content fetching and classification (This may take several minutes...)`);
  
  const results: ProcessingResult[] = [];
  let idCounter = 1;

  const CONCURRENCY_LIMIT = 5;
  for (let i = 0; i < parsedEntries.length; i += CONCURRENCY_LIMIT) {
    const chunkEntries = parsedEntries.slice(i, i + CONCURRENCY_LIMIT);
    
    const mappedPromises = chunkEntries.map(async (entry, indexInChunk) => {
      const globalIndex = i + indexInChunk + 1;
      const { url, title, policy, preFetched } = entry;

      try {
        // X ブックマーク等、構造化済みソースは preFetched を使い fetch/extract を飛ばす
        const article = preFetched
          ? preFetched
          : extractAndConvert(await fetchRenderedHtml(url), url);
        const finalTitle = article.title || title;

        // X ブックマークは Classifier を通さず専用フォルダに固定ルーティングする。
        //   - 他ジャンルへの混入を防ぐ（監査性）
        //   - 短いツイート本文に対する分類 API コストを削減
        //   - Router の日付ベース昇格は通常通り適用される
        //   - フォルダ階層は x_folder_mapper で X 側フォルダ名から事前変換済み (article.xFolderName)
        const xFolderSubPath = (article as ScrapedBookmark).xFolderName;
        const classification: ClassificationResult =
          policy === 'x_bookmark'
            ? {
                proposedPath: xFolderSubPath
                  ? `${X_BOOKMARKS_BASE_FOLDER}/${xFolderSubPath}`
                  : X_BOOKMARKS_BASE_FOLDER,
                isNewFolder: false,
                confidence: 1.0,
                reasoning: xFolderSubPath
                  ? `X bookmark folder → ${xFolderSubPath}`
                  : 'X bookmark → 専用フォルダへ固定ルーティング',
              }
            : await classifyArticle(url, finalTitle, article.textContent);
        
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
      } catch (err: any) {
        console.log(`[${globalIndex}/${parsedEntries.length}] ${title.substring(0, 30)}... Failed: ${err.message}`);
        return { failure: true, url, title, reason: err.message };
      }
    });

    const chunkResults = await Promise.all(mappedPromises);
    for (const res of chunkResults) {
      if (!res) continue;
      if (res.failure && res.url !== undefined && res.title !== undefined && res.reason !== undefined) {
        failures.push({ url: res.url, title: res.title, reason: res.reason });
      } else if (res.success && res.data) {
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
    const failedPath = path.join(INTERNAL_LOGS_DIR, `failed_onetab_${dateStr}.txt`);
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
    if (res.status === 'success' && res.classification && res.articleContext) {
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

