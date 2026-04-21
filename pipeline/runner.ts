import fs from 'fs';
import path from 'path';
import { closeBrowser } from '../fetcher';
import { getKnownUrls, updateVaultTreeSnapshot } from '../storage';
import { tokenUsageMetrics } from '../classifier';
import { loadFolderRules, updateThresholds, getRoutedPath } from '../router';
import { getVaultRoot } from '../config';
import { ProcessingResult } from '../types';
import { ParsedCliArgs } from '../cli';
import { ParsedEntry, FailureRecord } from './types';
import { readOneTabFile } from './input_onetab';
import { prepareXBookmarks } from './input_x_bookmarks';
import { processEntries } from './processor';
import { generateReport } from './report';
import { interactiveReviewLoop } from './interactive';
import { askQuestion } from './prompt';

/**
 * X API ブックマーク専用のベースフォルダ。
 * 通常記事の Classifier によるフォルダ分類とは別系統で、すべての X ブックマークを
 * ここに集約する（混入防止・監査容易化）。環境変数 X_BOOKMARKS_FOLDER で上書き可能。
 * Router の閾値 (QUARTERLY=10 / MONTHLY=20) を超えると、自動で日付サブフォルダへ昇格する。
 */
const X_BOOKMARKS_BASE_FOLDER = process.env.X_BOOKMARKS_FOLDER || 'Clippings/X-Bookmarks';

/**
 * 通常パイプライン (OneTab / X ブックマーク) のフロー制御。
 *
 * 6 ステージの線形フロー:
 *   1. 出力ディレクトリ初期化 + Vault ツリースナップショット
 *   2. 入力構築 (OneTab .txt パース or X API フェッチ) → ParsedEntry[]
 *   3. 実行前ユーザー確認 [y/n]
 *   4. 並行 fetch/extract/classify (processor)
 *   5. Router phase (閾値判定 → /YYYY-Qn|YYYY-MM 付与)
 *   6. レポート書出 + 対話レビュー (interactive)
 *
 * 上位 (index.ts) は CLI 引数に応じて当関数を呼ぶだけで、パイプライン全体が完結する。
 */
export async function runPipeline(args: ParsedCliArgs): Promise<void> {
  const { REPORTS_DIR, INTERNAL_LOGS_DIR } = setupOutputDirs();
  updateVaultTreeSnapshot();

  if (!args.filePath && !args.xBookmarks) {
    console.error('Usage: tsx index.ts <path-to-onetab.txt>');
    console.error('   or: tsx index.ts --x-bookmarks [--x-limit=N]');
    process.exit(1);
  }

  // === 1. 入力構築 ===
  console.log('\n🔍 Indexing existing articles in the Vault...');
  const knownUrls = getKnownUrls();
  console.log(`Found ${knownUrls.size} unique URLs already saved.\n`);

  const { entries, failures } = await buildEntries(args, knownUrls);

  // === 2. 実行前ユーザー確認 ===
  const approved = await confirmBeforeRun(entries, failures, REPORTS_DIR, args);
  if (!approved) {
    await closeBrowser();
    return;
  }

  // === 3. 並行 fetch/extract/classify ===
  console.log(
    `\nStarting Phase 3 Pipeline... found ${entries.length} fetchable URLs (${failures.length} skipped).`
  );
  console.log('Performing content fetching and classification (This may take several minutes...)');

  const { results, failures: processingFailures } = await processEntries(entries, {
    xBookmarksBaseFolder: X_BOOKMARKS_BASE_FOLDER,
  });
  failures.push(...processingFailures);

  await closeBrowser();

  // === 4. 失敗ログ書出 ===
  const dateStr = new Date().toISOString().split('T')[0].replace(/-/g, '');
  writeFailureLog(failures, INTERNAL_LOGS_DIR, dateStr);

  if (results.length === 0) {
    console.log('\nNo items were successfully processed. Exiting.');
    return;
  }

  // === 5. Router phase ===
  applyRouterPhase(results);

  // === 6. レポート生成 + 対話レビュー ===
  const reportPath = path.join(REPORTS_DIR, `OneTab分類結果レポート-${dateStr}.md`);
  fs.writeFileSync(reportPath, generateReport(results, tokenUsageMetrics), 'utf8');
  await interactiveReviewLoop(results, reportPath);
}

/**
 * Vault 配下に 2 種類の出力先を確保する:
 *   - REPORTS_DIR:     Obsidian で閲覧する分類結果レポート .md
 *   - INTERNAL_LOGS_DIR: 失敗 URL 等のパイプライン内部ログ (ユーザー向けではない)
 */
function setupOutputDirs(): { REPORTS_DIR: string; INTERNAL_LOGS_DIR: string } {
  const REPORTS_DIR = path.join(getVaultRoot(), '__skills', 'context', '分類結果レポート');
  const INTERNAL_LOGS_DIR = path.join(getVaultRoot(), '__skills', 'pipeline', 'reports');
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
  if (!fs.existsSync(INTERNAL_LOGS_DIR)) fs.mkdirSync(INTERNAL_LOGS_DIR, { recursive: true });
  return { REPORTS_DIR, INTERNAL_LOGS_DIR };
}

async function buildEntries(
  args: ParsedCliArgs,
  knownUrls: Set<string>
): Promise<{ entries: ParsedEntry[]; failures: FailureRecord[] }> {
  if (args.xBookmarks) {
    try {
      return await prepareXBookmarks({ maxItems: args.xLimit, knownUrls });
    } catch (e: any) {
      console.error(`❌ X ブックマーク取得失敗: ${e.message}`);
      if (e.message?.includes('x_tokens.json')) {
        console.error('   → 初回認証を実行してください: pnpm start -- --x-auth');
      }
      process.exit(1);
    }
  }
  return readOneTabFile(args.filePath!, knownUrls);
}

/**
 * 長時間実行/API コスト発生前に最終確認を取る。
 * 件数 0 でも「何もせず終了」の明示ができるよう、件数表示は常に出す。
 */
async function confirmBeforeRun(
  entries: ParsedEntry[],
  failures: FailureRecord[],
  reportsDir: string,
  args: ParsedCliArgs
): Promise<boolean> {
  console.log(`\n📋 処理予定: ${entries.length} 件 / スキップ: ${failures.length} 件`);
  console.log(`📁 分類結果レポート出力先: ${reportsDir}`);
  if (args.dryRun) console.log('🧪 dry-run モード: Vault へのファイル書き込みはスキップされます。');
  if (args.xBookmarks) console.log('🔖 X ブックマークモード');
  const answer = (await askQuestion('\nパイプラインを実行しますか？ [y/n]: ')).toLowerCase().trim();
  if (answer !== 'y') {
    console.log('キャンセルしました。');
    return false;
  }
  return true;
}

function writeFailureLog(
  failures: FailureRecord[],
  internalLogsDir: string,
  dateStr: string
): void {
  if (failures.length === 0) return;
  const failedContent = failures.map((f) => `${f.url} | ${f.title}`).join('\n');
  const failedPath = path.join(internalLogsDir, `failed_onetab_${dateStr}.txt`);
  fs.writeFileSync(failedPath, failedContent, 'utf8');
  console.log(`\n⚠️ Saved ${failures.length} failed/skipped items to ${failedPath}`);
}

/**
 * 各 result の proposedPath をベースカテゴリとみなし、router の閾値判定に基づいて
 * /YYYY-Qn または /YYYY-MM の日付サブフォルダを付与する。Router rule が 'none' の
 * カテゴリはそのまま。閾値昇格した場合は folder_rules.json も router 内で更新される。
 */
function applyRouterPhase(results: ProcessingResult[]): void {
  const currentRules = loadFolderRules();
  const updatedRules = updateThresholds(results, currentRules);

  for (const res of results) {
    if (res.status === 'success' && res.classification && res.articleContext) {
      const baseCat = res.classification.proposedPath;
      const pubDate = res.articleContext.date;
      const finalRoutedPath = getRoutedPath(baseCat, pubDate, updatedRules);
      // proposedPath を上書きすることで、レポート生成・対話 UI とも
      // 新しい (日付付き) パスで一貫して動作する
      res.classification.proposedPath = finalRoutedPath;
    }
  }
}
