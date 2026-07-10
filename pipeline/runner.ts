import fs from 'fs';
import os from 'os';
import path from 'path';
import { closeBrowser } from '../fetcher';
import { getKnownUrls, updateVaultTreeSnapshot } from '../storage';
import { tokenUsageMetrics } from '../classifier';
import { loadFolderRules, updateThresholds, getRoutedPath } from '../router';
import { getVaultRoot, getXBookmarksBaseFolder, isDryRun } from '../config';
import { ProcessingResult, PipelineConfig } from '../types';
import { ParsedCliArgs } from '../cli';
import { ParsedEntry, FailureRecord } from './types';
import { readOneTabFile } from './input_onetab';
import { prepareXBookmarks } from './input_x_bookmarks';
import { processEntries } from './processor';
import { generateReport } from './report';
import { interactiveReviewLoop, regenerateXBookmarkArtifacts } from './interactive';
import { closeDb } from '../x-bookmarks/db';
import { askQuestion } from './prompt';
import { listFolders } from '../x-bookmarks/api_client';
import { buildFolderTree, renderFolderTree } from '../x-bookmarks/folder_tree';
import { pickFolders } from '../x-bookmarks/interactive_picker';
import { loadForcedParents, loadApprovedMappings } from '../x-bookmarks/folder_mapper';
import { runSyncPhase } from '../x-bookmarks/session_sync';
import { createInteractiveOrphanResolver } from '../x-bookmarks/session_ai';
import { checkFolderCountInvariant, logInvariantCheck } from '../x-bookmarks/folder_invariant';

/**
 * X API ブックマーク専用のベースフォルダ。
 * config.ts::getXBookmarksBaseFolder() に集中管理 (デフォルト `X_Bookmarks`)。
 * 環境変数 X_BOOKMARKS_FOLDER で上書き可能。
 */
const X_BOOKMARKS_BASE_FOLDER = getXBookmarksBaseFolder();

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
export async function runPipeline(args: ParsedCliArgs, config?: PipelineConfig): Promise<void> {
  const { REPORTS_DIR, INTERNAL_LOGS_DIR } = setupOutputDirs();
  updateVaultTreeSnapshot();

  if (!args.filePath && !args.xBookmarks) {
    console.error('Usage: tsx index.ts <path-to-onetab.txt>');
    console.error('   or: tsx index.ts --x-bookmarks [--x-limit=N]');
    process.exit(1);
  }

  // `--x-resummarize-all` のクリア処理はここでは行わない。
  // ユーザーが confirmation で中止 / 処理 0 件の場合に「summary だけ消えて
  // 再生成されない」事故を防ぐため、x-bookmarks/summarizer.ts の中で
  // クリアと再生成をアトミックに実行する (interactive.ts から呼ばれる)。

  // === 0. Sync Phase (X bookmarks モードの先頭で必ず走る・--no-sync で抑止) ===
  if (args.xBookmarks && !args.noSync) {
    try {
      const result = await runSyncPhase({
        baseFolder: X_BOOKMARKS_BASE_FOLDER,
        resolver: createInteractiveOrphanResolver(askQuestion),
      });
      const summary = [
        `new=${result.newSessions}`,
        `updated=${result.updatedSessions}`,
        `vault_moves=${result.vaultMoves}`,
        `file_reassign=${result.fileReassignments}`,
        `orphan_x=${result.orphansOnX}`,
        `orphan_vault=${result.orphansOnVault}`,
      ].join(', ');
      console.log(`🔖 Sync Phase: ${summary}`);

      // 不変条件: X distinct folder 数 == <base>/ リーフ数 (集約解除時)
      try {
        const inv = checkFolderCountInvariant();
        logInvariantCheck(inv);
      } catch (invErr: any) {
        console.warn(`⚠️  Folder-count invariant チェック失敗 (続行): ${invErr.message}`);
      }
    } catch (e: any) {
      console.warn(`⚠️  Sync Phase 失敗 (続行): ${e.message}`);
    }
  } else if (args.xBookmarks && args.noSync) {
    console.log('🔖 --no-sync 指定: Sync Phase をスキップします (前回 sync 状態を再利用)');
  }

  // === 1. 入力構築 ===
  console.log('\n🔍 Indexing existing articles in the Vault...');
  const knownUrls = getKnownUrls();
  console.log(`Found ${knownUrls.size} unique URLs already saved.\n`);

  const { entries, failures } = await buildEntries(args, knownUrls);

  // --x-pick で「中止」が選ばれると entries も failures も 0 件で返る。
  // この場合は y/n 確認をスキップして即終了 (再度プロンプトを出すと UX が悪い)。
  // 他のフロー (--x-bookmarks 単独 / OneTab) で 0 件になった場合は、
  // 従来通り confirmBeforeRun で「処理予定: 0 件」を表示して y/n を出した方が
  // 「実行はしたが何もなかった」ことが明示できる。
  if (args.xPick && entries.length === 0 && failures.length === 0) {
    await closeBrowser();
    return;
  }

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

  let results: ProcessingResult[];
  try {
    const processed = await processEntries(entries, {
      xBookmarksBaseFolder: X_BOOKMARKS_BASE_FOLDER,
    });
    results = processed.results;
    failures.push(...processed.failures);
  } finally {
    await closeBrowser();
  }

  // === 4. 失敗ログ書出 ===
  const sourceTag = args.xBookmarks ? 'xbookmarks' : 'onetab';
  const dateStr = new Date().toISOString().split('T')[0].replace(/-/g, '');
  writeFailureLog(failures, INTERNAL_LOGS_DIR, sourceTag, dateStr);

  if (results.length === 0) {
    // `--x-resummarize-all` の本来の用途 (モデル / プロンプト変更後の既存要約の
    // 全件再生成) では「新規 0 件 + 全件再要約」が常態のため、ここで早期 return
    // すると flag が完全 no-op になる。X ブックマークモード + resummarizeAll の
    // 場合だけ regen パスを直接呼んで JSON / group ページまで一気通貫で更新する。
    if (args.xBookmarks && args.xResummarizeAll) {
      // dry-run 時は SQLite ai_summary クリア + JSON / group MD 書き換えという
      // 副作用を全て止める (CodeRabbit 指摘: confirmBeforeRun が「--dry-run は
      // Vault 書き込み無し」と明示しているため、ここも整合させる)。
      if (args.dryRun) {
        console.log('\n🧪 --dry-run: --x-resummarize-all の再生成はスキップしました。');
        closeDb();
        return;
      }
      console.log('\n🔄 新規ブックマーク 0 件 — --x-resummarize-all で既存要約を再生成します。');
      try {
        await regenerateXBookmarkArtifacts({
          xSummary: config?.xSummary,
          resummarizeAll: true,
        });
      } finally {
        closeDb();
      }
      return;
    }
    console.log('\nNo items were successfully processed. Exiting.');
    return;
  }

  // === 5. Router phase ===
  applyRouterPhase(results);

  // === 6. レポート生成 + 対話レビュー ===
  const reportLabel = args.xBookmarks ? 'X-Bookmarks' : 'OneTab';
  const reportPath = path.join(REPORTS_DIR, `${reportLabel}分類結果レポート-${dateStr}.md`);
  fs.writeFileSync(reportPath, generateReport(results, tokenUsageMetrics, reportLabel), 'utf8');
  await interactiveReviewLoop(results, reportPath, {
    resummarizeAll: args.xResummarizeAll,
    xSummary: config?.xSummary,
  });
}

/**
 * 2 種類の出力先を確保する:
 *   - REPORTS_DIR:     Obsidian で閲覧する分類結果レポート .md
 *   - INTERNAL_LOGS_DIR: 失敗 URL 等のパイプライン内部ログ (ユーザー向けではない)
 *
 * dry-run 時は Vault ツリーを一切変更しない契約 (confirmBeforeRun が「Vault 書き込み
 * なし」と明示) を守るため、両出力先を **Vault 外の一時ディレクトリ** に切り替える。
 * これにより分類結果レポート / 失敗ログのプレビューは残しつつ、Vault は無改変になる
 * (P0: dry-run zero-write。実行前後で Vault ツリーのハッシュが一致する回帰を保証)。
 */
export function setupOutputDirs(): { REPORTS_DIR: string; INTERNAL_LOGS_DIR: string } {
  if (isDryRun()) {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'obsidian-pipeline-dryrun-'));
    const REPORTS_DIR = path.join(base, 'reports');
    const INTERNAL_LOGS_DIR = path.join(base, 'internal-logs');
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
    fs.mkdirSync(INTERNAL_LOGS_DIR, { recursive: true });
    console.log(`🧪 dry-run: 出力は Vault 外の一時ディレクトリに書き出します (Vault は無改変): ${base}`);
    return { REPORTS_DIR, INTERNAL_LOGS_DIR };
  }
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
      // --x-pick: Stage 1 (フォルダ一覧表示) → 選択 → Stage 2 (本文取得)
      if (args.xPick) {
        const selection = await runFolderPickStage();
        if (selection.cancelled) {
          console.log('🚪 ユーザー中止 — ブックマーク取得をスキップします。');
          return { entries: [], failures: [] };
        }
        return await prepareXBookmarks({
          maxItems: args.xLimit,
          knownUrls,
          selectedFolders: selection.selectedFolders,
          includeUnfiled: selection.includeUnfiled,
          suppressGroupingProposal: true,
        });
      }
      // 従来挙動 (--x-bookmarks 単独): 全フォルダ自動取得
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
 * Stage 1: フォルダ一覧を取得 → 2 階層 Tree 表示 → 対話選択。
 *
 * API コールは `/users/me` + `/bookmarks/folders` のみ (本文 fetch なし)。
 * 選択結果は selectedFolders ({id, name}) として Stage 2 に渡される。
 */
async function runFolderPickStage(): Promise<{
  selectedFolders: { id: string; name: string }[];
  includeUnfiled: boolean;
  cancelled: boolean;
}> {
  console.log('\n🔖 Stage 1: フォルダ一覧を取得中...');
  const listing = await listFolders();
  console.log(`   authenticated as @${listing.username}`);

  const forcedParents = loadForcedParents();
  const approvedMap = loadApprovedMappings();
  const tree = buildFolderTree(listing.folders, forcedParents, approvedMap);
  const rendered = renderFolderTree(tree);
  const result = await pickFolders(tree, rendered, askQuestion);

  if (result.cancelled) {
    return { selectedFolders: [], includeUnfiled: false, cancelled: true };
  }

  // result.folderIds → listing.folders から {id, name} を再構築
  const idToName = new Map(listing.folders.map(f => [f.id, f.name]));
  const selectedFolders = result.folderIds.map(id => ({
    id,
    name: idToName.get(id) ?? id,
  }));
  console.log(
    `🔖 Stage 2: ${selectedFolders.length} フォルダ${result.includeUnfiled ? ' + Unfiled' : ''} を取得します`
  );
  return {
    selectedFolders,
    includeUnfiled: result.includeUnfiled,
    cancelled: false,
  };
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
  if (args.xBookmarks) {
    console.log(args.xPick ? '🔖 X ブックマークモード (--x-pick: 選択済みフォルダのみ)' : '🔖 X ブックマークモード');
  }
  const answer = (await askQuestion('\nパイプラインを実行しますか？ [y/n]: ')).toLowerCase().trim();
  if (answer !== 'y') {
    console.log('キャンセルしました。');
    return false;
  }
  return true;
}

export function writeFailureLog(
  failures: FailureRecord[],
  internalLogsDir: string,
  sourceTag: string,
  dateStr: string
): void {
  if (failures.length === 0) return;
  const failedContent = failures.map((f) => `${f.url} | ${f.title}`).join('\n');
  const failedPath = path.join(internalLogsDir, `failed_${sourceTag}_${dateStr}.txt`);
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
