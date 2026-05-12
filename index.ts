/**
 * Obsidian AI Pipeline のエントリポイント。
 *
 * このファイルは **モード dispatch** と **ライフサイクル管理** のみに責任を持ち、
 * 実装ロジックは一切置かない。各モードの実装は対応モジュールに委譲する:
 *
 *   --x-auth              x_auth_server.ts        X OAuth 認可サーバ
 *   --hands-on=<folder>   hands_on_generator.ts   X ブックマーク DB → ハンズオン生成
 *   --sync-rules          sync-rules.ts           snippets → folder_rules 同期
 *   --config              config.ts               対話ウィザード
 *   <file> | --x-bookmarks pipeline/runner.ts      通常パイプライン (OneTab / X API)
 *
 * 新モード追加の定型:
 *   1. 対応する実装モジュールを作成 (`<name>.ts` または `pipeline/<name>.ts`)
 *   2. `cli.ts::ParsedCliArgs` にフラグを追加
 *   3. ここの main() に dispatch 分岐を追加
 */
import { parseArgs, printUsage } from './cli';
import {
  loadConfig,
  runConfigWizard,
  applyConfigToEnv,
  setDryRun,
  getXBookmarksBaseFolder,
  runXSummaryWizard,
  saveConfig,
  getXSummaryConfig,
} from './config';
import { syncRulesFromSnippets } from './sync-rules';
import { runAuthServer } from './x_auth_server';
import { generateHandsOn } from './hands_on_generator';
import { askQuestion, closePrompt } from './pipeline/prompt';
import { runPipeline } from './pipeline/runner';

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.dryRun) setDryRun(true);

  let config = loadConfig();

  // ------------------------------------------------------------------
  // 単機能モード: config 完了後すぐに実装モジュールへ丸投げして終了
  // ------------------------------------------------------------------
  if (args.xAuth) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    await runAuthServer();
    // runAuthServer は内部で process.exit(0) するのでここには到達しない想定
    return;
  }

  if (args.handsOn) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    try {
      await generateHandsOn({
        folder: args.handsOn,
        since: args.since,
        dryRun: args.dryRun,
      });
    } catch (e: any) {
      console.error(`❌ ハンズオン生成失敗: ${e.message}`);
      process.exit(1);
    }
    closePrompt();
    process.exit(0);
  }

  // --x-migrate-legacy: 旧 Clippings/X-Bookmarks/ を _Archived/ に退避するワンショット移行
  if (args.xMigrateLegacy) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    try {
      const { runMigrateLegacy } = await import('./x_migrate_legacy');
      const result = runMigrateLegacy();
      if (result.skipped) {
        console.log(`ℹ️  移行スキップ: ${result.reason}`);
      } else {
        console.log('\n📦 旧 X ブックマークパスを退避しました:');
        console.log(`   ${result.legacyPath}`);
        console.log(`   → ${result.archivedPath}`);
        console.log(`   .md ファイル: ${result.filesMoved} 件`);
        console.log(`   folder_sessions 書き換え: ${result.sessionsUpdated} 件`);
        console.log(`   bookmarks 書き換え:       ${result.bookmarksUpdated} 件`);
      }
    } catch (e: any) {
      console.error(`❌ 移行失敗: ${e.message}`);
      process.exit(1);
    }
    closePrompt();
    process.exit(0);
  }

  // --x-derive-rules: vault 構造を解析して x_forced_parents.json を自動推定 (.bak 残し)
  if (args.xDeriveRules) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    try {
      const { runDeriveRulesCli } = await import('./x_rule_deriver');
      await runDeriveRulesCli({ ask: askQuestion });
    } catch (e: any) {
      console.error(`❌ ルール推定失敗: ${e.message}`);
      process.exit(1);
    }
    closePrompt();
    process.exit(0);
  }

  // --x-sync-folders: Sync Phase 単独実行 (Vault 再編後 / orphan AI 判定だけ走らせたいとき)
  if (args.xSyncFolders) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    try {
      const { runSyncPhase } = await import('./x_session_sync');
      const { createInteractiveOrphanResolver } = await import('./x_session_ai');
      const baseFolder = getXBookmarksBaseFolder();
      const result = await runSyncPhase({
        baseFolder,
        resolver: createInteractiveOrphanResolver(askQuestion),
      });
      console.log('\n🔖 Sync 完了:');
      console.log(`  新規 sessions: ${result.newSessions}`);
      console.log(`  更新 sessions: ${result.updatedSessions}`);
      console.log(`  Vault 移動検知: ${result.vaultMoves}`);
      console.log(`  ファイル再 bind: ${result.fileReassignments}`);
      console.log(`  orphan_on_x:    ${result.orphansOnX}`);
      console.log(`  orphan_on_vault: ${result.orphansOnVault}`);
      try {
        const { checkFolderCountInvariant, logInvariantCheck } = await import('./x_folder_invariant');
        logInvariantCheck(checkFolderCountInvariant());
      } catch (invErr: any) {
        console.warn(`⚠️  Folder-count invariant チェック失敗: ${invErr.message}`);
      }
    } catch (e: any) {
      console.error(`❌ Sync 失敗: ${e.message}`);
      process.exit(1);
    }
    closePrompt();
    process.exit(0);
  }

  // ------------------------------------------------------------------
  // Config wizard の必要性判定
  // ------------------------------------------------------------------
  if (!config || args.config) {
    if (!args.filePath && !args.config && !args.xBookmarks) {
      printUsage();
      process.exit(1);
    }
    config = await runConfigWizard(askQuestion);
    if (args.config && !args.filePath && !args.xBookmarks) {
      console.log('Configuration finished. Exiting.');
      process.exit(0);
    }
  }
  applyConfigToEnv(config);

  // sync-rules は config 適用後の純粋モード
  if (args.syncRules) {
    syncRulesFromSnippets();
    process.exit(0);
  }

  // ------------------------------------------------------------------
  // X 要約 dedicated provider / model の初回セットアップ
  //
  // 分類フェーズの AI_PROVIDER とは独立した設定 (X 要約はあくまで 1 行 200 字の
  // 軽量タスクで cloud Haiku 4.5 が推奨)。
  //   - `--x-bookmarks` 系で xSummary 未保存 → 初回ウィザード
  //   - `--x-summary-reconfig` 明示時 → 強制再選択
  // ------------------------------------------------------------------
  if (args.xBookmarks && (getXSummaryConfig(config) === null || args.xSummaryReconfig)) {
    const xSummary = await runXSummaryWizard(askQuestion);
    config = { ...config, xSummary };
    saveConfig(config);
  }

  // ------------------------------------------------------------------
  // 通常パイプライン (OneTab / X ブックマーク)
  // ------------------------------------------------------------------
  console.log('\n======================================================');
  console.log(`🤖 AI Provider: ${config.provider}`);
  console.log(`🔹 Step 1 Model (Fast): ${config.fastModel}`);
  console.log(`🔸 Step 2 Model (Smart): ${config.smartModel}`);
  if (config.xSummary) {
    console.log(`🧵 X 要約: ${config.xSummary.provider} / ${config.xSummary.model}  (--x-summary-reconfig で変更)`);
  }
  console.log('💡 Run with `--config` anytime to change these settings.');
  console.log('======================================================\n');

  await runPipeline(args, config);

  closePrompt();
  process.exit(0);
}

main();
