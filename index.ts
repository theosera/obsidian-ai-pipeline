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
import { loadConfig, runConfigWizard, applyConfigToEnv, setDryRun } from './config';
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
  // 通常パイプライン (OneTab / X ブックマーク)
  // ------------------------------------------------------------------
  console.log('\n======================================================');
  console.log(`🤖 AI Provider: ${config.provider}`);
  console.log(`🔹 Step 1 Model (Fast): ${config.fastModel}`);
  console.log(`🔸 Step 2 Model (Smart): ${config.smartModel}`);
  console.log('💡 Run with `--config` anytime to change these settings.');
  console.log('======================================================\n');

  await runPipeline(args);

  closePrompt();
  process.exit(0);
}

main();
