/**
 * Obsidian AI Pipeline のエントリポイント。
 *
 * このファイルは **モード dispatch** と **ライフサイクル管理** のみに責任を持ち、
 * 実装ロジックは一切置かない。各モードの実装は対応モジュールに委譲する:
 *
 *   --x-auth              x-bookmarks/auth_server.ts        X OAuth 認可サーバ
 *   --hands-on=<folder>   x-bookmarks/hands_on_generator.ts X ブックマーク DB → ハンズオン生成
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
  getVaultRoot,
  getXBookmarksBaseFolder,
  runXSummaryWizard,
  saveConfig,
  getXSummaryConfig,
  getThreatRelevanceConfig,
  runThreatRelevanceWizard,
} from './config';
import { syncRulesFromSnippets } from './sync-rules';
import { runAuthServer } from './x-bookmarks/auth_server';
import { generateHandsOn } from './x-bookmarks/hands_on_generator';
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
      const { runMigrateLegacy } = await import('./x-bookmarks/migrate_legacy');
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

  // --ingest-threat-report: 週次 LLM 脅威レポート (.md) を取り込み DB + JSON + index 更新
  // Gmail からの取得は Claude Code (MCP) 側の責務。本 CLI はファイル入力に専念。
  if (args.ingestThreatReport) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    try {
      const { ingestThreatReport, ContractError } = await import('./threat-reports/ingest');
      try {
        const result = await ingestThreatReport({ filePath: args.ingestThreatReport });
        console.log('\n🛡️  脅威レポート取込完了:');
        console.log(`   report_id:        ${result.reportId}`);
        console.log(`   week_of:          ${result.weekOf}`);
        console.log(`   vulnerabilities:  ${result.vulnerabilities}`);
        console.log(`   raw archive:      ${result.archivedPath ?? '(skip)'}`);
        console.log(`   JSON:             ${result.jsonPath}`);
        console.log(`   index:            ${result.indexPath}`);
      } catch (inner: unknown) {
        // 契約違反 (frontmatter 不正) は I/O エラーと区別して明示する
        if (inner instanceof ContractError) {
          console.error(`❌ 脅威レポート契約違反: ${inner.message}`);
          console.error('   想定外スキーマのメールを誤取込しないよう ingest を中止しました。');
          process.exit(2);
        }
        throw inner;
      }
    } catch (e: any) {
      console.error(`❌ 脅威レポート取込失敗: ${e.message}`);
      process.exit(1);
    }
    closePrompt();
    process.exit(0);
  }

  // --rebuild-threat-reports-db: raw/<week>.md を真実として threat_reports DB を
  // 作り直す (破損退避 / 手動削除後の明示的な復旧)。human 入力は raw に無いので復元不可。
  if (args.rebuildThreatReportsDb) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    try {
      const { rebuildThreatReportsDbFromVault } = await import('./threat-reports/ingest');
      const result = await rebuildThreatReportsDbFromVault();
      console.log('\n🛡️  threat_reports DB 再構築完了 (raw/*.md → DB):');
      console.log(`   raw dir:          ${result.rawDir}`);
      console.log(`   .md 発見:         ${result.filesFound} 件`);
      console.log(`   reports 復元:     ${result.reportsRebuilt} 件`);
      console.log(`   vulnerabilities:  ${result.vulnerabilities} 件 / impl_checks: ${result.implementationChecks} 件`);
      console.log(`   JSON:             ${result.jsonPath}`);
      console.log(`   index:            ${result.indexPath}`);
      if (result.skipped.length > 0) {
        console.warn(`   ⚠ skip (取込失敗): ${result.skipped.length} 件`);
        for (const s of result.skipped) console.warn(`      - ${s.file}: ${s.reason}`);
      }
      console.log('   ⚠ ai_relevance_note / relevance_reviewed_at は raw に無いため復元されません。');
      console.log('     退避された <db>.corrupted_* が開ける場合はそちらから手動サルベージしてください。');
    } catch (e: any) {
      console.error(`❌ threat_reports DB 再構築失敗: ${e.message}`);
      process.exit(1);
    }
    closePrompt();
    process.exit(0);
  }

  // --list-target-repos: ローカル clone 済みリポを列挙する (/sec-review 対象リポ選択)。
  // 読み取り専用 (fs 列挙 + git remote 読取のみ)。
  if (args.listTargetRepos) {
    const { discoverLocalRepos } = await import('./threat-reports/repo_target');
    const repos = discoverLocalRepos();
    console.log('\n📁 ローカル clone 済みリポジトリ (--target-repo に指定可能):');
    if (repos.length === 0) {
      console.log('   (見つかりません — cwd とその兄弟ディレクトリに git リポがありません)');
    } else {
      for (const r of repos) console.log(`   - ${r.key}\t(root: ${r.root})`);
    }
    console.log('\n   ※ 上記以外の owner/repo も指定できますが、該当性判定 (--analyze-threat-relevance)');
    console.log('     はリポを fs 走査するため、ローカルに clone 済みのものに限られます。');
    closePrompt();
    process.exit(0);
  }

  // --analyze-threat-relevance: 取込済み脅威の「対象リポ該当性」を判定し
  // per-repo ノートを自動記入する (Level 2 検知)。検知のみ — コード変更はしない。
  if (args.analyzeThreatRelevance) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    // 判定モデルの dedicated provider/model (初回 or --threat-relevance-reconfig)
    if (getThreatRelevanceConfig(config) === null || args.threatRelevanceReconfig) {
      const threatRelevance = await runThreatRelevanceWizard(askQuestion);
      config = { ...config, threatRelevance };
      saveConfig(config);
    }
    try {
      const { getDb } = await import('./threat-reports/db');
      const { buildRepoProfile, runThreatRelevanceAnalysis } = await import('./threat-reports/relevance');
      const { resolveRepoTarget } = await import('./threat-reports/repo_target');
      const { exportThreatReportsJson } = await import('./threat-reports/json_export');
      const { regenerateIndexPage } = await import('./threat-reports/index_writer');
      const db = getDb();
      const target = resolveRepoTarget(args.targetRepo);
      // located=false = 対象リポのローカルチェックアウトが無い → buildRepoProfile が
      // 別リポ (cwd) を誤走査してしまうため、ここで止める (検知の正確性を守る最後の砦)。
      if (!target.located) {
        console.error(`❌ 対象リポのローカルチェックアウトが見つかりません: ${target.key}`);
        console.error('   該当性判定はリポを fs 走査するため、ローカルに clone されている必要があります。');
        console.error('   `--list-target-repos` で候補を確認するか、`--target-repo=<ローカルパス>` を指定してください。');
        process.exit(1);
      }
      const rel = config.threatRelevance ?? { provider: config.provider, model: config.smartModel };
      const stats = await runThreatRelevanceAnalysis(db, {
        provider: rel.provider,
        model: rel.model,
        redoAll: args.threatRelevanceAll,
        repoKey: target.key,
        repoRoot: target.root,
        repoProfile: buildRepoProfile(target.root, target.key),
      });
      // checked_untrusted: 「対象リポで実際に下書きノートが生成された」レポートにのみ印を
      // 付ける (人手レビュー済みフラグとは別軸)。**finding を持つだけでは付けない** — 全 finding が
      // AI 失敗で NULL のままなら下書きは存在しないので、checks を「下書きあり」シグナルとして
      // 使う /sec-review を誤導しないため、relevance_notes に対象リポのノートが 1 件以上ある
      // レポートだけを checked にする (Codex P2)。
      const checkedAt = new Date().toISOString();
      const draftedReportIds = new Set<string>(
        db.listRelevanceNotes()
          .filter((n) => n.repo_key === target.key)
          .map((n) => n.report_id),
      );
      for (const reportId of draftedReportIds) db.markReportChecked(reportId, target.key, checkedAt);
      const vaultRoot = getVaultRoot();
      const jsonPath = exportThreatReportsJson({ db, vaultRoot });
      const indexPath = regenerateIndexPage({ vaultRoot });
      console.log('\n🛡️  脅威レポート 該当性判定 (Level 2 検知) 完了:');
      console.log(`   対象リポ:      ${target.key} (走査ルート: ${target.root})`);
      console.log(`   モデル:        ${rel.provider} / ${rel.model}`);
      console.log(`   vuln 判定:     ${stats.vulnAnalyzed} 件 / check 判定: ${stats.implAnalyzed} 件`);
      console.log(`   ⚠ 該当: ${stats.applies} / ? 要確認: ${stats.unclear} / skip(既存): ${stats.skipped} / 失敗: ${stats.failed}`);
      console.log(`   下書き生成済(checked_untrusted): ${draftedReportIds.size} レポート (人手レビューは /sec-review)`);
      console.log(`   JSON:          ${jsonPath}`);
      console.log(`   index:         ${indexPath}`);
      console.log('   ※ 検知のみ。修正は人手レビュー後に通常 PR フローで行ってください。');
    } catch (e: any) {
      console.error(`❌ 該当性判定失敗: ${e.message}`);
      process.exit(1);
    }
    closePrompt();
    process.exit(0);
  }

  // --mark-threat-reviewed=<report_id>: 該当性レビュー (/sec-review) 完了印を立て、
  // JSON / index を再生成する。これにより次回 /sec-review はこのレポートをスキップ。
  if (args.markThreatReviewed) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    try {
      const { getDb } = await import('./threat-reports/db');
      const { resolveRepoTarget } = await import('./threat-reports/repo_target');
      const { exportThreatReportsJson } = await import('./threat-reports/json_export');
      const { regenerateIndexPage } = await import('./threat-reports/index_writer');
      const db = getDb();
      const target = resolveRepoTarget(args.targetRepo);
      // located=false = 対象リポを確定できていない (typo した --target-repo=<path> は
      // key が cwd 由来に化けるため、無確認で mark すると **現在のリポを誤ってレビュー済み**
      // にしてしまう / CodeRabbit Major)。analyze と同様に located を要求する。
      if (!target.located) {
        console.error(`❌ 対象リポを確定できません: ${target.key}`);
        console.error('   --target-repo の owner/repo がローカル clone と一致しない、またはパスが存在しません。');
        console.error('   `--list-target-repos` で候補を確認するか、正しい owner/repo / ローカルパスを指定してください。');
        process.exit(1);
      }
      const reportId = args.markThreatReviewed;
      const changed = db.markReportReviewed(reportId, target.key);
      if (changed === 0) {
        console.error(`❌ 該当 report_id が見つかりません: ${reportId}`);
        console.error('   --analyze-threat-relevance の出力 / .threat_reports.json の reports[] で report_id を確認してください。');
        process.exit(1);
      }
      const vaultRoot = getVaultRoot();
      const jsonPath = exportThreatReportsJson({ db, vaultRoot });
      const indexPath = regenerateIndexPage({ vaultRoot });
      console.log('\n🛡️  該当性レビュー済みフラグを立てました:');
      console.log(`   対象リポ:  ${target.key}`);
      console.log(`   report_id: ${reportId}`);
      console.log(`   JSON:      ${jsonPath}`);
      console.log(`   index:     ${indexPath}`);
    } catch (e: any) {
      console.error(`❌ レビュー済みフラグ更新失敗: ${e.message}`);
      process.exit(1);
    }
    closePrompt();
    process.exit(0);
  }

  // --agent="<task>": Vault サンドボックス内の Tool Use エージェントを 1 ショット起動。
  // read/create のみ、各操作に Human-in-the-Loop [y/N] 承認を挟む (tool-use/agent.ts)。
  if (args.agent) {
    if (!config) config = await runConfigWizard(askQuestion);
    applyConfigToEnv(config);
    try {
      const { runAgentCli } = await import('./tool-use/cli_entry');
      await runAgentCli({ task: args.agent, config, ask: askQuestion });
    } catch (e: any) {
      console.error(`❌ Tool Use エージェント失敗: ${e.message}`);
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
      const { runDeriveRulesCli } = await import('./x-bookmarks/rule_deriver');
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
      const { runSyncPhase } = await import('./x-bookmarks/session_sync');
      const { createInteractiveOrphanResolver } = await import('./x-bookmarks/session_ai');
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
        const { checkFolderCountInvariant, logInvariantCheck } = await import('./x-bookmarks/folder_invariant');
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

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
