/**
 * CLI 引数パース専用モジュール。
 *
 * index.ts の主責務は「引数に応じたモード分岐」であり、
 * フラグ検出ロジック自体を切り出すことで index.ts を dispatch 一枚に保つ。
 *
 * 対応モード:
 *   --config              設定ウィザード (他の flag と組合せ可能)
 *   --dry-run             ファイル移動/保存を抑止
 *   --sync-rules          snippets→folder_rules 同期のみ実行
 *   --x-auth              X OAuth 認可サーバを起動して終了
 *   --x-bookmarks         X API v2 ブックマーク取込モード (全フォルダ自動)
 *   --x-pick              Stage 1 (フォルダ一覧) → 対話選択 → Stage 2 (本文取得)
 *                         --x-bookmarks を含意するので併記不要
 *   --x-sync-folders      Sync Phase だけ実行して終了 (Vault 再編後の手動同期用)
 *   --no-sync             X bookmarks コマンドの先頭で走る Sync Phase を抑止
 *                         (cron 等で速度優先したい場合のエスケープ)
 *   --x-limit=N           X 取得件数上限
 *   --hands-on=<folder>   X ブックマーク DB からハンズオン生成
 *   --since=YYYY-MM-DD    --hands-on の対象期間起点
 *   <path>                上記に該当しない位置引数 = OneTab .txt パス
 */

export interface ParsedCliArgs {
  config: boolean;
  dryRun: boolean;
  syncRules: boolean;
  xAuth: boolean;
  xBookmarks: boolean;
  /** Stage 1 (フォルダ一覧) → 対話選択 → Stage 2 (本文取得) */
  xPick: boolean;
  /** Sync Phase 単独実行モード (Vault 再編後 / orphan AI 判定のためだけに走らせたいとき) */
  xSyncFolders: boolean;
  /** Sync Phase を抑止 (cron 等で速度優先) */
  noSync: boolean;
  /**
   * 旧パス `Clippings/X-Bookmarks/` を `_Archived/` に退避するワンショット移行。
   * 2026-05 のテーブルビュー化リファクタに伴うパス移行用。
   */
  xMigrateLegacy: boolean;
  /**
   * 現行 vault フォルダ構造から `x_forced_parents.json` を自動推定し
   * (.bak を残して) 上書き提案する。`pnpm start -- --x-derive-rules`
   */
  xDeriveRules: boolean;
  /**
   * `--x-bookmarks` 時に AI 要約を全件再生成する (`bookmarks.ai_summary` を
   * 一旦全 NULL にしてから summarize を走らせる)。モデル変更やプロンプト改善
   * を反映したいときの opt-in 再要約。
   */
  xResummarizeAll: boolean;
  /**
   * X 要約の provider / model を再選択するウィザードを起動 (`--x-bookmarks` と
   * 併用)。初回 `--x-bookmarks` 実行時は xSummary 未保存なら自動でウィザードが
   * 走るので、このフラグは「保存済みの設定を変えたい」とき専用。
   */
  xSummaryReconfig: boolean;
  /**
   * 脅威レポート (.md) を取り込む。
   * `--ingest-threat-report=<path>` 形式。Claude Code が Gmail MCP で取得した
   * frontmatter 付き md を Vault 配下に書き出してからこの CLI を呼ぶ責務分担。
   */
  ingestThreatReport?: string;
  /**
   * 取込済み脅威レポートの各脅威 (vulnerabilities / implementation_checks) について
   * 「自リポ該当性」を判定し `ai_relevance_note` を自動記入する (Level 2 検知)。
   * `--analyze-threat-relevance`。検知のみ — コード変更・提案・実行はしない。
   */
  analyzeThreatRelevance: boolean;
  /**
   * 該当性判定を AI 記入済み行も含めて再生成する。人手 note (センチネル無しの
   * 非 NULL) は redo でも**絶対に上書きしない**。`--threat-relevance-all`。
   */
  threatRelevanceAll: boolean;
  /** 該当性判定の provider / model を再選択するウィザードを起動。`--threat-relevance-reconfig`。 */
  threatRelevanceReconfig: boolean;
  /**
   * `raw/<week>.md` を真実として threat_reports DB を作り直す。`--rebuild-threat-reports-db`。
   * 破損退避 / 手動削除後の明示的な復旧コマンド。human 入力 (ai_relevance_note /
   * relevance_reviewed_at) は raw に無いため復元されない (実行時に警告)。
   */
  rebuildThreatReportsDb: boolean;
  /**
   * 指定 report_id を「該当性レビュー済み」に印付けする (`/sec-review` が逐次
   * レビュー完了後に呼ぶ)。`--mark-threat-reviewed=<report_id>` 形式。DB の
   * relevance_reviewed_at を立て、JSON / index を再生成する。
   */
  markThreatReviewed?: string;
  /**
   * `/sec-review` の該当性レビュー対象リポジトリ。`--target-repo=<owner/repo | local-path>`。
   * `--analyze-threat-relevance` / `--mark-threat-reviewed` の per-repo スコープを決める。
   * 省略時は現在のリポ (cwd) を git remote から導出 (resolveRepoTarget)。
   */
  targetRepo?: string;
  /**
   * ローカルに clone 済みのリポジトリを列挙する (`/sec-review` 対象リポ選択メニュー用)。
   * `--list-target-repos`。読み取り専用 (fs 列挙 + git remote 読取のみ)。
   */
  listTargetRepos: boolean;
  /**
   * Tool Use (Function Calling) エージェントを 1 ショット起動する。
   * `--agent=<task>` 形式。Vault サンドボックス内の read/create のみを、毎回
   * Human-in-the-Loop 承認を挟んで実行する (`tool-use/agent.ts`)。
   */
  agent?: string;
  xLimit?: number;
  handsOn?: string;
  since?: string;
  filePath?: string;
}

export function parseArgs(argv: readonly string[]): ParsedCliArgs {
  const handsOnArg = argv.find((a) => a.startsWith('--hands-on='));
  const sinceArg = argv.find((a) => a.startsWith('--since='));
  const xLimitArg = argv.find((a) => a.startsWith('--x-limit='));
  const ingestThreatReportArg = argv.find((a) => a.startsWith('--ingest-threat-report='));
  const markThreatReviewedArg = argv.find((a) => a.startsWith('--mark-threat-reviewed='));
  const targetRepoArg = argv.find((a) => a.startsWith('--target-repo='));
  const agentArg = argv.find((a) => a.startsWith('--agent='));

  // --key=value 形式の値抽出。= 以降を再結合するのは、--hands-on=Foo=Bar のように
  // 値側に = が含まれる可能性を考慮している (Windows パス等)。
  const extractValue = (arg: string | undefined): string | undefined =>
    arg ? arg.split('=').slice(1).join('=') : undefined;

  const xLimitValue = extractValue(xLimitArg);
  let xLimit: number | undefined;
  if (xLimitValue !== undefined) {
    if (!/^[1-9]\d*$/.test(xLimitValue)) {
      console.error(`Invalid --x-limit value: "${xLimitValue}" (expected positive integer)`);
      printUsage();
      process.exit(1);
    }
    const parsed = Number(xLimitValue);
    if (!Number.isSafeInteger(parsed)) {
      console.error(`Invalid --x-limit value: "${xLimitValue}" (exceeds safe integer range)`);
      printUsage();
      process.exit(1);
    }
    xLimit = parsed;
  }

  const ingestThreatReportValue = extractValue(ingestThreatReportArg);
  if (ingestThreatReportValue !== undefined && ingestThreatReportValue === '') {
    console.error('Invalid --ingest-threat-report value: "" (expected non-empty path)');
    printUsage();
    process.exit(1);
  }

  const markThreatReviewedValue = extractValue(markThreatReviewedArg);
  if (markThreatReviewedValue !== undefined && markThreatReviewedValue === '') {
    console.error('Invalid --mark-threat-reviewed value: "" (expected non-empty report_id)');
    printUsage();
    process.exit(1);
  }

  const agentValue = extractValue(agentArg);
  if (agentValue !== undefined && agentValue.trim() === '') {
    console.error('Invalid --agent value: "" (expected a non-empty task description)');
    printUsage();
    process.exit(1);
  }

  const targetRepoValue = extractValue(targetRepoArg);
  if (targetRepoValue !== undefined && targetRepoValue.trim() === '') {
    console.error('Invalid --target-repo value: "" (expected <owner/repo> or a local path)');
    printUsage();
    process.exit(1);
  }

  const xPick = argv.includes('--x-pick');
  const xSyncFolders = argv.includes('--x-sync-folders');

  return {
    config: argv.includes('--config'),
    dryRun: argv.includes('--dry-run'),
    syncRules: argv.includes('--sync-rules'),
    xAuth: argv.includes('--x-auth'),
    // --x-pick は --x-bookmarks を含意 (両者の単独/併記どちらも有効)
    xBookmarks: argv.includes('--x-bookmarks') || xPick,
    xPick,
    xSyncFolders,
    noSync: argv.includes('--no-sync'),
    xMigrateLegacy: argv.includes('--x-migrate-legacy'),
    xDeriveRules: argv.includes('--x-derive-rules'),
    xResummarizeAll: argv.includes('--x-resummarize-all'),
    xSummaryReconfig: argv.includes('--x-summary-reconfig'),
    xLimit,
    ingestThreatReport: ingestThreatReportValue,
    analyzeThreatRelevance: argv.includes('--analyze-threat-relevance'),
    threatRelevanceAll: argv.includes('--threat-relevance-all'),
    threatRelevanceReconfig: argv.includes('--threat-relevance-reconfig'),
    rebuildThreatReportsDb: argv.includes('--rebuild-threat-reports-db'),
    markThreatReviewed: markThreatReviewedValue,
    targetRepo: targetRepoValue,
    listTargetRepos: argv.includes('--list-target-repos'),
    agent: agentValue,
    handsOn: extractValue(handsOnArg),
    since: extractValue(sinceArg),
    // 位置引数 (非 flag): 先頭のみ採用
    filePath: argv.find((a) => !a.startsWith('--')),
  };
}

export function printUsage(): void {
  console.error('Usage:');
  console.error('  tsx index.ts <path-to-onetab.txt> [--config] [--dry-run]');
  console.error('  tsx index.ts --x-bookmarks [--x-limit=N] [--dry-run] [--no-sync]');
  console.error('  tsx index.ts --x-pick      [--x-limit=N] [--dry-run] [--no-sync]  (フォルダ対話選択)');
  console.error('  tsx index.ts --x-sync-folders        (Vault再編後 / orphan AI 判定用の手動同期)');
  console.error('  tsx index.ts --x-migrate-legacy      (旧 Clippings/X-Bookmarks/ → _Archived/ への一度きり移行)');
  console.error('  tsx index.ts --x-derive-rules        (vault 構造から x_forced_parents.json を自動推定)');
  console.error('  tsx index.ts --x-bookmarks --x-resummarize-all  (AI 要約を全件再生成)');
  console.error('  tsx index.ts --x-bookmarks --x-summary-reconfig (AI 要約の provider / model を再選択)');
  console.error('  tsx index.ts --x-auth                (X OAuth 初回認証)');
  console.error('  tsx index.ts --hands-on="<vault-path>" [--since=YYYY-MM-DD]');
  console.error('  tsx index.ts --sync-rules            (snippets→folder_rules 同期のみ)');
  console.error('  tsx index.ts --ingest-threat-report=<path>.md  (週次 LLM 脅威レポート取込)');
  console.error('  tsx index.ts --analyze-threat-relevance [--target-repo=<owner/repo|path>]  (取込済み脅威の対象リポ該当性を判定→per-repo ノート記入 / Level 2 検知)');
  console.error('  tsx index.ts --analyze-threat-relevance --threat-relevance-all       (AI 記入済みも再判定 / 人手 note は保護)');
  console.error('  tsx index.ts --analyze-threat-relevance --threat-relevance-reconfig  (判定 provider / model を再選択)');
  console.error('  tsx index.ts --rebuild-threat-reports-db       (raw/*.md から threat_reports DB を再構築 / 破損復旧。human note は復元不可)');
  console.error('  tsx index.ts --mark-threat-reviewed=<report_id> [--target-repo=<owner/repo|path>]  (対象リポについて該当性レビュー済みフラグを立てる / /sec-review 用)');
  console.error('  tsx index.ts --list-target-repos               (ローカル clone 済みリポを列挙 / /sec-review の対象リポ選択用)');
  console.error('  tsx index.ts --agent="<task>"        (Vault サンドボックス内の Tool Use エージェント / 各操作に [y/N] 承認)');
}
