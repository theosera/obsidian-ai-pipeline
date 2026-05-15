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
 *   --x-bookmarks-rebuild-db
 *                         .md frontmatter + _session.json から DB を再構築 (復旧用)
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
  /** Vault の .md frontmatter + _session.json から DB を再構築 (復旧用・他フラグと併用不可) */
  xBookmarksRebuildDb: boolean;
  /** Sync Phase を抑止 (cron 等で速度優先) */
  noSync: boolean;
  xLimit?: number;
  handsOn?: string;
  since?: string;
  filePath?: string;
}

export function parseArgs(argv: readonly string[]): ParsedCliArgs {
  const handsOnArg = argv.find((a) => a.startsWith('--hands-on='));
  const sinceArg = argv.find((a) => a.startsWith('--since='));
  const xLimitArg = argv.find((a) => a.startsWith('--x-limit='));

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

  const xPick = argv.includes('--x-pick');
  const xSyncFolders = argv.includes('--x-sync-folders');
  const xBookmarksRebuildDb = argv.includes('--x-bookmarks-rebuild-db');

  // --x-bookmarks-rebuild-db はオフライン復旧用なので、他モードフラグとの併記を禁止する。
  // (CodeRabbit: 黙って受け流すと意図しない動作になる)
  if (xBookmarksRebuildDb) {
    const conflictFlags = [
      argv.includes('--x-bookmarks') && '--x-bookmarks',
      xPick && '--x-pick',
      xSyncFolders && '--x-sync-folders',
      argv.includes('--x-auth') && '--x-auth',
      argv.includes('--sync-rules') && '--sync-rules',
      !!handsOnArg && '--hands-on=...',
    ].filter((v): v is string => Boolean(v));
    if (conflictFlags.length > 0) {
      console.error(
        `Error: --x-bookmarks-rebuild-db は他モードと併用できません (検出: ${conflictFlags.join(', ')})`
      );
      printUsage();
      process.exit(1);
    }
  }

  return {
    config: argv.includes('--config'),
    dryRun: argv.includes('--dry-run'),
    syncRules: argv.includes('--sync-rules'),
    xAuth: argv.includes('--x-auth'),
    // --x-pick は --x-bookmarks を含意 (両者の単独/併記どちらも有効)
    xBookmarks: argv.includes('--x-bookmarks') || xPick,
    xPick,
    xSyncFolders,
    xBookmarksRebuildDb,
    noSync: argv.includes('--no-sync'),
    xLimit,
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
  console.error('  tsx index.ts --x-bookmarks-rebuild-db  (Vault .md → DB 再構築・復旧用)');
  console.error('  tsx index.ts --x-auth                (X OAuth 初回認証)');
  console.error('  tsx index.ts --hands-on="<vault-path>" [--since=YYYY-MM-DD]');
  console.error('  tsx index.ts --sync-rules            (snippets→folder_rules 同期のみ)');
}
