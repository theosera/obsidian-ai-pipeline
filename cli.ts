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
 *   --x-bookmarks         X API v2 ブックマーク取込モード
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
    if (!/^\d+$/.test(xLimitValue)) {
      console.error(`Invalid --x-limit value: "${xLimitValue}" (expected positive integer)`);
      printUsage();
      process.exit(1);
    }
    xLimit = parseInt(xLimitValue, 10);
  }

  return {
    config: argv.includes('--config'),
    dryRun: argv.includes('--dry-run'),
    syncRules: argv.includes('--sync-rules'),
    xAuth: argv.includes('--x-auth'),
    xBookmarks: argv.includes('--x-bookmarks'),
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
  console.error('  tsx index.ts --x-bookmarks [--x-limit=N] [--dry-run]');
  console.error('  tsx index.ts --x-auth                (X OAuth 初回認証)');
  console.error('  tsx index.ts --hands-on="<vault-path>" [--since=YYYY-MM-DD]');
  console.error('  tsx index.ts --sync-rules            (snippets→folder_rules 同期のみ)');
}
