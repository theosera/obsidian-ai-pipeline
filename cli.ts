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
  console.error('  tsx index.ts --x-migrate-legacy      (旧 Clippings/X-Bookmarks/ → _Archived/ への一度きり移行)');
  console.error('  tsx index.ts --x-derive-rules        (vault 構造から x_forced_parents.json を自動推定)');
  console.error('  tsx index.ts --x-bookmarks --x-resummarize-all  (AI 要約を全件再生成)');
  console.error('  tsx index.ts --x-auth                (X OAuth 初回認証)');
  console.error('  tsx index.ts --hands-on="<vault-path>" [--since=YYYY-MM-DD]');
  console.error('  tsx index.ts --sync-rules            (snippets→folder_rules 同期のみ)');
}
