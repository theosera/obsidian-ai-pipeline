/**
 * rescue-from-report.ts
 *
 * 中断した分類結果レポート (.md) から Vault への保存だけを再実行するリカバリモード。
 * AI 分類を丸ごとスキップ (API コスト $0) し、レポートに記載された {folder, url, title}
 * を Web fetch → extract → saveMarkdown で保存する。
 *
 * 呼び出し口:
 *   - `pnpm start -- --rescue <report>.md`     index.ts が runRescueFromReport を dispatch
 *   - `tsx rescue-from-report.ts <report>.md`   本ファイルの CLI main-guard から直接実行
 *
 * 本モジュールは import しても副作用を起こさない (CLI は main-guard 配下でのみ走る)。
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { fetchRenderedHtml, closeBrowser } from './fetcher.js';
import { extractAndConvert } from './extractor.js';
import { saveMarkdown, updateVaultTreeSnapshot, ensureSafePath } from './storage.js';
import { loadConfig, applyConfigToEnv, isDryRun, setDryRun } from './config.js';

interface RescueItem {
  url: string;
  title: string;
  /** ensureSafePath で Vault 相対に正規化済みのフォルダ (要 VAULT_ROOT) */
  folder: string;
}

export interface RescueResult {
  total: number;
  saved: number;
  failed: number;
}

/**
 * レポートが X ブックマーク由来か (H1 タイトルが `# X-Bookmarks分類結果レポート`) を判定する。
 *
 * X フローは 1 ツイート 1 MD を書かず SQLite upsert + group ページ再生成で管理するため、
 * 汎用 rescue (per-tweet `.md` を saveMarkdown) をそのまま流すと Vault に不整合ファイルを
 * 生成し、X DB / group ページも更新されない。rescue はこれを検出して拒否する。
 *
 * ラベルは `report.ts::generateReport` の `# ${reportLabel}分類結果レポート` に由来
 * (reportLabel = 'X-Bookmarks' | 'OneTab')。
 */
export function isXBookmarksReport(content: string): boolean {
  return /^#\s+X-Bookmarks分類結果レポート/m.test(content);
}

/**
 * 分類結果レポート .md をパースして保存対象 {url, title, folder}[] を抽出する。
 * フォルダ見出し `### <folder>` (✨(新規提案) バッジは除去) の配下に続く
 * `- [n] [title](url)` 行を、その直近フォルダに束ねる。
 *
 * folder は `ensureSafePath` で Vault 相対に正規化するため VAULT_ROOT が必要
 * (パストラバーサルを含む見出しは安全なフォールバックパスに落ちる)。
 */
export function parseReportItems(content: string): RescueItem[] {
  const lines = content.split('\n');
  let currentFolder: string | null = null;
  const items: RescueItem[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    // フォルダ見出し: `### Engineer/LLM ✨(新規提案)` / `### Engineer/LLM`
    if (line.startsWith('### ')) {
      currentFolder = line
        .replace(/^###\s+/, '')
        .replace(/✨\(新規提案\)/, '')
        .trim();
      continue;
    }

    const linkMatch = line.match(/^- \[\d+\] \[(.*?)\]\((.*?)\)/);
    if (linkMatch && currentFolder) {
      items.push({
        title: linkMatch[1],
        url: linkMatch[2],
        folder: ensureSafePath(currentFolder),
      });
    }
  }
  return items;
}

/**
 * レポートから Vault 保存を再実行する (AI 分類はスキップ)。
 * dry-run 時は Web fetch / extract までは行うが、saveMarkdown / snapshot 更新
 * (= Vault への書き込み) は一切行わず「保存予定」だけをログする。
 */
export async function runRescueFromReport(opts: {
  reportPath: string;
  dryRun?: boolean;
}): Promise<RescueResult> {
  // 直接実行 (本ファイルの CLI) では自前で dry-run を立てる。index.ts 経由では
  // 既に main() が setDryRun 済みなので、二重のバナー出力を避けて再設定しない。
  if (opts.dryRun && !isDryRun()) setDryRun(true);
  const dry = isDryRun();

  const content = fs.readFileSync(opts.reportPath, 'utf8');

  // X ブックマーク由来レポートは拒否する。汎用 rescue の per-tweet .md 保存は X フロー
  // (SQLite upsert + group ページ) と非互換で、Vault に不整合ファイルを生成するため。
  if (isXBookmarksReport(content)) {
    console.error('❌ このレポートは X ブックマーク由来です (`# X-Bookmarks分類結果レポート`)。');
    console.error('   --rescue は X ブックマークの再開に対応していません:');
    console.error('   X フローは 1 ツイート 1 MD を書かず、SQLite への upsert + group ページ再生成で管理します。');
    console.error('   汎用 rescue で per-tweet .md を書くと Vault に不整合ファイルが生成されます。');
    console.error('   → 再取得は `pnpm start -- --x-bookmarks` を使ってください (dedup で既取得分はスキップ)。');
    throw new Error('rescue は X ブックマークレポートに未対応です (--x-bookmarks で再取得してください)');
  }

  const items = parseReportItems(content);

  if (items.length === 0) {
    console.log('No valid classification links found in the report.');
    return { total: 0, saved: 0, failed: 0 };
  }

  console.log(`\nFound ${items.length} items to rescue and save.`);
  console.log('AI Classification will be SKIPPED (saving API costs).');
  if (dry) {
    console.log('🧪 dry-run: Web fetch は行いますが Vault への保存はスキップします (計画のみログ)。');
  }
  console.log('Proceeding to Web Fetch and Direct Vault Save...\n');

  let saved = 0;
  let failed = 0;
  const CONCURRENCY_LIMIT = 5;

  try {
    for (let i = 0; i < items.length; i += CONCURRENCY_LIMIT) {
      const chunk = items.slice(i, i + CONCURRENCY_LIMIT);

      const chunkResults = await Promise.all(
        chunk.map(async (item, indexInChunk) => {
          const globalIndex = i + indexInChunk + 1;
          const label = `[${globalIndex}/${items.length}] ${item.title.substring(0, 30)}...`;
          try {
            const html = await fetchRenderedHtml(item.url);
            const article = extractAndConvert(html, item.url);
            if (dry) {
              console.log(`${label} 🧪 [DRY-RUN] would save to ${item.folder}`);
            } else {
              saveMarkdown(article, item.folder);
              console.log(`${label} ✅ Saved to ${item.folder}`);
            }
            return true;
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            console.log(`${label} ❌ Failed: ${msg}`);
            return false;
          }
        })
      );

      for (const ok of chunkResults) {
        if (ok) saved++;
        else failed++;
      }
    }
  } finally {
    await closeBrowser();
  }

  // 新規作成フォルダをスナップショットへ反映 (dry-run は Vault を変更しないのでスキップ)。
  if (saved > 0 && !dry) {
    updateVaultTreeSnapshot();
  }

  console.log(
    `\n🎉 Rescue Complete! ${saved}/${items.length} articles ${dry ? 'would be' : 'successfully'} saved to Vault.`
  );
  console.log(`\n## 💸 APIトークン使用量と概算コスト`);
  console.log(`- **AI推論スキップ (Rescue Mode)**: Input 0 tokens, Output 0 tokens (約 $0.0000)`);
  console.log(`\n**💰 Total Estimated Cost: $0.0000**\n`);

  return { total: items.length, saved, failed };
}

// ------------------------------------------------------------------ //
// CLI entry point (直接実行時のみ — import では副作用を起こさない)
// ------------------------------------------------------------------ //
async function runCli(): Promise<void> {
  const args = process.argv.slice(2);
  const reportPath = args.find((a) => !a.startsWith('--'));
  const dryRun = args.includes('--dry-run');

  if (!reportPath || !fs.existsSync(reportPath)) {
    console.error('Usage: tsx rescue-from-report.ts <path-to-markdown-report> [--dry-run]');
    process.exit(1);
  }

  // コンフィグから VAULT_ROOT を読み込む
  const config = loadConfig();
  if (!config) {
    console.error('pipeline_config.json が見つかりません。先に pnpm start -- --config を実行してください。');
    process.exit(1);
  }
  applyConfigToEnv(config);

  console.log(`Starting Rescue Mode from Report: ${reportPath}`);
  await runRescueFromReport({ reportPath, dryRun });
  process.exit(0);
}

const invokedDirectly = (() => {
  if (!process.argv[1]) return false;
  return path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
})();
if (invokedDirectly) {
  runCli().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
