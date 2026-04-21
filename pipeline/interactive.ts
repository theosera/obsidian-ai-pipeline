import fs from 'fs';
import { saveMarkdown, updateVaultTreeSnapshot, ensureSafePath } from '../storage';
import { tokenUsageMetrics } from '../classifier';
import { ProcessingResult } from '../types';
import { ApiBookmark } from '../x_bookmarks_api';
import { getDb, closeDb } from '../x_bookmarks_db';
import { askQuestion, isPromptClosed } from './prompt';
import { generateReport } from './report';

/**
 * 分類結果に対する人間レビュー + 保存確定ループ。
 *
 * 3 つのコマンド:
 *   [y] Approve: 全件を Vault に保存。X ブックマーク由来なら SQLite メタキャッシュにも upsert
 *   [e] Edit:    ID 指定で個別の proposedPath を手動修正。修正後レポートも再生成
 *   [q] Quit:    何も保存せず終了
 *
 * 非対話実行 (stdin EOF) への配慮:
 *   パイプ実行時などは入力が空文字で返ってくる。その場合「レポートは生成済みなので
 *   後から --rescue で再開できる」ことをユーザーに案内して安全にループを抜ける。
 *   データを勝手に保存しないことで、意図しない書き込みを防止する。
 */
export async function interactiveReviewLoop(
  results: ProcessingResult[],
  reportMdPath: string
): Promise<void> {
  let reviewing = true;

  while (reviewing) {
    console.log('\n=========================================');
    console.log(`Report generated at: ${reportMdPath}`);
    console.log(
      'Type [y] to Approve all & save, [e] to Edit a classification, [q] to Quit/Abort.'
    );

    const cmd = (await askQuestion('Command [y/e/q]: ')).toLowerCase();

    if (cmd === 'y') {
      await saveApprovedResults(results);
      reviewing = false;
    } else if (cmd === 'e') {
      await editOneClassification(results, reportMdPath);
    } else if (cmd === 'q') {
      console.log('Aborted execution.');
      reviewing = false;
    } else if (cmd === '' && isPromptClosed()) {
      // stdin EOF: 非対話環境。レポートは既に生成済みなので Vault への
      // 保存はスキップして安全に終了する。
      console.log('\n⚠️ stdin が閉じられました（非対話実行）。');
      console.log(`   レポートは生成済み: ${reportMdPath}`);
      console.log('   レビュー後、以下で Vault への保存を実行できます:');
      console.log(`   pnpm start -- --rescue "${reportMdPath}"`);
      reviewing = false;
    }
  }
}

async function saveApprovedResults(results: ProcessingResult[]): Promise<void> {
  console.log('\n🚀 Approved! Proceeding to save files to Vault...');

  for (const res of results) {
    if (!(res.status === 'success' && res.articleContext && res.classification)) continue;

    try {
      const savedPath = saveMarkdown(res.articleContext, res.classification.proposedPath);
      console.log(` ✅ Saved: ${savedPath}`);

      // X ブックマーク経由なら SQLite メタキャッシュにも反映 (差分スクレイプ用)
      const ax = res.articleContext as ApiBookmark;
      if (res.policy === 'x_bookmark' && ax.xTweetId) {
        try {
          getDb().upsertBookmark({
            tweetId: ax.xTweetId,
            url: ax.url,
            tweetText: ax.textContent,
            createdAt: ax.date,
            xFolderName: ax.xFolderName,
            vaultPath: savedPath,
          });
        } catch (dbErr: any) {
          console.warn(`   ⚠️  DB upsert 失敗 (続行): ${dbErr.message}`);
        }
      }
    } catch (e: any) {
      console.error(` ❌ Error saving ${res.url}: ${e.message}`);
    }
  }

  console.log('🎉 All files saved.');
  updateVaultTreeSnapshot(); // 新規作成フォルダをスナップショットに反映
  closeDb();
}

async function editOneClassification(
  results: ProcessingResult[],
  reportMdPath: string
): Promise<void> {
  const idStr = await askQuestion('Enter the item ID (e.g., 1): ');
  const itemId = parseInt(idStr, 10);
  const target = results.find((r) => r.id === itemId);

  if (!target || !target.classification) {
    console.log('Item ID not found or already excluded.');
    return;
  }

  console.log(`Current Path: ${target.classification.proposedPath}`);
  const newPath = await askQuestion('Enter new folder path (leave empty to cancel): ');
  if (newPath.trim() === '') return;

  const safePath = ensureSafePath(newPath.trim());
  if (safePath !== newPath.trim()) {
    console.log(`[Security] パスがサニタイズされました: "${newPath.trim()}" -> "${safePath}"`);
  }
  target.classification.proposedPath = safePath;
  target.classification.isNewFolder = false;
  console.log('Updated!');

  // 修正を反映したレポート .md を再書き出し
  const newReportMd = generateReport(results, tokenUsageMetrics);
  fs.writeFileSync(reportMdPath, newReportMd, 'utf8');
}
