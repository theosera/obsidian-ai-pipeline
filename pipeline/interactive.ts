import fs from 'fs';
import { saveMarkdown, updateVaultTreeSnapshot, ensureSafePath } from '../storage';
import { tokenUsageMetrics } from '../classifier';
import { ProcessingResult } from '../types';
import { ApiBookmark } from '../x_bookmarks_api';
import { getDb, closeDb } from '../x_bookmarks_db';
import { exportAndWriteAllGroupPages } from '../x_group_page_writer';
import { summarizePendingBookmarks } from '../x_bookmarks_summarizer';
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
  reportMdPath: string,
  options: { resummarizeAll?: boolean } = {}
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
      await saveApprovedResults(results, options);
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

async function saveApprovedResults(
  results: ProcessingResult[],
  options: { resummarizeAll?: boolean } = {}
): Promise<void> {
  console.log('\n🚀 Approved! Proceeding to save files to Vault...');
  let xBookmarkCount = 0;

  for (const res of results) {
    if (!(res.status === 'success' && res.articleContext && res.classification)) continue;

    try {
      const ax = res.articleContext as ApiBookmark;
      const isXBookmark = res.policy === 'x_bookmark' && !!ax.xTweetId;

      if (isXBookmark) {
        // X ブックマークは 1 ツイート 1 MD を書かない。SQLite にだけ反映し、
        // ユーザー向けには「1 グループ 1 MD + dataviewjs テーブル」で見せる。
        try {
          getDb().upsertBookmark({
            tweetId: ax.xTweetId!,
            url: ax.url,
            author: ax.xAuthorHandle ?? undefined,
            tweetText: ax.textContent,
            noteTweetText: ax.xNoteTweetText,
            createdAt: ax.date,
            xFolderName: ax.xFolderName,
            vaultPath: res.classification.proposedPath,
            sessionId: ax.xSessionId,
            engagementLikes: ax.xLikes,
            engagementRetweets: ax.xRetweets,
            engagementReplies: ax.xReplies,
          });
          xBookmarkCount++;
          console.log(` 🔖 Indexed: ${ax.xTweetId} → ${res.classification.proposedPath}`);
        } catch (dbErr: any) {
          console.warn(`   ⚠️  DB upsert 失敗 (続行): ${dbErr.message}`);
        }
        continue;
      }

      // 非 X (OneTab / Hatena 等) は従来通り 1 記事 1 MD で保存。
      const savedPath = saveMarkdown(res.articleContext, res.classification.proposedPath);
      console.log(` ✅ Saved: ${savedPath}`);
    } catch (e: any) {
      console.error(` ❌ Error saving ${res.url}: ${e.message}`);
    }
  }

  // X ブックマークが含まれていれば AI 要約 → JSON ビュー → group ページ更新の順で実行。
  // 要約を先に走らせるのは JSON エクスポート時点で summary 列が埋まっているように
  // するため (Dataview が次に開かれた瞬間に新しい要約が反映される)。
  if (xBookmarkCount > 0) {
    try {
      const stats = await summarizePendingBookmarks({
        resummarizeAll: options.resummarizeAll,
      });
      if (stats.pending > 0) {
        console.log(`🤖 AI 要約: ${stats.succeeded}/${stats.pending} 件成功, ${stats.failed} 件失敗`);
      }
    } catch (e: any) {
      console.warn(`⚠️  AI 要約失敗 (続行): ${e.message}`);
    }

    try {
      const { jsonPath, pages } = exportAndWriteAllGroupPages();
      console.log(`🗂  JSON ビュー更新: ${jsonPath}`);
      const summary = pages.reduce<Record<string, number>>((acc, p) => {
        acc[p.action] = (acc[p.action] ?? 0) + 1;
        return acc;
      }, {});
      const summaryStr = Object.entries(summary).map(([k, v]) => `${k}=${v}`).join(', ');
      console.log(`📄 Group ページ: ${pages.length} 件 (${summaryStr})`);
    } catch (e: any) {
      console.warn(`⚠️  JSON / group ページ更新失敗 (続行): ${e.message}`);
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
