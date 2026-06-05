import fs from 'fs';
import { saveMarkdown, updateVaultTreeSnapshot, ensureSafePath } from '../storage';
import { tokenUsageMetrics } from '../classifier';
import { ProcessingResult, XSummaryConfig } from '../types';
import { DEFAULT_X_SUMMARY, isDryRun } from '../config';
import { ApiBookmark } from '../x-bookmarks/types';
import { getDb, closeDb } from '../x-bookmarks/db';
import { exportAndWriteAllGroupPages } from '../x-bookmarks/group_page_writer';
import { summarizePendingBookmarks } from '../x-bookmarks/summarizer';
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
  options: { resummarizeAll?: boolean; xSummary?: XSummaryConfig } = {}
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
      // 保存はスキップして安全に終了する。`--x-resummarize-all` を伴って実行された
      // 場合はモデル / プロンプト変更後の再要約意図が乗っているので、rescue 提案
      // にも flag を引き継ぐ (CodeRabbit 指摘)。
      const extraFlags = options.resummarizeAll ? ' --x-resummarize-all' : '';
      console.log('\n⚠️ stdin が閉じられました（非対話実行）。');
      console.log(`   レポートは生成済み: ${reportMdPath}`);
      console.log('   レビュー後、以下で Vault への保存を実行できます:');
      console.log(`   pnpm start -- --rescue "${reportMdPath}"${extraFlags}`);
      reviewing = false;
    }
  }
}

async function saveApprovedResults(
  results: ProcessingResult[],
  options: { resummarizeAll?: boolean; xSummary?: XSummaryConfig } = {}
): Promise<void> {
  const dry = isDryRun();
  if (dry) {
    // runner の confirmBeforeRun が "🧪 dry-run: Vault 書き込みはスキップ" と
    // 明示しているのに、ここで saveMarkdown / DB upsert /
    // regenerateXBookmarkArtifacts (= AI 要約 + JSON 書出 + group MD) を実行
    // すると整合性が崩れ、ユーザー期待を裏切る (回帰防止)。
    // --x-resummarize-all + 新規 0 件パスは runner.ts:154 で既に同様の dry-run
    // ガードがあるため、ここではこのパスを揃える役割。
    console.log('\n🧪 dry-run: Vault 書き込み・DB upsert・group ページ再生成はスキップします (計画のみログ出力)');
  } else {
    console.log('\n🚀 Approved! Proceeding to save files to Vault...');
  }
  let xBookmarkCount = 0;

  for (const res of results) {
    if (!(res.status === 'success' && res.articleContext && res.classification)) continue;

    try {
      const ax = res.articleContext as ApiBookmark;
      const isXBookmark = res.policy === 'x_bookmark' && !!ax.xTweetId;
      const targetPath = res.classification.proposedPath;

      if (isXBookmark) {
        if (dry) {
          console.log(` [DRY-RUN] would upsert bookmark tweet_id=${ax.xTweetId} → ${targetPath}`);
          xBookmarkCount++;
          continue;
        }
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
            vaultPath: targetPath,
            sessionId: ax.xSessionId,
            engagementLikes: ax.xLikes,
            engagementRetweets: ax.xRetweets,
            engagementReplies: ax.xReplies,
          });
          xBookmarkCount++;
          console.log(` 🔖 Indexed: ${ax.xTweetId} → ${targetPath}`);
        } catch (dbErr: any) {
          console.warn(`   ⚠️  DB upsert 失敗 (続行): ${dbErr.message}`);
        }
        continue;
      }

      // 非 X (OneTab / Hatena 等) は従来通り 1 記事 1 MD で保存。
      if (dry) {
        console.log(` [DRY-RUN] would save: ${targetPath}/<title>.md (url=${res.url})`);
        continue;
      }
      const savedPath = saveMarkdown(res.articleContext, targetPath);
      console.log(` ✅ Saved: ${savedPath}`);
    } catch (e: any) {
      console.error(` ❌ Error saving ${res.url}: ${e.message}`);
    }
  }

  // X ブックマークが含まれていれば AI 要約 → JSON ビュー → group ページ更新の順で実行。
  // `--x-resummarize-all` 指定時は、新規 upsert が 0 件でも既存 ai_summary を
  // 再生成する必要があるため `xBookmarkCount === 0` でも走らせる (本フラグの本来の
  // 用途 = モデル/プロンプト変更後の再生成では「新規 0 件 + 全件再要約」が常態)。
  // dry-run は AI コスト + Vault 書き込みを伴うのでスキップする。
  if ((xBookmarkCount > 0 || options.resummarizeAll) && !dry) {
    await regenerateXBookmarkArtifacts({
      xSummary: options.xSummary,
      resummarizeAll: options.resummarizeAll,
    });
  } else if ((xBookmarkCount > 0 || options.resummarizeAll) && dry) {
    console.log('   [DRY-RUN] would regenerate X artifacts (AI summary + JSON + group MD)');
  }

  if (dry) {
    console.log('🧪 dry-run 終了: 実体は変更されていません。');
  } else {
    console.log('🎉 All files saved.');
    updateVaultTreeSnapshot(); // 新規作成フォルダをスナップショットに反映
  }
  closeDb();
}

/**
 * X ブックマークの後処理セット (AI 要約 → JSON ビュー → group ページ).
 *
 * runner.ts の「新規 0 件 + `--x-resummarize-all`」パスからも直接呼ばれるため、
 * `saveApprovedResults` の中身から分離して公開している。要約を先に走らせるのは
 * JSON エクスポート時点で `ai_summary` 列が埋まっているようにするため (Dataview
 * が次に開かれた瞬間に新しい要約が反映される)。
 *
 * いずれの段階も try/catch で個別に握り潰す: best-effort で動かし、ベスト
 * エフォートで失敗ログだけ残して上位パイプを止めない方針 (要約失敗で JSON 更新
 * まで失われると Dataview 画面が古いままになるため)。
 */
export async function regenerateXBookmarkArtifacts(
  options: { xSummary?: XSummaryConfig; resummarizeAll?: boolean } = {}
): Promise<void> {
  // xSummary は通常 `runXSummaryWizard` 経由で必ず埋まっているが、テストや
  // 直叩きで未指定の場合は DEFAULT_X_SUMMARY (= cloud Anthropic Haiku 4.5)
  // にフォールバックして classifier 側の AI_PROVIDER とは独立した動作を保つ。
  const xSummary = options.xSummary ?? DEFAULT_X_SUMMARY;

  try {
    const stats = await summarizePendingBookmarks({
      resummarizeAll: options.resummarizeAll,
      provider: xSummary.provider,
      model: xSummary.model,
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

// テスト用 export (dry-run ガードの回帰防止)
export const __test = {
  saveApprovedResults,
};
