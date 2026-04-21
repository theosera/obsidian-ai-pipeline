import { getVaultFolders } from '../storage';
import { stripDateSuffix } from '../router';
import { ProcessingResult } from '../types';

/**
 * 分類結果の Markdown レポート生成。
 *
 * main パイプラインの ProcessingResult[] を受け取り、Obsidian 上でそのまま
 * プレビュー/閲覧できる .md 文字列を返す。副作用なし (ファイル書き込みは呼び出し側の責務)。
 *
 * 含まれる要素:
 *   - 実行サマリー (件数・新規提案数・要レビュー件数)
 *   - API トークン使用量と概算コスト
 *   - フォルダ別グルーピング詳細 (新規フォルダにはトレンド/差分の理由ブロック)
 *
 * 副作用として result.classification.isNewFolder を書き換える点に注意:
 * 日付サブフォルダ付きパスでベースカテゴリが既存なら「新規」扱いを取り消す。
 * これにより ✨(新規提案) は真に新しいジャンルだけに絞られ、router が
 * 自動付与した /YYYY-Qn を誤って新規扱いすることを防ぐ。
 */

/**
 * Million-token 単位のモデル別料金テーブル (USD)。
 * 新モデル追加時はここだけ更新すれば generateReport() のコスト表示が正しく動く。
 */
const PRICING_MILLION_TOKENS: Record<string, { in: number; out: number }> = {
  'gpt-4o': { in: 5.0, out: 15.0 },
  'gpt-4o-mini': { in: 0.15, out: 0.6 },
  'gemini-2.5-flash': { in: 0.075, out: 0.3 },
  'gemini-2.5-pro': { in: 1.25, out: 5.0 },
  'claude-haiku-4-5-20251001': { in: 0.25, out: 1.25 },
  'claude-3-5-haiku-20241022': { in: 0.25, out: 1.25 },
  'claude-sonnet-4-6': { in: 3.0, out: 15.0 },
  'claude-3-7-sonnet-20250219': { in: 3.0, out: 15.0 },
  'claude-opus-4-6': { in: 15.0, out: 75.0 },
};

/**
 * 日付サブフォルダ (`/YYYY-Qn` / `/YYYY-MM`) を剥がしたベースカテゴリが
 * 既に Vault に存在するなら「新規ジャンルではない」(= router が自動付与した
 * 日付サブフォルダにすぎない) と判定する。
 */
function isGenuinelyNewFolder(proposedPath: string, vaultFolders: string[]): boolean {
  const base = stripDateSuffix(proposedPath);
  // 日付 suffix がなかった (= proposedPath そのまま) ならベース判定に意味がない
  if (base === proposedPath) return true;
  return !vaultFolders.includes(base);
}

export function generateReport(
  results: ProcessingResult[],
  usageData: Record<string, { input: number; output: number }> = {}
): string {
  const successResults = results.filter((r) => r.status === 'success');
  const vaultFolders = getVaultFolders();

  // classifier が isNewFolder=true でも、日付サブフォルダで親カテゴリが既存なら新規扱いしない
  for (const r of successResults) {
    if (r.classification?.isNewFolder && r.classification.proposedPath) {
      if (!isGenuinelyNewFolder(r.classification.proposedPath, vaultFolders)) {
        r.classification.isNewFolder = false;
      }
    }
  }

  const newFolders = successResults.filter((r) => r.classification?.isNewFolder);
  const reviewItems = successResults.filter((r) => r.policy === 'public_review');

  let report = `# OneTab分類結果レポート\n\n`;
  report += `## 📊 実行サマリー\n`;
  report += `- **総取得件数:** ${successResults.length}件\n`;
  report += `- **新規提案フォルダ数:** ${newFolders.length}件\n`;
  report += `- **要レビュー(note/wired等):** ${reviewItems.length}件\n\n`;

  // === 💸 Token Usage & Cost ===
  if (Object.keys(usageData).length > 0) {
    report += `## 💸 APIトークン使用量と概算コスト\n`;
    let totalCost = 0;
    for (const [model, stats] of Object.entries(usageData)) {
      const rates = PRICING_MILLION_TOKENS[model] || { in: 0, out: 0 };
      const costIn = (stats.input / 1_000_000) * rates.in;
      const costOut = (stats.output / 1_000_000) * rates.out;
      const modelCost = costIn + costOut;
      totalCost += modelCost;

      report += `- **${model}**: Input ${stats.input.toLocaleString()} tokens, Output ${stats.output.toLocaleString()} tokens `;
      if (modelCost > 0) report += `(約 $${modelCost.toFixed(4)})\n`;
      else report += `(Local or Rate Unknown)\n`;
    }
    report += `\n**💰 Total Estimated Cost: $${totalCost.toFixed(4)}**\n\n`;
  }

  report += `## 📁 分類結果詳細\n\n`;

  // Group by folder
  const groups: Record<string, ProcessingResult[]> = {};
  for (const res of successResults) {
    if (!res.classification) continue;
    const folder = res.classification.proposedPath;
    if (!groups[folder]) groups[folder] = [];
    groups[folder].push(res);
  }

  for (const [folder, items] of Object.entries(groups)) {
    const isNew = items[0].classification!.isNewFolder;
    report += `### ${folder} ${isNew ? '✨(新規提案)' : ''}\n`;

    // For new folders, add reasoning block at the top
    if (isNew) {
      if (items[0].classification!.trendReasoning)
        report += `> **対応トレンド**: ${items[0].classification!.trendReasoning}\n`;
      if (items[0].classification!.diffReasoning)
        report += `> **既存との違い**: ${items[0].classification!.diffReasoning}\n\n`;
    }

    for (const item of items) {
      const reviewBadge = item.policy === 'public_review' ? ' ⚠️[要完全性チェック]' : '';
      report += `- [${item.id}] [${item.title || 'No Title'}](${item.url})${reviewBadge}\n`;
      if (item.classification!.reasoning && !isNew) {
        report += `  - *理由: ${item.classification!.reasoning}*\n`;
      }
    }
    report += `\n`;
  }

  return report;
}
