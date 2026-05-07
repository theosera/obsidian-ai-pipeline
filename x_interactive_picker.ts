/**
 * `--x-pick` の Stage 2: ユーザー選択 → folder ID 配列。
 *
 * 選択文法 (カンマ区切りで複数指定可):
 *   "1"        → グループ [1] の全サブフォルダ (unfiled グループなら unfiled だけ選択)
 *   "1.2"      → サブフォルダ [1.2] のみ
 *   "1-3"      → グループ [1]〜[3] (範囲展開)
 *   "all"      → 全フォルダ + unfiled
 *   "q"        → 中止 (cancelled=true)
 *
 * 出力:
 *   {
 *     folderIds: string[],   // 重複排除済み・入力順
 *     includeUnfiled: boolean,
 *     cancelled: boolean,    // "q" 入力時 true
 *   }
 *
 * パースは pure function なのでテストしやすい。readline 統合 (pickFolders) は
 * pipeline/prompt.ts の askQuestion を依存注入で受け取る。
 */

import type { FolderTree } from './x_folder_tree';

export interface SelectionResult {
  folderIds: string[];
  includeUnfiled: boolean;
  cancelled: boolean;
}

/**
 * 選択文字列を SelectionResult に変換する pure 関数。
 * 不正トークンは Error を投げる (呼出し側で再プロンプトする想定)。
 */
export function parseSelection(input: string, tree: FolderTree): SelectionResult {
  const trimmed = input.trim().toLowerCase();
  if (trimmed === 'q' || trimmed === 'quit' || trimmed === 'cancel') {
    return { folderIds: [], includeUnfiled: false, cancelled: true };
  }
  if (trimmed === '' ) {
    throw new Error('入力が空です。番号を入力してください (例: 1, 2.3 / 中止は q)');
  }

  // all → 全グループ全選択
  if (trimmed === 'all') {
    const folderIds: string[] = [];
    let includeUnfiled = false;
    for (const g of tree.groups) {
      if (g.kind === 'unfiled') { includeUnfiled = true; continue; }
      for (const c of g.children) {
        if (c.folderId) folderIds.push(c.folderId);
      }
    }
    return { folderIds: dedupeOrdered(folderIds), includeUnfiled, cancelled: false };
  }

  const tokens = input.split(',').map(t => t.trim()).filter(t => t.length > 0);
  const folderIds: string[] = [];
  let includeUnfiled = false;

  for (const tok of tokens) {
    // グループ範囲 "1-3" (サブ番号は範囲非対応・「.」を含むなら通常パース)
    const rangeMatch = tok.match(/^(\d+)\s*-\s*(\d+)$/);
    if (rangeMatch) {
      const from = Number(rangeMatch[1]);
      const to = Number(rangeMatch[2]);
      if (!Number.isFinite(from) || !Number.isFinite(to) || from < 1 || to < from) {
        throw new Error(`不正な範囲指定: "${tok}"`);
      }
      for (let i = from; i <= to; i++) {
        applyGroupSelection(String(i), tree, folderIds, (u) => { if (u) includeUnfiled = true; });
      }
      continue;
    }

    // サブフォルダ "n.m"
    const subMatch = tok.match(/^(\d+)\.(\d+)$/);
    if (subMatch) {
      const groupIdx = subMatch[1];
      const childIdx = `${groupIdx}.${subMatch[2]}`;
      const group = tree.groups.find(g => g.index === groupIdx);
      if (!group) throw new Error(`グループ番号 [${groupIdx}] は存在しません`);
      if (group.kind === 'unfiled') {
        // unfiled グループにサブはないが、"n.1" 形式が来たら unfiled として吸収する
        includeUnfiled = true;
        continue;
      }
      const child = group.children.find(c => c.index === childIdx);
      if (!child) throw new Error(`サブフォルダ番号 [${childIdx}] は存在しません`);
      if (child.folderId) folderIds.push(child.folderId);
      continue;
    }

    // グループ単独 "n"
    if (/^\d+$/.test(tok)) {
      applyGroupSelection(tok, tree, folderIds, (u) => { if (u) includeUnfiled = true; });
      continue;
    }

    throw new Error(`不正な入力: "${tok}" (例: 1 / 1.2 / 1-3 / all / q)`);
  }

  if (folderIds.length === 0 && !includeUnfiled) {
    // tokens 全部マッチしてもこの状態 = ロジック異常。安全のため例外。
    throw new Error('選択結果が空です。少なくとも 1 つのフォルダを指定してください。');
  }

  return { folderIds: dedupeOrdered(folderIds), includeUnfiled, cancelled: false };
}

function applyGroupSelection(
  groupIdx: string,
  tree: FolderTree,
  folderIds: string[],
  setUnfiled: (v: boolean) => void
): void {
  const group = tree.groups.find(g => g.index === groupIdx);
  if (!group) throw new Error(`グループ番号 [${groupIdx}] は存在しません`);
  if (group.kind === 'unfiled') {
    setUnfiled(true);
    return;
  }
  for (const c of group.children) {
    if (c.folderId) folderIds.push(c.folderId);
  }
}

function dedupeOrdered<T>(arr: T[]): T[] {
  const seen = new Set<T>();
  const out: T[] = [];
  for (const x of arr) {
    if (!seen.has(x)) {
      seen.add(x);
      out.push(x);
    }
  }
  return out;
}

/**
 * Tree を表示 → askQuestion ループでユーザー選択を取る対話ヘルパ。
 * 不正入力時は再プロンプト (最大 maxRetries 回)。超過時は cancelled として返す。
 *
 * askFn は pipeline/prompt.ts の askQuestion を渡す想定 (テストではモック)。
 */
export async function pickFolders(
  tree: FolderTree,
  renderedTree: string,
  askFn: (prompt: string) => Promise<string>,
  maxRetries = 3
): Promise<SelectionResult> {
  console.log('\n' + renderedTree + '\n');
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const answer = await askFn('選択 > ');
    try {
      return parseSelection(answer, tree);
    } catch (e: any) {
      console.error(`⚠️  ${e.message}`);
      if (attempt === maxRetries) {
        console.error(`再試行回数上限 (${maxRetries}) に達したため中止します。`);
        return { folderIds: [], includeUnfiled: false, cancelled: true };
      }
    }
  }
  // unreachable
  return { folderIds: [], includeUnfiled: false, cancelled: true };
}
