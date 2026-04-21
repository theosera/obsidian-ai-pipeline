import { fetchBookmarksViaApi, ApiBookmark } from '../x_bookmarks_api';
import {
  loadForcedParents,
  loadApprovedMappings,
  mapFolderToVaultPath,
  detectCommonKeywords,
  writeGroupingProposal,
} from '../x_folder_mapper';
import { getDb } from '../x_bookmarks_db';
import { ParsedEntry, FailureRecord } from './types';

/**
 * X API v2 からブックマークを取得し ParsedEntry[] に変換。
 *
 * fetcher/extractor をバイパス:
 *   API で既に構造化データ (ApiBookmark = ArticleData + X metadata) を取得しているため、
 *   preFetched に詰めて processor 以降ではそのまま使う。
 *
 * フォルダマッピング (3段階):
 *   Tier 1 (強制親): x_forced_parents.json 記載のキーワードを含めば親フォルダに強制振分
 *   Tier 2 (承認済みマップ): x_folder_mapping.json に登録済みのフォルダ名は展開
 *   Tier 3 (そのまま): X 側フォルダ名を sanitize した相対パスとして使用
 *
 * 共通キーワード提案レポート:
 *   Tier 1/2 のどちらにもマッチしなかったフォルダ名群から検出した keywords を
 *   .md レポートとして書き出す (Obsidian で確認 → 承認ステップへ)。
 *
 * 差分同期:
 *   SQLite メタキャッシュの tweet ID を API に渡して、既取得分を転送量から除外する。
 */
export async function prepareXBookmarks(options: {
  maxItems?: number;
  knownUrls: Set<string>;
}): Promise<{ entries: ParsedEntry[]; failures: FailureRecord[] }> {
  const { maxItems, knownUrls } = options;
  const entries: ParsedEntry[] = [];
  const failures: FailureRecord[] = [];

  console.log('🔖 X API v2 でブックマークを取得します...');
  const db = getDb();
  const knownTweetIds = db.getKnownTweetIds();
  const forcedParents = loadForcedParents();
  const approvedMap = loadApprovedMappings();
  console.log(
    `🔖 強制親フォルダキーワード: ${forcedParents.length > 0 ? forcedParents.join(', ') : '(未設定)'}`
  );
  console.log(`🔖 既知ツイートID: ${knownTweetIds.size} 件 (DB キャッシュ)`);

  const bookmarks: ApiBookmark[] = await fetchBookmarksViaApi({
    maxItems,
    skipKnownIds: knownTweetIds,
  });

  // 共通キーワード提案レポート (未マッチフォルダのみ対象)
  const folderNamesRaw = [...new Set(bookmarks.map((b) => b.xFolderName))];
  const proposals = detectCommonKeywords(folderNamesRaw, forcedParents);
  if (proposals.length > 0) {
    const reportPath = writeGroupingProposal(proposals);
    console.log(`📋 共通キーワード提案レポート: ${reportPath}`);
    console.log('   → 親フォルダとして承認するなら x_forced_parents.json に追記してください。');
  }

  for (let i = 0; i < bookmarks.length; i++) {
    const bm = bookmarks[i];
    const url = bm.url;
    const title = bm.title || `X post ${i + 1}`;
    const checkUrl = url.endsWith('/') ? url.slice(0, -1) : url;

    if (knownUrls.has(checkUrl)) {
      console.log(
        `[${i + 1}/${bookmarks.length}] ${title.substring(0, 40)}... Skipped (Duplicate in Vault)`
      );
      failures.push({ url, title, reason: 'Duplicate: Already exists in Vault' });
      continue;
    }

    // X 側フォルダ名 → Vault 階層パスに変換 (Tier 1/2/3)
    const vaultSubPath = mapFolderToVaultPath(bm.xFolderName, forcedParents, approvedMap);
    // 後段 processor の X bookmark 固定ルーティングで参照される
    bm.xFolderName = vaultSubPath;

    // X ブックマークは evaluatePolicy をバイパス (x.com は通常 manual_skip される)
    entries.push({ url, title, policy: 'x_bookmark', preFetched: bm });
  }

  return { entries, failures };
}
