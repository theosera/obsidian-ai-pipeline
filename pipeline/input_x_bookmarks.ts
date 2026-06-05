import { fetchBookmarksViaApi } from '../x-bookmarks/api_client';
import { ApiBookmark } from '../x-bookmarks/types';
import {
  loadForcedParents,
  loadApprovedMappings,
  mapFolderToVaultPath,
  detectCommonKeywords,
  writeGroupingProposal,
  prioritizeForcedParents,
} from '../x-bookmarks/folder_mapper';
import { getDb } from '../x-bookmarks/db';
import { lookupVaultPath } from '../x-bookmarks/session_registry';
import { getXBookmarksBaseFolder } from '../config';
import { ParsedEntry, FailureRecord } from './types';

/**
 * session 経由の vault_path は X_Bookmarks/... のようなフル相対パスで保存されている。
 * input_x_bookmarks → processor の流れでは processor 側が base folder を再 prefix する
 * 設計なので、ここで一旦剥がす。
 */
function stripBaseFolderPrefix(vaultPath: string): string {
  const baseNorm = getXBookmarksBaseFolder().replace(/\/+$/, '');
  if (vaultPath === baseNorm) return '';
  if (vaultPath.startsWith(baseNorm + '/')) {
    return vaultPath.slice(baseNorm.length + 1);
  }
  return vaultPath;
}

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
  /**
   * --x-pick 経由で選択されたフォルダ ({id, name}) 配列。
   * undefined は従来挙動 (全フォルダ)。空配列 + includeUnfiled=true は Unfiled だけ取得。
   */
  selectedFolders?: { id: string; name: string }[];
  /** --x-pick で _Unfiled を選択したかどうか。未指定は true (従来挙動)。 */
  includeUnfiled?: boolean;
  /** --x-pick 経由のときは Tier 3 提案レポート出力をスキップ (Stage 1 で表示済み)。 */
  suppressGroupingProposal?: boolean;
}): Promise<{ entries: ParsedEntry[]; failures: FailureRecord[] }> {
  const { maxItems, knownUrls, selectedFolders, includeUnfiled, suppressGroupingProposal } = options;
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
    selectedFolders,
    includeUnfiled,
  });

  // 各 ApiBookmark に session_id を注入 (folder_sessions DB ベース)。
  // sync phase が走っていれば全 X 側 folder ID は session 登録済み。
  // N+1 を避けるため xFolderId → session_id を一度だけキャッシュする。
  const folderSessionCache = new Map<string, string>();
  for (const bm of bookmarks) {
    if (!bm.xFolderId) continue;
    if (!folderSessionCache.has(bm.xFolderId)) {
      const sess = db.getFolderSessionByXFolderId(bm.xFolderId);
      folderSessionCache.set(bm.xFolderId, sess?.session_id ?? '');
    }
    const sid = folderSessionCache.get(bm.xFolderId);
    if (sid) bm.xSessionId = sid;
  }

  // 共通キーワード提案レポート (未マッチフォルダのみ対象)
  if (!suppressGroupingProposal) {
    const folderNamesRaw = [...new Set(bookmarks.map((b) => b.xFolderName))];
    const proposals = detectCommonKeywords(folderNamesRaw, forcedParents);
    if (proposals.length > 0) {
      const reportPath = writeGroupingProposal(proposals);
      console.log(`📋 共通キーワード提案レポート: ${reportPath}`);
      console.log('   → 親フォルダとして承認するなら x_forced_parents.json に追記してください。');
    }
  }

  // 頻度優先のキーワード並び替えはバッチに対して 1 度だけ計算 (per-iteration sort 回避)
  const allFolderNames = [...new Set(bookmarks.map(b => b.xFolderName))];
  const sortedForcedParents = prioritizeForcedParents(forcedParents, allFolderNames);

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

    // session があれば session.vault_path を最優先 (Vault 移動・再編に追従)。
    // 無ければ Tier 1/2/3 のキーワードベース解決にフォールバック。
    // session 経由のパスには X-Bookmarks ベース prefix が付いている可能性があるため、
    // processor 側の再 prefix と二重にならないように一度剥がす。
    const sessionPath = bm.xSessionId ? lookupVaultPath(bm.xSessionId) : null;
    const vaultSubPath = sessionPath
      ? stripBaseFolderPrefix(sessionPath)
      : mapFolderToVaultPath(bm.xFolderName, sortedForcedParents, approvedMap, {
          presortedForcedParents: sortedForcedParents,
        });
    // 後段 processor の X bookmark 固定ルーティングで参照される
    bm.xFolderName = vaultSubPath;

    // X ブックマークは evaluatePolicy をバイパス (x.com は通常 manual_skip される)
    entries.push({ url, title, policy: 'x_bookmark', preFetched: bm });
  }

  return { entries, failures };
}
