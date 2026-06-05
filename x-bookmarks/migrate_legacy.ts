/**
 * 旧パス `<vault>/Clippings/X-Bookmarks/` を `<vault>/_Archived/Clippings-X-Bookmarks-<ts>/`
 * に退避するワンショット移行ツール。
 *
 * 新パイプライン (X_Bookmarks/ + 1 グループ 1 MD + .x_bookmarks.json) への移行を
 * 安全に行うため、自動実行はしない。`pnpm start -- --x-migrate-legacy` で明示的に走らせる。
 *
 * 振る舞い:
 *   1. `Clippings/X-Bookmarks/` が無ければ no-op
 *   2. 既に `_Archived/` 配下に同名 timestamp ディレクトリがあれば衝突回避 (suffix を増やす)
 *   3. fs.renameSync で一括移動 (高速・原子的)。失敗時は abort
 *   4. SQLite の folder_sessions のうち vault_path が旧 prefix で始まる行は
 *      新 (archived) パスに rewrite し status を 'archived' に変更
 *   5. bookmarks 行の vault_path も新 prefix に書き換える (Dataview の JSON ビューが
 *      行を group='_Unfiled' として表示できるようにするため)
 *
 * dry-run 対応 (--dry-run): 計画だけログして実移動はしない。
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot, isDryRun } from '../config';
import { getDb } from './db';

const LEGACY_RELATIVE = path.posix.join('Clippings', 'X-Bookmarks');
const ARCHIVE_ROOT = '_Archived';

export interface MigrationResult {
  legacyPath: string;
  archivedPath: string | null;
  filesMoved: number;
  sessionsUpdated: number;
  bookmarksUpdated: number;
  skipped: boolean;
  reason?: string;
}

/**
 * 旧ディレクトリの存在チェック + 退避先パスの決定。
 * 衝突する場合は `-1` `-2` ... を suffix として付ける。
 */
function resolveArchivePath(vaultRoot: string): { src: string; dest: string } {
  const src = path.join(vaultRoot, LEGACY_RELATIVE);
  const now = new Date()
    .toISOString()
    .replace(/[:T]/g, '-')
    .replace(/\..+$/, ''); // YYYY-MM-DD-HH-MM-SS
  const baseName = `Clippings-X-Bookmarks-${now}`;
  let dest = path.join(vaultRoot, ARCHIVE_ROOT, baseName);
  let suffix = 1;
  while (fs.existsSync(dest)) {
    dest = path.join(vaultRoot, ARCHIVE_ROOT, `${baseName}-${suffix}`);
    suffix++;
  }
  return { src, dest };
}

function countMdRecursive(dir: string): number {
  if (!fs.existsSync(dir)) return 0;
  let n = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(full);
      else if (e.isFile() && e.name.endsWith('.md')) n++;
    }
  }
  return n;
}

/**
 * SQLite の行を新 archive prefix にマッピングする。
 * `oldVaultRelPrefix` (例: `"Clippings/X-Bookmarks"`) で始まる vault_path を
 * `newVaultRelPrefix` (例: `"_Archived/Clippings-X-Bookmarks-2026-05-11-..."`) に
 * 置換する。文字列前方一致で十分 (path separator も `/` で統一済み)。
 */
function rewritePrefix(oldPath: string, oldPrefix: string, newPrefix: string): string {
  const normalized = oldPath.replace(/\\/g, '/');
  if (normalized === oldPrefix) return newPrefix;
  if (normalized.startsWith(oldPrefix + '/')) {
    return newPrefix + normalized.slice(oldPrefix.length);
  }
  return oldPath; // 該当しないものは変更しない
}

export interface RunMigrationOptions {
  vaultRoot?: string;
}

export function runMigrateLegacy(options: RunMigrationOptions = {}): MigrationResult {
  const vaultRoot = options.vaultRoot ?? getVaultRoot();
  const legacyAbs = path.join(vaultRoot, LEGACY_RELATIVE);

  if (!fs.existsSync(legacyAbs)) {
    return {
      legacyPath: legacyAbs,
      archivedPath: null,
      filesMoved: 0,
      sessionsUpdated: 0,
      bookmarksUpdated: 0,
      skipped: true,
      reason: '旧ディレクトリが存在しません',
    };
  }

  const { src, dest } = resolveArchivePath(vaultRoot);
  const filesMoved = countMdRecursive(src);
  const newRelPrefix = path.posix.join(ARCHIVE_ROOT, path.basename(dest));

  if (isDryRun()) {
    console.log(`[DRY-RUN] move ${src} → ${dest}  (${filesMoved} .md)`);
    return {
      legacyPath: src,
      archivedPath: dest,
      filesMoved,
      sessionsUpdated: 0,
      bookmarksUpdated: 0,
      skipped: false,
      reason: 'dry-run',
    };
  }

  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.renameSync(src, dest);

  // SQLite を新パスに書き換え。
  // 既に archived な session は触らない (rerun 時の no-op を保証)。
  const db = getDb();
  let sessionsUpdated = 0;
  for (const s of db.listFolderSessions()) {
    if (!s.vault_path) continue;
    if (s.status === 'archived') continue;
    const rewritten = rewritePrefix(s.vault_path, LEGACY_RELATIVE, newRelPrefix);
    if (rewritten !== s.vault_path) {
      db.upsertFolderSession({
        sessionId: s.session_id,
        xFolderId: s.x_folder_id,
        xFolderName: s.x_folder_name,
        vaultPath: rewritten,
        parentKeyword: s.parent_keyword,
        status: 'archived',
      });
      sessionsUpdated++;
    }
  }

  // bookmarks 行も同様に rewrite (DB の整合性確保 + JSON ビューでの archive 表示)
  let bookmarksUpdated = 0;
  for (const r of db.listBookmarksForExport()) {
    if (!r.vault_path) continue;
    const rewritten = rewritePrefix(r.vault_path, LEGACY_RELATIVE, newRelPrefix);
    if (rewritten !== r.vault_path) {
      db.updateBookmarkVaultPath({
        tweetId: r.tweet_id,
        vaultPath: rewritten,
        xFolderName: undefined,
      });
      bookmarksUpdated++;
    }
  }

  return {
    legacyPath: src,
    archivedPath: dest,
    filesMoved,
    sessionsUpdated,
    bookmarksUpdated,
    skipped: false,
  };
}
