/**
 * `--x-bookmarks-rebuild-db`: Vault 上の `.md` (frontmatter) と `_session.json`
 * から SQLite (`x_bookmarks.db`) を再構築する復旧ツール。
 *
 * 用途:
 *   - DB ファイル破損 / `.corrupted_*` 退避からの復旧
 *   - 別マシンに Vault をコピーした後の DB 復元
 *   - .md を source of truth として扱う運用ポリシーの徹底
 *
 * 入力:
 *   - `<vault>/<X_BOOKMARKS_FOLDER>/` 配下の `.md` (frontmatter から bookmark 情報)
 *   - 同配下の各フォルダの `_session.json` (folder_sessions の復元)
 *
 * 出力:
 *   - `bookmarks` テーブルへの UPSERT (重複は無視)
 *   - `folder_sessions` テーブルへの UPSERT
 *
 * **既存 DB は上書きしない** (UPSERT で merge する設計)。
 * 完全クリーンアップが必要なら手動で DB を消してから実行すること。
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot } from './config';
import { getDb } from './x_bookmarks_db';

export interface RebuildResult {
  scannedFiles: number;
  bookmarksUpserted: number;
  sessionsUpserted: number;
  skippedFiles: number;
}

interface ParsedFrontmatter {
  title?: string;
  source?: string;
  published?: string;
  session_id?: string;
  x_folder_id?: string;
  x_tweet_id?: string;
  x_folder_name?: string;
}

export function rebuildDbFromVault(baseFolder: string): RebuildResult {
  const db = getDb();
  const baseAbs = path.join(getVaultRoot(), baseFolder);
  const result: RebuildResult = {
    scannedFiles: 0,
    bookmarksUpserted: 0,
    sessionsUpserted: 0,
    skippedFiles: 0,
  };
  if (!fs.existsSync(baseAbs)) {
    console.warn(`⚠️  rebuild-db: ${baseFolder} が存在しません (vault path 設定を確認)`);
    return result;
  }

  const stack: string[] = [baseAbs];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (e.isFile() && e.name === '_session.json') {
        if (upsertSessionFromMarker(full, dir, baseFolder)) result.sessionsUpserted++;
        continue;
      }
      if (e.isFile() && e.name.endsWith('.md')) {
        result.scannedFiles++;
        const upserted = upsertBookmarkFromMd(full, baseFolder);
        if (upserted) result.bookmarksUpserted++;
        else result.skippedFiles++;
      }
    }
  }
  return result;
}

const VALID_STATUSES = new Set(['active', 'orphaned_on_x', 'orphaned_on_vault', 'archived']);

function upsertSessionFromMarker(file: string, dir: string, baseFolder: string): boolean {
  const db = getDb();
  try {
    const marker = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (typeof marker?.session_id !== 'string') return false;
    const vaultRelative = path.relative(getVaultRoot(), dir);
    // marker.status を尊重しつつ、無ければパスから推測 (_archived 配下なら archived)。
    // どちらも該当しないときだけ 'active' に倒す。
    // (CodeRabbit: 強制 'active' で archived/orphaned が resurrect されるリグレッション防止)
    const markerStatus = typeof marker?.status === 'string' && VALID_STATUSES.has(marker.status)
      ? marker.status as 'active' | 'orphaned_on_x' | 'orphaned_on_vault' | 'archived'
      : null;
    const looksArchived = vaultRelative.split(path.sep).includes('_archived');
    const status = markerStatus ?? (looksArchived ? 'archived' : 'active');
    db.upsertFolderSession({
      sessionId: marker.session_id,
      xFolderId: marker.x_folder_id ?? null,
      xFolderName: marker.x_folder_name ?? null,
      vaultPath: vaultRelative,
      status,
    });
    return true;
  } catch (e: any) {
    console.warn(`⚠️  rebuild-db: marker 解析失敗 ${file}: ${e.message}`);
    return false;
  }
}

function upsertBookmarkFromMd(file: string, baseFolder: string): boolean {
  const db = getDb();
  let fm: ParsedFrontmatter;
  try {
    fm = parseFrontmatter(fs.readFileSync(file, 'utf8'));
  } catch {
    return false;
  }
  if (!fm.x_tweet_id || !fm.source) return false; // X bookmark でない .md はスキップ
  db.upsertBookmark({
    tweetId: fm.x_tweet_id,
    url: fm.source,
    createdAt: fm.published,
    xFolderName: fm.x_folder_name,
    vaultPath: path.relative(getVaultRoot(), file),
    sessionId: fm.session_id,
  });
  return true;
}

/**
 * .md の YAML frontmatter を最小限パース。
 * - 先頭 `---\n` で始まり次の `---\n` までを frontmatter として扱う
 * - `key: "value"` または `key: value` 形式のみ対応 (本リポの saveMarkdown 出力に揃える)
 * - 配列 / インデント値はパースしない (該当フィールドなし)
 */
export function parseFrontmatter(raw: string): ParsedFrontmatter {
  const out: ParsedFrontmatter = {};
  if (!raw.startsWith('---\n')) return out;
  const end = raw.indexOf('\n---', 4);
  if (end < 0) return out;
  const block = raw.slice(4, end);
  for (const line of block.split('\n')) {
    const m = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    let value = m[2].trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value
        .slice(1, -1)
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\');
    }
    if (!value) continue;
    switch (key) {
      case 'title': out.title = value; break;
      case 'source': out.source = value; break;
      case 'published': out.published = value; break;
      case 'session_id': out.session_id = value; break;
      case 'x_folder_id': out.x_folder_id = value; break;
      case 'x_tweet_id': out.x_tweet_id = value; break;
      case 'x_folder_name': out.x_folder_name = value; break;
    }
  }
  return out;
}

export const __test = {
  parseFrontmatter,
};
