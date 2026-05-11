/**
 * SQLite (`x_bookmarks.db`) の bookmarks テーブルを `<vault>/<base>/.x_bookmarks.json`
 * に書き出す。Dataview (DataviewJS) がこの JSON を `dv.io.load()` で読んでテーブル
 * ビューを描画する。
 *
 * 設計:
 *   - SQLite が transactional な内部キャッシュ (session lifecycle / dedupe / 移動追跡)、
 *     JSON が Obsidian ユーザーに見える「DB ビュー」。同期のたびに上書き再生成する。
 *   - 行のスキーマは追加可能。`ai_summary` はプロデューサー未実装のため `null` 固定で
 *     書き出すが、列はテーブルビューに常に確保する (Dataview テンプレート側で対応)。
 *   - `group` は `<base>/<group>/...` の `<group>` 部分。`base` ちょうどに保存された
 *     orphan 行 (vault_path == base) は `group` 未確定とみなし `'_Unfiled'` を割り当てる。
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot, getXBookmarksBaseFolder } from './config';
import { XBookmarksDb, getDb } from './x_bookmarks_db';

export interface ExportedBookmarkRow {
  tweet_id: string;
  url: string;
  author: string | null;
  tweet_text: string | null;
  note_tweet_text: string | null;
  created_at: string | null;
  saved_at: string;
  engagement_likes: number | null;
  engagement_retweets: number | null;
  engagement_replies: number | null;
  x_folder_name: string | null;
  vault_path: string | null;
  group: string;
  ai_summary: string | null;
}

export interface ExportedJson {
  version: 1;
  generated_at: string;
  base_folder: string;
  rows: ExportedBookmarkRow[];
}

export const X_JSON_FILENAME = '.x_bookmarks.json';

/**
 * `vault_path` から group 名を抽出。
 *   - base 自身に保存された行 → '_Unfiled'
 *   - `<base>/<group>/...` → `<group>`
 *   - base 配下でない (legacy / migration 前) → '_Unfiled'
 */
export function deriveGroup(vaultPath: string | null, baseFolder: string): string {
  if (!vaultPath) return '_Unfiled';
  const baseNorm = baseFolder.replace(/\/+$/, '');
  const normalized = vaultPath.replace(/\\/g, '/').replace(/\/+$/, '');
  if (normalized === baseNorm) return '_Unfiled';
  const prefix = baseNorm + '/';
  if (!normalized.startsWith(prefix)) return '_Unfiled';
  const rest = normalized.slice(prefix.length);
  const firstSeg = rest.split('/')[0];
  return firstSeg || '_Unfiled';
}

interface ExportOptions {
  /** テスト注入用。省略時は getDb() */
  db?: XBookmarksDb;
  /** テスト注入用。省略時は getVaultRoot() */
  vaultRoot?: string;
  /** テスト注入用。省略時は getXBookmarksBaseFolder() */
  baseFolder?: string;
}

interface RawRow {
  tweet_id: string;
  url: string;
  author: string | null;
  tweet_text: string | null;
  note_tweet_text: string | null;
  created_at: string | null;
  saved_at: string;
  engagement_likes: number | null;
  engagement_retweets: number | null;
  engagement_replies: number | null;
  x_folder_name: string | null;
  vault_path: string | null;
}

/**
 * SQLite から全 bookmark 行を読み出し `ExportedJson` を組み立てる (副作用なし)。
 * 主にテスト用 — ファイル書き出しは `exportBookmarksJson()` 側。
 */
export function buildExportPayload(options: ExportOptions = {}): ExportedJson {
  const baseFolder = options.baseFolder ?? getXBookmarksBaseFolder();
  const db = options.db ?? getDb();
  // XBookmarksDb 内側の Database 参照は private なので、bookmarks を直接読むための
  // SQL は持たない。Phase 1 では既存 helper 経由で getKnownTweetIds() しか無いので
  // ここで内部 db を露出するアクセサを使わずに済むよう、`listBookmarksForExport()` を
  // x_bookmarks_db.ts に追加して呼び出す (このモジュールは buildExportPayload に集中)。
  const rows = db.listBookmarksForExport() as RawRow[];
  const exported: ExportedBookmarkRow[] = rows.map(r => ({
    tweet_id: r.tweet_id,
    url: r.url,
    author: r.author,
    tweet_text: r.tweet_text,
    note_tweet_text: r.note_tweet_text,
    created_at: r.created_at,
    saved_at: r.saved_at,
    engagement_likes: r.engagement_likes,
    engagement_retweets: r.engagement_retweets,
    engagement_replies: r.engagement_replies,
    x_folder_name: r.x_folder_name,
    vault_path: r.vault_path,
    group: deriveGroup(r.vault_path, baseFolder),
    ai_summary: null,
  }));
  return {
    version: 1,
    generated_at: new Date().toISOString(),
    base_folder: baseFolder,
    rows: exported,
  };
}

/**
 * `<vault>/<base>/.x_bookmarks.json` を atomic に書き出す。
 * Dataview から読まれる最中のクラッシュで JSON が壊れないよう
 * `<file>.tmp` → rename で原子的に置き換える。
 *
 * `payload` を渡せば DB 再読み込みを省略できる (sync 末尾で group page 更新と共有)。
 */
export function exportBookmarksJson(
  options: ExportOptions & { payload?: ExportedJson } = {}
): string {
  const vaultRoot = options.vaultRoot ?? getVaultRoot();
  const baseFolder = options.baseFolder ?? getXBookmarksBaseFolder();
  const payload = options.payload ?? buildExportPayload({ ...options, baseFolder });

  const dir = path.join(vaultRoot, baseFolder);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const outPath = path.join(dir, X_JSON_FILENAME);
  const tmpPath = outPath + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), 'utf8');
  fs.renameSync(tmpPath, outPath);
  return outPath;
}
