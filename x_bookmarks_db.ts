/**
 * X ブックマーク用 SQLite メタデータキャッシュ。
 *
 * 設計思想:
 *   - .md ファイル (Vault) が source of truth。本 DB は派生データ。
 *   - 用途: 重複検出 O(1)、差分スクレイプ、フォルダ件数モニタリング (Phase 2 用基盤)
 *   - 壊れたら .md から再構築可能 (rebuildFromVault は Phase 2 で実装)
 *
 * ファイル配置:
 *   <vault>/__skills/pipeline/x_bookmarks.db   ← .gitignore 対象 (個人データ)
 *
 * テストでは createDb(':memory:') で in-memory DB を生成しネットワーク不要。
 */

import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { getVaultRoot } from './config';

export interface BookmarkRow {
  tweet_id: string;
  url: string;
  author: string | null;
  tweet_text: string | null;
  created_at: string | null;
  x_folder_name: string | null;
  vault_path: string | null;
  saved_at: string;
  engagement_likes: number | null;
  engagement_retweets: number | null;
  engagement_replies: number | null;
}

export interface BookmarkUpsertInput {
  tweetId: string;
  url: string;
  author?: string;
  tweetText?: string;
  createdAt?: string;
  xFolderName?: string;
  vaultPath?: string;
  engagementLikes?: number;
  engagementRetweets?: number;
  engagementReplies?: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS bookmarks (
  tweet_id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  author TEXT,
  tweet_text TEXT,
  created_at TEXT,
  x_folder_name TEXT,
  vault_path TEXT,
  saved_at TEXT NOT NULL,
  engagement_likes INTEGER,
  engagement_retweets INTEGER,
  engagement_replies INTEGER
);
CREATE INDEX IF NOT EXISTS idx_folder ON bookmarks(x_folder_name);
CREATE INDEX IF NOT EXISTS idx_saved_at ON bookmarks(saved_at);
`;

export class XBookmarksDb {
  private db: Database.Database;

  constructor(filePath: string) {
    this.db = new Database(filePath);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(SCHEMA);
  }

  getKnownTweetIds(): Set<string> {
    const rows = this.db.prepare('SELECT tweet_id FROM bookmarks').all() as { tweet_id: string }[];
    return new Set(rows.map(r => r.tweet_id));
  }

  upsertBookmark(input: BookmarkUpsertInput): void {
    const stmt = this.db.prepare(`
      INSERT INTO bookmarks (
        tweet_id, url, author, tweet_text, created_at,
        x_folder_name, vault_path, saved_at,
        engagement_likes, engagement_retweets, engagement_replies
      ) VALUES (
        @tweet_id, @url, @author, @tweet_text, @created_at,
        @x_folder_name, @vault_path, @saved_at,
        @engagement_likes, @engagement_retweets, @engagement_replies
      )
      ON CONFLICT(tweet_id) DO UPDATE SET
        url = excluded.url,
        author = excluded.author,
        tweet_text = excluded.tweet_text,
        created_at = excluded.created_at,
        x_folder_name = excluded.x_folder_name,
        vault_path = excluded.vault_path,
        saved_at = excluded.saved_at,
        engagement_likes = excluded.engagement_likes,
        engagement_retweets = excluded.engagement_retweets,
        engagement_replies = excluded.engagement_replies
    `);
    stmt.run({
      tweet_id: input.tweetId,
      url: input.url,
      author: input.author ?? null,
      tweet_text: input.tweetText ?? null,
      created_at: input.createdAt ?? null,
      x_folder_name: input.xFolderName ?? null,
      vault_path: input.vaultPath ?? null,
      saved_at: new Date().toISOString(),
      engagement_likes: input.engagementLikes ?? null,
      engagement_retweets: input.engagementRetweets ?? null,
      engagement_replies: input.engagementReplies ?? null,
    });
  }

  getFolderCounts(): { folder: string; count: number }[] {
    const rows = this.db.prepare(`
      SELECT x_folder_name AS folder, COUNT(*) AS count
      FROM bookmarks
      WHERE x_folder_name IS NOT NULL
      GROUP BY x_folder_name
      ORDER BY count DESC
    `).all() as { folder: string; count: number }[];
    return rows;
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM bookmarks').get() as { n: number };
    return row.n;
  }

  close(): void {
    this.db.close();
  }
}

let _instance: XBookmarksDb | null = null;

function getDbPath(): string {
  const dir = path.join(getVaultRoot(), '__skills', 'pipeline');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, 'x_bookmarks.db');
}

export function getDb(): XBookmarksDb {
  if (_instance) return _instance;
  const filePath = getDbPath();
  try {
    _instance = new XBookmarksDb(filePath);
  } catch (e: any) {
    // DB 破損時は別名退避して空 DB で続行 (.md から手動再構築)
    if (fs.existsSync(filePath)) {
      const backup = filePath + '.corrupted_' + Date.now();
      fs.renameSync(filePath, backup);
      console.warn(`⚠️  x_bookmarks.db が破損していました。${backup} に退避し新規作成します。`);
      _instance = new XBookmarksDb(filePath);
    } else {
      throw e;
    }
  }
  return _instance;
}

export function closeDb(): void {
  if (_instance) {
    _instance.close();
    _instance = null;
  }
}
