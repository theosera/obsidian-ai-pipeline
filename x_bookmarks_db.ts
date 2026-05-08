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
  note_tweet_text: string | null;
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
  /** X Premium 長文ツイート全文 (note_tweet.text)。truncated でない方。 */
  noteTweetText?: string;
  createdAt?: string;
  xFolderName?: string;
  vaultPath?: string;
  /** 当ブックマークが属する X folder の session_id (Vault 移動追跡用) */
  sessionId?: string;
  engagementLikes?: number;
  engagementRetweets?: number;
  engagementReplies?: number;
}

export type SessionStatus = 'active' | 'orphaned_on_x' | 'orphaned_on_vault' | 'archived';

export interface FolderSessionRow {
  session_id: string;
  x_folder_id: string | null;
  x_folder_name: string | null;
  vault_path: string | null;
  parent_keyword: string | null;
  status: SessionStatus;
  created_at: string;
  last_synced_at: string;
}

export interface FolderSessionUpsert {
  sessionId: string;
  xFolderId?: string | null;
  xFolderName?: string | null;
  vaultPath?: string | null;
  parentKeyword?: string | null;
  status?: SessionStatus;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS bookmarks (
  tweet_id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  author TEXT,
  tweet_text TEXT,
  note_tweet_text TEXT,
  created_at TEXT,
  x_folder_name TEXT,
  vault_path TEXT,
  session_id TEXT,
  saved_at TEXT NOT NULL,
  engagement_likes INTEGER,
  engagement_retweets INTEGER,
  engagement_replies INTEGER
);
CREATE INDEX IF NOT EXISTS idx_folder ON bookmarks(x_folder_name);
CREATE INDEX IF NOT EXISTS idx_saved_at ON bookmarks(saved_at);
-- NOTE: idx_session は migrateAddSessionId() 内で作成する。SCHEMA に書くと
-- 旧 DB (session_id 列なし) を開いた瞬間 "no such column" で throw → getDb() の
-- catch が DB を corrupted 退避 → ユーザーのキャッシュ消失 という致命バグになる。
-- column 追加が確実に終わってから index を張ること。

CREATE TABLE IF NOT EXISTS folder_sessions (
  session_id TEXT PRIMARY KEY,
  x_folder_id TEXT UNIQUE,
  x_folder_name TEXT,
  vault_path TEXT,
  parent_keyword TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  last_synced_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_xfolder ON folder_sessions(x_folder_id);
CREATE INDEX IF NOT EXISTS idx_session_vault ON folder_sessions(vault_path);
CREATE INDEX IF NOT EXISTS idx_session_status ON folder_sessions(status);
`;

export class XBookmarksDb {
  private db: Database.Database;

  constructor(filePath: string) {
    this.db = new Database(filePath);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(SCHEMA);
    this.migrateAddNoteTweetText();
    this.migrateAddSessionId();
  }

  /**
   * 既存 DB に `note_tweet_text` カラムが無ければ idempotent に追加する。
   * better-sqlite3 の `ALTER TABLE ADD COLUMN` は非破壊で既存行は NULL になる。
   */
  private migrateAddNoteTweetText(): void {
    const cols = this.db.prepare("PRAGMA table_info(bookmarks)").all() as { name: string }[];
    if (!cols.some(c => c.name === 'note_tweet_text')) {
      this.db.exec("ALTER TABLE bookmarks ADD COLUMN note_tweet_text TEXT");
    }
  }

  /**
   * bookmarks テーブルに session_id 列を idempotent に追加 (folder_sessions 連携用)。
   * index は **column 追加後**に必ず作る (旧 DB を壊さないため SCHEMA からは外してある)。
   */
  private migrateAddSessionId(): void {
    const cols = this.db.prepare("PRAGMA table_info(bookmarks)").all() as { name: string }[];
    if (!cols.some(c => c.name === 'session_id')) {
      this.db.exec("ALTER TABLE bookmarks ADD COLUMN session_id TEXT");
    }
    // column が確実に存在する状態で index を作成 (idempotent)
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_session ON bookmarks(session_id)");
  }

  getKnownTweetIds(): Set<string> {
    const rows = this.db.prepare('SELECT tweet_id FROM bookmarks').all() as { tweet_id: string }[];
    return new Set(rows.map(r => r.tweet_id));
  }

  upsertBookmark(input: BookmarkUpsertInput): void {
    const stmt = this.db.prepare(`
      INSERT INTO bookmarks (
        tweet_id, url, author, tweet_text, note_tweet_text, created_at,
        x_folder_name, vault_path, session_id, saved_at,
        engagement_likes, engagement_retweets, engagement_replies
      ) VALUES (
        @tweet_id, @url, @author, @tweet_text, @note_tweet_text, @created_at,
        @x_folder_name, @vault_path, @session_id, @saved_at,
        @engagement_likes, @engagement_retweets, @engagement_replies
      )
      ON CONFLICT(tweet_id) DO UPDATE SET
        url = excluded.url,
        author = excluded.author,
        tweet_text = excluded.tweet_text,
        note_tweet_text = excluded.note_tweet_text,
        created_at = excluded.created_at,
        x_folder_name = excluded.x_folder_name,
        vault_path = excluded.vault_path,
        session_id = excluded.session_id,
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
      note_tweet_text: input.noteTweetText ?? null,
      created_at: input.createdAt ?? null,
      x_folder_name: input.xFolderName ?? null,
      vault_path: input.vaultPath ?? null,
      session_id: input.sessionId ?? null,
      saved_at: new Date().toISOString(),
      engagement_likes: input.engagementLikes ?? null,
      engagement_retweets: input.engagementRetweets ?? null,
      engagement_replies: input.engagementReplies ?? null,
    });
  }

  // -----------------------------------------------------------------------
  // folder_sessions CRUD
  // -----------------------------------------------------------------------

  upsertFolderSession(input: FolderSessionUpsert): void {
    const now = new Date().toISOString();
    const existing = this.db
      .prepare('SELECT created_at FROM folder_sessions WHERE session_id = ?')
      .get(input.sessionId) as { created_at: string } | undefined;
    const stmt = this.db.prepare(`
      INSERT INTO folder_sessions (
        session_id, x_folder_id, x_folder_name, vault_path, parent_keyword,
        status, created_at, last_synced_at
      ) VALUES (
        @session_id, @x_folder_id, @x_folder_name, @vault_path, @parent_keyword,
        @status, @created_at, @last_synced_at
      )
      ON CONFLICT(session_id) DO UPDATE SET
        x_folder_id = excluded.x_folder_id,
        x_folder_name = excluded.x_folder_name,
        vault_path = excluded.vault_path,
        parent_keyword = excluded.parent_keyword,
        status = excluded.status,
        last_synced_at = excluded.last_synced_at
    `);
    stmt.run({
      session_id: input.sessionId,
      x_folder_id: input.xFolderId ?? null,
      x_folder_name: input.xFolderName ?? null,
      vault_path: input.vaultPath ?? null,
      parent_keyword: input.parentKeyword ?? null,
      status: input.status ?? 'active',
      created_at: existing?.created_at ?? now,
      last_synced_at: now,
    });
  }

  getFolderSessionByXFolderId(xFolderId: string): FolderSessionRow | undefined {
    return this.db
      .prepare('SELECT * FROM folder_sessions WHERE x_folder_id = ?')
      .get(xFolderId) as FolderSessionRow | undefined;
  }

  getFolderSession(sessionId: string): FolderSessionRow | undefined {
    return this.db
      .prepare('SELECT * FROM folder_sessions WHERE session_id = ?')
      .get(sessionId) as FolderSessionRow | undefined;
  }

  listFolderSessions(): FolderSessionRow[] {
    return this.db
      .prepare('SELECT * FROM folder_sessions ORDER BY created_at ASC')
      .all() as FolderSessionRow[];
  }

  setSessionStatus(sessionId: string, status: SessionStatus): void {
    this.db
      .prepare('UPDATE folder_sessions SET status = ?, last_synced_at = ? WHERE session_id = ?')
      .run(status, new Date().toISOString(), sessionId);
  }

  deleteFolderSession(sessionId: string): void {
    this.db.prepare('DELETE FROM folder_sessions WHERE session_id = ?').run(sessionId);
  }

  /**
   * .md ファイル移動検知時の再 bind 用 (sync phase から呼ばれる)。
   * SQL を DB モジュール内に閉じ込めるための typed wrapper。
   * `xFolderName` を渡すと `x_folder_name` も同時に更新する (stale 名前回避)。
   */
  reassignBookmarkSession(input: {
    tweetId: string;
    sessionId: string;
    vaultPath: string;
    xFolderName?: string | null;
  }): void {
    this.db
      .prepare(
        'UPDATE bookmarks SET session_id = ?, vault_path = ?, ' +
          'x_folder_name = COALESCE(?, x_folder_name) WHERE tweet_id = ?'
      )
      .run(input.sessionId, input.vaultPath, input.xFolderName ?? null, input.tweetId);
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
