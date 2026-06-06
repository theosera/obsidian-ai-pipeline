/**
 * X フォルダ session_id レジストリ。
 *
 * X 側 folder ID と Vault フォルダ実体の永続的な紐付けを担当する。
 * 3 層で保持:
 *   1. SQLite (`folder_sessions` テーブル) — canonical
 *   2. Vault folder marker `_session.json` — Vault 移動追跡用
 *   3. .md frontmatter `session_id` — ファイル単位の出自追跡用
 *
 * Session_id は UUID v4。X 側 folder ID とは独立したライフサイクルを持ち、
 * X 側で folder が削除/再作成されても Vault 側の history を保つ。
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { getVaultRoot } from '../config';
import { getDb, FolderSessionRow, SessionStatus } from './db';

export interface SessionMarker {
  session_id: string;
  x_folder_id: string | null;
  x_folder_name: string | null;
  /** マーカー作成時刻 (ISO 8601) */
  created_at: string;
  /** 最終 sync 時刻 (ISO 8601)。Vault 移動検知の参考値 */
  last_synced_at: string;
}

const MARKER_FILENAME = '_session.json';

export function newSessionId(): string {
  return crypto.randomUUID();
}

export function markerFilename(): string {
  return MARKER_FILENAME;
}

/**
 * 指定フォルダに session marker を書き出す (idempotent)。
 * 既存マーカーがあれば session_id は維持し metadata だけ更新する。
 */
export function writeSessionMarker(
  vaultAbsoluteDir: string,
  marker: SessionMarker
): void {
  if (!fs.existsSync(vaultAbsoluteDir)) {
    fs.mkdirSync(vaultAbsoluteDir, { recursive: true });
  }
  const file = path.join(vaultAbsoluteDir, MARKER_FILENAME);
  // 既存ファイルから session_id を維持して上書き失敗を防ぐ
  let preservedId = marker.session_id;
  if (fs.existsSync(file)) {
    try {
      const existing = JSON.parse(fs.readFileSync(file, 'utf8')) as SessionMarker;
      if (existing.session_id) preservedId = existing.session_id;
    } catch {
      // 壊れたマーカーは新規上書き
    }
  }
  fs.writeFileSync(
    file,
    JSON.stringify({ ...marker, session_id: preservedId }, null, 2),
    'utf8'
  );
}

export function readSessionMarker(vaultAbsoluteDir: string): SessionMarker | null {
  const file = path.join(vaultAbsoluteDir, MARKER_FILENAME);
  if (!fs.existsSync(file)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (typeof parsed?.session_id !== 'string') return null;
    return parsed as SessionMarker;
  } catch {
    return null;
  }
}

/**
 * Vault 配下のあるルートディレクトリを再帰走査して、見つかった全
 * `_session.json` を収集する。
 *
 * 戻り値: { absoluteDir, marker, vaultRelative }
 */
export function walkSessionMarkers(rootAbsoluteDir: string): Array<{
  absoluteDir: string;
  vaultRelative: string;
  marker: SessionMarker;
}> {
  if (!fs.existsSync(rootAbsoluteDir)) return [];
  const vaultRoot = getVaultRoot();
  const out: Array<{ absoluteDir: string; vaultRelative: string; marker: SessionMarker }> = [];
  const stack: string[] = [rootAbsoluteDir];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(full);
      } else if (e.isFile() && e.name === MARKER_FILENAME) {
        const marker = readSessionMarker(dir);
        if (marker) {
          out.push({
            absoluteDir: dir,
            vaultRelative: path.relative(vaultRoot, dir),
            marker,
          });
        }
      }
    }
  }
  return out;
}

/**
 * X folder ID から既存 session を取得。なければ新規発行して DB と marker を作る。
 *
 * @param xFolderId  X 側 folder ID
 * @param xFolderName  X 側 folder 表示名 (最新観測)
 * @param vaultRelativePath  Vault 相対パス (e.g., "Clippings/X-Bookmarks-claude/Claude Code/Tips")
 * @param parentKeyword  Tier 1 マッチ時のキーワード (なければ undefined)
 */
export function getOrCreateSession(args: {
  xFolderId: string;
  xFolderName: string;
  vaultRelativePath: string;
  parentKeyword?: string;
}): FolderSessionRow {
  const db = getDb();
  let row = db.getFolderSessionByXFolderId(args.xFolderId);
  if (!row) {
    const sessionId = newSessionId();
    db.upsertFolderSession({
      sessionId,
      xFolderId: args.xFolderId,
      xFolderName: args.xFolderName,
      vaultPath: args.vaultRelativePath,
      parentKeyword: args.parentKeyword ?? null,
      status: 'active',
    });
    row = db.getFolderSession(sessionId)!;
  } else {
    // metadata 同期 (status は触らない — sync phase 側で判定)
    db.upsertFolderSession({
      sessionId: row.session_id,
      xFolderId: args.xFolderId,
      xFolderName: args.xFolderName,
      vaultPath: args.vaultRelativePath,
      parentKeyword: args.parentKeyword ?? row.parent_keyword,
      status: row.status,
    });
    row = db.getFolderSession(row.session_id)!;
  }
  // marker は absolute path で書く
  const absoluteDir = path.join(getVaultRoot(), args.vaultRelativePath);
  writeSessionMarker(absoluteDir, {
    session_id: row.session_id,
    x_folder_id: args.xFolderId,
    x_folder_name: args.xFolderName,
    created_at: row.created_at,
    last_synced_at: new Date().toISOString(),
  });
  return row;
}

/**
 * session_id → 現在の vault 相対パス。
 * DB を信頼するが、marker / .md frontmatter から拾った最新情報があれば
 * そちらを優先したい場合は呼出し側で db.upsertFolderSession() してから呼ぶこと。
 */
export function lookupVaultPath(sessionId: string): string | null {
  const row = getDb().getFolderSession(sessionId);
  return row?.vault_path ?? null;
}

export function setStatus(sessionId: string, status: SessionStatus): void {
  getDb().setSessionStatus(sessionId, status);
}
