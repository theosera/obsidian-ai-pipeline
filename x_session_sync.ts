/**
 * X folder ↔ Vault folder の Sync Phase。
 *
 * 各 X-bookmark コマンド (--x-pick / --x-bookmarks) の先頭で必ず走る (--no-sync で抑止可)。
 *
 * 3 軸の drift を検出:
 *
 *   軸 X→DB:  X 側に新規 folder         → UUID 発行 + marker 作成 (active)
 *             X 側で folder 削除          → orphan_on_x → AI 判定ループへ (handler 注入)
 *
 *   軸 Vault→DB: Vault マーカー発見 / DB 未登録 → marker.session_id を尊重して登録
 *               DB 登録あり / 実体ディレクトリ無し → orphan_on_vault マーク
 *               実体は別パスに移動 → DB.vault_path 更新
 *
 *   軸 .md→folder: .md frontmatter session_id ≠ 親フォルダ marker
 *                 → 「.md がユーザーにより別フォルダへ移動された」とみなし、
 *                    .md の DB row を新親フォルダ session に再 bind
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot } from './config';
import { getDb, FolderSessionRow } from './x_bookmarks_db';
import {
  walkSessionMarkers,
  writeSessionMarker,
  readSessionMarker,
  newSessionId,
  markerFilename,
} from './x_session_registry';
import { listFolders, FolderListing } from './x_bookmarks_api';
import {
  loadForcedParents,
  loadApprovedMappings,
  mapFolderToVaultPath,
} from './x_folder_mapper';

export interface OrphanOnX {
  session: FolderSessionRow;
  vaultAbsoluteDir: string;
  mdCount: number;
  latestPostDate: string | null;
}

export type OrphanResolution = 'keep' | 'archive' | 'skip';

export interface OrphanResolver {
  /** orphan ごとに呼ばれる。AI 判定 + ユーザー確認を担当 (sync.ts は判断しない) */
  resolveOrphan(orphan: OrphanOnX): Promise<OrphanResolution>;
}

export interface SyncResult {
  newSessions: number;
  updatedSessions: number;
  vaultMoves: number;
  fileReassignments: number;
  orphansOnX: number;
  orphansOnVault: number;
}

/**
 * Sync Phase 本体。
 *
 * @param baseFolder  X bookmarks の Vault root (相対) 例: "Clippings/X-Bookmarks-claude"
 * @param resolver    orphan_on_x 検出時の判断を委譲するハンドラ (AI + 対話)
 *                    省略時は orphan を status='orphaned_on_x' に更新するだけで何もしない
 * @param fetchFolderListing  X API を叩く関数 (テストで mock 可)。省略時は listFolders()
 */
export async function runSyncPhase(args: {
  baseFolder: string;
  resolver?: OrphanResolver;
  fetchFolderListing?: () => Promise<FolderListing>;
}): Promise<SyncResult> {
  const db = getDb();
  const vaultRoot = getVaultRoot();
  const baseAbs = path.join(vaultRoot, args.baseFolder);

  const result: SyncResult = {
    newSessions: 0,
    updatedSessions: 0,
    vaultMoves: 0,
    fileReassignments: 0,
    orphansOnX: 0,
    orphansOnVault: 0,
  };

  // === Step 1: Vault 側を走査して現状を把握 ===
  const markers = walkSessionMarkers(baseAbs); // [{absoluteDir, vaultRelative, marker}]
  const markerByXFolderId = new Map<string, typeof markers[number]>();
  const markerBySessionId = new Map<string, typeof markers[number]>();
  for (const m of markers) {
    if (m.marker.x_folder_id) markerByXFolderId.set(m.marker.x_folder_id, m);
    markerBySessionId.set(m.marker.session_id, m);
  }

  // === Step 2: X API でフォルダ一覧を取得 ===
  const fetchListing = args.fetchFolderListing ?? listFolders;
  let listing: FolderListing;
  try {
    listing = await fetchListing();
  } catch (e: any) {
    console.warn(`⚠️  [sync] X API folder list 取得失敗: ${e.message} (sync skip)`);
    return result;
  }
  const xFolderIds = new Set(listing.folders.map(f => f.id));

  // === Step 3: X→DB 軸 (新規 + 既存更新) ===
  const allFolderNames = listing.folders.map(f => f.name);
  const forcedParents = loadForcedParents();
  const approvedMap = loadApprovedMappings();

  for (const folder of listing.folders) {
    const existing = db.getFolderSessionByXFolderId(folder.id);
    const vaultRel = path.posix.join(
      args.baseFolder,
      mapFolderToVaultPath(folder.name, forcedParents, approvedMap, { allFolderNames })
    );

    if (!existing) {
      // 新規: 既存の marker を探して再利用 (例: ユーザーが手動で marker をコピーした場合)
      const reusable = markerByXFolderId.get(folder.id);
      const sessionId = reusable?.marker.session_id ?? newSessionId();
      const finalVault = reusable?.vaultRelative ?? vaultRel;
      db.upsertFolderSession({
        sessionId,
        xFolderId: folder.id,
        xFolderName: folder.name,
        vaultPath: finalVault,
        status: 'active',
      });
      writeSessionMarker(path.join(vaultRoot, finalVault), {
        session_id: sessionId,
        x_folder_id: folder.id,
        x_folder_name: folder.name,
        created_at: db.getFolderSession(sessionId)!.created_at,
        last_synced_at: new Date().toISOString(),
      });
      result.newSessions++;
    } else {
      // 既存: vault_path 整合チェック (Vault 移動検知)
      const markerForSession = markerBySessionId.get(existing.session_id);
      let updatedVaultPath = existing.vault_path;
      if (markerForSession && markerForSession.vaultRelative !== existing.vault_path) {
        updatedVaultPath = markerForSession.vaultRelative;
        result.vaultMoves++;
      } else if (!markerForSession) {
        // marker 欠落: 期待 path に書き出す (Vault 側を再生成)
        writeSessionMarker(path.join(vaultRoot, existing.vault_path ?? vaultRel), {
          session_id: existing.session_id,
          x_folder_id: folder.id,
          x_folder_name: folder.name,
          created_at: existing.created_at,
          last_synced_at: new Date().toISOString(),
        });
      }
      db.upsertFolderSession({
        sessionId: existing.session_id,
        xFolderId: folder.id,
        xFolderName: folder.name,
        vaultPath: updatedVaultPath,
        parentKeyword: existing.parent_keyword,
        status: existing.status === 'orphaned_on_x' ? 'active' : existing.status,
      });
      result.updatedSessions++;
    }
  }

  // === Step 4: X 側で削除されたフォルダの検出 (orphan_on_x) ===
  const allSessions = db.listFolderSessions();
  for (const s of allSessions) {
    if (!s.x_folder_id) continue;
    if (xFolderIds.has(s.x_folder_id)) continue;
    if (s.status === 'archived') continue;
    // X 側に無いがまだ active or unknown: orphan として処理
    const vaultAbs = s.vault_path ? path.join(vaultRoot, s.vault_path) : null;
    const mdCount = vaultAbs && fs.existsSync(vaultAbs) ? countMdFiles(vaultAbs) : 0;
    const latestPostDate = vaultAbs && fs.existsSync(vaultAbs)
      ? findLatestPostDate(vaultAbs)
      : null;
    const orphan: OrphanOnX = {
      session: s,
      vaultAbsoluteDir: vaultAbs ?? '',
      mdCount,
      latestPostDate,
    };
    result.orphansOnX++;
    if (args.resolver) {
      const decision = await args.resolver.resolveOrphan(orphan);
      applyOrphanDecision(s, decision, baseAbs);
    } else {
      db.setSessionStatus(s.session_id, 'orphaned_on_x');
    }
  }

  // === Step 5: Vault 側で実体が無いセッション (orphan_on_vault) ===
  for (const s of db.listFolderSessions()) {
    if (s.status !== 'active') continue;
    if (!s.vault_path) continue;
    const abs = path.join(vaultRoot, s.vault_path);
    if (!fs.existsSync(abs)) {
      db.setSessionStatus(s.session_id, 'orphaned_on_vault');
      result.orphansOnVault++;
    }
  }

  // === Step 6: .md frontmatter 軸 (ファイル単位移動の追跡) ===
  result.fileReassignments = reassignMisplacedFiles(baseAbs);

  return result;
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function countMdFiles(dir: string): number {
  let n = 0;
  const stack: string[] = [dir];
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

function findLatestPostDate(dir: string): string | null {
  let latest: string | null = null;
  const stack: string[] = [dir];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(full);
      else if (e.isFile() && e.name.endsWith('.md')) {
        const stat = fs.statSync(full);
        const iso = stat.mtime.toISOString();
        if (!latest || iso > latest) latest = iso;
      }
    }
  }
  return latest;
}

function applyOrphanDecision(
  session: FolderSessionRow,
  decision: OrphanResolution,
  baseAbs: string
): void {
  const db = getDb();
  if (decision === 'keep') {
    db.setSessionStatus(session.session_id, 'orphaned_on_x');
    return;
  }
  if (decision === 'archive') {
    // Codex review P2: archive 移動が実際に成功したときだけ status='archived' に
    // するのが正しい。失敗時 (権限 / 既存先 / I/O 例外) は DB が嘘をつかないよう
    // 'orphaned_on_x' のままにし、次回 sync で再度ユーザーに判断させる。
    let archived = false;
    if (session.vault_path) {
      const src = path.join(getVaultRoot(), session.vault_path);
      const archiveDir = path.join(baseAbs, '_archived', session.session_id);
      if (!fs.existsSync(src)) {
        // Vault 側にそもそも実体が無い → archive する対象が無い
        // (orphaned_on_vault に近い状態)。status は archived 扱いで OK。
        archived = true;
      } else if (fs.existsSync(archiveDir)) {
        console.warn(
          `⚠️  [sync] archive 先 ${archiveDir} が既に存在するため archive をスキップ ` +
          `(${session.session_id})。status は orphaned_on_x のまま、次回再判定。`
        );
      } else {
        try {
          fs.mkdirSync(path.dirname(archiveDir), { recursive: true });
          fs.renameSync(src, archiveDir);
          archived = true;
        } catch (e: any) {
          console.warn(`⚠️  [sync] archive 失敗 (${session.session_id}): ${e.message}`);
        }
      }
    } else {
      // vault_path 不明 → archive 不可能。orphaned_on_x にしておく。
    }
    db.setSessionStatus(session.session_id, archived ? 'archived' : 'orphaned_on_x');
    return;
  }
  // 'skip' は何もしない (次回再判定)
}

/**
 * .md frontmatter の session_id を読んで、現在の親フォルダの marker.session_id と
 * 食い違う場合 = ユーザーが Obsidian でファイルを別フォルダに移動した、と判断し
 * DB の bookmarks.session_id を新親フォルダ session に書き換える。
 *
 * 戻り値: 再 bind 件数。
 */
function reassignMisplacedFiles(baseAbs: string): number {
  const db = getDb();
  const vaultRoot = getVaultRoot();
  let count = 0;
  if (!fs.existsSync(baseAbs)) return 0;

  const stack: string[] = [baseAbs];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!e.isFile() || !e.name.endsWith('.md')) continue;

      const fileSession = readMdSessionId(full);
      if (!fileSession) continue;
      // 親フォルダの marker
      const parentMarker = readSessionMarker(cur);
      if (!parentMarker) continue;
      if (parentMarker.session_id === fileSession) continue;

      // 食い違い: bookmarks 行を更新
      const tweetId = readMdTweetId(full);
      if (!tweetId) continue;
      const stmt = (db as any).db.prepare(
        'UPDATE bookmarks SET session_id = ?, vault_path = ? WHERE tweet_id = ?'
      );
      stmt.run(parentMarker.session_id, path.relative(vaultRoot, full), tweetId);
      // .md frontmatter も新 session_id に書き換える (idempotent)
      rewriteMdSessionId(full, parentMarker.session_id);
      count++;
    }
  }
  return count;
}

function readMdSessionId(file: string): string | null {
  try {
    const head = fs.readFileSync(file, 'utf8').slice(0, 4096);
    const m = head.match(/^session_id:\s*"?([0-9a-fA-F-]+)"?\s*$/m);
    return m?.[1] ?? null;
  } catch { return null; }
}

function readMdTweetId(file: string): string | null {
  try {
    const head = fs.readFileSync(file, 'utf8').slice(0, 4096);
    // tweet_id: "12345" or post_id: "12345"
    const m = head.match(/^(?:post_id|tweet_id|x_tweet_id):\s*"?(\d+)"?\s*$/m);
    return m?.[1] ?? null;
  } catch { return null; }
}

function rewriteMdSessionId(file: string, sessionId: string): void {
  try {
    const content = fs.readFileSync(file, 'utf8');
    const replaced = content.replace(
      /^session_id:\s*"?[0-9a-fA-F-]+"?\s*$/m,
      `session_id: "${sessionId}"`
    );
    if (replaced !== content) fs.writeFileSync(file, replaced, 'utf8');
  } catch {
    // 失敗してもパイプラインは止めない (ログのみ)
  }
}

// re-export for tests
export const __test = {
  countMdFiles,
  findLatestPostDate,
  reassignMisplacedFiles,
  readMdSessionId,
  readMdTweetId,
};
