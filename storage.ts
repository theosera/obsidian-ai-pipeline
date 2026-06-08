import fs from 'fs';
import path from 'path';
import { ArticleData } from './types';
import { getVaultRoot, isDryRun } from './config';

const FALLBACK_PATH = 'Clippings/Inbox';

/**
 * `resolveVaultPath` の判定結果 (discriminated union)。
 *
 * 7 フェーズ防御を通過したら絶対/相対パスを、違反したら**機械可読な理由**を返す。
 * `ensureSafePath` (フォールバック型) と Tool Use 実行レイヤー (strict 型) の
 * 両方がこの 1 関数を唯一の真実として共有する。
 */
export type VaultPathResult =
  | { ok: true; safeRelative: string; absolute: string }
  | { ok: false; reason: string };

/**
 * パストラバーサル防止の **strict 版**: resolved パスが VAULT_ROOT 配下である
 * ことを 7 フェーズで保証し、違反時は **フォールバックせず** `{ ok: false }` を返す。
 *
 * 防御フェーズ:
 *   0. URL デコード（%2e%2e 等のエンコード済みトラバーサル対策）
 *   1. 絶対パス拒否（/, ~, ドライブレター）
 *   2. nullバイト・制御文字の除去
 *   3. Unicode NFC 正規化（macOS NFD 差異による迂回防止）
 *   4. パスセグメント検証（.. を検出したら即座に拒否）
 *   5. resolve 後のプレフィックス検証
 *   6. 既存パスの場合 realpath(symlink解決済み)でも検証
 *   7. パス長制限
 *
 * `ensureSafePath` はこの結果を安全なフォールバックパスにマップする薄いラッパで、
 * 7 フェーズ判定の single source of truth は本関数。Tool Use 実行レイヤーは
 * 「Inbox へ無言クランプ」が誤動作になる (モデルが要求したパスを黙って書き換えて
 * しまう) ため strict 版を直接使い、違反を人間に提示して拒否する。
 */
export function resolveVaultPath(proposedRelative: string): VaultPathResult {
  if (!proposedRelative || typeof proposedRelative !== 'string') {
    return { ok: false, reason: 'empty-or-non-string-path' };
  }

  const vaultRoot = getVaultRoot();

  // Phase 0: URLデコード（%2e%2e などのエンコード済みトラバーサル対策）
  let decoded: string;
  try {
    decoded = decodeURIComponent(proposedRelative);
  } catch {
    decoded = proposedRelative;
  }

  // Phase 1: 絶対パス拒否
  if (/^[\/\\~]|^[a-zA-Z]:/.test(decoded)) {
    return { ok: false, reason: `absolute-path-rejected: "${proposedRelative}"` };
  }

  // Phase 2: nullバイト・制御文字の除去
  const noControl = decoded.replace(/[\x00-\x1f\x7f]/g, '');

  // Phase 3: Unicode NFC 正規化（macOS HFS+ は NFD を使うため、NFC/NFD 差異を統一）
  const normalized = noControl.normalize('NFC');

  // Phase 4: パスセグメント単位での検証
  const segments = normalized.split(/[\/\\]/);

  // ".." が含まれていれば即座に拒否（sanitize ではなく reject）
  if (segments.some(seg => seg === '..')) {
    return { ok: false, reason: `path-traversal-rejected (..): "${proposedRelative}"` };
  }

  // "." と空文字列はフィルタ（ドットファイル名 ".hidden" は通す）
  const sanitized = segments
    .filter(seg => seg !== '.' && seg !== '')
    .join(path.sep);

  if (!sanitized) {
    return { ok: false, reason: 'empty-after-sanitize' };
  }

  // Phase 5: resolve後のプレフィックス検証
  const resolved = path.resolve(vaultRoot, sanitized);
  if (!resolved.startsWith(vaultRoot + path.sep) && resolved !== vaultRoot) {
    return { ok: false, reason: `path-traversal-rejected (resolve): "${proposedRelative}" -> "${resolved}"` };
  }

  // Phase 6: 既存パスの場合、realpath(symlink解決済み)でも検証
  if (fs.existsSync(resolved)) {
    try {
      const real = fs.realpathSync(resolved);
      const realVault = fs.realpathSync(vaultRoot);
      if (!real.startsWith(realVault + path.sep) && real !== realVault) {
        return { ok: false, reason: `symlink-traversal-rejected: "${resolved}" -> realpath "${real}"` };
      }
    } catch {
      // realpathSync失敗は無視（パスが存在しない場合はPhase 5で十分）
    }
  }

  // Phase 7: パス長制限（極端に長いパスはOSレベルの問題を引き起こす）
  if (sanitized.length > 500) {
    return { ok: false, reason: `path-too-long (${sanitized.length} chars)` };
  }

  return { ok: true, safeRelative: sanitized, absolute: resolved };
}

/**
 * パストラバーサル防止 (フォールバック版): `resolveVaultPath` を通し、違反時は
 * 安全なフォールバックパス (`Clippings/Inbox`) を返す。AI 分類結果のパスのように
 * 「Vault 外なら Inbox に置けばよい」セマンティクスを持つ呼出側用。
 *
 * Tool Use のように「黙って書き換えると危険」な経路は `resolveVaultPath` を直接使う。
 */
export function ensureSafePath(proposedRelative: string): string {
  const result = resolveVaultPath(proposedRelative);
  if (result.ok) return result.safeRelative;
  // 空入力は元から silent fallback（過剰ログを避ける）。実トラバーサル等のみログ。
  if (!result.reason.startsWith('empty')) {
    console.error(`[Security] ${result.reason}`);
  }
  return FALLBACK_PATH;
}

/**
 * dry-run 対応のファイル移動。
 * isDryRun() が true の場合、ログ出力のみでファイルは移動しない。
 */
export function safeRename(src: string, dest: string): void {
  const vaultRoot = getVaultRoot();
  const relSrc = path.relative(vaultRoot, src);
  const relDest = path.relative(vaultRoot, dest);

  if (isDryRun()) {
    console.log(`  [DRY-RUN] ${relSrc} -> ${relDest}`);
    return;
  }
  fs.renameSync(src, dest);
}

export function checkFolderExists(folderPath: string): boolean {
  const safePath = ensureSafePath(folderPath);
  const fullPath = path.join(getVaultRoot(), safePath);
  return fs.existsSync(fullPath);
}

export function saveMarkdown(articleData: ArticleData, folderPath: string): string {
  const vaultRoot = getVaultRoot();
  const date = new Date();

  // パストラバーサル防止: AI出力パスを検証
  const finalPath = ensureSafePath(folderPath);

  const fullDirPath = path.join(vaultRoot, finalPath);

  if (!fs.existsSync(fullDirPath)) {
    fs.mkdirSync(fullDirPath, { recursive: true });
  }

  const today = date.toISOString().split('T')[0];

  let mm_dd = today.substring(5); // Default to today's MM-DD
  // Use frontmatter date logic if it matches YYYY-MM-DD
  const createdMatch = articleData.date?.match(/^\d{4}-(\d{2}-\d{2})$/);
  if (createdMatch) {
      mm_dd = createdMatch[1];
  }

  const safeTitle = (articleData.title || 'Untitled')
    .replace(/[\x00-\x1f\x7f]/g, '')       // 制御文字・ヌル文字を除去
    .replace(/[\/\\*?:""<>|／＼]/g, '')      // パス区切り文字（半角・全角）を除去
    .trim()
    .slice(0, 100);
  const baseName = `${safeTitle}_${mm_dd}`;
  let fileName = `${baseName}.md`;
  // ファイル名衝突時は連番サフィックス (_2, _3, …) を付与し、別記事の上書きを避ける。
  for (let seq = 2; seq < 1000 && fs.existsSync(path.join(fullDirPath, fileName)); seq++) {
    fileName = `${baseName}_${seq}.md`;
  }
  // 連番が上限に達した場合、最後の候補が空きとは限らないため再検証する。
  if (fs.existsSync(path.join(fullDirPath, fileName))) {
    throw new Error(`[Storage] ファイル名の空きが見つかりません: "${baseName}"`);
  }
  const filePath = path.join(fullDirPath, fileName);

  // 保存直前の最終防御: ensureSafePath / safeTitle で前段防御済みだが、
  // 書き込み座標で resolve + プレフィックス検証をもう一段噛ませる
  // (defense-in-depth)。ここで Vault 外を指していたら上流防御の破綻なので
  // フォールバックせず即座に throw する。
  const resolvedFilePath = path.resolve(filePath);
  if (!resolvedFilePath.startsWith(path.resolve(vaultRoot) + path.sep)) {
    throw new Error(`[Security] 保存先が Vault 外を指しています: "${resolvedFilePath}"`);
  }

  const pubDate = articleData.date || '';
  const siteLink = articleData.siteName ? `\n  - "[[${escapeFrontmatter(articleData.siteName)}]]"` : '';

  // X bookmark の場合だけ session_id 等の X 専用 frontmatter フィールドを書き出す。
  // ファイル単位移動の追跡 (sync phase の reassignMisplacedFiles) で必要。
  const ax = articleData as Partial<{
    xSessionId: string;
    xFolderId: string;
    xTweetId: string;
    xFolderName: string;
  }>;
  const xExtras: string[] = [];
  if (ax.xSessionId) xExtras.push(`session_id: "${escapeFrontmatter(ax.xSessionId)}"`);
  if (ax.xFolderId) xExtras.push(`x_folder_id: "${escapeFrontmatter(ax.xFolderId)}"`);
  if (ax.xTweetId) xExtras.push(`x_tweet_id: "${escapeFrontmatter(ax.xTweetId)}"`);
  if (ax.xFolderName) xExtras.push(`x_folder_name: "${escapeFrontmatter(ax.xFolderName)}"`);
  const xExtrasBlock = xExtras.length > 0 ? '\n' + xExtras.join('\n') : '';

  const frontmatter = `---
title: "${escapeFrontmatter(articleData.title || '')}"
source: "${articleData.url || ''}"
author:${siteLink}
published: ${pubDate}
created: ${today}
description: "${escapeFrontmatter(articleData.excerpt || '')}"
tags:
  - "clippings"${xExtrasBlock}
---

`;

  const body = frontmatter + (articleData.content || '');
  fs.writeFileSync(resolvedFilePath, body, 'utf8');
  // A2: 保存できた URL を dedup 集合へ即反映 (本番経路の更新口)。
  // 集合未初期化なら no-op (次回 getKnownUrls が全走査で構築する)。
  addKnownUrl(articleData.url);
  return resolvedFilePath;
}

export function escapeFrontmatter(str: string): string {
  if (!str) return '';
  return str
    .replace(/\\/g, '\\\\')          // バックスラッシュをエスケープ（先にやる）
    .replace(/"/g, '\\"')             // ダブルクォートをエスケープ
    .replace(/\n/g, ' ')              // 改行をスペースに変換（YAML構造破壊防止）
    .replace(/\r/g, '')               // CRを除去
    .replace(/---/g, '\\-\\-\\-');    // YAMLセパレータを無害化
}

let cachedFolders: string[] | null = null;

export function getVaultFolders(forceRefresh: boolean = false): string[] {
  if (cachedFolders && !forceRefresh) return cachedFolders;

  const vaultRoot = getVaultRoot();
  const folders: string[] = [];

  function scan(dirPath: string, relativePath: string = '', depth: number = 0): void {
    if (depth > 6) return; // limit depth to not scan too deep

    let entries;
    try {
      entries = fs.readdirSync(dirPath, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      // Skip hidden and date-based folders (YYYY-MM, YYYY-Qn)
      if (entry.name.startsWith('.') || entry.name.match(/^\d{4}-/)) continue;
      // Skip special skills folder
      if (entry.name === '__skills') continue;

      const currentRel = relativePath ? path.join(relativePath, entry.name) : entry.name;
      folders.push(currentRel);
      scan(path.join(dirPath, entry.name), currentRel, depth + 1);
    }
  }

  scan(vaultRoot);
  cachedFolders = folders;
  return cachedFolders;
}

export function updateVaultTreeSnapshot(): void {
  const vaultRoot = getVaultRoot();
  const folders = getVaultFolders(true);
  const treeFilePath = path.join(vaultRoot, '__skills', 'context', 'iCloud Vault 2026.txt');
  const historyDir = path.join(vaultRoot, '__skills', 'context', 'vault_tree_history');

  if (!fs.existsSync(historyDir)) {
    fs.mkdirSync(historyDir, { recursive: true });
  }

  const treeContent = folders.sort().join('\n');
  fs.writeFileSync(treeFilePath, treeContent, 'utf8');

  // Save timestamped snapshot (e.g., 2026-03-29_095315)
  const dateStr = new Date().toISOString().replace(/[:.]/g, '-').split('T');
  const timeStr = dateStr[1].substring(0,6);
  const snapshotName = `vault_tree_${dateStr[0]}_${timeStr}.txt`;
  fs.writeFileSync(path.join(historyDir, snapshotName), treeContent, 'utf8');
}

let cachedKnownUrls: Set<string> | null = null;

/**
 * Vault 配下に保存済みの全 `.md` を走査して、YAML frontmatter の `source:`
 * URL を集める。重複検出 (再投入の skip) に使用。
 *
 * 旧実装は `execSync('grep -rhI ...')` を使っていたが grep バイナリ依存だったため、
 * Node 純粋実装に置き換え。Windows / minimal container / grep が PATH に無い
 * 環境で silent に空 Set を返して重複保存事故を起こす回帰を防止する。
 *
 * パフォーマンス配慮:
 *   - 各 `.md` の先頭 4KB だけ読む (YAML frontmatter は通常 < 1KB)
 *   - シンボリックリンクは追わない (ループ防止)
 *   - 結果は module-level でキャッシュ。**本番経路の更新口は `addKnownUrl`**
 *     (保存直後に呼ぶ) / テスト用の全破棄は `resetKnownUrlsCache`。
 */
export function getKnownUrls(): Set<string> {
  if (cachedKnownUrls) return cachedKnownUrls;
  const vaultRoot = getVaultRoot();
  const known = new Set<string>();

  try {
    walkMdFiles(vaultRoot, (filePath) => {
      const head = readFileHead(filePath, FRONTMATTER_READ_BYTES);
      if (head === null) return;
      // `/m` で行頭 `^` を行単位にマッチ。URL は frontmatter の `source: "url"`。
      // 互換のため未クォート版も拾う (旧 .md 手動編集ケース)。
      const match = head.match(/^source:\s*"?(https?:\/\/[^"\s]+?)"?\s*$/m);
      if (match && match[1]) {
        known.add(normalizeKnownUrl(match[1]));
      }
    });
  } catch (err: any) {
    console.warn('[Storage] Failed to scan existing URLs:', err.message);
  }

  cachedKnownUrls = known;
  return cachedKnownUrls;
}

/**
 * dedup 集合のキー正規化。`getKnownUrls` (走査) と `addKnownUrl` (更新) が
 * **同じ正規化**を使うことで、保存直後に追加した URL が次の重複判定にヒットする。
 * 現状は末尾スラッシュ除去のみ (getKnownUrls の従来挙動を踏襲)。
 */
function normalizeKnownUrl(url: string): string {
  const trimmed = url.trim();
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

/**
 * 新規保存した URL を in-memory dedup 集合へ反映する **本番経路の更新口**。
 * `saveMarkdown` が `.md` を書き出した直後に呼ぶことで、同一プロセス内で
 * 続けて処理する後続バッチが「直前に保存した URL」を既知として扱える
 * (A2 欠陥の解消: 旧来は `resetKnownUrlsCache` のテスト専用口しか無く、本番では
 *  保存後に再 dedup する経路で stale = 重複保存し得た)。
 *
 * キャッシュ未初期化 (= `getKnownUrls` 未呼出) の場合は **何もしない**:
 * 次回 `getKnownUrls` が Vault 全走査で正しく構築するため、ここで先走って
 * 部分集合を作らない (部分集合を作ると「走査前なのに小さい集合」が固定化する)。
 */
export function addKnownUrl(url: string | undefined | null): void {
  if (!cachedKnownUrls) return;
  if (!url || !/^https?:\/\//.test(url.trim())) return;
  cachedKnownUrls.add(normalizeKnownUrl(url));
}

/** テスト用: モジュールキャッシュを破棄して次回 `getKnownUrls` を再走査させる */
export function resetKnownUrlsCache(): void {
  cachedKnownUrls = null;
}

const FRONTMATTER_READ_BYTES = 4096;

function readFileHead(filePath: string, bytes: number): string | null {
  let fd: number;
  try {
    fd = fs.openSync(filePath, 'r');
  } catch {
    return null;
  }
  try {
    const buf = Buffer.alloc(bytes);
    const bytesRead = fs.readSync(fd, buf, 0, bytes, 0);
    return buf.subarray(0, bytesRead).toString('utf8');
  } catch {
    return null;
  } finally {
    try { fs.closeSync(fd); } catch { /* noop */ }
  }
}

/**
 * `rootDir` 配下の `.md` ファイルだけを再帰的に列挙して visitor を呼ぶ。
 * - シンボリックリンクは追わない
 * - 読めないディレクトリは静かにスキップ
 */
function walkMdFiles(rootDir: string, visit: (filePath: string) => void): void {
  const stack: string[] = [rootDir];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      // symlink 経由のディレクトリ走査はループの危険があるので追わない。
      // readdirSync は通常 lstat ベースの結果を返すので isSymbolicLink で判定可。
      if (e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(full);
      } else if (e.isFile() && e.name.endsWith('.md')) {
        visit(full);
      }
    }
  }
}
