import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { ArticleData } from './types';

// Current Vault root
const VAULT_ROOT = '/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026';

const FALLBACK_PATH = 'Clippings/Inbox';

/**
 * パストラバーサル防止: resolvedパスがVAULT_ROOT配下であることを保証する。
 * nullバイト除去、セグメント検証、resolve後のプレフィックス検証、
 * さらに実体パス(realpath)によるsymlink追跡を行う。
 * 違反時は安全なフォールバックパスを返す。
 */
export function ensureSafePath(proposedRelative: string): string {
  if (!proposedRelative || typeof proposedRelative !== 'string') {
    return FALLBACK_PATH;
  }

  // Phase 1: nullバイト・制御文字の除去
  const noNull = proposedRelative.replace(/[\x00-\x1f\x7f]/g, '');

  // Phase 2: パスセグメント単位でのサニタイズ
  const sanitized = noNull
    .split(/[\/\\]/)
    .filter(seg => seg !== '..' && seg !== '.' && seg !== '')
    .join(path.sep);

  if (!sanitized) {
    return FALLBACK_PATH;
  }

  // Phase 3: resolve後のプレフィックス検証
  const resolved = path.resolve(VAULT_ROOT, sanitized);
  if (!resolved.startsWith(VAULT_ROOT + path.sep) && resolved !== VAULT_ROOT) {
    console.error(`[Security] パストラバーサル検出 (resolve): "${proposedRelative}" -> "${resolved}"`);
    return FALLBACK_PATH;
  }

  // Phase 4: 既存パスの場合、realpath(symlink解決済み)でも検証
  if (fs.existsSync(resolved)) {
    try {
      const real = fs.realpathSync(resolved);
      const realVault = fs.realpathSync(VAULT_ROOT);
      if (!real.startsWith(realVault + path.sep) && real !== realVault) {
        console.error(`[Security] symlink経由のパストラバーサル検出: "${resolved}" -> realpath "${real}"`);
        return FALLBACK_PATH;
      }
    } catch {
      // realpathSync失敗は無視（パスが存在しない場合はPhase 3で十分）
    }
  }

  // Phase 5: パス長制限（極端に長いパスはOSレベルの問題を引き起こす）
  if (sanitized.length > 500) {
    console.error(`[Security] パス長超過 (${sanitized.length} chars): "${sanitized.substring(0, 80)}..."`);
    return FALLBACK_PATH;
  }

  return sanitized;
}

export function checkFolderExists(folderPath: string): boolean {
  const safePath = ensureSafePath(folderPath);
  const fullPath = path.join(VAULT_ROOT, safePath);
  return fs.existsSync(fullPath);
}

export function saveMarkdown(articleData: ArticleData, folderPath: string): string {
  const date = new Date();

  // パストラバーサル防止: AI出力パスを検証
  let finalPath = ensureSafePath(folderPath);

  const fullDirPath = path.join(VAULT_ROOT, finalPath);
  
  if (!fs.existsSync(fullDirPath)) {
    fs.mkdirSync(fullDirPath, { recursive: true });
  }

  const today = date.toISOString().split('T')[0];
  const saveDate = articleData.date || today; // Fallback to today if no date

  let mm_dd = today.substring(5); // Default to today's MM-DD
  // Use frontmatter date logic if it matches YYYY-MM-DD
  const createdMatch = today.match(/^\d{4}-(\d{2}-\d{2})$/);
  if (createdMatch) {
      mm_dd = createdMatch[1];
  }

  const safeTitle = (articleData.title || 'Untitled')
    .replace(/[\x00-\x1f\x7f]/g, '')       // 制御文字・ヌル文字を除去
    .replace(/[\/\\*?:""<>|／＼]/g, '')      // パス区切り文字（半角・全角）を除去
    .trim()
    .slice(0, 100);
  const fileName = `${safeTitle}_${mm_dd}.md`;
  const filePath = path.join(fullDirPath, fileName);

  const pubDate = articleData.date || '';
  const siteLink = articleData.siteName ? `\n  - "[[${escapeFrontmatter(articleData.siteName)}]]"` : '';

  const frontmatter = `---
title: "${escapeFrontmatter(articleData.title || '')}"
source: "${articleData.url || ''}"
author:${siteLink}
published: ${pubDate}
created: ${today}
description: "${escapeFrontmatter(articleData.excerpt || '')}"
tags:
  - "clippings"
---

`;

  const body = frontmatter + (articleData.content || '');
  fs.writeFileSync(filePath, body, 'utf8');
  return filePath;
}

function escapeFrontmatter(str: string): string {
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

  scan(VAULT_ROOT);
  cachedFolders = folders;
  return cachedFolders;
}

export function updateVaultTreeSnapshot(): void {
  const folders = getVaultFolders(true);
  const treeFilePath = path.join(VAULT_ROOT, '__skills', 'context', 'iCloud Vault 2026.txt');
  const historyDir = path.join(VAULT_ROOT, '__skills', 'context', 'vault_tree_history');

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

export function getKnownUrls(): Set<string> {
  if (cachedKnownUrls) return cachedKnownUrls;
  const known = new Set<string>();
  
  try {
    const output = execSync('grep -rhI "^source: \\"" . || true', { 
      cwd: VAULT_ROOT, 
      encoding: 'utf8', 
      stdio: ['pipe', 'pipe', 'ignore'] 
    });
    
    const lines = output.split('\n');
    for (const line of lines) {
      const match = line.match(/^source:\s*"?(https?:\/\/[^"]+)"?/);
      if (match && match[1]) {
        let url = match[1].trim();
        url = url.endsWith('/') ? url.slice(0, -1) : url;
        known.add(url);
      }
    }
  } catch (err: any) {
    console.warn("[Storage] Failed to grep existing URLs:", err.message);
  }
  
  cachedKnownUrls = known;
  return cachedKnownUrls;
}
