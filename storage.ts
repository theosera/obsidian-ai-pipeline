import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { ArticleData } from './types';

// Current Vault root
const VAULT_ROOT = '/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026';

export function checkFolderExists(folderPath: string): boolean {
  const fullPath = path.join(VAULT_ROOT, folderPath);
  return fs.existsSync(fullPath);
}

export function saveMarkdown(articleData: ArticleData, folderPath: string): string {
  const date = new Date();
  
  // rely on the AI's classification for Quarterly folder logic
  let finalPath = folderPath;

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

  const safeTitle = (articleData.title || 'Untitled').replace(/[\/\\*?:""<>|]/g, '').slice(0, 100);
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
  return str.replace(/"/g, '\\"');
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
