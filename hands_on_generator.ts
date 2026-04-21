/**
 * X ブックマーク群を素材に、Claude Code CLI (OAuth サブスク枠) を呼び出して
 * ハンズオン形式のチュートリアル .md を生成する。
 *
 * 前提:
 *   - ローカルに Claude Code CLI (`claude`) がインストールされ OAuth 認証済み
 *   - 対象フォルダの X ブックマークが既に Vault + SQLite DB に投入済み
 *
 * 素材の抽出元:
 *   <vault>/__skills/pipeline/x_bookmarks.db の bookmarks テーブル。
 *   vault_path が "Clippings/X-Bookmarks/<folder>/" で始まる行を対象に、
 *   `--since=YYYY-MM-DD` 指定時は created_at の前方一致フィルタも併用する。
 *
 * 生成先:
 *   <vault>/__skills/context/ハンズオン/<folder-slug>-YYYYMMDD.md
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn, spawnSync } from 'child_process';
import { getVaultRoot } from './config';
import Database from 'better-sqlite3';

interface BookmarkRow {
  tweet_id: string;
  url: string;
  author: string | null;
  tweet_text: string | null;
  created_at: string | null;
  x_folder_name: string | null;
  vault_path: string | null;
}

export interface HandsOnOptions {
  /** 対象 Vault フォルダ (例: "Clippings/X-Bookmarks/Claude Code") */
  folder: string;
  /** YYYY-MM-DD 形式、指定日以降のポストのみ */
  since?: string;
  /** テスト用: claude コマンドを呼び出さずプロンプトを返すだけ */
  dryRun?: boolean;
  /** テスト用: claude コマンドパス上書き */
  claudeBin?: string;
}

const PROMPT_TEMPLATE_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'prompts',
  'hands_on.md'
);

function dbPath(): string {
  return path.join(getVaultRoot(), '__skills', 'pipeline', 'x_bookmarks.db');
}

function loadBookmarksForFolder(folder: string, since?: string): BookmarkRow[] {
  const p = dbPath();
  if (!fs.existsSync(p)) {
    throw new Error(`x_bookmarks.db が見つかりません: ${p}\n  先に --x-bookmarks で同期してください。`);
  }
  const db = new Database(p, { readonly: true });
  try {
    const likePattern = `${folder.replace(/\/+$/, '')}/%`;
    const exactPattern = folder.replace(/\/+$/, '');
    const params: any[] = [likePattern, exactPattern];
    let sql = `
      SELECT tweet_id, url, author, tweet_text, created_at, x_folder_name, vault_path
      FROM bookmarks
      WHERE (vault_path LIKE ? OR vault_path = ?)
    `;
    if (since) {
      sql += ` AND created_at >= ?`;
      params.push(since);
    }
    sql += ` ORDER BY created_at DESC`;
    return db.prepare(sql).all(...params) as BookmarkRow[];
  } finally {
    db.close();
  }
}

export function buildCorpus(rows: BookmarkRow[]): string {
  if (rows.length === 0) return '(素材なし)';
  return rows
    .map((r, i) => {
      const head = `### Post ${i + 1}${r.author ? ` by @${r.author}` : ''}${r.created_at ? ` (${r.created_at})` : ''}`;
      const body = (r.tweet_text ?? '').trim();
      return `${head}\n${body}\n元ポスト: ${r.url}\n`;
    })
    .join('\n---\n\n');
}

export function renderPrompt(folder: string, corpus: string, date: string): string {
  const tpl = fs.readFileSync(PROMPT_TEMPLATE_PATH, 'utf8');
  return tpl
    .replace(/\{\{folder\}\}/g, folder)
    .replace(/\{\{corpus\}\}/g, corpus)
    .replace(/\{\{date\}\}/g, date);
}

function folderSlug(folder: string): string {
  // "Clippings/X-Bookmarks/Claude Code" → "Claude Code"
  const last = folder.split('/').filter(Boolean).pop() ?? 'unfiled';
  return last.replace(/[\/\\:*?"<>|]/g, '_').replace(/\s+/g, ' ').trim().slice(0, 80);
}

function preflightClaudeCli(bin: string): void {
  // `claude --version` で疎通確認
  const res = spawnSync(bin, ['--version'], { encoding: 'utf8' });
  if (res.error || res.status !== 0) {
    throw new Error(
      `claude CLI が見つかりません (${bin})。\n` +
        '  - Claude Code をインストール: https://claude.ai/code\n' +
        '  - OAuth サインイン: `claude`'
    );
  }
}

export async function generateHandsOn(options: HandsOnOptions): Promise<string> {
  const folder = options.folder.replace(/\/+$/, '');
  const slug = folderSlug(folder);
  const today = new Date();
  const dateStr = today.toISOString().split('T')[0];
  const dateCompact = dateStr.replace(/-/g, '');

  const rows = loadBookmarksForFolder(folder, options.since);
  if (rows.length === 0) {
    throw new Error(`対象フォルダに素材がありません: ${folder}${options.since ? ` (since=${options.since})` : ''}`);
  }
  console.log(`📝 ${rows.length} 件のポストを素材にします。`);

  const corpus = buildCorpus(rows);
  const prompt = renderPrompt(folder, corpus, dateStr);

  const outDir = path.join(getVaultRoot(), '__skills', 'context', 'ハンズオン');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${slug}-${dateCompact}.md`);

  if (options.dryRun) {
    fs.writeFileSync(outPath + '.prompt.txt', prompt, 'utf8');
    console.log(`🧪 dry-run: プロンプトを保存しました ${outPath}.prompt.txt`);
    return outPath + '.prompt.txt';
  }

  const claudeBin = options.claudeBin ?? 'claude';
  preflightClaudeCli(claudeBin);

  console.log(`🤖 claude CLI を呼び出し中 (プロンプト ${prompt.length} 文字)...`);

  const generated = await new Promise<string>((resolve, reject) => {
    const proc = spawn(claudeBin, ['-p', prompt], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const chunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    proc.stdout.on('data', d => chunks.push(d));
    proc.stderr.on('data', d => errChunks.push(d));
    proc.on('error', reject);
    proc.on('close', code => {
      if (code !== 0) {
        reject(
          new Error(
            `claude CLI が異常終了 (code=${code}): ${Buffer.concat(errChunks).toString('utf8').slice(0, 1000)}`
          )
        );
      } else {
        resolve(Buffer.concat(chunks).toString('utf8'));
      }
    });
  });

  fs.writeFileSync(outPath, generated, 'utf8');
  console.log(`✅ ハンズオンを生成しました: ${outPath}`);
  return outPath;
}

export const __test = {
  buildCorpus,
  renderPrompt,
  folderSlug,
};
