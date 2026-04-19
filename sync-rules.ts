/**
 * sync-rules.ts
 *
 * snippets_YYYYMMDD.xml（_分析コンテキスト/内の最新版）を解析し、
 * フォルダパスの末尾パターンから monthly / quarterly ルールを推定して
 * folder_rules.json へマージ（昇格のみ・既存ルールは絶対に降格しない）。
 *
 * 実行: pnpm run sync-rules
 */

import fs from 'fs';
import path from 'path';
import { XMLParser } from 'fast-xml-parser';
import { loadConfig, applyConfigToEnv, getVaultRoot } from './config.js';
import { loadFolderRules, saveFolderRules } from './router.js';

// ------------------------------------------------------------------ //
// Helpers
// ------------------------------------------------------------------ //

/** _分析コンテキスト/ 内の最新 snippets_YYYYMMDD.xml を返す */
function findLatestSnippetsFile(): string | null {
  const analysisDir = path.join(getVaultRoot(), '__skills', 'context', '_分析コンテキスト');
  if (!fs.existsSync(analysisDir)) {
    console.error(`[sync-rules] ディレクトリが見つかりません: ${analysisDir}`);
    return null;
  }
  const files = fs.readdirSync(analysisDir)
    .filter(f => /^snippets_\d{8}\.xml$/.test(f))
    .sort()
    .reverse(); // 最新日付が先頭
  if (files.length === 0) {
    console.error('[sync-rules] snippets_YYYYMMDD.xml が見つかりません。');
    return null;
  }
  return path.join(analysisDir, files[0]);
}

/** snippets XML を { title, content }[] として解析 */
function parseSnippets(xmlPath: string): { title: string; content: string }[] {
  const xmlData = fs.readFileSync(xmlPath, 'utf8');
  const parser = new XMLParser({ ignoreAttributes: false });
  const parsed = parser.parse(xmlData);
  const arr: { title: string; content: string }[] = [];
  const folders = parsed.folders?.folder ?? [];
  const folderArray = Array.isArray(folders) ? folders : [folders];
  for (const folder of folderArray) {
    const snippets = folder.snippets?.snippet ?? [];
    const snippetArray = Array.isArray(snippets) ? snippets : [snippets];
    for (const s of snippetArray) {
      if (s.title && s.content) {
        arr.push({ title: String(s.title).trim(), content: String(s.content).trim() });
      }
    }
  }
  return arr;
}

type Rule = 'quarterly' | 'monthly' | 'none';
const RULE_PRIORITY: Record<Rule, number> = { none: 0, quarterly: 1, monthly: 2 };

/**
 * content の末尾パターンからベースパスとルールを推定する。
 * - `/` 始まり → Obsidian 部分スニペット（スキップ）
 * - 末尾 /YYYY-Qn → quarterly
 * - 末尾 /YYYY-MM → monthly
 */
function inferRule(content: string): { base: string; rule: Rule } | null {
  const c = content.trim();
  if (c.startsWith('/')) return null;

  const qMatch = c.match(/^(.+)\/\d{4}-Q\d$/);
  if (qMatch) return { base: qMatch[1], rule: 'quarterly' };

  const mMatch = c.match(/^(.+)\/\d{4}-\d{2}$/);
  if (mMatch) return { base: mMatch[1], rule: 'monthly' };

  return null;
}

// ------------------------------------------------------------------ //
// Main export (also called from index.ts --sync-rules)
// ------------------------------------------------------------------ //

export function syncRulesFromSnippets(): void {
  const snippetsPath = findLatestSnippetsFile();
  if (!snippetsPath) return;

  console.log(`\n🔄 [sync-rules] 読み込み: ${path.basename(snippetsPath)}`);
  const snippets = parseSnippets(snippetsPath);
  const existingRules = loadFolderRules();
  const newRules: Record<string, string> = { ...existingRules };

  let added = 0;
  let upgraded = 0;
  let skipped = 0;

  for (const s of snippets) {
    const inferred = inferRule(s.content);
    if (!inferred) continue;

    const { base, rule } = inferred;
    const existing = (existingRules[base] ?? 'none') as Rule;
    const existingPrio = RULE_PRIORITY[existing] ?? 0;
    const newPrio = RULE_PRIORITY[rule];

    if (newPrio > existingPrio) {
      newRules[base] = rule;
      if (existing === 'none') {
        console.log(`  ✨ [新規追加: ${rule}] ${base}`);
        added++;
      } else {
        console.log(`  📈 [昇格: ${existing}→${rule}] ${base}`);
        upgraded++;
      }
    } else {
      skipped++;
    }
  }

  saveFolderRules(newRules);
  console.log(
    `\n✅ [sync-rules] 完了: 新規追加 ${added}件, 昇格 ${upgraded}件, スキップ ${skipped}件（既存ルール優先または対象外）\n`
  );
}

// ------------------------------------------------------------------ //
// CLI entry point
// ------------------------------------------------------------------ //

const config = loadConfig();
if (config) applyConfigToEnv(config);
syncRulesFromSnippets();
