/**
 * X ブックマークフォルダ名 → Vault 階層パスへのマッピング層。
 *
 * 2 層構造:
 *
 *   Tier 1: 強制親フォルダ (x_forced_parents.json)
 *     - ユーザーが手動メンテするキーワードホワイトリスト
 *     - X フォルダ名がキーワードを「単語境界マッチ」で含むなら、そのキーワードを親フォルダ化
 *     - 例: ["Claude Code", "Obsidian", "MCP"] が登録されていれば、
 *           X フォルダ "Claude Code Tips"   → "Claude Code/Tips"
 *           X フォルダ "Claude Code"        → "Claude Code"
 *           X フォルダ "Obsidian Plugins"   → "Obsidian/Plugins"
 *           X フォルダ "MCP"                → "MCP"
 *           X フォルダ "LangChain"          → "LangChain"  (マッチなし)
 *     - 部分一致は禁止 ("AI" は "AIRI" にマッチしない)
 *     - キーワード重複時は「より長いキーワード」を優先
 *
 *   Tier 2: 承認済み自動マッピング (x_folder_mapping.json)
 *     - {"AI Tools": "AI/Tools"} のような明示マップ
 *     - Tier 1 で未マッチのフォルダにのみ適用
 *
 *   Tier 3: 共通キーワード自動検出 → 提案レポート
 *     - Tier 1/2 でも未マッチのフォルダ群から共通キーワードを検出
 *     - analysis/x_folder_grouping_proposal_YYYYMMDD.md として出力
 *     - ユーザー承認後 x_folder_mapping.json に手動転記される運用
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot } from './config';

const STOP_WORDS = new Set([
  'and', 'the', 'my', 'a', 'an', 'to', 'of', 'in', 'on', 'for',
  'with', 'by', 'is', 'it', 'as', 'at', 'or',
]);

const FORCED_PARENTS_FILENAME = 'x_forced_parents.json';
const FOLDER_MAPPING_FILENAME = 'x_folder_mapping.json';

function configDir(): string {
  return path.join(getVaultRoot(), '__skills', 'pipeline');
}

export function loadForcedParents(): string[] {
  const file = path.join(configDir(), FORCED_PARENTS_FILENAME);
  if (!fs.existsSync(file)) return [];
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((s: unknown): s is string => typeof s === 'string' && s.trim().length > 0);
  } catch {
    return [];
  }
}

export function loadApprovedMappings(): Record<string, string> {
  const file = path.join(configDir(), FOLDER_MAPPING_FILENAME);
  if (!fs.existsSync(file)) return {};
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {};
    const result: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof k === 'string' && typeof v === 'string') result[k] = v;
    }
    return result;
  } catch {
    return {};
  }
}

/**
 * フォルダ名 1 件分のサニタイズ。パス区切り文字・制御文字・改行を除去し80字に切り詰める。
 * パス全体ではなく「1 セグメント分」のサニタイズなので、`/` は除去する (パス結合は呼び出し側)。
 * 完全な多層防御は呼び出し側の ensureSafePath() に委ねる。
 */
export function sanitizeFolderName(raw: string): string {
  if (!raw) return '_Unfiled';
  const cleaned = raw
    .replace(/[\x00-\x1f\x7f]/g, '')
    .replace(/[\/\\]/g, '-')
    .replace(/[*?:""<>|／＼]/g, '')
    .trim()
    .normalize('NFC')
    .slice(0, 80);
  return cleaned || '_Unfiled';
}

/**
 * X フォルダ名内に強制親キーワードが「単語境界マッチ」で含まれるかを判定。
 * - 大小文字無視
 * - 単語境界: 英数字以外 (空白/記号/アンダースコア除く境界)
 * - 例: keyword="AI", folder="AI Agent" → true
 *       keyword="AI", folder="AIRI"     → false
 *       keyword="Claude Code", folder="Claude Code Tips" → true
 */
function hasWordBoundaryMatch(folderName: string, keyword: string): boolean {
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // (?<![A-Za-z0-9]) と (?![A-Za-z0-9]) で英数字以外の境界を担保。
  // 日本語等の非ASCII文字隣接でもマッチさせる (例: "MCP連携" の "MCP" もマッチ)。
  const re = new RegExp(`(?<![A-Za-z0-9])${escaped}(?![A-Za-z0-9])`, 'i');
  return re.test(folderName);
}

/**
 * X フォルダ名から強制親キーワード部分を取り除き、残った部分をサブフォルダ名として返す。
 * 残りが空なら親フォルダ直下扱い (空文字を返す)。
 */
function stripKeyword(folderName: string, keyword: string): string {
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?<![A-Za-z0-9])${escaped}(?![A-Za-z0-9])`, 'i');
  return folderName.replace(re, '').replace(/\s+/g, ' ').trim();
}

/**
 * X フォルダ名 → Vault 階層パス (相対) のマッピング。
 *
 * 適用順:
 *   1. 強制親キーワード (より長いキーワード優先・大小文字無視)
 *   2. 承認済み明示マッピング (完全一致)
 *   3. なにもなければ raw フォルダ名そのまま
 *
 * 戻り値はサニタイズ済みの相対パス (`/` 区切り)。空文字や _Unfiled も返り得る。
 */
export function mapFolderToVaultPath(
  xFolderName: string,
  forcedParents: string[],
  approvedMappings: Record<string, string>
): string {
  const folder = (xFolderName || '').trim();
  if (!folder) return '_Unfiled';

  // Tier 1: 強制親キーワード (長い順にチェックして最長一致を優先)
  const sortedKeywords = [...forcedParents].sort((a, b) => b.length - a.length);
  for (const keyword of sortedKeywords) {
    if (!keyword.trim()) continue;
    if (hasWordBoundaryMatch(folder, keyword)) {
      const parent = sanitizeFolderName(keyword);
      const remainder = stripKeyword(folder, keyword);
      if (!remainder) return parent;
      return `${parent}/${sanitizeFolderName(remainder)}`;
    }
  }

  // Tier 2: 承認済みマッピング (完全一致)
  if (approvedMappings[folder]) {
    const mapped = approvedMappings[folder];
    return mapped.split('/').map(seg => sanitizeFolderName(seg)).filter(Boolean).join('/');
  }

  // Tier 3: フォールバック
  return sanitizeFolderName(folder);
}

/**
 * 共通キーワード検出。
 * Tier 1 (強制親) でマッチしなかったフォルダ群を対象に、
 * 単語境界で出現する 3 個以上の共通単語を探す。
 *
 * 戻り値: { keyword, folders } の配列 (出現フォルダ数の多い順)
 */
export function detectCommonKeywords(
  folderNames: string[],
  forcedParents: string[]
): { keyword: string; folders: string[] }[] {
  // Tier 1 で吸収済みのフォルダは除外
  const unmatched = folderNames.filter(f =>
    !forcedParents.some(kw => kw.trim() && hasWordBoundaryMatch(f, kw))
  );

  // 各単語 → どのフォルダに出現したか
  const keywordToFolders = new Map<string, Set<string>>();
  // 単語頻度カウント用 (大小文字無視)
  const lowerToOriginal = new Map<string, string>();

  for (const folder of unmatched) {
    // 単語境界 (空白/_/-) で分割し、英数字または日本語含むトークンを抽出
    const tokens = folder
      .split(/[\s_\-]+/)
      .map(t => t.trim())
      .filter(t => t.length >= 2 && !STOP_WORDS.has(t.toLowerCase()));

    const seenInFolder = new Set<string>();
    for (const token of tokens) {
      const lower = token.toLowerCase();
      if (seenInFolder.has(lower)) continue;
      seenInFolder.add(lower);
      if (!lowerToOriginal.has(lower)) lowerToOriginal.set(lower, token);
      if (!keywordToFolders.has(lower)) keywordToFolders.set(lower, new Set());
      keywordToFolders.get(lower)!.add(folder);
    }
  }

  const proposals: { keyword: string; folders: string[] }[] = [];
  for (const [lower, folders] of keywordToFolders.entries()) {
    if (folders.size < 3) continue;
    proposals.push({
      keyword: lowerToOriginal.get(lower) || lower,
      folders: [...folders].sort(),
    });
  }
  proposals.sort((a, b) => b.folders.length - a.folders.length);
  return proposals;
}

/**
 * 提案レポートを analysis/ 配下に書き出し、書き出し先パスを返す。
 * proposals が空なら何もせず空文字を返す。
 */
export function writeGroupingProposal(
  proposals: { keyword: string; folders: string[] }[]
): string {
  if (proposals.length === 0) return '';
  const dir = path.join(getVaultRoot(), '__skills', 'context', '分類結果レポート');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const dateStr = new Date().toISOString().split('T')[0].replace(/-/g, '');
  const file = path.join(dir, `x_folder_grouping_proposal_${dateStr}.md`);

  let md = `# X ブックマークフォルダ 共通キーワード提案レポート\n\n`;
  md += `生成日時: ${new Date().toISOString()}\n\n`;
  md += `以下のキーワードが 3 件以上のフォルダに共通で出現しました。\n`;
  md += `親フォルダとして承認する場合は \`x_forced_parents.json\` に追記してください。\n`;
  md += `特定のフォルダだけ別パスに飛ばしたい場合は \`x_folder_mapping.json\` に明示マップを追記してください。\n\n`;

  for (const p of proposals) {
    md += `## キーワード候補: \`${p.keyword}\` (${p.folders.length} フォルダ)\n\n`;
    for (const f of p.folders) {
      md += `- ${f}\n`;
    }
    md += `\n`;
  }

  fs.writeFileSync(file, md, 'utf8');
  return file;
}
