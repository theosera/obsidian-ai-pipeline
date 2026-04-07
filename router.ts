import fs from 'fs';
import path from 'path';
import { ProcessingResult } from './types';

const VAULT_ROOT = '/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026';
const RULES_PATH = path.join(VAULT_ROOT, '__skills', 'pipeline', 'folder_rules.json');

// デフォルトの閾値 (The user can edit this file later if they want to adjust, or we might add a config prompt)
const THRESHOLDS = {
  QUARTERLY: 10,
  MONTHLY: 20
};

type RulesMap = Record<string, string>;

export function loadFolderRules(): RulesMap {
  if (fs.existsSync(RULES_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(RULES_PATH, 'utf8'));
    } catch (e) {
      console.error('Failed to parse folder_rules.json, starting fresh.');
      return {};
    }
  }
  return {};
}

export function saveFolderRules(rules: RulesMap): void {
  fs.writeFileSync(RULES_PATH, JSON.stringify(rules, null, 2), 'utf8');
}

export function getRoutedPath(baseCategory: string, publishDateStr: string | undefined, rules: RulesMap): string {
  // EXCEPTION: how/howto folders are completely EXEMPT from quarterly/monthly rules
  if (/(?:\/|^)(how|howto)(?:\/|$)/i.test(baseCategory)) {
    return baseCategory;
  }

  const rule = rules[baseCategory] || 'none';
  const dateObj = publishDateStr ? new Date(publishDateStr) : new Date();
  
  if (rule === 'monthly') {
    const year = dateObj.getFullYear();
    const month = String(dateObj.getMonth() + 1).padStart(2, '0');
    return `${baseCategory}/${year}-${month}`;
  }
  
  if (rule === 'quarterly') {
    const year = dateObj.getFullYear();
    const quarter = Math.floor(dateObj.getMonth() / 3) + 1;
    return `${baseCategory}/${year}-Q${quarter}`;
  }
  
  return baseCategory;
}

export function updateThresholds(results: ProcessingResult[], currentRules: RulesMap): RulesMap {
  let updated = false;
  
  // 今バッチでの各ベースカテゴリの処理予定数
  const batchCounts: Record<string, number> = {};
  for (const r of results) {
    if (r.status === 'success' && r.classification) {
      const baseCat = r.classification.proposedPath;
      if (baseCat === '__EXCLUDED__') continue;
      if (!batchCounts[baseCat]) batchCounts[baseCat] = 0;
      batchCounts[baseCat]++;
    }
  }

  // Vault全体のスキャンと閾値評価
  for (const [baseCat, batchCount] of Object.entries(batchCounts)) {
    let currentRule = currentRules[baseCat] || 'none';
    
    // Vault内の対象ジャンルの既存ファイル数をカウント
    const catPath = path.join(VAULT_ROOT, baseCat);
    let vaultCount = batchCount; 
    
    if (fs.existsSync(catPath) && fs.statSync(catPath).isDirectory()) {
       vaultCount += countMarkdownFiles(catPath);
    }
    
    let newRule = currentRule;
    
    // EXCEPTION: how/howto folders do not get upgraded
    if (/(?:\/|^)(how|howto)(?:\/|$)/i.test(baseCat)) {
      continue;
    }
    
    // 昇格ロジック (一度上がったら下がらない)
    if (currentRule !== 'monthly') {
      if (vaultCount >= THRESHOLDS.MONTHLY) {
        newRule = 'monthly';
      } else if (vaultCount >= THRESHOLDS.QUARTERLY && currentRule !== 'quarterly') {
        newRule = 'quarterly';
      }
    }
    
    if (newRule !== currentRule) {
      console.log(`\n📈 [フォルダ規則の自動昇格] '${baseCat}' の記事数が ${vaultCount} 件に達したため、ルールが [${currentRule}] -> [${newRule}] に昇格しました！`);
      console.log(`🔄 既存のファイルを新しいルール (${newRule}) に基づき再編成します...`);
      migrateExistingFiles(baseCat, newRule);
      
      currentRules[baseCat] = newRule;
      updated = true;
    }
  }
  
  if (updated) {
    saveFolderRules(currentRules);
  }
  
  return currentRules;
}

/**
 * 既存のファイルを新しいルールに基づいて移動（再編成）する
 */
function migrateExistingFiles(baseCat: string, newRule: string): void {
  const baseDir = path.join(VAULT_ROOT, baseCat);
  if (!fs.existsSync(baseDir)) return;

  // 再帰的にすべてのマークダウンファイルを収集
  const allMdFiles = collectMarkdownFiles(baseDir);

  for (const filePath of allMdFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      
      // フロントマターから date: または published: 抽出
      let fileDate: string | undefined = undefined;
      const dateMatch = content.match(/^(?:date|published):\s*"?(\d{4}-\d{2}-\d{2})"?/m);
      if (dateMatch && dateMatch[1]) {
        fileDate = dateMatch[1];
      } else {
        // フォールバック: ファイルの作成日時
        const stat = fs.statSync(filePath);
        fileDate = stat.birthtime.toISOString().split('T')[0];
      }

      // 新しいルールに基づいた相対パスを取得 (Engineer/LLM/2026-02 など)
      // モックのルールオブジェクトを渡して解決する
      const tempRules: RulesMap = { [baseCat]: newRule };
      const newRelativePath = getRoutedPath(baseCat, fileDate, tempRules);
      const newAbsoluteDir = path.join(VAULT_ROOT, newRelativePath);
      
      // 移動先ディレクトリの作成
      if (!fs.existsSync(newAbsoluteDir)) {
        fs.mkdirSync(newAbsoluteDir, { recursive: true });
      }

      const fileName = path.basename(filePath);
      const newFilePath = path.join(newAbsoluteDir, fileName);

      // 移動先が元の場所と違う場合のみ移動
      if (filePath !== newFilePath) {
         fs.renameSync(filePath, newFilePath);
      }

    } catch (err: any) {
      console.error(`[Router] Failed to migrate file ${filePath}:`, err.message);
    }
  }
  
  // 空になった過去のディレクトリをクリーンアップ (深さ1まで)
  cleanupEmptyDirectories(baseDir);
}

/**
 * 指定ディレクトリ直下の空ディレクトリを削除
 */
function cleanupEmptyDirectories(dir: string): void {
  try {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      const fullPath = path.join(dir, item);
      if (fs.statSync(fullPath).isDirectory()) {
         const children = fs.readdirSync(fullPath);
         if (children.length === 0) {
           fs.rmdirSync(fullPath);
         }
      }
    }
  } catch (err) {}
}

/**
 * フォルダ内のすべての .md ファイルの絶対パスを配列で返す
 */
function collectMarkdownFiles(dir: string): string[] {
  let results: string[] = [];
  try {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      const fullPath = path.join(dir, item);
      if (fs.statSync(fullPath).isDirectory()) {
        results = results.concat(collectMarkdownFiles(fullPath));
      } else if (fullPath.endsWith('.md')) {
        results.push(fullPath);
      }
    }
  } catch(err) { }
  return results;
}

/**
 * サブフォルダ内の特定の深さまで.mdファイルを再帰的にカウントする
 */
function countMarkdownFiles(dir: string): number {
  let count = 0;
  try {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      const fullPath = path.join(dir, item);
      if (fs.statSync(fullPath).isDirectory()) {
        // 深追いしすぎないように軽くカウント (ex. 四半期などのサブフォルダを考慮)
        count += countMarkdownFiles(fullPath);
      } else if (fullPath.endsWith('.md')) {
        count++;
      }
    }
  } catch (err) {
    // ignore
  }
  return count;
}
