/**
 * フォルダ集約ルール ( `x_forced_parents.json` ) の自動推定。
 *
 * 着想:
 *   ユーザーは vault 上で `X_Bookmarks/Claude Code/Tips`, `X_Bookmarks/Claude Code/Hooks`,
 *   `X_Bookmarks/UI_LP作成/...` のように手動でグループ化してきた。これらの第一階層名
 *   (`Claude Code`, `UI_LP作成`) は本人が選んだ「正準的なキーワード」なので、
 *   `x_forced_parents.json` の入力として最も信頼できる。
 *
 * アルゴリズム:
 *   1. SQLite の folder_sessions を `vault_path` の第一階層 (= group) でバケット化
 *      (status は active / archived どちらも採用。orphaned 系は除外)
 *   2. バケット内 distinct な x_folder_name が >= 2 個あるものを候補に採用
 *      (同じ X folder 名の重複 session が複数あっても 1 とカウント。
 *       1 つの X folder しか持たない group は強制親にする意味が薄い)
 *   3. "Claude" / "ClaudeCode" / "Claude Code" のように case/space が異なる候補は
 *      すべて別キーワードとして emit する (既存 word-boundary マッチで区別される)
 *   4. 現行 `x_forced_parents.json` との diff を出し、追記すべきもの・既知のものを表示
 *
 * インタラクティブ実行:
 *   stdin で y/N を取り、`y` のとき `x_forced_parents.json.bak` を残してから上書き。
 */

import fs from 'fs';
import path from 'path';
import {
  getVaultRoot,
  getXBookmarksBaseFolder,
} from './config';
import { getDb, FolderSessionRow } from './x_bookmarks_db';
import { loadForcedParents } from './x_folder_mapper';

const FORCED_PARENTS_FILENAME = 'x_forced_parents.json';

export interface DeriveResult {
  /** 既存 forced_parents */
  current: string[];
  /** 推定された候補 (current にも含まれる canonical を保持) */
  proposed: string[];
  /** 推定理由 (キーワード → 集約された X folder 名) */
  evidence: Map<string, string[]>;
  /** 推定された候補のうち、current に無いもの (新規) */
  toAdd: string[];
  /** current にあって proposed に無いもの (削除候補 — 安全側でデフォルト保持) */
  notSeen: string[];
}

interface DeriveInput {
  sessions?: FolderSessionRow[];
  baseFolder?: string;
  forcedParents?: string[];
}

/**
 * 純関数: folder_sessions と現行 forced_parents から DeriveResult を組み立てる。
 * ファイル I/O やプロンプトはしない。テスト容易。
 */
export function deriveForcedParents(input: DeriveInput = {}): DeriveResult {
  const baseFolder = (input.baseFolder ?? getXBookmarksBaseFolder()).replace(/\/+$/, '');
  const sessions = input.sessions ?? getDb().listFolderSessions();
  const current = input.forcedParents ?? loadForcedParents();

  // group (第一階層) → X-side folder names のバケット
  const buckets = new Map<string, Set<string>>();
  for (const s of sessions) {
    if (s.status !== 'active' && s.status !== 'archived') continue;
    const vp = s.vault_path;
    if (!vp) continue;
    const norm = vp.replace(/\\/g, '/').replace(/\/+$/, '');
    if (norm === baseFolder) continue;
    if (!norm.startsWith(baseFolder + '/')) continue;
    const rest = norm.slice(baseFolder.length + 1);
    const group = rest.split('/')[0];
    if (!group || group === '_archived' || group === '_Archived' || group === '_Unfiled') continue;
    if (!buckets.has(group)) buckets.set(group, new Set());
    if (s.x_folder_name) buckets.get(group)!.add(s.x_folder_name);
  }

  // 集約しているグループ (sessions >= 2) のみ候補化
  const proposed: string[] = [];
  const evidence = new Map<string, string[]>();
  for (const [group, names] of buckets.entries()) {
    if (names.size < 2) continue;
    proposed.push(group);
    evidence.set(group, [...names].sort());
  }
  proposed.sort((a, b) => a.localeCompare(b));

  const currentSet = new Set(current);
  const proposedSet = new Set(proposed);
  const toAdd = proposed.filter(k => !currentSet.has(k));
  const notSeen = current.filter(k => !proposedSet.has(k));

  return { current, proposed, evidence, toAdd, notSeen };
}

/**
 * DeriveResult を人間可読な diff にフォーマット。CLI 出力用。
 */
export function formatDeriveDiff(result: DeriveResult): string {
  const lines: string[] = [];
  lines.push('## フォルダ集約ルール推定結果');
  lines.push('');
  lines.push(`現在の x_forced_parents.json (${result.current.length} 件): ${result.current.join(', ') || '(空)'}`);
  lines.push('');
  if (result.toAdd.length === 0) {
    lines.push('✅ 追加候補なし (推定済みのキーワードはすべて登録済み)');
  } else {
    lines.push(`+ 追加候補 (${result.toAdd.length} 件):`);
    for (const k of result.toAdd) {
      const ev = result.evidence.get(k) ?? [];
      lines.push(`  + "${k}"   ← ${ev.length} 個の X folder を集約`);
      for (const f of ev) lines.push(`      - ${f}`);
    }
  }
  if (result.notSeen.length > 0) {
    lines.push('');
    lines.push(`? 推定で見えなかったキーワード (削除はしない — 念のため保持):`);
    for (const k of result.notSeen) lines.push(`    - "${k}"`);
  }
  return lines.join('\n');
}

/**
 * 新しい forced_parents 配列を書き出す。.bak を残す (idempotent な上書き保護)。
 * 戻り値は書き出し先パス。
 */
export function writeForcedParents(next: string[], options: { vaultRoot?: string } = {}): string {
  const vaultRoot = options.vaultRoot ?? getVaultRoot();
  const dir = path.join(vaultRoot, '__skills', 'pipeline');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const target = path.join(dir, FORCED_PARENTS_FILENAME);
  if (fs.existsSync(target)) {
    fs.copyFileSync(target, target + '.bak');
  }
  fs.writeFileSync(target, JSON.stringify(next, null, 2) + '\n', 'utf8');
  return target;
}

/**
 * CLI エントリ。`pnpm start -- --x-derive-rules` から呼ばれる。
 * `ask` を渡せばインタラクティブ確認をモック可能 (テスト用)。
 */
export async function runDeriveRulesCli(args: {
  ask?: (q: string) => Promise<string>;
} = {}): Promise<void> {
  const ask = args.ask ?? (await import('./pipeline/prompt')).askQuestion;
  const result = deriveForcedParents();
  console.log(formatDeriveDiff(result));

  if (result.toAdd.length === 0) {
    console.log('\nファイル更新は不要です。');
    return;
  }

  // 既存に無いものだけを足し、現行は (notSeen も含めて) 保持する。
  const next = [...result.current];
  for (const k of result.toAdd) {
    if (!next.includes(k)) next.push(k);
  }

  const answer = (await ask(`\n上記 ${result.toAdd.length} 件を x_forced_parents.json に追記しますか？ [y/N]: `)).trim().toLowerCase();
  if (answer !== 'y') {
    console.log('キャンセルしました。');
    return;
  }
  const written = writeForcedParents(next);
  console.log(`✅ 更新しました: ${written}  (.bak を残しています)`);
}
