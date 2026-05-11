/**
 * フォルダ数保存則 (folder-count conservation invariant)。
 *
 * 制約:
 *   X 側 distinct ブックマークフォルダ数 (= 種類数)
 *     == `<vault>/<base>/` 配下のリーフフォルダ数 (キーワード集約解除時)
 *
 * リーフフォルダとは:
 *   `<base>/<group>/<sub>` の `<sub>` が末端 (= さらに子ディレクトリを持たない) のもの。
 *   forced_parents による集約で `<base>/<group>` が中間ノードになる場合、その
 *   `<group>` 自身はリーフではない。
 *   フラットな (集約されていない) `<base>/<folderName>` は `<folderName>` がリーフ。
 *
 * 例外として無視するもの (リーフ集計から外す):
 *   - `_Unfiled`, `_archived`, `_Archived` (システム予約 / archive)
 *   - 日付ベース (`YYYY-Qn`, `YYYY-MM`)
 *   - 隠しフォルダ
 *
 * 用途:
 *   sync 末尾と E2E テストでアサーションする。違反したら警告ログ + orphan 列挙。
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot, getXBookmarksBaseFolder } from './config';
import { getDb } from './x_bookmarks_db';

export interface InvariantCheck {
  xFolderCount: number;
  leafFolderCount: number;
  matched: boolean;
  /** X 側にあって leaf として現れない folder 名 */
  missingLeaves: string[];
  /** leaf として存在するが X 側に対応する distinct folder 名が無いリーフ相対パス */
  extraneousLeaves: string[];
}

interface CheckOptions {
  vaultRoot?: string;
  baseFolder?: string;
}

/**
 * Vault 側のリーフフォルダ相対パス一覧を再帰列挙。
 * `<base>` 直下から探す。深さ無制限だが Obsidian の通常運用では 3〜4 階層程度。
 */
export function listLeafFolders(args: CheckOptions = {}): string[] {
  const vaultRoot = args.vaultRoot ?? getVaultRoot();
  const baseFolder = args.baseFolder ?? getXBookmarksBaseFolder();
  const baseAbs = path.join(vaultRoot, baseFolder);
  if (!fs.existsSync(baseAbs)) return [];

  const leaves: string[] = [];

  function walk(absDir: string, relParts: string[]): void {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(absDir, { withFileTypes: true }); } catch { return; }
    const childDirs = entries.filter(e => e.isDirectory() && !shouldIgnore(e.name));
    if (childDirs.length === 0) {
      // ここがリーフ。ただし `<base>` 直下自身はリーフではない (relParts.length === 0)
      if (relParts.length > 0) leaves.push(relParts.join('/'));
      return;
    }
    for (const e of childDirs) walk(path.join(absDir, e.name), [...relParts, e.name]);
  }

  walk(baseAbs, []);
  return leaves;
}

function shouldIgnore(name: string): boolean {
  if (name.startsWith('.')) return true;
  if (name === '_Unfiled') return true;
  if (name === '_archived' || name === '_Archived') return true;
  if (/^\d{4}-(Q[1-4]|\d{2})$/.test(name)) return true;
  return false;
}

/**
 * X 側 active folder 名集合 (folder_sessions.status === 'active') を返す。
 * archived / orphaned は X 側に無い (もう存在しない) ものとして数えない。
 */
export function listActiveXFolderNames(): string[] {
  const sessions = getDb().listFolderSessions();
  const out = new Set<string>();
  for (const s of sessions) {
    if (s.status !== 'active') continue;
    if (!s.x_folder_name) continue;
    out.add(s.x_folder_name);
  }
  return [...out];
}

/**
 * 不変条件チェック本体。`sessions` を渡せばテストでモック可。
 */
export function checkFolderCountInvariant(args: CheckOptions & {
  xFolderNames?: string[];
} = {}): InvariantCheck {
  const xNames = args.xFolderNames ?? listActiveXFolderNames();
  const leaves = listLeafFolders(args);

  // 集約後の leaf 末端セグメント名で X folder 名と突き合わせる
  // (forced_parents で `Claude Code` 親フォルダに集約された "Claude Code Tips" の
  //  leaf は `Claude Code/Tips` で、末端は `Tips`。これは X folder 名そのものと
  //  一致しないため、ここで安易な「集合一致」はできない。よって件数のみ比較し、
  //  詳細 orphan 列挙は best-effort で「leaf 末端を X folder 名で完全一致」した
  //  ものを除外する。)
  const leafEndSegments = leaves.map(p => p.split('/').pop()!);
  const xSet = new Set(xNames);
  const leafSet = new Set(leafEndSegments);

  const missingLeaves = xNames.filter(name => !leafSet.has(name) && !leafSet.has(lastSegment(name)));
  const extraneousLeaves = leaves.filter(p => {
    const last = p.split('/').pop()!;
    return !xSet.has(last);
  });

  return {
    xFolderCount: xNames.length,
    leafFolderCount: leaves.length,
    matched: xNames.length === leaves.length,
    missingLeaves,
    extraneousLeaves,
  };
}

function lastSegment(s: string): string {
  return s.split('/').pop() ?? s;
}

/**
 * sync 末尾でログ出力する用の helper。assertion 失敗でも throw はせず警告のみ。
 */
export function logInvariantCheck(check: InvariantCheck): void {
  const tag = check.matched ? '✅' : '⚠️ ';
  console.log(`${tag} folder-count invariant: X=${check.xFolderCount} / leaves=${check.leafFolderCount}`);
  if (!check.matched) {
    if (check.missingLeaves.length > 0) {
      console.log(`   X 側にあって leaf 無し (${check.missingLeaves.length}): ${check.missingLeaves.slice(0, 5).join(', ')}${check.missingLeaves.length > 5 ? ' …' : ''}`);
    }
    if (check.extraneousLeaves.length > 0) {
      console.log(`   leaf があって X 側無し (${check.extraneousLeaves.length}): ${check.extraneousLeaves.slice(0, 5).join(', ')}${check.extraneousLeaves.length > 5 ? ' …' : ''}`);
    }
  }
}
