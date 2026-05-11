/**
 * `<vault>/<base>/<group>/<group>.md` を 1 グループ 1 枚 idempotent に書き出す。
 *
 * group の決定方法:
 *   `.x_bookmarks.json` から `row.group` の distinct を取る (`_Unfiled` 含む)。
 *
 * 振る舞い:
 *   - フォルダが無ければ作成 (mkdir -p)
 *   - MD が無ければ新規生成 (`renderGroupPage`)
 *   - MD が存在し sentinel 区間がある → その区間だけ差し替え (`replaceAutoBlock`)
 *   - sentinel 区間が無い → 末尾に追記 (ユーザー本文を保護)
 *
 * dry-run の場合は書き出しをスキップし、計画される更新内容を返す。
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot, getXBookmarksBaseFolder, isDryRun } from './config';
import {
  renderGroupPage,
  replaceAutoBlock,
  SENTINEL_START,
} from './x_group_page_template';
import {
  exportBookmarksJson,
  ExportedJson,
  buildExportPayload,
  X_JSON_FILENAME,
} from './x_bookmarks_json_export';

export interface GroupPageWriteResult {
  group: string;
  filePath: string;
  action: 'created' | 'updated' | 'unchanged' | 'dry-run';
}

interface WriteOptions {
  /** テスト注入用 */
  vaultRoot?: string;
  baseFolder?: string;
  /** 既にエクスポート済み payload を再利用したい場合に渡す (sync の二重 export を防ぐ) */
  payload?: ExportedJson;
}

/**
 * payload (JSON) から distinct group を抽出し、各 `<group>/<group>.md` を更新する。
 * 戻り値は各グループの処理結果。
 */
export function writeAllGroupPages(options: WriteOptions = {}): GroupPageWriteResult[] {
  const vaultRoot = options.vaultRoot ?? getVaultRoot();
  const baseFolder = options.baseFolder ?? getXBookmarksBaseFolder();
  const payload = options.payload ?? buildExportPayload({ baseFolder });

  const groups = new Set<string>();
  for (const r of payload.rows) groups.add(r.group);

  const jsonRel = path.posix.join(baseFolder, X_JSON_FILENAME);
  const results: GroupPageWriteResult[] = [];
  for (const group of groups) {
    results.push(writeSingleGroupPage({ vaultRoot, baseFolder, group, jsonRel }));
  }
  return results;
}

function writeSingleGroupPage(args: {
  vaultRoot: string;
  baseFolder: string;
  group: string;
  jsonRel: string;
}): GroupPageWriteResult {
  const { vaultRoot, baseFolder, group, jsonRel } = args;
  const dir = path.join(vaultRoot, baseFolder, group);
  const filePath = path.join(dir, `${group}.md`);

  if (isDryRun()) {
    return { group, filePath, action: 'dry-run' };
  }

  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, renderGroupPage({ group, jsonRelativePath: jsonRel }), 'utf8');
    return { group, filePath, action: 'created' };
  }

  const existing = fs.readFileSync(filePath, 'utf8');
  const updated = replaceAutoBlock(existing, { group, jsonRelativePath: jsonRel });
  if (updated === existing) {
    return { group, filePath, action: 'unchanged' };
  }
  fs.writeFileSync(filePath, updated, 'utf8');
  return {
    group,
    filePath,
    action: existing.includes(SENTINEL_START) ? 'updated' : 'updated',
  };
}

/**
 * JSON エクスポート + 全グループ MD 更新を 1 度のスキャンで実行する。
 * sync 末尾から呼ばれる。
 */
export function exportAndWriteAllGroupPages(): {
  jsonPath: string;
  pages: GroupPageWriteResult[];
} {
  const baseFolder = getXBookmarksBaseFolder();
  const payload = buildExportPayload({ baseFolder });
  const jsonPath = exportBookmarksJson({ baseFolder, payload });
  const pages = writeAllGroupPages({ baseFolder, payload });
  return { jsonPath, pages };
}
