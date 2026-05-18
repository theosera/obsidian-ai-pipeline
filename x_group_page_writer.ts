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
  SENTINEL_END,
} from './x_group_page_template';
import {
  exportBookmarksJson,
  ExportedJson,
  buildExportPayload,
  X_JSON_FILENAME,
} from './x_bookmarks_json_export';

interface GroupPageWriteResult {
  group: string;
  filePath: string;
  /**
   * `created`   = ファイル新規作成
   * `updated`   = 既存ファイルの sentinel 区間を差し替え
   * `appended`  = sentinel 無し既存ファイルの末尾に追記
   * `unchanged` = 差分なし (idempotent)
   * `dry-run`   = dry-run モードで実書き出しをスキップ
   * `invalid-group` = group 名がパス安全条件を満たさず書き出しを拒否
   */
  action: 'created' | 'updated' | 'appended' | 'unchanged' | 'dry-run' | 'invalid-group';
}

/**
 * `group` がディレクトリセグメントとして安全か検査する。
 * deriveGroup() は通常 vault_path の先頭セグメントを返すだけなので、
 * `..` や `/` を含む値は理論上発生しないが、DB が壊れていたり別系統で
 * 値が注入された場合に path traversal を防ぐ最後の砦としてここで弾く。
 */
function isSafeGroupSegment(group: string): boolean {
  if (!group || group === '.' || group === '..') return false;
  if (group.includes('/') || group.includes('\\') || group.includes('\0')) return false;
  // path.sep を多重ガード (Windows パス上の \\?\ 等)
  if (group.includes(path.sep)) return false;
  return true;
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

  if (!isSafeGroupSegment(group)) {
    console.warn(`⚠️  [group-page-writer] 不正な group 名のためスキップ: ${JSON.stringify(group)}`);
    return { group, filePath: '', action: 'invalid-group' };
  }

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
  // `replaceAutoBlock` の判定ロジックと一致させる: start/end の両方が存在し、
  // かつ end が start より後にある well-formed なペアの時だけ 'updated'。
  // 半壊 (start のみ / 順序逆転) の場合は `replaceAutoBlock` 側が末尾追記する
  // ので 'appended' が観測実態と一致する。
  const startIdx = existing.indexOf(SENTINEL_START);
  const endIdx = existing.indexOf(SENTINEL_END);
  const hadSentinel = startIdx !== -1 && endIdx !== -1 && endIdx > startIdx;
  return { group, filePath, action: hadSentinel ? 'updated' : 'appended' };
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
