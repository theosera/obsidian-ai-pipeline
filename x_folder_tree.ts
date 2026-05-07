/**
 * X ブックマークフォルダ群を 2 階層 Tree に集約するビルダ + レンダラ。
 *
 * `--x-pick` の Stage 1 で使う。X API 側は親子の概念を持たない (フラットな folder
 * リスト) なので、本モジュールが既存の x_folder_mapper.ts のロジックを流用して
 * 親グループを合成する:
 *
 *   Tier 1 (forced):   x_forced_parents.json のキーワード単位でグルーピング
 *   Tier 2 (approved): x_folder_mapping.json の親パス先頭セグメント単位でグルーピング
 *   Tier 3 (dynamic):  detectCommonKeywords (3 フォルダ以上の共通キーワード)
 *   Tier 4 (orphan):   どの親にも入らなかったフォルダの寄せ集め
 *   Tier 5 (unfiled):  X 側の "どのフォルダにも未割当" 仮想グループ (常時表示)
 *
 * ID 体系:
 *   - 各グループに通番 [n]
 *   - サブフォルダは [n.m]
 *   - Unfiled も通常グループと同じ通番を割り振る (ユーザー指示)
 */

import {
  detectCommonKeywords,
  hasWordBoundaryMatch,
  stripKeyword,
} from './x_folder_mapper';

export type FolderGroupKind = 'forced' | 'approved' | 'dynamic' | 'orphan' | 'unfiled';

export interface FolderTreeChild {
  /** "1.2" のような番号 */
  index: string;
  /** X 側のフォルダ ID。unfiled グループのときは null */
  folderId: string | null;
  /** 表示名 (X 側 raw 名 / unfiled は "_Unfiled") */
  rawName: string;
  /** 親グループからの相対ラベル (親キーワードを除去した残り)。空なら親自身 */
  remainder: string;
}

export interface FolderTreeGroup {
  /** "1" のような番号 */
  index: string;
  kind: FolderGroupKind;
  /** 親フォルダ表示名 (Tier 1=キーワード / Tier 2=mapping パス先頭 / Tier 3=検出語 / Tier 4="(その他)" / Tier 5="_Unfiled") */
  label: string;
  /** 配下のサブフォルダ。unfiled は children=[] (グループ自身を選ぶと unfiled が拾われる) */
  children: FolderTreeChild[];
}

export interface FolderTree {
  groups: FolderTreeGroup[];
  /** 元データ件数 (orphan/unfiled 含む folder count) */
  totalFolders: number;
}

interface FolderInput {
  id: string;
  name: string;
}

/**
 * フォルダ ID/名 配列 + 設定 → 2 階層 Tree。
 *
 * - 各フォルダは「最初にマッチした親」に1回だけ所属させる (重複しない)
 * - グループ内のフォルダ並びは入力順 (X API の返り順) を維持
 * - グループの並びは Tier 1 → Tier 2 → Tier 3 → Tier 4 → Tier 5 (unfiled 固定末尾)
 */
export function buildFolderTree(
  folders: FolderInput[],
  forcedParents: string[],
  approvedMappings: Record<string, string>
): FolderTree {
  const assigned = new Set<string>(); // folder id ベースで重複防止
  const groups: FolderTreeGroup[] = [];

  // ---- Tier 1: forced parents ----
  // mapper と同じく長一致優先で「最長キーワード」が勝つ
  const sortedForced = [...forcedParents]
    .filter(k => k.trim().length > 0)
    .sort((a, b) => b.length - a.length);

  for (const keyword of sortedForced) {
    const matched = folders.filter(f =>
      !assigned.has(f.id) && hasWordBoundaryMatch(f.name, keyword)
    );
    if (matched.length === 0) continue;
    const children: FolderTreeChild[] = matched.map(f => {
      assigned.add(f.id);
      return {
        index: '',
        folderId: f.id,
        rawName: f.name,
        remainder: stripKeyword(f.name, keyword),
      };
    });
    groups.push({ index: '', kind: 'forced', label: keyword, children });
  }

  // ---- Tier 2: approved mappings ----
  // mapping value のパス先頭セグメントで再グルーピング
  const approvedGrouped = new Map<string, FolderTreeChild[]>();
  for (const f of folders) {
    if (assigned.has(f.id)) continue;
    const mapped = approvedMappings[f.name];
    if (!mapped) continue;
    const segments = mapped.split('/').filter(Boolean);
    const parent = segments[0] ?? f.name;
    const remainder = segments.slice(1).join('/');
    if (!approvedGrouped.has(parent)) approvedGrouped.set(parent, []);
    approvedGrouped.get(parent)!.push({
      index: '', folderId: f.id, rawName: f.name, remainder,
    });
    assigned.add(f.id);
  }
  for (const [parent, children] of approvedGrouped) {
    groups.push({ index: '', kind: 'approved', label: parent, children });
  }

  // ---- Tier 3: dynamic common keywords ----
  // detectCommonKeywords は forced で吸収済みのものを除外する仕様なので、
  // ここでは「未割当 (assigned に入っていない) フォルダだけ」を渡す。
  // また、既に Tier 2 で消費した label が誤って動的検出にも昇格するのを防ぐため、
  // 既存グループ全 label を擬似 forced として渡す。
  const remainingNames = folders
    .filter(f => !assigned.has(f.id))
    .map(f => f.name);
  const usedLabels = groups.map(g => g.label);
  const proposals = detectCommonKeywords(remainingNames, usedLabels);
  for (const p of proposals) {
    const matched = folders.filter(f =>
      !assigned.has(f.id) && p.folders.includes(f.name)
    );
    if (matched.length === 0) continue;
    const children: FolderTreeChild[] = matched.map(f => {
      assigned.add(f.id);
      return {
        index: '',
        folderId: f.id,
        rawName: f.name,
        remainder: stripKeyword(f.name, p.keyword),
      };
    });
    groups.push({ index: '', kind: 'dynamic', label: p.keyword, children });
  }

  // ---- Tier 4: orphan (どの親にも入らなかった) ----
  const orphans = folders.filter(f => !assigned.has(f.id));
  if (orphans.length > 0) {
    const children: FolderTreeChild[] = orphans.map(f => ({
      index: '', folderId: f.id, rawName: f.name, remainder: '',
    }));
    groups.push({ index: '', kind: 'orphan', label: '(その他)', children });
  }

  // ---- Tier 5: unfiled (常時表示) ----
  groups.push({
    index: '',
    kind: 'unfiled',
    label: '_Unfiled',
    children: [],
  });

  // 通番割り振り
  groups.forEach((g, i) => {
    g.index = String(i + 1);
    g.children.forEach((c, j) => {
      c.index = `${g.index}.${j + 1}`;
    });
  });

  return { groups, totalFolders: folders.length };
}

/**
 * 2 階層 Tree を端末向け ASCII 文字列にレンダリング。
 *
 *   [1] Claude Code  (強制親, 4)
 *       ├─ [1.1] Claude Code
 *       ├─ [1.2] Claude Code Tips
 *       └─ [1.3] Claude Code Hooks
 *   [2] _Unfiled  (フォルダ未割当)
 */
export function renderFolderTree(tree: FolderTree): string {
  const lines: string[] = [];
  lines.push(`🔖 X ブックマークフォルダ (合計 ${tree.totalFolders} フォルダ)`);
  lines.push('');

  for (const g of tree.groups) {
    const tag = groupKindTag(g.kind);
    if (g.kind === 'unfiled') {
      lines.push(`[${g.index}] _Unfiled  (${tag})`);
      continue;
    }
    lines.push(`[${g.index}] ${g.label}  (${tag}, ${g.children.length})`);
    g.children.forEach((c, i) => {
      const isLast = i === g.children.length - 1;
      const branch = isLast ? '└─' : '├─';
      const display = c.remainder
        ? `${c.rawName}  (= ${g.label}/${c.remainder})`
        : c.rawName;
      lines.push(`    ${branch} [${c.index}] ${display}`);
    });
    lines.push('');
  }

  lines.push('選択してください。複数指定はカンマ区切り。');
  lines.push('  例: 1            → グループ [1] の全サブフォルダ');
  lines.push('      1.2          → サブフォルダ [1.2] のみ');
  lines.push('      1, 3.1, 5    → 複合指定');
  lines.push('      1-3          → グループ範囲指定');
  lines.push('      all          → 全フォルダ + Unfiled');
  lines.push('      q            → 中止');
  return lines.join('\n');
}

function groupKindTag(kind: FolderGroupKind): string {
  switch (kind) {
    case 'forced': return '強制親';
    case 'approved': return 'マッピング';
    case 'dynamic': return '動的検出';
    case 'orphan': return '未グルーピング';
    case 'unfiled': return 'フォルダ未割当';
  }
}
