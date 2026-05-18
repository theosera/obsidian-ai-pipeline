/**
 * 1 グループ 1 MD ページに埋め込む dataviewjs テンプレート。
 *
 * Obsidian の Dataview コミュニティプラグインを前提とする (README 参照)。
 * 各グループ MD の `<group>/<group>.md` にこのテンプレートを sentinel
 * (`<!-- x-bookmarks:auto:start -->` ... `<!-- x-bookmarks:auto:end -->`)
 * で囲って書き出す。再生成時はその間だけを差し替え、外側のユーザー記述は保護する。
 *
 * テーブル仕様:
 *   - 列は固定 (AI 要約プロデューサー未実装でも `summary` 列を確保):
 *     published / added / author / tweet / likes / replies / summary / url
 *   - 列ヘッダクリックで昇順/降順トグル (Excel / Google Sheets 風)
 *   - 現ソート列に ▲ / ▼ を表示
 *   - 初期ソート: `added` (DB 取り込み順) の降順
 *   - 数値列は数値比較、文字列列は localeCompare
 *
 * `dv.io.load()` で読む JSON は `<base>/.x_bookmarks.json` (vault-relative)。
 */

export const SENTINEL_START = '<!-- x-bookmarks:auto:start -->';
export const SENTINEL_END = '<!-- x-bookmarks:auto:end -->';

interface RenderArgs {
  /** グループ名 (例: "Claude Code"). dataviewjs 内では実行時に file.folder から再抽出する */
  group: string;
  /** vault-relative path of the JSON DB (例: "X_Bookmarks/.x_bookmarks.json") */
  jsonRelativePath: string;
}

/**
 * `<group>.md` 全体を返す (sentinel 込み)。
 * 既存ファイルに sentinel 区間がある場合は `replaceAutoBlock()` で部分置換に使う。
 */
export function renderGroupPage(args: RenderArgs): string {
  const auto = renderAutoBlock(args);
  return `# ${args.group}\n\n${auto}\n`;
}

/**
 * sentinel で囲まれた自動生成ブロックだけを返す (テンプレート本体)。
 *
 * dataviewjs 側では、ページのフォルダ名から `group` を再抽出する。これにより
 * ユーザーがフォルダをリネームしてもテンプレ生成 = 表示 = フォルダ実態が一致する。
 */
export function renderAutoBlock(args: RenderArgs): string {
  const safeJsonPath = args.jsonRelativePath.replace(/\\/g, '/');
  // dataviewjs ブロック内の JS は **ランタイムで Obsidian の dataview コンテキスト
  // (dv, dv.container, dv.io, dv.current) に依存する**。ここでは文字列として
  // テンプレ生成しているだけなので、TS の型チェックは通らないがそれで OK。
  const lines = [
    SENTINEL_START,
    '```dataviewjs',
    `const data = JSON.parse(await dv.io.load("${safeJsonPath}"));`,
    'const folder = dv.current().file.folder.split("/").pop();',
    'const rows = (data.rows || []).filter(r => r.group === folder);',
    '',
    '// 列定義 — key は JSON のフィールド名、numeric は数値比較フラグ。',
    '// 列追加時は columns[] に push するだけ (テンプレ再描画は自動)。',
    'const columns = [',
    '  { key: "created_at",         label: "published", numeric: false, render: r => (r.created_at || "").slice(0, 10) },',
    '  { key: "added_at",           label: "added",     numeric: false, render: r => (r.added_at   || "").slice(0, 10) },',
    '  { key: "author",             label: "author",    numeric: false, render: r => r.author || "" },',
    '  { key: "tweet_text",         label: "tweet",     numeric: false, render: r => (r.tweet_text || "").slice(0, 280) },',
    '  { key: "engagement_likes",   label: "likes",     numeric: true,  render: r => r.engagement_likes ?? 0 },',
    '  { key: "engagement_replies", label: "replies",   numeric: true,  render: r => r.engagement_replies ?? 0 },',
    '  { key: "ai_summary",         label: "summary",   numeric: false, render: r => r.ai_summary || "" },',
    '  { key: "url",                label: "url",       numeric: false, render: r => r.url ? "link" : "" },',
    '];',
    '',
    '// 初期ソート: 追加日の降順 (新しいものを上に)',
    'let sortKey = "added_at";',
    'let sortDesc = true;',
    '',
    'function compare(a, b, col) {',
    '  const av = a[col.key];',
    '  const bv = b[col.key];',
    '  if (av == null && bv == null) return 0;',
    '  if (av == null) return 1;',
    '  if (bv == null) return -1;',
    '  if (col.numeric) return Number(av) - Number(bv);',
    '  return String(av).localeCompare(String(bv));',
    '}',
    '',
    'const root = dv.container.createDiv({ cls: "x-bookmarks-sortable" });',
    'function render() {',
    '  root.empty();',
    '  const col = columns.find(c => c.key === sortKey) || columns[0];',
    '  const sorted = [...rows].sort((a, b) => {',
    '    const cmp = compare(a, b, col);',
    '    return sortDesc ? -cmp : cmp;',
    '  });',
    '  const table = root.createEl("table", { cls: "dataview" });',
    '  table.style.width = "100%";',
    '  const thead = table.createEl("thead");',
    '  const headTr = thead.createEl("tr");',
    '  for (const c of columns) {',
    '    const arrow = c.key === sortKey ? (sortDesc ? " ▼" : " ▲") : "";',
    '    const th = headTr.createEl("th", { text: c.label + arrow });',
    '    th.style.cursor = "pointer";',
    '    th.style.userSelect = "none";',
    '    th.onclick = () => {',
    '      if (c.key === sortKey) sortDesc = !sortDesc;',
    '      else { sortKey = c.key; sortDesc = true; }',
    '      render();',
    '    };',
    '  }',
    '  const tbody = table.createEl("tbody");',
    '  for (const r of sorted) {',
    '    const tr = tbody.createEl("tr");',
    '    for (const c of columns) {',
    '      const td = tr.createEl("td");',
    '      if (c.key === "url" && r.url) {',
    '        const a = td.createEl("a", { text: "link", href: r.url });',
    '        a.setAttribute("target", "_blank");',
    '        a.setAttribute("rel", "noopener");',
    '      } else if (c.key === "tweet_text") {',
    '        td.setText(String(c.render(r)));',
    '        td.style.maxWidth = "32em";',
    '        td.style.whiteSpace = "normal";',
    '      } else {',
    '        td.setText(String(c.render(r)));',
    '      }',
    '    }',
    '  }',
    '  // 件数表示',
    '  root.createEl("div", { text: `${sorted.length} 件`, cls: "x-bookmarks-count" });',
    '}',
    'render();',
    '```',
    SENTINEL_END,
  ];
  return lines.join('\n');
}

/**
 * 既存 `<group>.md` 内の sentinel 区間を新しい auto block で差し替える。
 *
 * sentinel が無い場合 = ユーザーが手書きで MD を作っていた、または最初の生成。
 * その場合は末尾に追記する (ユーザー本文は前段に残す)。
 */
export function replaceAutoBlock(existing: string, args: RenderArgs): string {
  const auto = renderAutoBlock(args);
  const startIdx = existing.indexOf(SENTINEL_START);
  const endIdx = existing.indexOf(SENTINEL_END);
  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) {
    // sentinel 無し: 末尾に追記
    const trimmed = existing.replace(/\s+$/, '');
    return `${trimmed}\n\n${auto}\n`;
  }
  const before = existing.slice(0, startIdx);
  const after = existing.slice(endIdx + SENTINEL_END.length);
  return `${before}${auto}${after}`;
}
