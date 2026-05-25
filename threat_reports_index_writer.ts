/**
 * 脅威レポート Dataview インデックスページ writer。
 *
 * x_group_page_writer + x_group_page_template と同じ sentinel-bound 差し替え
 * パターン。ユーザーがページ上下に書き加えた本文は保護する。
 *
 * 配置: `<vault>/<base>/_index.md`
 *
 * テーブルは custom HTML + dataviewjs で `setText` 描画 (XSS なし)。
 * 列クリックでソート可能 (X bookmarks と同じ UX)。
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot } from './config';
import { getThreatReportsBaseFolder } from './threat_reports_config';
import { THREAT_REPORTS_JSON_FILENAME } from './threat_reports_json_export';

const SENTINEL_START = '<!-- threat-reports:auto-block:start -->';
const SENTINEL_END = '<!-- threat-reports:auto-block:end -->';

interface RenderArgs {
  baseFolder: string;
}

export function renderAutoBlock(args: RenderArgs): string {
  // JSON へのパスは index.md と同じディレクトリにあるので相対パスで十分。
  // Dataview の dv.io.load() は vault root 相対だが、ここは base 相対の方が
  // 設定変更に追従しやすい。
  const safeJsonPath = `${args.baseFolder}/${THREAT_REPORTS_JSON_FILENAME}`;
  const lines = [
    SENTINEL_START,
    '> このページは自動生成された脅威レポート横串インデックスです。',
    '> 表は列ヘッダクリックで昇順/降順ソートできます。',
    '> 個別レポート原文は `raw/<YYYY-MM-DD>.md` に保存されています。',
    '',
    '```dataviewjs',
    `const data = JSON.parse(await dv.io.load("${safeJsonPath}"));`,
    'const rows = data.rows || [];',
    '',
    'const columns = [',
    '  { key: "week_of",          label: "week",        numeric: false, render: r => r.week_of || "" },',
    '  { key: "risk_score",       label: "risk",        numeric: true,  render: r => r.risk_score == null ? "" : r.risk_score.toFixed(1) },',
    '  { key: "name",             label: "vulnerability", numeric: false, render: r => r.name || "" },',
    '  { key: "category",         label: "category",    numeric: false, render: r => r.category || "" },',
    '  { key: "affected",         label: "affected",    numeric: false, render: r => r.affected || "" },',
    '  { key: "impact",           label: "I",           numeric: true,  render: r => r.impact ?? "" },',
    '  { key: "exploitability",   label: "E",           numeric: true,  render: r => r.exploitability ?? "" },',
    '  { key: "status",           label: "status",      numeric: false, render: r => r.status || "" },',
    '  { key: "ai_relevance_note", label: "repo relevance", numeric: false, render: r => r.ai_relevance_note || "" },',
    '];',
    '',
    '// 初期ソート: 週新しい順 → リスクスコア降順',
    'let sortKey = "week_of";',
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
    'const root = dv.container.createDiv({ cls: "threat-reports-sortable" });',
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
    '      td.setText(String(c.render(r)));',
    '      if (c.key === "name" || c.key === "affected" || c.key === "ai_relevance_note") {',
    '        td.style.maxWidth = "24em";',
    '        td.style.whiteSpace = "normal";',
    '      }',
    '    }',
    '  }',
    '  root.createEl("div", { text: `${sorted.length} 件 / 最終更新: ${data.generated_at}`, cls: "threat-reports-count" });',
    '}',
    'render();',
    '```',
    SENTINEL_END,
  ];
  return lines.join('\n');
}

export function replaceAutoBlock(existing: string, args: RenderArgs): string {
  const auto = renderAutoBlock(args);
  const startIdx = existing.indexOf(SENTINEL_START);
  const endIdx = existing.indexOf(SENTINEL_END);
  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) {
    const trimmed = existing.replace(/\s+$/, '');
    return `${trimmed}\n\n${auto}\n`;
  }
  const before = existing.slice(0, startIdx);
  const after = existing.slice(endIdx + SENTINEL_END.length);
  return `${before}${auto}${after}`;
}

interface RegenerateOptions {
  vaultRoot?: string;
  baseFolder?: string;
}

const DEFAULT_HEADER = '# 🛡️ LLM Security Weekly — Cross-Report Index\n\n';

export function regenerateIndexPage(options: RegenerateOptions = {}): string {
  const vaultRoot = options.vaultRoot ?? getVaultRoot();
  const baseFolder = options.baseFolder ?? getThreatReportsBaseFolder();

  const dir = path.join(vaultRoot, baseFolder);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const outPath = path.join(dir, '_index.md');

  const existing = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8') : DEFAULT_HEADER;
  const updated = replaceAutoBlock(existing, { baseFolder });

  const tmpPath = outPath + '.tmp';
  fs.writeFileSync(tmpPath, updated, 'utf8');
  fs.renameSync(tmpPath, outPath);
  return outPath;
}
