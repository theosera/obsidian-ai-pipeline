/**
 * 脅威レポート Dataview インデックスページ writer。
 *
 * x-bookmarks/group_page_writer + x-bookmarks/group_page_template と同じ sentinel-bound 差し替え
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
    'const checks = data.implementation_checks || [];',
    '',
    'function compare(a, b, col) {',
    '  const av = col.sortValue ? col.sortValue(a) : a[col.key];',
    '  const bv = col.sortValue ? col.sortValue(b) : b[col.key];',
    '  if (av == null && bv == null) return 0;',
    '  if (av == null) return 1;',
    '  if (bv == null) return -1;',
    '  if (col.numeric) return Number(av) - Number(bv);',
    '  return String(av).localeCompare(String(bv));',
    '}',
    '',
    '// per-repo 該当性ノート ([{repo_key, note}]) を "repo: note  |  repo: note" に整形。',
    'function fmtNotes(arr) {',
    '  return (arr || []).filter(n => n && n.note).map(n => `${n.repo_key}: ${n.note}`).join("  |  ");',
    '}',
    '',
    '// ----- Table 1: 脆弱性リスト (Section 1) -----',
    'const vulnColumns = [',
    '  { key: "week_of",          label: "week",        numeric: false, render: r => r.week_of || "" },',
    '  { key: "risk_score",       label: "risk",        numeric: true,  render: r => r.risk_score == null ? "" : r.risk_score.toFixed(1) },',
    '  { key: "name",             label: "vulnerability", numeric: false, render: r => r.name || "" },',
    '  { key: "category",         label: "category",    numeric: false, render: r => r.category || "" },',
    '  { key: "affected",         label: "affected",    numeric: false, render: r => r.affected || "" },',
    '  { key: "impact",           label: "I",           numeric: true,  render: r => r.impact ?? "" },',
    '  { key: "exploitability",   label: "E",           numeric: true,  render: r => r.exploitability ?? "" },',
    '  { key: "status",           label: "status",      numeric: false, render: r => r.status || "" },',
    '  { key: "repo_notes",       label: "repo relevance", numeric: false, render: r => fmtNotes(r.repo_notes), sortValue: r => fmtNotes(r.repo_notes) },',
    '];',
    'let vulnSortKey = "week_of";',
    'let vulnSortDesc = true;',
    'dv.header(2, "Vulnerabilities");',
    'const vulnRoot = dv.container.createDiv({ cls: "threat-reports-sortable" });',
    'function renderVulns() {',
    '  vulnRoot.empty();',
    '  const col = vulnColumns.find(c => c.key === vulnSortKey) || vulnColumns[0];',
    '  const sorted = [...rows].sort((a, b) => {',
    '    const cmp = compare(a, b, col);',
    '    return vulnSortDesc ? -cmp : cmp;',
    '  });',
    '  const table = vulnRoot.createEl("table", { cls: "dataview" });',
    '  table.style.width = "100%";',
    '  const thead = table.createEl("thead");',
    '  const headTr = thead.createEl("tr");',
    '  for (const c of vulnColumns) {',
    '    const arrow = c.key === vulnSortKey ? (vulnSortDesc ? " ▼" : " ▲") : "";',
    '    const th = headTr.createEl("th", { text: c.label + arrow });',
    '    th.style.cursor = "pointer";',
    '    th.style.userSelect = "none";',
    '    th.onclick = () => {',
    '      if (c.key === vulnSortKey) vulnSortDesc = !vulnSortDesc;',
    '      else { vulnSortKey = c.key; vulnSortDesc = true; }',
    '      renderVulns();',
    '    };',
    '  }',
    '  const tbody = table.createEl("tbody");',
    '  for (const r of sorted) {',
    '    const tr = tbody.createEl("tr");',
    '    for (const c of vulnColumns) {',
    '      const td = tr.createEl("td");',
    '      td.setText(String(c.render(r)));',
    '      if (c.key === "name" || c.key === "affected" || c.key === "repo_notes") {',
    '        td.style.maxWidth = "24em";',
    '        td.style.whiteSpace = "normal";',
    '      }',
    '    }',
    '  }',
    '  vulnRoot.createEl("div", { text: `${sorted.length} vulnerabilities / 最終更新: ${data.generated_at}`, cls: "threat-reports-count" });',
    '}',
    'renderVulns();',
    '',
    '// ----- Table 2: 実装検証観点 (Section 4 / 新形式) -----',
    'if (checks.length > 0) {',
    '  const checkColumns = [',
    '    { key: "week_of",           label: "week",         numeric: false, render: r => r.week_of || "" },',
    '    { key: "perspective",       label: "perspective",  numeric: false, render: r => r.perspective || "" },',
    '    { key: "pattern",           label: "pattern",      numeric: false, render: r => r.pattern || "" },',
    '    { key: "warning_signs",     label: "warning signs", numeric: false, render: r => r.warning_signs || "" },',
    '    { key: "recommendation",    label: "recommendation", numeric: false, render: r => r.recommendation || "" },',
    '    { key: "repo_notes",        label: "repo relevance", numeric: false, render: r => fmtNotes(r.repo_notes), sortValue: r => fmtNotes(r.repo_notes) },',
    '  ];',
    '  let checkSortKey = "week_of";',
    '  let checkSortDesc = true;',
    '  dv.header(2, "Implementation review checklist");',
    '  const checkRoot = dv.container.createDiv({ cls: "threat-reports-sortable" });',
    '  function renderChecks() {',
    '    checkRoot.empty();',
    '    const col = checkColumns.find(c => c.key === checkSortKey) || checkColumns[0];',
    '    const sorted = [...checks].sort((a, b) => {',
    '      const cmp = compare(a, b, col);',
    '      return checkSortDesc ? -cmp : cmp;',
    '    });',
    '    const table = checkRoot.createEl("table", { cls: "dataview" });',
    '    table.style.width = "100%";',
    '    const thead = table.createEl("thead");',
    '    const headTr = thead.createEl("tr");',
    '    for (const c of checkColumns) {',
    '      const arrow = c.key === checkSortKey ? (checkSortDesc ? " ▼" : " ▲") : "";',
    '      const th = headTr.createEl("th", { text: c.label + arrow });',
    '      th.style.cursor = "pointer";',
    '      th.style.userSelect = "none";',
    '      th.onclick = () => {',
    '        if (c.key === checkSortKey) checkSortDesc = !checkSortDesc;',
    '        else { checkSortKey = c.key; checkSortDesc = true; }',
    '        renderChecks();',
    '      };',
    '    }',
    '    const tbody = table.createEl("tbody");',
    '    for (const r of sorted) {',
    '      const tr = tbody.createEl("tr");',
    '      for (const c of checkColumns) {',
    '        const td = tr.createEl("td");',
    '        td.setText(String(c.render(r)));',
    '        if (c.key === "pattern" || c.key === "warning_signs" || c.key === "recommendation" || c.key === "repo_notes") {',
    '          td.style.maxWidth = "24em";',
    '          td.style.whiteSpace = "normal";',
    '        }',
    '      }',
    '    }',
    '    checkRoot.createEl("div", { text: `${sorted.length} implementation checks`, cls: "threat-reports-count" });',
    '  }',
    '  renderChecks();',
    '}',
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
