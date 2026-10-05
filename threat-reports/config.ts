/**
 * 脅威レポート用 Vault パス設定。
 *
 * X bookmarks の `getXBookmarksBaseFolder()` パターンと揃える。
 * 環境変数で上書き可能だが、デフォルトの 1 箇所運用を推奨。
 */

import path from 'path';

const DEFAULT_BASE = 'Permanent Note/10_Threat_Reports';
const ARCHIVE_SUBDIR = 'raw';
/**
 * Vault へ保存する原文は Markdown として実行させない。
 * `.md.txt` にして bytes を一切変えず保存することで、Obsidian/Dataview の
 * `dataviewjs` codeblock post processor の対象外にする (security scan F2)。
 */
export const THREAT_REPORT_ARCHIVE_SUFFIX = '.md.txt';

/**
 * Vault 内の脅威レポート格納フォルダ (相対パス)。
 * `<vault>/<base>/_index.md` と `<vault>/<base>/.threat_reports.json` が住む場所。
 *
 * `THREAT_REPORTS_FOLDER` env で上書き可能だが、絶対パス (`/etc/...`) や
 * traversal (`..`) を含む値は Vault 外への書き出しを許してしまうため拒否し
 * DEFAULT_BASE にフォールバックする。
 */
export function getThreatReportsBaseFolder(): string {
  const raw = process.env.THREAT_REPORTS_FOLDER;
  if (!raw) return DEFAULT_BASE;

  const normalized = path.posix.normalize(raw.replace(/\\/g, '/'));
  const isAbsolute = path.isAbsolute(raw) || normalized.startsWith('/');
  const hasTraversal = normalized.split('/').some((seg) => seg === '..');
  if (isAbsolute || hasTraversal || normalized === '.' || normalized === '') {
    console.warn(
      `⚠️  THREAT_REPORTS_FOLDER="${raw}" は不正 (絶対パス / traversal / 空) — DEFAULT (${DEFAULT_BASE}) を使用。`
    );
    return DEFAULT_BASE;
  }
  return normalized;
}

/** raw report archive の相対ディレクトリ。 */
export function getThreatReportsArchiveFolder(): string {
  return `${getThreatReportsBaseFolder()}/${ARCHIVE_SUBDIR}`;
}

/**
 * 1週分の raw report filename。
 *
 * `.md.txt` は意図的。原文は完全保存するが Markdown renderer / DataviewJS に
 * 実行対象として渡さない。parser/rebuild は拡張子に依存せず本文を読む。
 */
export function getThreatReportArchiveFilename(weekOf: string): string {
  return `${weekOf}${THREAT_REPORT_ARCHIVE_SUFFIX}`;
}
