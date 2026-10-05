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
 * Untrusted Markdown は Obsidian に Markdown として解釈させない。
 * 内容は一切変えず、拡張子だけ `.md.txt` にして source-of-truth を保持する。
 */
export const THREAT_REPORT_ARCHIVE_SUFFIX = '.md.txt';
/** PR #181 以前の legacy archive。migration で `.md.txt` へ rename する。 */
export const LEGACY_THREAT_REPORT_ARCHIVE_SUFFIX = '.md';

export function getThreatReportArchiveFilename(weekOf: string): string {
  return `${weekOf}${THREAT_REPORT_ARCHIVE_SUFFIX}`;
}

export function isThreatReportArchiveFilename(name: string): boolean {
  return name.endsWith(THREAT_REPORT_ARCHIVE_SUFFIX) ||
    (name.endsWith(LEGACY_THREAT_REPORT_ARCHIVE_SUFFIX) && !name.endsWith(THREAT_REPORT_ARCHIVE_SUFFIX));
}

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

/**
 * raw Markdown payload の相対ディレクトリ。
 * 原文 bytes はそのまま `<vault>/<base>/<archive>/<YYYY-MM-DD>.md.txt` に保存する。
 * `.txt` 終端にすることで Obsidian/Dataview がレポート本文のコード fence を
 * 実行対象 Markdown として解釈しない。内容の復元性は失わない。
 */
export function getThreatReportsArchiveFolder(): string {
  return `${getThreatReportsBaseFolder()}/${ARCHIVE_SUBDIR}`;
}
