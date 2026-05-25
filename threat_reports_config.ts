/**
 * 脅威レポート用 Vault パス設定。
 *
 * X bookmarks の `getXBookmarksBaseFolder()` パターンと揃える。
 * 環境変数で上書き可能だが、デフォルトの 1 箇所運用を推奨。
 */

const DEFAULT_BASE = 'Permanent Note/10_Threat_Reports';
const ARCHIVE_SUBDIR = 'raw';

/**
 * Vault 内の脅威レポート格納フォルダ (相対パス)。
 * `<vault>/<base>/_index.md` と `<vault>/<base>/.threat_reports.json` が住む場所。
 */
export function getThreatReportsBaseFolder(): string {
  return process.env.THREAT_REPORTS_FOLDER || DEFAULT_BASE;
}

/**
 * raw markdown アーカイブの相対パス。
 * `<vault>/<base>/<archive>/<YYYY-MM-DD>.md` に 1 週 1 ファイルで保存される。
 */
export function getThreatReportsArchiveFolder(): string {
  return `${getThreatReportsBaseFolder()}/${ARCHIVE_SUBDIR}`;
}
