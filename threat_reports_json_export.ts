/**
 * 脅威レポート SQLite を Dataview 用 JSON にエクスポート。
 *
 * x_bookmarks_json_export.ts と同じパターン: SQLite は transactional な内部
 * キャッシュ、JSON は Obsidian 側で読まれる「読み取り専用ビュー」。
 *
 * 配置: `<vault>/<base>/.threat_reports.json`
 *   (`.` プレフィックスで Obsidian の通常ファイル一覧から外れる)
 */

import fs from 'fs';
import path from 'path';
import { getVaultRoot } from './config';
import { getThreatReportsBaseFolder } from './threat_reports_config';
import { ThreatReportsDb, getDb, VulnerabilityRow, ImplementationCheckRow } from './threat_reports_db';

export const THREAT_REPORTS_JSON_FILENAME = '.threat_reports.json';

export interface ExportedVulnerabilityRow {
  report_id: string;
  week_of: string;
  name: string;
  category: string | null;
  affected: string | null;
  impact: number | null;
  exploitability: number | null;
  risk_score: number | null;
  status: string | null;
  technical_summary: string | null;
  business_impact: string | null;
  mitigations: string | null;
  ai_relevance_note: string | null;
  /** Vault 内 raw markdown の相対パス。null なら未アーカイブ。 */
  raw_md_path: string | null;
}

/**
 * Section 4 「実装検証観点」エクスポート行 (Dataview 用)。
 */
export interface ExportedImplementationCheckRow {
  report_id: string;
  week_of: string;
  perspective: string;
  pattern: string | null;
  warning_signs: string | null;
  recommendation: string | null;
  ai_relevance_note: string | null;
  raw_md_path: string | null;
}

/**
 * レポート単位のメタ行 (Dataview / `/sec-review` 用)。`relevance_reviewed_at` が
 * 非 null なら該当性レビュー済み = `/sec-review` は次回以降スキップする。
 */
export interface ExportedReportRow {
  report_id: string;
  week_of: string;
  ingested_at: string;
  /** ISO 8601 / null=未レビュー。`/sec-review` が立てる「処理済みフラグ」。 */
  relevance_reviewed_at: string | null;
}

/**
 * JSON エクスポート全体。`version` は **JSON スキーマ自体のバージョン**で、
 * レポートの `schema_version` とは別物 (Dataview script との互換管理用)。
 *
 * version 2 で `implementation_checks` を、version 3 で `reports` (レポート単位の
 * レビュー済みフラグ) を追加。いずれも **追加のみ** なので、古い Dataview script
 * (`rows` のみ参照) は新フィールドを無視しても破綻しない。
 */
export interface ExportedJson {
  version: 3;
  generated_at: string;
  base_folder: string;
  rows: ExportedVulnerabilityRow[];
  implementation_checks: ExportedImplementationCheckRow[];
  reports: ExportedReportRow[];
}

interface ExportOptions {
  db?: ThreatReportsDb;
  vaultRoot?: string;
  baseFolder?: string;
}

export function buildExportPayload(options: ExportOptions = {}): ExportedJson {
  const db = options.db ?? getDb();
  const baseFolder = options.baseFolder ?? getThreatReportsBaseFolder();
  const rows = db.listVulnerabilitiesWithReport() as Array<
    VulnerabilityRow & { week_of: string; vault_path: string | null }
  >;
  const exported: ExportedVulnerabilityRow[] = rows.map(r => ({
    report_id: r.report_id,
    week_of: r.week_of,
    name: r.name,
    category: r.category,
    affected: r.affected,
    impact: r.impact,
    exploitability: r.exploitability,
    risk_score: r.risk_score,
    status: r.status,
    technical_summary: r.technical_summary,
    business_impact: r.business_impact,
    mitigations: r.mitigations,
    ai_relevance_note: r.ai_relevance_note,
    raw_md_path: r.vault_path,
  }));
  const checkRows = db.listImplementationChecksWithReport() as Array<
    ImplementationCheckRow & { week_of: string; vault_path: string | null }
  >;
  const exportedChecks: ExportedImplementationCheckRow[] = checkRows.map(c => ({
    report_id: c.report_id,
    week_of: c.week_of,
    perspective: c.perspective,
    pattern: c.pattern,
    warning_signs: c.warning_signs,
    recommendation: c.recommendation,
    ai_relevance_note: c.ai_relevance_note,
    raw_md_path: c.vault_path,
  }));
  const reports: ExportedReportRow[] = db.listReports().map(r => ({
    report_id: r.id,
    week_of: r.week_of,
    ingested_at: r.ingested_at,
    relevance_reviewed_at: r.relevance_reviewed_at,
  }));
  return {
    version: 3,
    generated_at: new Date().toISOString(),
    base_folder: baseFolder,
    rows: exported,
    implementation_checks: exportedChecks,
    reports,
  };
}

export function exportThreatReportsJson(options: ExportOptions = {}): string {
  const vaultRoot = options.vaultRoot ?? getVaultRoot();
  const baseFolder = options.baseFolder ?? getThreatReportsBaseFolder();
  const payload = buildExportPayload({ ...options, baseFolder });

  const dir = path.join(vaultRoot, baseFolder);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const outPath = path.join(dir, THREAT_REPORTS_JSON_FILENAME);
  const tmpPath = outPath + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), 'utf8');
  fs.renameSync(tmpPath, outPath);
  return outPath;
}
