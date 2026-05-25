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
import { ThreatReportsDb, getDb, VulnerabilityRow } from './threat_reports_db';

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

export interface ExportedJson {
  version: 1;
  generated_at: string;
  base_folder: string;
  rows: ExportedVulnerabilityRow[];
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
  return {
    version: 1,
    generated_at: new Date().toISOString(),
    base_folder: baseFolder,
    rows: exported,
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
