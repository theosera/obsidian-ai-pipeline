/**
 * 脅威レポート ingest オーケストレータ。
 *
 * 流れ:
 *   1. .md ファイル読み込み
 *   2. frontmatter + 本文パース (parser が契約違反なら throw)
 *   3. SQLite に report + vulnerabilities を upsert
 *   4. JSON エクスポート (Dataview 用)
 *   5. index ページ再生成 (sentinel block 差し替え)
 *   6. Vault に raw markdown をアーカイブ (オプション)
 *
 * Gmail からのフェッチは **Claude Code 側 (このセッション)** が MCP 経由で
 * 行い、生 markdown をファイル化してからこの CLI を呼ぶ責務分担。
 *
 * 理由: Node ランタイム (`pnpm start`) は MCP に接続できない (MCP は IDE/Claude
 * Code 側のみで提供される)。CLI はファイル入力に専念し、Gmail 連携は別レイヤー
 * とする方が再利用性 (手動ダウンロード / 別 OAuth 経路) も担保できる。
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { getVaultRoot } from './config';
import { getThreatReportsBaseFolder, getThreatReportsArchiveFolder } from './threat_reports_config';
import { ThreatReportsDb, getDb } from './threat_reports_db';
import { parseReport, ContractError } from './threat_reports_parser';
import { exportThreatReportsJson } from './threat_reports_json_export';
import { regenerateIndexPage } from './threat_reports_index_writer';

export interface IngestOptions {
  /** ingest 対象の .md ファイルパス (絶対 or cwd 相対) */
  filePath: string;
  /** テスト注入用: 省略時は getDb() */
  db?: ThreatReportsDb;
  /** テスト注入用: 省略時は getVaultRoot() */
  vaultRoot?: string;
  /**
   * Vault アーカイブを行うかどうか。デフォルト true。
   * false なら DB と JSON / index のみ更新 (生 markdown は Vault に書かない)。
   */
  archive?: boolean;
  /**
   * source 文字列。Gmail 経由なら 'gmail:<message_id>'、手動なら 'file:<path>'。
   * 省略時は filePath から自動生成。
   */
  source?: string;
}

export interface IngestResult {
  reportId: string;
  weekOf: string;
  vulnerabilities: number;
  archivedPath: string | null;
  jsonPath: string;
  indexPath: string;
}

/**
 * 1 ファイルを ingest する。
 * 契約違反 (`ContractError`) や I/O エラーは throw する (caller で表示)。
 */
export async function ingestThreatReport(options: IngestOptions): Promise<IngestResult> {
  const filePath = path.resolve(options.filePath);
  if (!fs.existsSync(filePath)) {
    throw new Error(`脅威レポートファイルが見つかりません: ${filePath}`);
  }
  const markdown = fs.readFileSync(filePath, 'utf8');
  const parsed = parseReport(markdown);

  const db = options.db ?? getDb();
  const vaultRoot = options.vaultRoot ?? getVaultRoot();
  const source = options.source ?? `file:${path.basename(filePath)}`;
  // ID は (source + week_of) のハッシュ。同じ週次レポートを再 ingest しても同じ ID
  // になり upsert で衝突する → 重複行が増えない。
  const reportId = generateReportId(source, parsed.frontmatter.period_end);

  // 1. Vault アーカイブ (DB に vault_path を入れる前に書き出し成否を確定させる)
  let archivedPath: string | null = null;
  if (options.archive !== false) {
    archivedPath = archiveRawMarkdown(vaultRoot, parsed.frontmatter.period_end, markdown);
  }

  // 2. report 行 upsert
  db.upsertReport({
    id: reportId,
    source,
    receivedAt: new Date().toISOString(),
    weekOf: parsed.frontmatter.period_end,
    rawMarkdown: markdown,
    vaultPath: archivedPath
      ? path.relative(vaultRoot, archivedPath).replace(/\\/g, '/')
      : null,
    schemaVersion: parsed.frontmatter.schema_version,
    trustLevel: parsed.frontmatter.trust_level,
    reportType: parsed.frontmatter.report_type,
  });

  // 3. vulnerability セットを「最新パース結果」と完全同期 (upsert + 削除).
  //    同レポートの再 ingest で名前が消えた / 訂正された vuln が stale で
  //    残らないよう、1 トランザクションで delete-not-in + upsert する。
  db.syncReportVulnerabilities(
    reportId,
    parsed.vulnerabilities.map((vuln) => ({
      reportId,
      name: vuln.name,
      category: vuln.category,
      affected: vuln.affected,
      impact: vuln.impact,
      exploitability: vuln.exploitability,
      riskScore: vuln.risk_score,
      status: vuln.status,
      technicalSummary: vuln.technical_summary,
      businessImpact: vuln.business_impact,
      mitigations: vuln.mitigations,
    }))
  );

  // 4. JSON エクスポート + index ページ再生成
  const jsonPath = exportThreatReportsJson({ db, vaultRoot });
  const indexPath = regenerateIndexPage({ vaultRoot });

  return {
    reportId,
    weekOf: parsed.frontmatter.period_end,
    vulnerabilities: parsed.vulnerabilities.length,
    archivedPath,
    jsonPath,
    indexPath,
  };
}

/**
 * report ID は source + week_of の安定ハッシュ。同じソース・同じ週の再 ingest は
 * 同 ID になり UPSERT で衝突 → DB 行が増えない (= 取り込み冪等性が保たれる)。
 *
 * 別ソース (例: 同じ週次レポートを Gmail と手動ファイル両方から取り込む) は
 * 別 ID で別行になる。これは「同一レポートの異なる経路を別記録として残す」
 * 設計判断。重複が嫌なら ID を week_of のみのハッシュにすれば収束させられる。
 */
function generateReportId(source: string, weekOf: string): string {
  const hash = crypto.createHash('sha256').update(`${source}::${weekOf}`).digest('hex');
  return hash.slice(0, 16);
}

/**
 * Vault に raw markdown を `<base>/raw/<YYYY-MM-DD>.md` として保存。
 *
 * 同名ファイルがあれば上書き (= 同じ週のレポートが parser 改良で再 ingest
 * されても 1 ファイルにまとまる)。
 */
function archiveRawMarkdown(vaultRoot: string, weekOf: string, markdown: string): string {
  const archiveDir = path.join(vaultRoot, getThreatReportsArchiveFolder());
  if (!fs.existsSync(archiveDir)) fs.mkdirSync(archiveDir, { recursive: true });
  const outPath = path.join(archiveDir, `${weekOf}.md`);
  const tmpPath = outPath + '.tmp';
  fs.writeFileSync(tmpPath, markdown, 'utf8');
  fs.renameSync(tmpPath, outPath);
  return outPath;
}

export { ContractError };
export { getThreatReportsBaseFolder };
