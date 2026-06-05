/**
 * 週次 LLM 攻撃ベクター脅威レポート用 SQLite メタデータストア。
 *
 * 設計思想:
 *   - 生レポート (.md) が source of truth、本 DB は派生インデックス
 *   - 用途: 横串検索 / リスクスコア順表示 / 過去レポートとの差分
 *   - 壊れたら raw/*.md から再構築できる:
 *     `threat_reports_ingest.ts::rebuildThreatReportsDbFromVault()`
 *     (CLI: `--rebuild-threat-reports-db`)。ただし ai_relevance_note /
 *     relevance_reviewed_at は raw に無い human 入力なので再構築では復元されない。
 *
 * ファイル配置:
 *   <vault>/__skills/pipeline/threat_reports.db   ← .gitignore 対象 (派生データ)
 *
 * テーブル設計:
 *   reports          1 行 = 1 週次レポート (1 通のメール / 1 ファイル)
 *   vulnerabilities  1 行 = レポート内の個別脆弱性 (1 レポート = 通常 5 行)
 *
 * テストでは `new ThreatReportsDb(':memory:')` で in-memory DB を生成。
 */

import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { getVaultRoot } from './config';

export interface ReportRow {
  id: string;                  // ingest 時に生成する uuid 風 ID
  source: string;              // 'gmail:<message_id>' / 'file:<path>' / 'paste'
  received_at: string;         // ISO 8601 (メール受信時刻 or 取り込み時刻)
  week_of: string;             // 'YYYY-MM-DD' (frontmatter.period_end)
  raw_markdown: string;        // 原文そのまま (再パース可能性のため必ず保持)
  vault_path: string | null;   // Vault 内アーカイブパス (null なら未保存)
  /**
   * Frontmatter 契約 (ChatGPT/Codex 側で出力時に必ず付与):
   *   schema_version: 取り込みパーサの後方互換判定に使用
   *   trust_level: 'external_research_summary' を期待。それ以外は ingest 拒否
   *   report_type: 'llm_security_weekly' を期待
   * 本フィールドは「契約違反検知」のために DB に残す (= 後から監査可能)。
   */
  schema_version: number;
  trust_level: string | null;
  report_type: string | null;
  ingested_at: string;
}

export interface VulnerabilityRow {
  id: number;
  report_id: string;
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
  /**
   * 「自リポへの関連度コメント」— LLM や Claude セッションが手動で埋める列。
   * 例: 「x_bookmarks_summarizer.ts の sanitizeForLLM で対応済 (PR #51)」
   */
  ai_relevance_note: string | null;
  ingested_at: string;
}

/**
 * Section 4 「実装検証観点」(週次レポートの新形式) を表す行。
 * 1 レポート内で `perspective` (観点) が UNIQUE。
 *
 * `ai_relevance_note` は vuln 側と同じ運用 — 人手で「自リポでの対応状況」を
 * 書き、再 ingest しても上書きされない。
 */
export interface ImplementationCheckRow {
  id: number;
  report_id: string;
  perspective: string;
  pattern: string | null;
  warning_signs: string | null;
  recommendation: string | null;
  ai_relevance_note: string | null;
  ingested_at: string;
}

export interface ReportUpsertInput {
  id: string;
  source: string;
  receivedAt: string;
  weekOf: string;
  rawMarkdown: string;
  vaultPath?: string | null;
  schemaVersion?: number;
  trustLevel?: string | null;
  reportType?: string | null;
}

export interface VulnerabilityUpsertInput {
  reportId: string;
  name: string;
  category?: string | null;
  affected?: string | null;
  impact?: number | null;
  exploitability?: number | null;
  riskScore?: number | null;
  status?: string | null;
  technicalSummary?: string | null;
  businessImpact?: string | null;
  mitigations?: string | null;
}

export interface ImplementationCheckUpsertInput {
  reportId: string;
  perspective: string;
  pattern?: string | null;
  warningSigns?: string | null;
  recommendation?: string | null;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  received_at TEXT NOT NULL,
  week_of TEXT NOT NULL,
  raw_markdown TEXT NOT NULL,
  vault_path TEXT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  trust_level TEXT,
  report_type TEXT,
  ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_week ON reports(week_of);
CREATE INDEX IF NOT EXISTS idx_reports_source ON reports(source);
CREATE INDEX IF NOT EXISTS idx_reports_trust ON reports(trust_level);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  category TEXT,
  affected TEXT,
  impact INTEGER,
  exploitability INTEGER,
  risk_score REAL,
  status TEXT,
  technical_summary TEXT,
  business_impact TEXT,
  mitigations TEXT,
  ai_relevance_note TEXT,
  ingested_at TEXT NOT NULL,
  UNIQUE(report_id, name)
);
CREATE INDEX IF NOT EXISTS idx_vuln_score ON vulnerabilities(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_category ON vulnerabilities(category);
CREATE INDEX IF NOT EXISTS idx_vuln_report ON vulnerabilities(report_id);

CREATE TABLE IF NOT EXISTS implementation_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  perspective TEXT NOT NULL,
  pattern TEXT,
  warning_signs TEXT,
  recommendation TEXT,
  ai_relevance_note TEXT,
  ingested_at TEXT NOT NULL,
  UNIQUE(report_id, perspective)
);
CREATE INDEX IF NOT EXISTS idx_impl_report ON implementation_checks(report_id);
`;

export class ThreatReportsDb {
  private db: Database.Database;

  constructor(filePath: string) {
    this.db = new Database(filePath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.exec(SCHEMA);
  }

  upsertReport(input: ReportUpsertInput): void {
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO reports (
        id, source, received_at, week_of, raw_markdown, vault_path,
        schema_version, trust_level, report_type, ingested_at
      )
      VALUES (
        @id, @source, @received_at, @week_of, @raw_markdown, @vault_path,
        @schema_version, @trust_level, @report_type, @ingested_at
      )
      ON CONFLICT(id) DO UPDATE SET
        source = excluded.source,
        received_at = excluded.received_at,
        week_of = excluded.week_of,
        raw_markdown = excluded.raw_markdown,
        vault_path = excluded.vault_path,
        schema_version = excluded.schema_version,
        trust_level = excluded.trust_level,
        report_type = excluded.report_type
        -- ingested_at は INSERT 時のみ保持 (初回取り込み時刻)
    `).run({
      id: input.id,
      source: input.source,
      received_at: input.receivedAt,
      week_of: input.weekOf,
      raw_markdown: input.rawMarkdown,
      vault_path: input.vaultPath ?? null,
      schema_version: input.schemaVersion ?? 1,
      trust_level: input.trustLevel ?? null,
      report_type: input.reportType ?? null,
      ingested_at: now,
    });
  }

  /**
   * 同レポート (report_id) 内の脆弱性を name で UPSERT する。
   * 再 ingest 時に同名の vuln は内容が上書きされる (parser 改良の反映が容易になる)。
   * `ai_relevance_note` は **保持** する (人が書いたコメントを上書き再 ingest で失わない)。
   */
  upsertVulnerability(input: VulnerabilityUpsertInput): void {
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO vulnerabilities (
        report_id, name, category, affected, impact, exploitability, risk_score,
        status, technical_summary, business_impact, mitigations, ingested_at
      ) VALUES (
        @report_id, @name, @category, @affected, @impact, @exploitability, @risk_score,
        @status, @technical_summary, @business_impact, @mitigations, @ingested_at
      )
      ON CONFLICT(report_id, name) DO UPDATE SET
        category = excluded.category,
        affected = excluded.affected,
        impact = excluded.impact,
        exploitability = excluded.exploitability,
        risk_score = excluded.risk_score,
        status = excluded.status,
        technical_summary = excluded.technical_summary,
        business_impact = excluded.business_impact,
        mitigations = excluded.mitigations
        -- ai_relevance_note は触らない (人手コメント保護)
    `).run({
      report_id: input.reportId,
      name: input.name,
      category: input.category ?? null,
      affected: input.affected ?? null,
      impact: input.impact ?? null,
      exploitability: input.exploitability ?? null,
      risk_score: input.riskScore ?? null,
      status: input.status ?? null,
      technical_summary: input.technicalSummary ?? null,
      business_impact: input.businessImpact ?? null,
      mitigations: input.mitigations ?? null,
      ingested_at: now,
    });
  }

  /**
   * 同一 report の vulnerability セットを「最新パース結果」と完全同期する。
   *
   * 動作:
   *   1. `inputs` 各行を `upsertVulnerability` と同じ ON CONFLICT 規則で UPSERT
   *      (= 内容更新 / `ai_relevance_note` 保護)
   *   2. **同じ report_id で `inputs` に存在しない name の行を DELETE**
   *      → parser 改良で名前が変わった / 元レポートが訂正された場合に古い行が
   *      stale で残るのを防ぐ
   *   3. 1-2 を 1 トランザクションで実行 (途中失敗時は元の状態にロールバック)
   *
   * `inputs` が空配列なら report 内の vulnerability を全削除する (ただし parser
   * 側で 0 件は ContractError として弾くので通常パスでは起きない)。
   */
  syncReportVulnerabilities(reportId: string, inputs: VulnerabilityUpsertInput[]): void {
    const now = new Date().toISOString();
    const upsertStmt = this.db.prepare(`
      INSERT INTO vulnerabilities (
        report_id, name, category, affected, impact, exploitability, risk_score,
        status, technical_summary, business_impact, mitigations, ingested_at
      ) VALUES (
        @report_id, @name, @category, @affected, @impact, @exploitability, @risk_score,
        @status, @technical_summary, @business_impact, @mitigations, @ingested_at
      )
      ON CONFLICT(report_id, name) DO UPDATE SET
        category = excluded.category,
        affected = excluded.affected,
        impact = excluded.impact,
        exploitability = excluded.exploitability,
        risk_score = excluded.risk_score,
        status = excluded.status,
        technical_summary = excluded.technical_summary,
        business_impact = excluded.business_impact,
        mitigations = excluded.mitigations
        -- ai_relevance_note は触らない (人手コメント保護)
    `);

    const tx = this.db.transaction((rows: VulnerabilityUpsertInput[]) => {
      for (const input of rows) {
        // Guard: caller が誤って別 report の input を混ぜた場合に「UPSERT は
        // input.reportId へ、DELETE は scope の reportId からのみ」という
        // cross-report write が起きる。整合性を transaction 内で強制する。
        if (input.reportId !== reportId) {
          throw new Error(
            `syncReportVulnerabilities reportId mismatch: expected "${reportId}", got "${input.reportId}" (name="${input.name}")`
          );
        }
        upsertStmt.run({
          report_id: reportId,
          name: input.name,
          category: input.category ?? null,
          affected: input.affected ?? null,
          impact: input.impact ?? null,
          exploitability: input.exploitability ?? null,
          risk_score: input.riskScore ?? null,
          status: input.status ?? null,
          technical_summary: input.technicalSummary ?? null,
          business_impact: input.businessImpact ?? null,
          mitigations: input.mitigations ?? null,
          ingested_at: now,
        });
      }
      // DELETE は NOT IN で。空配列のときは「全削除」になるよう placeholder を
      // 1 つだけ NULL にして必ず外す。
      if (rows.length === 0) {
        this.db.prepare('DELETE FROM vulnerabilities WHERE report_id = ?').run(reportId);
      } else {
        const placeholders = rows.map(() => '?').join(', ');
        const params: (string | null)[] = [reportId, ...rows.map((r) => r.name)];
        this.db
          .prepare(`DELETE FROM vulnerabilities WHERE report_id = ? AND name NOT IN (${placeholders})`)
          .run(...params);
      }
    });
    tx(inputs);
  }

  /**
   * Section 4 「実装検証観点」を report 単位で完全同期。
   * vulnerabilities 側の syncReportVulnerabilities と同じ delete-not-in +
   * upsert + ai_relevance_note 保護のパターン。
   */
  syncReportImplementationChecks(reportId: string, inputs: ImplementationCheckUpsertInput[]): void {
    const now = new Date().toISOString();
    const upsertStmt = this.db.prepare(`
      INSERT INTO implementation_checks (
        report_id, perspective, pattern, warning_signs, recommendation, ingested_at
      ) VALUES (
        @report_id, @perspective, @pattern, @warning_signs, @recommendation, @ingested_at
      )
      ON CONFLICT(report_id, perspective) DO UPDATE SET
        pattern = excluded.pattern,
        warning_signs = excluded.warning_signs,
        recommendation = excluded.recommendation
        -- ai_relevance_note は触らない (人手コメント保護)
    `);

    const tx = this.db.transaction((rows: ImplementationCheckUpsertInput[]) => {
      for (const input of rows) {
        if (input.reportId !== reportId) {
          throw new Error(
            `syncReportImplementationChecks reportId mismatch: expected "${reportId}", got "${input.reportId}" (perspective="${input.perspective}")`
          );
        }
        upsertStmt.run({
          report_id: reportId,
          perspective: input.perspective,
          pattern: input.pattern ?? null,
          warning_signs: input.warningSigns ?? null,
          recommendation: input.recommendation ?? null,
          ingested_at: now,
        });
      }
      if (rows.length === 0) {
        this.db.prepare('DELETE FROM implementation_checks WHERE report_id = ?').run(reportId);
      } else {
        const placeholders = rows.map(() => '?').join(', ');
        const params: (string | null)[] = [reportId, ...rows.map((r) => r.perspective)];
        this.db
          .prepare(`DELETE FROM implementation_checks WHERE report_id = ? AND perspective NOT IN (${placeholders})`)
          .run(...params);
      }
    });
    tx(inputs);
  }

  listImplementationChecks(reportId?: string): ImplementationCheckRow[] {
    if (reportId) {
      return this.db.prepare(
        'SELECT * FROM implementation_checks WHERE report_id = ? ORDER BY perspective ASC'
      ).all(reportId) as ImplementationCheckRow[];
    }
    return this.db.prepare(
      'SELECT * FROM implementation_checks ORDER BY ingested_at DESC'
    ).all() as ImplementationCheckRow[];
  }

  /** Dataview 用にレポート JOIN 済みの全 implementation_check 行を返す。 */
  listImplementationChecksWithReport(): Array<ImplementationCheckRow & { week_of: string; vault_path: string | null }> {
    return this.db.prepare(`
      SELECT c.*, r.week_of, r.vault_path
      FROM implementation_checks c
      INNER JOIN reports r ON c.report_id = r.id
      ORDER BY r.week_of DESC, c.perspective ASC
    `).all() as Array<ImplementationCheckRow & { week_of: string; vault_path: string | null }>;
  }

  setImplementationCheckNote(reportId: string, perspective: string, note: string | null): void {
    this.db.prepare(
      'UPDATE implementation_checks SET ai_relevance_note = ? WHERE report_id = ? AND perspective = ?'
    ).run(note, reportId, perspective);
  }

  setRelevanceNote(reportId: string, name: string, note: string | null): void {
    this.db.prepare(
      'UPDATE vulnerabilities SET ai_relevance_note = ? WHERE report_id = ? AND name = ?'
    ).run(note, reportId, name);
  }

  getReport(id: string): ReportRow | undefined {
    return this.db.prepare('SELECT * FROM reports WHERE id = ?').get(id) as ReportRow | undefined;
  }

  listReports(): ReportRow[] {
    return this.db.prepare('SELECT * FROM reports ORDER BY week_of DESC, received_at DESC').all() as ReportRow[];
  }

  listVulnerabilities(reportId?: string): VulnerabilityRow[] {
    if (reportId) {
      return this.db.prepare(
        'SELECT * FROM vulnerabilities WHERE report_id = ? ORDER BY risk_score DESC, name ASC'
      ).all(reportId) as VulnerabilityRow[];
    }
    return this.db.prepare(
      'SELECT * FROM vulnerabilities ORDER BY risk_score DESC, ingested_at DESC'
    ).all() as VulnerabilityRow[];
  }

  /** Dataview 用にレポート JOIN 済みの全 vulnerability 行を返す。 */
  listVulnerabilitiesWithReport(): Array<VulnerabilityRow & { week_of: string; vault_path: string | null }> {
    return this.db.prepare(`
      SELECT v.*, r.week_of, r.vault_path
      FROM vulnerabilities v
      INNER JOIN reports r ON v.report_id = r.id
      ORDER BY r.week_of DESC, v.risk_score DESC
    `).all() as Array<VulnerabilityRow & { week_of: string; vault_path: string | null }>;
  }

  deleteReport(id: string): void {
    // foreign_keys=ON + ON DELETE CASCADE で vulnerabilities も自動削除される
    this.db.prepare('DELETE FROM reports WHERE id = ?').run(id);
  }

  close(): void {
    this.db.close();
  }
}

let _instance: ThreatReportsDb | null = null;

function getDbPath(): string {
  const dir = path.join(getVaultRoot(), '__skills', 'pipeline');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, 'threat_reports.db');
}

export function getDb(): ThreatReportsDb {
  if (_instance) return _instance;
  const filePath = getDbPath();
  try {
    _instance = new ThreatReportsDb(filePath);
  } catch (e: unknown) {
    if (fs.existsSync(filePath)) {
      const backup = filePath + '.corrupted_' + Date.now();
      fs.renameSync(filePath, backup);
      console.warn(`⚠️  threat_reports.db が破損していました。${backup} に退避し新規作成します。`);
      _instance = new ThreatReportsDb(filePath);
    } else {
      throw e;
    }
  }
  return _instance;
}

export function closeDb(): void {
  if (_instance) {
    _instance.close();
    _instance = null;
  }
}
