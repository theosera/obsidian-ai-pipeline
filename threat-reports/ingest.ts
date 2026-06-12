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
import { getVaultRoot } from '../config';
import { getThreatReportsBaseFolder, getThreatReportsArchiveFolder } from './config';
import { ThreatReportsDb, getDb } from './db';
import { parseReport, ContractError } from './parser';
import { exportThreatReportsJson } from './json_export';
import { regenerateIndexPage } from './index_writer';

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
  implementationChecks: number;
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

  // 4. implementation_checks (Section 4 新形式) の同期。
  //    parsed.implementation_checks の値:
  //      - null  : Section 4 ヘッダなし (旧フォーマット報告) → **sync しない**。
  //                既存 DB 行と人手 `ai_relevance_note` を温存する。
  //      - []    : ヘッダはあったが行 0 (当週「観点なし」を明示) → sync する
  //                (= 既存行を全削除する)。
  //      - [...] : 通常 → sync する (delete-not-in + upsert)。
  //    null と [] を区別しないと、旧フォーマット再 ingest で人手ノートが
  //    全消去される (PR #55 Codex P2 指摘)。
  if (parsed.implementation_checks !== null) {
    db.syncReportImplementationChecks(
      reportId,
      parsed.implementation_checks.map((c) => ({
        reportId,
        perspective: c.perspective,
        pattern: c.pattern,
        warningSigns: c.warning_signs,
        recommendation: c.recommendation,
      }))
    );
  }

  // 5. JSON エクスポート + index ページ再生成
  const jsonPath = exportThreatReportsJson({ db, vaultRoot });
  const indexPath = regenerateIndexPage({ vaultRoot });

  return {
    reportId,
    weekOf: parsed.frontmatter.period_end,
    vulnerabilities: parsed.vulnerabilities.length,
    // null (Section 4 absent) は 0 として報告 (DB は触っていない)
    implementationChecks: parsed.implementation_checks?.length ?? 0,
    archivedPath,
    jsonPath,
    indexPath,
  };
}

export interface RebuildResult {
  /** 走査した raw アーカイブディレクトリ (絶対パス) */
  rawDir: string;
  /** 見つかった `.md` 件数 */
  filesFound: number;
  /** 再構築できたレポート行数 */
  reportsRebuilt: number;
  /** 再構築した vulnerability 行の合計 */
  vulnerabilities: number;
  /** 再構築した implementation_check 行の合計 */
  implementationChecks: number;
  /** パース/契約違反等で取り込めなかったファイル */
  skipped: Array<{ file: string; reason: string }>;
  jsonPath: string;
  indexPath: string;
}

/**
 * `raw/<week>.md` を唯一の真実として threat_reports DB を作り直す。
 *
 * ヘッダコメントが長らく謳ってきた「壊れたら .md から再構築可能 (rebuildFromVault)」を
 * 実装したもの。破損退避 (`<file>.corrupted_*`) や手動 DB 削除のあとに、Vault に
 * 残る生 markdown から派生インデックスを復元する**明示的な復旧コマンド**。
 *
 * ⚠️ **復元されないフィールド** (= raw markdown に存在しない human 入力):
 *   - `vulnerabilities.ai_relevance_note` / `implementation_checks.ai_relevance_note`
 *   - `reports.relevance_reviewed_at`
 *   これらは DB のみが持つため、再構築後は空に戻る。退避された
 *   `<file>.corrupted_*` が開ければそちらから手動サルベージする必要がある。
 *   この破壊性ゆえ、本処理は破損時に**自動起動しない** (CLI から明示実行)。
 *
 * source は raw ファイル名から決定論的に再導出する (元の `gmail:<id>` は失われるが、
 * 再構築 ID の安定性 = 同じ raw を 2 度 rebuild しても同じ行、は保たれる)。
 */
export async function rebuildThreatReportsDbFromVault(options?: {
  /** テスト注入用: 省略時は getDb() */
  db?: ThreatReportsDb;
  /** テスト注入用: 省略時は getVaultRoot() */
  vaultRoot?: string;
}): Promise<RebuildResult> {
  const db = options?.db ?? getDb();
  const vaultRoot = options?.vaultRoot ?? getVaultRoot();
  const rawDir = path.join(vaultRoot, getThreatReportsArchiveFolder());

  // 1. 既存行を全削除。reports を消すと vulnerabilities / implementation_checks は
  //    ON DELETE CASCADE で連動削除される。raw/*.md だけを真実として作り直すため、
  //    raw が消えた孤児レポートもここで落ちる。
  for (const r of db.listReports()) db.deleteReport(r.id);

  // 2. raw/*.md を列挙 (週順で安定させるためソート)。
  const files = fs.existsSync(rawDir)
    ? fs.readdirSync(rawDir).filter((f) => f.endsWith('.md')).sort()
    : [];

  let reportsRebuilt = 0;
  let vulnerabilities = 0;
  let implementationChecks = 0;
  const skipped: Array<{ file: string; reason: string }> = [];

  // 3. 各 raw を再 ingest。archive=true (既定) のまま再アーカイブする:
  //    ingestThreatReport は archive 実行時のみ reports.vault_path を埋めるため、
  //    archive=false にすると再構築行の vault_path が null になり JSON の
  //    raw_md_path も null = 元レポートへのリンクが切れる (Codex #82 P2)。
  //    raw/<week>.md への書き戻しは tmp→rename の冪等上書き (内容は ingest 冒頭で
  //    メモリ読込済みなので同一パスでも安全) で、archive パスを正しく記録する。
  //    1 ファイルの契約違反 (ContractError) / I/O 失敗で全体を止めず、その 1 件だけ
  //    skip して残りを復元する (部分復旧 > 全失敗)。
  for (const file of files) {
    try {
      const res = await ingestThreatReport({
        filePath: path.join(rawDir, file),
        db,
        vaultRoot,
        source: `file:${file}`,
      });
      reportsRebuilt += 1;
      vulnerabilities += res.vulnerabilities;
      implementationChecks += res.implementationChecks;
    } catch (err: unknown) {
      skipped.push({ file, reason: err instanceof Error ? err.message : String(err) });
    }
  }

  // 4. 0 ファイル / 全 skip でも JSON / index を最新 DB 状態 (= 空) に揃える。
  //    ingestThreatReport は成功毎に再生成するが、ここで最後に必ず 1 回実行して
  //    「古い JSON が残ったまま DB だけ空」というズレを防ぐ。
  const jsonPath = exportThreatReportsJson({ db, vaultRoot });
  const indexPath = regenerateIndexPage({ vaultRoot });

  return {
    rawDir,
    filesFound: files.length,
    reportsRebuilt,
    vulnerabilities,
    implementationChecks,
    skipped,
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
