/**
 * 脅威レポート ingest オーケストレータ。
 *
 * 流れ:
 *   1. .md ファイル読み込み
 *   2. frontmatter + 本文パース (parser が契約違反なら throw)
 *   3. SQLite に report + vulnerabilities を upsert
 *   4. JSON エクスポート (Dataview 用)
 *   5. index ページ再生成 (sentinel block 差し替え)
 *   6. Vault に raw Markdown payload を非実行拡張子 (`.md.txt`) でアーカイブ (オプション)
 *
 * Gmail からのフェッチは **Claude Code 側 (このセッション)** が MCP 経由で
 * 行い、生 Markdown payload をファイル化してからこの CLI を呼ぶ責務分担。
 *
 * 理由: Node ランタイム (`pnpm start`) は MCP に接続できない (MCP は IDE/Claude
 * Code 側のみで提供される)。CLI はファイル入力に専念し、Gmail 連携は別レイヤー
 * とする方が再利用性 (手動ダウンロード / 別 OAuth 経路) も担保できる。
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { getVaultRoot } from '../config';
import {
  getThreatReportsBaseFolder,
  getThreatReportsArchiveFolder,
  getThreatReportArchiveFilename,
  THREAT_REPORT_ARCHIVE_SUFFIX,
  LEGACY_THREAT_REPORT_ARCHIVE_SUFFIX,
} from './config';
import { resolveVaultPath, isInsideVaultRealpath } from '../storage';
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
   * false なら DB と JSON / index のみ更新 (生 Markdown payload は Vault に書かない)。
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

  const db = options.db ?? getDb();
  const vaultRoot = options.vaultRoot ?? getVaultRoot();

  // F2: legacy raw/*.md 自体が input の場合、parser が拒否する本文でも
  // executable Markdown を Vault に残さない。本文は既に memory に読み込んで
  // あるので、契約パースより先に内容不変の .md.txt migration を行う。
  const migration = migrateLegacyThreatReportArchives({ db, vaultRoot });
  if (migration.migrated || migration.deduplicated || migration.dbPathsUpdated) {
    // parseReport() がこの後 ContractError で止まっても、既に変更した vault_path と
    // 派生 JSON/index を食い違わせない。
    exportThreatReportsJson({ db, vaultRoot });
    regenerateIndexPage({ vaultRoot });
  }

  const parsed = parseReport(markdown);
  const source = options.source ?? canonicalFileSource(filePath, vaultRoot);
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

export interface RawArchiveMigrationResult {
  /** legacy `.md` から `.md.txt` へ rename した件数。 */
  migrated: number;
  /** 既に同一内容の `.md.txt` があり legacy 側だけ削除した件数。 */
  deduplicated: number;
  /** reports.vault_path を新しい拡張子へ追随させた行数。 */
  dbPathsUpdated: number;
}

/**
 * PR #181 より前の `raw/<week>.md` を `raw/<week>.md.txt` へ安全に移行する。
 *
 * - 本文 bytes は変更しない。拡張子だけを変えるので完全に可逆。
 * - `.md` と `.md.txt` が両方存在し、内容が違う場合は何も変更せず fail-closed。
 * - symlink / 非 regular file は拒否する。
 * - DB は `vault_path` だけを限定更新し、人手 note / review 状態には触れない。
 */
export function migrateLegacyThreatReportArchives(options?: {
  db?: ThreatReportsDb;
  vaultRoot?: string;
}): RawArchiveMigrationResult {
  const db = options?.db ?? getDb();
  const vaultRoot = options?.vaultRoot ?? getVaultRoot();
  const rawDir = path.join(vaultRoot, getThreatReportsArchiveFolder());
  if (!fs.existsSync(rawDir)) {
    return { migrated: 0, deduplicated: 0, dbPathsUpdated: 0 };
  }
  if (!isInsideVaultRealpath(rawDir, vaultRoot)) {
    throw new Error(`raw archive dir が vault 外 (symlink?): ${rawDir}`);
  }

  const allEntries = fs.readdirSync(rawDir);
  const legacyFiles = allEntries
    .filter((name) => /^\d{4}-\d{2}-\d{2}\.md$/.test(name))
    .sort();
  const existingInertFiles = allEntries
    .filter((name) => /^\d{4}-\d{2}-\d{2}\.md\.txt$/.test(name))
    .sort();

  // 先に既存 inert archive を全件 preflight。legacy と無関係な .md.txt に
  // symlink/非 regular file が混じっていても、1件も rename する前に停止する。
  for (const file of existingInertFiles) {
    const targetPath = path.join(rawDir, file);
    const targetStat = fs.lstatSync(targetPath);
    if (!targetStat.isFile() || targetStat.isSymbolicLink()) {
      throw new Error(`新形式 raw archive が regular file でない: ${targetPath}`);
    }
  }

  // legacy/new の内容 conflict も全件 preflight。途中まで rename してから
  // conflict を見つける状態を作らない。
  for (const file of legacyFiles) {
    const legacyPath = path.join(rawDir, file);
    const targetPath = path.join(
      rawDir,
      file.slice(0, -LEGACY_THREAT_REPORT_ARCHIVE_SUFFIX.length) + THREAT_REPORT_ARCHIVE_SUFFIX
    );
    const legacyStat = fs.lstatSync(legacyPath);
    if (!legacyStat.isFile() || legacyStat.isSymbolicLink()) {
      throw new Error(`legacy raw archive が regular file でない: ${legacyPath}`);
    }
    if (fs.existsSync(targetPath)) {
      if (!fs.readFileSync(legacyPath).equals(fs.readFileSync(targetPath))) {
        throw new Error(
          `legacy/new raw archive conflict (内容が異なるため移行停止): ${file} / ${path.basename(targetPath)}`
        );
      }
    }
  }

  let migrated = 0;
  let deduplicated = 0;
  for (const file of legacyFiles) {
    const legacyPath = path.join(rawDir, file);
    const targetName =
      file.slice(0, -LEGACY_THREAT_REPORT_ARCHIVE_SUFFIX.length) + THREAT_REPORT_ARCHIVE_SUFFIX;
    const targetPath = path.join(rawDir, targetName);
    if (fs.existsSync(targetPath)) {
      fs.unlinkSync(legacyPath);
      deduplicated++;
    } else {
      fs.renameSync(legacyPath, targetPath);
      migrated++;
    }
  }

  // DB 更新が rename 後に失敗しても、次回は既存 .md.txt を列挙して stale path を
  // 修復できるよう reconciliation を独立して行う。これにより migration は retry-safe。
  let dbPathsUpdated = 0;
  const inertFiles = fs.readdirSync(rawDir)
    .filter((name) => /^\d{4}-\d{2}-\d{2}\.md\.txt$/.test(name))
    .sort();
  for (const file of inertFiles) {
    const targetPath = path.join(rawDir, file);
    const targetStat = fs.lstatSync(targetPath);
    if (!targetStat.isFile() || targetStat.isSymbolicLink()) {
      throw new Error(`新形式 raw archive が regular file でない: ${targetPath}`);
    }
    const legacyName = file.slice(0, -'.txt'.length);
    const legacyPath = path.join(rawDir, legacyName);
    const oldRel = path.relative(vaultRoot, legacyPath).replace(/\\/g, '/');
    const newRel = path.relative(vaultRoot, targetPath).replace(/\\/g, '/');
    dbPathsUpdated += db.updateReportVaultPath(oldRel, newRel);
  }
  return { migrated, deduplicated, dbPathsUpdated };
}

export interface RebuildResult {
  /** 走査した raw アーカイブディレクトリ (絶対パス) */
  rawDir: string;
  /** 見つかった raw source (`.md.txt`) 件数 */
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
 * `raw/<week>.md.txt` を唯一の真実として threat_reports DB を作り直す。
 * legacy `raw/<week>.md` が残っていれば、最初に内容不変の rename migration を行う。
 *
 * ヘッダコメントが長らく謳ってきた「壊れたら raw source から再構築可能 (rebuildFromVault)」を
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

  // 0. legacy `.md` を非実行拡張子へ移す。DB を消す前に path 追随まで済ませる。
  migrateLegacyThreatReportArchives({ db, vaultRoot });

  // 1. 既存行を全削除。reports を消すと vulnerabilities / implementation_checks は
  //    ON DELETE CASCADE で連動削除される。raw/*.md.txt だけを真実として作り直すため、
  //    raw が消えた孤児レポートもここで落ちる。
  for (const r of db.listReports()) db.deleteReport(r.id);

  // 2. raw/*.md.txt を列挙 (週順で安定させるためソート)。
  const files = fs.existsSync(rawDir)
    ? fs.readdirSync(rawDir).filter((f) => f.endsWith(THREAT_REPORT_ARCHIVE_SUFFIX)).sort()
    : [];

  let reportsRebuilt = 0;
  let vulnerabilities = 0;
  let implementationChecks = 0;
  const skipped: Array<{ file: string; reason: string }> = [];

  // 3. 各 raw を再 ingest。archive=true (既定) のまま再アーカイブする:
  //    ingestThreatReport は archive 実行時のみ reports.vault_path を埋めるため、
  //    archive=false にすると再構築行の vault_path が null になり JSON の
  //    raw_md_path も null = 元レポートへのリンクが切れる (Codex #82 P2)。
  //    raw/<week>.md.txt への書き戻しは tmp→rename の冪等上書き (内容は ingest 冒頭で
  //    メモリ読込済みなので同一パスでも安全) で、archive パスを正しく記録する。
  //    1 ファイルの契約違反 (ContractError) / I/O 失敗で全体を止めず、その 1 件だけ
  //    skip して残りを復元する (部分復旧 > 全失敗)。
  for (const file of files) {
    try {
      const res = await ingestThreatReport({
        filePath: path.join(rawDir, file),
        db,
        vaultRoot,
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
 * raw archive の拡張子移行で report identity を変えないため、`.md.txt` は
 * legacy `.md` と同じ file source identity に正規化する。
 */
export function canonicalFileSource(filePath: string, vaultRoot?: string): string {
  const abs = path.resolve(filePath);
  const base = path.basename(abs);
  const root = vaultRoot ? path.resolve(vaultRoot) : null;
  const rawDir = root ? path.resolve(root, getThreatReportsArchiveFolder()) : null;
  const isDateNamedRawArchive =
    rawDir !== null &&
    path.dirname(abs) === rawDir &&
    /^\d{4}-\d{2}-\d{2}\.md\.txt$/.test(base);
  const canonical = isDateNamedRawArchive
    ? base.slice(0, -'.txt'.length)
    : base;
  return `file:${canonical}`;
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
 * Vault に raw Markdown payload を `<base>/raw/<YYYY-MM-DD>.md.txt` として保存。
 * 内容は 1 byte も変更しない。Obsidian/Dataview に Markdown として実行させないため、
 * 最終拡張子だけ `.txt` にする。
 *
 * 同名ファイルがあれば上書き (= 同じ週のレポートが parser 改良で再 ingest
 * されても 1 ファイルにまとまる)。
 */
function archiveRawMarkdown(vaultRoot: string, weekOf: string, markdown: string): string {
  // 保存先が vault 配下に収まることを書込前に strict 検証する (resolveVaultPath の
  // Phase 4/5/6: `..` 拒否 + resolve 後プレフィックス + symlink realpath)。改竄された
  // archive-folder 設定や symlink フォルダ経由の vault 外書込への defense-in-depth。
  const rel = path.join(getThreatReportsArchiveFolder(), getThreatReportArchiveFilename(weekOf));
  const safe = resolveVaultPath(rel);
  if (!safe.ok) {
    throw new Error(`raw markdown の保存先が安全でない: ${safe.reason}`);
  }
  const outPath = safe.absolute;
  if (!outPath.startsWith(vaultRoot + path.sep)) {
    throw new Error(`raw markdown の保存先が vault 外: ${outPath}`);
  }
  const archiveDir = path.dirname(outPath);
  if (!fs.existsSync(archiveDir)) fs.mkdirSync(archiveDir, { recursive: true });
  // mkdir 後に realpath を再検証 (validate→write 間の symlink 差し替え TOCTOU)。
  if (!isInsideVaultRealpath(archiveDir, vaultRoot)) {
    throw new Error(`raw markdown の保存先 dir が vault 外 (symlink?): ${archiveDir}`);
  }
  const tmpPath = outPath + '.tmp';
  fs.writeFileSync(tmpPath, markdown, 'utf8');
  fs.renameSync(tmpPath, outPath);
  return outPath;
}

export { ContractError };
export { getThreatReportsBaseFolder };
