import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { decodeDocument, readDocument } from '../utils/document_integrity';
import { splitFrontmatter, validateFrontmatter } from './parser';

export type DeliveryStatus = 'prepared' | 'sending' | 'sent' | 'retryable' | 'rejected' | 'unknown' | 'conflict';
export type ScanStatus = 'pending' | 'clean' | 'suspicious' | 'blocked' | 'error';
export type IngestionStatus = 'pending' | 'ingested' | 'quarantined' | 'error';

export interface DeliveryRecord {
  report_id: string;
  content_sha256: string;
  file_path: string;
  body_bytes: number;
  period_end: string;
  account: string;
  recipient: string;
  subject: string;
  rfc_message_id: string;
  status: DeliveryStatus;
  gmail_message_id: string | null;
  gmail_thread_id: string | null;
  attempt_count: number;
  next_attempt_at: string | null;
  created_at: string;
  updated_at: string;
  sent_at: string | null;
  last_error: string | null;
  scan_status: ScanStatus;
  ingestion_status: IngestionStatus;
  ingest_report_id: string | null;
  ingestion_observed_at: string | null;
}

export interface DeliveryAttempt {
  id: number;
  report_id: string;
  attempt_number: number;
  started_at: string;
  finished_at: string | null;
  status: DeliveryStatus;
  gmail_message_id: string | null;
  gmail_thread_id: string | null;
  error_code: string | null;
}

export interface PrepareDeliveryInput {
  reportId: string;
  filePath: string;
  expectedSha256: string;
  account: string;
  recipient?: string;
}

interface StoredDelivery extends DeliveryRecord { body: Buffer }
export interface IngestionReceiptInput {
  contentSha256: string;
  messageId: string;
  scanStatus: Exclude<ScanStatus, 'pending'>;
  ingestionStatus: IngestionStatus;
  ingestReportId?: string | null;
}

export interface DeliveryOutcome {
  status: DeliveryStatus;
  messageId?: string | null;
  threadId?: string | null;
  errorCode?: string | null;
  nextAttemptAt?: string | null;
}
interface DeliveryExpectation {
  status: DeliveryStatus;
  attemptCount: number;
  messageId: string | null;
}

export function normalizeDeliveryAddress(value: string): string {
  const result = value.trim().toLowerCase();
  if (!/^[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+$/.test(result)) {
    throw new Error('Delivery account must be one bare email address.');
  }
  return result;
}

export function defaultDeliveryDbPath(): string {
  return path.join(os.homedir(), '.local', 'state', 'obsidian-ai-pipeline', 'llm-sec-delivery.sqlite3');
}

export class DeliveryStore {
  private readonly db: Database.Database;

  constructor(dbPath = defaultDeliveryDbPath()) {
    if (dbPath !== ':memory:') {
      const target = path.resolve(dbPath);
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
      if (fs.lstatSync(path.dirname(target)).isSymbolicLink()) throw new Error('Delivery directory cannot be a symlink.');
      if (fs.existsSync(target)) {
        if (!fs.lstatSync(target).isFile() || fs.lstatSync(target).isSymbolicLink()) throw new Error('Delivery database must be a regular file.');
        fs.chmodSync(target, 0o600);
      } else {
        try { fs.closeSync(fs.openSync(target, 'wx', 0o600)); }
        catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
          if (!fs.lstatSync(target).isFile() || fs.lstatSync(target).isSymbolicLink()) throw new Error('Delivery database must be a regular file.');
        }
      }
      dbPath = target;
    }
    this.db = new Database(dbPath);
    this.db.pragma('busy_timeout = 5000');
    // DELETE journaling avoids persistent WAL sidecars containing report data.
    this.db.pragma('journal_mode = DELETE');
    this.db.pragma('synchronous = FULL');
    this.db.pragma('foreign_keys = ON');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS delivery_reports (
        report_id TEXT PRIMARY KEY, content_sha256 TEXT NOT NULL UNIQUE,
        file_path TEXT NOT NULL, body BLOB NOT NULL, body_bytes INTEGER NOT NULL,
        period_end TEXT NOT NULL, account TEXT NOT NULL, recipient TEXT NOT NULL,
        subject TEXT NOT NULL, rfc_message_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'prepared', gmail_message_id TEXT, gmail_thread_id TEXT,
        attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, sent_at TEXT, last_error TEXT,
        scan_status TEXT NOT NULL DEFAULT 'pending', ingestion_status TEXT NOT NULL DEFAULT 'pending',
        ingest_report_id TEXT, ingestion_observed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS delivery_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL REFERENCES delivery_reports(report_id),
        attempt_number INTEGER NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
        status TEXT NOT NULL, gmail_message_id TEXT, gmail_thread_id TEXT, error_code TEXT,
        UNIQUE(report_id, attempt_number)
      );
    `);
  }

  prepare(input: PrepareDeliveryInput): DeliveryRecord {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.reportId)) throw new Error('Invalid report_id.');
    const account = normalizeDeliveryAddress(input.account);
    const recipient = normalizeDeliveryAddress(input.recipient ?? account);
    if (recipient !== account) throw new Error('Weekly report delivery is restricted to the bound self-send account.');
    const filePath = fs.realpathSync(input.filePath);
    const bytes = readDocument(filePath, input.expectedSha256);
    const contentSha256 = input.expectedSha256.toLowerCase();
    const { yamlText } = splitFrontmatter(decodeDocument(bytes));
    const { period_end: periodEnd } = validateFrontmatter(yamlText);
    const periodDate = new Date(`${periodEnd}T00:00:00.000Z`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(periodEnd) || !Number.isFinite(periodDate.getTime()) ||
      periodDate.toISOString().slice(0, 10) !== periodEnd) throw new Error('Report period_end must be an actual YYYY-MM-DD calendar date.');
    const subject = `[LLM-Sec-Weekly] ${periodEnd}`;
    return this.db.transaction(() => {
      const existing = this.get(input.reportId);
      if (existing) {
        if (existing.content_sha256 !== contentSha256 || existing.account !== account || existing.recipient !== recipient || existing.subject !== subject) {
          throw new Error('Delivery identity conflict: report_id is already bound to another document or account.');
        }
        return existing;
      }
      if (this.db.prepare('SELECT report_id FROM delivery_reports WHERE content_sha256 = ?').get(contentSha256)) {
        throw new Error('Delivery identity conflict: this SHA-256 already belongs to another report_id.');
      }
      const timestamp = new Date().toISOString();
      const messageKey = crypto.createHash('sha256').update(`${account}\0${input.reportId}\0${contentSha256}`).digest('hex');
      this.db.prepare(`INSERT INTO delivery_reports
        (report_id, content_sha256, file_path, body, body_bytes, period_end, account, recipient,
        subject, rfc_message_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(input.reportId, contentSha256, filePath, bytes, bytes.length, periodEnd, account, recipient,
          subject, `<llm-sec-${messageKey}@obsidian-ai-pipeline.local>`, timestamp, timestamp);
      return this.required(input.reportId);
    }).immediate();
  }

  get(reportId: string): DeliveryRecord | null {
    const row = this.db.prepare('SELECT * FROM delivery_reports WHERE report_id = ?').get(reportId) as StoredDelivery | undefined;
    if (!row) return null;
    const { body: _body, ...record } = row;
    return record;
  }

  list(): DeliveryRecord[] {
    return (this.db.prepare('SELECT report_id FROM delivery_reports ORDER BY created_at, report_id').all() as { report_id: string }[])
      .map(({ report_id }) => this.required(report_id));
  }

  attempts(reportId: string): DeliveryAttempt[] {
    return this.db.prepare('SELECT * FROM delivery_attempts WHERE report_id = ? ORDER BY attempt_number').all(reportId) as DeliveryAttempt[];
  }

  required(reportId: string): DeliveryRecord {
    const record = this.get(reportId);
    if (!record) throw new Error('Delivery report is not prepared.');
    return record;
  }

  snapshot(reportId: string): Buffer {
    const row = this.db.prepare('SELECT body FROM delivery_reports WHERE report_id = ?').get(reportId) as { body: Buffer } | undefined;
    if (!row) throw new Error('Delivery report is not prepared.');
    return Buffer.from(row.body);
  }

  claim(reportId: string, now: number): { attemptId: number; record: DeliveryRecord } | null {
    return this.db.transaction(() => {
      const record = this.required(reportId);
      if (!['prepared', 'retryable'].includes(record.status) || record.attempt_count >= 3 ||
        (record.next_attempt_at !== null && Date.parse(record.next_attempt_at) > now)) return null;
      const timestamp = new Date(now).toISOString();
      const attemptNumber = record.attempt_count + 1;
      this.db.prepare(`UPDATE delivery_reports SET status = 'sending', attempt_count = ?,
        next_attempt_at = NULL, updated_at = ?, last_error = NULL WHERE report_id = ?`)
        .run(attemptNumber, timestamp, reportId);
      const result = this.db.prepare(`INSERT INTO delivery_attempts
        (report_id, attempt_number, started_at, status) VALUES (?, ?, ?, 'sending')`)
        .run(reportId, attemptNumber, timestamp);
      return { attemptId: Number(result.lastInsertRowid), record: this.required(reportId) };
    }).immediate();
  }

  outcome(reportId: string, outcome: DeliveryOutcome, now: number, attemptId?: number, expected?: DeliveryExpectation): DeliveryRecord {
    return this.db.transaction(() => {
      const current = this.required(reportId);
      if (expected && (current.status !== expected.status || current.attempt_count !== expected.attemptCount || current.gmail_message_id !== expected.messageId)) return current;
      if (current.status === 'conflict' && !(outcome.status === 'sent' && expected?.status === 'conflict' &&
        current.last_error === 'sent_message_integrity_mismatch' && current.gmail_message_id !== null &&
        outcome.messageId === current.gmail_message_id)) return current;
      // A concurrent reconciliation may already have proved delivery. Never downgrade it.
      if (current.status === 'sent' && outcome.status !== 'sent' && outcome.status !== 'conflict') return current;
      if (outcome.status === 'sent' && current.gmail_message_id !== null && outcome.messageId !== current.gmail_message_id) {
        outcome = { status: 'conflict', errorCode: 'accepted_message_id_conflict' };
      }
      const timestamp = new Date(now).toISOString();
      const messageId = outcome.messageId ?? current.gmail_message_id;
      const threadId = outcome.threadId ?? current.gmail_thread_id;
      this.db.prepare(`UPDATE delivery_reports SET status = ?, gmail_message_id = ?, gmail_thread_id = ?,
        updated_at = ?, sent_at = ?, last_error = ?, next_attempt_at = ? WHERE report_id = ?`)
        .run(outcome.status, messageId, threadId, timestamp,
          outcome.status === 'sent' ? current.sent_at ?? timestamp : current.sent_at,
          outcome.errorCode ?? null, outcome.nextAttemptAt ?? null, reportId);
      const activeAttempt = attemptId ?? (this.db.prepare(`SELECT id FROM delivery_attempts WHERE report_id = ?
        ORDER BY attempt_number DESC LIMIT 1`).get(reportId) as { id: number } | undefined)?.id;
      if (activeAttempt !== undefined) {
        this.db.prepare(`UPDATE delivery_attempts SET finished_at = ?, status = ?,
          gmail_message_id = ?, gmail_thread_id = ?, error_code = ? WHERE id = ? AND report_id = ?`)
          .run(timestamp, outcome.status, messageId, threadId, outcome.errorCode ?? null, activeAttempt, reportId);
      }
      return this.required(reportId);
    }).immediate();
  }

  recordIngestion(input: IngestionReceiptInput): boolean {
    return this.db.transaction(() => {
      const row = this.db.prepare('SELECT report_id FROM delivery_reports WHERE content_sha256 = ?').get(input.contentSha256) as { report_id: string } | undefined;
      if (!row) return false;
      const current = this.required(row.report_id);
      if (current.gmail_message_id === null) return false;
      if (current.gmail_message_id !== input.messageId) throw new Error('Ingestion evidence does not match the recorded Gmail message.');
      if (input.ingestionStatus === 'ingested' && input.scanStatus !== 'clean') throw new Error('Only a clean scan can be recorded as ingested.');
      if (current.ingestion_status === 'ingested') {
        // Completion is historical evidence; later policy scans are new evidence.
        this.db.prepare(`UPDATE delivery_reports SET scan_status = ?,
          ingestion_observed_at = ?, updated_at = ? WHERE report_id = ?`)
          .run(input.scanStatus, new Date().toISOString(), new Date().toISOString(), current.report_id);
        return true;
      }
      this.db.prepare(`UPDATE delivery_reports SET scan_status = ?, ingestion_status = ?,
        ingest_report_id = ?, ingestion_observed_at = ?, updated_at = ? WHERE report_id = ?`)
        .run(input.scanStatus, input.ingestionStatus, input.ingestReportId ?? null,
          new Date().toISOString(), new Date().toISOString(), current.report_id);
      return true;
    }).immediate();
  }

  close(): void { this.db.close(); }
}
