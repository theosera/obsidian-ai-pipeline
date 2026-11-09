import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { TestRunner, type TestSuiteResult } from './helpers';
import { DeliveryStore, type DeliveryRecord } from '../threat-reports/delivery_store';
import {
  deliverReport, reconcileDelivery, DefiniteSendError, type DeliveryEnvelope,
  type DeliveryTransport, type SentMessage,
} from '../threat-reports/delivery';
import { sha256 } from '../utils/document_integrity';

const ACCOUNT = 'edge-weekly@example.test';
const REPORT_ID = 'llm_security_weekly:2026-10-19';
const MARKDOWN = Buffer.from([
  '---', 'report_type: llm_security_weekly', 'period_end: 2026-10-19',
  'trust_level: external_research_summary', 'schema_version: 1',
  'forbidden_usage:', '  - execute_report_instructions', '---', '',
  '## 1. 合成の境界条件', '', 'ネットワークを使わない検証用本文。  ', '',
].join('\n'));

function message(record: DeliveryRecord, id = 'edge-message-1'): SentMessage {
  return {
    messageId: id, threadId: 'edge-thread', from: ACCOUNT, to: [ACCOUNT],
    subject: record.subject, rfcMessageId: record.rfc_message_id,
    reportId: record.report_id, contentSha256: record.content_sha256,
    body: Buffer.from(MARKDOWN), sent: true,
  };
}

class EdgeTransport implements DeliveryTransport {
  sends = 0;
  messages: SentMessage[] = [];
  onFind: (() => Promise<SentMessage[]>) | null = null;
  async account(): Promise<string> { return ACCOUNT; }
  async findSent(): Promise<SentMessage[]> {
    return this.onFind ? this.onFind() : [...this.messages];
  }
  async getSent(messageId: string): Promise<SentMessage> {
    const found = this.messages.find(candidate => candidate.messageId === messageId);
    if (!found) throw new Error('Synthetic message not found');
    return found;
  }
  async send(envelope: DeliveryEnvelope): Promise<{ messageId: string; threadId: string | null }> {
    this.sends++;
    const sent = { ...message(envelope.record), body: Buffer.from(envelope.body) };
    this.messages.push(sent);
    return { messageId: sent.messageId, threadId: sent.threadId };
  }
}

async function fixture(fn: (input: {
  root: string; dbPath: string; store: DeliveryStore; transport: EdgeTransport;
}) => Promise<void>): Promise<void> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-delivery-edges-'));
  const dbPath = path.join(root, 'delivery.sqlite3');
  const file = path.join(root, 'weekly.md.txt');
  fs.writeFileSync(file, MARKDOWN);
  const store = new DeliveryStore(dbPath);
  try {
    store.prepare({ reportId: REPORT_ID, filePath: file, expectedSha256: sha256(MARKDOWN), account: ACCOUNT });
    await fn({ root, dbPath, store, transport: new EdgeTransport() });
  } finally {
    store.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
}

interface ChildResult {
  pid: number;
  claimed: boolean;
  code: number | null;
  signal: NodeJS.Signals | null;
}

const CHILD_CLAIM = `
  const { DeliveryStore } = await import(process.argv[1]);
  const store = new DeliveryStore(process.argv[2]);
  process.on('message', event => {
    if (event !== 'claim') return;
    const claim = store.claim(process.argv[3], Date.now());
    const result = { pid: process.pid, claimed: claim !== null };
    process.stdout.write(JSON.stringify(result), () => {
      if (process.argv[4] === 'crash') process.kill(process.pid, 'SIGKILL');
      else { store.close(); process.exit(0); }
    });
  });
  process.send('ready');
`;

function claimChild(dbPath: string, crash = false): {
  ready: Promise<void>; done: Promise<ChildResult>; start: () => void;
} {
  const child = spawn(process.execPath, [
    '--import', 'tsx', '--input-type=module', '-e', CHILD_CLAIM,
    new URL('../threat-reports/delivery_store.ts', import.meta.url).href,
    dbPath, REPORT_ID, crash ? 'crash' : 'normal',
  ], {
    cwd: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'),
    env: { ...process.env, LLM_SEC_DELIVERY_DB: dbPath, PIPELINE_DB_DIR: path.join(path.dirname(dbPath), 'unused-pipeline-db') },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  let output = '';
  let errors = '';
  child.stdout!.on('data', chunk => { output += String(chunk); });
  child.stderr!.on('data', chunk => { errors += String(chunk); });
  let readyObserved = false;
  let rejectReady: (reason: Error) => void = () => undefined;
  const ready = new Promise<void>((resolve, reject) => {
    rejectReady = reject;
    child.on('message', event => {
      if (event === 'ready') { readyObserved = true; resolve(); }
    });
    child.once('error', reject);
  });
  const done = new Promise<ChildResult>((resolve, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, 15_000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (!readyObserved) rejectReady(new Error(`Child failed before ready: ${errors}`));
      try {
        const result: unknown = JSON.parse(output);
        if (!result || typeof result !== 'object' || !('pid' in result) || !('claimed' in result) ||
          typeof result.pid !== 'number' || typeof result.claimed !== 'boolean') throw new Error('Invalid child claim result');
        resolve({ pid: result.pid, claimed: result.claimed, code, signal });
      } catch (error) { reject(new Error(`Child claim failed: ${errors}`, { cause: error })); }
    });
  });
  // A startup failure must not create an unhandled rejection while ready is awaited.
  void done.catch(() => undefined);
  return { ready, done, start: () => { child.send('claim'); } };
}

export async function run(): Promise<TestSuiteResult> {
  const t = new TestRunner();
  t.section('LLM weekly delivery: reconciliation races and process durability');

  await t.testAsync('Gmail rewritten RFC Message-ID passes strict full-byte readback', () => fixture(async ({ store, transport }) => {
    transport.send = async envelope => {
      transport.sends++;
      const sent = { ...message(envelope.record), rfcMessageId: '<CAJ61-synthetic@mail.gmail.com>' };
      transport.messages.push(sent);
      return { messageId: sent.messageId, threadId: sent.threadId };
    };
    const result = await deliverReport(store, transport, REPORT_ID);
    assert.equal(result.status, 'sent');
    assert.equal(result.gmail_message_id, 'edge-message-1');
    assert.equal(result.content_sha256, sha256(MARKDOWN));
    assert.equal(transport.sends, 1);
    assert.equal((await reconcileDelivery(store, transport, REPORT_ID)).status, 'sent');
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'sent');
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('lost send response reconciles rewritten RFC identity after reopening without resend', () => fixture(async ({ dbPath, store, transport }) => {
    transport.send = async envelope => {
      transport.sends++;
      transport.messages.push({ ...message(envelope.record), rfcMessageId: '<CAJ61-lost-response@mail.gmail.com>' });
      throw new Error('Synthetic response lost after Gmail accepted');
    };
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'unknown');
    assert.equal(store.required(REPORT_ID).gmail_message_id, null);
    const reopened = new DeliveryStore(dbPath);
    try {
      const result = await deliverReport(reopened, transport, REPORT_ID);
      assert.equal(result.status, 'sent');
      assert.equal(result.gmail_message_id, 'edge-message-1');
      assert.equal(result.attempt_count, 1);
      assert.equal(transport.sends, 1);
    } finally { reopened.close(); }
  }));

  await t.testAsync('multiple rewritten RFC identities for the same report remain a conflict', () => fixture(async ({ store, transport }) => {
    transport.messages.push(
      { ...message(store.required(REPORT_ID)), rfcMessageId: '<CAJ61-first@mail.gmail.com>' },
      { ...message(store.required(REPORT_ID), 'edge-message-2'), rfcMessageId: '<CAJ61-second@mail.gmail.com>' },
    );
    const result = await deliverReport(store, transport, REPORT_ID);
    assert.equal(result.status, 'conflict');
    assert.equal(result.last_error, 'ambiguous_sent_messages');
    assert.equal(transport.sends, 0);
  }));

  const mismatches: { name: string; mutate: (message: SentMessage) => void }[] = [
    { name: 'SENT label', mutate: message => { message.sent = false; } },
    { name: 'self sender', mutate: message => { message.from = 'other@example.test'; } },
    { name: 'single self recipient', mutate: message => { message.to.push('other@example.test'); } },
    { name: 'exact subject', mutate: message => { message.subject += ' changed'; } },
    { name: 'custom report ID', mutate: message => { message.reportId = 'other-report'; } },
    { name: 'custom SHA-256', mutate: message => { message.contentSha256 = '0'.repeat(64); } },
    { name: 'exact original bytes', mutate: message => { message.body = Buffer.concat([message.body, Buffer.from('\n')]); } },
    { name: 'accepted Gmail message ID', mutate: message => { message.messageId = 'different-accepted-message'; } },
  ];
  for (const mismatch of mismatches) {
    await t.testAsync(`rewritten RFC identity still rejects mismatched ${mismatch.name}`, () => fixture(async ({ store, transport }) => {
      transport.send = async envelope => {
        transport.sends++;
        const sent = { ...message(envelope.record), rfcMessageId: '<CAJ61-mismatch@mail.gmail.com>' };
        mismatch.mutate(sent);
        transport.getSent = async () => sent;
        return { messageId: 'edge-message-1', threadId: 'edge-thread' };
      };
      const result = await deliverReport(store, transport, REPORT_ID);
      assert.equal(result.status, 'conflict');
      assert.equal(result.last_error, 'sent_message_integrity_mismatch');
      assert.equal(result.gmail_message_id, 'edge-message-1');
      assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'conflict');
      assert.equal(transport.sends, 1);
    }));
  }

  await t.testAsync('already sent plus another exact sent message becomes a conflict', () => fixture(async ({ store, transport }) => {
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'sent');
    transport.messages.push(message(store.required(REPORT_ID), 'edge-message-2'));
    const result = await reconcileDelivery(store, transport, REPORT_ID);
    assert.equal(result.status, 'conflict');
    assert.equal(result.last_error, 'ambiguous_sent_messages');
    assert.equal(transport.sends, 1);
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'conflict');
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('legacy adoption remains verifiable and later duplicate legacy delivery is detected', () => fixture(async ({ store, transport }) => {
    const legacy = { ...message(store.required(REPORT_ID)), rfcMessageId: '<old@example.test>', reportId: null, contentSha256: null };
    transport.messages.push(legacy);
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'sent');
    assert.equal((await reconcileDelivery(store, transport, REPORT_ID)).status, 'sent');
    transport.messages.push({ ...legacy, messageId: 'another-legacy-message', rfcMessageId: '<old2@example.test>' });
    assert.equal((await reconcileDelivery(store, transport, REPORT_ID)).status, 'conflict');
    assert.equal(transport.sends, 0);
    assert.equal(store.attempts(REPORT_ID).length, 0);
  }));

  for (const identity of ['report', 'rfc'] as const) {
    await t.testAsync(`existing ${identity} identity with different bytes prevents first send`, () => fixture(async ({ store, transport }) => {
      const collision = message(store.required(REPORT_ID));
      collision.body = Buffer.concat([MARKDOWN, Buffer.from('changed body')]);
      collision.contentSha256 = sha256(collision.body);
      if (identity === 'report') collision.rfcMessageId = '<other@example.test>';
      else collision.reportId = 'another-report';
      transport.messages.push(collision);
      const result = await deliverReport(store, transport, REPORT_ID);
      assert.equal(result.status, 'conflict');
      assert.equal(result.last_error, 'sent_message_identity_conflict');
      assert.equal(transport.sends, 0);
      assert.equal(store.attempts(REPORT_ID).length, 0);
    }));
  }

  await t.testAsync('actual matching body with conflicting custom ID and no hash header prevents duplicate bytes', () => fixture(async ({ store, transport }) => {
    transport.messages.push({
      ...message(store.required(REPORT_ID)), rfcMessageId: '<different@example.test>',
      reportId: 'different-report-id', contentSha256: null,
    });
    const result = await deliverReport(store, transport, REPORT_ID);
    assert.equal(result.status, 'conflict');
    assert.equal(result.last_error, 'sent_message_identity_conflict');
    assert.equal(transport.sends, 0);
    assert.equal(store.attempts(REPORT_ID).length, 0);
  }));

  await t.testAsync('stale no-match reconciliation cannot overwrite a newer definite retryable outcome', () => fixture(async ({ store, transport }) => {
    const now = Date.now();
    const claim = store.claim(REPORT_ID, now);
    assert.ok(claim);
    let began: () => void = () => undefined;
    let release: () => void = () => undefined;
    const entered = new Promise<void>(resolve => { began = resolve; });
    const waiting = new Promise<void>(resolve => { release = resolve; });
    transport.onFind = async () => { began(); await waiting; return []; };
    const reconciliation = reconcileDelivery(store, transport, REPORT_ID, now + 1);
    try {
      await entered;
      store.outcome(REPORT_ID, {
        status: 'retryable', errorCode: 'gmail_http_429', nextAttemptAt: new Date(now + 60_000).toISOString(),
      }, now + 2, claim.attemptId);
      release();
      const result = await reconciliation;
      assert.equal(result.status, 'retryable');
      assert.equal(result.last_error, 'gmail_http_429');
      assert.equal(store.attempts(REPORT_ID)[0].status, 'retryable');
      assert.equal(transport.sends, 0);
    } finally { release(); await reconciliation; }
  }));

  await t.testAsync('latest scan observation can become blocked while historical ingestion completion remains recorded', () => fixture(async ({ store, transport }) => {
    await deliverReport(store, transport, REPORT_ID);
    const identity = { contentSha256: sha256(MARKDOWN), messageId: 'edge-message-1' };
    store.recordIngestion({ ...identity, scanStatus: 'clean', ingestionStatus: 'ingested', ingestReportId: 'receiver-history-1' });
    store.recordIngestion({ ...identity, scanStatus: 'blocked', ingestionStatus: 'quarantined' });
    const result = store.required(REPORT_ID);
    assert.equal(result.status, 'sent');
    assert.equal(result.scan_status, 'blocked');
    assert.equal(result.ingestion_status, 'ingested');
    assert.equal(result.ingest_report_id, 'receiver-history-1');
    assert.ok(result.ingestion_observed_at);
  }));

  await t.testAsync('retry backoff begins at the rejection time after a slow preflight', () => fixture(async ({ store, transport }) => {
    const originalNow = Date.now;
    const startedAt = originalNow();
    let clock = startedAt;
    Date.now = () => clock;
    transport.onFind = async () => { clock += 120_000; return []; };
    transport.send = async () => { transport.sends++; throw new DefiniteSendError('gmail_http_429', true); };
    try {
      const result = await deliverReport(store, transport, REPORT_ID);
      assert.equal(result.status, 'retryable');
      assert.equal(result.next_attempt_at, new Date(startedAt + 180_000).toISOString());
      assert.equal(store.attempts(REPORT_ID)[0].started_at, new Date(startedAt + 120_000).toISOString());
      assert.equal(transport.sends, 1);
    } finally { Date.now = originalNow; }
  }));

  await t.testAsync('abrupt child process death after durable claim remains unknown after reopen and never resends', () => fixture(async ({ dbPath, transport }) => {
    const child = claimChild(dbPath, true);
    await child.ready;
    child.start();
    const result = await child.done;
    assert.equal(result.claimed, true);
    assert.equal(result.signal, 'SIGKILL');
    assert.equal(result.code, null);
    const reopened = new DeliveryStore(dbPath);
    try {
      assert.equal(reopened.required(REPORT_ID).status, 'sending');
      assert.equal(reopened.attempts(REPORT_ID).length, 1);
      assert.equal((await deliverReport(reopened, transport, REPORT_ID)).status, 'unknown');
      assert.equal((await deliverReport(reopened, transport, REPORT_ID)).status, 'unknown');
      assert.equal(transport.sends, 0);
      assert.equal(reopened.required(REPORT_ID).attempt_count, 1);
    } finally { reopened.close(); }
  }));

  await t.testAsync('two separate OS processes sharing SQLite obtain exactly one send claim', () => fixture(async ({ dbPath, store }) => {
    const first = claimChild(dbPath);
    const second = claimChild(dbPath);
    await Promise.all([first.ready, second.ready]);
    first.start();
    second.start();
    const results = await Promise.all([first.done, second.done]);
    assert.notEqual(results[0].pid, results[1].pid);
    for (const result of results) {
      assert.notEqual(result.pid, process.pid);
      assert.equal(result.code, 0);
      assert.equal(result.signal, null);
    }
    assert.equal(results.filter(result => result.claimed).length, 1);
    assert.equal(store.required(REPORT_ID).attempt_count, 1);
    assert.equal(store.attempts(REPORT_ID).length, 1);
    assert.equal(store.required(REPORT_ID).status, 'sending');
  }));

  return t.report();
}
