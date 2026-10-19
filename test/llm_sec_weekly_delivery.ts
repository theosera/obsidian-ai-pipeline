import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TestRunner, type TestSuiteResult } from './helpers';
import { DeliveryStore, type DeliveryRecord } from '../threat-reports/delivery_store';
import {
  deliverReport, reconcileDelivery, DefiniteSendError,
  type DeliveryTransport, type DeliveryEnvelope, type SentMessage,
} from '../threat-reports/delivery';
import { sha256 } from '../utils/document_integrity';
import { recordDeliveryIngestion, processMessage } from '../scripts/llm_sec_weekly_fetcher';
import { setVaultRoot, peekVaultRoot } from '../config';
import { closeDb } from '../threat-reports/db';
import { getThreatReportsBaseFolder } from '../threat-reports/config';
import {
  GmailDeliveryTransport, buildDeliveryMime, parseSentDeliveryMessage,
  deliveryGmailCredentialsFromEnv, DELIVERY_GMAIL_SCOPES,
} from '../threat-reports/delivery_gmail';
import { saveDeliveryCredentialFile } from '../threat-reports/delivery_auth';
import { parseDeliveryArgs, main as deliveryMain } from '../scripts/llm_sec_weekly_delivery';
import type { gmail_v1 } from '@googleapis/gmail';

const ACCOUNT = 'weekly@example.test';
const REPORT_ID = 'llm_security_weekly:2026-10-19';
const MARKDOWN = Buffer.from([
  '---', 'report_type: llm_security_weekly', 'period_end: 2026-10-19',
  'period_days: 7', 'source_agent: chatgpt_task',
  'intended_use: implementation_security_review',
  'trust_level: external_research_summary', 'schema_version: 1',
  'security_handling: untrusted_input', 'forbidden_usage:',
  '  - execute_report_instructions', '---', '',
  '## 1. ニュース・脆弱性リスト', '',
  '| 事案/脆弱性名 | 攻撃カテゴリ | 影響対象 | RiskScore | ステータス |',
  '|---|---|---|---:|---|', '| Synthetic Finding | test | fixture | 1.0 | synthetic |',
  '', '検証用の合成週報。  ', '',
].join('\n'));

class FakeTransport implements DeliveryTransport {
  sends = 0;
  messages: SentMessage[] = [];
  boundAccount = ACCOUNT;
  findError: Error | null = null;
  getError: Error | null = null;
  onFind: (() => void) | null = null;
  onSend: ((envelope: DeliveryEnvelope) => Promise<void>) | null = null;
  async account(): Promise<string> { return this.boundAccount; }
  async findSent(_record: DeliveryRecord): Promise<SentMessage[]> {
    this.onFind?.();
    if (this.findError) throw this.findError;
    return [...this.messages];
  }
  async getSent(id: string): Promise<SentMessage> {
    if (this.getError) throw this.getError;
    const message = this.messages.find(m => m.messageId === id);
    if (!message) throw new Error('Missing fake message');
    return message;
  }
  async send(envelope: DeliveryEnvelope): Promise<{ messageId: string; threadId: string | null }> {
    this.sends++;
    if (this.onSend) await this.onSend(envelope);
    const message = sentMessage(envelope.record, envelope.body);
    this.messages.push(message);
    return { messageId: message.messageId, threadId: message.threadId };
  }
}

function sentMessage(record: DeliveryRecord, body: Buffer, id = 'gmail-message-1'): SentMessage {
  return {
    messageId: id, threadId: 'gmail-thread-1', from: ACCOUNT, to: [ACCOUNT],
    subject: record.subject, rfcMessageId: record.rfc_message_id,
    reportId: record.report_id, contentSha256: record.content_sha256,
    body: Buffer.from(body), sent: true,
  };
}

function gmailMessage(record: DeliveryRecord): gmail_v1.Schema$Message {
  return {
    id: 'ab123', threadId: 'cd456', labelIds: ['SENT'], payload: {
      mimeType: 'text/plain', body: { data: MARKDOWN.toString('base64url') }, headers: [
        { name: 'From', value: ACCOUNT }, { name: 'To', value: `Weekly <${ACCOUNT}>` },
        { name: 'Subject', value: record.subject }, { name: 'Message-ID', value: record.rfc_message_id },
        { name: 'X-LLM-Report-ID', value: record.report_id },
        { name: 'X-Content-SHA256', value: record.content_sha256 },
      ],
    },
  };
}

async function fixture(fn: (f: {
  root: string; file: string; dbPath: string; store: DeliveryStore; transport: FakeTransport;
}) => Promise<void> | void, bytes = MARKDOWN): Promise<void> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-delivery-'));
  const file = path.join(root, 'weekly.md.txt');
  const dbPath = path.join(root, 'delivery.sqlite3');
  fs.writeFileSync(file, bytes);
  const store = new DeliveryStore(dbPath);
  try {
    store.prepare({ reportId: REPORT_ID, filePath: file, expectedSha256: sha256(bytes), account: ACCOUNT });
    await fn({ root, file, dbPath, store, transport: new FakeTransport() });
  } finally {
    store.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
}

export async function run(): Promise<TestSuiteResult> {
  const t = new TestRunner();
  t.section('LLM weekly delivery: immutable handoff and send evidence');

  await t.testAsync('prepare reads back exact bytes and is idempotent across connections', () => fixture(({ store, file, dbPath }) => {
    const other = new DeliveryStore(dbPath);
    try {
      const record = other.prepare({ reportId: REPORT_ID, filePath: file, expectedSha256: sha256(MARKDOWN), account: ACCOUNT });
      assert.equal(record.status, 'prepared');
      assert.equal(record.content_sha256, sha256(MARKDOWN));
      assert.equal(record.body_bytes, MARKDOWN.length);
      assert.deepEqual(store.snapshot(REPORT_ID), MARKDOWN);
      assert.equal(other.list().length, 1);
      assert.equal(fs.statSync(dbPath).mode & 0o777, 0o600);
    } finally { other.close(); }
  }));

  await t.testAsync('same report_id cannot replace content or account', () => fixture(({ store, file }) => {
    const changed = Buffer.concat([MARKDOWN, Buffer.from('changed')]);
    fs.writeFileSync(file, changed);
    assert.throws(() => store.prepare({ reportId: REPORT_ID, filePath: file, expectedSha256: sha256(changed), account: ACCOUNT }), /conflict/i);
    assert.deepEqual(store.snapshot(REPORT_ID), MARKDOWN);
    fs.writeFileSync(file, MARKDOWN);
    assert.throws(() => store.prepare({ reportId: REPORT_ID, filePath: file, expectedSha256: sha256(MARKDOWN), account: 'other@example.test' }), /conflict/i);
  }));

  await t.testAsync('same SHA-256 under a new report_id cannot bypass deduplication', () => fixture(({ store, file }) => {
    assert.throws(() => store.prepare({ reportId: 'another-id', filePath: file, expectedSha256: sha256(MARKDOWN), account: ACCOUNT }), /conflict/i);
  }));

  await t.testAsync('handoff rejects incorrect hash, invalid UTF8 and header injection', () => fixture(({ store, file }) => {
    assert.throws(() => store.prepare({ reportId: 'new', filePath: file, expectedSha256: '0'.repeat(64), account: ACCOUNT }), /SHA-256/);
    fs.writeFileSync(file, Buffer.from([0xff]));
    assert.throws(() => store.prepare({ reportId: 'invalid', filePath: file, expectedSha256: sha256(Buffer.from([0xff])), account: ACCOUNT }));
    assert.throws(() => store.prepare({ reportId: 'bad\r\nBcc: exfil', filePath: file, expectedSha256: sha256(MARKDOWN), account: ACCOUNT }));
  }));

  await t.testAsync('send records Gmail IDs and readback while ingestion remains pending', () => fixture(async ({ store, transport }) => {
    const result = await deliverReport(store, transport, REPORT_ID);
    assert.equal(result.status, 'sent');
    assert.equal(result.gmail_message_id, 'gmail-message-1');
    assert.equal(result.gmail_thread_id, 'gmail-thread-1');
    assert.ok(result.sent_at);
    assert.equal(result.scan_status, 'pending');
    assert.equal(result.ingestion_status, 'pending');
    assert.equal(result.ingest_report_id, null);
    assert.equal(store.attempts(REPORT_ID)[0].status, 'sent');
    assert.deepEqual(transport.messages[0].body, MARKDOWN);
    await deliverReport(store, transport, REPORT_ID);
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('CRLF, Japanese, trailing spaces and final newline survive full-byte handoff', () => {
    const crlf = Buffer.from(MARKDOWN.toString('utf8').replace(/\n/g, '\r\n'));
    return fixture(async ({ store, transport }) => {
      await deliverReport(store, transport, REPORT_ID);
      assert.deepEqual(transport.messages[0].body, crlf);
      assert.notEqual(sha256(crlf), sha256(MARKDOWN));
    }, crlf);
  });

  await t.testAsync('changed saved Markdown prevents any network send', () => fixture(async ({ store, file, transport }) => {
    fs.appendFileSync(file, '\n');
    await assert.rejects(deliverReport(store, transport, REPORT_ID), /SHA-256/);
    assert.equal(transport.sends, 0);
    assert.equal(store.attempts(REPORT_ID).length, 0);
  }));

  await t.testAsync('file changed during preflight is checked again before send', () => fixture(async ({ store, file, transport }) => {
    transport.onFind = () => fs.appendFileSync(file, 'one changed byte');
    const result = await deliverReport(store, transport, REPORT_ID);
    assert.equal(result.status, 'conflict');
    assert.equal(transport.sends, 0);
  }));

  await t.testAsync('wrong OAuth mailbox cannot send or reconcile', () => fixture(async ({ store, transport }) => {
    transport.boundAccount = 'wrong@example.test';
    await assert.rejects(deliverReport(store, transport, REPORT_ID), /account/i);
    assert.equal(transport.sends, 0);
    assert.equal(store.attempts(REPORT_ID).length, 0);
  }));

  await t.testAsync('preflight lookup failure is not absence and consumes no send attempt', () => fixture(async ({ store, transport }) => {
    transport.findError = new Error('Read denied');
    await assert.rejects(deliverReport(store, transport, REPORT_ID), /Read denied/);
    assert.equal(store.get(REPORT_ID)?.status, 'prepared');
    assert.equal(store.attempts(REPORT_ID).length, 0);
  }));

  await t.testAsync('existing exact historical sent body is adopted without resending', () => fixture(async ({ store, transport }) => {
    const legacy = sentMessage(store.required(REPORT_ID), MARKDOWN);
    legacy.rfcMessageId = '<legacy@example.test>';
    legacy.reportId = null;
    legacy.contentSha256 = null;
    transport.messages.push(legacy);
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'sent');
    assert.equal(transport.sends, 0);
  }));

  await t.testAsync('multiple exact sent copies are a conflict', () => fixture(async ({ store, transport }) => {
    transport.messages = [sentMessage(store.required(REPORT_ID), MARKDOWN, 'm1'), sentMessage(store.required(REPORT_ID), MARKDOWN, 'm2')];
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'conflict');
    assert.equal(transport.sends, 0);
  }));

  await t.testAsync('unknown send with zero search matches never authorizes a retry', () => fixture(async ({ store, transport }) => {
    transport.onSend = async () => { throw new Error('Socket timeout'); };
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'unknown');
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'unknown');
    assert.equal(transport.sends, 1);
    assert.equal(store.attempts(REPORT_ID).length, 1);
  }));

  await t.testAsync('response loss after acceptance reconciles exact sent bytes', () => fixture(async ({ store, transport }) => {
    transport.onSend = async envelope => {
      transport.messages.push(sentMessage(envelope.record, envelope.body));
      throw new Error('Response lost');
    };
    await deliverReport(store, transport, REPORT_ID);
    assert.equal((await reconcileDelivery(store, transport, REPORT_ID)).status, 'sent');
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('accepted ID persists before failed readback and recovers after reopen', () => fixture(async ({ store, transport, dbPath }) => {
    transport.getError = new Error('Readback unavailable');
    const pending = await deliverReport(store, transport, REPORT_ID);
    assert.equal(pending.status, 'unknown');
    assert.equal(pending.gmail_message_id, 'gmail-message-1');
    transport.getError = null;
    const other = new DeliveryStore(dbPath);
    try { assert.equal((await deliverReport(other, transport, REPORT_ID)).status, 'sent'); }
    finally { other.close(); }
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('sent readback mismatch blocks retry and retains accepted ID', () => fixture(async ({ store, transport }) => {
    transport.getSent = async id => ({ ...transport.messages[0], messageId: id, body: Buffer.concat([MARKDOWN, Buffer.from('\n')]) });
    const result = await deliverReport(store, transport, REPORT_ID);
    assert.equal(result.status, 'conflict');
    assert.equal(result.gmail_message_id, 'gmail-message-1');
    await deliverReport(store, transport, REPORT_ID);
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('definite rate limit rejection uses backoff and a maximum of three sends', () => fixture(async ({ store, transport }) => {
    transport.onSend = async () => { throw new DefiniteSendError('429', true); };
    const now = Date.now();
    const first = await deliverReport(store, transport, REPORT_ID, now);
    assert.equal(first.status, 'retryable');
    assert.ok(first.next_attempt_at);
    await deliverReport(store, transport, REPORT_ID, now + 1);
    assert.equal(transport.sends, 1);
    await deliverReport(store, transport, REPORT_ID, now + 60_001);
    await deliverReport(store, transport, REPORT_ID, now + 180_002);
    assert.equal(store.required(REPORT_ID).status, 'rejected');
    await deliverReport(store, transport, REPORT_ID, now + 999_999);
    assert.equal(transport.sends, 3);
    assert.deepEqual(store.attempts(REPORT_ID).map(a => a.status), ['retryable', 'retryable', 'rejected']);
  }));

  await t.testAsync('policy/auth rejection is terminal and never automatically retried', () => fixture(async ({ store, transport }) => {
    transport.onSend = async () => { throw new DefiniteSendError('403', false); };
    assert.equal((await deliverReport(store, transport, REPORT_ID)).status, 'rejected');
    await deliverReport(store, transport, REPORT_ID);
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('two simultaneous callers sharing SQLite send only once', () => fixture(async ({ store, transport, dbPath }) => {
    const other = new DeliveryStore(dbPath);
    let resume: (() => void) | undefined;
    let entered: (() => void) | undefined;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const released = new Promise<void>(resolve => { resume = resolve; });
    transport.onSend = async () => { entered?.(); await released; };
    const first = deliverReport(store, transport, REPORT_ID);
    try {
      await started;
      await deliverReport(other, transport, REPORT_ID);
      resume?.();
      await first;
      assert.equal(transport.sends, 1);
      assert.equal(store.required(REPORT_ID).status, 'sent');
    } finally { resume?.(); await first; other.close(); }
  }));

  await t.testAsync('scan quarantine is independent of successful Gmail delivery', () => fixture(async ({ store, transport }) => {
    await deliverReport(store, transport, REPORT_ID);
    assert.equal(store.recordIngestion({ contentSha256: sha256(MARKDOWN), messageId: 'gmail-message-1', scanStatus: 'blocked', ingestionStatus: 'quarantined' }), true);
    const row = store.required(REPORT_ID);
    assert.equal(row.status, 'sent');
    assert.equal(row.scan_status, 'blocked');
    assert.equal(row.ingestion_status, 'quarantined');
    assert.equal(row.ingest_report_id, null);
    assert.throws(() => store.recordIngestion({ contentSha256: sha256(MARKDOWN), messageId: 'another-message', scanStatus: 'clean', ingestionStatus: 'ingested', ingestReportId: 'r1' }));
  }));

  await t.testAsync('clean scan alone never marks ingestion done and completed evidence is retained', () => fixture(async ({ store, transport }) => {
    await deliverReport(store, transport, REPORT_ID);
    const identity = { contentSha256: sha256(MARKDOWN), messageId: 'gmail-message-1', scanStatus: 'clean' as const };
    store.recordIngestion({ ...identity, ingestionStatus: 'pending' });
    assert.equal(store.required(REPORT_ID).ingestion_status, 'pending');
    store.recordIngestion({ ...identity, ingestionStatus: 'error' });
    assert.equal(store.required(REPORT_ID).status, 'sent');
    store.recordIngestion({ ...identity, ingestionStatus: 'ingested', ingestReportId: 'receiver-report-1' });
    store.recordIngestion({ ...identity, ingestionStatus: 'pending' });
    assert.equal(store.required(REPORT_ID).ingestion_status, 'ingested');
    assert.equal(store.required(REPORT_ID).ingest_report_id, 'receiver-report-1');
  }));

  await t.testAsync('unrelated hash and absent bridge do not create a delivery receipt', () => fixture(({ store }) => {
    assert.equal(store.recordIngestion({ contentSha256: '0'.repeat(64), messageId: 'unknown', scanStatus: 'clean', ingestionStatus: 'pending' }), false);
    assert.equal(recordDeliveryIngestion({ body: MARKDOWN.toString('utf8'), messageId: 'm1', scanStatus: 'clean', ingestionStatus: 'pending' }, ''), false);
    assert.equal(store.required(REPORT_ID).ingestion_status, 'pending');
  }));

  for (const verdict of ['blocked', 'clean'] as const) {
    await t.testAsync(`actual synthetic receiver ${verdict} outcome updates separate ingestion axis`, () => fixture(async ({ root, dbPath, store, transport }) => {
      await deliverReport(store, transport, REPORT_ID);
      const previousRoot = peekVaultRoot();
      const previousDb = process.env.LLM_SEC_DELIVERY_DB;
      const previousPipelineDb = process.env.PIPELINE_DB_DIR;
      const vault = path.join(root, 'vault');
      fs.mkdirSync(vault);
      try {
        setVaultRoot(vault);
        process.env.LLM_SEC_DELIVERY_DB = dbPath;
        process.env.PIPELINE_DB_DIR = path.join(vault, '__skills', 'pipeline');
        const message = {
          id: 'gmail-message-1', labelIds: ['SENT'], payload: {
            mimeType: 'text/plain', headers: [
              { name: 'From', value: ACCOUNT }, { name: 'To', value: ACCOUNT },
              { name: 'Subject', value: '[LLM-Sec-Weekly] 2026-10-19' },
            ], body: { data: MARKDOWN.toString('base64url') },
          },
        };
        const result = await processMessage('gmail-thread-1', message, 1, vault, false,
          () => ({ verdict, detail: 'Synthetic deterministic fixture' }), ACCOUNT);
        assert.equal(result.status, verdict === 'blocked' ? 'quarantined' : 'ingested', result.reason);
        const row = store.required(REPORT_ID);
        assert.equal(row.status, 'sent');
        assert.equal(row.scan_status, verdict);
        assert.equal(row.ingestion_status, verdict === 'blocked' ? 'quarantined' : 'ingested');
        assert.equal(result.status, verdict === 'blocked' ? 'quarantined' : 'ingested');
        if (verdict === 'blocked') {
          assert.equal(fs.existsSync(path.join(vault, getThreatReportsBaseFolder(), 'raw', '2026-10-19.md.txt')), false);
        } else { assert.ok(row.ingest_report_id); }
      } finally {
        closeDb();
        setVaultRoot(previousRoot);
        if (previousDb === undefined) delete process.env.LLM_SEC_DELIVERY_DB;
        else process.env.LLM_SEC_DELIVERY_DB = previousDb;
        if (previousPipelineDb === undefined) delete process.env.PIPELINE_DB_DIR;
        else process.env.PIPELINE_DB_DIR = previousPipelineDb;
      }
    }));
  }

  t.section('Gmail MIME, API adapter and offline CLI');
  await t.testAsync('MIME body decodes to the entire saved bytes without newline conversion', () => fixture(({ store }) => {
    const raw = buildDeliveryMime(store.required(REPORT_ID), MARKDOWN).toString('utf8');
    const split = raw.indexOf('\r\n\r\n');
    assert.ok(split > 0);
    assert.match(raw.slice(0, split), /Content-Transfer-Encoding: base64/);
    assert.deepEqual(Buffer.from(raw.slice(split + 4).replace(/\r\n/g, ''), 'base64'), MARKDOWN);
    assert.throws(() => buildDeliveryMime({ ...store.required(REPORT_ID), subject: 'subject\r\nBcc: attacker@example.test' }, MARKDOWN));
  }));

  await t.testAsync('Gmail full readback rejects extra recipients, duplicate headers and multiple plain bodies', () => fixture(({ store }) => {
    const record = store.required(REPORT_ID);
    assert.deepEqual(parseSentDeliveryMessage(gmailMessage(record)).body, MARKDOWN);
    const extraTo = gmailMessage(record);
    extraTo.payload!.headers![1].value = `other@example.test, Self <${ACCOUNT}>`;
    assert.throws(() => parseSentDeliveryMessage(extraTo), /mailbox/);
    const duplicate = gmailMessage(record);
    duplicate.payload!.headers!.push({ name: 'To', value: ACCOUNT });
    assert.throws(() => parseSentDeliveryMessage(duplicate), /Ambiguous/);
    const twoPlain = gmailMessage(record);
    twoPlain.payload!.parts = [{ mimeType: 'text/plain', body: { data: MARKDOWN.toString('base64url') } }];
    assert.throws(() => parseSentDeliveryMessage(twoPlain), /exactly one/);
    const withCc = gmailMessage(record);
    withCc.payload!.headers!.push({ name: 'Cc', value: 'other@example.test' });
    assert.throws(() => parseSentDeliveryMessage(withCc), /additional recipients/);
  }));

  await t.testAsync('delivery credentials never fall back to incoming Gmail credentials', () => {
    assert.throws(() => deliveryGmailCredentialsFromEnv({ GMAIL_CLIENT_ID: 'incoming', GMAIL_CLIENT_SECRET: 'incoming', GMAIL_REFRESH_TOKEN: 'incoming' }), /GMAIL_DELIVERY_CLIENT_ID/);
    assert.deepEqual(deliveryGmailCredentialsFromEnv({ GMAIL_DELIVERY_CLIENT_ID: 'client', GMAIL_DELIVERY_CLIENT_SECRET: 'secret', GMAIL_DELIVERY_REFRESH_TOKEN: 'refresh' }),
      { clientId: 'client', clientSecret: 'secret', refreshToken: 'refresh' });
    return Promise.resolve();
  });

  for (const status of [403, 408, 429, 500]) {
    await t.testAsync(`Gmail HTTP ${status} performs one POST with SDK retries disabled`, () => fixture(async ({ store }) => {
      let calls = 0;
      const client = { users: { messages: { send: async (_input: unknown, options: unknown) => {
        calls++;
        assert.deepEqual(options, { retry: false, retryConfig: { retry: 0 }, timeout: 30_000 });
        throw { response: { status } };
      } } } } as unknown as gmail_v1.Gmail;
      const transport = new GmailDeliveryTransport({ clientId: 'fixture', clientSecret: 'fixture', refreshToken: 'fixture' }, client);
      await assert.rejects(transport.send({ record: store.required(REPORT_ID), body: MARKDOWN }), error => {
        if (status === 403 || status === 429) {
          assert.ok(error instanceof DefiniteSendError);
          assert.equal(error.retryable, status === 429);
        } else { assert.ok(!(error instanceof DefiniteSendError)); }
        return true;
      });
      assert.equal(calls, 1);
    }));
  }

  await t.testAsync('Gmail successful send passes RFC MIME and records returned identity', () => fixture(async ({ store }) => {
    let calls = 0;
    const client = { users: { messages: { send: async (input: { requestBody: { raw: string } }) => {
      calls++;
      const raw = Buffer.from(input.requestBody.raw, 'base64url').toString('utf8');
      assert.match(raw, /X-Content-SHA256: [a-f0-9]{64}\r\n/);
      assert.deepEqual(Buffer.from(raw.slice(raw.indexOf('\r\n\r\n') + 4), 'base64'), MARKDOWN);
      return { data: { id: 'ab123', threadId: 'cd456' } };
    } } } } as unknown as gmail_v1.Gmail;
    const transport = new GmailDeliveryTransport({ clientId: 'fixture', clientSecret: 'fixture', refreshToken: 'fixture' }, client);
    assert.deepEqual(await transport.send({ record: store.required(REPORT_ID), body: MARKDOWN }), { messageId: 'ab123', threadId: 'cd456' });
    assert.equal(calls, 1);
  }));

  await t.testAsync('paginated Gmail lookup retrieves every candidate and rejects truncated searches', () => fixture(async ({ store }) => {
    let pages = 0;
    const record = store.required(REPORT_ID);
    const client = { users: { messages: {
      list: async (input: { q: string; pageToken?: string }) => {
        pages++;
        assert.match(input.q, /in:sent/);
        assert.match(input.q, /rfc822msgid:/);
        return { data: input.pageToken ? { messages: [{ id: 'ab124' }] } : { messages: [{ id: 'ab123' }], nextPageToken: 'p2' } };
      },
      get: async (input: { id: string }) => ({ data: { ...gmailMessage(record), id: input.id } }),
    } } } as unknown as gmail_v1.Gmail;
    const transport = new GmailDeliveryTransport({ clientId: 'fixture', clientSecret: 'fixture', refreshToken: 'fixture' }, client);
    assert.equal((await transport.findSent(record)).length, 2);
    assert.equal(pages, 2);
    client.users.messages.list = (async () => ({ data: { messages: [], nextPageToken: 'again' } })) as unknown as typeof client.users.messages.list;
    await assert.rejects(transport.findSent(record), /truncated/);
  }));

  await t.testAsync('CLI requires explicit identity/database and rejects ambiguous arguments', () => fixture(({ dbPath }) => {
    for (const args of [
      ['--phase=send'], ['--phase=send', '--db=relative.sqlite', '--report-id=r1'],
      ['--phase=send', `--db=${dbPath}`, '--report-id=r1', '--report-id=r2'],
      ['--phase=send', `--db=${dbPath}`, '--report-id=r1', '--account=override@example.test'],
    ]) assert.throws(() => parseDeliveryArgs(args));
    assert.equal(parseDeliveryArgs(['--phase=status', `--db=${dbPath}`]).phase, 'status');
  }));

  await t.testAsync('credential-file CLI option is absolute, unique and restricted to send/reconcile', () => fixture(({ dbPath, root, file }) => {
    const credentialsFile = path.join(fs.realpathSync(root), 'dedicated-credentials.json');
    for (const phase of ['send', 'reconcile']) {
      const args = [`--phase=${phase}`, `--db=${dbPath}`, `--report-id=${REPORT_ID}`];
      assert.equal(parseDeliveryArgs([...args, `--credentials-file=${credentialsFile}`]).credentialsFile, credentialsFile);
      assert.throws(() => parseDeliveryArgs([...args, '--credentials-file=relative.json']), /absolute path/);
      assert.throws(() => parseDeliveryArgs([...args, `--credentials-file=${credentialsFile}`, `--credentials-file=${credentialsFile}`]), /duplicate/);
    }
    assert.throws(() => parseDeliveryArgs(['--phase=status', `--db=${dbPath}`, `--credentials-file=${credentialsFile}`]), /only accepted by send\/reconcile/);
    assert.throws(() => parseDeliveryArgs([
      '--phase=prepare', `--db=${dbPath}`, `--report-id=${REPORT_ID}`, `--file=${file}`,
      `--sha256=${sha256(MARKDOWN)}`, `--account=${ACCOUNT}`, `--credentials-file=${credentialsFile}`,
    ]), /only accepted by send\/reconcile/);
  }));

  await t.testAsync('wrong dedicated credential account fails before any Gmail request or send attempt', () => fixture(async ({ dbPath, root, store }) => {
    const credentialsFile = path.join(fs.realpathSync(root), 'dedicated-credentials.json');
    saveDeliveryCredentialFile(credentialsFile, {
      schema_version: 1, account: 'other@example.test', client_id: 'fixture.apps.googleusercontent.com',
      client_secret: 'synthetic-client-secret', refresh_token: 'synthetic-refresh-token', scopes: [...DELIVERY_GMAIL_SCOPES],
    });
    const originalAccount = GmailDeliveryTransport.prototype.account;
    let requests = 0;
    GmailDeliveryTransport.prototype.account = async () => { requests++; throw new Error('Unexpected Gmail request'); };
    try {
      for (const phase of ['send', 'reconcile']) {
        await assert.rejects(deliveryMain([
          `--phase=${phase}`, `--db=${dbPath}`, `--report-id=${REPORT_ID}`, `--credentials-file=${credentialsFile}`,
        ]), /credential account differs/);
      }
      assert.equal(requests, 0);
      assert.equal(store.required(REPORT_ID).status, 'prepared');
      assert.equal(store.attempts(REPORT_ID).length, 0);
    } finally { GmailDeliveryTransport.prototype.account = originalAccount; }
  }));

  await t.testAsync('dedicated credential file works without environment credentials and CLI output omits secrets', () => fixture(async ({ dbPath, root, store, transport }) => {
    const credentialsFile = path.join(fs.realpathSync(root), 'dedicated-credentials.json');
    saveDeliveryCredentialFile(credentialsFile, {
      schema_version: 1, account: ACCOUNT, client_id: 'fixture.apps.googleusercontent.com',
      client_secret: 'synthetic-client-secret', refresh_token: 'synthetic-refresh-token', scopes: [...DELIVERY_GMAIL_SCOPES],
    });
    const names = ['GMAIL_DELIVERY_CLIENT_ID', 'GMAIL_DELIVERY_CLIENT_SECRET', 'GMAIL_DELIVERY_REFRESH_TOKEN',
      'GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET', 'GMAIL_REFRESH_TOKEN'] as const;
    const previousEnv = names.map(name => [name, process.env[name]] as const);
    const prototype = GmailDeliveryTransport.prototype;
    const originalMethods = { account: prototype.account, findSent: prototype.findSent, getSent: prototype.getSent, send: prototype.send };
    const originalLog = console.log;
    const lines: string[] = [];
    try {
      for (const name of names) delete process.env[name];
      prototype.account = () => transport.account();
      prototype.findSent = record => transport.findSent(record);
      prototype.getSent = messageId => transport.getSent(messageId);
      prototype.send = envelope => transport.send(envelope);
      console.log = (...items: unknown[]) => { lines.push(items.join(' ')); };
      for (const phase of ['send', 'reconcile']) {
        assert.equal(await deliveryMain([
          `--phase=${phase}`, `--db=${dbPath}`, `--report-id=${REPORT_ID}`, `--credentials-file=${credentialsFile}`,
        ]), 0);
      }
      assert.equal(transport.sends, 1);
      assert.equal(store.required(REPORT_ID).gmail_message_id, 'gmail-message-1');
      assert.equal(store.attempts(REPORT_ID).length, 1);
      assert.equal(lines.length, 2);
      for (const line of lines) {
        assert.equal(JSON.parse(line).status, 'sent');
        assert.ok(!line.includes('synthetic-client-secret'));
        assert.ok(!line.includes('synthetic-refresh-token'));
      }
    } finally {
      Object.assign(prototype, originalMethods);
      console.log = originalLog;
      for (const [name, value] of previousEnv) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  }));

  await t.testAsync('prepare/status CLI work offline and unknown status never creates a ledger', () => fixture(async ({ file, root }) => {
    const dbPath = path.join(root, 'cli-delivery.sqlite');
    const oldLog = console.log;
    const lines: string[] = [];
    console.log = (...items: unknown[]) => { lines.push(items.join(' ')); };
    try {
      assert.equal(await deliveryMain(['--phase=prepare', `--db=${dbPath}`, `--file=${file}`, `--sha256=${sha256(MARKDOWN)}`, `--account=${ACCOUNT}`, `--report-id=${REPORT_ID}`]), 0);
      assert.equal(await deliveryMain(['--phase=status', `--db=${dbPath}`, `--report-id=${REPORT_ID}`]), 0);
      assert.equal(JSON.parse(lines[1]).record.status, 'prepared');
      const missing = path.join(root, 'missing.sqlite');
      await assert.rejects(deliveryMain(['--phase=status', `--db=${missing}`]), /does not exist/);
      assert.equal(fs.existsSync(missing), false);
    } finally { console.log = oldLog; }
  }));

  return t.report();
}
