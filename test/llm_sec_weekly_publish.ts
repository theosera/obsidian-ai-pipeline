import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { TestRunner, type TestSuiteResult } from './helpers';
import { DeliveryStore, type DeliveryRecord } from '../threat-reports/delivery_store';
import { type DeliveryEnvelope, type DeliveryTransport, type SentMessage } from '../threat-reports/delivery';
import { PUBLISH_DB_REL, PUBLISH_OUTBOX_REL, parsePublishArgs, persistDeliveryLedger, publishOutbox } from '../scripts/llm_sec_weekly_publish';
import { documentSha256 } from '../utils/document_integrity';

const ACCOUNT = 'weekly@example.test';
const REPORT_ID = 'llm-security-weekly-2026-10-19';
const MARKDOWN = [
  '---', 'report_type: llm_security_weekly', 'period_end: 2026-10-19', 'period_days: 7',
  'source_agent: chatgpt_task', 'intended_use: implementation_security_review',
  'trust_level: external_research_summary', 'schema_version: 1', 'security_handling: untrusted_input',
  'forbidden_usage:', '  - execute_report_instructions', '---', '',
  '## 1. ニュース・脆弱性リスト', '',
  '| 事案/脆弱性名 | 攻撃カテゴリ | 影響対象 | RiskScore | ステータス |',
  '|---|---|---|---:|---|', '| Synthetic Finding | test | fixture | 1.0 | synthetic |', '',
].join('\n');

class FakeTransport implements DeliveryTransport {
  sends = 0;
  messages: SentMessage[] = [];
  onSend: ((record: DeliveryRecord) => void) | null = null;
  async account(): Promise<string> { return ACCOUNT; }
  async findSent(_record: DeliveryRecord): Promise<SentMessage[]> { return [...this.messages]; }
  async getSent(messageId: string): Promise<SentMessage> {
    const message = this.messages.find(message => message.messageId === messageId);
    if (!message) throw new Error('Missing fake sent message');
    return message;
  }
  async send({ record, body }: DeliveryEnvelope): Promise<{ messageId: string; threadId: string | null }> {
    this.onSend?.(record);
    this.sends++;
    this.messages.push({
      messageId: 'test-message', threadId: 'test-thread', from: ACCOUNT, to: [ACCOUNT],
      subject: record.subject, rfcMessageId: record.rfc_message_id, reportId: record.report_id,
      contentSha256: record.content_sha256, body: Buffer.from(body), sent: true,
    });
    return { messageId: 'test-message', threadId: 'test-thread' };
  }
}

function readState(dbPath: string): DeliveryRecord {
  const store = new DeliveryStore(dbPath);
  try { return store.required(REPORT_ID); } finally { store.close(); }
}

function seedAcceptedConflict(dbPath: string, file: string, transport: FakeTransport, errorCode: string): DeliveryRecord {
  const store = new DeliveryStore(dbPath);
  try {
    store.prepare({ reportId: REPORT_ID, filePath: file, expectedSha256: documentSha256(Buffer.from(MARKDOWN)), account: ACCOUNT });
    const claim = store.claim(REPORT_ID, Date.now());
    assert.ok(claim);
    const record = store.outcome(REPORT_ID, {
      status: 'conflict', messageId: 'test-message', threadId: 'test-thread', errorCode,
    }, Date.now(), claim.attemptId);
    transport.messages = [{
      messageId: 'test-message', threadId: 'test-thread', from: ACCOUNT, to: [ACCOUNT],
      subject: record.subject, rfcMessageId: '<gmail-rewritten@example.test>', reportId: record.report_id,
      contentSha256: record.content_sha256, body: Buffer.from(MARKDOWN), sent: true,
    }];
    return record;
  } finally { store.close(); }
}

async function fixture(fn: (fixture: { root: string; file: string; dbPath: string; transport: FakeTransport }) => Promise<void>): Promise<void> {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'llm-publisher-')));
  const outbox = path.join(root, PUBLISH_OUTBOX_REL);
  fs.mkdirSync(outbox, { recursive: true });
  const file = path.join(outbox, '2026-10-19.md.txt');
  fs.writeFileSync(file, MARKDOWN);
  try { await fn({ root, file, dbPath: path.join(root, PUBLISH_DB_REL), transport: new FakeTransport() }); }
  finally { fs.rmSync(root, { recursive: true, force: true }); }
}

function git(root: string, args: readonly string[]): Buffer {
  return execFileSync('git', [...args], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
}

function gitFixture(root: string): { origin: string; other: string } {
  const origin = path.join(root, 'test-origin.git');
  const other = path.join(root, 'test-other');
  git(root, ['init', '--bare', origin]);
  git(root, ['init', '-b', 'main']);
  git(root, ['config', 'user.name', 'test']);
  git(root, ['config', 'user.email', 'test@example.test']);
  git(root, ['add', '--', PUBLISH_OUTBOX_REL]);
  git(root, ['commit', '-m', 'canonical report']);
  git(root, ['remote', 'add', 'origin', origin]);
  git(root, ['push', '-u', 'origin', 'main']);
  git(root, ['clone', '-b', 'main', origin, other]);
  git(other, ['config', 'user.name', 'other']);
  git(other, ['config', 'user.email', 'other@example.test']);
  return { origin, other };
}

export async function run(): Promise<TestSuiteResult> {
  const t = new TestRunner();
  t.section('Hosted weekly publisher: durable claim before Gmail');

  t.test('arguments reject relative paths, duplicates and unsupported options', () => {
    assert.deepEqual(parsePublishArgs(['--vault-root=/tmp/vault', `--account=${ACCOUNT}`]), { vaultRoot: '/tmp/vault', account: ACCOUNT });
    assert.throws(() => parsePublishArgs(['--vault-root=relative', `--account=${ACCOUNT}`]));
    assert.throws(() => parsePublishArgs(['--vault-root=/tmp/a', '--vault-root=/tmp/b', `--account=${ACCOUNT}`]));
    assert.throws(() => parsePublishArgs(['--vault-root=/tmp/a', `--account=${ACCOUNT}`, '--send=true']));
  });

  await t.testAsync('missing outbox is an offline no-op without creating state', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-empty-publisher-'));
    try { assert.deepEqual(await publishOutbox(root, ACCOUNT), []); assert.equal(fs.existsSync(path.join(root, PUBLISH_DB_REL)), false); }
    finally { fs.rmSync(root, { recursive: true, force: true }); }
  });

  await t.testAsync('zero-row parser drift prevents preparation and Gmail traffic', () => fixture(async ({ root, file, transport }) => {
    fs.writeFileSync(file, MARKDOWN.replace('| Synthetic Finding | test | fixture | 1.0 | synthetic |', ''));
    await assert.rejects(publishOutbox(root, ACCOUNT, { transport, persist: async () => {} }), /1 件も抽出/);
    assert.equal(transport.sends, 0);
    assert.equal(fs.existsSync(path.join(root, PUBLISH_DB_REL)), false);
  }));

  await t.testAsync('filename and period mismatch fails before Gmail traffic', () => fixture(async ({ root, file, transport }) => {
    fs.renameSync(file, path.join(path.dirname(file), '2026-10-12.md.txt'));
    await assert.rejects(publishOutbox(root, ACCOUNT, { transport, persist: async () => {} }), /canonical filename/);
    assert.equal(transport.sends, 0);
  }));

  await t.testAsync('symlink report is rejected', () => fixture(async ({ root, file, transport }) => {
    const original = path.join(root, 'source.txt');
    fs.renameSync(file, original);
    fs.symlinkSync(original, file);
    await assert.rejects(publishOutbox(root, ACCOUNT, { transport, persist: async () => {} }), /symlink/);
    assert.equal(transport.sends, 0);
  }));

  await t.testAsync('prepare, sending and final evidence persist in order; rerun sends once', () => fixture(async ({ root, dbPath, transport }) => {
    const states: string[] = [];
    const persist = async (): Promise<void> => { states.push(readState(dbPath).status); };
    transport.onSend = () => { assert.equal(states.at(-1), 'sending'); };
    const [result] = await publishOutbox(root, ACCOUNT, { transport, persist });
    assert.equal(result.status, 'sent');
    assert.equal(result.gmail_message_id, 'test-message');
    assert.equal(result.scan_status, 'pending');
    assert.deepEqual(states, ['prepared', 'sending', 'sent']);
    await publishOutbox(root, ACCOUNT, { transport, persist });
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('failed durability hook forbids send and later automatic retry', () => fixture(async ({ root, dbPath, transport }) => {
    const persist = async (): Promise<void> => {
      if (readState(dbPath).status === 'sending') throw new Error('Push response lost');
    };
    const [first] = await publishOutbox(root, ACCOUNT, { transport, persist });
    assert.equal(first.status, 'unknown');
    assert.equal(first.last_error, 'pre_send_durability_failed');
    assert.equal(transport.sends, 0);
    const [second] = await publishOutbox(root, ACCOUNT, { transport, persist });
    assert.equal(second.status, 'unknown');
    assert.equal(transport.sends, 0);
    assert.equal(second.attempt_count, 1);
  }));

  await t.testAsync('lost final persistence restores durable sending and reconciles without resend', () => fixture(async ({ root, dbPath, transport }) => {
    let durable: Buffer | null = null;
    const persist = async (): Promise<void> => {
      if (readState(dbPath).status === 'sent') throw new Error('Final push response lost');
      durable = fs.readFileSync(dbPath);
    };
    await assert.rejects(publishOutbox(root, ACCOUNT, { transport, persist }), /Final push/);
    assert.equal(transport.sends, 1);
    assert.ok(durable);
    fs.writeFileSync(dbPath, durable);
    assert.equal(readState(dbPath).status, 'sending');
    const [result] = await publishOutbox(root, ACCOUNT, { transport, persist: async () => {} });
    assert.equal(result.status, 'sent');
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('same-week canonical content cannot be replaced after successful delivery', () => fixture(async ({ root, file, transport }) => {
    await publishOutbox(root, ACCOUNT, { transport, persist: async () => {} });
    fs.appendFileSync(file, '\nChanged canonical bytes');
    await assert.rejects(publishOutbox(root, ACCOUNT, { transport, persist: async () => {} }), /identity conflict/);
    assert.equal(transport.sends, 1);
  }));

  await t.testAsync('accepted integrity mismatch reconciles rewritten Gmail identity without resending', () => fixture(async ({ root, file, dbPath, transport }) => {
    seedAcceptedConflict(dbPath, file, transport, 'sent_message_integrity_mismatch');
    const states: string[] = [];
    const persist = async (): Promise<void> => { states.push(readState(dbPath).status); };
    const [result] = await publishOutbox(root, ACCOUNT, { transport, persist });
    assert.equal(result.status, 'sent');
    assert.equal(result.gmail_message_id, 'test-message');
    assert.equal(result.attempt_count, 1);
    assert.equal(result.scan_status, 'pending');
    assert.equal(result.ingestion_status, 'pending');
    assert.deepEqual(states, ['conflict', 'sent']);
    await publishOutbox(root, ACCOUNT, { transport, persist });
    assert.equal(transport.sends, 0);
  }));

  await t.testAsync('recovery still rejects changed accepted bytes and duplicate strict matches without resending', () => fixture(async ({ root, file, dbPath, transport }) => {
    seedAcceptedConflict(dbPath, file, transport, 'sent_message_integrity_mismatch');
    const exact = transport.messages[0];
    transport.messages = [{ ...exact, body: Buffer.from(`${MARKDOWN}\nchanged`) }];
    assert.equal((await publishOutbox(root, ACCOUNT, { transport, persist: async () => {} }))[0].status, 'conflict');
    transport.messages = [exact, { ...exact, messageId: 'second-accepted-message' }];
    assert.equal((await publishOutbox(root, ACCOUNT, { transport, persist: async () => {} }))[0].status, 'conflict');
    assert.equal(transport.sends, 0);
    assert.equal(readState(dbPath).attempt_count, 1);
  }));

  for (const errorCode of ['ambiguous_sent_messages', 'sent_message_identity_conflict']) {
    await t.testAsync(`${errorCode} stays terminal even if a later lookup could find an exact accepted message`, () => fixture(async ({ root, file, dbPath, transport }) => {
      const record = seedAcceptedConflict(dbPath, file, transport, errorCode);
      transport.findSent = async () => { throw new Error('Terminal conflict must not enter reconciliation'); };
      const [result] = await publishOutbox(root, ACCOUNT, { transport, persist: async () => {} });
      assert.equal(result.status, 'conflict');
      assert.equal(result.last_error, errorCode);
      assert.equal(transport.sends, 0);
      const store = new DeliveryStore(dbPath);
      try {
        const result = store.outcome(REPORT_ID, { status: 'sent', messageId: record.gmail_message_id }, Date.now(), undefined, {
          status: 'conflict', attemptCount: record.attempt_count, messageId: record.gmail_message_id,
        });
        assert.equal(result.status, 'conflict');
        assert.equal(result.last_error, errorCode);
      } finally { store.close(); }
    }));
  }

  await t.testAsync('integrity conflict requires the same accepted ID and unchanged expected snapshot to clear', () => fixture(async ({ file, dbPath, transport }) => {
    const record = seedAcceptedConflict(dbPath, file, transport, 'sent_message_integrity_mismatch');
    const store = new DeliveryStore(dbPath);
    const expected = { status: 'conflict' as const, attemptCount: record.attempt_count, messageId: record.gmail_message_id };
    try {
      assert.equal(store.outcome(REPORT_ID, { status: 'sent', messageId: record.gmail_message_id }, Date.now()).status, 'conflict');
      for (const binding of [
        { ...expected, status: 'unknown' as const }, { ...expected, attemptCount: record.attempt_count + 1 },
        { ...expected, messageId: 'different-accepted-message' },
      ]) {
        assert.equal(store.outcome(REPORT_ID, { status: 'sent', messageId: record.gmail_message_id }, Date.now(), undefined, binding).status, 'conflict');
      }
      assert.equal(store.outcome(REPORT_ID, { status: 'sent', messageId: 'different-accepted-message' }, Date.now(), undefined, expected).status, 'conflict');
      assert.equal(store.required(REPORT_ID).attempt_count, 1);
      assert.equal(store.required(REPORT_ID).gmail_message_id, 'test-message');
    } finally { store.close(); }
  }));

  await t.testAsync('integrity conflict without an accepted Gmail ID cannot enter recovery or acquire a new ID', () => fixture(async ({ root, file, dbPath, transport }) => {
    const store = new DeliveryStore(dbPath);
    try {
      store.prepare({ reportId: REPORT_ID, filePath: file, expectedSha256: documentSha256(Buffer.from(MARKDOWN)), account: ACCOUNT });
      const claim = store.claim(REPORT_ID, Date.now());
      assert.ok(claim);
      store.outcome(REPORT_ID, { status: 'conflict', errorCode: 'sent_message_integrity_mismatch' }, Date.now(), claim.attemptId);
      transport.findSent = async () => { throw new Error('Unknown accepted identity must not enter recovery'); };
      const [result] = await publishOutbox(root, ACCOUNT, { transport, persist: async () => {} });
      assert.equal(result.status, 'conflict');
      assert.equal(result.gmail_message_id, null);
      assert.equal(store.outcome(REPORT_ID, { status: 'sent', messageId: 'new-message' }, Date.now(), undefined, {
        status: 'conflict', attemptCount: 1, messageId: null,
      }).status, 'conflict');
      assert.equal(transport.sends, 0);
      assert.equal(store.required(REPORT_ID).gmail_message_id, null);
    } finally { store.close(); }
  }));

  await t.testAsync('real Git remote contains sending claim before simulated Gmail submission', () => fixture(async ({ root, transport }) => {
    const { origin } = gitFixture(root);
    transport.onSend = () => {
      const bytes = git(root, ['--git-dir', origin, 'show', `main:${PUBLISH_DB_REL}`]);
      const copy = path.join(root, 'observed.sqlite3');
      fs.writeFileSync(copy, bytes);
      assert.equal(readState(copy).status, 'sending');
    };
    const [result] = await publishOutbox(root, ACCOUNT, { transport });
    assert.equal(result.status, 'sent');
    const files = git(root, ['diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD']).toString('utf8').trim().split('\n');
    assert.deepEqual(files, [PUBLISH_DB_REL]);
    assert.equal(git(root, ['status', '--porcelain', '--', PUBLISH_DB_REL]).length, 0);
  }));

  await t.testAsync('unrelated staged files prevent ledger commit and Gmail send', () => fixture(async ({ root, dbPath, transport }) => {
    gitFixture(root);
    fs.writeFileSync(path.join(root, 'unrelated.md'), 'owner work');
    git(root, ['add', '--', 'unrelated.md']);
    await assert.rejects(publishOutbox(root, ACCOUNT, { transport }), /unrelated staged/);
    assert.equal(readState(dbPath).status, 'prepared');
    assert.equal(transport.sends, 0);
    assert.equal(git(root, ['diff', '--cached', '--name-only']).toString('utf8').trim(), 'unrelated.md');
  }));

  await t.testAsync('non-fast-forward rejection stops before Gmail without replacing an open database', () => fixture(async ({ root, transport }) => {
    const { other } = gitFixture(root);
    fs.writeFileSync(path.join(other, 'owner.md'), 'owner change');
    git(other, ['add', '--', 'owner.md']);
    git(other, ['commit', '-m', 'owner change']);
    git(other, ['push', 'origin', 'main']);
    await assert.rejects(publishOutbox(root, ACCOUNT, { transport }), /push rejected/);
    assert.equal(fs.existsSync(path.join(root, 'owner.md')), false);
    assert.equal(transport.sends, 0);
  }));

  await t.testAsync('unconfirmed push failure before claim never calls Gmail', () => fixture(async ({ root, transport }) => {
    gitFixture(root);
    git(root, ['remote', 'set-url', 'origin', path.join(root, 'missing.git')]);
    await assert.rejects(publishOutbox(root, ACCOUNT, { transport }), /push result is uncertain/);
    assert.equal(transport.sends, 0);
  }));

  await t.testAsync('persist helper cannot stage an arbitrary path', () => fixture(async ({ root, file }) => {
    gitFixture(root);
    await assert.rejects(persistDeliveryLedger(root, file), /fixed delivery database/);
  }));

  return t.report();
}
