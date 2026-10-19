import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decodeDocument, documentSha256, readDocument } from '../utils/document_integrity';
import { parseReport } from '../threat-reports/parser';
import { DeliveryStore, normalizeDeliveryAddress, type DeliveryRecord } from '../threat-reports/delivery_store';
import { deliverReport, reconcileDelivery, type DeliveryTransport } from '../threat-reports/delivery';
import { GmailDeliveryTransport, deliveryGmailCredentialsFromEnv } from '../threat-reports/delivery_gmail';

export const PUBLISH_STATE_REL = '__skills/pipeline.nosync/llm-sec-delivery';
export const PUBLISH_OUTBOX_REL = `${PUBLISH_STATE_REL}/outbox`;
export const PUBLISH_DB_REL = `${PUBLISH_STATE_REL}/llm-sec-delivery.sqlite3`;

interface PublishArgs { vaultRoot: string; account: string }
export interface PublishOptions {
  transport?: DeliveryTransport;
  persist?: (vaultRoot: string, dbPath: string) => Promise<void>;
}

export function parsePublishArgs(argv: readonly string[]): PublishArgs {
  const values = new Map<string, string>();
  for (const arg of argv) {
    const match = arg.match(/^--(vault-root|account)=(.+)$/s);
    if (!match || values.has(match[1]) || !match[2].trim()) throw new Error('Publisher requires --vault-root=<absolute-path> and --account=<self-address>');
    values.set(match[1], match[2]);
  }
  const vaultRoot = values.get('vault-root');
  const account = values.get('account');
  if (!vaultRoot || !path.isAbsolute(vaultRoot) || !account) throw new Error('Publisher requires an absolute Vault root and expected Gmail account');
  return { vaultRoot: path.resolve(vaultRoot), account: normalizeDeliveryAddress(account) };
}

function fixedPath(vaultRoot: string, relative: string): string {
  const root = fs.realpathSync(vaultRoot);
  let current = root;
  for (const segment of relative.split('/')) {
    current = path.join(current, segment);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) throw new Error('Publisher state and outbox paths cannot contain symlinks');
  }
  return current;
}

function git(vaultRoot: string, args: readonly string[]): string {
  try {
    return execFileSync('git', [...args], {
      cwd: vaultRoot, encoding: 'utf8', timeout: 60_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    // Git output can contain credential-bearing remote configuration.
    throw new Error(`Delivery ledger Git operation failed (${args[0] ?? 'unknown'})`);
  }
}

function pushLedger(vaultRoot: string, branch: string): void {
  try {
    execFileSync('git', ['push', 'origin', branch], {
      cwd: vaultRoot, encoding: 'utf8', timeout: 60_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const stderr = (error as { stderr?: unknown }).stderr;
    if (typeof stderr === 'string' && /\[rejected\].*\((?:non-fast-forward|fetch first)\)/.test(stderr)) {
      throw new Error('Delivery ledger push rejected; refresh the checkout after closing the database');
    }
    throw new Error('Delivery ledger push result is uncertain; Gmail send is forbidden');
  }
}

export async function persistDeliveryLedger(vaultRoot: string, dbPath: string): Promise<void> {
  const root = fs.realpathSync(vaultRoot);
  if (fs.realpathSync(git(root, ['rev-parse', '--show-toplevel']).trim()) !== root) throw new Error('Publisher Vault root must be the Git checkout root');
  if (path.resolve(dbPath) !== fixedPath(root, PUBLISH_DB_REL) || !fs.lstatSync(dbPath).isFile()) throw new Error('Publisher can persist only its fixed delivery database');
  const ledgerHash = documentSha256(fs.readFileSync(dbPath));
  const staged = git(root, ['diff', '--cached', '--name-only', '-z']).split('\0').filter(Boolean);
  if (staged.some(file => file !== PUBLISH_DB_REL)) throw new Error('Refusing to commit unrelated staged Vault changes');
  const branch = git(root, ['rev-parse', '--abbrev-ref', 'HEAD']).trim();
  if (!branch || branch === 'HEAD' || branch.startsWith('-')) throw new Error('Publisher requires an attached Vault branch');
  git(root, ['add', '-f', '--', PUBLISH_DB_REL]);
  if (git(root, ['diff', '--cached', '--name-only', '-z']).split('\0').includes(PUBLISH_DB_REL)) {
    git(root, ['-c', 'user.name=llm-sec-weekly-bot', '-c', 'user.email=llm-sec-weekly-bot@users.noreply.github.com',
      'commit', '-m', 'chore: persist weekly LLM report delivery state', '--', PUBLISH_DB_REL]);
  }
  // Checkout/rebase can replace the SQLite inode while DeliveryStore is open.
  // Refresh only in a later process, after this connection has been closed.
  pushLedger(root, branch);
  if (documentSha256(fs.readFileSync(dbPath)) !== ledgerHash) throw new Error('Delivery database changed during persistence');
}

export async function publishOutbox(vaultRoot: string, expectedAccount: string, options: PublishOptions = {}): Promise<DeliveryRecord[]> {
  const root = fs.realpathSync(vaultRoot);
  const account = normalizeDeliveryAddress(expectedAccount);
  const outbox = fixedPath(root, PUBLISH_OUTBOX_REL);
  if (!fs.existsSync(outbox)) return [];
  if (!fs.lstatSync(outbox).isDirectory()) throw new Error('Publisher outbox must be a directory');
  const files = fs.readdirSync(outbox).sort().flatMap(name => {
    const full = path.join(outbox, name);
    const stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) throw new Error('Publisher outbox cannot contain symlinks');
    const match = name.match(/^(\d{4}-\d{2}-\d{2})\.md\.txt$/);
    if (!match) {
      if (name.endsWith('.md.txt')) throw new Error('Publisher outbox report filename must be YYYY-MM-DD.md.txt');
      return [];
    }
    if (!stat.isFile()) throw new Error('Publisher report must be a regular file');
    const bytes = fs.readFileSync(full);
    const hash = documentSha256(bytes);
    const parsed = parseReport(decodeDocument(readDocument(full, hash)));
    if (parsed.frontmatter.period_end !== match[1]) throw new Error('Publisher report date differs from its canonical filename');
    const date = new Date(`${match[1]}T00:00:00.000Z`);
    if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== match[1]) throw new Error('Publisher report filename has an invalid calendar date');
    return [{ file: full, hash, reportId: `llm-security-weekly-${match[1]}` }];
  });
  if (files.length === 0) return [];
  const dbPath = fixedPath(root, PUBLISH_DB_REL);
  const transport = options.transport ?? new GmailDeliveryTransport(deliveryGmailCredentialsFromEnv());
  const persist = options.persist ?? persistDeliveryLedger;
  const store = new DeliveryStore(dbPath);
  const results: DeliveryRecord[] = [];
  try {
    for (const file of files) {
      const prepared = store.prepare({ reportId: file.reportId, filePath: file.file, expectedSha256: file.hash, account });
      if (prepared.file_path !== file.file) throw new Error('Publisher canonical outbox path differs from the prepared delivery');
      await persist(root, dbPath);
      const record = prepared.status === 'conflict' && prepared.last_error === 'sent_message_integrity_mismatch' &&
        prepared.gmail_message_id !== null
        ? await reconcileDelivery(store, transport, file.reportId)
        : await deliverReport(store, transport, file.reportId, undefined, {
          beforeSend: async () => { await persist(root, dbPath); },
        });
      await persist(root, dbPath);
      results.push(record);
    }
    return results;
  } finally { store.close(); }
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  if (argv.length === 1 && argv[0] === '--help') {
    console.log('Publish canonical weekly reports through the durable private-Vault delivery ledger\n  pnpm tsx scripts/llm_sec_weekly_publish.ts --vault-root=/absolute/vault --account=expected-self-address');
    return 0;
  }
  const args = parsePublishArgs(argv);
  const records = await publishOutbox(args.vaultRoot, args.account);
  for (const record of records) console.log(JSON.stringify({
    report_id: record.report_id, content_sha256: record.content_sha256, status: record.status,
    gmail_message_id: record.gmail_message_id, attempt_count: record.attempt_count,
    scan_status: record.scan_status, ingestion_status: record.ingestion_status,
  }));
  console.log(`Publisher processed ${records.length} canonical reports`);
  return records.every(record => record.status === 'sent') ? 0 : 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(code => { process.exitCode = code; }, error => {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  });
}
