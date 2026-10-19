import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DeliveryStore } from '../threat-reports/delivery_store';
import { deliverReport, reconcileDelivery } from '../threat-reports/delivery';
import { GmailDeliveryTransport, deliveryGmailCredentialsFromEnv } from '../threat-reports/delivery_gmail';
import { readDeliveryCredentialFile } from '../threat-reports/delivery_auth';

type Phase = 'prepare' | 'send' | 'reconcile' | 'status';

interface DeliveryCliArgs {
  phase: Phase;
  db: string;
  reportId: string | null;
  file: string | null;
  sha256: string | null;
  account: string | null;
  recipient: string | null;
  credentialsFile: string | null;
}

const USAGE = `Weekly LLM security report delivery (separate from /sec-mode intake)
  pnpm exec tsx scripts/llm_sec_weekly_delivery.ts --phase=prepare --db=/absolute/private/delivery.sqlite --report-id=<id> --file=/absolute/report.md --sha256=<64-hex> --account=<self-address>
  pnpm exec tsx scripts/llm_sec_weekly_delivery.ts --phase=send --db=/absolute/private/delivery.sqlite --report-id=<id>
  pnpm exec tsx scripts/llm_sec_weekly_delivery.ts --phase=reconcile --db=/absolute/private/delivery.sqlite --report-id=<id>
  pnpm exec tsx scripts/llm_sec_weekly_delivery.ts --phase=status --db=/absolute/private/delivery.sqlite [--report-id=<id>]

No default database or Gmail account is selected. prepare/status are offline.
send/reconcile use GMAIL_DELIVERY_CLIENT_ID, GMAIL_DELIVERY_CLIENT_SECRET,
GMAIL_DELIVERY_REFRESH_TOKEN; alternatively supply --credentials-file=/absolute/private/credentials.json.
They never use intake GMAIL_* credentials.`;

export function parseDeliveryArgs(argv: readonly string[]): DeliveryCliArgs {
  const allowed = new Set(['phase', 'db', 'report-id', 'file', 'sha256', 'account', 'recipient', 'credentials-file']);
  const values = new Map<string, string>();
  for (const arg of argv) {
    const match = arg.match(/^--([a-z][a-z0-9-]*)=(.+)$/s);
    if (!match || !allowed.has(match[1]) || values.has(match[1]) || !match[2].trim()) {
      throw new Error('Invalid, duplicate, or unsupported delivery argument; use --help');
    }
    values.set(match[1], match[2]);
  }
  const phase = values.get('phase');
  if (phase !== 'prepare' && phase !== 'send' && phase !== 'reconcile' && phase !== 'status') {
    throw new Error('--phase must be prepare, send, reconcile, or status');
  }
  const db = values.get('db');
  if (!db || !path.isAbsolute(db)) throw new Error('--db must name an explicit absolute path');
  const reportId = values.get('report-id') ?? null;
  if (phase !== 'status' && !reportId) throw new Error('--report-id is required');
  if (phase === 'prepare') {
    for (const name of ['file', 'sha256', 'account']) {
      if (!values.has(name)) throw new Error(`--${name} is required for prepare`);
    }
  } else {
    for (const name of ['file', 'sha256', 'account', 'recipient']) {
      if (values.has(name)) throw new Error(`--${name} is only accepted by prepare`);
    }
  }
  const credentialsFile = values.get('credentials-file') ?? null;
  if (credentialsFile && (phase === 'prepare' || phase === 'status' || !path.isAbsolute(credentialsFile))) {
    throw new Error('--credentials-file must be an absolute path and is only accepted by send/reconcile');
  }
  return {
    phase, db: path.resolve(db), reportId, credentialsFile,
    file: values.get('file') ?? null,
    sha256: values.get('sha256') ?? null,
    account: values.get('account') ?? null,
    recipient: values.get('recipient') ?? null,
  };
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  if (argv.length === 1 && argv[0] === '--help') {
    console.log(USAGE);
    return 0;
  }
  const args = parseDeliveryArgs(argv);
  if (args.phase !== 'prepare' && !fs.existsSync(args.db)) throw new Error('Delivery database does not exist; prepare it explicitly first');

  const store = new DeliveryStore(args.db);
  try {
    if (args.phase === 'prepare') {
      const record = store.prepare({
        reportId: args.reportId!, filePath: args.file!, expectedSha256: args.sha256!,
        account: args.account!, ...(args.recipient ? { recipient: args.recipient } : {}),
      });
      console.log(JSON.stringify(record, null, 2));
      return 0;
    }
    if (args.phase === 'status') {
      if (args.reportId) {
        const record = store.get(args.reportId);
        if (!record) throw new Error('Unknown delivery report ID');
        console.log(JSON.stringify({ record, attempts: store.attempts(args.reportId) }, null, 2));
      } else console.log(JSON.stringify(store.list(), null, 2));
      return 0;
    }
    const credential = args.credentialsFile ? readDeliveryCredentialFile(args.credentialsFile) : null;
    if (credential && credential.account !== store.required(args.reportId!).account) {
      throw new Error('Dedicated credential account differs from the prepared delivery account');
    }
    const transport = new GmailDeliveryTransport(credential ? {
      clientId: credential.client_id, clientSecret: credential.client_secret, refreshToken: credential.refresh_token,
    } : deliveryGmailCredentialsFromEnv());
    const record = args.phase === 'send'
      ? await deliverReport(store, transport, args.reportId!)
      : await reconcileDelivery(store, transport, args.reportId!);
    console.log(JSON.stringify(record, null, 2));
    return record.status === 'sent' ? 0 : 2;
  } finally {
    store.close();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    code => { process.exitCode = code; },
    error => {
      console.error(error instanceof Error ? error.stack : String(error));
      process.exitCode = 1;
    },
  );
}
