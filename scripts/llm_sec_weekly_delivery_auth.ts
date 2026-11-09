import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeDeliveryAccount, readDeliveryDesktopClient, startDeliveryAuthorization } from '../threat-reports/delivery_auth';

const USAGE = `Authorize a dedicated weekly-report publisher (Desktop OAuth + PKCE)
  pnpm exec tsx scripts/llm_sec_weekly_delivery_auth.ts --client-file=/absolute/private/delivery-client.json --output-file=/absolute/private/delivery-credentials.json --account=<self-address>

Create a separate Desktop OAuth client first. Enable Gmail API and authorize only
gmail.send + gmail.readonly. Both input file and existing output directory must be
private to the current user (chmod 600 file / chmod 700 directory), without symlinks.
Output must not already exist. Open the printed Google URL in your browser and
complete consent within 5 minutes. Tokens and the client secret are never printed.
No email is sent. Intake GMAIL_* credentials and the existing MCP token are not used.`;

export function parseDeliveryAuthArgs(argv: readonly string[]): { clientFile: string; outputFile: string; account: string } {
  const values = new Map<string, string>();
  for (const arg of argv) {
    const match = arg.match(/^--(client-file|output-file|account)=(.+)$/s);
    if (!match || values.has(match[1]) || match[2].trim() !== match[2]) throw new Error('Invalid or duplicate delivery authorization argument; use --help');
    values.set(match[1], match[2]);
  }
  const clientFile = values.get('client-file');
  const outputFile = values.get('output-file');
  const account = values.get('account');
  if (!clientFile || !outputFile || !account || !path.isAbsolute(clientFile) || !path.isAbsolute(outputFile)) {
    throw new Error('Explicit absolute --client-file / --output-file and --account are required');
  }
  if (path.resolve(clientFile) === path.resolve(outputFile)) throw new Error('Client and credential output files must be different');
  return { clientFile: path.resolve(clientFile), outputFile: path.resolve(outputFile), account: normalizeDeliveryAccount(account) };
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  if (argv.length === 1 && argv[0] === '--help') { console.log(USAGE); return 0; }
  const args = parseDeliveryAuthArgs(argv);
  const result = await startDeliveryAuthorization({
    client: readDeliveryDesktopClient(args.clientFile), account: args.account, outputFile: args.outputFile,
    onAuthorizationUrl: url => { console.log(`Open this Google authorization URL in your browser:\n${url}`); },
  });
  console.log(JSON.stringify(result, null, 2));
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    code => { process.exitCode = code; },
    () => { console.error('Dedicated Gmail authorization failed. Check the client file, private paths, requested account, and consent. No credentials were printed.'); process.exitCode = 1; },
  );
}
