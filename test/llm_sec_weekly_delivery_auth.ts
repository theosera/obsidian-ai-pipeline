import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TestRunner, type TestSuiteResult } from './helpers';
import {
  createDeliveryPkce, deliveryAuthorizationUrl, normalizeDeliveryAccount,
  readDeliveryDesktopClient, readDeliveryCredentialFile, saveDeliveryCredentialFile,
  startDeliveryAuthorization, validateDeliveryCallback, validateDeliveryCredentialFile,
  type DeliveryCredentialFile, type DeliveryAuthServices,
} from '../threat-reports/delivery_auth';
import { DELIVERY_GMAIL_SCOPES } from '../threat-reports/delivery_gmail';
import { parseDeliveryAuthArgs, main as authMain } from '../scripts/llm_sec_weekly_delivery_auth';

const CLIENT = { clientId: 'fixture.apps.googleusercontent.com', clientSecret: 'synthetic-client-secret' };
const ACCOUNT = 'weekly@example.test';
const REDIRECT = 'http://127.0.0.1:35421/oauth2/callback';
const CREDENTIAL: DeliveryCredentialFile = {
  schema_version: 1, account: ACCOUNT, client_id: CLIENT.clientId, client_secret: CLIENT.clientSecret,
  refresh_token: 'synthetic-refresh-token', scopes: [...DELIVERY_GMAIL_SCOPES],
};

function fixture(fn: (root: string) => void): void {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'delivery-auth-'));
  fs.chmodSync(root, 0o700);
  try { fn(root); } finally { fs.rmSync(root, { force: true, recursive: true }); }
}

async function asyncFixture(fn: (root: string) => Promise<void>): Promise<void> {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'delivery-auth-'));
  fs.chmodSync(root, 0o700);
  try { await fn(root); } finally { fs.rmSync(root, { force: true, recursive: true }); }
}

function writeClient(file: string, overrides: Record<string, unknown> = {}): void {
  fs.writeFileSync(file, JSON.stringify({ installed: {
    client_id: CLIENT.clientId, client_secret: CLIENT.clientSecret,
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token', ...overrides,
  } }), { mode: 0o600 });
}

function services(options: { scopes?: readonly string[]; account?: string; audience?: string; failure?: 'denied' | 'timeout' } = {}): {
  fake: DeliveryAuthServices; exchanges: () => number;
} {
  let exchanges = 0;
  let challenge = '';
  return {
    exchanges: () => exchanges,
    fake: {
      async awaitCode(input) {
        const url = input.authorizationUrl(REDIRECT);
        const parsed = new URL(url);
        challenge = parsed.searchParams.get('code_challenge')!;
        assert.equal(parsed.searchParams.get('state'), input.state);
        input.onAuthorizationUrl(url);
        if (options.failure) throw new Error(options.failure === 'timeout' ? 'Delivery authorization timed out' : 'Delivery authorization was denied');
        return { code: 'synthetic-code', redirectUri: REDIRECT };
      },
      async exchange(input) {
        exchanges++;
        assert.equal(input.code, 'synthetic-code');
        assert.equal(input.redirectUri, REDIRECT);
        assert.equal(createHash('sha256').update(input.verifier, 'ascii').digest('base64url'), challenge);
        return {
          accessToken: 'synthetic-access-token', refreshToken: CREDENTIAL.refresh_token,
          scopes: [...(options.scopes ?? DELIVERY_GMAIL_SCOPES)], audience: options.audience ?? CLIENT.clientId,
        };
      },
      async profile() { return options.account ?? ACCOUNT; },
    },
  };
}

export async function run(): Promise<TestSuiteResult> {
  const t = new TestRunner();
  t.section('Dedicated delivery OAuth: callback binding and private credentials');

  t.test('auth arguments require dedicated absolute files and an explicit account', () => {
    assert.deepEqual(parseDeliveryAuthArgs(['--client-file=/private/client.json', '--output-file=/private/token.json', `--account=${ACCOUNT}`]), {
      clientFile: '/private/client.json', outputFile: '/private/token.json', account: ACCOUNT,
    });
    for (const args of [[], ['--client-file=relative'], ['--client-file=/a', '--output-file=/a', `--account=${ACCOUNT}`],
      ['--client-file=/a', '--output-file=/b', '--account=a@example.test,b@example.test'],
      ['--client-file=/a', '--output-file=/b', `--account=${ACCOUNT}`, `--account=${ACCOUNT}`],
      ['--client-secret=secret']]) assert.throws(() => parseDeliveryAuthArgs(args));
    assert.equal(normalizeDeliveryAccount('Weekly@Example.Test'), ACCOUNT);
  });

  t.test('only private installed client JSON with fixed Google endpoints is accepted', () => fixture(root => {
    const file = path.join(root, 'client.json');
    writeClient(file);
    assert.deepEqual(readDeliveryDesktopClient(file), CLIENT);
    writeClient(file, { token_uri: 'https://example.test/token' });
    assert.throws(() => readDeliveryDesktopClient(file), /official Google/);
    fs.writeFileSync(file, JSON.stringify({ web: {} }));
    assert.throws(() => readDeliveryDesktopClient(file), /Desktop/);
    writeClient(file);
    fs.chmodSync(file, 0o644);
    assert.throws(() => readDeliveryDesktopClient(file), /private/);
  }));

  t.test('credential paths reject symlink files and symlink ancestors', () => fixture(root => {
    const file = path.join(root, 'client.json');
    writeClient(file);
    const link = path.join(root, 'link.json');
    fs.symlinkSync(file, link);
    assert.throws(() => readDeliveryDesktopClient(link), /symlink/);
    const directory = path.join(root, 'link-dir');
    fs.symlinkSync(root, directory);
    assert.throws(() => readDeliveryDesktopClient(path.join(directory, 'client.json')), /symlink/);
    assert.throws(() => saveDeliveryCredentialFile(link, CREDENTIAL), /symlink/);
  }));

  t.test('credential schema refuses broad or partial scopes and accidental access-token persistence', () => {
    assert.deepEqual(validateDeliveryCredentialFile(CREDENTIAL), CREDENTIAL);
    for (const value of [
      { ...CREDENTIAL, scopes: [DELIVERY_GMAIL_SCOPES[0]] },
      { ...CREDENTIAL, scopes: [...DELIVERY_GMAIL_SCOPES, 'https://www.googleapis.com/auth/gmail.modify'] },
      { ...CREDENTIAL, scopes: [DELIVERY_GMAIL_SCOPES[0], DELIVERY_GMAIL_SCOPES[0]] },
      { ...CREDENTIAL, access_token: 'synthetic-access-token' },
      { ...CREDENTIAL, schema_version: 2 }, { ...CREDENTIAL, refresh_token: '' },
    ]) assert.throws(() => validateDeliveryCredentialFile(value));
  });

  t.test('credential creation is private, readable, and never overwrites an existing file', () => fixture(root => {
    const file = path.join(root, 'credentials.json');
    saveDeliveryCredentialFile(file, CREDENTIAL);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(readDeliveryCredentialFile(file), CREDENTIAL);
    const original = fs.readFileSync(file);
    assert.throws(() => saveDeliveryCredentialFile(file, { ...CREDENTIAL, refresh_token: 'changed' }), /overwrite/);
    assert.deepEqual(fs.readFileSync(file), original);
    fs.chmodSync(root, 0o755);
    assert.throws(() => saveDeliveryCredentialFile(path.join(root, 'other.json'), CREDENTIAL), /private/);
  }));

  t.test('PKCE values are unique and only the S256 challenge is placed in the Google URL', () => {
    const first = createDeliveryPkce();
    const second = createDeliveryPkce();
    assert.equal(first.verifier.length, 43);
    assert.equal(first.challenge, createHash('sha256').update(first.verifier, 'ascii').digest('base64url'));
    assert.notEqual(first.state, second.state);
    assert.notEqual(first.verifier, second.verifier);
    const url = new URL(deliveryAuthorizationUrl({ clientId: CLIENT.clientId, account: ACCOUNT, redirectUri: REDIRECT, state: first.state, challenge: first.challenge }));
    assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
    assert.equal(url.searchParams.get('scope'), DELIVERY_GMAIL_SCOPES.join(' '));
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('include_granted_scopes'), 'false');
    assert.equal(url.searchParams.get('client_secret'), null);
    assert.equal(url.searchParams.get('code_verifier'), null);
    assert.ok(!url.href.includes(CLIENT.clientSecret));
    for (const redirectUri of ['https://127.0.0.1:1234/oauth2/callback', 'http://localhost:1234/oauth2/callback', 'http://127.0.0.1:1234/other', `${REDIRECT}?other=1`]) {
      assert.throws(() => deliveryAuthorizationUrl({ clientId: CLIENT.clientId, account: ACCOUNT, redirectUri, state: first.state, challenge: first.challenge }));
    }
  });

  const callback = (url: string, extra: Partial<Parameters<typeof validateDeliveryCallback>[0]> = {}) => validateDeliveryCallback({
    method: 'GET', host: '127.0.0.1:35421', url, redirectUri: REDIRECT, state: 'expected-state', ...extra,
  });
  t.test('callback accepts exactly one code bound to the expected loopback host, path and state', () => {
    assert.deepEqual(callback('/oauth2/callback?state=expected-state&code=synthetic-code'), { kind: 'code', code: 'synthetic-code' });
    assert.deepEqual(callback('/favicon.ico'), { kind: 'ignore' });
    assert.deepEqual(callback('/oauth2/../oauth2/callback?state=expected-state&code=code'), { kind: 'ignore' });
  });
  t.test('callback rejects wrong method, host, origin, state, duplicate parameters and mixed errors', () => {
    const url = '/oauth2/callback?state=expected-state&code=code';
    assert.equal(callback(url, { method: 'POST' }).kind, 'invalid');
    assert.equal(callback(url, { host: 'localhost:35421' }).kind, 'invalid');
    for (const candidate of [
      `https://example.test${url}`, '//example.test/oauth2/callback', '/oauth2/callback?code=code',
      '/oauth2/callback?state=wrong&code=code', '/oauth2/callback?state=expected-state&state=expected-state&code=code',
      '/oauth2/callback?state=expected-state&code=one&code=two', '/oauth2/callback?state=expected-state&code=',
      '/oauth2/callback?state=expected-state&code=bad%0Acode', '/oauth2/callback?state=expected-state&code=code&error=denied',
      '/oauth2/callback?state=expected-state&code=code#fragment',
    ]) assert.equal(callback(candidate).kind, 'invalid');
    assert.equal(callback('/oauth2/callback?state=expected-state&error=access_denied').kind, 'denied');
    assert.equal(callback('/oauth2/callback?state=wrong&error=access_denied').kind, 'invalid');
  });

  await t.testAsync('complete fake authorization verifies client, scopes and account before saving only the refresh token', () => asyncFixture(async root => {
    const outputFile = path.join(root, 'credentials.json');
    const fake = services();
    const urls: string[] = [];
    const result = await startDeliveryAuthorization({ client: CLIENT, account: ACCOUNT, outputFile, services: fake.fake, onAuthorizationUrl: url => { urls.push(url); } });
    assert.deepEqual(result, { account: ACCOUNT, outputFile, scopes: [...DELIVERY_GMAIL_SCOPES] });
    assert.deepEqual(readDeliveryCredentialFile(outputFile), CREDENTIAL);
    assert.equal(fake.exchanges(), 1);
    assert.equal(urls.length, 1);
    const saved = fs.readFileSync(outputFile, 'utf8');
    assert.ok(!saved.includes('synthetic-access-token'));
    assert.ok(!saved.includes('synthetic-code'));
    assert.ok(!JSON.stringify(result).includes(CREDENTIAL.refresh_token));
  }));

  for (const [name, options] of [
    ['partial scopes', { scopes: [DELIVERY_GMAIL_SCOPES[0]] }],
    ['broader scopes', { scopes: [...DELIVERY_GMAIL_SCOPES, 'https://www.googleapis.com/auth/gmail.modify'] }],
    ['different client', { audience: 'other.apps.googleusercontent.com' }],
    ['different account', { account: 'other@example.test' }],
    ['consent denied', { failure: 'denied' as const }],
    ['consent timeout', { failure: 'timeout' as const }],
  ] as const) {
    await t.testAsync(`${name} leaves no credential output`, () => asyncFixture(async root => {
      const outputFile = path.join(root, 'credentials.json');
      const fake = services(options);
      await assert.rejects(startDeliveryAuthorization({ client: CLIENT, account: ACCOUNT, outputFile, services: fake.fake, onAuthorizationUrl: () => undefined }));
      assert.equal(fs.existsSync(outputFile), false);
      if ('failure' in options) assert.equal(fake.exchanges(), 0);
    }));
  }

  await t.testAsync('occupied output refuses authorization before exposing a URL or exchanging a code', () => asyncFixture(async root => {
    const outputFile = path.join(root, 'credentials.json');
    saveDeliveryCredentialFile(outputFile, CREDENTIAL);
    const fake = services();
    let presented = false;
    await assert.rejects(startDeliveryAuthorization({ client: CLIENT, account: ACCOUNT, outputFile, services: fake.fake, onAuthorizationUrl: () => { presented = true; } }), /overwrite/);
    assert.equal(presented, false);
    assert.equal(fake.exchanges(), 0);
    assert.deepEqual(readDeliveryCredentialFile(outputFile), CREDENTIAL);
  }));

  await t.testAsync('help is offline and does not require client credentials', async () => {
    const log = console.log;
    const output: string[] = [];
    console.log = (...args: unknown[]) => { output.push(args.join(' ')); };
    try { assert.equal(await authMain(['--help']), 0); } finally { console.log = log; }
    assert.match(output.join('\n'), /PKCE/);
    assert.ok(!output.join('\n').includes(CLIENT.clientSecret));
  });

  return t.report();
}
