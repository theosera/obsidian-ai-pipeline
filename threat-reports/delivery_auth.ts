import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { auth as gmailAuth, gmail } from '@googleapis/gmail';
import { DELIVERY_GMAIL_SCOPES } from './delivery_gmail';

const AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const CALLBACK_PATH = '/oauth2/callback';
const DEFAULT_TIMEOUT_MS = 5 * 60_000;

export interface DeliveryDesktopClient { clientId: string; clientSecret: string }

export interface DeliveryCredentialFile {
  schema_version: 1;
  account: string;
  client_id: string;
  client_secret: string;
  refresh_token: string;
  scopes: string[];
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid delivery credential structure');
  return value as Record<string, unknown>;
}

function secret(value: unknown): string {
  if (typeof value !== 'string' || !value || /[\s\x00-\x1f\x7f]/.test(value)) throw new Error('Missing or invalid delivery credential field');
  return value;
}

export function normalizeDeliveryAccount(value: string): string {
  if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(value)) {
    throw new Error('A single explicit Gmail account address is required');
  }
  return value.toLowerCase();
}

function clientId(value: unknown): string {
  const id = secret(value);
  if (!/^[a-zA-Z0-9._-]+\.apps\.googleusercontent\.com$/.test(id)) throw new Error('Invalid Google Desktop client ID');
  return id;
}

function validateScopes(value: unknown): string[] {
  if (!Array.isArray(value) || value.length !== DELIVERY_GMAIL_SCOPES.length ||
    !DELIVERY_GMAIL_SCOPES.every(scope => value.includes(scope))) {
    throw new Error('Dedicated delivery authorization requires exactly gmail.send and gmail.readonly');
  }
  return [...DELIVERY_GMAIL_SCOPES];
}

/** Do not follow a symlink in any explicit credential path component. */
function checkedAbsolutePath(filePath: string): string {
  if (!path.isAbsolute(filePath)) throw new Error('Credential paths must be explicit absolute paths');
  const resolved = path.resolve(filePath);
  const segments = resolved.split(path.sep).filter(Boolean);
  let current = path.parse(resolved).root;
  for (const segment of segments) {
    current = path.join(current, segment);
    try {
      if (fs.lstatSync(current).isSymbolicLink()) throw new Error('Credential paths must not contain symlinks');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      // The final output file may not exist; its directory must exist.
      if (current !== resolved) throw new Error('Credential parent directory must already exist');
    }
  }
  return resolved;
}

function privateOwner(stats: fs.Stats): void {
  if ((stats.mode & 0o077) !== 0 || (process.getuid && stats.uid !== process.getuid())) {
    throw new Error('Credential file or output directory must be private to the current user');
  }
}

function readPrivateJson(filePath: string): unknown {
  const target = checkedAbsolutePath(filePath);
  const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stats = fs.fstatSync(fd);
    if (!stats.isFile() || stats.size > 64 * 1024) throw new Error('Credentials must be a small regular file');
    privateOwner(stats);
    try { return JSON.parse(fs.readFileSync(fd, 'utf8')) as unknown; }
    catch { throw new Error('Credential file contains invalid JSON'); }
  } finally { fs.closeSync(fd); }
}

export function readDeliveryDesktopClient(filePath: string): DeliveryDesktopClient {
  const data = object(readPrivateJson(filePath));
  if ('web' in data || !('installed' in data)) throw new Error('A dedicated Google Desktop OAuth client JSON is required');
  const installed = object(data.installed);
  if (![AUTHORIZATION_ENDPOINT, 'https://accounts.google.com/o/oauth2/auth'].includes(String(installed.auth_uri)) ||
    installed.token_uri !== TOKEN_ENDPOINT) throw new Error('Only official Google OAuth endpoints are accepted');
  return { clientId: clientId(installed.client_id), clientSecret: secret(installed.client_secret) };
}

export function validateDeliveryCredentialFile(value: unknown): DeliveryCredentialFile {
  const data = object(value);
  const keys = ['schema_version', 'account', 'client_id', 'client_secret', 'refresh_token', 'scopes'];
  if (data.schema_version !== 1 || Object.keys(data).some(key => !keys.includes(key))) throw new Error('Unsupported delivery credential schema');
  return {
    schema_version: 1,
    account: normalizeDeliveryAccount(secret(data.account)),
    client_id: clientId(data.client_id),
    client_secret: secret(data.client_secret),
    refresh_token: secret(data.refresh_token),
    scopes: validateScopes(data.scopes),
  };
}

export function readDeliveryCredentialFile(filePath: string): DeliveryCredentialFile {
  return validateDeliveryCredentialFile(readPrivateJson(filePath));
}

function checkOutput(filePath: string): string {
  const target = checkedAbsolutePath(filePath);
  const parent = fs.statSync(path.dirname(target));
  if (!parent.isDirectory()) throw new Error('Credential parent must be a directory');
  privateOwner(parent);
  try {
    fs.lstatSync(target);
    throw new Error('Delivery credential output already exists; refusing overwrite');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  return target;
}

export function saveDeliveryCredentialFile(filePath: string, value: DeliveryCredentialFile): void {
  const credential = validateDeliveryCredentialFile(value);
  const target = checkOutput(filePath);
  const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(credential, null, 2)}\n`, 'utf8');
    fs.fsyncSync(fd);
  } catch {
    // A partially written credential must never become usable by the delivery CLI.
    fs.unlinkSync(target);
    throw new Error('Unable to save delivery credentials');
  } finally { fs.closeSync(fd); }
}

export function createDeliveryPkce(): { verifier: string; challenge: string; state: string } {
  const verifier = randomBytes(32).toString('base64url');
  return {
    verifier, challenge: createHash('sha256').update(verifier, 'ascii').digest('base64url'),
    state: randomBytes(32).toString('base64url'),
  };
}

export function deliveryAuthorizationUrl(input: {
  clientId: string; account: string; redirectUri: string; state: string; challenge: string;
}): string {
  const redirect = new URL(input.redirectUri);
  if (redirect.protocol !== 'http:' || redirect.hostname !== '127.0.0.1' || !redirect.port ||
    redirect.pathname !== CALLBACK_PATH || redirect.search || redirect.hash || redirect.username || redirect.password) {
    throw new Error('Invalid delivery loopback redirect');
  }
  const url = new URL(AUTHORIZATION_ENDPOINT);
  url.search = new URLSearchParams({
    client_id: clientId(input.clientId), redirect_uri: redirect.href, response_type: 'code',
    scope: DELIVERY_GMAIL_SCOPES.join(' '), access_type: 'offline', prompt: 'consent',
    include_granted_scopes: 'false', login_hint: normalizeDeliveryAccount(input.account),
    code_challenge: input.challenge, code_challenge_method: 'S256', state: input.state,
  }).toString();
  return url.href;
}

/** Pure validation keeps unexpected callback bytes out of logs and token exchange. */
export function validateDeliveryCallback(input: {
  method: string; host: string; url: string; redirectUri: string; state: string;
}): { kind: 'code'; code: string } | { kind: 'ignore' | 'invalid' | 'denied' } {
  const redirect = new URL(input.redirectUri);
  if (input.method !== 'GET' || input.host !== redirect.host || !input.url.startsWith('/') || input.url.startsWith('//')) return { kind: 'invalid' };
  let callback: URL;
  try { callback = new URL(input.url, redirect.origin); } catch { return { kind: 'invalid' }; }
  if (callback.origin !== redirect.origin || callback.hash) return { kind: 'invalid' };
  if (input.url.split('?')[0] !== redirect.pathname || callback.pathname !== redirect.pathname) return { kind: 'ignore' };
  const states = callback.searchParams.getAll('state');
  if (states.length !== 1 || Buffer.byteLength(states[0]) !== Buffer.byteLength(input.state) ||
    !timingSafeEqual(Buffer.from(states[0]), Buffer.from(input.state))) return { kind: 'invalid' };
  const codes = callback.searchParams.getAll('code');
  const errors = callback.searchParams.getAll('error');
  if (errors.length === 1 && errors[0] && codes.length === 0) return { kind: 'denied' };
  if (errors.length !== 0 || codes.length !== 1 || !codes[0] || /[\s\x00-\x1f\x7f]/.test(codes[0])) return { kind: 'invalid' };
  return { kind: 'code', code: codes[0] };
}

interface AwaitCodeInput {
  state: string;
  timeoutMs: number;
  authorizationUrl: (redirectUri: string) => string;
  onAuthorizationUrl: (url: string) => void;
}

export interface DeliveryAuthServices {
  awaitCode(input: AwaitCodeInput): Promise<{ code: string; redirectUri: string }>;
  exchange(input: DeliveryDesktopClient & { code: string; redirectUri: string; verifier: string }): Promise<{
    accessToken: string; refreshToken: string; scopes: string[]; audience: string;
  }>;
  profile(accessToken: string): Promise<string>;
}

function awaitLoopbackCode(input: AwaitCodeInput): Promise<{ code: string; redirectUri: string }> {
  return new Promise((resolve, reject) => {
    let redirectUri = '';
    let settled = false;
    const finish = (error: Error | null, code?: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      server.close();
      server.closeAllConnections();
      if (error) reject(error);
      else resolve({ code: code!, redirectUri });
    };
    const server = http.createServer((request, response) => {
      const result = validateDeliveryCallback({
        method: request.method ?? '', host: request.headers.host ?? '', url: request.url ?? '',
        redirectUri, state: input.state,
      });
      response.setHeader('Content-Type', 'text/plain; charset=utf-8');
      response.setHeader('Cache-Control', 'no-store');
      response.setHeader('Referrer-Policy', 'no-referrer');
      response.setHeader('X-Content-Type-Options', 'nosniff');
      response.statusCode = result.kind === 'code' ? 200 : result.kind === 'ignore' ? 404 : 400;
      response.end(result.kind === 'code' ? 'Authorization received. Return to the terminal.' : 'Authorization callback rejected. Return to the terminal.', () => {
        if (result.kind === 'code') finish(null, result.code);
        else if (result.kind !== 'ignore') finish(new Error(result.kind === 'denied' ? 'Delivery authorization was denied' : 'Invalid delivery authorization callback'));
      });
    });
    server.maxHeadersCount = 30;
    server.requestTimeout = 10_000;
    server.headersTimeout = 10_000;
    server.on('error', () => { finish(new Error('Unable to open delivery loopback callback')); });
    const timer = setTimeout(() => { finish(new Error('Delivery authorization timed out')); }, input.timeoutMs);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') { finish(new Error('Unable to determine delivery callback port')); return; }
      redirectUri = `http://127.0.0.1:${address.port}${CALLBACK_PATH}`;
      try { input.onAuthorizationUrl(input.authorizationUrl(redirectUri)); }
      catch { finish(new Error('Unable to present delivery authorization URL')); }
    });
  });
}

const DEFAULT_SERVICES: DeliveryAuthServices = {
  awaitCode: awaitLoopbackCode,
  async exchange(input) {
    const oauth = new gmailAuth.OAuth2({
      clientId: input.clientId, clientSecret: input.clientSecret, redirectUri: input.redirectUri,
      transporterOptions: { timeout: 30_000, retry: false },
    });
    try {
      const { tokens } = await oauth.getToken({ code: input.code, codeVerifier: input.verifier, redirect_uri: input.redirectUri });
      if (!tokens.access_token || !tokens.refresh_token) throw new Error('Missing token');
      const info = await oauth.getTokenInfo(tokens.access_token);
      return { accessToken: tokens.access_token, refreshToken: tokens.refresh_token, scopes: info.scopes, audience: info.aud };
    } catch { throw new Error('Delivery OAuth token exchange or scope verification failed'); }
  },
  async profile(accessToken) {
    const oauth = new gmailAuth.OAuth2();
    oauth.setCredentials({ access_token: accessToken });
    try {
      const { data } = await gmail({ version: 'v1', auth: oauth }).users.getProfile({ userId: 'me' }, { retry: false, timeout: 30_000 });
      if (!data.emailAddress) throw new Error('Missing profile account');
      return data.emailAddress;
    } catch { throw new Error('Unable to verify dedicated delivery Gmail profile'); }
  },
};

export async function startDeliveryAuthorization(input: {
  client: DeliveryDesktopClient;
  account: string;
  outputFile: string;
  onAuthorizationUrl: (url: string) => void;
  timeoutMs?: number;
  services?: DeliveryAuthServices;
}): Promise<{ account: string; outputFile: string; scopes: string[] }> {
  const account = normalizeDeliveryAccount(input.account);
  const outputFile = checkOutput(input.outputFile);
  const client = { clientId: clientId(input.client.clientId), clientSecret: secret(input.client.clientSecret) };
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15 * 60_000) throw new Error('Invalid delivery authorization timeout');
  const pkce = createDeliveryPkce();
  const services = input.services ?? DEFAULT_SERVICES;
  const callback = await services.awaitCode({
    state: pkce.state, timeoutMs, onAuthorizationUrl: input.onAuthorizationUrl,
    authorizationUrl: redirectUri => deliveryAuthorizationUrl({ clientId: client.clientId, account, redirectUri, state: pkce.state, challenge: pkce.challenge }),
  });
  const token = await services.exchange({ ...client, ...callback, verifier: pkce.verifier });
  if (token.audience !== client.clientId) throw new Error('Delivery token belongs to another OAuth client');
  const scopes = validateScopes(token.scopes);
  if (normalizeDeliveryAccount(await services.profile(secret(token.accessToken))) !== account) throw new Error('Dedicated delivery Gmail account does not match the requested account');
  saveDeliveryCredentialFile(outputFile, {
    schema_version: 1, account, client_id: client.clientId, client_secret: client.clientSecret,
    refresh_token: secret(token.refreshToken), scopes,
  });
  return { account, outputFile, scopes };
}
