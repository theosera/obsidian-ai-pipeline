/**
 * X API OAuth 2.0 Authorization Code Flow with PKCE の認可サーバ。
 *
 * `pnpm start -- --x-auth` 実行時のみ起動する短命サーバ。
 * ブラウザで /auth/login → X 認可画面 → /auth/callback に戻ってくる流れを処理し、
 * アクセストークン/リフレッシュトークンを <vault>/__skills/pipeline/x_tokens.json に保存して終了する。
 *
 * 依存を増やさないために Node 組み込み `http` モジュールを使用 (Express 不要)。
 */
import http from 'http';
import crypto from 'crypto';
import { URL } from 'url';
import { exec } from 'child_process';
import { saveTokens, StoredTokens, getTokensPath } from './x_bookmarks_api';

const AUTHORIZE_ENDPOINT = 'https://x.com/i/oauth2/authorize';
const TOKEN_ENDPOINT = 'https://api.x.com/2/oauth2/token';

const SCOPES = ['tweet.read', 'users.read', 'bookmark.read', 'offline.access'];

function base64UrlEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export function randomBase64Url(bytes = 32): string {
  return base64UrlEncode(crypto.randomBytes(bytes));
}

export function codeChallengeFromVerifier(verifier: string): string {
  return base64UrlEncode(crypto.createHash('sha256').update(verifier).digest());
}

export function buildAuthorizeUrl(params: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scopes: string[];
}): string {
  const url = new URL(AUTHORIZE_ENDPOINT);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('scope', params.scopes.join(' '));
  url.searchParams.set('state', params.state);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

function buildTokenHeaders(clientId: string, clientSecret: string): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (clientSecret) {
    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    headers.Authorization = `Basic ${basic}`;
  }
  return headers;
}

async function exchangeCodeForToken(
  code: string,
  verifier: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string
): Promise<StoredTokens> {
  const body = new URLSearchParams();
  body.set('code', code);
  body.set('grant_type', 'authorization_code');
  body.set('client_id', clientId);
  body.set('redirect_uri', redirectUri);
  body.set('code_verifier', verifier);

  const res = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: buildTokenHeaders(clientId, clientSecret),
    body: body.toString(),
  });
  const json: any = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Token exchange failed: ${res.status} ${JSON.stringify(json)}`);
  }
  return {
    access_token: json.access_token,
    refresh_token: json.refresh_token,
    token_type: json.token_type,
    expires_in: json.expires_in,
    scope: json.scope,
    obtained_at: new Date().toISOString(),
  };
}

function tryOpenBrowser(url: string): void {
  const cmd =
    process.platform === 'darwin' ? `open "${url}"` :
    process.platform === 'win32' ? `start "" "${url}"` :
    `xdg-open "${url}"`;
  exec(cmd, err => {
    if (err) {
      // ブラウザ自動起動は best-effort。失敗してもユーザーが手動で開けば良い。
    }
  });
}

export async function runAuthServer(): Promise<void> {
  const clientId = process.env.X_CLIENT_ID;
  const clientSecret = process.env.X_CLIENT_SECRET ?? '';
  const port = Number(process.env.X_AUTH_PORT ?? 3737);
  const redirectUri = process.env.X_REDIRECT_URI ?? `http://localhost:${port}/auth/callback`;

  if (!clientId) {
    console.error('❌ X_CLIENT_ID が未設定です。.env に設定してください。');
    console.error('   X Developer Portal で OAuth 2.0 App を作り、Client ID を取得してください。');
    process.exit(1);
  }

  const pkce = new Map<string, { verifier: string }>();

  const server = http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url ?? '/', `http://localhost:${port}`);

    if (reqUrl.pathname === '/' || reqUrl.pathname === '/auth/login') {
      const state = randomBase64Url(24);
      const verifier = randomBase64Url(48);
      const challenge = codeChallengeFromVerifier(verifier);
      pkce.set(state, { verifier });
      const redirect = buildAuthorizeUrl({
        clientId,
        redirectUri,
        state,
        codeChallenge: challenge,
        scopes: SCOPES,
      });
      res.writeHead(302, { Location: redirect });
      res.end();
      return;
    }

    if (reqUrl.pathname === '/auth/callback') {
      const code = reqUrl.searchParams.get('code') ?? '';
      const state = reqUrl.searchParams.get('state') ?? '';
      const saved = pkce.get(state);
      if (!code || !state || !saved) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('認可失敗: code / state が不正です。');
        return;
      }
      try {
        const tokens = await exchangeCodeForToken(code, saved.verifier, clientId, clientSecret, redirectUri);
        saveTokens(tokens);
        pkce.delete(state);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`
          <!doctype html>
          <html><body style="font-family: sans-serif; padding: 2rem;">
            <h1>✅ X 認証成功</h1>
            <p>トークンを保存しました: <code>${getTokensPath()}</code></p>
            <p>このタブは閉じて構いません。ターミナルに戻ってください。</p>
          </body></html>
        `);
        console.log(`✅ X OAuth 認証成功。トークン保存先: ${getTokensPath()}`);
        console.log(`   refresh_token: ${tokens.refresh_token ? 'あり' : 'なし (offline.access 未付与?)'}`);
        server.close(() => process.exit(0));
      } catch (e: any) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(`トークン交換失敗: ${e.message}`);
        console.error(`❌ ${e.message}`);
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  });

  server.listen(port, () => {
    const loginUrl = `http://localhost:${port}/auth/login`;
    console.log('');
    console.log('🔐 X OAuth 認可サーバを起動しました。');
    console.log(`   ${loginUrl}`);
    console.log('   ブラウザで上記を開いて X の認可を完了してください。');
    console.log('   (ブラウザが自動起動しない場合は手動で開いてください)');
    console.log('');
    tryOpenBrowser(loginUrl);
  });
}

export const __test = {
  buildAuthorizeUrl,
  codeChallengeFromVerifier,
  randomBase64Url,
};
