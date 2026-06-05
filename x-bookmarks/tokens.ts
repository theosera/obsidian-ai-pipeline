/**
 * X API OAuth 2.0 トークンの永続化 + リフレッシュ。
 *
 * access_token / refresh_token は `<vault>/__skills/pipeline/x_tokens.json`
 * (`.gitignore` 対象) に保存する。期限切れ時は refresh_token で自動更新する。
 *
 * 認可フロー本体 (PKCE / 認可サーバ) は `auth_server.ts`、API 呼び出しは
 * `api_client.ts` が本モジュールの `getValidAccessToken` 経由でトークンを得る。
 */
import fs from 'fs';
import path from 'path';
import { getVaultRoot } from '../config';
import { StoredTokens } from './types';

const API_BASE = 'https://api.x.com/2';
const TOKEN_ENDPOINT = `${API_BASE}/oauth2/token`;

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------
export function getTokensPath(): string {
  const dir = path.join(getVaultRoot(), '__skills', 'pipeline');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, 'x_tokens.json');
}

/**
 * パースした値が StoredTokens の必須フィールドを満たすか検証する型ガード。
 * 破損 / 旧スキーマ / 手書きミスの x_tokens.json で空や非文字列の access_token を
 * 掴んで後続の認証連鎖を壊さないよう、境界で弾く (ts-coding-conventions: API 境界検証)。
 */
function isStoredTokens(v: unknown): v is StoredTokens {
  if (!v || typeof v !== 'object') return false;
  const t = v as Partial<StoredTokens>;
  return typeof t.access_token === 'string' && t.access_token.length > 0
    && typeof t.obtained_at === 'string';
}

export function loadTokens(): StoredTokens | null {
  const p = getTokensPath();
  if (!fs.existsSync(p)) return null;
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!isStoredTokens(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveTokens(tokens: StoredTokens): void {
  const p = getTokensPath();
  fs.writeFileSync(p, JSON.stringify(tokens, null, 2), 'utf8');
  try {
    fs.chmodSync(p, 0o600);
  } catch {
    // Windows や一部 FS では chmod が noop / 失敗する。無視して続行。
  }
}

/**
 * アクセストークンが期限切れ間近か判定。
 * obtained_at + expires_in - 60s を閾値にする (時計ドリフト安全マージン)。
 */
export function isTokenExpired(tokens: StoredTokens, nowMs = Date.now()): boolean {
  if (!tokens.expires_in) return false;
  const obtained = Date.parse(tokens.obtained_at);
  if (Number.isNaN(obtained)) return true;
  const expiresAt = obtained + tokens.expires_in * 1000 - 60_000;
  return nowMs >= expiresAt;
}

// ---------------------------------------------------------------------------
// OAuth token refresh
// ---------------------------------------------------------------------------
function buildTokenHeaders(clientId: string, clientSecret: string): HeadersInit {
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (clientSecret) {
    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    headers.Authorization = `Basic ${basic}`;
  }
  return headers;
}

export async function refreshAccessToken(
  refreshToken: string,
  clientId: string,
  clientSecret: string,
  fetchFn: typeof fetch = fetch
): Promise<StoredTokens> {
  const body = new URLSearchParams();
  body.set('refresh_token', refreshToken);
  body.set('grant_type', 'refresh_token');
  body.set('client_id', clientId);

  const res = await fetchFn(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: buildTokenHeaders(clientId, clientSecret),
    body: body.toString(),
  });
  const json: any = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Token refresh failed: ${res.status} ${JSON.stringify(json)}`);
  }
  // レスポンス本体を保存前に検証する。不正なら disk のトークンを上書きせず throw
  // (空 access_token を保存して以降の getValidAccessToken を壊さない)。
  if (typeof json.access_token !== 'string' || json.access_token.length === 0) {
    throw new Error('Token refresh failed: missing access_token in response');
  }
  if (json.expires_in != null && typeof json.expires_in !== 'number') {
    throw new Error('Token refresh failed: invalid expires_in in response');
  }
  return {
    access_token: json.access_token,
    refresh_token: json.refresh_token ?? refreshToken,
    token_type: json.token_type,
    expires_in: json.expires_in,
    scope: json.scope,
    obtained_at: new Date().toISOString(),
  };
}

/**
 * 有効な access_token を返す。期限切れなら refresh_token で更新して保存。
 */
export async function getValidAccessToken(
  clientId: string,
  clientSecret: string,
  fetchFn: typeof fetch = fetch
): Promise<string> {
  const tokens = loadTokens();
  if (!tokens) {
    throw new Error(
      'x_tokens.json が見つかりません。先に `pnpm start -- --x-auth` で OAuth 認証を完了してください。'
    );
  }
  if (!isTokenExpired(tokens)) {
    return tokens.access_token;
  }
  if (!tokens.refresh_token) {
    throw new Error(
      'access_token が期限切れですが refresh_token がありません。`pnpm start -- --x-auth` で再認証してください。'
    );
  }
  const refreshed = await refreshAccessToken(tokens.refresh_token, clientId, clientSecret, fetchFn);
  saveTokens(refreshed);
  return refreshed.access_token;
}
