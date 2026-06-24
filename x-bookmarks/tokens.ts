/**
 * X API OAuth 2.0 トークンの永続化 + リフレッシュ。
 *
 * access_token / refresh_token は **OS keyring を優先**して保存し、keyring が無い
 * 環境では `<vault>/__skills/pipeline/x_tokens.json` (`.gitignore` 対象, 0600) へ
 * fallback する。期限切れ時は refresh_token で自動更新する。
 *
 * 認可フロー本体 (PKCE / 認可サーバ) は `auth_server.ts`、API 呼び出しは
 * `api_client.ts` が本モジュールの `getValidAccessToken` 経由でトークンを得る。
 */
import fs from 'fs';
import path from 'path';
import { randomBytes } from 'crypto';
import { getVaultRoot } from '../config';
import { Entry } from '@napi-rs/keyring';
import { StoredTokens } from './types';

const API_BASE = 'https://api.x.com/2';
const TOKEN_ENDPOINT = `${API_BASE}/oauth2/token`;

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------
export function getTokensPath(): string {
  const dir = path.join(getVaultRoot(), '__skills', 'pipeline');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return path.join(dir, 'x_tokens.json');
}

// OS keyring (macOS Keychain / Linux libsecret / Windows Credential Manager) is
// the primary store for the long-lived X refresh_token. When no backend is
// available (headless CI, missing libsecret/D-Bus) keyring ops throw and we
// transparently fall back to the hardened 0600 file below.
const KEYRING_SERVICE = 'obsidian-ai-pipeline:x-bookmarks';
const KEYRING_ACCOUNT = 'x_oauth_tokens';

function keyringEntry(): Entry | null {
  try {
    return new Entry(KEYRING_SERVICE, KEYRING_ACCOUNT);
  } catch {
    // Native module / backend unavailable — caller falls back to the file.
    return null;
  }
}

/** Token file path WITHOUT the mkdir side effect (for existence-check / delete). */
function tokensFilePath(): string {
  return path.join(getVaultRoot(), '__skills', 'pipeline', 'x_tokens.json');
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

function loadTokensFromFile(): StoredTokens | null {
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

function saveTokensToFile(tokens: StoredTokens): void {
  const p = getTokensPath();
  // Atomic, private write: create a UNIQUE 0600 temp file (per-process + random,
  // O_EXCL via 'wx') so concurrent --x-auth / refresh in the same vault can't
  // clobber a shared temp path, then rename over the target. This closes the
  // world-readable window between writeFileSync and chmod and never leaves a
  // half-written tokens file (the refresh_token is long-lived).
  const tmp = `${p}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(tokens, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    try {
      fs.chmodSync(tmp, 0o600);
    } catch {
      // Windows や一部 FS では chmod が noop / 失敗する。無視して続行。
    }
    fs.renameSync(tmp, p);
  } catch (err) {
    // write/chmod/rename いずれかが失敗したら temp を残さない (credential を
    // orphan させない)。rename 成功後はこの経路に来ない。
    try {
      fs.unlinkSync(tmp);
    } catch {
      // 既に rename 済 / 未作成なら ENOENT。無視。
    }
    throw err;
  }
}

/**
 * トークンを取得する。優先: OS keyring → fallback: 0600 ファイル。ファイルにあって
 * keyring が使えるなら keyring へ移行し、平文ファイルを削除する (best-effort)。
 */
export function loadTokens(): StoredTokens | null {
  const entry = keyringEntry();
  if (entry) {
    try {
      const parsed: unknown = JSON.parse(entry.getPassword());
      if (isStoredTokens(parsed)) return parsed;
    } catch {
      // keyring 未保存 / backend 不可 → ファイルへ。
    }
  }
  const fromFile = loadTokensFromFile();
  if (fromFile && entry) {
    try {
      entry.setPassword(JSON.stringify(fromFile));
      const p = tokensFilePath();
      if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch {
      // 移行失敗時はファイルを残す (次回再試行)。
    }
  }
  return fromFile;
}

/**
 * トークンを保存する。優先: OS keyring。keyring 不可なら 0600 ファイルへ fallback。
 * keyring 保存に成功したら、残っている平文ファイルを削除する。
 */
export function saveTokens(tokens: StoredTokens): void {
  const entry = keyringEntry();
  if (entry) {
    try {
      entry.setPassword(JSON.stringify(tokens));
      try {
        const p = tokensFilePath();
        if (fs.existsSync(p)) fs.unlinkSync(p);
      } catch {
        // 平文ファイル削除失敗は無視 (権限 / 未存在)。
      }
      return;
    } catch {
      // backend 不可 → ファイルへ fallback。
    }
  }
  saveTokensToFile(tokens);
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
