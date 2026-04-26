/**
 * X API v2 ブックマーク取得モジュール (Playwright スクレイパからの置換)。
 *
 * 公式エンドポイント:
 *   GET /2/users/:id/bookmarks                        — 全ブックマーク
 *   GET /2/users/:id/bookmarks/folders                — フォルダ一覧
 *   GET /2/users/:id/bookmarks/folders/:folder_id     — フォルダ内ポスト
 *
 * 認可: OAuth 2.0 Authorization Code Flow with PKCE
 *   scope: tweet.read users.read bookmark.read offline.access
 *   access_token は `<vault>/__skills/pipeline/x_tokens.json` に永続化。
 *   期限切れ時は refresh_token で自動更新。
 *
 * コスト配慮:
 *   - pay-per-use。同一 UTC 日内の同 Post 再取得は dedup されるが、
 *     DB の known_tweet_ids に当たったら早期終了して API コールを抑える。
 *
 * レート制限:
 *   /bookmarks         — 180 req / 15分
 *   /bookmarks/folders — 50 req / 15分
 *   /bookmarks/folders/{id} — 50 req / 15分
 */
import fs from 'fs';
import path from 'path';
import { ArticleData } from './types';
import { getVaultRoot } from './config';

const API_BASE = 'https://api.x.com/2';
const TOKEN_ENDPOINT = `${API_BASE}/oauth2/token`;

export interface ApiBookmark extends ArticleData {
  xFolderName: string;
  xTweetId: string;
  /**
   * X Premium 長文ツイートの全文 (note_tweet.text)。
   * `text` が truncate されている場合のみセットされる。SQLite キャッシュに
   * full text を保存するため interactive.ts で参照される。
   */
  xNoteTweetText?: string;
}

export interface FetchOptions {
  maxItems?: number;
  skipKnownIds?: Set<string>;
  /** テストから fetch をモックするための差し替え口 */
  fetchFn?: typeof fetch;
}

export interface StoredTokens {
  access_token: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  obtained_at: string;
}

export interface XUser {
  id: string;
  name?: string;
  username?: string;
}

export interface XPost {
  id: string;
  text: string;
  author_id?: string;
  created_at?: string;
  public_metrics?: {
    like_count?: number;
    reply_count?: number;
    retweet_count?: number;
    quote_count?: number;
  };
  entities?: {
    urls?: { url: string; expanded_url?: string; display_url?: string }[];
  };
  /**
   * X Premium 長文ツイート (~25,000 字) の本文。
   * これがあるツイートでは `text` は冒頭で `…` 付きで切れているため、
   * `note_tweet.text` を優先して使う。
   */
  note_tweet?: { text: string };
}

export interface BookmarksResponse {
  data?: XPost[];
  includes?: { users?: XUser[] };
  meta?: { result_count?: number; next_token?: string };
}

export interface BookmarkFoldersResponse {
  data?: { id: string; name: string }[];
  meta?: { result_count?: number; next_token?: string };
}

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------
export function getTokensPath(): string {
  const dir = path.join(getVaultRoot(), '__skills', 'pipeline');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, 'x_tokens.json');
}

export function loadTokens(): StoredTokens | null {
  const p = getTokensPath();
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8')) as StoredTokens;
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

// ---------------------------------------------------------------------------
// HTTP helper with 401 refresh + 429 backoff
// ---------------------------------------------------------------------------
async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * X API GET 呼び出しラッパ。
 *   - 401: 1回だけ refresh して再試行 (retryAuth=true 時のみ)
 *   - 429: Retry-After 準拠で最大2回待機、超過時は例外
 *   - 5xx: 1秒待って1回だけリトライ
 */
export async function xGet<T>(
  url: string,
  ctx: { accessToken: string; clientId: string; clientSecret: string; fetchFn: typeof fetch; onRefreshed?: (newToken: string) => void },
  retryAuth = true
): Promise<T> {
  let attempts429 = 0;
  while (true) {
    const res = await ctx.fetchFn(url, {
      headers: { Authorization: `Bearer ${ctx.accessToken}` },
    });
    if (res.ok) {
      return (await res.json()) as T;
    }
    if (res.status === 401 && retryAuth) {
      const tokens = loadTokens();
      if (tokens?.refresh_token) {
        const refreshed = await refreshAccessToken(
          tokens.refresh_token,
          ctx.clientId,
          ctx.clientSecret,
          ctx.fetchFn
        );
        saveTokens(refreshed);
        ctx.accessToken = refreshed.access_token;
        ctx.onRefreshed?.(refreshed.access_token);
        return xGet<T>(url, ctx, false); // 再試行は 1 回まで
      }
    }
    if (res.status === 429 && attempts429 < 2) {
      const ra = Number(res.headers.get('retry-after') ?? '0');
      const waitMs = (Number.isFinite(ra) && ra > 0 ? ra : 15) * 1000;
      console.warn(`[X API] 429 Rate limited. waiting ${waitMs}ms then retrying...`);
      await sleep(waitMs);
      attempts429 += 1;
      continue;
    }
    const text = await res.text().catch(() => '');
    throw new Error(`X API GET ${url} failed: ${res.status} ${text.slice(0, 500)}`);
  }
}

// ---------------------------------------------------------------------------
// Pure conversion (testable without network)
// ---------------------------------------------------------------------------
/**
 * XPost + XUser → ApiBookmark 変換。
 * 旧 x_bookmarks_scraper.ts の rawToScrapedBookmark と同じ体裁で .md を組む:
 *   - 引用ブロックで本文
 *   - expanded URL 一覧
 *   - エンゲージメントメトリクス
 *   - 元ポストへのリンク
 */
export function tweetToApiBookmark(post: XPost, author: XUser | undefined, folderName: string): ApiBookmark {
  const username = author?.username ?? 'unknown';
  const displayName = author?.name ?? username;
  const url = `https://x.com/${username}/status/${post.id}`;

  // X Premium 長文ツイートは `text` が冒頭で truncate されるが、
  // `note_tweet.text` には全文が入る。`note_tweet` があれば必ずそちらを使う。
  const bodyText = post.note_tweet?.text ?? post.text ?? '';
  const firstLine = bodyText.split('\n')[0].trim();
  const titleSnippet = firstLine.length > 60 ? firstLine.substring(0, 60) + '…' : firstLine;
  const title = `${displayName} (@${username}): ${titleSnippet || post.id}`;
  const date = post.created_at ? post.created_at.substring(0, 10) : undefined;

  const quotedBody = bodyText
    .split('\n')
    .map(line => `> ${line}`)
    .join('\n');

  // entities.urls が付いている場合は expanded_url を優先的に引用する。
  // 自己リンク (x.com / twitter.com の投稿 URL) を除外する。
  // includes() ではなく hostname を解析する (box.com 等の誤マッチ防止)。
  const expandedUrls = (post.entities?.urls ?? [])
    .map(u => u.expanded_url || u.url)
    .filter((u): u is string => !!u)
    .filter(u => {
      try {
        const parsed = new URL(u);
        const host = parsed.hostname.toLowerCase();
        const isXHost = host === 'x.com' || host.endsWith('.x.com')
                     || host === 'twitter.com' || host.endsWith('.twitter.com');
        if (!isXHost) return true;
        // 自分自身のポスト URL だけ除外し、他のツイートやプロフィールへのリンクは残す
        const statusMatch = parsed.pathname.match(/^\/(?:[^/]+\/status|i\/web\/status)\/([^/]+)/);
        return statusMatch?.[1] !== post.id;
      } catch {
        return true;
      }
    })
    .filter((v, i, arr) => arr.indexOf(v) === i);

  const linksSection = expandedUrls.length > 0
    ? `\n\n## 含まれるリンク\n${expandedUrls.map(u => `- ${u}`).join('\n')}`
    : '';

  const likes = post.public_metrics?.like_count;
  const retweets = post.public_metrics?.retweet_count;
  const replies = post.public_metrics?.reply_count;
  const hasMetric = likes != null || retweets != null || replies != null;
  const metricsSection = hasMetric
    ? `\n\n---\n**エンゲージメント**: ❤️ ${likes ?? '-'} · 🔁 ${retweets ?? '-'} · 💬 ${replies ?? '-'}`
    : '';

  const content = `${quotedBody}${linksSection}${metricsSection}\n\n[元ポストを X で見る](${url})\n`;

  const result: ApiBookmark = {
    url,
    title,
    content,
    textContent: bodyText,
    excerpt: firstLine.substring(0, 200),
    date,
    siteName: 'X (Twitter)',
    xFolderName: folderName,
    xTweetId: post.id,
  };
  if (post.note_tweet?.text) {
    result.xNoteTweetText = post.note_tweet.text;
  }
  return result;
}

/**
 * BookmarksResponse を ApiBookmark[] に展開。
 * includes.users の id → XUser マップを構築して author を解決する。
 */
export function expandBookmarksPage(page: BookmarksResponse, folderName: string): ApiBookmark[] {
  const userMap = new Map<string, XUser>((page.includes?.users ?? []).map(u => [u.id, u]));
  const out: ApiBookmark[] = [];
  for (const post of page.data ?? []) {
    const author = post.author_id ? userMap.get(post.author_id) : undefined;
    out.push(tweetToApiBookmark(post, author, folderName));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Endpoint builders (pure)
// ---------------------------------------------------------------------------
function buildBookmarksUrl(userId: string, paginationToken?: string): string {
  const url = new URL(`${API_BASE}/users/${userId}/bookmarks`);
  url.searchParams.set('max_results', '100');
  url.searchParams.set('tweet.fields', 'created_at,author_id,public_metrics,entities,note_tweet');
  url.searchParams.set('expansions', 'author_id');
  url.searchParams.set('user.fields', 'username,name');
  if (paginationToken) url.searchParams.set('pagination_token', paginationToken);
  return url.toString();
}

function buildFolderBookmarksUrl(userId: string, folderId: string, paginationToken?: string): string {
  const url = new URL(`${API_BASE}/users/${userId}/bookmarks/folders/${folderId}`);
  url.searchParams.set('max_results', '100');
  url.searchParams.set('tweet.fields', 'created_at,author_id,public_metrics,entities,note_tweet');
  url.searchParams.set('expansions', 'author_id');
  url.searchParams.set('user.fields', 'username,name');
  if (paginationToken) url.searchParams.set('pagination_token', paginationToken);
  return url.toString();
}

function buildFoldersUrl(userId: string, paginationToken?: string): string {
  const url = new URL(`${API_BASE}/users/${userId}/bookmarks/folders`);
  url.searchParams.set('max_results', '100');
  if (paginationToken) url.searchParams.set('pagination_token', paginationToken);
  return url.toString();
}

// ---------------------------------------------------------------------------
// Main fetch entry
// ---------------------------------------------------------------------------
export async function fetchBookmarksViaApi(options: FetchOptions = {}): Promise<ApiBookmark[]> {
  const maxItems = options.maxItems ?? Infinity;
  const skipKnownIds = options.skipKnownIds ?? new Set<string>();
  const fetchFn = options.fetchFn ?? fetch;

  const clientId = process.env.X_CLIENT_ID ?? '';
  const clientSecret = process.env.X_CLIENT_SECRET ?? '';
  if (!clientId) {
    throw new Error('X_CLIENT_ID が未設定です。.env に追加してください。');
  }

  let accessToken = await getValidAccessToken(clientId, clientSecret, fetchFn);
  const ctx = {
    accessToken,
    clientId,
    clientSecret,
    fetchFn,
    onRefreshed: (t: string) => { accessToken = t; },
  };

  // 1. ユーザー ID 取得
  const me = await xGet<{ data: { id: string; username: string } }>(
    `${API_BASE}/users/me`,
    ctx
  );
  const userId = me.data.id;
  console.log(`🔖 [X API] authenticated as @${me.data.username} (${userId})`);

  // 2. フォルダ一覧
  const folders: { id: string; name: string }[] = [];
  {
    let token: string | undefined;
    do {
      const page = await xGet<BookmarkFoldersResponse>(buildFoldersUrl(userId, token), ctx);
      folders.push(...(page.data ?? []));
      token = page.meta?.next_token;
    } while (token);
  }
  console.log(
    `🔖 [X API] フォルダ ${folders.length} 件: ${folders.map(f => f.name).join(', ') || '(なし)'}`
  );

  const all: ApiBookmark[] = [];
  const folderTweetIds = new Set<string>();

  // 3. フォルダ毎にページング。3 件連続で既知ツイートなら早期終了。
  for (const folder of folders) {
    if (all.length >= maxItems) break;
    let token: string | undefined;
    let consecutiveKnown = 0;
    let folderCount = 0;
    do {
      if (all.length >= maxItems) break;
      const page = await xGet<BookmarksResponse>(
        buildFolderBookmarksUrl(userId, folder.id, token),
        ctx
      );
      const bookmarks = expandBookmarksPage(page, folder.name);
      for (const bm of bookmarks) {
        folderTweetIds.add(bm.xTweetId);
        if (skipKnownIds.has(bm.xTweetId)) {
          consecutiveKnown += 1;
          if (consecutiveKnown >= 3) {
            token = undefined; // ページング打ち切り
            break;
          }
          continue;
        }
        consecutiveKnown = 0;
        all.push(bm);
        folderCount += 1;
        if (all.length >= maxItems) break;
      }
      if (token !== undefined) token = page.meta?.next_token;
    } while (token);
    console.log(`🔖 [X API]   "${folder.name}": ${folderCount} 件 (新規)`);
  }

  // 4. Unfiled (All Bookmarks にあるがどのフォルダにも無いもの)
  if (all.length < maxItems) {
    let token: string | undefined;
    let consecutiveKnown = 0;
    let unfiledCount = 0;
    do {
      if (all.length >= maxItems) break;
      const page = await xGet<BookmarksResponse>(buildBookmarksUrl(userId, token), ctx);
      const bookmarks = expandBookmarksPage(page, '_Unfiled');
      for (const bm of bookmarks) {
        if (folderTweetIds.has(bm.xTweetId)) continue; // フォルダ側で既に拾った
        if (skipKnownIds.has(bm.xTweetId)) {
          consecutiveKnown += 1;
          if (consecutiveKnown >= 3) {
            token = undefined;
            break;
          }
          continue;
        }
        consecutiveKnown = 0;
        all.push(bm);
        unfiledCount += 1;
        if (all.length >= maxItems) break;
      }
      if (token !== undefined) token = page.meta?.next_token;
    } while (token);
    console.log(`🔖 [X API]   _Unfiled: ${unfiledCount} 件 (新規)`);
  }

  console.log(`🔖 [X API] 合計 ${all.length} 件を取得しました。`);
  return all;
}

// テスト用 export
export const __test = {
  tweetToApiBookmark,
  expandBookmarksPage,
  isTokenExpired,
  buildBookmarksUrl,
  buildFolderBookmarksUrl,
  buildFoldersUrl,
};
