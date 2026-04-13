/**
 * X (Twitter) API v2 経由でログインユーザーのブックマークを取得し、
 * 本パイプラインの ArticleData に正規化するモジュール。
 *
 * 思想: xurl 寄りのワンショット HTTP 呼び出し。MCP 層は挟まない。
 *
 * 必要スコープ (OAuth 2.0 User Context):
 *   - bookmark.read
 *   - tweet.read
 *   - users.read
 *
 * 認証: 事前に取得した User Access Token を環境変数で渡す。
 *   X_USER_BEARER_TOKEN=<user access token>
 *
 * 使用エンドポイント:
 *   GET /2/users/me
 *   GET /2/users/:id/bookmarks
 */

import { ArticleData } from './types';

const X_API_BASE = 'https://api.x.com/2';

interface XUser {
  id: string;
  username: string;
  name: string;
}

interface XTweet {
  id: string;
  text: string;
  created_at?: string;
  author_id?: string;
  lang?: string;
  public_metrics?: {
    like_count: number;
    retweet_count: number;
    reply_count: number;
    quote_count: number;
    impression_count?: number;
  };
  entities?: {
    urls?: Array<{ expanded_url: string; display_url: string; url: string }>;
    hashtags?: Array<{ tag: string }>;
  };
  referenced_tweets?: Array<{ type: 'retweeted' | 'quoted' | 'replied_to'; id: string }>;
}

interface XApiResponse {
  data?: XTweet[];
  includes?: { users?: XUser[] };
  meta?: { next_token?: string; result_count?: number };
  errors?: Array<{ title: string; detail?: string }>;
}

function getUserBearerToken(): string {
  const token = process.env.X_USER_BEARER_TOKEN || process.env.X_BEARER_TOKEN;
  if (!token) {
    throw new Error(
      'X API のユーザーコンテキスト Bearer トークンが必要です。\n' +
      'OAuth 2.0 で bookmark.read / tweet.read / users.read スコープを付与した\n' +
      'User Access Token を環境変数 X_USER_BEARER_TOKEN に設定してください。\n' +
      '(App-only の Bearer では /users/:id/bookmarks は 403 になります)'
    );
  }
  return token;
}

async function callXApi<T = any>(
  pathname: string,
  token: string,
  params: Record<string, string> = {}
): Promise<T> {
  const url = new URL(X_API_BASE + pathname);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const res = await fetch(url.toString(), {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'obsidian-ai-pipeline/x-bookmarks',
    },
  });

  if (res.status === 429) {
    const reset = res.headers.get('x-rate-limit-reset');
    const resetAt = reset ? new Date(parseInt(reset, 10) * 1000).toISOString() : 'unknown';
    throw new Error(`X API rate limited (429). Reset at: ${resetAt}`);
  }

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`X API ${res.status} ${res.statusText}: ${body.substring(0, 500)}`);
  }

  return res.json() as Promise<T>;
}

async function getAuthenticatedUserId(token: string): Promise<{ id: string; username: string }> {
  const data = await callXApi<{ data: XUser }>('/users/me', token);
  if (!data?.data?.id) {
    throw new Error('X API /users/me が想定外の形式を返しました: ' + JSON.stringify(data));
  }
  return { id: data.data.id, username: data.data.username };
}

/**
 * 1 ツイートを Obsidian に保存するための ArticleData に変換する。
 * - url は正規化された https://x.com/{username}/status/{id}
 * - content は Markdown（引用符ブロック + リンク一覧 + エンゲージメント指標）
 * - textContent は Classifier への入力として「本文のみ」
 * - date は created_at の日付部分（router の四半期/月別ルーティングで利用）
 */
function tweetToArticleData(tweet: XTweet, userMap: Map<string, XUser>): ArticleData {
  const author = tweet.author_id ? userMap.get(tweet.author_id) : undefined;
  const handle = author?.username || 'i';
  const displayName = author?.name || handle;

  const url = `https://x.com/${handle}/status/${tweet.id}`;
  const firstLine = (tweet.text || '').split('\n')[0].trim();
  const titleSnippet = firstLine.length > 60 ? firstLine.substring(0, 60) + '…' : firstLine;
  const title = `${displayName} (@${handle}): ${titleSnippet || tweet.id}`;

  const date = tweet.created_at ? tweet.created_at.substring(0, 10) : undefined;

  const quotedBody = (tweet.text || '')
    .split('\n')
    .map(line => `> ${line}`)
    .join('\n');

  const expandedUrls = tweet.entities?.urls
    ?.map(u => u.expanded_url)
    .filter(u => u && !u.includes('x.com/') && !u.includes('twitter.com/'));
  const linksSection =
    expandedUrls && expandedUrls.length > 0
      ? `\n\n## 含まれるリンク\n${expandedUrls.map(u => `- ${u}`).join('\n')}`
      : '';

  const m = tweet.public_metrics;
  const metricsSection = m
    ? `\n\n---\n**エンゲージメント**: ❤️ ${m.like_count} · 🔁 ${m.retweet_count} · 💬 ${m.reply_count} · 🗨️ ${m.quote_count}`
    : '';

  const refType = tweet.referenced_tweets?.[0]?.type;
  const refBadge = refType ? `\n\n*(${refType} tweet)*` : '';

  const content = `${quotedBody}${refBadge}${linksSection}${metricsSection}\n\n[元ポストを X で見る](${url})\n`;

  // Classifier は textContent を本文として読む。純粋な本文テキストを渡す。
  const textContent = tweet.text || '';

  return {
    url,
    title,
    content,
    textContent,
    excerpt: firstLine.substring(0, 200),
    date,
    siteName: 'X (Twitter)',
  };
}

export interface FetchBookmarksOptions {
  /** 取得上限。未指定なら全ページ取得。 */
  maxItems?: number;
  /** 1 ページあたりの件数 (X API 上限 100)。 */
  pageSize?: number;
}

/**
 * ログインユーザーのブックマークを全件（または maxItems まで）取得し、
 * パイプラインが扱える ArticleData の配列に変換して返す。
 */
export async function fetchBookmarks(
  options: FetchBookmarksOptions = {}
): Promise<ArticleData[]> {
  const token = getUserBearerToken();
  const pageSize = Math.min(Math.max(options.pageSize ?? 100, 1), 100);
  const maxItems = options.maxItems ?? Infinity;

  console.log('🔖 [X] /users/me で認証ユーザー ID を解決中...');
  const { id: userId, username } = await getAuthenticatedUserId(token);
  console.log(`🔖 [X] 認証済み: @${username} (id=${userId})`);

  const results: ArticleData[] = [];
  let nextToken: string | undefined;
  let page = 0;

  do {
    page += 1;
    const params: Record<string, string> = {
      max_results: String(pageSize),
      'tweet.fields': 'created_at,text,public_metrics,entities,lang,referenced_tweets',
      expansions: 'author_id',
      'user.fields': 'username,name',
    };
    if (nextToken) params['pagination_token'] = nextToken;

    const data = await callXApi<XApiResponse>(`/users/${userId}/bookmarks`, token, params);

    if (data.errors && data.errors.length > 0) {
      console.warn(`[X] API が errors を返しました: ${JSON.stringify(data.errors)}`);
    }

    const tweets = data.data || [];
    const users = data.includes?.users || [];
    const userMap = new Map(users.map(u => [u.id, u]));

    console.log(`🔖 [X] page ${page}: ${tweets.length} 件取得`);

    for (const tweet of tweets) {
      if (results.length >= maxItems) break;
      results.push(tweetToArticleData(tweet, userMap));
    }

    nextToken = data.meta?.next_token;
    if (results.length >= maxItems) break;
  } while (nextToken);

  console.log(`🔖 [X] ブックマーク合計 ${results.length} 件を ArticleData に正規化しました。`);
  return results;
}
