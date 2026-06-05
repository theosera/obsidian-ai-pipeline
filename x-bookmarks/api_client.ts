/**
 * X API v2 ブックマーク取得クライアント (Playwright スクレイパからの置換)。
 *
 * 公式エンドポイント:
 *   GET /2/users/:id/bookmarks                        — 全ブックマーク (本文込み, ページング有)
 *   GET /2/users/:id/bookmarks/folders                — フォルダ一覧
 *   GET /2/users/:id/bookmarks/folders/:folder_id     — フォルダ内ツイートID列のみ
 *                                                       (params 不可, 本文無し)
 *   GET /2/tweets?ids=...                             — ID から本文をハイドレート (最大100件/req)
 *
 *   フォルダ別取り込みは「索引 (folders/:id) → 本文 (tweets?ids=)」の 2 段。
 *   詳細経緯は docs/x_bookmarks_api_research.md
 *
 * 認可: OAuth 2.0 Authorization Code Flow with PKCE (token 永続化は `tokens.ts`)。
 *   scope: tweet.read users.read bookmark.read offline.access
 *
 * コスト配慮:
 *   - pay-per-use。skipKnownIds で DB 既知の ID は索引段階で除外し、
 *     本文ハイドレーション (/2/tweets) を呼ばない。
 *
 * レート制限:
 *   /bookmarks                — 180 req / 15分
 *   /bookmarks/folders        — 50 req / 15分
 *   /bookmarks/folders/{id}   — 50 req / 15分
 *   /tweets                   — 300 req / 15分 (user)
 */
import {
  ApiBookmark,
  FetchOptions,
  FolderListing,
  XUser,
  XPost,
  XMediaResponse,
  BookmarksResponse,
  BookmarkFoldersResponse,
} from './types';
import {
  loadTokens,
  saveTokens,
  refreshAccessToken,
  getValidAccessToken,
  isTokenExpired,
} from './tokens';
import {
  extractFramesFromTweetVideo,
  isVideoFramesEnabled,
  pickBestVariantUrl,
  pickVideoMedia,
  renderKeyFramesSection,
} from './video_frames';

const API_BASE = 'https://api.x.com/2';

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
export function tweetToApiBookmark(
  post: XPost,
  author: XUser | undefined,
  folderName: string,
  /**
   * media_key → XMediaResponse の解決関数。
   * `expandBookmarksPage` が `includes.media[]` から map を作って渡す。
   * 省略時は media 抽出をスキップ (テスト互換)。
   */
  mediaResolver?: (mediaKey: string) => XMediaResponse | undefined,
): ApiBookmark {
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
  // 著者が API includes.users から解決できなかったケースでは URL/title の表示用
  // フォールバック ('unknown') を流用しつつ、DB / JSON ビュー には書かない
  // ことで「実値」と「不明」を区別できるようにする。
  if (author?.username) result.xAuthorHandle = author.username;
  if (typeof likes === 'number') result.xLikes = likes;
  if (typeof retweets === 'number') result.xRetweets = retweets;
  if (typeof replies === 'number') result.xReplies = replies;
  if (post.note_tweet?.text) {
    result.xNoteTweetText = post.note_tweet.text;
  }

  // 動画 (video / animated_gif) があれば最高 bitrate URL と duration を ApiBookmark に転記。
  // 実フレーム抽出は async 後処理 (enrichBookmarksWithFrames) に委ねる。
  // `pickVideoMedia` / `pickBestVariantUrl` の選別ロジックを共有して、
  // 「何が主動画か」「どの variant を選ぶか」のルールを一箇所に保つ。
  if (mediaResolver && post.attachments?.media_keys?.length) {
    const resolved = post.attachments.media_keys
      .map(k => mediaResolver(k))
      .filter((m): m is XMediaResponse => !!m);
    const video = pickVideoMedia(resolved);
    const best = video ? pickBestVariantUrl(video) : undefined;
    if (video && best) {
      result.xVideoUrl = best;
      if (typeof video.duration_ms === 'number') {
        result.xVideoDurationMs = video.duration_ms;
      }
    }
  }

  return result;
}

/**
 * BookmarksResponse を ApiBookmark[] に展開。
 * includes.users の id → XUser マップを構築して author を解決する。
 *
 * `folderId` を渡すと各 ApiBookmark に xFolderId をセット (session 紐付けに利用)。
 * Unfiled fetch の場合は undefined のままにする。
 */
export function expandBookmarksPage(
  page: BookmarksResponse,
  folderName: string,
  folderId?: string
): ApiBookmark[] {
  const userMap = new Map<string, XUser>((page.includes?.users ?? []).map(u => [u.id, u]));
  const mediaMap = new Map<string, XMediaResponse>(
    (page.includes?.media ?? []).map(m => [m.media_key, m])
  );
  const resolver = (key: string) => mediaMap.get(key);
  const out: ApiBookmark[] = [];
  for (const post of page.data ?? []) {
    const author = post.author_id ? userMap.get(post.author_id) : undefined;
    const bm = tweetToApiBookmark(post, author, folderName, resolver);
    if (folderId) bm.xFolderId = folderId;
    out.push(bm);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Endpoint builders (pure)
// ---------------------------------------------------------------------------
function buildBookmarksUrl(userId: string, paginationToken?: string): string {
  const url = new URL(`${API_BASE}/users/${userId}/bookmarks`);
  url.searchParams.set('max_results', '100');
  url.searchParams.set('tweet.fields', 'created_at,author_id,public_metrics,entities,note_tweet,attachments');
  url.searchParams.set('expansions', 'author_id,attachments.media_keys');
  url.searchParams.set('user.fields', 'username,name');
  url.searchParams.set('media.fields', 'type,duration_ms,preview_image_url,variants,alt_text');
  if (paginationToken) url.searchParams.set('pagination_token', paginationToken);
  return url.toString();
}

// 索引専用エンドポイント。X API はクエリパラメータを一切受け付けず
// `{ data: [{ id }, ...] }` (ツイートID列のみ) を返す。
// 本文・著者・メディアは buildTweetsLookupUrl 経由でハイドレートする。
// 参考: docs/x_bookmarks_api_research.md
function buildFolderBookmarksUrl(userId: string, folderId: string): string {
  return `${API_BASE}/users/${userId}/bookmarks/folders/${folderId}`;
}

// /2/tweets?ids=... は 1 リクエスト最大 100 件。
// expansions / *.fields は通常の bookmarks 取得と揃えておく。
function buildTweetsLookupUrl(ids: string[]): string {
  const url = new URL(`${API_BASE}/tweets`);
  url.searchParams.set('ids', ids.join(','));
  url.searchParams.set('tweet.fields', 'created_at,author_id,public_metrics,entities,note_tweet,attachments');
  url.searchParams.set('expansions', 'author_id,attachments.media_keys');
  url.searchParams.set('user.fields', 'username,name');
  url.searchParams.set('media.fields', 'type,duration_ms,preview_image_url,variants,alt_text');
  return url.toString();
}

// 100 件ごとにチャンクして /2/tweets?ids= でハイドレート。
// 戻り値は通常の BookmarksResponse 形式 (data + includes) にマージ。
const TWEETS_LOOKUP_CHUNK = 100;

async function hydrateTweetsByIds(
  ids: string[],
  ctx: { accessToken: string; clientId: string; clientSecret: string; fetchFn: typeof fetch; onRefreshed?: (t: string) => void }
): Promise<BookmarksResponse> {
  if (ids.length === 0) return { data: [], includes: { users: [], media: [] } };
  const merged: BookmarksResponse = { data: [], includes: { users: [], media: [] } };
  const seenUsers = new Set<string>();
  const seenMedia = new Set<string>();
  for (let i = 0; i < ids.length; i += TWEETS_LOOKUP_CHUNK) {
    const chunk = ids.slice(i, i + TWEETS_LOOKUP_CHUNK);
    const page = await xGet<BookmarksResponse>(buildTweetsLookupUrl(chunk), ctx);
    if (page.data) merged.data!.push(...page.data);
    for (const u of page.includes?.users ?? []) {
      if (!seenUsers.has(u.id)) { seenUsers.add(u.id); merged.includes!.users!.push(u); }
    }
    for (const m of page.includes?.media ?? []) {
      if (!seenMedia.has(m.media_key)) { seenMedia.add(m.media_key); merged.includes!.media!.push(m); }
    }
  }
  return merged;
}

async function fetchFolderTweetIds(
  userId: string,
  folderId: string,
  ctx: { accessToken: string; clientId: string; clientSecret: string; fetchFn: typeof fetch; onRefreshed?: (t: string) => void }
): Promise<string[]> {
  // 実測 (11件フォルダ) では meta 自体返らず、pagination_token 以外の query は
  // 「[id, folder_id] のみ受付」400 で弾かれた。pagination_token の可否は未検証。
  // → meta.next_token が返ったら警告して可視化する (Codex PR #38 review への対応)。
  const res = await xGet<{ data?: { id: string }[]; meta?: { next_token?: string } }>(
    buildFolderBookmarksUrl(userId, folderId),
    ctx
  );
  if (res.meta?.next_token) {
    console.warn(
      `🔖 [X API] WARNING: folder ${folderId} returned meta.next_token but ` +
      `/bookmarks/folders/{id} ページング実装は未対応 (X API がクエリ全般を拒否するため未検証)。` +
      `このフォルダのブックマークが欠落している可能性があります。` +
      `docs/x_api_v2_gotchas.md の「フォルダ索引のページング」項目を参照してください。`
    );
  }
  return (res.data ?? []).map(d => d.id);
}

function buildFoldersUrl(userId: string, paginationToken?: string): string {
  const url = new URL(`${API_BASE}/users/${userId}/bookmarks/folders`);
  url.searchParams.set('max_results', '100');
  if (paginationToken) url.searchParams.set('pagination_token', paginationToken);
  return url.toString();
}

// ---------------------------------------------------------------------------
// Stage 1: フォルダ一覧のみ取得 (本文 fetch は走らせない)
// ---------------------------------------------------------------------------
/**
 * `--x-pick` の Stage 1 で利用する軽量フェッチ。
 * `/users/me` + `/bookmarks/folders` のみ叩き、本文取得 (`/bookmarks/folders/:id`)
 * には進まない。これにより「とりあえず一覧だけ確認」のコストを大幅に下げる。
 */
export async function listFolders(
  fetchFn: typeof fetch = fetch
): Promise<FolderListing> {
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

  const me = await xGet<{ data: { id: string; username: string } }>(
    `${API_BASE}/users/me`,
    ctx
  );
  const userId = me.data.id;
  const username = me.data.username;

  const folders: { id: string; name: string }[] = [];
  let token: string | undefined;
  do {
    const page = await xGet<BookmarkFoldersResponse>(buildFoldersUrl(userId, token), ctx);
    folders.push(...(page.data ?? []));
    token = page.meta?.next_token;
  } while (token);

  return { userId, username, folders };
}

// ---------------------------------------------------------------------------
// Main fetch entry
// ---------------------------------------------------------------------------
export async function fetchBookmarksViaApi(options: FetchOptions = {}): Promise<ApiBookmark[]> {
  const maxItems = options.maxItems ?? Infinity;
  const skipKnownIds = options.skipKnownIds ?? new Set<string>();
  const fetchFn = options.fetchFn ?? fetch;
  // selectedFolders が undefined: 従来通り「全フォルダ列挙」
  // selectedFolders が空配列:     フォルダ取得をスキップ (Unfiled だけ取りたいときの明示意図)
  // selectedFolders が配列:        その {id,name} のフォルダのみ取得
  const selectedFolders = options.selectedFolders;
  const includeUnfiled = options.includeUnfiled ?? true;

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

  // 2. フォルダ一覧 (--x-pick 経由で selectedFolders が来ているなら列挙不要)
  let folders: { id: string; name: string }[];
  if (selectedFolders === undefined) {
    folders = [];
    let token: string | undefined;
    do {
      const page = await xGet<BookmarkFoldersResponse>(buildFoldersUrl(userId, token), ctx);
      folders.push(...(page.data ?? []));
      token = page.meta?.next_token;
    } while (token);
    console.log(
      `🔖 [X API] フォルダ ${folders.length} 件: ${folders.map(f => f.name).join(', ') || '(なし)'}`
    );
  } else {
    folders = selectedFolders;
    console.log(
      `🔖 [X API] 指定フォルダ ${folders.length} 件のみ取得: ${folders.map(f => f.name).join(', ') || '(なし)'}`
    );
  }

  const all: ApiBookmark[] = [];
  const folderTweetIds = new Set<string>();

  // 3a. selectedFolders + includeUnfiled の組み合わせは、Unfiled 判定のために
  //    「他のフォルダにあるツイート ID」も必要 (なければ folder X のツイートが
  //     Unfiled として誤分類される)。ID 収集だけ目的で他フォルダも fetch する。
  //     本文は all[] に積まない (--x-pick の選択意図を尊重)。
  if (selectedFolders !== undefined && includeUnfiled) {
    const allFolders: { id: string; name: string }[] = [];
    let token: string | undefined;
    do {
      const page = await xGet<BookmarkFoldersResponse>(buildFoldersUrl(userId, token), ctx);
      allFolders.push(...(page.data ?? []));
      token = page.meta?.next_token;
    } while (token);
    const selectedIds = new Set(selectedFolders.map(f => f.id));
    const otherFolders = allFolders.filter(f => !selectedIds.has(f.id));
    if (otherFolders.length > 0) {
      console.log(
        `🔖 [X API] _Unfiled 判定のため他 ${otherFolders.length} フォルダの ID を収集します ` +
        `(本文ハイドレーションはスキップ)`
      );
      for (const f of otherFolders) {
        const ids = await fetchFolderTweetIds(userId, f.id, ctx);
        for (const id of ids) folderTweetIds.add(id);
      }
    }
  }

  // 3. フォルダ毎: 索引で全 ID 取得 → 既知除外 → /2/tweets でハイドレート。
  //    (folders/:id はページング無し / params 不可。詳細 docs/x_bookmarks_api_research.md)
  for (const folder of folders) {
    if (all.length >= maxItems) break;
    const allIds = await fetchFolderTweetIds(userId, folder.id, ctx);
    for (const id of allIds) folderTweetIds.add(id);
    const newIds = allIds.filter(id => !skipKnownIds.has(id));
    const remaining = maxItems - all.length;
    const targetIds = remaining < newIds.length ? newIds.slice(0, remaining) : newIds;
    if (targetIds.length === 0) {
      console.log(`🔖 [X API]   "${folder.name}": 0 件 (新規) / index=${allIds.length}`);
      continue;
    }
    const page = await hydrateTweetsByIds(targetIds, ctx);
    const bookmarks = expandBookmarksPage(page, folder.name, folder.id);
    all.push(...bookmarks);
    console.log(
      `🔖 [X API]   "${folder.name}": ${bookmarks.length} 件 (新規) / index=${allIds.length}`
    );
  }

  // 4. Unfiled (All Bookmarks にあるがどのフォルダにも無いもの)
  // --x-pick で _Unfiled が選ばれていない場合は API コールを丸ごと省略する。
  if (includeUnfiled && all.length < maxItems) {
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

  // 動画フレーム抽出 (X_VIDEO_FRAMES=true のときだけ動作)
  if (isVideoFramesEnabled()) {
    await enrichBookmarksWithFrames(all);
  }

  return all;
}

/**
 * 取得済み bookmark 群に対して、動画があるツイートはフレームを抽出して
 * `## キーフレーム` セクションを `content` 末尾に追記する。
 *
 * 失敗 (DL 失敗 / size 超過 / ffmpeg 不在等) しても本文保存は妨げない。
 * 個々のツイートの失敗は警告ログのみ。
 */
async function enrichBookmarksWithFrames(bookmarks: ApiBookmark[]): Promise<void> {
  // duration_ms 不在の動画も拾う (extractFramesFromTweetVideo 側で `no_duration`
  // skip が出て本文に「取得失敗」セクションが出る → silently 落ちることがない)
  const targets = bookmarks.filter(b => b.xVideoUrl);
  if (targets.length === 0) return;
  console.log(`🎞️  [X API] 動画 ${targets.length} 件のキーフレーム抽出を開始`);
  let success = 0;
  let failed = 0;
  const skipReasons: Record<string, number> = {};
  for (const bm of targets) {
    try {
      const result = await extractFramesFromTweetVideo(
        bm.xTweetId,
        bm.xVideoUrl!,
        bm.xVideoDurationMs ?? 0,
        { logger: (m) => console.log(m) },
      );
      const section = renderKeyFramesSection(result);
      if (section) {
        bm.content = (bm.content ?? '') + section;
      }
      if (result.skipped) {
        skipReasons[result.skipped] = (skipReasons[result.skipped] ?? 0) + 1;
      } else {
        success += 1;
      }
    } catch (e: any) {
      console.warn(`   ⚠️  frame extraction failed for ${bm.xTweetId}: ${e.message}`);
      failed += 1;
    }
  }
  const skipSummary = Object.keys(skipReasons).length === 0
    ? ''
    : ' / skipped: ' + Object.entries(skipReasons).map(([k, v]) => `${k}=${v}`).join(', ');
  console.log(
    `🎞️  [X API] キーフレーム抽出完了: success=${success} failed=${failed}${skipSummary}`
  );
}

// テスト用 export。isTokenExpired は tokens.ts に移ったが、既存テスト
// (apiInternals.isTokenExpired) との互換のためここから再エクスポートする。
export const __test = {
  tweetToApiBookmark,
  expandBookmarksPage,
  isTokenExpired,
  buildBookmarksUrl,
  buildFolderBookmarksUrl,
  buildTweetsLookupUrl,
  buildFoldersUrl,
};
