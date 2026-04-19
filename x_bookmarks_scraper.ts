/**
 * X (Twitter) ブックマーク Playwright スクレイパー。
 *
 * 既存 fetcher.ts の永続 Chromium セッション (~/.chromium-data) を流用し、
 * X UI からブックマークフォルダ構造とフォルダ内ツイートをスクレイプする。
 *
 * フロー:
 *   1. /i/bookmarks にアクセスしてログイン状態を確認
 *   2. /i/bookmarks/all_folders からフォルダ一覧と folder_id を取得
 *   3. 各フォルダ /i/bookmarks/<folder_id> をスクロールしてツイート収集
 *   4. /i/bookmarks (All Bookmarks) も同様にスクレイプし、フォルダ別取得済みID
 *      を除外して未整理ツイートを抽出 (フォルダ名 "_Unfiled")
 *
 * 差分スクレイプ:
 *   - skipKnownIds に含まれるツイートIDに 3 件連続で遭遇したら、
 *     そのフォルダのスクロールを早期終了する (X は新着順表示のため)
 *
 * 公開 API:
 *   scrapeBookmarksByFolder(options) → Promise<ScrapedBookmark[]>
 *
 * 注: ツイート → ArticleData 変換ロジックは旧 x_bookmarks.ts の
 *     tweetToArticleData の体裁 (引用ブロック + リンク + メトリクス + 元ポストリンク)
 *     を踏襲する。
 */

import { Page } from 'playwright';
import { getBrowserContext } from './fetcher';
import { ArticleData } from './types';

export interface ScrapedBookmark extends ArticleData {
  xFolderName: string;
  xTweetId: string;
}

export interface ScrapeOptions {
  maxItems?: number;
  skipKnownIds?: Set<string>;
  /** スクロール間の待機 ms (テストでオーバーライド可) */
  scrollWaitMs?: number;
  /** 1 フォルダあたり最大スクロール回数 */
  maxScrollsPerFolder?: number;
}

interface RawTweet {
  tweetId: string;
  url: string;
  authorHandle: string;
  authorDisplayName: string;
  text: string;
  createdAt: string | null;
  likeCount: number | null;
  retweetCount: number | null;
  replyCount: number | null;
  expandedUrls: string[];
}

const SELECTORS = {
  tweetArticle: 'article[data-testid="tweet"]',
  loginBlocked: 'a[href="/login"], a[href*="/i/flow/login"]',
};

const X_BASE = 'https://x.com';

/**
 * ページ内 DOM からツイート要素配列を抽出する関数。Playwright page.evaluate に渡す。
 * 戻り値の構造はシリアライザブルなプリミティブのみで構成する必要がある。
 */
function extractTweetsScript(): RawTweet[] {
  const articles = Array.from(document.querySelectorAll('article[data-testid="tweet"]'));
  const out: RawTweet[] = [];
  for (const art of articles) {
    const statusLink = art.querySelector('a[href*="/status/"]') as HTMLAnchorElement | null;
    if (!statusLink) continue;
    const m = statusLink.getAttribute('href')?.match(/^\/([^/]+)\/status\/(\d+)/);
    if (!m) continue;
    const authorHandle = m[1];
    const tweetId = m[2];
    const url = `https://x.com/${authorHandle}/status/${tweetId}`;

    const userNameBlock = art.querySelector('div[data-testid="User-Name"]');
    const displayNameSpan = userNameBlock?.querySelector('span');
    const authorDisplayName = displayNameSpan?.textContent?.trim() || authorHandle;

    const tweetTextEl = art.querySelector('div[data-testid="tweetText"]');
    // textContent はリンクの expanded text を含まない場合があるため、子ノードを順次走査
    const text = (tweetTextEl?.textContent || '').trim();

    const timeEl = art.querySelector('time');
    const createdAt = timeEl?.getAttribute('datetime') || null;

    const parseMetric = (testid: string): number | null => {
      const el = art.querySelector(`button[data-testid="${testid}"], div[data-testid="${testid}"]`);
      if (!el) return null;
      const label = el.getAttribute('aria-label') || el.textContent || '';
      const num = label.match(/[\d,]+/);
      if (!num) return null;
      return parseInt(num[0].replace(/,/g, ''), 10);
    };

    const likeCount = parseMetric('like');
    const retweetCount = parseMetric('retweet');
    const replyCount = parseMetric('reply');

    const expandedUrls = Array.from(art.querySelectorAll('a[href]'))
      .map(a => (a as HTMLAnchorElement).href)
      .filter(h => h && !h.includes('x.com/') && !h.includes('twitter.com/'))
      .filter((v, i, arr) => arr.indexOf(v) === i);

    out.push({
      tweetId,
      url,
      authorHandle,
      authorDisplayName,
      text,
      createdAt,
      likeCount,
      retweetCount,
      replyCount,
      expandedUrls,
    });
  }
  return out;
}

/**
 * フォルダ一覧ページの DOM から { name, folderId } を抽出する関数。page.evaluate 用。
 *
 * X のフォルダ一覧 URL は /i/bookmarks/all_folders で、各フォルダへのリンクは
 *   /i/bookmarks/<folder_id>
 * の形式。folder_id は数値文字列。
 */
function extractFoldersScript(): { name: string; folderId: string }[] {
  const links = Array.from(document.querySelectorAll('a[href^="/i/bookmarks/"]'));
  const out: { name: string; folderId: string }[] = [];
  const seen = new Set<string>();
  for (const a of links) {
    const href = a.getAttribute('href') || '';
    const m = href.match(/^\/i\/bookmarks\/(\d+)/);
    if (!m) continue;
    const folderId = m[1];
    if (seen.has(folderId)) continue;
    const name = (a.textContent || '').trim();
    if (!name) continue;
    seen.add(folderId);
    out.push({ name, folderId });
  }
  return out;
}

/**
 * 1 ツイート (RawTweet) → ScrapedBookmark に変換。
 * 旧 x_bookmarks.ts の tweetToArticleData の体裁を踏襲。
 */
function rawToScrapedBookmark(raw: RawTweet, xFolderName: string): ScrapedBookmark {
  const firstLine = raw.text.split('\n')[0].trim();
  const titleSnippet = firstLine.length > 60 ? firstLine.substring(0, 60) + '…' : firstLine;
  const title = `${raw.authorDisplayName} (@${raw.authorHandle}): ${titleSnippet || raw.tweetId}`;
  const date = raw.createdAt ? raw.createdAt.substring(0, 10) : undefined;

  const quotedBody = raw.text
    .split('\n')
    .map(line => `> ${line}`)
    .join('\n');

  const linksSection = raw.expandedUrls.length > 0
    ? `\n\n## 含まれるリンク\n${raw.expandedUrls.map(u => `- ${u}`).join('\n')}`
    : '';

  const hasMetric = raw.likeCount != null || raw.retweetCount != null || raw.replyCount != null;
  const metricsSection = hasMetric
    ? `\n\n---\n**エンゲージメント**: ❤️ ${raw.likeCount ?? '-'} · 🔁 ${raw.retweetCount ?? '-'} · 💬 ${raw.replyCount ?? '-'}`
    : '';

  const content = `${quotedBody}${linksSection}${metricsSection}\n\n[元ポストを X で見る](${raw.url})\n`;

  return {
    url: raw.url,
    title,
    content,
    textContent: raw.text,
    excerpt: firstLine.substring(0, 200),
    date,
    siteName: 'X (Twitter)',
    xFolderName,
    xTweetId: raw.tweetId,
  };
}

async function checkLoggedIn(page: Page): Promise<void> {
  await page.goto(`${X_BASE}/i/bookmarks`, { waitUntil: 'load', timeout: 30000 });
  // ログインフローへリダイレクトされたか、ログイン誘導要素が出現したらブロック扱い
  const currentUrl = page.url();
  if (currentUrl.includes('/i/flow/login') || currentUrl.includes('/login')) {
    throw new Error(
      'X に未ログイン状態です。一度 Playwright を headless=false で起動して X に手動ログインしてください。\n' +
      '例: PWDEBUG=1 や、fetcher.ts:initBrowser の headless オプションを一時的に false に変更。'
    );
  }
  // /i/bookmarks に来たがログイン誘導 UI が出ているケース
  const loginEl = await page.$(SELECTORS.loginBlocked);
  if (loginEl) {
    throw new Error('X ログインセッションが切れている可能性があります。再度ログインしてください。');
  }
}

async function scrollAndCollect(
  page: Page,
  xFolderName: string,
  options: Required<Pick<ScrapeOptions, 'scrollWaitMs' | 'maxScrollsPerFolder'>> & {
    skipKnownIds: Set<string>;
    remainingBudget: number;
    excludeIds: Set<string>;
  }
): Promise<ScrapedBookmark[]> {
  const collected = new Map<string, ScrapedBookmark>();
  let stagnantScrolls = 0;
  let consecutiveKnown = 0;
  let scrolls = 0;

  while (scrolls < options.maxScrollsPerFolder) {
    let raws: RawTweet[];
    try {
      raws = await page.evaluate(extractTweetsScript);
    } catch (e: any) {
      console.warn(`[XScraper] DOM 抽出失敗 (folder="${xFolderName}"): ${e.message}`);
      break;
    }

    let newThisRound = 0;
    for (const raw of raws) {
      if (collected.has(raw.tweetId)) continue;
      if (options.excludeIds.has(raw.tweetId)) continue;

      if (options.skipKnownIds.has(raw.tweetId)) {
        consecutiveKnown += 1;
        if (consecutiveKnown >= 3) {
          // 既知ツイートに 3 件連続で当たった → 新着終了
          return [...collected.values()];
        }
        continue;
      }
      consecutiveKnown = 0;

      collected.set(raw.tweetId, rawToScrapedBookmark(raw, xFolderName));
      newThisRound += 1;

      if (collected.size >= options.remainingBudget) {
        return [...collected.values()];
      }
    }

    if (newThisRound === 0) {
      stagnantScrolls += 1;
      if (stagnantScrolls >= 3) break;
    } else {
      stagnantScrolls = 0;
    }

    await page.evaluate(() => window.scrollBy(0, window.innerHeight));
    await page.waitForTimeout(options.scrollWaitMs);
    scrolls += 1;
  }

  return [...collected.values()];
}

export async function scrapeBookmarksByFolder(
  options: ScrapeOptions = {}
): Promise<ScrapedBookmark[]> {
  const maxItems = options.maxItems ?? Infinity;
  const skipKnownIds = options.skipKnownIds ?? new Set<string>();
  const scrollWaitMs = options.scrollWaitMs ?? 2000;
  const maxScrollsPerFolder = options.maxScrollsPerFolder ?? 200;

  const ctx = await getBrowserContext();
  const page = await ctx.newPage();

  try {
    console.log('🔖 [XScraper] X ログイン状態を確認中...');
    await checkLoggedIn(page);

    // フォルダ一覧
    console.log('🔖 [XScraper] フォルダ一覧を取得中...');
    await page.goto(`${X_BASE}/i/bookmarks/all_folders`, { waitUntil: 'load', timeout: 30000 });
    try {
      await page.waitForLoadState('networkidle', { timeout: 8000 });
    } catch { /* ignore */ }
    await page.waitForTimeout(1500);

    const folders = await page.evaluate(extractFoldersScript);
    console.log(`🔖 [XScraper] フォルダ ${folders.length} 件を検出: ${folders.map(f => f.name).join(', ') || '(なし)'}`);

    const allResults: ScrapedBookmark[] = [];
    const folderTweetIds = new Set<string>();

    for (const folder of folders) {
      if (allResults.length >= maxItems) break;
      const remaining = maxItems - allResults.length;
      console.log(`🔖 [XScraper] folder "${folder.name}" (${folder.folderId}) を取得中 (残り上限: ${remaining})...`);

      await page.goto(`${X_BASE}/i/bookmarks/${folder.folderId}`, { waitUntil: 'load', timeout: 30000 });
      try {
        await page.waitForLoadState('networkidle', { timeout: 8000 });
      } catch { /* ignore */ }
      await page.waitForTimeout(1500);

      const got = await scrollAndCollect(page, folder.name, {
        scrollWaitMs,
        maxScrollsPerFolder,
        skipKnownIds,
        remainingBudget: remaining,
        excludeIds: new Set(),
      });
      console.log(`🔖 [XScraper]   "${folder.name}": ${got.length} 件 (新規)`);
      for (const b of got) folderTweetIds.add(b.xTweetId);
      allResults.push(...got);
    }

    // 未整理ブックマーク (All Bookmarks にあるがどのフォルダにも入っていないもの)
    if (allResults.length < maxItems) {
      const remaining = maxItems - allResults.length;
      console.log(`🔖 [XScraper] 未整理ブックマーク (_Unfiled) を取得中 (残り上限: ${remaining})...`);
      await page.goto(`${X_BASE}/i/bookmarks`, { waitUntil: 'load', timeout: 30000 });
      try {
        await page.waitForLoadState('networkidle', { timeout: 8000 });
      } catch { /* ignore */ }
      await page.waitForTimeout(1500);

      const unfiled = await scrollAndCollect(page, '_Unfiled', {
        scrollWaitMs,
        maxScrollsPerFolder,
        skipKnownIds,
        remainingBudget: remaining,
        excludeIds: folderTweetIds,
      });
      console.log(`🔖 [XScraper]   _Unfiled: ${unfiled.length} 件 (新規)`);
      allResults.push(...unfiled);
    }

    console.log(`🔖 [XScraper] 合計 ${allResults.length} 件を取得しました。`);
    return allResults;
  } finally {
    await page.close();
  }
}

// テスト用 export (内部関数を直接検証する)
export const __test = {
  extractTweetsScript,
  extractFoldersScript,
  rawToScrapedBookmark,
};
