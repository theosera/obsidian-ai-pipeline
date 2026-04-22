/**
 * URL のサイトポリシー判定。
 *
 * パイプラインがフェッチする前に URL を 3 カテゴリに振り分ける:
 *   - manual_skip   : 技術記事にならない動的サイト (X, YouTube, 各種チャットUI)
 *   - public_review : 画像や有料領域を含みがちで、抽出結果の完全性を人間チェック
 *                     したい媒体 (note, wired 等)。保存前のレビューでマーカー表示される
 *   - public_auto   : 上記以外。Playwright のヘッドレスブラウザで取得して進める
 *
 * 判定は URL.hostname ベースの完全一致 (サブドメイン許容) で行う。
 * 旧実装の includes() は `x.com` が `netflix.com` に誤マッチするバグがあった。
 */
export type SitePolicy = 'manual_skip' | 'public_review' | 'public_auto';

const SKIP_LIST = [
  'google.com/search',
  'x.com',
  'youtube.com',
  'chatgpt.com',
  'grok.com',
  'gemini.google.com',
] as const;

const REVIEW_LIST = ['note.com', 'wired.jp'] as const;

function matchesHostRule(url: string, rule: string): boolean {
  let host: string;
  let pathname: string;
  try {
    const u = new URL(url);
    host = u.hostname.toLowerCase();
    pathname = u.pathname;
  } catch {
    return false;
  }
  const [rHost, ...rPathParts] = rule.split('/');
  const rPath = rPathParts.length ? '/' + rPathParts.join('/') : '';
  const hostOk = host === rHost || host.endsWith('.' + rHost);
  if (!hostOk) return false;
  return rPath ? pathname.startsWith(rPath) : true;
}

export function evaluatePolicy(url: string): SitePolicy {
  if (SKIP_LIST.some((r) => matchesHostRule(url, r))) return 'manual_skip';
  if (REVIEW_LIST.some((r) => matchesHostRule(url, r))) return 'public_review';
  return 'public_auto';
}
