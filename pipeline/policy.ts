/**
 * URL のサイトポリシー判定。
 *
 * パイプラインがフェッチする前に URL を 3 カテゴリに振り分ける:
 *   - manual_skip   : 技術記事にならない動的サイト (X, YouTube, 各種チャットUI)
 *   - public_review : 画像や有料領域を含みがちで、抽出結果の完全性を人間チェック
 *                     したい媒体 (note, wired 等)。保存前のレビューでマーカー表示される
 *   - public_auto   : 上記以外。Playwright のヘッドレスブラウザで取得して進める
 *
 * 判定は URL 部分一致のみの単純ロジック。個別の例外はルールベース (classifier)
 * 側で扱い、ここでは「そもそもフェッチするか」のゲートだけを担う。
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

export function evaluatePolicy(url: string): SitePolicy {
  if (SKIP_LIST.some((s) => url.includes(s))) return 'manual_skip';
  if (REVIEW_LIST.some((s) => url.includes(s))) return 'public_review';
  return 'public_auto';
}
