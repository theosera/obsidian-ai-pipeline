/**
 * 1 グループ 1 MD ページに埋め込む dataviewjs テンプレート。
 *
 * Obsidian の Dataview コミュニティプラグインを前提とする (README 参照)。
 * 各グループ MD の `<group>/<group>.md` にこのテンプレートを sentinel
 * (`<!-- x-bookmarks:auto:start -->` ... `<!-- x-bookmarks:auto:end -->`)
 * で囲って書き出す。再生成時はその間だけを差し替え、外側のユーザー記述は保護する。
 *
 * テーブル列は **常に同じ** ことが重要 (AI 要約プロデューサー未実装でも `summary` 列を確保):
 *   - published / author / tweet / likes / replies / summary / url
 *
 * `dv.io.load()` で読む JSON は `<base>/.x_bookmarks.json` (vault-relative)。
 */

export const SENTINEL_START = '<!-- x-bookmarks:auto:start -->';
export const SENTINEL_END = '<!-- x-bookmarks:auto:end -->';

interface RenderArgs {
  /** グループ名 (例: "Claude Code"). dataviewjs 内では実行時に file.folder から再抽出する */
  group: string;
  /** vault-relative path of the JSON DB (例: "X_Bookmarks/.x_bookmarks.json") */
  jsonRelativePath: string;
}

/**
 * `<group>.md` 全体を返す (sentinel 込み)。
 * 既存ファイルに sentinel 区間がある場合は `replaceAutoBlock()` で部分置換に使う。
 */
export function renderGroupPage(args: RenderArgs): string {
  const auto = renderAutoBlock(args);
  return `# ${args.group}\n\n${auto}\n`;
}

/**
 * sentinel で囲まれた自動生成ブロックだけを返す (テンプレート本体)。
 *
 * dataviewjs 側では、ページのフォルダ名から `group` を再抽出する。これにより
 * ユーザーがフォルダをリネームしてもテンプレ生成 = 表示 = フォルダ実態が一致する。
 */
export function renderAutoBlock(args: RenderArgs): string {
  const safeJsonPath = args.jsonRelativePath.replace(/\\/g, '/');
  const lines = [
    SENTINEL_START,
    '```dataviewjs',
    `const data = JSON.parse(await dv.io.load("${safeJsonPath}"));`,
    'const folder = dv.current().file.folder.split("/").pop();',
    'const rows = (data.rows || [])',
    '  .filter(r => r.group === folder)',
    '  .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));',
    'dv.table(',
    '  ["published", "author", "tweet", "likes", "replies", "summary", "url"],',
    '  rows.map(r => [',
    '    (r.created_at || "").slice(0, 10),',
    '    r.author || "",',
    '    (r.tweet_text || "").slice(0, 280),',
    '    r.engagement_likes ?? 0,',
    '    r.engagement_replies ?? 0,',
    '    r.ai_summary || "",',
    '    r.url ? `[link](${r.url})` : "",',
    '  ]),',
    ');',
    '```',
    SENTINEL_END,
  ];
  return lines.join('\n');
}

/**
 * 既存 `<group>.md` 内の sentinel 区間を新しい auto block で差し替える。
 *
 * sentinel が無い場合 = ユーザーが手書きで MD を作っていた、または最初の生成。
 * その場合は末尾に追記する (ユーザー本文は前段に残す)。
 */
export function replaceAutoBlock(existing: string, args: RenderArgs): string {
  const auto = renderAutoBlock(args);
  const startIdx = existing.indexOf(SENTINEL_START);
  const endIdx = existing.indexOf(SENTINEL_END);
  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) {
    // sentinel 無し: 末尾に追記
    const trimmed = existing.replace(/\s+$/, '');
    return `${trimmed}\n\n${auto}\n`;
  }
  const before = existing.slice(0, startIdx);
  const after = existing.slice(endIdx + SENTINEL_END.length);
  return `${before}${auto}${after}`;
}
