/**
 * 信頼できないテキストのサニタイズ（制御文字・ゼロ幅文字を除去）
 * ポート元: classifier.ts:198-205
 */
export function sanitizeUntrustedText(raw: string, maxLength: number): string {
  if (!raw || typeof raw !== 'string') return '';
  return raw
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')  // 制御文字（改行・タブは保持）
    .replace(/[\u200b-\u200f\u2028-\u202f\u2060\ufeff\ufff9-\ufffb]/g, '') // ゼロ幅・不可視Unicode
    .replace(/[\u0000]/g, '')  // nullバイト
    .slice(0, maxLength);
}

/**
 * YAML frontmatter用エスケープ
 * ポート元: storage.ts:173-181
 */
export function escapeFrontmatter(str: string): string {
  if (!str) return '';
  return str
    .replace(/\\/g, '\\\\')          // バックスラッシュをエスケープ
    .replace(/"/g, '\\"')             // ダブルクォートをエスケープ
    .replace(/\n/g, ' ')              // 改行をスペースに変換
    .replace(/\r/g, '')               // CRを除去
    .replace(/---/g, '\\-\\-\\-');    // YAMLセパレータを無害化
}
