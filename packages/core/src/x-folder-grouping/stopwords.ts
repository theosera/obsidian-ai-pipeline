export const DEFAULT_STOPWORDS = new Set([
  "and",
  "or",
  "the",
  "a",
  "an",
  "of",
  "for",
  "to",
  "in",
  "on",
  "by",
  "with",
  "from",
  "info",
  "notes",
  "memo",
  "misc",
  "other",
  "その他",
  "メモ",
  "雑多",
  "資料",
  "情報",
  "まとめ"
]);

export function isStopword(token: string): boolean {
  return DEFAULT_STOPWORDS.has(token.toLowerCase());
}
