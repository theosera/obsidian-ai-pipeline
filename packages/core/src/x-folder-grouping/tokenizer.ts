import { stripDateSuffix } from "../path/date-suffix-stripper.js";

const SPLIT_REGEX = /[ _-]+/;

export function tokenizeFolderName(folderName: string): string[] {
  const stripped = stripDateSuffix(folderName);
  return stripped
    .split(SPLIT_REGEX)
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token.length > 0);
}
