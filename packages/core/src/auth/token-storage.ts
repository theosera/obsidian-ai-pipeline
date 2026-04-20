import { readJsonFile, writeJsonFile, fileExists } from "../fs/file-utils.js";
import type { XTokenSet } from "../types/shared.js";

export async function saveTokens(tokensPath: string, tokens: XTokenSet): Promise<void> {
  await writeJsonFile(tokensPath, tokens);
}

export async function loadTokens(tokensPath: string): Promise<XTokenSet> {
  if (!(await fileExists(tokensPath))) {
    throw new Error(`Token file not found: ${tokensPath}. Run auth flow first.`);
  }
  return readJsonFile<XTokenSet>(tokensPath);
}
