import fs from "node:fs/promises";
import path from "node:path";
import { readJsonFile, fileExists } from "../fs/file-utils.js";
import type { XTokenSet } from "../types/shared.js";

export async function saveTokens(tokensPath: string, tokens: XTokenSet): Promise<void> {
  await fs.mkdir(path.dirname(tokensPath), { recursive: true });
  await fs.writeFile(tokensPath, `${JSON.stringify(tokens, null, 2)}\n`, {
    encoding: "utf-8",
    mode: 0o600
  });
}

export async function loadTokens(tokensPath: string): Promise<XTokenSet> {
  if (!(await fileExists(tokensPath))) {
    throw new Error(`Token file not found: ${tokensPath}. Run auth flow first.`);
  }
  return readJsonFile<XTokenSet>(tokensPath);
}
