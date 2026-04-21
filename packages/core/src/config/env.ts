import path from "node:path";
import fs from "node:fs";

export interface EnvConfig {
  xClientId: string;
  xClientSecret?: string;
  xRedirectUri: string;
  xScope: string;
  xAuthBaseUrl: string;
  xApiBaseUrl: string;
  localAuthPort: number;
  tokensPath: string;
  pkceStatePath: string;
  obsidianVaultPath: string;
  xBookmarksRoot: string;
  sourceRoot: string;
  proposalPrefix: string;
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function readPort(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value) {
    return fallback;
  }
  const trimmed = value.trim();
  const port = Number(trimmed);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(
      `Invalid port for ${name}: "${value}". Must be an integer between 1 and 65535.`
    );
  }
  return port;
}

function safeFileSegment(value: string): string {
  const trimmed = value.trim();
  const safe = trimmed.replace(/[^A-Za-z0-9._-]/g, "_");
  return safe || "codex";
}

export function loadEnvConfig(repoRoot = process.cwd()): EnvConfig {
  loadDotEnv(path.resolve(repoRoot, ".env"));
  const dataDir = path.resolve(repoRoot, "data");
  const config: EnvConfig = {
    xClientId: requireEnv("X_CLIENT_ID"),
    xRedirectUri: requireEnv("X_REDIRECT_URI"),
    xScope:
      process.env.X_SCOPE ?? "tweet.read users.read bookmark.read offline.access",
    xAuthBaseUrl: process.env.X_AUTH_BASE_URL ?? "https://twitter.com/i/oauth2",
    xApiBaseUrl: process.env.X_API_BASE_URL ?? "https://api.x.com",
    localAuthPort: readPort("AUTH_PORT", 3838),
    tokensPath: process.env.TOKENS_PATH ?? path.join(dataDir, "tokens.json"),
    pkceStatePath: process.env.PKCE_STATE_PATH ?? path.join(dataDir, "pkce_state.json"),
    obsidianVaultPath: requireEnv("OBSIDIAN_VAULT_PATH"),
    xBookmarksRoot: process.env.X_BOOKMARKS_ROOT ?? "Clippings/X-Bookmarks-codex",
    sourceRoot: process.env.SOURCE_ROOT ?? "Clippings/X-Bookmarks-codex",
    proposalPrefix: safeFileSegment(process.env.PROPOSAL_PREFIX ?? "codex")
  };
  const secret = process.env.X_CLIENT_SECRET;
  if (secret) {
    config.xClientSecret = secret;
  }
  return config;
}

function loadDotEnv(envPath: string): void {
  if (!fs.existsSync(envPath)) return;
  const raw = fs.readFileSync(envPath, "utf-8");
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) continue;
    const key = trimmed.slice(0, idx).trim();
    if (process.env[key] !== undefined) continue;
    const value = trimmed.slice(idx + 1).trim().replace(/^['"]|['"]$/g, "");
    process.env[key] = value;
  }
}