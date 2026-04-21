import path from "node:path";
import fs from "node:fs";

export interface EnvConfig {
  xClientId: string;
  xClientSecret?: string;
  xRedirectUri: string;
  localAuthHost: string;
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

export function loadEnvConfig(repoRoot = process.cwd()): EnvConfig {
  loadDotEnv(path.resolve(repoRoot, ".env"));
  const dataDir = path.resolve(repoRoot, "data");
  const xRedirectUri = requireEnv("X_REDIRECT_URI");
  const parsedRedirect = new URL(xRedirectUri);
  const config: EnvConfig = {
    xClientId: requireEnv("X_CLIENT_ID"),
    xRedirectUri,
    localAuthHost: parsedRedirect.hostname || "127.0.0.1",
    xScope:
      process.env.X_SCOPE ?? "tweet.read users.read bookmark.read offline.access",
    xAuthBaseUrl: process.env.X_AUTH_BASE_URL ?? "https://twitter.com/i/oauth2",
    xApiBaseUrl: process.env.X_API_BASE_URL ?? "https://api.x.com",
    localAuthPort: Number(process.env.AUTH_PORT ?? "3838"),
    tokensPath: process.env.TOKENS_PATH ?? path.join(dataDir, "tokens.json"),
    pkceStatePath: process.env.PKCE_STATE_PATH ?? path.join(dataDir, "pkce_state.json"),
    obsidianVaultPath: requireEnv("OBSIDIAN_VAULT_PATH"),
    xBookmarksRoot: process.env.X_BOOKMARKS_ROOT ?? "Clippings/X-Bookmarks-codex",
    sourceRoot: process.env.SOURCE_ROOT ?? "Clippings/X-Bookmarks-codex",
    proposalPrefix: process.env.PROPOSAL_PREFIX ?? "codex"
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

function readPort(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number(raw.trim());
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`Invalid port for ${name}: ${raw}`);
  }
  return value;
}

function safeFileSegment(value: string): string {
  const normalized = value.trim().replace(/[^A-Za-z0-9_-]+/g, "_");
  return normalized.length > 0 ? normalized : "codex";
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
