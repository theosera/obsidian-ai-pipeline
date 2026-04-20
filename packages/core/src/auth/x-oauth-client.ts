import type { EnvConfig } from "../config/env.js";
import type { XTokenSet } from "../types/shared.js";

interface TokenResponse {
  access_token: string;
  token_type?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

function authHeader(clientId: string, clientSecret?: string): string | undefined {
  if (!clientSecret) return undefined;
  const token = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  return `Basic ${token}`;
}

function toTokenSet(source: TokenResponse): XTokenSet {
  const expiresAt = source.expires_in
    ? new Date(Date.now() + source.expires_in * 1000).toISOString()
    : undefined;
  const tokenSet: XTokenSet = {
    access_token: source.access_token,
  };
  if (source.refresh_token) tokenSet.refresh_token = source.refresh_token;
  if (source.token_type) tokenSet.token_type = source.token_type;
  if (source.scope) tokenSet.scope = source.scope;
  if (expiresAt) tokenSet.expires_at = expiresAt;
  return tokenSet;
}

async function exchange(config: EnvConfig, body: URLSearchParams): Promise<XTokenSet> {
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded"
  };
  const basic = authHeader(config.xClientId, config.xClientSecret);
  if (basic) {
    headers.Authorization = basic;
  }

  const response = await fetch(`${config.xApiBaseUrl}/2/oauth2/token`, {
    method: "POST",
    headers,
    body
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Token exchange failed (${response.status}): ${detail}`);
  }

  const json = (await response.json()) as TokenResponse;
  return toTokenSet(json);
}

export async function exchangeCodeForToken(params: {
  config: EnvConfig;
  code: string;
  codeVerifier: string;
}): Promise<XTokenSet> {
  const body = new URLSearchParams({
    code: params.code,
    grant_type: "authorization_code",
    client_id: params.config.xClientId,
    redirect_uri: params.config.xRedirectUri,
    code_verifier: params.codeVerifier
  });
  return exchange(params.config, body);
}

export async function refreshAccessToken(config: EnvConfig, refreshToken: string): Promise<XTokenSet> {
  const body = new URLSearchParams({
    refresh_token: refreshToken,
    grant_type: "refresh_token",
    client_id: config.xClientId
  });
  return exchange(config, body);
}
