import "dotenv/config";
import http from "node:http";
import path from "node:path";
import {
  createPkcePair,
  exchangeCodeForToken,
  loadEnvConfig,
  saveTokens,
  writeJsonFile,
  readJsonFile,
  XApiClient
} from "@obsidian-ai-pipeline/core";

interface PkceState {
  state: string;
  codeVerifier: string;
  createdAt: string;
}

const repoRoot = path.resolve(process.cwd(), "../..");
const config = loadEnvConfig(repoRoot);

async function savePkceState(pkce: PkceState): Promise<void> {
  await writeJsonFile(config.pkceStatePath, pkce);
}

async function loadPkceState(): Promise<PkceState> {
  return readJsonFile<PkceState>(config.pkceStatePath);
}

function send(res: http.ServerResponse, status: number, message: string): void {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(message);
}

const server = http.createServer(async (req, res) => {
  try {
    if (!req.url) {
      send(res, 400, "missing url");
      return;
    }
    const url = new URL(req.url, `http://localhost:${config.localAuthPort}`);

    if (url.pathname === "/auth/login") {
      const pkce = createPkcePair();
      await savePkceState({
        state: pkce.state,
        codeVerifier: pkce.codeVerifier,
        createdAt: new Date().toISOString()
      });

      const authUrl = new URL(`${config.xAuthBaseUrl}/authorize`);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("client_id", config.xClientId);
      authUrl.searchParams.set("redirect_uri", config.xRedirectUri);
      authUrl.searchParams.set("scope", config.xScope);
      authUrl.searchParams.set("state", pkce.state);
      authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      res.writeHead(302, { Location: authUrl.toString() });
      res.end();
      return;
    }

    if (url.pathname === "/auth/callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!code || !state) {
        send(res, 400, "Missing code/state in callback");
        return;
      }

      const saved = await loadPkceState();
      if (saved.state !== state) {
        send(res, 400, `State mismatch. expected=${saved.state} actual=${state}`);
        return;
      }

      const tokens = await exchangeCodeForToken({
        config,
        code,
        codeVerifier: saved.codeVerifier
      });
      await saveTokens(config.tokensPath, tokens);

      const client = new XApiClient(config, tokens);
      const me = await client.getMe();
      send(
        res,
        200,
        `<h1>Auth Success</h1><p>User: ${me.name} (@${me.username})</p><p>tokens saved: ${config.tokensPath}</p>`
      );
      return;
    }

    if (url.pathname === "/") {
      send(
        res,
        200,
        `<h1>X Auth Server</h1><p><a href=\"/auth/login\">Login with X</a></p><p>Redirect URI: ${config.xRedirectUri}</p>`
      );
      return;
    }

    send(res, 404, `Not found: ${url.pathname}`);
  } catch (error) {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    send(res, 500, `<pre>${message}</pre>`);
  }
});

server.listen(config.localAuthPort, () => {
  console.log(`Auth server running: http://localhost:${config.localAuthPort}`);
  console.log("Open /auth/login to start OAuth2 PKCE flow");
});
