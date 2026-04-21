import crypto from "node:crypto";

function base64Url(input: Buffer): string {
  return input
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export function createPkcePair(): { codeVerifier: string; codeChallenge: string; state: string } {
  const codeVerifier = base64Url(crypto.randomBytes(64));
  const codeChallenge = base64Url(
    crypto.createHash("sha256").update(codeVerifier).digest()
  );
  const state = base64Url(crypto.randomBytes(24));
  return { codeVerifier, codeChallenge, state };
}
