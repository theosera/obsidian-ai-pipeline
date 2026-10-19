import crypto from 'node:crypto';
import fs from 'node:fs';
import { TextDecoder } from 'node:util';

export function documentSha256(bytes: Buffer): string {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

export const sha256 = documentSha256;

export function decodeDocument(bytes: Buffer): string {
  if (bytes.length === 0) throw new Error('Document is empty.');
  // Reject lossy decoding: the transport must preserve exactly the saved bytes.
  new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return bytes.toString('utf8');
}

export function readDocument(filePath: string, expectedSha256: string): Buffer {
  if (!/^[0-9a-f]{64}$/i.test(expectedSha256)) throw new Error('Expected a full SHA-256 hex digest.');
  const bytes = fs.readFileSync(filePath);
  decodeDocument(bytes);
  if (documentSha256(bytes) !== expectedSha256.toLowerCase()) {
    throw new Error('Saved Markdown SHA-256 differs from the approved document.');
  }
  return bytes;
}
