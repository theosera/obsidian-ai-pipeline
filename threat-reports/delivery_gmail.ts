import { gmail, auth as gmailAuth, type gmail_v1 } from '@googleapis/gmail';
import { DefiniteSendError, type DeliveryTransport, type SentMessage } from './delivery';
import type { DeliveryRecord } from './delivery_store';

export const DELIVERY_GMAIL_SCOPES = [
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.readonly',
] as const;

const REQUEST_OPTIONS = { retry: false, retryConfig: { retry: 0 }, timeout: 30_000 };
const MAX_SENT_CANDIDATES = 50;
const MAX_SEARCH_PAGES = 5;

export interface DeliveryGmailCredentials {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}

export function deliveryGmailCredentialsFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): DeliveryGmailCredentials {
  const required = (name: string): string => {
    const value = env[name];
    if (!value || value.trim() !== value) throw new Error(`Missing or invalid ${name}`);
    return value;
  };
  return {
    clientId: required('GMAIL_DELIVERY_CLIENT_ID'),
    clientSecret: required('GMAIL_DELIVERY_CLIENT_SECRET'),
    refreshToken: required('GMAIL_DELIVERY_REFRESH_TOKEN'),
  };
}

function headerValue(value: string): string {
  if (!value || !/^[\x20-\x7e]+$/.test(value)) throw new Error('Invalid delivery MIME header');
  return value;
}

/** Base64 transfer encoding preserves the Markdown bytes, including the final newline. */
export function buildDeliveryMime(record: DeliveryRecord, body: Buffer): Buffer {
  const encodedBody = body.toString('base64').match(/.{1,76}/g)?.join('\r\n') ?? '';
  return Buffer.from([
    `From: ${headerValue(record.account)}`,
    `To: ${headerValue(record.recipient)}`,
    `Subject: ${headerValue(record.subject)}`,
    `Date: ${headerValue(new Date(record.created_at).toUTCString())}`,
    `Message-ID: ${headerValue(record.rfc_message_id)}`,
    `X-LLM-Report-ID: ${headerValue(record.report_id)}`,
    `X-Content-SHA256: ${headerValue(record.content_sha256)}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    encodedBody,
    '',
  ].join('\r\n'), 'utf8');
}

function uniqueHeader(message: gmail_v1.Schema$Message, name: string, required = false): string | null {
  const values = (message.payload?.headers ?? [])
    .filter(header => header.name?.toLowerCase() === name.toLowerCase());
  if (values.length > 1 || (required && values.length !== 1)) {
    throw new Error(`Ambiguous or missing Gmail ${name} header`);
  }
  const value = values[0]?.value;
  if (value === undefined || value === null) {
    if (required) throw new Error(`Missing Gmail ${name} header`);
    return null;
  }
  if (/[\r\n\0]/.test(value)) throw new Error(`Invalid Gmail ${name} header`);
  return value.trim();
}

function singleMailbox(value: string): string {
  const angle = value.match(/^[^<>@,;]*<([^<>]+)>$/);
  const candidate = (angle ? angle[1] : value).trim().toLowerCase();
  if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(candidate)) {
    throw new Error('Invalid or multiple Gmail mailbox addresses');
  }
  return candidate;
}

function decodeBody(data: string): Buffer {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(data) || data.replace(/=+$/, '').length % 4 === 1) {
    throw new Error('Invalid Gmail body encoding');
  }
  const body = Buffer.from(data, 'base64url');
  if (body.toString('base64url') !== data.replace(/=+$/, '')) throw new Error('Non-canonical Gmail body encoding');
  return body;
}

/** Full Gmail readback is evidence; duplicate headers and multiple plain bodies fail closed. */
export function parseSentDeliveryMessage(message: gmail_v1.Schema$Message): SentMessage {
  if (!message.id || !message.payload) throw new Error('Incomplete Gmail sent-message readback');
  const plain: Buffer[] = [];
  const walk = (part: gmail_v1.Schema$MessagePart): void => {
    if (part.mimeType === 'text/plain') {
      if (part.body?.attachmentId || typeof part.body?.data !== 'string') {
        throw new Error('Gmail text/plain body must be available inline');
      }
      if (part.filename) throw new Error('Gmail text/plain attachment is not a report body');
      plain.push(decodeBody(part.body.data));
    }
    for (const child of part.parts ?? []) walk(child);
  };
  walk(message.payload);
  if (plain.length !== 1) throw new Error('Gmail delivery must contain exactly one text/plain body');
  const cc = uniqueHeader(message, 'Cc');
  const bcc = uniqueHeader(message, 'Bcc');
  if (cc || bcc) throw new Error('Gmail delivery contains additional recipients');
  return {
    messageId: message.id,
    threadId: message.threadId ?? null,
    from: singleMailbox(uniqueHeader(message, 'From', true)!),
    to: [singleMailbox(uniqueHeader(message, 'To', true)!)],
    subject: uniqueHeader(message, 'Subject', true)!,
    rfcMessageId: uniqueHeader(message, 'Message-ID'),
    reportId: uniqueHeader(message, 'X-LLM-Report-ID'),
    contentSha256: uniqueHeader(message, 'X-Content-SHA256'),
    body: plain[0],
    sent: message.labelIds?.includes('SENT') ?? false,
  };
}

function httpStatus(error: unknown): number | null {
  if (!error || typeof error !== 'object' || !('response' in error)) return null;
  const response = error.response;
  if (!response || typeof response !== 'object' || !('status' in response)) return null;
  return typeof response.status === 'number' ? response.status : null;
}

/** A 403 is retryable only when all structured Gmail reasons are known rate limits. */
function isGmailRateLimitRejection(error: unknown): boolean {
  if (!error || typeof error !== 'object' || !('response' in error)) return false;
  const response = error.response;
  if (!response || typeof response !== 'object' || !('data' in response)) return false;
  const data = response.data;
  if (!data || typeof data !== 'object' || Array.isArray(data) || !('error' in data)) return false;
  const details = data.error;
  if (!details || typeof details !== 'object' || Array.isArray(details) || !('errors' in details)) return false;
  if ('code' in details && details.code !== 403) return false;
  if (!Array.isArray(details.errors) || details.errors.length === 0) return false;
  for (const entry of details.errors) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || !('reason' in entry) ||
      (entry.reason !== 'rateLimitExceeded' && entry.reason !== 'userRateLimitExceeded')) return false;
  }
  return true;
}

/** No API call runs until an explicit transport method is invoked. */
export class GmailDeliveryTransport implements DeliveryTransport {
  private readonly refreshClient: InstanceType<typeof gmailAuth.OAuth2>;
  private requestClient: gmail_v1.Gmail | null = null;

  constructor(credentials: DeliveryGmailCredentials, requestClient?: gmail_v1.Gmail) {
    this.refreshClient = new gmailAuth.OAuth2(credentials.clientId, credentials.clientSecret);
    this.refreshClient.forceRefreshOnFailure = false;
    this.refreshClient.setCredentials({ refresh_token: credentials.refreshToken });
    this.requestClient = requestClient ?? null;
  }

  private async client(): Promise<gmail_v1.Gmail> {
    if (this.requestClient) return this.requestClient;
    const token = await this.refreshClient.getAccessToken();
    if (!token.token) throw new Error('Gmail delivery access token unavailable');
    // google-auth-library can replay a 401/403 POST when refresh credentials exist.
    // The request client has only a short-lived token, so auth cannot replay a send.
    const requestAuth = new gmailAuth.OAuth2();
    requestAuth.forceRefreshOnFailure = false;
    requestAuth.setCredentials({
      access_token: token.token,
      expiry_date: this.refreshClient.credentials.expiry_date ?? Date.now() + 60_000,
    });
    this.requestClient = gmail({ version: 'v1', auth: requestAuth });
    return this.requestClient;
  }

  async account(): Promise<string> {
    const client = await this.client();
    const result = await client.users.getProfile({ userId: 'me' }, REQUEST_OPTIONS);
    return singleMailbox(result.data.emailAddress ?? '');
  }

  async getSent(messageId: string): Promise<SentMessage> {
    if (!/^[a-zA-Z0-9_-]+$/.test(messageId)) throw new Error('Invalid Gmail message ID');
    const client = await this.client();
    const result = await client.users.messages.get({ userId: 'me', id: messageId, format: 'full' }, REQUEST_OPTIONS);
    return parseSentDeliveryMessage(result.data);
  }

  async findSent(record: DeliveryRecord): Promise<SentMessage[]> {
    const client = await this.client();
    const rfcId = headerValue(record.rfc_message_id).replace(/^<|>$/g, '');
    const subject = headerValue(record.subject);
    if (!/^[a-zA-Z0-9@._-]+$/.test(rfcId) || /["\\]/.test(subject)) throw new Error('Invalid delivery search identity');
    const account = singleMailbox(record.account);
    const recipient = singleMailbox(record.recipient);
    const q = `in:sent from:${account} to:${recipient} {rfc822msgid:${rfcId} subject:"${subject}"}`;
    const ids = new Set<string>();
    let pageToken: string | undefined;
    for (let page = 0; page < MAX_SEARCH_PAGES; page++) {
      const result = await client.users.messages.list({
        userId: 'me', q, maxResults: MAX_SENT_CANDIDATES, pageToken, includeSpamTrash: false,
      }, REQUEST_OPTIONS);
      for (const message of result.data.messages ?? []) {
        if (!message.id) throw new Error('Missing Gmail search result identity');
        ids.add(message.id);
      }
      if (ids.size > MAX_SENT_CANDIDATES) throw new Error('Gmail reconciliation search exceeds candidate limit');
      pageToken = result.data.nextPageToken ?? undefined;
      if (!pageToken) {
        const messages: SentMessage[] = [];
        for (const id of ids) {
          const message = await this.getSent(id);
          messages.push(message);
        }
        return messages;
      }
    }
    throw new Error('Gmail reconciliation search truncated; sending remains blocked');
  }

  async send(input: { record: DeliveryRecord; body: Buffer }): Promise<{ messageId: string; threadId: string | null }> {
    const client = await this.client();
    const raw = buildDeliveryMime(input.record, input.body).toString('base64url');
    try {
      const result = await client.users.messages.send({ userId: 'me', requestBody: { raw } }, REQUEST_OPTIONS);
      if (!result.data.id) throw new Error('Gmail send response has no message ID');
      return { messageId: result.data.id, threadId: result.data.threadId ?? null };
    } catch (error: unknown) {
      const status = httpStatus(error);
      if (status !== null && status >= 400 && status < 500 && status !== 408) {
        throw new DefiniteSendError(`gmail_http_${status}`, status === 429 || (status === 403 && isGmailRateLimitRejection(error)));
      }
      // 5xx/timeouts/network failures may occur after Gmail accepted the message.
      // Core stores an unknown outcome and reconciles; it must never resend here.
      throw new Error('Gmail send outcome unknown; reconcile before any further send');
    }
  }
}
