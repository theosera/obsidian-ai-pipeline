import { documentSha256, readDocument } from '../utils/document_integrity';
import { DeliveryStore, normalizeDeliveryAddress, type DeliveryRecord } from './delivery_store';

export type { DeliveryRecord } from './delivery_store';

export interface SentMessage {
  messageId: string;
  threadId: string | null;
  from: string;
  to: string[];
  subject: string;
  rfcMessageId: string | null;
  reportId: string | null;
  contentSha256: string | null;
  body: Buffer;
  sent: boolean;
}

export interface DeliveryEnvelope { record: DeliveryRecord; body: Buffer }
export interface DeliveryTransport {
  account(): Promise<string>;
  findSent(record: DeliveryRecord): Promise<SentMessage[]>;
  getSent(messageId: string): Promise<SentMessage>;
  send(envelope: DeliveryEnvelope): Promise<{ messageId: string; threadId: string | null }>;
}

export interface DeliveryOptions {
  beforeSend?: (record: DeliveryRecord) => Promise<void>;
}

export class DefiniteSendError extends Error {
  constructor(readonly code: string, readonly retryable: boolean) {
    super(`Gmail rejected the send before acceptance (${code}).`);
    this.name = 'DefiniteSendError';
  }
}

function exactMessage(record: DeliveryRecord, message: SentMessage, body: Buffer, allowLegacy: boolean): boolean {
  let addressesMatch = false;
  try {
    addressesMatch = normalizeDeliveryAddress(message.from) === record.account &&
      message.to.length === 1 && normalizeDeliveryAddress(message.to[0]) === record.recipient;
  } catch { return false; }
  const headersMatch = message.rfcMessageId === record.rfc_message_id &&
    message.reportId === record.report_id && message.contentSha256 === record.content_sha256;
  // Legacy messages may lack the three delivery headers. Scope is established
  // by SENT + bound From/To + exact subject + the entire immutable body.
  const legacyHeaders = allowLegacy && message.rfcMessageId !== record.rfc_message_id &&
    message.reportId === null && message.contentSha256 === null;
  return message.sent && addressesMatch && message.subject === record.subject &&
    (headersMatch || legacyHeaders) && body.equals(message.body) &&
    documentSha256(message.body) === record.content_sha256;
}

async function assertAccount(transport: DeliveryTransport, record: DeliveryRecord): Promise<void> {
  if (normalizeDeliveryAddress(await transport.account()) !== record.account || record.recipient !== record.account) {
    throw new Error('Authenticated Gmail account does not match the bound self-send account.');
  }
}

function verifiedBody(store: DeliveryStore, record: DeliveryRecord): Buffer {
  const bytes = readDocument(record.file_path, record.content_sha256);
  if (!bytes.equals(store.snapshot(record.report_id))) throw new Error('Saved Markdown differs from the immutable delivery snapshot.');
  return bytes;
}

export async function reconcileDelivery(
  store: DeliveryStore, transport: DeliveryTransport, reportId: string, now?: number,
): Promise<DeliveryRecord> {
  const record = store.required(reportId);
  await assertAccount(transport, record);
  const body = store.snapshot(reportId);
  // A lookup failure is not evidence of absence and never authorizes a send.
  const candidates = await transport.findSent(record);
  if (record.gmail_message_id !== null && !candidates.some((candidate) => candidate.messageId === record.gmail_message_id)) {
    candidates.push(await transport.getSent(record.gmail_message_id));
  }
  const observedAt = now ?? Date.now();
  const distinct = [...new Map(candidates.map((candidate) => [candidate.messageId, candidate])).values()];
  const matches = distinct.filter((candidate) => exactMessage(record, candidate, body, record.attempt_count === 0));
  const identityCollision = distinct.some((candidate) =>
    (candidate.messageId === record.gmail_message_id || candidate.rfcMessageId === record.rfc_message_id ||
      candidate.reportId === record.report_id || candidate.contentSha256 === record.content_sha256 ||
      documentSha256(candidate.body) === record.content_sha256) &&
    !matches.some((match) => match.messageId === candidate.messageId));
  if (identityCollision) return store.outcome(reportId, { status: 'conflict', errorCode: 'sent_message_identity_conflict' }, observedAt);
  if (matches.length > 1) return store.outcome(reportId, { status: 'conflict', errorCode: 'ambiguous_sent_messages' }, observedAt);
  if (matches.length === 1) {
    const match = matches[0];
    if (record.gmail_message_id !== null && match.messageId !== record.gmail_message_id) {
      return store.outcome(reportId, { status: 'conflict', errorCode: 'accepted_message_id_conflict' }, observedAt);
    }
    return store.outcome(reportId, { status: 'sent', messageId: match.messageId, threadId: match.threadId }, observedAt);
  }
  if (record.status === 'sending' || record.status === 'unknown' || record.gmail_message_id !== null) {
    return store.outcome(reportId, { status: 'unknown', errorCode: 'send_not_reconciled' }, observedAt, undefined, {
      status: record.status, attemptCount: record.attempt_count, messageId: record.gmail_message_id,
    });
  }
  return record;
}

export async function deliverReport(
  store: DeliveryStore, transport: DeliveryTransport, reportId: string, now?: number,
  options: DeliveryOptions = {},
): Promise<DeliveryRecord> {
  const record = store.required(reportId);
  await assertAccount(transport, record);
  if (record.status === 'sent' || record.status === 'rejected' || record.status === 'conflict') return record;
  if (record.status === 'sending' || record.status === 'unknown') return reconcileDelivery(store, transport, reportId, now);
  verifiedBody(store, record);
  const reconciled = await reconcileDelivery(store, transport, reportId, now);
  if (!['prepared', 'retryable'].includes(reconciled.status)) return reconciled;
  const claim = store.claim(reportId, now ?? Date.now());
  if (!claim) return store.required(reportId);
  let body: Buffer;
  try {
    body = verifiedBody(store, claim.record);
  } catch {
    return store.outcome(reportId, { status: 'conflict', errorCode: 'document_changed_before_send' }, now ?? Date.now(), claim.attemptId);
  }
  try {
    await options.beforeSend?.(claim.record);
  } catch {
    // A remote persistence response can itself be ambiguous. The claimed attempt
    // must remain non-retryable even though this process did not call Gmail.
    return store.outcome(reportId, { status: 'unknown', errorCode: 'pre_send_durability_failed' }, now ?? Date.now(), claim.attemptId);
  }
  try {
    body = verifiedBody(store, claim.record);
  } catch {
    return store.outcome(reportId, { status: 'conflict', errorCode: 'document_changed_before_send' }, now ?? Date.now(), claim.attemptId);
  }
  let accepted: { messageId: string; threadId: string | null };
  try {
    accepted = await transport.send({ record: claim.record, body });
  } catch (error) {
    if (error instanceof DefiniteSendError) {
      const rejectedAt = now ?? Date.now();
      const retry = error.retryable && claim.record.attempt_count < 3;
      return store.outcome(reportId, {
        status: retry ? 'retryable' : 'rejected', errorCode: error.code,
        nextAttemptAt: retry ? new Date(rejectedAt + 60_000 * 2 ** (claim.record.attempt_count - 1)).toISOString() : null,
      }, rejectedAt, claim.attemptId);
    }
    return store.outcome(reportId, { status: 'unknown', errorCode: 'send_result_unknown' }, now ?? Date.now(), claim.attemptId);
  }
  // Persist acceptance before any readback request can fail or the process exit.
  if (!accepted.messageId) return store.outcome(reportId, { status: 'unknown', errorCode: 'send_response_missing_message_id' }, now ?? Date.now(), claim.attemptId);
  store.outcome(reportId, { status: 'unknown', messageId: accepted.messageId, threadId: accepted.threadId, errorCode: 'readback_pending' }, now ?? Date.now(), claim.attemptId);
  try {
    const sent = await transport.getSent(accepted.messageId);
    if (sent.messageId !== accepted.messageId || !exactMessage(claim.record, sent, body, false)) {
      return store.outcome(reportId, { status: 'conflict', errorCode: 'sent_message_integrity_mismatch' }, now ?? Date.now(), claim.attemptId);
    }
    return store.outcome(reportId, { status: 'sent', messageId: sent.messageId, threadId: sent.threadId }, now ?? Date.now(), claim.attemptId);
  } catch {
    return store.outcome(reportId, { status: 'unknown', errorCode: 'sent_message_readback_failed' }, now ?? Date.now(), claim.attemptId);
  }
}
