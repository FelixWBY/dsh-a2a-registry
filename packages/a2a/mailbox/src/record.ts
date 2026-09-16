/** Strict persisted records and immutable body AAD; request states come from registry-domain. */
import { createHash } from 'node:crypto'
import { z } from 'zod'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'
import { transitionA2aRequest, type A2aRequestState } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { SessionId } from '@deepseek-ai/dsh-session'
import type { MailboxBinding, MailboxConsumerClaim, MailboxErrorCode, MailboxLimits, MailboxReceipt, MailboxTransition } from './types.ts'

/** Sanitized queue diagnostic. */
export class MailboxError extends Error {
  /** @param code - Payload-free failure category. */
  constructor(readonly code: MailboxErrorCode) {
    super(`a2a mailbox: ${code}`)
    this.name = 'MailboxError'
  }
}

/** Assert a queue-owned condition.
 * @param condition - Required condition.
 * @param code - Sanitized rejection category. */
export function requireMailbox(condition: unknown, code: MailboxErrorCode): asserts condition {
  if (!condition) throw new MailboxError(code)
}

const identifier = z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/)
const branded = <T extends Branded<string>>() => identifier.transform(value => brandString<T>(value))
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).refine(value => !Object.is(value, -0))
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const bindingSchema = z.strictObject({
  requestId: branded<MailboxBinding['requestId']>(), organizationId: branded<MailboxBinding['organizationId']>(),
  disclosureId: branded<MailboxBinding['disclosureId']>(), requesterId: branded<MailboxBinding['requesterId']>(),
  instanceId: branded<MailboxBinding['instanceId']>(), checkpointHash: digest.transform(value => brandString<MailboxBinding['checkpointHash']>(value)),
  authorizationVersion: integer, expiresAt: integer,
})
const state = z.string().transform((value): A2aRequestState => transitionA2aRequest(value as A2aRequestState, value as A2aRequestState))
const encrypted = z.string().min(1).regex(/^[A-Za-z0-9_-]+$/)
const recordSchema = z.strictObject({
  binding: bindingSchema, state, version: integer, authorizationVersion: integer, questionHash: digest,
  replyHash: digest.nullable(), updatedAt: integer, question: encrypted.nullable(), reply: encrypted.nullable(),
})
const claimSchema = z.strictObject({ binding: bindingSchema, questionHash: digest, sessionId: branded<SessionId>() })
const transitionSchema = z.union([
  z.strictObject({ state: z.literal('running') }), z.strictObject({ state: z.literal('failed') }),
  z.strictObject({ state: z.literal('cancelled') }), z.strictObject({ state: z.literal('completed'), reply: z.string() }),
])

/** One request's ciphertext and transition receipt form one atomic KV record. */
export interface MailboxRecord extends MailboxReceipt {
  readonly question: string | null
  readonly reply: string | null
}

/** A terminal body-free record is the durable idempotency tombstone for its request key. */
export function isMailboxTombstone(record: MailboxRecord): boolean {
  const terminal = record.state === 'completed' || record.state === 'expired'
    || record.state === 'cancelled' || record.state === 'failed'
  return terminal && record.question === null && record.reply === null
}

/** Complete UTF-8 JSON byte count.
 * @param value - JSON value.
 * @returns Serialized byte count. */
export function bytes(value: unknown): number { return Buffer.byteLength(JSON.stringify(value)) }

/** Validate explicit deployment limits.
 * @param limits - All bounds; no defaults are supplied. */
export function validateLimits(limits: MailboxLimits): void {
  const values = [limits.maxTextBytes, limits.maxTextCharacters, limits.maxCiphertextBytes,
    limits.maxAggregateBytes, limits.maxRequests, limits.maxRetainedRequests,
    limits.maxPendingOperations, limits.maxLifetimeMs]
  requireMailbox(values.every(value => Number.isSafeInteger(value) && value > 0)
    && limits.maxRetainedRequests >= limits.maxRequests, 'invalid-input')
}

/** Validate persisted/enqueued binding without accepting extra fields.
 * @param value - Parsed JSON or queued request identity.
 * @returns Canonical detached binding. */
export function parseBinding(value: unknown): MailboxBinding { return bindingSchema.parse(value) }

/** Validate an organization selector with the same syntax as retained bindings.
 * @param value - Trusted maintenance configuration or operation input.
 * @returns Canonical branded organization identity. */
export function parseMailboxOrganization(value: unknown): MailboxBinding['organizationId'] {
  return branded<MailboxBinding['organizationId']>().parse(value)
}

/** Validate the restricted queued transition operation, not the wider domain state set.
 * @param value - Queued operation input.
 * @returns Detached operation with exact allowed fields. */
export function parseTransition(value: unknown): MailboxTransition {
  const result = transitionSchema.safeParse(value)
  requireMailbox(result.success, 'invalid-input')
  return result.data
}

/** Validate complete ciphertext bytes and canonical base64url representation.
 * @param value - Encoded AEAD payload.
 * @param limits - Complete ciphertext limit. */
export function checkCiphertext(value: string, limits: MailboxLimits): void {
  requireMailbox(encrypted.safeParse(value).success && Buffer.byteLength(value) <= limits.maxCiphertextBytes
    && Buffer.from(value, 'base64url').toString('base64url') === value, 'codec-failed')
}

/** Validate complete text without truncation or Unicode replacement.
 * @param text - Complete question/reply.
 * @param limits - UTF-8 and Unicode scalar bounds.
 * @returns SHA-256 of the exact UTF-8 text. */
export function textHash(text: string, limits: MailboxLimits): string {
  requireMailbox(text.length > 0 && text.isWellFormed() && !text.includes('\0')
    && Buffer.byteLength(text) <= limits.maxTextBytes && Array.from(text).length <= limits.maxTextCharacters, 'invalid-input')
  return `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`
}

/** Parse and validate a whole aggregate, including state-dependent sensitive-data cleanup.
 * @param value - Durable JSON or queued candidate.
 * @param limits - Complete record/ciphertext bounds.
 * @returns Detached validated aggregate. */
export function parseRecord(value: unknown, limits: MailboxLimits): MailboxRecord {
  const record = recordSchema.parse(value)
  requireMailbox(record.authorizationVersion >= record.binding.authorizationVersion && record.version > 0
    && record.state !== 'created' && record.updatedAt < Number.MAX_SAFE_INTEGER, 'invalid-storage')
  const pending = record.state === 'queued' || record.state === 'delivered' || record.state === 'running'
  requireMailbox((record.question !== null) === pending && (record.reply === null || record.state === 'completed')
    && (record.replyHash !== null) === (record.state === 'completed'), 'invalid-storage')
  for (const ciphertext of [record.question, record.reply]) if (ciphertext !== null) checkCiphertext(ciphertext, limits)
  requireMailbox(bytes(record) <= limits.maxAggregateBytes, 'limit')
  return record
}

/** Validate a durable instance-local claim.
 * @param value - Stored JSON or proposed claim.
 * @param limits - Complete claim bound.
 * @returns Detached metadata-only claim. */
export function parseClaim(value: unknown, limits: MailboxLimits): MailboxConsumerClaim {
  const claim = claimSchema.parse(value)
  requireMailbox(bytes(claim) <= limits.maxAggregateBytes, 'limit')
  return claim
}

/** Collision-free single-record key.
 * @param binding - Organization-scoped request identity.
 * @returns Canonical KV key. */
export function recordKey(binding: MailboxBinding): string { return JSON.stringify([binding.organizationId, binding.requestId]) }

/** Exact immutable AEAD associated data; current authorization versions never rewrite ciphertext.
 * @param binding - Frozen initial request identity.
 * @param kind - Distinguishes question and reply ciphertext.
 * @returns Canonical versioned associated data. */
export function bodyAad(binding: MailboxBinding, kind: 'question' | 'reply'): string {
  return JSON.stringify(['dsh-a2a-mailbox', 1, binding.organizationId, binding.instanceId, binding.requestId,
    binding.requesterId, binding.disclosureId, binding.checkpointHash, binding.authorizationVersion, binding.expiresAt, kind])
}

/** Strip all ciphertext before returning metadata or recording audit.
 * @param record - Validated aggregate.
 * @returns Detached metadata receipt. */
export function receiptOf(record: MailboxRecord): MailboxReceipt {
  const { question: _question, reply: _reply, ...receipt } = record
  return structuredClone(receipt)
}
