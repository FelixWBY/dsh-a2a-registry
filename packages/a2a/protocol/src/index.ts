/**
 * Stable disclosure records shared by a DSH instance and a registry service.
 * The records deliberately exclude the internal SessionEvent type: disclosure
 * projects a user-visible event set before encryption and transport.
 * @module @deepseek-ai/dsh-a2a-protocol
 */

import { createHash } from 'node:crypto'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'

/** Current major version of every disclosure record in this package. */
export const DISCLOSURE_PROTOCOL_VERSION = 1 as const

/** Registry tenant that owns a disclosure. */
export type OrganizationId = Branded<'A2AOrganizationId'>
/** Device-bound Harness instance that produced a disclosure record. */
export type DshInstanceId = Branded<'A2ADshInstanceId'>
/** Source conversation identity within one Harness instance. */
export type DisclosureConversationId = Branded<'A2ADisclosureConversationId'>
/** One independently revocable disclosure. */
export type DisclosureId = Branded<'A2ADisclosureId'>
/** Globally unique idempotency identity for one projected event. */
export type DisclosureEventId = Branded<'A2ADisclosureEventId'>
/** Canonical lowercase SHA-256 digest prefixed with `sha256:`. */
export type DisclosureHash = Branded<'A2ADisclosureHash'>
/** Canonical signature bytes encoded as base64url without padding. */
export type DisclosureSignature = Branded<'A2ADisclosureSignature'>

/** User-visible event kinds admitted by disclosure protocol version 1. */
export type DisclosureSemanticEvent =
  | {
    readonly version: 1
    readonly type: 'conversation.user-message'
    readonly text: string
  }
  | {
    readonly version: 1
    readonly type: 'conversation.assistant-message'
    readonly text: string
  }
  | {
    readonly version: 1
    readonly type: 'conversation.tool-result-summary'
    readonly toolName: string
    readonly outcome: 'success' | 'failure'
    readonly text: string
  }
  | {
    readonly version: 1
    readonly type: 'conversation.title'
    readonly title: string
  }

/** Discriminant union for every user-visible event admitted by protocol version 1. */
export type DisclosureSemanticEventType = DisclosureSemanticEvent['type']

/**
 * Encrypted projected event sent from one DSH instance to the registry.
 * `disclosureSeq` is contiguous after local filtering; `sourceCursor` only
 * records how far the local source log was inspected and never defines a
 * registry gap. `eventHash` commits every field except itself and `signature`.
 */
export interface DisclosureEventEnvelope {
  readonly protocolVersion: 1
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly conversationId: DisclosureConversationId
  readonly disclosureId: DisclosureId
  readonly eventId: DisclosureEventId
  readonly disclosureSeq: number
  readonly sourceCursor: number
  readonly eventType: DisclosureSemanticEventType
  readonly policyVersion: number
  readonly occurredAt: number
  readonly previousEventHash: DisclosureHash | null
  readonly ciphertext: string
  readonly ciphertextHash: DisclosureHash
  readonly eventHash: DisclosureHash
  readonly signature: DisclosureSignature
}

/**
 * Signed completion marker for one full-history prefix. The registry may make
 * a disclosure readable only after it has stored the contiguous prefix named
 * by this checkpoint and verified the signature with the instance public key.
 */
export interface DisclosureCheckpoint {
  readonly protocolVersion: 1
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly disclosureId: DisclosureId
  readonly policyVersion: number
  readonly sourceCursor: number
  readonly eventCount: number
  readonly lastDisclosureSeq: number
  readonly lastEventHash: DisclosureHash | null
  readonly checkpointHash: DisclosureHash
  readonly signature: DisclosureSignature
}

/** Structural or integrity failure found while decoding an untrusted record. */
export class DisclosureProtocolError extends Error {
  /** @param message - Exact violated disclosure protocol rule. */
  constructor(message: string) {
    super(message)
    this.name = 'DisclosureProtocolError'
  }
}

const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/
const HASH = /^sha256:[0-9a-f]{64}$/
const BASE64URL = /^[A-Za-z0-9_-]+$/
/** Runtime allowlist shared by semantic decoding and consumers of authenticated event metadata. */
export const DISCLOSURE_SEMANTIC_EVENT_TYPES: readonly DisclosureSemanticEventType[] = Object.freeze([
  'conversation.user-message',
  'conversation.assistant-message',
  'conversation.tool-result-summary',
  'conversation.title',
])
const semanticTypes = new Set(DISCLOSURE_SEMANTIC_EVENT_TYPES)

function fail(path: string, expectation: string): never {
  throw new DisclosureProtocolError(`${path} ${expectation}`)
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail(path, 'must be an object')
  }
  return value as Record<string, unknown>
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], path: string): void {
  const allowedSet = new Set(allowed)
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) fail(`${path}.${key}`, 'is not supported')
  }
  for (const key of allowed) {
    if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, 'is required')
  }
}

function literal<T extends string | number>(value: unknown, expected: T, path: string): T {
  if (value !== expected) fail(path, `must be ${JSON.stringify(expected)}`)
  return expected
}

function nonEmptyString(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.length === 0) fail(path, 'must be a non-empty string')
  return value
}

function identifier(value: unknown, path: string): string {
  const text = nonEmptyString(value, path)
  if (!IDENTIFIER.test(text)) fail(path, 'must be a canonical opaque identifier')
  return text
}

function safeInteger(value: unknown, minimum: number, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || Object.is(value, -0)) {
    fail(path, `must be a safe integer greater than or equal to ${String(minimum)}`)
  }
  return value as number
}

function hash(value: unknown, path: string): DisclosureHash {
  const text = nonEmptyString(value, path)
  if (!HASH.test(text)) fail(path, 'must be a canonical SHA-256 digest')
  return brandString<DisclosureHash>(text)
}

function nullableHash(value: unknown, path: string): DisclosureHash | null {
  return value === null ? null : hash(value, path)
}

function base64url(value: unknown, path: string): string {
  const text = nonEmptyString(value, path)
  if (!BASE64URL.test(text)) fail(path, 'must be unpadded base64url')
  const bytes = Buffer.from(text, 'base64url')
  if (bytes.length === 0 || bytes.toString('base64url') !== text) {
    fail(path, 'must be canonical unpadded base64url')
  }
  return text
}

function signature(value: unknown, path: string): DisclosureSignature {
  return brandString<DisclosureSignature>(base64url(value, path))
}

function semanticType(value: unknown, path: string): DisclosureSemanticEventType {
  if (typeof value !== 'string' || !semanticTypes.has(value as DisclosureSemanticEventType)) {
    fail(path, 'must be a supported disclosure event type')
  }
  return value as DisclosureSemanticEventType
}

function sha256(value: string | Uint8Array): DisclosureHash {
  return brandString<DisclosureHash>(`sha256:${createHash('sha256').update(value).digest('hex')}`)
}

/**
 * Decode one untrusted plaintext projection with exact fields and the version
 * 1 disclosure allowlist. The caller owns byte and item bounds before calling.
 * @param input - Parsed JSON candidate.
 * @returns A detached semantic event.
 * @throws {DisclosureProtocolError} when the candidate is not an exact version 1 event.
 */
export function decodeDisclosureSemanticEvent(input: unknown): DisclosureSemanticEvent {
  const value = record(input, 'event')
  const type = semanticType(value.type, 'event.type')
  if (type === 'conversation.tool-result-summary') {
    exactKeys(value, ['version', 'type', 'toolName', 'outcome', 'text'], 'event')
    const outcome = value.outcome
    if (outcome !== 'success' && outcome !== 'failure') {
      fail('event.outcome', 'must be "success" or "failure"')
    }
    return {
      version: literal(value.version, 1, 'event.version'),
      type,
      toolName: nonEmptyString(value.toolName, 'event.toolName'),
      outcome,
      text: nonEmptyString(value.text, 'event.text'),
    }
  }
  if (type === 'conversation.title') {
    exactKeys(value, ['version', 'type', 'title'], 'event')
    return {
      version: literal(value.version, 1, 'event.version'),
      type,
      title: nonEmptyString(value.title, 'event.title'),
    }
  }
  exactKeys(value, ['version', 'type', 'text'], 'event')
  return {
    version: literal(value.version, 1, 'event.version'),
    type,
    text: nonEmptyString(value.text, 'event.text'),
  }
}

type EventHashInput = Omit<DisclosureEventEnvelope, 'eventHash' | 'signature'>

/**
 * Build the exact JSON tuple whose UTF-8 bytes are hashed for `eventHash`.
 * Arrays make field order explicit and portable without relying on object-key order.
 * @param event - Event fields excluding the derived hash and signature.
 * @returns Canonical JSON text for hashing.
 */
export function disclosureEventHashInput(event: EventHashInput): string {
  return JSON.stringify([
    event.protocolVersion,
    event.organizationId,
    event.instanceId,
    event.conversationId,
    event.disclosureId,
    event.eventId,
    event.disclosureSeq,
    event.sourceCursor,
    event.eventType,
    event.policyVersion,
    event.occurredAt,
    event.previousEventHash,
    event.ciphertextHash,
  ])
}

/**
 * Hash canonical ciphertext after decoding it to bytes.
 * @param ciphertext - Canonical base64url ciphertext.
 * @returns Digest of the decoded ciphertext bytes.
 */
export function computeDisclosureCiphertextHash(ciphertext: string): DisclosureHash {
  return sha256(Buffer.from(base64url(ciphertext, 'ciphertext'), 'base64url'))
}

/**
 * Hash the canonical event commitment tuple.
 * @param event - Event fields excluding the derived hash and signature.
 * @returns Digest committed by `eventHash`.
 */
export function computeDisclosureEventHash(event: EventHashInput): DisclosureHash {
  return sha256(disclosureEventHashInput(event))
}

/**
 * Decode an untrusted encrypted event and verify its ciphertext and event hashes.
 * Signature verification remains with the device-identity consumer that owns the public key.
 * @param input - Parsed JSON candidate.
 * @returns The detached, structurally valid envelope.
 * @throws {DisclosureProtocolError} when fields or committed hashes are invalid.
 */
export function decodeDisclosureEventEnvelope(input: unknown): DisclosureEventEnvelope {
  const value = record(input, 'envelope')
  exactKeys(value, [
    'protocolVersion', 'organizationId', 'instanceId', 'conversationId', 'disclosureId',
    'eventId', 'disclosureSeq', 'sourceCursor', 'eventType', 'policyVersion', 'occurredAt',
    'previousEventHash', 'ciphertext', 'ciphertextHash', 'eventHash', 'signature',
  ], 'envelope')
  const envelope: DisclosureEventEnvelope = {
    protocolVersion: literal(value.protocolVersion, DISCLOSURE_PROTOCOL_VERSION, 'envelope.protocolVersion'),
    organizationId: brandString<OrganizationId>(identifier(value.organizationId, 'envelope.organizationId')),
    instanceId: brandString<DshInstanceId>(identifier(value.instanceId, 'envelope.instanceId')),
    conversationId: brandString<DisclosureConversationId>(identifier(value.conversationId, 'envelope.conversationId')),
    disclosureId: brandString<DisclosureId>(identifier(value.disclosureId, 'envelope.disclosureId')),
    eventId: brandString<DisclosureEventId>(identifier(value.eventId, 'envelope.eventId')),
    disclosureSeq: safeInteger(value.disclosureSeq, 0, 'envelope.disclosureSeq'),
    sourceCursor: safeInteger(value.sourceCursor, 0, 'envelope.sourceCursor'),
    eventType: semanticType(value.eventType, 'envelope.eventType'),
    policyVersion: safeInteger(value.policyVersion, 1, 'envelope.policyVersion'),
    occurredAt: safeInteger(value.occurredAt, 0, 'envelope.occurredAt'),
    previousEventHash: nullableHash(value.previousEventHash, 'envelope.previousEventHash'),
    ciphertext: base64url(value.ciphertext, 'envelope.ciphertext'),
    ciphertextHash: hash(value.ciphertextHash, 'envelope.ciphertextHash'),
    eventHash: hash(value.eventHash, 'envelope.eventHash'),
    signature: signature(value.signature, 'envelope.signature'),
  }
  const first = envelope.disclosureSeq === 0
  if ((envelope.previousEventHash === null) !== first) {
    fail('envelope.previousEventHash', first ? 'must be null for the first event' : 'is required after the first event')
  }
  if (computeDisclosureCiphertextHash(envelope.ciphertext) !== envelope.ciphertextHash) {
    fail('envelope.ciphertextHash', 'does not match ciphertext')
  }
  if (computeDisclosureEventHash(envelope) !== envelope.eventHash) {
    fail('envelope.eventHash', 'does not match the committed event fields')
  }
  return envelope
}

type CheckpointHashInput = Omit<DisclosureCheckpoint, 'checkpointHash' | 'signature'>

/**
 * Build the exact JSON tuple whose UTF-8 bytes are hashed for `checkpointHash`.
 * @param checkpoint - Checkpoint fields excluding the derived hash and signature.
 * @returns Canonical JSON text for hashing.
 */
export function disclosureCheckpointHashInput(checkpoint: CheckpointHashInput): string {
  return JSON.stringify([
    checkpoint.protocolVersion,
    checkpoint.organizationId,
    checkpoint.instanceId,
    checkpoint.disclosureId,
    checkpoint.policyVersion,
    checkpoint.sourceCursor,
    checkpoint.eventCount,
    checkpoint.lastDisclosureSeq,
    checkpoint.lastEventHash,
  ])
}

/**
 * Hash the canonical checkpoint commitment tuple.
 * @param checkpoint - Checkpoint fields excluding the derived hash and signature.
 * @returns Digest committed by `checkpointHash`.
 */
export function computeDisclosureCheckpointHash(checkpoint: CheckpointHashInput): DisclosureHash {
  return sha256(disclosureCheckpointHashInput(checkpoint))
}

/**
 * Decode an untrusted full-history checkpoint and verify its count and hash relations.
 * Signature verification remains with the device-identity consumer.
 * @param input - Parsed JSON candidate.
 * @returns The detached, structurally valid checkpoint.
 * @throws {DisclosureProtocolError} when fields or committed hashes are invalid.
 */
export function decodeDisclosureCheckpoint(input: unknown): DisclosureCheckpoint {
  const value = record(input, 'checkpoint')
  exactKeys(value, [
    'protocolVersion', 'organizationId', 'instanceId', 'disclosureId', 'policyVersion',
    'sourceCursor', 'eventCount', 'lastDisclosureSeq', 'lastEventHash', 'checkpointHash', 'signature',
  ], 'checkpoint')
  const checkpoint: DisclosureCheckpoint = {
    protocolVersion: literal(value.protocolVersion, DISCLOSURE_PROTOCOL_VERSION, 'checkpoint.protocolVersion'),
    organizationId: brandString<OrganizationId>(identifier(value.organizationId, 'checkpoint.organizationId')),
    instanceId: brandString<DshInstanceId>(identifier(value.instanceId, 'checkpoint.instanceId')),
    disclosureId: brandString<DisclosureId>(identifier(value.disclosureId, 'checkpoint.disclosureId')),
    policyVersion: safeInteger(value.policyVersion, 1, 'checkpoint.policyVersion'),
    sourceCursor: safeInteger(value.sourceCursor, 0, 'checkpoint.sourceCursor'),
    eventCount: safeInteger(value.eventCount, 0, 'checkpoint.eventCount'),
    lastDisclosureSeq: safeInteger(value.lastDisclosureSeq, -1, 'checkpoint.lastDisclosureSeq'),
    lastEventHash: nullableHash(value.lastEventHash, 'checkpoint.lastEventHash'),
    checkpointHash: hash(value.checkpointHash, 'checkpoint.checkpointHash'),
    signature: signature(value.signature, 'checkpoint.signature'),
  }
  const empty = checkpoint.eventCount === 0
  if (checkpoint.lastDisclosureSeq !== checkpoint.eventCount - 1) {
    fail('checkpoint.lastDisclosureSeq', 'must equal eventCount minus one')
  }
  if ((checkpoint.lastEventHash === null) !== empty) {
    fail('checkpoint.lastEventHash', empty ? 'must be null for an empty prefix' : 'is required for a non-empty prefix')
  }
  if (computeDisclosureCheckpointHash(checkpoint) !== checkpoint.checkpointHash) {
    fail('checkpoint.checkpointHash', 'does not match the committed checkpoint fields')
  }
  return checkpoint
}
