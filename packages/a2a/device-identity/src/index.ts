/**
 * Ed25519 authentication for disclosure protocol commitments.
 * The caller supplies registry-authenticated key history and connection identity;
 * decoding public-key JSON does not establish account or device ownership.
 * @module @deepseek-ai/dsh-a2a-device-identity
 */
import { createHash, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto'
import { brandString } from '@deepseek-ai/dsh-brand'
import {
  computeDisclosureCheckpointHash,
  computeDisclosureEventHash,
  decodeDisclosureCheckpoint,
  decodeDisclosureEventEnvelope,
  type DisclosureCheckpoint,
  type DisclosureEventEnvelope,
  type DisclosureHash,
  type DisclosureSignature,
  type DshInstanceId,
  type OrganizationId,
} from '@deepseek-ai/dsh-a2a-protocol'
import type {
  InstanceKeyHistory,
  InstanceKeyId,
  InstanceKeyPair,
  InstancePublicKey,
  InstanceVerificationContext,
} from './types.ts'

export type { InstanceKeyHistory, InstanceKeyId, InstanceKeyPair, InstancePublicKey, InstanceVerificationContext } from './types.ts'

/** Invalid key history, expired/revoked authority, or failed instance authentication. */
export class InstanceIdentityError extends Error {
  /** @param message - Violated identity or signature requirement. */
  constructor(message: string) {
    super(message)
    this.name = 'InstanceIdentityError'
  }
}

/** A decoded signature has the wrong byte length or fails Ed25519 verification after ownership and key checks.
 * Consumers may distinguish this from authority or protocol failures without parsing diagnostic messages. */
export class InstanceSignatureError extends InstanceIdentityError {
  constructor() {
    super('instance signature verification failed')
    this.name = 'InstanceSignatureError'
  }
}

function fail(message: string): never {
  throw new InstanceIdentityError(message)
}

function timestamp(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || Object.is(value, -0)) {
    fail(`${path} must be a non-negative safe integer`)
  }
  return value as number
}

function exactRecord(input: unknown, keys: readonly string[], path: string): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) fail(`${path} must be an object`)
  const record = input as Record<string, unknown>
  if (Object.keys(record).length !== keys.length || keys.some(key => !Object.hasOwn(record, key))) {
    fail(`${path} must contain exactly ${keys.join(', ')}`)
  }
  return record
}

function identifier(input: unknown, path: string): string {
  if (typeof input !== 'string' || !/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/.test(input)) {
    fail(`${path} must be a canonical opaque identifier`)
  }
  return input
}

function publicKey(input: unknown): KeyObject {
  if (typeof input !== 'string' || !/^[A-Za-z0-9_-]+$/.test(input)) {
    fail('publicKeySpki must be canonical unpadded base64url')
  }
  const bytes = Buffer.from(input, 'base64url')
  if (bytes.toString('base64url') !== input) fail('publicKeySpki must be canonical unpadded base64url')
  let key: KeyObject
  try {
    key = createPublicKey({ key: bytes, format: 'der', type: 'spki' })
  } catch {
    // OpenSSL parser errors contain no useful protocol-level recovery detail.
    return fail('publicKeySpki must encode an Ed25519 SPKI public key')
  }
  if (key.asymmetricKeyType !== 'ed25519') fail('publicKeySpki must encode an Ed25519 SPKI public key')
  if (!key.export({ format: 'der', type: 'spki' }).equals(bytes)) fail('publicKeySpki must use canonical DER')
  return key
}

function fingerprint(spki: string): InstanceKeyId {
  return brandString<InstanceKeyId>(`sha256:${createHash('sha256').update(Buffer.from(spki, 'base64url')).digest('hex')}`)
}

/**
 * Generate an independent Ed25519 private key held only in process memory.
 * @returns Private KeyObject, canonical public SPKI, and public-key fingerprint.
 */
export function generateInstanceKeyPair(): InstanceKeyPair {
  const pair = generateKeyPairSync('ed25519')
  const publicKeySpki = pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url')
  return { privateKey: pair.privateKey, publicKeySpki, keyId: fingerprint(publicKeySpki) }
}

/**
 * Validate persisted or received registry-owned public-key history without authenticating its source.
 * @param input - JSON obtained from an authenticated registry authority, with caller-owned size bounds.
 * @returns Detached history with canonical Ed25519 keys and unique matching fingerprints.
 * @throws {InstanceIdentityError} for malformed fields, keys, or validity intervals.
 */
export function decodeInstanceKeyHistory(input: unknown): InstanceKeyHistory {
  const value = exactRecord(input, ['organizationId', 'instanceId', 'status', 'keys'], 'history')
  if (value.status !== 'active' && value.status !== 'revoked') fail('history.status must be active or revoked')
  if (!Array.isArray(value.keys) || value.keys.length === 0) fail('history.keys must be a non-empty array')
  const ids = new Set<InstanceKeyId>()
  const keys = value.keys.map((inputKey: unknown): InstancePublicKey => {
    const key = exactRecord(inputKey, ['keyId', 'publicKeySpki', 'validFrom', 'validUntil', 'revokedAt'], 'key')
    publicKey(key.publicKeySpki)
    const spki = key.publicKeySpki as string
    const keyId = fingerprint(spki)
    if (key.keyId !== keyId) fail('key.keyId must match the public-key fingerprint')
    if (ids.has(keyId)) fail('history.keys must not repeat a keyId')
    ids.add(keyId)
    const validFrom = timestamp(key.validFrom, 'key.validFrom')
    const validUntil = key.validUntil === null ? null : timestamp(key.validUntil, 'key.validUntil')
    const revokedAt = key.revokedAt === null ? null : timestamp(key.revokedAt, 'key.revokedAt')
    if (validUntil !== null && validUntil <= validFrom) fail('key.validUntil must exceed validFrom')
    if (revokedAt !== null && revokedAt < validFrom) fail('key.revokedAt must not precede validFrom')
    return { keyId, publicKeySpki: spki, validFrom, validUntil, revokedAt }
  })
  return {
    organizationId: brandString<OrganizationId>(identifier(value.organizationId, 'history.organizationId')),
    instanceId: brandString<DshInstanceId>(identifier(value.instanceId, 'history.instanceId')),
    status: value.status,
    keys,
  }
}

function signHash(hash: DisclosureHash, key: KeyObject): DisclosureSignature {
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') fail('signing requires an Ed25519 private key')
  // Protocol v1 signs the UTF-8 `sha256:<lowercase hex>` string, including its prefix.
  return brandString<DisclosureSignature>(sign(null, Buffer.from(hash, 'utf8'), key).toString('base64url'))
}

/**
 * Compute an event commitment and sign its canonical prefixed hash string.
 * @param event - Unsigned projected envelope with its ciphertext digest already computed.
 * @param privateKey - In-memory Ed25519 key from the authenticated source instance.
 * @returns Structurally validated signed event; no transport or persistence occurs.
 */
export function signDisclosureEvent(
  event: Omit<DisclosureEventEnvelope, 'eventHash' | 'signature'>,
  privateKey: KeyObject,
): DisclosureEventEnvelope {
  const eventHash = computeDisclosureEventHash(event)
  return decodeDisclosureEventEnvelope({ ...event, eventHash, signature: signHash(eventHash, privateKey) })
}

/**
 * Compute a checkpoint commitment and sign its canonical prefixed hash string.
 * @param checkpoint - Unsigned completion checkpoint.
 * @param privateKey - In-memory Ed25519 key from the authenticated source instance.
 * @returns Structurally validated signed checkpoint; no transport or persistence occurs.
 */
export function signDisclosureCheckpoint(
  checkpoint: Omit<DisclosureCheckpoint, 'checkpointHash' | 'signature'>,
  privateKey: KeyObject,
): DisclosureCheckpoint {
  const checkpointHash = computeDisclosureCheckpointHash(checkpoint)
  return decodeDisclosureCheckpoint({ ...checkpoint, checkpointHash, signature: signHash(checkpointHash, privateKey) })
}

function authenticate(
  record: Pick<DisclosureEventEnvelope, 'organizationId' | 'instanceId'>,
  recordTime: number,
  hash: DisclosureHash,
  signature: DisclosureSignature,
  history: InstanceKeyHistory,
  context: InstanceVerificationContext,
): void {
  timestamp(context.now, 'context.now')
  if (record.organizationId !== context.organizationId || record.instanceId !== context.instanceId
    || history.organizationId !== context.organizationId || history.instanceId !== context.instanceId) {
    fail('record, authenticated connection, and key history must identify the same organization and instance')
  }
  if (history.status !== 'active') fail('instance is revoked')
  const key = history.keys.find(candidate => candidate.keyId === context.keyId)
  if (!key) fail('authenticated keyId is absent from instance history')
  if (key.revokedAt !== null) fail('instance key is revoked')
  if (recordTime > context.now) fail('record time must not exceed the trusted receive time')
  if (recordTime < key.validFrom || (key.validUntil !== null && recordTime >= key.validUntil)) {
    fail('record time is outside the instance key validity interval')
  }
  const bytes = Buffer.from(signature, 'base64url')
  if (bytes.length !== 64 || !verify(null, Buffer.from(hash, 'utf8'), publicKey(key.publicKeySpki), bytes)) {
    throw new InstanceSignatureError()
  }
}

/**
 * Decode and authenticate an event against its signed occurrence time and trusted ownership.
 * @param input - Untrusted event JSON; transport limits apply before decoding.
 * @param history - Decoded history from the authenticated registry authority, not the message sender.
 * @param context - Authenticated organization, instance, handshake-selected key, and receive time.
 * @returns Detached verified envelope; repeated valid records remain valid for the ingest owner's deduplication.
 * @throws {InstanceIdentityError} for invalid authority; signature failures use its InstanceSignatureError subclass.
 * Protocol decoding errors propagate.
 */
export function verifyDisclosureEvent(
  input: unknown,
  history: InstanceKeyHistory,
  context: InstanceVerificationContext,
): DisclosureEventEnvelope {
  const event = decodeDisclosureEventEnvelope(input)
  authenticate(event, event.occurredAt, event.eventHash, event.signature, history, context)
  return event
}

/**
 * Decode and authenticate a checkpoint using its trusted receive time for key validity.
 * V1 checkpoints contain no signed timestamp; expired keys cannot authenticate late checkpoints.
 * @param input - Untrusted checkpoint JSON; transport limits apply before decoding.
 * @param history - Decoded history from the authenticated registry authority.
 * @param context - Authenticated identity and handshake key, with the trusted receive time.
 * @returns Detached verified checkpoint; authorization and stored-prefix checks remain caller-owned.
 * @throws {InstanceIdentityError} for invalid authority; signature failures use its InstanceSignatureError subclass.
 * Protocol decoding errors propagate.
 */
export function verifyDisclosureCheckpoint(
  input: unknown,
  history: InstanceKeyHistory,
  context: InstanceVerificationContext,
): DisclosureCheckpoint {
  const checkpoint = decodeDisclosureCheckpoint(input)
  authenticate(checkpoint, context.now, checkpoint.checkpointHash, checkpoint.signature, history, context)
  return checkpoint
}
