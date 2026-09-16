/**
 * AES-256-GCM disclosure payloads with bounded decoding and exact authenticated metadata.
 * Authorization, policy filtering, KMS integration, and key persistence belong to callers.
 * @module @deepseek-ai/dsh-a2a-disclosure-crypto
 */
import {
  createCipheriv, createDecipheriv, createHash, createSecretKey, generateKeySync, hkdfSync, KeyObject,
  randomBytes, randomUUID,
} from 'node:crypto'
import { brandString } from '@deepseek-ai/dsh-brand'
import { credentialKey, type CredentialRecord } from '@deepseek-ai/dsh-credentials'
import {
  decodeDisclosureSemanticEvent, DISCLOSURE_SEMANTIC_EVENT_TYPES,
  type DisclosureSemanticEvent, type DisclosureSemanticEventType,
} from '@deepseek-ai/dsh-a2a-protocol'
import type {
  DisclosureCryptoErrorCode, DisclosureCryptoLimits, DisclosureDataKey, DisclosureDataKeyId,
  DisclosureDataKeyGrant, DisclosureDataKeyGrantOwner, DisclosureDataKeyGrantScope,
  DisclosureDataKeyWrapContext, DisclosureEncryptionMetadata, DisclosureKeyScope, WrappedDisclosureDataKey,
} from './types.ts'

export type * from './types.ts'

const VERSION = 1
const scopeFields = ['organizationId', 'instanceId', 'conversationId'] as const
const metadataFields = [...scopeFields, 'disclosureId', 'eventId', 'eventType', 'policyVersion'] as const
const eventTypes = new Set<DisclosureSemanticEventType>(DISCLOSURE_SEMANTIC_EVENT_TYPES)
const DATA_KEY_BYTES = 32
const SHARED_SECRET_MIN_BYTES = 32
const SHARED_SECRET_MAX_BYTES = 4_096
const WRAP_NONCE_BYTES = 12
const WRAP_TAG_BYTES = 16
const WRAP_KDF_SALT = Buffer.from('dsh-a2a-disclosure-key-escrow-v1', 'utf8')
const WRAP_KDF_INFO = Buffer.from('test-only/source-to-registry/aes-256-gcm-kek', 'utf8')
const grantOwners: ReadonlySet<string> = new Set(['web-app', 'registry-app'])
const grantScopeFields = [...scopeFields, 'disclosureId'] as const
const wrapContextFields = ['version', 'organizationId', 'sourceInstanceId', 'conversationId',
  'disclosureId', 'keyId'] as const

/** Rejected input or failed authentication; neither its message nor cause contains payload text. */
export class DisclosureCryptoError extends Error {
  /** @param code - Stable content-free failure category. */
  constructor(readonly code: DisclosureCryptoErrorCode) {
    super(`disclosure crypto: ${code}`)
    this.name = 'DisclosureCryptoError'
  }
}

function requireCrypto(condition: boolean, code: DisclosureCryptoErrorCode): asserts condition {
  if (!condition) throw new DisclosureCryptoError(code)
}

function exactRecord(input: unknown, fields: readonly string[], code: DisclosureCryptoErrorCode): Record<string, unknown> {
  requireCrypto(typeof input === 'object' && input !== null && !Array.isArray(input), code)
  const value = input as Record<string, unknown>
  requireCrypto(Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field)), code)
  return value
}

function identifier(input: unknown, code: DisclosureCryptoErrorCode): string {
  requireCrypto(typeof input === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/.test(input), code)
  return input
}

function scope(input: DisclosureKeyScope): DisclosureKeyScope {
  const value = exactRecord(input, scopeFields, 'invalid-key')
  for (const field of scopeFields) identifier(value[field], 'invalid-key')
  return Object.freeze({ ...input })
}

function metadata(input: DisclosureEncryptionMetadata): DisclosureEncryptionMetadata {
  const value = exactRecord(input, metadataFields, 'invalid-metadata')
  for (const field of [...scopeFields, 'disclosureId', 'eventId']) identifier(value[field], 'invalid-metadata')
  requireCrypto(eventTypes.has(value.eventType as DisclosureSemanticEventType)
    && Number.isSafeInteger(value.policyVersion) && (value.policyVersion as number) > 0, 'invalid-metadata')
  return { ...input }
}

function limits(input: DisclosureCryptoLimits): DisclosureCryptoLimits {
  const value = exactRecord(input, ['maxPlaintextBytes', 'maxCiphertextBytes', 'maxTrustedKeys'], 'invalid-limits')
  for (const field of Object.values(value)) {
    requireCrypto(Number.isSafeInteger(field) && (field as number) > 0, 'invalid-limits')
  }
  return { ...input }
}

function checkedKey(input: DisclosureDataKey): DisclosureDataKey {
  identifier(input.keyId, 'invalid-key')
  requireCrypto(input.key instanceof KeyObject && input.key.type === 'secret' && input.key.symmetricKeySize === 32, 'invalid-key')
  return { keyId: input.keyId, scope: scope(input.scope), key: input.key }
}

function grantScope(input: DisclosureDataKeyGrantScope): DisclosureDataKeyGrantScope {
  const value = exactRecord(input, grantScopeFields, 'invalid-key')
  for (const field of grantScopeFields) identifier(value[field], 'invalid-key')
  return Object.freeze({ ...input })
}

function wrapContext(input: DisclosureDataKeyWrapContext): DisclosureDataKeyWrapContext {
  const value = exactRecord(input, wrapContextFields, 'invalid-metadata')
  requireCrypto(value.version === VERSION, 'unsupported-version')
  for (const field of wrapContextFields.slice(1)) identifier(value[field], 'invalid-metadata')
  return Object.freeze({ ...input })
}

function sharedSecret(input: string): Buffer {
  requireCrypto(typeof input === 'string', 'invalid-key')
  const value = Buffer.from(input, 'utf8')
  requireCrypto(value.byteLength >= SHARED_SECRET_MIN_BYTES && value.byteLength <= SHARED_SECRET_MAX_BYTES,
    'invalid-key')
  return value
}

function wrapAad(value: DisclosureDataKeyWrapContext): Buffer {
  return Buffer.from(JSON.stringify([value.version, value.organizationId, value.sourceInstanceId,
    value.conversationId, value.disclosureId, value.keyId]), 'utf8')
}

function kek(input: string): Buffer {
  const secret = sharedSecret(input)
  try { return Buffer.from(hkdfSync('sha256', secret, WRAP_KDF_SALT, WRAP_KDF_INFO, DATA_KEY_BYTES)) }
  finally { secret.fill(0) }
}

function wrappedDataKey(input: unknown): {
  value: WrappedDisclosureDataKey
  nonce: Buffer
  ciphertext: Buffer
  tag: Buffer
} {
  const value = exactRecord(input, ['version', 'nonce', 'ciphertext', 'tag'], 'invalid-payload')
  requireCrypto(value.version === VERSION, 'unsupported-version')
  const nonce = base64url(value.nonce, WRAP_NONCE_BYTES)
  const ciphertext = base64url(value.ciphertext, DATA_KEY_BYTES)
  const tag = base64url(value.tag, WRAP_TAG_BYTES)
  return { value: { version: VERSION, nonce: nonce.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'), tag: tag.toString('base64url') }, nonce, ciphertext, tag }
}

function grantRecord(input: unknown, expectedScope: DisclosureDataKeyGrantScope,
  maximum: number): readonly DisclosureDataKey[] {
  requireCrypto(Number.isSafeInteger(maximum) && maximum > 0, 'invalid-limits')
  const record = exactRecord(input, ['kind', 'payload'], 'invalid-key')
  requireCrypto(record.kind === 'grant', 'invalid-key')
  const payload = exactRecord(record.payload, ['version', 'scope', 'keys'], 'invalid-key')
  requireCrypto(payload.version === VERSION, 'invalid-key')
  const storedScope = grantScope(payload.scope as DisclosureDataKeyGrantScope)
  requireCrypto(grantScopeFields.every(field => storedScope[field] === expectedScope[field]), 'key-scope-mismatch')
  requireCrypto(Array.isArray(payload.keys) && payload.keys.length > 0 && payload.keys.length <= maximum, 'invalid-key')
  const seen = new Set<string>()
  return payload.keys.map((candidate): DisclosureDataKey => {
    const value = exactRecord(candidate, ['keyId', 'material'], 'invalid-key')
    const keyId = identifier(value.keyId, 'invalid-key')
    requireCrypto(!seen.has(keyId), 'ambiguous-key')
    seen.add(keyId)
    const material = base64url(value.material, DATA_KEY_BYTES)
    try {
      return { keyId: brandString<DisclosureDataKeyId>(keyId), scope: {
        organizationId: expectedScope.organizationId,
        instanceId: expectedScope.instanceId,
        conversationId: expectedScope.conversationId,
      }, key: createSecretKey(material) }
    } finally { material.fill(0) }
  })
}

function requireScope(key: DisclosureDataKey, value: DisclosureEncryptionMetadata): void {
  requireCrypto(scopeFields.every(field => key.scope[field] === value[field]), 'key-scope-mismatch')
}

function additionalData(value: DisclosureEncryptionMetadata, keyId: DisclosureDataKeyId): Buffer {
  return Buffer.from(JSON.stringify([
    VERSION, keyId, value.organizationId, value.instanceId, value.conversationId,
    value.disclosureId, value.eventId, value.eventType, value.policyVersion,
  ]), 'utf8')
}

function semantic(input: unknown): DisclosureSemanticEvent {
  try {
    return decodeDisclosureSemanticEvent(input)
  } catch {
    // Decoder diagnostics may quote input fields; public crypto errors never retain them.
    throw new DisclosureCryptoError('invalid-semantic-event')
  }
}

function plaintext(event: DisclosureSemanticEvent, maximum: number): Buffer {
  // Limit each source string before JSON escaping allocates at most six bytes per code unit.
  for (const value of Object.values(event)) {
    requireCrypto(typeof value !== 'string' || value.length <= maximum, 'limit-exceeded')
  }
  const serialized = JSON.stringify(event)
  requireCrypto(Buffer.byteLength(serialized, 'utf8') <= maximum, 'limit-exceeded')
  return Buffer.from(serialized, 'utf8')
}

function base64url(input: unknown, exactBytes?: number): Buffer {
  requireCrypto(typeof input === 'string' && /^[A-Za-z0-9_-]+$/.test(input), 'invalid-payload')
  if (exactBytes !== undefined) {
    requireCrypto(input.length === Math.ceil(exactBytes * 4 / 3), 'invalid-payload')
  }
  const bytes = Buffer.from(input, 'base64url')
  requireCrypto(bytes.length > 0 && bytes.toString('base64url') === input
    && (exactBytes === undefined || bytes.length === exactBytes), 'invalid-payload')
  return bytes
}

function parseJson(input: string, code: DisclosureCryptoErrorCode): unknown {
  try {
    return JSON.parse(input)
  } catch {
    // JSON parser messages can include plaintext; only the stable category leaves this library.
    throw new DisclosureCryptoError(code)
  }
}

interface Payload {
  version: number
  keyId: DisclosureDataKeyId
  nonce: string
  ciphertext: string
  tag: string
}

function payload(input: unknown, maximum: number): { value: Payload; nonce: Buffer; ciphertext: Buffer; tag: Buffer } {
  requireCrypto(typeof input === 'string', 'invalid-payload')
  requireCrypto(input.length <= maximum, 'limit-exceeded')
  const bytes = base64url(input)
  const text = bytes.toString('utf8')
  const candidate = exactRecord(parseJson(text, 'invalid-payload'), ['version', 'keyId', 'nonce', 'ciphertext', 'tag'], 'invalid-payload')
  requireCrypto(candidate.version === VERSION, 'unsupported-version')
  const keyId = brandString<DisclosureDataKeyId>(identifier(candidate.keyId, 'invalid-payload'))
  const nonce = base64url(candidate.nonce, 12)
  const ciphertext = base64url(candidate.ciphertext)
  const tag = base64url(candidate.tag, 16)
  const value: Payload = {
    version: VERSION, keyId, nonce: nonce.toString('base64url'), ciphertext: ciphertext.toString('base64url'), tag: tag.toString('base64url'),
  }
  requireCrypto(JSON.stringify(value) === text, 'invalid-payload')
  return { value, nonce, ciphertext, tag }
}

/**
 * Generate an independent in-memory AES-256 conversation key and snapshot its immutable scope.
 * @param keyScope - Canonical organization, instance, and conversation identities.
 * @returns Exportable Node KeyObject with an independent opaque key selector; no key persistence occurs.
 * @throws {DisclosureCryptoError} if the scope is malformed.
 */
export function generateDisclosureDataKey(keyScope: DisclosureKeyScope): DisclosureDataKey {
  const capturedScope = scope(keyScope)
  return Object.freeze({
    keyId: brandString<DisclosureDataKeyId>(`data-key:${randomUUID()}`),
    scope: capturedScope,
    key: generateKeySync('aes', { length: 256 }),
  })
}

/**
 * Address one disclosure-specific local-test key grant without exposing its scope in the credential key.
 * @param owner - Fixed Web or Registry grant owner.
 * @param keyScope - Exact organization, source, conversation and disclosure scope.
 * @returns Deterministic credential key for this owner and scope.
 */
export function disclosureDataKeyCredential(owner: DisclosureDataKeyGrantOwner,
  keyScope: DisclosureDataKeyGrantScope): ReturnType<typeof credentialKey> {
  requireCrypto(grantOwners.has(owner), 'invalid-key')
  const captured = grantScope(keyScope)
  const digest = createHash('sha256').update(grantScopeFields.map(field => captured[field]).join('\0'), 'utf8').digest('hex')
  return credentialKey(owner, `a2a-disclosure-key-${digest}`)
}

/**
 * Encode one or more same-scope keys as the exact local-test Credentials grant format.
 * @param owner - Fixed Web or Registry grant owner.
 * @param keyScope - Disclosure-specific persisted scope.
 * @param dataKeys - Nonempty, uniquely identified keys for the scope.
 * @returns Matching credential address and detached grant record.
 */
export function encodeDisclosureDataKeyGrant(owner: DisclosureDataKeyGrantOwner,
  keyScope: DisclosureDataKeyGrantScope, dataKeys: readonly DisclosureDataKey[]): DisclosureDataKeyGrant {
  const captured = grantScope(keyScope)
  requireCrypto(dataKeys.length > 0, 'invalid-key')
  const keys = dataKeys.map(checkedKey)
  requireCrypto(new Set(keys.map(key => key.keyId)).size === keys.length, 'ambiguous-key')
  requireCrypto(keys.every(key => scopeFields.every(field => key.scope[field] === captured[field])), 'key-scope-mismatch')
  const serialized = keys.map((key) => {
    const exported = key.key.export()
    const material = Buffer.isBuffer(exported) ? exported : Buffer.from(exported)
    try { return { keyId: key.keyId, material: material.toString('base64url') } }
    finally { material.fill(0) }
  })
  const record: CredentialRecord = { kind: 'grant', payload: {
    version: VERSION, scope: captured, keys: serialized,
  } }
  return { key: disclosureDataKeyCredential(owner, captured), record }
}

/**
 * Decode a local-test Credentials grant only when every persisted scope field matches.
 * @param input - Untrusted credential record value.
 * @param expectedScope - Exact disclosure-specific scope selected outside the record.
 * @param maxTrustedKeys - Maximum retained keys admitted from the record.
 * @returns Detached in-memory AES keys.
 */
export function decodeDisclosureDataKeyGrant(input: unknown, expectedScope: DisclosureDataKeyGrantScope,
  maxTrustedKeys: number): readonly DisclosureDataKey[] {
  return grantRecord(input, grantScope(expectedScope), maxTrustedKeys)
}

/**
 * Wrap one raw data key for the explicit local-test source-to-Registry channel.
 * @param dataKey - Existing disclosure data key; no new content key is generated.
 * @param context - Exact transfer coordinates authenticated as GCM AAD.
 * @param secret - Shared loopback secret used only as HKDF input.
 * @returns Fixed-size AES-256-GCM wrapped-key envelope.
 */
export function wrapDisclosureDataKey(dataKey: DisclosureDataKey, context: DisclosureDataKeyWrapContext,
  secret: string): WrappedDisclosureDataKey {
  const key = checkedKey(dataKey)
  const captured = wrapContext(context)
  requireCrypto(key.keyId === captured.keyId && key.scope.organizationId === captured.organizationId
    && key.scope.instanceId === captured.sourceInstanceId
    && key.scope.conversationId === captured.conversationId, 'key-scope-mismatch')
  const wrappingKey = kek(secret)
  const material = key.key.export()
  const raw = Buffer.isBuffer(material) ? material : Buffer.from(material)
  const nonce = randomBytes(WRAP_NONCE_BYTES)
  try {
    const cipher = createCipheriv('aes-256-gcm', wrappingKey, nonce, { authTagLength: WRAP_TAG_BYTES })
    cipher.setAAD(wrapAad(captured))
    const ciphertext = Buffer.concat([cipher.update(raw), cipher.final()])
    return { version: VERSION, nonce: nonce.toString('base64url'), ciphertext: ciphertext.toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url') }
  } finally {
    wrappingKey.fill(0)
    raw.fill(0)
  }
}

/**
 * Unwrap one local-test transfer only under the exact externally selected coordinates.
 * @param input - Untrusted wrapped-key envelope.
 * @param context - Exact transfer coordinates authenticated as GCM AAD.
 * @param secret - Shared loopback secret used only as HKDF input.
 * @returns In-memory data key scoped to the authenticated organization, source and conversation.
 */
export function unwrapDisclosureDataKey(input: unknown, context: DisclosureDataKeyWrapContext,
  secret: string): DisclosureDataKey {
  const captured = wrapContext(context)
  const wrapped = wrappedDataKey(input)
  const wrappingKey = kek(secret)
  const decipher = createDecipheriv('aes-256-gcm', wrappingKey, wrapped.nonce, { authTagLength: WRAP_TAG_BYTES })
  decipher.setAAD(wrapAad(captured))
  decipher.setAuthTag(wrapped.tag)
  let material: Buffer
  try { material = Buffer.concat([decipher.update(wrapped.ciphertext), decipher.final()]) } catch {
    throw new DisclosureCryptoError('authentication-failed')
  } finally { wrappingKey.fill(0) }
  try {
    requireCrypto(material.byteLength === DATA_KEY_BYTES, 'invalid-key')
    return { keyId: captured.keyId, scope: { organizationId: captured.organizationId,
      instanceId: captured.sourceInstanceId, conversationId: captured.conversationId },
    key: createSecretKey(material) }
  } finally { material.fill(0) }
}

/**
 * Encrypt a policy-approved semantic event with a fresh 96-bit nonce and a 128-bit GCM tag.
 * @param event - Text-only semantic event after caller-owned policy filtering and preview.
 * @param authenticatedMetadata - Exact metadata to bind as AAD; its type must match the semantic event.
 * @param dataKey - Explicit active key from a trusted conversation-key provider.
 * @param bounds - Complete plaintext/payload and trusted-key count limits.
 * @returns Canonical unpadded base64url payload suitable for the protocol envelope's ciphertext field.
 * @throws {DisclosureCryptoError} for invalid metadata, key, semantics, or exceeded bounds; no plaintext enters diagnostics.
 */
export function encryptDisclosurePayload(
  event: DisclosureSemanticEvent,
  authenticatedMetadata: DisclosureEncryptionMetadata,
  dataKey: DisclosureDataKey,
  bounds: DisclosureCryptoLimits,
): string {
  const maximum = limits(bounds)
  const captured = metadata(authenticatedMetadata)
  const key = checkedKey(dataKey)
  requireScope(key, captured)
  const decoded = semantic(event)
  requireCrypto(decoded.type === captured.eventType, 'invalid-metadata')
  const bytes = plaintext(decoded, maximum.maxPlaintextBytes)
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key.key, nonce, { authTagLength: 16 })
  cipher.setAAD(additionalData(captured, key.keyId))
  const encrypted = Buffer.concat([cipher.update(bytes), cipher.final()])
  const value: Payload = {
    version: VERSION, keyId: key.keyId, nonce: nonce.toString('base64url'),
    ciphertext: encrypted.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'),
  }
  const result = Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  requireCrypto(result.length <= maximum.maxCiphertextBytes, 'limit-exceeded')
  return result
}

/**
 * Decrypt a payload only with an explicitly permitted key from the authenticated provider.
 * Callers must authorize the reader before invoking this function and authenticate the outer envelope.
 * @param input - Untrusted protocol ciphertext string, bounded before base64 or JSON allocation.
 * @param authenticatedMetadata - Exact expected envelope metadata; no value is taken from plaintext.
 * @param trustedKeys - Explicit current or historical keys; duplicate selectors reject instead of choosing arbitrarily.
 * @param bounds - Complete plaintext/payload and trusted-key count limits.
 * @returns Detached strict semantic event after GCM authentication, scope, and event-type checks.
 * @throws {DisclosureCryptoError} for invalid input, unavailable keys, authentication failure, or exceeded bounds.
 */
export function decryptDisclosurePayload(
  input: unknown,
  authenticatedMetadata: DisclosureEncryptionMetadata,
  trustedKeys: readonly DisclosureDataKey[],
  bounds: DisclosureCryptoLimits,
): DisclosureSemanticEvent {
  const maximum = limits(bounds)
  const captured = metadata(authenticatedMetadata)
  requireCrypto(trustedKeys.length <= maximum.maxTrustedKeys, 'limit-exceeded')
  const keys = trustedKeys.map(checkedKey)
  requireCrypto(new Set(keys.map(key => key.keyId)).size === keys.length, 'ambiguous-key')
  const decoded = payload(input, maximum.maxCiphertextBytes)
  requireCrypto(decoded.ciphertext.length <= maximum.maxPlaintextBytes, 'limit-exceeded')
  const key = keys.find(candidate => candidate.keyId === decoded.value.keyId)
  requireCrypto(key !== undefined, 'key-not-found')
  requireScope(key, captured)
  const decipher = createDecipheriv('aes-256-gcm', key.key, decoded.nonce, { authTagLength: 16 })
  decipher.setAAD(additionalData(captured, key.keyId))
  decipher.setAuthTag(decoded.tag)
  let bytes: Buffer
  try {
    bytes = Buffer.concat([decipher.update(decoded.ciphertext), decipher.final()])
  } catch {
    // Authentication failures expose neither OpenSSL details nor candidate plaintext.
    throw new DisclosureCryptoError('authentication-failed')
  }
  const text = bytes.toString('utf8')
  requireCrypto(Buffer.from(text, 'utf8').equals(bytes), 'invalid-semantic-event')
  const event = semantic(parseJson(text, 'invalid-semantic-event'))
  requireCrypto(event.type === captured.eventType, 'invalid-metadata')
  return event
}
