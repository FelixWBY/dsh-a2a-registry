/** Test-only Registry data-key escrow and bounded plaintext projection for confirmed disclosure prefixes. */
import { timingSafeEqual } from 'node:crypto'
import {
  decodeDisclosureDataKeyGrant,
  decryptDisclosurePayload,
  disclosureDataKeyCredential,
  encodeDisclosureDataKeyGrant,
  unwrapDisclosureDataKey,
  type DisclosureCryptoLimits,
  type DisclosureDataKey,
  type DisclosureDataKeyGrantScope,
  type DisclosureDataKeyId,
  type DisclosureDataKeyWrapContext,
  type WrappedDisclosureDataKey,
} from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import type { RegistryConfirmedPrefix } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import type { RegistryDisclosureContent, RegistryDisclosureContentEvent } from './operations.ts'

/** Payload-free failure category used by the signed escrow adapter. */
export class LocalHarnessDisclosureContentError extends Error {
  constructor(readonly code: 'conflict' | 'unavailable' | 'limit') {
    super(`Registry local disclosure content: ${code}`)
    this.name = 'LocalHarnessDisclosureContentError'
  }
}

/** Exact signed request body after transport parsing. */
export interface LocalHarnessDisclosureKeyEscrowInput extends DisclosureDataKeyWrapContext {
  readonly wrappedKey: WrappedDisclosureDataKey
}

function fail(code: LocalHarnessDisclosureContentError['code']): never {
  throw new LocalHarnessDisclosureContentError(code)
}

function scopeOf(input: {
  readonly organizationId: DisclosureDataKeyGrantScope['organizationId']
  readonly sourceInstanceId: DisclosureDataKeyGrantScope['instanceId']
  readonly conversationId: DisclosureDataKeyGrantScope['conversationId']
  readonly disclosureId: DisclosureDataKeyGrantScope['disclosureId']
}): DisclosureDataKeyGrantScope {
  return { organizationId: input.organizationId, instanceId: input.sourceInstanceId,
    conversationId: input.conversationId, disclosureId: input.disclosureId }
}

function sameKey(left: DisclosureDataKey, right: DisclosureDataKey): boolean {
  if (left.keyId !== right.keyId) return false
  const leftMaterial = left.key.export()
  const rightMaterial = right.key.export()
  const leftBytes = Buffer.isBuffer(leftMaterial) ? leftMaterial : Buffer.from(leftMaterial)
  const rightBytes = Buffer.isBuffer(rightMaterial) ? rightMaterial : Buffer.from(rightMaterial)
  try { return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes) }
  finally { leftBytes.fill(0); rightBytes.fill(0) }
}

function onlyKey(input: unknown, scope: DisclosureDataKeyGrantScope): DisclosureDataKey {
  let keys: readonly DisclosureDataKey[]
  try { keys = decodeDisclosureDataKeyGrant(input, scope, 1) } catch { return fail('conflict') }
  const key = keys[0]
  if (key === undefined || keys.length !== 1) fail('conflict')
  return key
}

/**
 * Unwrap and durably retain one disclosure-specific key in Registry Credentials.
 * A semantic retry with the same scope, selector and key material is a no-op; every other retained value conflicts.
 * @param credentials - Registry-owned writable Credentials provider.
 * @param secret - Current shared loopback secret already used to authenticate the request.
 * @param input - Exact signed transfer coordinates and wrapped key.
 */
export async function escrowRegistryDisclosureDataKey(credentials: CredentialProvider, secret: string,
  input: LocalHarnessDisclosureKeyEscrowInput, maxKeys: number): Promise<void> {
  const context: DisclosureDataKeyWrapContext = {
    version: input.version,
    organizationId: input.organizationId,
    sourceInstanceId: input.sourceInstanceId,
    conversationId: input.conversationId,
    disclosureId: input.disclosureId,
    keyId: input.keyId,
  }
  let candidate: DisclosureDataKey
  try { candidate = unwrapDisclosureDataKey(input.wrappedKey, context, secret) } catch { return fail('unavailable') }
  const scope = scopeOf(input)
  const grant = encodeDisclosureDataKeyGrant('registry-app', scope, [candidate])
  if (!Number.isSafeInteger(maxKeys) || maxKeys <= 0) fail('limit')
  let entries: Awaited<ReturnType<CredentialProvider['listRecords']>>
  try { entries = await credentials.listRecords() } catch { return fail('unavailable') }
  const owned = entries.filter(entry => entry.key.startsWith('registry-app/a2a-disclosure-key-'))
  if (!owned.some(entry => entry.key === grant.key) && owned.length >= maxKeys) fail('limit')
  let retained: Awaited<ReturnType<CredentialProvider['modifyRecord']>>
  try {
    retained = await credentials.modifyRecord(grant.key, (current) => {
      if (current === undefined) return Promise.resolve(grant.record)
      if (!sameKey(onlyKey(current, scope), candidate)) fail('conflict')
      return Promise.resolve(undefined)
    })
  } catch (error) {
    if (error instanceof LocalHarnessDisclosureContentError) throw error
    return fail('unavailable')
  }
  if (retained === undefined || !sameKey(onlyKey(retained, scope), candidate)) fail('unavailable')
}

/**
 * Require the exact Registry-owned disclosure key before admitting its disclosure registration.
 * @param credentials - Registry-owned Credentials provider.
 * @param scope - Exact disclosure-specific grant scope.
 * @param keyId - Data-key selector committed by the registration request.
 */
export async function requireRegistryDisclosureDataKey(credentials: CredentialProvider,
  scope: DisclosureDataKeyGrantScope, keyId: DisclosureDataKeyId): Promise<void> {
  let record: Awaited<ReturnType<CredentialProvider['readRecord']>>
  try { record = await credentials.readRecord(disclosureDataKeyCredential('registry-app', scope)) } catch {
    return fail('unavailable')
  }
  if (record === undefined) fail('conflict')
  const key = onlyKey(record, scope)
  if (key.keyId !== keyId) fail('conflict')
}

function projectEvent(event: ReturnType<typeof decryptDisclosurePayload>, disclosureSeq: number,
  occurredAt: number): RegistryDisclosureContentEvent {
  switch (event.type) {
    case 'conversation.user-message':
    case 'conversation.assistant-message':
      return { disclosureSeq, occurredAt, type: event.type, text: event.text }
    case 'conversation.tool-result-summary':
      return { disclosureSeq, occurredAt, type: event.type, toolName: event.toolName,
        outcome: event.outcome, text: event.text }
    case 'conversation.title':
      return { disclosureSeq, occurredAt, type: event.type, title: event.title }
  }
}

/**
 * Resolve the Registry-owned key afresh and decrypt one verified confirmed prefix only in memory.
 * @param credentials - Registry-owned Credentials provider.
 * @param prefix - Reader-verified fixed checkpoint and its complete encrypted prefix.
 * @param limits - Explicit event crypto and key-count ceilings.
 * @param maxEvents - Maximum events admitted from one confirmed prefix.
 * @param maxResponseBytes - Maximum serialized plaintext projection bytes.
 * @param signal - Browser request lifetime.
 * @returns Minimal user-visible event projection with no envelope or identity fields.
 */
export async function readRegistryDisclosureContent(credentials: CredentialProvider,
  prefix: RegistryConfirmedPrefix, limits: DisclosureCryptoLimits, maxEvents: number,
  maxResponseBytes: number, signal: AbortSignal): Promise<RegistryDisclosureContent> {
  signal.throwIfAborted()
  const checkpoint = prefix.checkpoint
  if (!Number.isSafeInteger(maxEvents) || maxEvents <= 0 || prefix.events.length > maxEvents
    || prefix.events.length !== checkpoint.eventCount
    || checkpoint.lastDisclosureSeq !== prefix.events.length - 1) fail('limit')
  const scope: DisclosureDataKeyGrantScope = {
    organizationId: checkpoint.organizationId,
    instanceId: checkpoint.instanceId,
    conversationId: prefix.conversationId,
    disclosureId: checkpoint.disclosureId,
  }
  let record: Awaited<ReturnType<CredentialProvider['readRecord']>>
  try { record = await credentials.readRecord(disclosureDataKeyCredential('registry-app', scope)) } catch {
    return fail('unavailable')
  }
  if (record === undefined) fail('unavailable')
  let keys: readonly DisclosureDataKey[]
  try { keys = decodeDisclosureDataKeyGrant(record, scope, limits.maxTrustedKeys) } catch { return fail('unavailable') }
  const events = prefix.events.map((envelope, index): RegistryDisclosureContentEvent => {
    if (envelope.disclosureSeq !== index || envelope.organizationId !== checkpoint.organizationId
      || envelope.instanceId !== checkpoint.instanceId || envelope.conversationId !== prefix.conversationId
      || envelope.disclosureId !== checkpoint.disclosureId || envelope.policyVersion !== checkpoint.policyVersion) {
      fail('unavailable')
    }
    let event: ReturnType<typeof decryptDisclosurePayload>
    try {
      event = decryptDisclosurePayload(envelope.ciphertext, {
        organizationId: envelope.organizationId,
        instanceId: envelope.instanceId,
        conversationId: envelope.conversationId,
        disclosureId: envelope.disclosureId,
        eventId: envelope.eventId,
        eventType: envelope.eventType,
        policyVersion: envelope.policyVersion,
      }, keys, limits)
    } catch { return fail('unavailable') }
    return projectEvent(event, envelope.disclosureSeq, envelope.occurredAt)
  })
  signal.throwIfAborted()
  const value: RegistryDisclosureContent = { checkpointHash: checkpoint.checkpointHash, events }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0
    || Buffer.byteLength(JSON.stringify(value), 'utf8') > maxResponseBytes) fail('limit')
  return value
}
