/** Bounded plaintext projection for one already authorized confirmed disclosure prefix. */
import { KeyObject } from 'node:crypto'
import {
  decryptDisclosurePayload,
  type DisclosureCryptoLimits,
  type DisclosureDataKey,
  type DisclosureDataKeyGrantScope,
} from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import type { RegistryConfirmedPrefix } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryDisclosureContent, RegistryDisclosureContentEvent } from './operations.ts'

/** Complete limits applied before keys or plaintext are admitted. */
export interface RegistryDisclosureContentProjectionLimits extends DisclosureCryptoLimits {
  readonly maxEvents: number
}

/** Resolve only the historical keys retained for one exact disclosure grant scope. */
export type RegistryDisclosureDataKeyResolver = (
  scope: DisclosureDataKeyGrantScope,
  maxKeys: number,
  signal: AbortSignal,
) => Promise<readonly DisclosureDataKey[]>

/** Payload-free failure category safe to cross the browser operation boundary. */
export class RegistryDisclosureContentProjectionError extends Error {
  constructor(readonly code: 'limit' | 'unavailable') {
    super(`Registry disclosure content projection: ${code}`)
    this.name = 'RegistryDisclosureContentProjectionError'
  }
}

function fail(code: RegistryDisclosureContentProjectionError['code']): never {
  throw new RegistryDisclosureContentProjectionError(code)
}

function positive(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0
}

function browserText(value: string): string {
  if (!value.isWellFormed() || value.includes('\0')) fail('unavailable')
  return value
}

function projectEvent(event: ReturnType<typeof decryptDisclosurePayload>, disclosureSeq: number,
  occurredAt: number): RegistryDisclosureContentEvent {
  switch (event.type) {
    case 'conversation.user-message':
    case 'conversation.assistant-message':
      return { disclosureSeq, occurredAt, type: event.type, text: browserText(event.text) }
    case 'conversation.tool-result-summary':
      return { disclosureSeq, occurredAt, type: event.type, toolName: browserText(event.toolName),
        outcome: event.outcome, text: browserText(event.text) }
    case 'conversation.title':
      return { disclosureSeq, occurredAt, type: event.type, title: browserText(event.title) }
  }
}

function validateKeys(keys: readonly DisclosureDataKey[], scope: DisclosureDataKeyGrantScope,
  maximum: number): void {
  if (keys.length === 0 || keys.length > maximum) fail('unavailable')
  const selectors = new Set<string>()
  for (const key of keys) {
    if (typeof key?.keyId !== 'string' || selectors.has(key.keyId)
      || key.scope?.organizationId !== scope.organizationId
      || key.scope.instanceId !== scope.instanceId
      || key.scope.conversationId !== scope.conversationId
      || !(key.key instanceof KeyObject) || key.key.type !== 'secret' || key.key.symmetricKeySize !== 32) {
      fail('unavailable')
    }
    selectors.add(key.keyId)
  }
}

/**
 * Resolve keys for, decrypt, and minimally project one fixed reader-authorized prefix.
 * Authorization and source-signature verification remain owned by the caller that produced `prefix`.
 * No plaintext or key is cached, logged, synthesized, skipped, or returned before the complete result passes its bound.
 */
export async function projectRegistryDisclosureContent(resolveDataKeys: RegistryDisclosureDataKeyResolver,
  prefix: RegistryConfirmedPrefix, limits: RegistryDisclosureContentProjectionLimits,
  maxResponseBytes: number, signal: AbortSignal): Promise<RegistryDisclosureContent> {
  signal.throwIfAborted()
  if (!positive(limits.maxEvents) || !positive(limits.maxPlaintextBytes)
    || !positive(limits.maxCiphertextBytes) || !positive(limits.maxTrustedKeys)
    || !positive(maxResponseBytes)) fail('limit')

  const checkpoint = prefix.checkpoint
  if (!Array.isArray(prefix.events) || prefix.events.length > limits.maxEvents
    || prefix.events.length !== checkpoint.eventCount
    || checkpoint.lastDisclosureSeq !== prefix.events.length - 1) fail('limit')

  const scope: DisclosureDataKeyGrantScope = Object.freeze({
    organizationId: checkpoint.organizationId,
    instanceId: checkpoint.instanceId,
    conversationId: prefix.conversationId,
    disclosureId: checkpoint.disclosureId,
  })
  let keys: readonly DisclosureDataKey[]
  try {
    keys = await resolveDataKeys(scope, limits.maxTrustedKeys, signal)
  } catch {
    signal.throwIfAborted()
    return fail('unavailable')
  }
  signal.throwIfAborted()
  validateKeys(keys, scope, limits.maxTrustedKeys)
  const cryptoLimits: DisclosureCryptoLimits = {
    maxPlaintextBytes: limits.maxPlaintextBytes,
    maxCiphertextBytes: limits.maxCiphertextBytes,
    maxTrustedKeys: limits.maxTrustedKeys,
  }

  const events: RegistryDisclosureContentEvent[] = []
  let responseBytes = Buffer.byteLength(JSON.stringify({
    checkpointHash: checkpoint.checkpointHash,
    events,
  }), 'utf8')
  if (responseBytes > maxResponseBytes) fail('limit')
  for (const [index, envelope] of prefix.events.entries()) {
    if (envelope.disclosureSeq !== index || envelope.organizationId !== checkpoint.organizationId
      || envelope.instanceId !== checkpoint.instanceId || envelope.conversationId !== prefix.conversationId
      || envelope.disclosureId !== checkpoint.disclosureId || envelope.policyVersion !== checkpoint.policyVersion) {
      fail('unavailable')
    }
    let projected: RegistryDisclosureContentEvent
    try {
      const event = decryptDisclosurePayload(envelope.ciphertext, {
        organizationId: envelope.organizationId,
        instanceId: envelope.instanceId,
        conversationId: envelope.conversationId,
        disclosureId: envelope.disclosureId,
        eventId: envelope.eventId,
        eventType: envelope.eventType,
        policyVersion: envelope.policyVersion,
      }, keys, cryptoLimits)
      projected = projectEvent(event, envelope.disclosureSeq, envelope.occurredAt)
    } catch { return fail('unavailable') }
    responseBytes += (events.length === 0 ? 0 : 1)
      + Buffer.byteLength(JSON.stringify(projected), 'utf8')
    if (responseBytes > maxResponseBytes) fail('limit')
    events.push(projected)
  }

  signal.throwIfAborted()
  const value: RegistryDisclosureContent = { checkpointHash: checkpoint.checkpointHash, events }
  // The incremental accounting is exact for this fixed object shape. Keep a
  // final equality check so future projection fields cannot silently weaken it.
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') !== responseBytes) fail('limit')
  return value
}
