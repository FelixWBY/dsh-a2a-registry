/** Bounded strict JSON frames; connection ordering, authentication and durability remain consumer-owned. */
import { brandString } from '@deepseek-ai/dsh-brand'
import { decodeDisclosureCheckpoint, decodeDisclosureEventEnvelope, type DisclosureConversationId,
  type DisclosureHash, type DisclosureId } from '@deepseek-ai/dsh-a2a-protocol'
import { decodeRegistryChallenge, decodeRegistryConnectionIdentity, decodeRegistryProof } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import { DISCLOSURE_CONTROL_STATES, REGISTRY_INGEST_STATES, type MemberId,
  type TeamId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { RegistryCheckpointReceipt, RegistryConfirmedPrefix, RegistryIngestReceipt,
  RegistryProducerSyncStatus } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { MailboxBinding, MailboxReceipt, MailboxTransition } from '@deepseek-ai/dsh-a2a-mailbox'
import type { RegistryClientFrame, RegistryImportDelivery, RegistryImportKeyGrant, RegistryImportOutcome, RegistryInstanceReport,
  RegistryProducerAccessUpdate, RegistryProducerRegistration, RegistryProducerTarget, RegistryQuestionDelivery,
  RegistryServerFrame, RegistrySyncErrorCode } from './types.ts'

export type * from './types.ts'

/** Exact upgrade path shared by both transport consumers. */
export const REGISTRY_SYNC_PATH = '/a2a/v1/sync'
/** The outer frame version; signed disclosure records keep their independent existing decoder. */
export const REGISTRY_SYNC_PROTOCOL_VERSION = 1 as const

const errors: readonly RegistrySyncErrorCode[] = ['not-found', 'invalid-input', 'conflict', 'gap', 'frozen', 'limit',
  'version-conflict', 'invalid-transition', 'storage-unavailable', 'invalid-storage', 'closed', 'unauthorized', 'protocol', 'busy']
const receiptKeys = ['disclosureId', 'lastDisclosureSeq', 'lastEventHash', 'checkpointHash', 'authorizationVersion', 'control', 'ingest']

/** Frame parsing failures carry no input, token, payload or nested parser diagnostics. */
export class RegistrySyncProtocolError extends Error {
  /** Construct the single content-free codec diagnostic. */
  constructor() { super('invalid Registry synchronization frame'); this.name = 'RegistrySyncProtocolError' }
}

function requireFrame(condition: boolean): asserts condition {
  if (!condition) throw new RegistrySyncProtocolError()
}

function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  requireFrame(typeof input === 'object' && input !== null && !Array.isArray(input))
  const value = input as Record<string, unknown>
  requireFrame(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)))
  return value
}

function integer(input: unknown, minimum: number): number {
  requireFrame(Number.isSafeInteger(input) && (input as number) >= minimum && !Object.is(input, -0))
  return input as number
}

function opaqueIdentifier(input: unknown): string {
  requireFrame(typeof input === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/.test(input))
  return input
}

function identifier(input: unknown): DisclosureId {
  return brandString<DisclosureId>(opaqueIdentifier(input))
}

function hash(input: unknown): DisclosureHash {
  requireFrame(typeof input === 'string' && /^sha256:[0-9a-f]{64}$/.test(input))
  return brandString<DisclosureHash>(input)
}

function nullableHash(input: unknown): DisclosureHash | null { return input === null ? null : hash(input) }

function receipt(input: unknown, checkpoint: true): RegistryCheckpointReceipt
function receipt(input: unknown, checkpoint: false): RegistryIngestReceipt
function receipt(input: unknown, checkpoint: boolean): RegistryIngestReceipt | RegistryCheckpointReceipt {
  const value = exact(input, checkpoint ? [...receiptKeys, 'acceptedCheckpointHash'] : receiptKeys)
  const control = value.control as RegistryIngestReceipt['control']
  const ingest = value.ingest as RegistryIngestReceipt['ingest']
  requireFrame(DISCLOSURE_CONTROL_STATES.includes(control) && control !== 'deleted' && REGISTRY_INGEST_STATES.includes(ingest))
  const lastDisclosureSeq = integer(value.lastDisclosureSeq, -1)
  const lastEventHash = nullableHash(value.lastEventHash)
  const checkpointHash = nullableHash(value.checkpointHash)
  requireFrame((lastDisclosureSeq === -1) === (lastEventHash === null))
  requireFrame((ingest !== 'pending' || checkpointHash === null) && (ingest !== 'ready' || checkpointHash !== null))
  const result: RegistryIngestReceipt = { disclosureId: identifier(value.disclosureId), lastDisclosureSeq, lastEventHash,
    checkpointHash, authorizationVersion: integer(value.authorizationVersion, 0), control, ingest }
  return checkpoint ? { ...result, acceptedCheckpointHash: hash(value.acceptedCheckpointHash) } : result
}

function status(input: unknown): RegistryProducerSyncStatus {
  requireFrame(typeof input === 'object' && input !== null && !Array.isArray(input))
  const kind = (input as Record<string, unknown>).kind
  if (kind === 'deleted') {
    const value = exact(input, ['kind', 'disclosureId', 'authorizationVersion'])
    return { kind, disclosureId: identifier(value.disclosureId), authorizationVersion: integer(value.authorizationVersion, 0) }
  }
  requireFrame(kind === 'live')
  const value = exact(input, ['kind', 'observedAt', 'expiresAt', 'receipt'])
  return { kind, observedAt: integer(value.observedAt, 0), expiresAt: integer(value.expiresAt, 0), receipt: receipt(value.receipt, false) }
}

function base(input: unknown): { value: Record<string, unknown>; requestId: number } {
  requireFrame(typeof input === 'object' && input !== null && !Array.isArray(input))
  const value = input as Record<string, unknown>
  requireFrame(value.protocolVersion === REGISTRY_SYNC_PROTOCOL_VERSION)
  return { value, requestId: integer(value.requestId, 1) }
}

function instanceReport(input: unknown): RegistryInstanceReport {
  const value = exact(input, ['state', 'acceptingA2A', 'activeRequests'])
  const state = value.state as RegistryInstanceReport['state']
  requireFrame(['online', 'busy', 'paused', 'degraded'].includes(state) && typeof value.acceptingA2A === 'boolean')
  return { state, acceptingA2A: value.acceptingA2A, activeRequests: integer(value.activeRequests, 0) }
}

function producerTarget(input: unknown): RegistryProducerTarget {
  requireFrame(typeof input === 'object' && input !== null && !Array.isArray(input))
  const kind = (input as Record<string, unknown>).kind
  if (kind === 'member') {
    const value = exact(input, ['kind', 'memberId'])
    return { kind, memberId: brandString<MemberId>(opaqueIdentifier(value.memberId)) }
  }
  requireFrame(kind === 'team')
  const value = exact(input, ['kind', 'teamId'])
  return { kind, teamId: brandString<TeamId>(opaqueIdentifier(value.teamId)) }
}

function producerTargets(input: unknown): readonly RegistryProducerTarget[] {
  requireFrame(Array.isArray(input) && input.length > 0)
  const targets = input.map(producerTarget)
  const keys = targets.map(target => target.kind === 'member'
    ? `member:${target.memberId}` : `team:${target.teamId}`)
  requireFrame(new Set(keys).size === keys.length)
  return targets
}

function producerRegistration(input: unknown): RegistryProducerRegistration {
  const value = exact(input, ['conversationId', 'policyVersion', 'targets', 'expiresAt'])
  return {
    conversationId: brandString<DisclosureConversationId>(opaqueIdentifier(value.conversationId)),
    policyVersion: integer(value.policyVersion, 1),
    targets: producerTargets(value.targets),
    expiresAt: integer(value.expiresAt, 0),
  }
}

function producerAccessUpdate(input: unknown): RegistryProducerAccessUpdate {
  const value = exact(input, ['targets', 'expiresAt'])
  return { targets: producerTargets(value.targets), expiresAt: integer(value.expiresAt, 0) }
}

function mailboxBinding(input: unknown): MailboxBinding {
  const value = exact(input, ['requestId', 'organizationId', 'disclosureId', 'requesterId', 'checkpointHash',
    'authorizationVersion', 'expiresAt', 'instanceId'])
  return {
    requestId: brandString<MailboxBinding['requestId']>(opaqueIdentifier(value.requestId)),
    organizationId: brandString<MailboxBinding['organizationId']>(opaqueIdentifier(value.organizationId)),
    disclosureId: identifier(value.disclosureId),
    requesterId: brandString<MailboxBinding['requesterId']>(opaqueIdentifier(value.requesterId)),
    checkpointHash: hash(value.checkpointHash),
    authorizationVersion: integer(value.authorizationVersion, 0),
    expiresAt: integer(value.expiresAt, 0),
    instanceId: brandString<MailboxBinding['instanceId']>(opaqueIdentifier(value.instanceId)),
  }
}

function sameMailboxBinding(left: MailboxBinding, right: MailboxBinding): boolean {
  return left.requestId === right.requestId && left.organizationId === right.organizationId
    && left.disclosureId === right.disclosureId && left.requesterId === right.requesterId
    && left.checkpointHash === right.checkpointHash && left.authorizationVersion === right.authorizationVersion
    && left.expiresAt === right.expiresAt && left.instanceId === right.instanceId
}

function mailboxReceipt(input: unknown): MailboxReceipt {
  const value = exact(input, ['binding', 'state', 'version', 'authorizationVersion', 'questionHash', 'replyHash', 'updatedAt'])
  const state = value.state as MailboxReceipt['state']
  requireFrame(['created', 'queued', 'delivered', 'running', 'completed', 'failed', 'cancelled', 'expired'].includes(state))
  return {
    binding: mailboxBinding(value.binding), state, version: integer(value.version, 1),
    authorizationVersion: integer(value.authorizationVersion, 0), questionHash: hash(value.questionHash),
    replyHash: nullableHash(value.replyHash), updatedAt: integer(value.updatedAt, 0),
  }
}

function mailboxTransition(input: unknown): MailboxTransition {
  requireFrame(typeof input === 'object' && input !== null && !Array.isArray(input))
  const state = (input as Record<string, unknown>).state
  if (state === 'completed') {
    const value = exact(input, ['state', 'reply'])
    requireFrame(typeof value.reply === 'string' && value.reply.isWellFormed() && !value.reply.includes('\0'))
    return { state, reply: value.reply }
  }
  requireFrame(state === 'failed' || state === 'cancelled' || state === 'running')
  exact(input, ['state'])
  return { state }
}

function confirmedPrefix(input: unknown): RegistryConfirmedPrefix {
  const value = exact(input, ['authorizationVersion', 'conversationId', 'checkpoint', 'events'])
  const checkpoint = decodeDisclosureCheckpoint(value.checkpoint)
  requireFrame(Array.isArray(value.events))
  const events = value.events.map(decodeDisclosureEventEnvelope)
  const conversationId = brandString<RegistryConfirmedPrefix['conversationId']>(opaqueIdentifier(value.conversationId))
  requireFrame(events.length === checkpoint.eventCount
    && events.every((event, index) => event.organizationId === checkpoint.organizationId
      && event.instanceId === checkpoint.instanceId && event.disclosureId === checkpoint.disclosureId
      && event.conversationId === conversationId && event.disclosureSeq === index)
    && (events.at(-1)?.eventHash ?? null) === checkpoint.lastEventHash)
  return { authorizationVersion: integer(value.authorizationVersion, 0), conversationId, checkpoint, events }
}

function canonicalKeyMaterial(input: unknown): string {
  requireFrame(typeof input === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(input))
  const bytes = Buffer.from(input, 'base64url')
  try { requireFrame(bytes.byteLength === 32 && bytes.toString('base64url') === input) }
  finally { bytes.fill(0) }
  return input
}

/** Validate and detach one bounded raw-key grant for an already authorized exact scope. */
export function decodeRegistryImportKeyGrant(input: unknown, expectedScope: RegistryImportKeyGrant['scope'],
  maxKeys: number, maxBytes: number): RegistryImportKeyGrant {
  integer(maxKeys, 1)
  integer(maxBytes, 1)
  let serialized: string
  try {
    const candidate = JSON.stringify(input)
    requireFrame(typeof candidate === 'string')
    serialized = candidate
  } catch { throw new RegistrySyncProtocolError() }
  bounded(serialized, maxBytes)
  let detached: unknown
  try { detached = JSON.parse(serialized) as unknown } catch { throw new RegistrySyncProtocolError() }
  const value = exact(detached, ['version', 'scope', 'keys'])
  requireFrame(value.version === 1)
  const selectedScope = exact(value.scope, ['organizationId', 'instanceId', 'conversationId', 'disclosureId'])
  const scope: RegistryImportKeyGrant['scope'] = {
    organizationId: brandString<RegistryImportKeyGrant['scope']['organizationId']>(
      opaqueIdentifier(selectedScope.organizationId)),
    instanceId: brandString<RegistryImportKeyGrant['scope']['instanceId']>(opaqueIdentifier(selectedScope.instanceId)),
    conversationId: brandString<RegistryImportKeyGrant['scope']['conversationId']>(
      opaqueIdentifier(selectedScope.conversationId)),
    disclosureId: identifier(selectedScope.disclosureId),
  }
  requireFrame(scope.organizationId === expectedScope.organizationId
    && scope.instanceId === expectedScope.instanceId
    && scope.conversationId === expectedScope.conversationId
    && scope.disclosureId === expectedScope.disclosureId
    && Array.isArray(value.keys) && value.keys.length > 0 && value.keys.length <= maxKeys)
  const seen = new Set<string>()
  const keys = value.keys.map((inputKey): RegistryImportKeyGrant['keys'][number] => {
    const selectedKey = exact(inputKey, ['keyId', 'material'])
    const keyId = opaqueIdentifier(selectedKey.keyId)
    requireFrame(!seen.has(keyId))
    seen.add(keyId)
    return { keyId, material: canonicalKeyMaterial(selectedKey.material) }
  })
  return { version: 1, scope, keys }
}

function displayText(input: unknown): string {
  requireFrame(typeof input === 'string' && input.length > 0 && input.isWellFormed() && !input.includes('\0'))
  return input
}

function questionDelivery(input: unknown): RegistryQuestionDelivery {
  const value = exact(input, ['binding', 'receipt', 'question', 'prefix', 'source'])
  const binding = mailboxBinding(value.binding)
  const selectedReceipt = mailboxReceipt(value.receipt)
  const prefix = confirmedPrefix(value.prefix)
  const source = exact(value.source, ['instanceName', 'conversationTitle'])
  requireFrame(sameMailboxBinding(binding, selectedReceipt.binding)
    && typeof value.question === 'string' && value.question.isWellFormed() && !value.question.includes('\0')
    && prefix.authorizationVersion === selectedReceipt.authorizationVersion
    && prefix.checkpoint.organizationId === binding.organizationId
    && prefix.checkpoint.instanceId === binding.instanceId
    && prefix.checkpoint.disclosureId === binding.disclosureId
    && prefix.checkpoint.checkpointHash === binding.checkpointHash)
  return { binding, receipt: selectedReceipt, question: value.question, prefix,
    source: { instanceName: displayText(source.instanceName), conversationTitle: displayText(source.conversationTitle) } }
}

function importDelivery(input: unknown): RegistryImportDelivery {
  const value = exact(input, ['operationId', 'targetInstanceId', 'organizationId', 'disclosureId',
    'sourceInstanceId', 'checkpointHash', 'prefix', 'keyGrant', 'source'])
  const prefix = confirmedPrefix(value.prefix)
  const keyGrant = decodeRegistryImportKeyGrant(value.keyGrant, {
    organizationId: prefix.checkpoint.organizationId,
    instanceId: prefix.checkpoint.instanceId,
    conversationId: prefix.conversationId,
    disclosureId: prefix.checkpoint.disclosureId,
  }, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)
  const source = exact(value.source, ['instanceName', 'conversationTitle'])
  const operationId = opaqueIdentifier(value.operationId)
  const targetInstanceId = brandString<RegistryImportDelivery['targetInstanceId']>(opaqueIdentifier(value.targetInstanceId))
  const organizationId = brandString<RegistryImportDelivery['organizationId']>(opaqueIdentifier(value.organizationId))
  const disclosureId = identifier(value.disclosureId)
  const sourceInstanceId = brandString<RegistryImportDelivery['sourceInstanceId']>(opaqueIdentifier(value.sourceInstanceId))
  const checkpointHash = hash(value.checkpointHash)
  requireFrame(prefix.checkpoint.organizationId === organizationId
    && prefix.checkpoint.instanceId === sourceInstanceId
    && prefix.checkpoint.disclosureId === disclosureId
    && prefix.checkpoint.checkpointHash === checkpointHash)
  return { operationId, targetInstanceId, organizationId, disclosureId, sourceInstanceId, checkpointHash, prefix, keyGrant,
    source: { instanceName: displayText(source.instanceName), conversationTitle: displayText(source.conversationTitle) } }
}

function importOutcome(input: unknown): RegistryImportOutcome {
  requireFrame(typeof input === 'object' && input !== null && !Array.isArray(input))
  const status = (input as Record<string, unknown>).status
  if (status === 'retry') {
    exact(input, ['status'])
    return { status }
  }
  requireFrame(status === 'completed')
  const value = exact(input, ['status', 'sessionId'])
  return { status, sessionId: opaqueIdentifier(value.sessionId) }
}

function excludedRequestIds(input: unknown): readonly MailboxBinding['requestId'][] {
  requireFrame(Array.isArray(input))
  const ids = input.map(value => brandString<MailboxBinding['requestId']>(opaqueIdentifier(value)))
  requireFrame(new Set(ids).size === ids.length)
  return ids
}

function client(input: unknown): RegistryClientFrame {
  const { value, requestId } = base(input)
  const header = { protocolVersion: REGISTRY_SYNC_PROTOCOL_VERSION, requestId }
  switch (value.type) {
    case 'hello': {
      exact(value, ['protocolVersion', 'requestId', 'type', 'token'])
      requireFrame(typeof value.token === 'string' && value.token.length > 0 && value.token.isWellFormed())
      return { ...header, type: value.type, token: value.token }
    }
    case 'prove':
      exact(value, ['protocolVersion', 'requestId', 'type', 'signature'])
      return { ...header, type: value.type, signature: decodeRegistryProof(value.signature) }
    case 'status':
      exact(value, ['protocolVersion', 'requestId', 'type', 'disclosureId'])
      return { ...header, type: value.type, disclosureId: identifier(value.disclosureId) }
    case 'producer-register':
      exact(value, ['protocolVersion', 'requestId', 'type', 'disclosureId', 'registration'])
      return { ...header, type: value.type, disclosureId: identifier(value.disclosureId),
        registration: producerRegistration(value.registration) }
    case 'producer-update-access':
      exact(value, ['protocolVersion', 'requestId', 'type', 'disclosureId', 'expectedAuthorizationVersion', 'update'])
      return { ...header, type: value.type, disclosureId: identifier(value.disclosureId),
        expectedAuthorizationVersion: integer(value.expectedAuthorizationVersion, 0),
        update: producerAccessUpdate(value.update) }
    case 'producer-transition-control': {
      exact(value, ['protocolVersion', 'requestId', 'type', 'disclosureId', 'expectedAuthorizationVersion', 'target'])
      const target = value.target as 'active' | 'paused' | 'revoked'
      requireFrame(target === 'active' || target === 'paused' || target === 'revoked')
      return { ...header, type: value.type, disclosureId: identifier(value.disclosureId),
        expectedAuthorizationVersion: integer(value.expectedAuthorizationVersion, 0), target }
    }
    case 'producer-delete':
      exact(value, ['protocolVersion', 'requestId', 'type', 'disclosureId', 'expectedAuthorizationVersion'])
      return { ...header, type: value.type, disclosureId: identifier(value.disclosureId),
        expectedAuthorizationVersion: integer(value.expectedAuthorizationVersion, 0) }
    case 'event': {
      exact(value, ['protocolVersion', 'requestId', 'type', 'disclosureId', 'envelope'])
      const disclosureId = identifier(value.disclosureId)
      const envelope = decodeDisclosureEventEnvelope(value.envelope)
      requireFrame(envelope.disclosureId === disclosureId)
      return { ...header, type: value.type, disclosureId, envelope }
    }
    case 'checkpoint': {
      exact(value, ['protocolVersion', 'requestId', 'type', 'disclosureId', 'checkpoint'])
      const disclosureId = identifier(value.disclosureId)
      const checkpoint = decodeDisclosureCheckpoint(value.checkpoint)
      requireFrame(checkpoint.disclosureId === disclosureId)
      return { ...header, type: value.type, disclosureId, checkpoint }
    }
    case 'heartbeat': {
      const reports = Object.hasOwn(value, 'report')
      exact(value, reports ? ['protocolVersion', 'requestId', 'type', 'report'] : ['protocolVersion', 'requestId', 'type'])
      return { ...header, type: value.type, ...(reports ? { report: instanceReport(value.report) } : {}) }
    }
    case 'question-dispatch': {
      const excludes = Object.hasOwn(value, 'excludeRequestIds')
      exact(value, excludes
        ? ['protocolVersion', 'requestId', 'type', 'excludeRequestIds']
        : ['protocolVersion', 'requestId', 'type'])
      return { ...header, type: value.type,
        ...(excludes ? { excludeRequestIds: excludedRequestIds(value.excludeRequestIds) } : {}) }
    }
    case 'question-start':
    case 'question-renew':
    case 'question-authorize':
      exact(value, ['protocolVersion', 'requestId', 'type', 'binding', 'expectedVersion'])
      return { ...header, type: value.type, binding: mailboxBinding(value.binding),
        expectedVersion: integer(value.expectedVersion, 1) }
    case 'question-status':
      exact(value, ['protocolVersion', 'requestId', 'type', 'binding'])
      return { ...header, type: value.type, binding: mailboxBinding(value.binding) }
    case 'question-transition':
      exact(value, ['protocolVersion', 'requestId', 'type', 'binding', 'expectedVersion', 'transition'])
      return { ...header, type: value.type, binding: mailboxBinding(value.binding),
        expectedVersion: integer(value.expectedVersion, 1), transition: mailboxTransition(value.transition) }
    case 'question-authorize-release':
      exact(value, ['protocolVersion', 'requestId', 'type', 'authorizationRequestId'])
      return { ...header, type: value.type, authorizationRequestId: integer(value.authorizationRequestId, 1) }
    case 'import-dispatch':
      exact(value, ['protocolVersion', 'requestId', 'type'])
      return { ...header, type: value.type }
    case 'import-release':
      exact(value, ['protocolVersion', 'requestId', 'type', 'authorizationRequestId', 'outcome'])
      return { ...header, type: value.type, authorizationRequestId: integer(value.authorizationRequestId, 1),
        outcome: importOutcome(value.outcome) }
    default: throw new RegistrySyncProtocolError()
  }
}

function server(input: unknown): RegistryServerFrame {
  const { value, requestId } = base(input)
  const header = { protocolVersion: REGISTRY_SYNC_PROTOCOL_VERSION, requestId }
  switch (value.type) {
    case 'challenge': {
      exact(value, ['protocolVersion', 'requestId', 'type', 'challenge'])
      const challenge = decodeRegistryChallenge(value.challenge)
      requireFrame(new URL(challenge.audience).pathname === REGISTRY_SYNC_PATH)
      return { ...header, type: value.type, challenge }
    }
    case 'authenticated':
      exact(value, ['protocolVersion', 'requestId', 'type', 'identity'])
      return { ...header, type: value.type, identity: decodeRegistryConnectionIdentity(value.identity) }
    case 'status':
      exact(value, ['protocolVersion', 'requestId', 'type', 'status'])
      return { ...header, type: value.type, status: status(value.status) }
    case 'producer-register-ack':
    case 'producer-update-access-ack':
    case 'producer-transition-control-ack':
    case 'producer-delete-ack':
      exact(value, ['protocolVersion', 'requestId', 'type', 'status'])
      return { ...header, type: value.type, status: status(value.status) }
    case 'event-ack': {
      exact(value, ['protocolVersion', 'requestId', 'type', 'receipt'])
      const result = receipt(value.receipt, false)
      requireFrame(result.control === 'active' && result.ingest !== 'frozen' && result.lastDisclosureSeq >= 0)
      return { ...header, type: value.type, receipt: result }
    }
    case 'checkpoint-ack': {
      exact(value, ['protocolVersion', 'requestId', 'type', 'receipt'])
      const result = receipt(value.receipt, true)
      requireFrame(result.control === 'active' && result.ingest === 'ready')
      return { ...header, type: value.type, receipt: result }
    }
    case 'heartbeat-ack':
      exact(value, ['protocolVersion', 'requestId', 'type', 'observedAt'])
      return { ...header, type: value.type, observedAt: integer(value.observedAt, 0) }
    case 'question-dispatch':
      exact(value, ['protocolVersion', 'requestId', 'type', 'delivery'])
      return { ...header, type: value.type,
        delivery: value.delivery === null ? null : questionDelivery(value.delivery) }
    case 'question-start': {
      exact(value, ['protocolVersion', 'requestId', 'type', 'receipt', 'started', 'renewAfterMs'])
      requireFrame(typeof value.started === 'boolean')
      return { ...header, type: value.type, receipt: mailboxReceipt(value.receipt), started: value.started,
        renewAfterMs: integer(value.renewAfterMs, 1) }
    }
    case 'question-renew':
      exact(value, ['protocolVersion', 'requestId', 'type', 'receipt', 'renewAfterMs'])
      return { ...header, type: value.type, receipt: mailboxReceipt(value.receipt),
        renewAfterMs: integer(value.renewAfterMs, 1) }
    case 'question-status':
    case 'question-transition':
      exact(value, ['protocolVersion', 'requestId', 'type', 'receipt'])
      return { ...header, type: value.type, receipt: mailboxReceipt(value.receipt) }
    case 'question-authorized':
      exact(value, ['protocolVersion', 'requestId', 'type', 'delivery'])
      return { ...header, type: value.type, delivery: questionDelivery(value.delivery) }
    case 'question-authorize-released':
    case 'import-released':
      exact(value, ['protocolVersion', 'requestId', 'type', 'authorizationRequestId'])
      return { ...header, type: value.type, authorizationRequestId: integer(value.authorizationRequestId, 1) }
    case 'import-dispatch':
      exact(value, ['protocolVersion', 'requestId', 'type', 'delivery'])
      return { ...header, type: value.type,
        delivery: value.delivery === null ? null : importDelivery(value.delivery) }
    case 'error':
      exact(value, ['protocolVersion', 'requestId', 'type', 'code'])
      requireFrame(errors.includes(value.code as RegistrySyncErrorCode))
      return { ...header, type: value.type, code: value.code as RegistrySyncErrorCode }
    default: throw new RegistrySyncProtocolError()
  }
}

function bounded(text: string, maxBytes: number): string {
  integer(maxBytes, 1)
  requireFrame(typeof text === 'string' && text.isWellFormed() && Buffer.byteLength(text, 'utf8') <= maxBytes)
  return text
}

function parse<T>(text: string, maxBytes: number, decode: (value: unknown) => T): T {
  try { return decode(JSON.parse(bounded(text, maxBytes))) } catch {
    // JSON, record and crypto decoder messages may include payload fields; only the codec category escapes.
    throw new RegistrySyncProtocolError()
  }
}

function encode<T>(value: T, maxBytes: number, decode: (input: unknown) => T): string {
  try { return bounded(JSON.stringify(decode(value)), maxBytes) } catch {
    // Runtime callers and nested record decoders share the same content-free failure.
    throw new RegistrySyncProtocolError()
  }
}

/** Decode one complete UTF-8 JSON request after applying the configured complete-frame byte bound.
 * @param text - Complete text frame; the WebSocket consumer must reject binary or invalid UTF-8 messages.
 * @param maxBytes - Trusted positive safe-integer frame limit, including wrappers and metadata.
 * @returns Detached validated request; no connection sequencing or authentication is performed. */
export function decodeRegistryClientFrame(text: string, maxBytes: number): RegistryClientFrame {
  return parse(text, maxBytes, client)
}

/** Decode one complete bounded response; consumers additionally match request, identity and connection generation.
 * @param text - Complete UTF-8 text frame.
 * @param maxBytes - Trusted complete-frame byte bound.
 * @returns Detached metadata or signed record acknowledgement, never proof that this peer is authenticated. */
export function decodeRegistryServerFrame(text: string, maxBytes: number): RegistryServerFrame {
  return parse(text, maxBytes, server)
}

/** Encode a validated request and reject an oversized complete JSON frame rather than truncating it.
 * @param frame - Exact version-one request.
 * @param maxBytes - Trusted complete-frame byte bound.
 * @returns Complete UTF-8 JSON text. */
export function encodeRegistryClientFrame(frame: RegistryClientFrame, maxBytes: number): string {
  return encode(frame, maxBytes, client)
}

/** Encode a validated response and reject an oversized complete JSON frame rather than truncating it.
 * @param frame - Exact version-one response.
 * @param maxBytes - Trusted complete-frame byte bound.
 * @returns Complete UTF-8 JSON text. */
export function encodeRegistryServerFrame(frame: RegistryServerFrame, maxBytes: number): string {
  return encode(frame, maxBytes, server)
}
