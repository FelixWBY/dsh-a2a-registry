/** Pure mutations of one verified disclosure aggregate; the storage owner supplies fresh authority. */
import type { DisclosureCheckpoint, DisclosureEventEnvelope } from '@deepseek-ai/dsh-a2a-protocol'
import type { InstanceVerificationContext } from '@deepseek-ai/dsh-a2a-device-identity'
import { transitionRegistryIngest } from '@deepseek-ai/dsh-a2a-registry-domain'
import { checkpointMatches, publishedCheckpoint, requireIngest, type AuditEntry, type IngestRecord, type VerifiedRecord } from './record.ts'
import type { RegistryIngestErrorCode, RegistryIngestLimits, RegistryIngestReceipt } from './types.ts'

/** Non-deleted aggregate narrowed after organization and source-instance selection. */
export type LiveRecord = Extract<IngestRecord, { kind: 'disclosure' }>
/** A frozen mutation commits before its conflict is returned to the producer. */
export interface Mutation {
  readonly record: IngestRecord
  readonly error?: RegistryIngestErrorCode
  readonly safetyStop?: boolean
}

/** Retain a bounded metadata audit window without copying user-controlled content.
 * @param record - Current aggregate.
 * @param action - Committed operation category.
 * @param now - Trusted receive time.
 * @param limits - Recent-history bound.
 * @returns Detached aggregate with bounded audit metadata. */
export function audit(record: LiveRecord, action: AuditEntry['action'], now: number, limits: RegistryIngestLimits): LiveRecord {
  const entry = { action, at: now, authorizationVersion: record.access.authorizationVersion }
  return { ...record, audit: [...record.audit, entry].slice(-limits.maxAuditEntries) }
}

function freeze(record: LiveRecord, now: number, limits: RegistryIngestLimits): Mutation {
  return {
    record: audit({ ...record, access: { ...record.access, ingest: transitionRegistryIngest(record.access.ingest, 'frozen') } }, 'frozen', now, limits),
    error: 'conflict',
    safetyStop: true,
  }
}

function verified<T>(value: T, connection: InstanceVerificationContext): VerifiedRecord<T> {
  return { value, keyId: connection.keyId, verifiedAt: connection.now }
}

/** Accept an exact envelope retry, append the next event, or persist an authenticated integrity conflict.
 * @param record - Current live aggregate.
 * @param event - Signature-verified envelope.
 * @param connection - Authenticated key and trusted receive time.
 * @param limits - Explicit retained-event and audit limits.
 * @returns Atomic mutation; any returned conflict must be reported after durability. */
export function appendEvent(record: LiveRecord, event: DisclosureEventEnvelope,
  connection: InstanceVerificationContext, limits: RegistryIngestLimits): Mutation {
  if (event.conversationId !== record.conversationId || event.policyVersion !== record.policyVersion) {
    return freeze(record, connection.now, limits)
  }
  const duplicate = record.events.find(receipt => receipt.value.eventId === event.eventId)
  const atSequence = record.events[event.disclosureSeq]
  if (duplicate !== undefined || atSequence !== undefined) {
    if (duplicate !== undefined && JSON.stringify(duplicate.value) === JSON.stringify(event)) return { record }
    return freeze(record, connection.now, limits)
  }
  requireIngest(event.disclosureSeq <= record.events.length, 'gap')
  const last = record.events.at(-1)?.value
  const checkpoint = publishedCheckpoint(record)
  if (event.previousEventHash !== (last?.eventHash ?? null) || (last !== undefined && event.sourceCursor <= last.sourceCursor)
    || (checkpoint !== null && event.sourceCursor <= checkpoint.value.sourceCursor)) {
    return freeze(record, connection.now, limits)
  }
  requireIngest(record.events.length < limits.maxEvents, 'limit')
  return { record: audit({ ...record, events: [...record.events, verified(event, connection)] }, 'event', connection.now, limits) }
}

/** Publish only a complete prefix; retries and delayed older checkpoints never move the trusted pointer backwards.
 * @param record - Current live aggregate.
 * @param checkpoint - Signature-verified completion marker.
 * @param connection - Authenticated key and receive time.
 * @param limits - Explicit audit limits.
 * @returns Atomic publication or conflict mutation. */
export function appendCheckpoint(record: LiveRecord, checkpoint: DisclosureCheckpoint,
  connection: InstanceVerificationContext, limits: RegistryIngestLimits): Mutation {
  requireIngest(checkpoint.eventCount <= record.events.length, 'gap')
  if (!checkpointMatches(record, checkpoint)) return freeze(record, connection.now, limits)
  const previous = record.checkpoints.find(receipt => receipt.value.checkpointHash === checkpoint.checkpointHash
    || receipt.value.sourceCursor === checkpoint.sourceCursor)
  if (previous !== undefined) {
    if (JSON.stringify(previous.value) === JSON.stringify(checkpoint)) return { record }
    return freeze(record, connection.now, limits)
  }
  requireIngest(record.checkpoints.length < limits.maxCheckpoints, 'limit')
  const current = publishedCheckpoint(record)?.value
  const publishedHash = current !== undefined && checkpoint.sourceCursor <= current.sourceCursor
    ? current.checkpointHash : checkpoint.checkpointHash
  return {
    record: audit({
      ...record, checkpoints: [...record.checkpoints, verified(checkpoint, connection)],
      access: { ...record.access, ingest: transitionRegistryIngest(record.access.ingest, 'ready'), checkpointHash: publishedHash },
    }, 'checkpoint', connection.now, limits),
  }
}

/** Project durable acknowledgements without exposing ciphertext or reader grants.
 * @param record - Committed aggregate or tombstone.
 * @returns Ciphertext-free durable metadata. */
export function receiptOf(record: IngestRecord): RegistryIngestReceipt {
  if (record.kind === 'tombstone') {
    return { disclosureId: record.disclosureId, lastDisclosureSeq: -1, lastEventHash: null, checkpointHash: null,
      authorizationVersion: record.authorizationVersion, control: 'deleted', ingest: 'frozen' }
  }
  const last = record.events.at(-1)?.value
  return { disclosureId: record.access.disclosureId, lastDisclosureSeq: last?.disclosureSeq ?? -1,
    lastEventHash: last?.eventHash ?? null, checkpointHash: record.access.checkpointHash,
    authorizationVersion: record.access.authorizationVersion, control: record.access.control, ingest: record.access.ingest }
}
