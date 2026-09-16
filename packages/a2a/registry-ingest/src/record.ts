/** Strict durable aggregate parsing and consistency checks; no authority is inferred from stored bytes. */
import { z } from 'zod'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'
import { decodeDisclosureCheckpoint, decodeDisclosureEventEnvelope, type DisclosureCheckpoint, type DisclosureEventEnvelope } from '@deepseek-ai/dsh-a2a-protocol'
import type { InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import { DISCLOSURE_CONTROL_STATES, PRODUCER_SYNC_STATES, REGISTRY_INGEST_STATES, DISCLOSURE_CAPABILITIES,
  type DisclosureAccess, type MemberId, type TeamId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { RegistryIngestErrorCode, RegistryIngestLimits } from './types.ts'

/** Stable metadata-only diagnostics shared by callers and durable operation audit parsing. */
export const REGISTRY_INGEST_ERROR_CODES = Object.freeze(['not-found', 'invalid-input', 'conflict', 'gap', 'frozen', 'limit',
  'version-conflict', 'invalid-transition', 'storage-unavailable', 'invalid-storage', 'closed'] as const)

/** Sanitized ingestion or persistence failure suitable for an adapter's error mapping. */
export class RegistryIngestError extends Error {
  /** @param code - Stable metadata-only failure category. */
  constructor(readonly code: RegistryIngestErrorCode) {
    super(`registry ingest: ${code}`)
    this.name = 'RegistryIngestError'
  }
}

/** Assert one package-owned condition without including untrusted data in an error.
 * @param condition - Required invariant.
 * @param code - Metadata category when the invariant fails. */
export function requireIngest(condition: unknown, code: RegistryIngestErrorCode): asserts condition {
  if (!condition) throw new RegistryIngestError(code)
}

/** UTF-8 size of the complete serialized record, including metadata and signatures.
 * @param value - JSON data to measure.
 * @returns Canonical JSON byte count; non-JSON inputs may throw. */
export function byteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

/** Reserve enough metadata space to stop a live record even at maximum timestamp/version widths.
 * @param record - Proposed durable aggregate.
 * @returns Byte requirement with one retained stop audit entry; no ciphertext is removed. */
export function stopReserveBytes(record: IngestRecord): number {
  if (record.kind === 'tombstone') return byteLength(record)
  return byteLength({ ...record,
    access: { ...record.access, control: 'deleting', ingest: 'pending', authorizationVersion: Number.MAX_SAFE_INTEGER },
    audit: [{ action: 'control', at: Number.MAX_SAFE_INTEGER, authorizationVersion: Number.MAX_SAFE_INTEGER }],
  })
}

/** Fit a required stop by removing only oldest audit metadata, never the confirmed prefix.
 * @param record - Validated stop mutation with its newest audit entry.
 * @param maximum - Complete aggregate byte limit.
 * @returns Fitting aggregate; throws if even one audit entry cannot fit. */
export function fitStopRecord(record: IngestRecord, maximum: number): IngestRecord {
  let next = record
  while (byteLength(next) > maximum && next.audit.length > 1) next = { ...next, audit: next.audit.slice(1) }
  requireIngest(byteLength(next) <= maximum, 'limit')
  return next
}

const identifier = z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/)
const branded = <T extends Branded<string>>() => identifier.transform(value => brandString<T>(value))
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const hash = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const capability = z.enum(DISCLOSURE_CAPABILITIES)
const grant = z.strictObject({
  target: z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.literal('member'), memberId: branded<MemberId>() }),
    z.strictObject({ kind: z.literal('team'), teamId: branded<TeamId>() }),
  ]),
  state: z.enum(['active', 'revoked']), capabilities: z.array(capability), expiresAt: integer,
})
const accessSchema = z.strictObject({
  organizationId: branded<DisclosureAccess['organizationId']>(), disclosureId: branded<DisclosureAccess['disclosureId']>(), instanceId: branded<DisclosureAccess['instanceId']>(),
  control: z.enum(DISCLOSURE_CONTROL_STATES), producer: z.enum(PRODUCER_SYNC_STATES),
  ingest: z.enum(REGISTRY_INGEST_STATES), expiresAt: integer, authorizationVersion: integer,
  capabilities: z.array(capability), grants: z.array(grant), checkpointHash: hash.transform(value => brandString<NonNullable<DisclosureAccess['checkpointHash']>>(value)).nullable(),
})

/** Minimal metadata retained with an aggregate, excluding record bodies and user text. */
export interface AuditEntry {
  readonly action: 'registered' | 'event' | 'checkpoint' | 'frozen' | 'access' | 'control' | 'deleted'
  readonly at: number
  readonly authorizationVersion: number
}

/** Signature verification receipt; the Registry, not the sender, selects its key and receive time. */
export interface VerifiedRecord<T> {
  readonly value: T
  readonly keyId: InstanceKeyId
  readonly verifiedAt: number
}

/** One atomic disclosure row. A deleted row contains no events, checkpoint, grants or source-conversation identity. */
export type IngestRecord = {
  readonly kind: 'disclosure'
  readonly access: DisclosureAccess
  readonly conversationId: string
  readonly policyVersion: number
  readonly events: readonly VerifiedRecord<DisclosureEventEnvelope>[]
  readonly checkpoints: readonly VerifiedRecord<DisclosureCheckpoint>[]
  readonly audit: readonly AuditEntry[]
} | {
  readonly kind: 'tombstone'
  readonly organizationId: DisclosureAccess['organizationId']
  readonly disclosureId: DisclosureAccess['disclosureId']
  readonly instanceId: DisclosureAccess['instanceId']
  readonly authorizationVersion: number
  readonly audit: readonly AuditEntry[]
}

const auditSchema = z.array(z.strictObject({
  action: z.enum(['registered', 'event', 'checkpoint', 'frozen', 'access', 'control', 'deleted']),
  at: integer, authorizationVersion: integer,
})).min(1)
const receiptFields = { keyId: hash.transform(value => value as InstanceKeyId), verifiedAt: integer }
const recordSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('disclosure'), access: accessSchema, conversationId: identifier, policyVersion: integer.min(1),
    events: z.array(z.strictObject({ value: z.unknown().transform(decodeDisclosureEventEnvelope), ...receiptFields })),
    checkpoints: z.array(z.strictObject({ value: z.unknown().transform(decodeDisclosureCheckpoint), ...receiptFields })),
    audit: auditSchema,
  }),
  z.strictObject({
    kind: z.literal('tombstone'), organizationId: branded<DisclosureAccess['organizationId']>(), disclosureId: branded<DisclosureAccess['disclosureId']>(), instanceId: branded<DisclosureAccess['instanceId']>(),
    authorizationVersion: integer, audit: auditSchema,
  }),
])

/** Composite keys cannot collide when opaque identifiers contain separators.
 * @param organizationId - Authenticated organization.
 * @param disclosureId - Organization-local disclosure.
 * @returns Unambiguous storage key. */
export function recordKey(organizationId: string, disclosureId: string): string {
  return JSON.stringify([organizationId, disclosureId])
}

/** Resolve the sole published selector without retaining a second copy of checkpoint data.
 * @param record - Validated disclosure aggregate.
 * @returns The published checkpoint receipt, or null before publication. */
export function publishedCheckpoint(record: Extract<IngestRecord, { kind: 'disclosure' }>): VerifiedRecord<DisclosureCheckpoint> | null {
  return record.checkpoints.find(receipt => receipt.value.checkpointHash === record.access.checkpointHash) ?? null
}

/** Check a decoded checkpoint against the exact retained prefix and immutable disclosure identity.
 * @param record - Full retained chain.
 * @param value - Structurally verified checkpoint.
 * @returns Whether the prefix, identity and neighboring cursor facts agree. */
export function checkpointMatches(record: Extract<IngestRecord, { kind: 'disclosure' }>, value: DisclosureCheckpoint): boolean {
  const last = record.events[value.eventCount - 1]?.value
  const successor = record.events[value.eventCount]?.value
  return value.organizationId === record.access.organizationId && value.instanceId === record.access.instanceId
    && value.disclosureId === record.access.disclosureId && value.policyVersion === record.policyVersion
    && value.eventCount <= record.events.length && value.lastEventHash === (last?.eventHash ?? null)
    && (last === undefined || value.sourceCursor >= last.sourceCursor)
    && (successor === undefined || value.sourceCursor < successor.sourceCursor)
}

/** Validate durable records, full chains, confirmed pointers and resource limits during every open.
 * @param input - Untrusted persisted JSON aggregate.
 * @param limits - Immutable deployment bounds.
 * @returns Detached validated aggregate; failures contain no accepted replacement record. */
export function parseRecord(input: unknown, limits: RegistryIngestLimits): IngestRecord {
  requireIngest(byteLength(input) <= limits.maxAggregateBytes, 'invalid-storage')
  const record = recordSchema.parse(input)
  requireIngest(record.audit.length <= limits.maxAuditEntries, 'invalid-storage')
  if (record.kind === 'tombstone') {
    requireIngest(record.audit.length === 1 && record.audit[0]?.action === 'deleted'
      && record.audit[0].authorizationVersion === record.authorizationVersion, 'invalid-storage')
    return record
  }
  requireIngest(record.access.control !== 'deleted' && record.events.length <= limits.maxEvents, 'invalid-storage')
  const ids = new Set<string>()
  for (const [index, receipt] of record.events.entries()) {
    const event = receipt.value
    const previous = record.events[index - 1]?.value
    requireIngest(event.organizationId === record.access.organizationId && event.instanceId === record.access.instanceId
      && event.disclosureId === record.access.disclosureId && event.conversationId === record.conversationId
      && event.policyVersion === record.policyVersion && event.disclosureSeq === index
      && event.previousEventHash === (previous?.eventHash ?? null)
      && (previous === undefined || event.sourceCursor > previous.sourceCursor)
      && !ids.has(event.eventId) && event.occurredAt <= receipt.verifiedAt, 'invalid-storage')
    ids.add(event.eventId)
  }
  requireIngest(record.checkpoints.length <= limits.maxCheckpoints, 'invalid-storage')
  const checkpointHashes = new Set<string>()
  const checkpointCursors = new Set<number>()
  for (const receipt of record.checkpoints) {
    const value = receipt.value
    requireIngest(checkpointMatches(record, value) && !checkpointHashes.has(value.checkpointHash)
      && !checkpointCursors.has(value.sourceCursor), 'invalid-storage')
    checkpointHashes.add(value.checkpointHash)
    checkpointCursors.add(value.sourceCursor)
  }
  const checkpoint = publishedCheckpoint(record)?.value
  requireIngest(record.access.checkpointHash === (checkpoint?.checkpointHash ?? null)
    && (checkpoint === undefined ? record.access.ingest !== 'ready' : record.access.ingest !== 'pending')
    && (checkpoint === undefined ? record.checkpoints.length === 0 : record.checkpoints.every(receipt =>
      receipt.value.sourceCursor <= checkpoint.sourceCursor && receipt.value.eventCount <= checkpoint.eventCount)), 'invalid-storage')
  requireIngest(record.audit.every(entry => entry.authorizationVersion <= record.access.authorizationVersion), 'invalid-storage')
  return record
}

/** Check explicit deployment bounds before opening a storage domain.
 * @param limits - Required positive safe-integer bounds. */
export function validateLimits(limits: RegistryIngestLimits): void {
  for (const value of [limits.maxInputBytes, limits.maxAggregateBytes, limits.maxEvents,
    limits.maxCheckpoints, limits.maxDisclosures, limits.maxAuditEntries]) {
    requireIngest(Number.isSafeInteger(value) && value > 0, 'limit')
  }
}
