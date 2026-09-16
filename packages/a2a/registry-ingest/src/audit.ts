/** Strict metadata-only operation journal records; storage and publication remain the ingest owner's responsibility. */
import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'
import type { DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { RegistryBindingId } from './binding-types.ts'
import { byteLength, RegistryIngestError, REGISTRY_INGEST_ERROR_CODES, requireIngest } from './record.ts'

/** Server-generated identity for one retained attempt, independent of transport request identifiers. */
export type RegistryAuditOperationId = Branded<'A2ARegistryAuditOperationId'>

/** Explicit journal bounds; the owning store enforces the total operation count. */
export interface RegistryAuditLimits {
  /** Maximum retained attempts, including those still unfinished. */
  readonly maxOperations: number
  /** Maximum UTF-8 bytes of a complete serialized journal record. */
  readonly maxRecordBytes: number
}

const maximumIdentifierLength = 128
const identifier = <T extends Branded<string>>() => z.string()
  .max(maximumIdentifierLength)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]*[A-Za-z0-9])?$/u).transform(value => brandString<T>(value))
const hash = <T extends Branded<string>>() => z.string().regex(/^sha256:[0-9a-f]{64}$/u).transform(value => brandString<T>(value))
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const action = z.enum(['register', 'status', 'event', 'checkpoint', 'read', 'metadata-read', 'metadata-list', 'access', 'control', 'delete', 'directory-read', 'directory-change',
  'binding-start', 'binding-approve', 'binding-confirm', 'binding-review', 'binding-reject', 'binding-revoke', 'binding-rename', 'binding-list'])
const actor = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('enrollment'), organizationId: identifier<OrganizationId>(),
    instanceId: identifier<DshInstanceId>(), keyId: hash<InstanceKeyId>() }),
  z.strictObject({ kind: z.literal('producer'), organizationId: identifier<OrganizationId>(),
    instanceId: identifier<DshInstanceId>(), keyId: hash<InstanceKeyId>() }),
  z.strictObject({ kind: z.literal('member'), organizationId: identifier<OrganizationId>(), memberId: identifier<MemberId>() }),
  z.strictObject({ kind: z.literal('maintenance'), organizationId: identifier<OrganizationId>() }),
  z.strictObject({ kind: z.literal('unattributed') }),
]).readonly()
const outcome = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('binding'), bindingId: z.uuid().transform(value => brandString<RegistryBindingId>(value)),
    phase: z.enum(['pending', 'approved', 'confirmed', 'rejected', 'revoked']) }),
  z.strictObject({ kind: z.literal('directory'), revision: integer, changed: z.boolean(), invalidatedDisclosures: integer }),
  z.strictObject({ kind: z.literal('committed'),
    effect: z.enum(['registered', 'event', 'checkpoint', 'access', 'control', 'deleted', 'frozen']),
    authorizationVersion: integer, recordHash: hash<DisclosureHash>().nullable() }),
  z.strictObject({ kind: z.literal('unchanged'), authorizationVersion: integer, recordHash: hash<DisclosureHash>().nullable() }),
  z.strictObject({ kind: z.literal('observed'), authorizationVersion: integer.nullable(), recordHash: hash<DisclosureHash>().nullable() }),
  z.strictObject({ kind: z.literal('rejected'), code: z.enum(REGISTRY_INGEST_ERROR_CODES),
    category: z.literal('signature-failure').optional() }),
]).readonly()
const completion = z.strictObject({ completedAt: integer, actor, outcome }).readonly()
const schema = z.strictObject({ version: z.literal(9), organizationId: identifier<OrganizationId>(),
  operationId: z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u)
    .transform(value => brandString<RegistryAuditOperationId>(value)),
  startedAt: integer, action, requestedDisclosureId: identifier<DisclosureId>().nullable(), completion: completion.nullable(),
}).readonly()

/** Closed ingest operation names; no arbitrary diagnostics or content become journal actions. */
export type RegistryAuditAction = z.infer<typeof action>
/** Trusted authentication, verified enrollment possession or configured maintenance; never request claims. */
export type RegistryAuditActor = z.infer<typeof actor>
/** Durable owner results, separate from response transmission or peer acknowledgement. */
export type RegistryAuditOutcome = z.infer<typeof outcome>
/** One final observation; absence remains an unfinished operation after cold reopen. */
export type RegistryAuditCompletion = z.infer<typeof completion>
/** Immutable store organization and attempt fields, with an optional single completion. */
export type RegistryAuditRecord = z.infer<typeof schema>

const effects: Record<RegistryAuditAction, readonly Extract<RegistryAuditOutcome, { kind: 'committed' }>['effect'][]> = {
  register: ['registered'], status: [], event: ['event', 'frozen'], checkpoint: ['checkpoint', 'frozen'],
  read: [], 'metadata-read': [], 'metadata-list': [], access: ['access'], control: ['control'], delete: ['deleted'],
  'directory-read': [], 'directory-change': [], 'binding-start': [], 'binding-approve': [], 'binding-confirm': [],
  'binding-review': [], 'binding-reject': [], 'binding-revoke': [], 'binding-rename': [], 'binding-list': [],
}
const observations = new Set<RegistryAuditAction>(['status', 'read', 'metadata-read', 'metadata-list', 'directory-read'])
const maximumId = 'x'.repeat(maximumIdentifierLength)
const maximumHash = `sha256:${'f'.repeat(64)}`
const maximumActors: readonly RegistryAuditActor[] = [
  { kind: 'enrollment', organizationId: brandString<OrganizationId>(maximumId),
    instanceId: brandString<DshInstanceId>(maximumId), keyId: brandString<InstanceKeyId>(maximumHash) },
  { kind: 'producer', organizationId: brandString<OrganizationId>(maximumId),
    instanceId: brandString<DshInstanceId>(maximumId), keyId: brandString<InstanceKeyId>(maximumHash) },
  { kind: 'member', organizationId: brandString<OrganizationId>(maximumId), memberId: brandString<MemberId>(maximumId) },
  { kind: 'maintenance', organizationId: brandString<OrganizationId>(maximumId) },
  { kind: 'unattributed' },
]
const maximumVersion = { authorizationVersion: Number.MAX_SAFE_INTEGER, recordHash: brandString<DisclosureHash>(maximumHash) }
const maximumOutcomes: readonly RegistryAuditOutcome[] = [
  ...(['pending', 'approved', 'confirmed', 'rejected', 'revoked'] as const).map(phase => ({ kind: 'binding' as const,
    bindingId: brandString<RegistryBindingId>('ffffffff-ffff-4fff-bfff-ffffffffffff'), phase })),
  { kind: 'directory', revision: Number.MAX_SAFE_INTEGER, changed: true, invalidatedDisclosures: Number.MAX_SAFE_INTEGER },
  ...Object.values(effects).flat().map(effect => ({ kind: 'committed' as const, effect, ...maximumVersion })),
  { kind: 'unchanged', ...maximumVersion }, { kind: 'observed', ...maximumVersion },
  ...REGISTRY_INGEST_ERROR_CODES.map(code => ({ kind: 'rejected' as const, code })),
  { kind: 'rejected', code: 'invalid-input', category: 'signature-failure' },
]

function coherent(record: RegistryAuditRecord): boolean {
  const { organizationId, action, requestedDisclosureId, completion } = record
  const directory = action === 'directory-read' || action === 'directory-change'
  const binding = action === 'binding-start' || action === 'binding-approve' || action === 'binding-confirm'
    || action === 'binding-review' || action === 'binding-reject' || action === 'binding-revoke' || action === 'binding-rename'
  if ((action === 'metadata-list' || action === 'binding-list' || directory || binding) && requestedDisclosureId !== null) return false
  if (completion === null) return true
  const { actor, outcome } = completion
  if (actor.kind !== 'unattributed' && actor.organizationId !== organizationId) return false
  if (action === 'binding-list') return requestedDisclosureId === null
    && (outcome.kind === 'rejected' ? outcome.category === undefined && (actor.kind === 'member' || actor.kind === 'unattributed')
      : actor.kind === 'member' && outcome.kind === 'observed' && outcome.authorizationVersion === null && outcome.recordHash === null)
  if (binding) {
    const expectedActor = action === 'binding-start' ? 'unattributed' : action === 'binding-confirm' ? 'enrollment' : 'member'
    if (outcome.kind === 'rejected') return outcome.category === undefined
      && (actor.kind === 'unattributed' || actor.kind === expectedActor)
    return actor.kind === expectedActor && outcome.kind === 'binding'
      && (action === 'binding-review'
        || outcome.phase === (action === 'binding-start' ? 'pending' : action === 'binding-approve' ? 'approved'
          : action === 'binding-confirm' || action === 'binding-rename' ? 'confirmed' : action === 'binding-revoke' ? 'revoked' : 'rejected'))
  }
  if (actor.kind === 'enrollment' || outcome.kind === 'binding') return false
  if (outcome.kind === 'rejected' && outcome.category !== undefined) {
    return outcome.code === 'invalid-input' && actor.kind === 'producer'
      && (action === 'event' || action === 'checkpoint') && requestedDisclosureId !== null
  }
  if (actor.kind === 'unattributed') return outcome.kind === 'rejected'
  if (actor.kind === 'maintenance' && action !== 'delete') return false
  if ((actor.kind === 'member') !== (action === 'read' || action === 'metadata-read' || action === 'metadata-list' || directory)) return false
  if (outcome.kind === 'rejected') return true
  if (action !== 'metadata-list' && !directory && requestedDisclosureId === null) return false
  switch (outcome.kind) {
    case 'directory': return action === 'directory-change' && (outcome.changed || outcome.invalidatedDisclosures === 0)
    case 'committed': return effects[action].includes(outcome.effect)
    case 'unchanged': return effects[action].length > 0
    case 'observed': return observations.has(action)
      && (!directory || (outcome.authorizationVersion === null && outcome.recordHash === null))
  }
}

/** Validate explicit deployment limits before the storage domain opens.
 * @param limits - Positive safe-integer journal capacity and complete record byte bound. */
export function validateAuditLimits(limits: RegistryAuditLimits): void {
  for (const value of [limits.maxOperations, limits.maxRecordBytes]) requireIngest(Number.isSafeInteger(value) && value > 0, 'limit')
}

/** Measure completion space from the legal metadata fields, rather than a deployment-varying estimate.
 * @param attempt - Parsed unfinished attempt whose immutable fields remain in every completion.
 * @returns Additional UTF-8 bytes needed for its largest permitted completion.
 * @throws RegistryIngestError with invalid-transition when given an already completed record. */
export function auditCompletionReserveBytes(attempt: RegistryAuditRecord): number {
  requireIngest(attempt.completion === null, 'invalid-transition')
  let maximum = 0
  for (const actor of maximumActors) {
    for (const outcome of maximumOutcomes) {
      const scopedActor = actor.kind === 'unattributed' ? actor : { ...actor, organizationId: attempt.organizationId }
      const record = { ...attempt, completion: { completedAt: Number.MAX_SAFE_INTEGER, actor: scopedActor, outcome } }
      if (coherent(record)) maximum = Math.max(maximum, byteLength(record))
    }
  }
  return maximum - byteLength(attempt)
}

/** Parse one stored record without retaining arbitrary fields or exposing parser diagnostics.
 * @param input - Untrusted persisted JSON record.
 * @param limits - Validated complete record limit; count is enforced by the owning table.
 * @returns Detached, recursively frozen metadata, preserving null completion.
 * @throws RegistryIngestError with invalid-storage for malformed, oversized or inconsistent records. */
export function parseAuditRecord(input: unknown, limits: RegistryAuditLimits): RegistryAuditRecord {
  try {
    requireIngest(byteLength(input) <= limits.maxRecordBytes, 'invalid-storage')
    const record = schema.parse(input)
    requireIngest(coherent(record), 'invalid-storage')
    return record
  } catch {
    // Persisted fields and parser errors may contain private input; only the category leaves this parser.
    throw new RegistryIngestError('invalid-storage')
  }
}

/** Create one unfinished operation using a fresh server-generated UUID.
 * @param organizationId - Immutable organization of the durable store, not an unvalidated request claim.
 * @param action - Owner-selected ingest operation.
 * @param requestedDisclosureId - Decoded requested ID, or null when absent; not proof the resource exists.
 * @param startedAt - Trusted server start time in integer milliseconds.
 * @param limits - Validated whole-record byte bound.
 * @returns A detached immutable attempt with enough byte capacity for any legal completion; it is not persisted here. */
export function createAuditAttempt(organizationId: OrganizationId, action: RegistryAuditAction, requestedDisclosureId: DisclosureId | null,
  startedAt: number, limits: RegistryAuditLimits): RegistryAuditRecord {
  const attempt = { version: 9, organizationId, operationId: randomUUID(), startedAt, action, requestedDisclosureId, completion: null }
  requireIngest(byteLength(attempt) <= limits.maxRecordBytes, 'limit')
  const record = parseAuditRecord(attempt, limits)
  requireIngest(byteLength(record) + auditCompletionReserveBytes(record) <= limits.maxRecordBytes, 'limit')
  return record
}

/** Complete an unfinished attempt without changing its identity, action, selection or start time.
 * @param attempt - Previously created or parsed unfinished record.
 * @param completion - Trusted terminal metadata; response transmission is not a commit result.
 * @param limits - Validated whole-record byte bound.
 * @returns A new immutable record; the original attempt remains unchanged.
 * @throws RegistryIngestError with invalid-transition when the attempt was already completed. */
export function completeAuditAttempt(attempt: RegistryAuditRecord, completion: RegistryAuditCompletion,
  limits: RegistryAuditLimits): RegistryAuditRecord {
  requireIngest(attempt.completion === null, 'invalid-transition')
  const record = { ...attempt, completion }
  requireIngest(byteLength(record) <= limits.maxRecordBytes, 'limit')
  return parseAuditRecord(record, limits)
}
