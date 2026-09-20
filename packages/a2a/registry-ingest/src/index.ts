/** Single-writer Registry ingestion over real storage-domain atomic record updates. */
import { z } from 'zod'
import { brandString } from '@deepseek-ai/dsh-brand'
import { defineDomain, domainTable, type Domain, type DomainFacility, type DomainRecordWrite } from '@deepseek-ai/dsh-storage-domain'
import { InstanceSignatureError, verifyDisclosureCheckpoint, verifyDisclosureEvent } from '@deepseek-ai/dsh-a2a-device-identity'
import type { InstanceKeyHistory, InstanceVerificationContext,
  RegistryBridgeSecretHash, RegistryDeviceSecretHash } from '@deepseek-ai/dsh-a2a-device-identity'
import { decodeDisclosureCheckpoint, decodeDisclosureEventEnvelope, type DisclosureCheckpoint, type DisclosureConversationId,
  type DisclosureHash, type DisclosureId, type DshInstanceId, type OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import { canUploadDisclosure, invalidateDisclosureAuthorization, transitionDisclosureControl, updateDisclosureAccess,
  type DisclosureAccessUpdate, type DisclosureAction, type DisclosureControlState } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { DisclosureSubject, MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { decodeRegistryAudience } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import { approveBinding, authenticateBindingCredential as resolveBindingCredential,
  authenticateBridgeCredential as resolveBridgeCredential, confirmedBindingHistory, confirmBinding, inspectBinding,
  parseBinding, rejectBinding, renameBinding, reviewBinding, revokeBinding, startBinding } from './binding.ts'
import type { RegistryBindingConfig, RegistryBindingId, RegistryBindingInvalidation, RegistryBindingReceipt, RegistryBindingRecord,
  RegistryBindingRequest, RegistryBindingReview, RegistryBindingScope, RegistryBindingTicket } from './binding-types.ts'
import { changeDirectory, directorySubject, initialDirectory, parseDirectory, validateDirectoryConfig } from './directory.ts'
import type { FreshRegistryDirectoryAuthority, RegistryDirectoryChange, RegistryDirectoryConfig, RegistryDirectoryMember,
  RegistryDirectoryReceipt, RegistryDirectoryState } from './directory-types.ts'
import { appendCheckpoint, appendEvent, audit, receiptOf, type LiveRecord, type Mutation } from './aggregate.ts'
import { byteLength, fitStopRecord, parseRecord, recordKey, RegistryIngestError, requireIngest, stopReserveBytes,
  validateLimits, type IngestRecord, type VerifiedRecord } from './record.ts'
import { confirmedPrefix, MetadataCursor, metadataOf } from './metadata.ts'
import { completeAuditAttempt, createAuditAttempt, parseAuditRecord, validateAuditLimits,
  type RegistryAuditAction, type RegistryAuditActor, type RegistryAuditLimits, type RegistryAuditOutcome,
  type RegistryAuditRecord } from './audit.ts'
import type { FreshProducerAuthority, FreshReaderAuthority, RegistryConfirmedPrefix, RegistryDisclosureRegistration,
  RegistryIngestLimits, RegistryIngestReceipt, RegistryCheckpointReceipt, RegistryProducerAuthority, FreshRegistryMetadataAuthority,
  RegistryDisclosureMetadata, RegistryMetadataListOptions, RegistryMetadataPage, RegistryMetadataReadOptions,
  RegistryDeletionBatchOptions, RegistryDeletionBatchReceipt, RegistryProducerSyncStatus, RegistryIngestErrorCode,
  RegistryDisclosureInvalidation } from './types.ts'

export type * from './types.ts'
export type * from './directory-types.ts'
export type { RegistryBindingConfig, RegistryBindingId, RegistryBindingInvalidation, RegistryBindingReceipt, RegistryBindingRequest,
  RegistryBindingReview, RegistryBindingScope, RegistryBindingTicket } from './binding-types.ts'
export { RegistryIngestError } from './record.ts'
export type { RegistryAuditAction, RegistryAuditActor, RegistryAuditLimits, RegistryAuditOperationId,
  RegistryAuditOutcome, RegistryAuditRecord } from './audit.ts'

/** Explicit opt-in operation journal. Capacity or persistence failures block every operation, including deletion. */
export interface RegistryAuditConfig extends RegistryAuditLimits {
  readonly failurePolicy: 'block-all'
}

/** Current per-request authority returned only after a v6 bridge credential is revalidated. */
export interface RegistryBridgeAuthority {
  readonly bindingId: RegistryBindingId
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly memberId: MemberId
  readonly producer: RegistryProducerAuthority
}

interface ActiveAudit {
  readonly attempt: RegistryAuditRecord
  readonly journal: JournalOwner
  actor: RegistryAuditActor
  completed: boolean
  recordHash: DisclosureHash | null
  signatureFailure: boolean
}
interface JournalOwner {
  readonly config: RegistryAuditConfig
  readonly putMany: NonNullable<Domain<ReturnType<typeof specification>>['putMany']>
}
type MutationAction = 'event' | 'checkpoint' | 'access' | 'control' | 'delete'
type InputAdmission<T> = { readonly accepted: true; readonly value: T }
  | { readonly accepted: false; readonly code: RegistryIngestErrorCode }
interface DeletionBatchInput {
  readonly organizationId: OrganizationId
  readonly now: number
  readonly maxItems: number
  readonly cancelled: () => boolean
}

function abortState(signal: AbortSignal): unknown {
  return Reflect.get(AbortSignal.prototype, 'aborted', signal)
}

function reportInvalidationListenerFailure(): void {
  try { console.error('Registry invalidation listener failed') } catch {
    // Diagnostics cannot veto a committed mutation or prevent another observer from running.
  }
}

function reportAuditListenerFailure(): void {
  try { console.error('Registry audit listener failed') } catch {
    // Diagnostic failure cannot reverse a confirmed journal completion.
  }
}

/** Physical storage identity for one organization-owned Registry aggregate. */
export interface RegistryIngestStorageScope {
  /** Stable backend unit name. Multi-tenant runtimes use a server-generated organization hash. */
  readonly domainName?: string
  /** Opaque backend tenant scope used by PostgreSQL RLS-capable storage. */
  readonly tenantId?: string
}

function specification(organizationId: OrganizationId, limits: RegistryIngestLimits, journal?: RegistryAuditConfig,
  directory?: RegistryDirectoryConfig, bindings?: RegistryBindingConfig, storage?: RegistryIngestStorageScope) {
  return defineDomain({ name: storage?.domainName ?? 'a2a_registry_ingest', version: 10, layout: 'single',
    ...(storage?.tenantId === undefined ? {} : { tenantId: storage.tenantId }), tables: {
    bindings: domainTable<string, RegistryBindingRecord>(z.unknown().transform((value) => {
      requireIngest(bindings !== undefined, 'invalid-storage')
      return parseBinding(value, bindings)
    })),
    owner: domainTable<string, { readonly organizationId: OrganizationId; readonly directory: RegistryDirectoryState | null }>(
      z.strictObject({ organizationId: z.literal(organizationId), directory: z.unknown().transform((value) => {
        if (directory === undefined) { requireIngest(value === null, 'invalid-storage'); return null }
        return parseDirectory(value, directory)
      }) }).readonly()),
    disclosures: domainTable<string, IngestRecord>(z.unknown().transform(value => parseRecord(value, limits))),
    audit: domainTable<string, RegistryAuditRecord>(z.unknown().transform((value) => {
      requireIngest(journal !== undefined, 'invalid-storage')
      return parseAuditRecord(value, journal)
    })),
  } })
}

function producer(authority: RegistryProducerAuthority): void {
  const { connection, history } = authority
  const key = history.keys.find(candidate => candidate.keyId === connection.keyId)
  requireIngest(history.organizationId === connection.organizationId && history.instanceId === connection.instanceId
    && history.status === 'active' && key !== undefined && Number.isSafeInteger(connection.now) && connection.now >= 0
    && key.revokedAt === null && connection.now >= key.validFrom
    && (key.validUntil === null || connection.now < key.validUntil), 'not-found')
}

function owns(record: IngestRecord, authority: RegistryProducerAuthority): void {
  const identity = record.kind === 'disclosure' ? record.access : record
  requireIngest(identity.organizationId === authority.connection.organizationId && identity.instanceId === authority.connection.instanceId, 'not-found')
}

function live(record: IngestRecord): LiveRecord {
  requireIngest(record.kind === 'disclosure', 'not-found')
  return record
}

function upload(record: LiveRecord, authority: RegistryProducerAuthority): void {
  requireIngest(record.access.control === 'active' && authority.connection.now < record.access.expiresAt, 'not-found')
  requireIngest(record.access.ingest !== 'frozen', 'frozen')
  requireIngest(canUploadDisclosure(record.access, authority.connection.organizationId, authority.connection.instanceId, authority.connection.now), 'not-found')
}

function retryContext<T>(value: T, receipt: VerifiedRecord<T> | undefined | null,
  connection: InstanceVerificationContext): InstanceVerificationContext {
  return receipt != null && JSON.stringify(receipt.value) === JSON.stringify(value)
    ? { ...connection, keyId: receipt.keyId, now: receipt.verifiedAt }
    : connection
}

function exactPristineRegistration(record: IngestRecord, candidate: LiveRecord): record is LiveRecord {
  const registered = record.audit[0]
  return record.kind === 'disclosure'
    && record.events.length === 0
    && record.checkpoints.length === 0
    && record.audit.length === 1
    && registered?.action === 'registered'
    && registered.authorizationVersion === 0
    && JSON.stringify({ access: record.access, conversationId: record.conversationId,
      policyVersion: record.policyVersion }) === JSON.stringify({ access: candidate.access,
      conversationId: candidate.conversationId, policyVersion: candidate.policyVersion })
}

/**
 * Open and validate every retained aggregate; failures reveal no stored payload or backend diagnostic.
 * @param facility - Exclusively owned storage-domain facility configured with the real backend.
 * @param organizationId - Explicit immutable organization binding, including when no disclosures remain.
 * @param limits - Explicit byte, event, checkpoint, disclosure and recent-audit limits.
 * @param journal - Explicit block-all audit policy and bounds; omission records no operations and refuses a nonempty journal.
 * @param directory - Optional explicit directory limits. A bootstrap owner provisions an empty domain; omission requires retained state.
 * @param bindings - Optional enrollment limits and fixed audience; requires the current member directory and atomic batches.
 * @returns An owner that must close before the same domain can reopen.
 * @throws RegistryIngestError if limits or persisted records fail validation.
 */
export async function openRegistryIngest(facility: DomainFacility, organizationId: OrganizationId, limits: RegistryIngestLimits,
  journal?: RegistryAuditConfig, directory?: RegistryDirectoryConfig, bindings?: RegistryBindingConfig,
  storage?: RegistryIngestStorageScope): Promise<RegistryIngest> {
  const resolvedLimits = Object.freeze({ ...limits })
  validateLimits(resolvedLimits)
  const resolvedJournal = journal === undefined ? undefined : Object.freeze({ ...journal })
  if (resolvedJournal !== undefined) validateAuditLimits(resolvedJournal)
  const resolvedDirectory = directory === undefined ? undefined : structuredClone(directory)
  if (resolvedDirectory !== undefined) validateDirectoryConfig(resolvedDirectory)
  const resolvedBindings = bindings === undefined ? undefined : Object.freeze({ ...bindings })
  if (resolvedBindings !== undefined) {
    requireIngest(resolvedDirectory !== undefined, 'invalid-input')
    for (const value of [resolvedBindings.ttlMs, resolvedBindings.maxRecordBytes,
      resolvedBindings.maxBindings, resolvedBindings.maxNameBytes]) {
      requireIngest(Number.isSafeInteger(value) && value > 0, 'limit')
    }
    try { decodeRegistryAudience(resolvedBindings.audience) } catch { throw new RegistryIngestError('invalid-input') }
  }
  let domain: Domain<ReturnType<typeof specification>>
  try {
    domain = await facility.open(specification(organizationId, resolvedLimits, resolvedJournal, resolvedDirectory,
      resolvedBindings, storage))
  } catch {
    // Storage validation errors can include persisted fields; only the category crosses this API.
    throw new RegistryIngestError('invalid-storage')
  }
  try {
    if (resolvedDirectory !== undefined) requireIngest(domain.putMany !== undefined, 'invalid-storage')
    const bindingTable = domain.table('bindings')
    requireIngest(bindingTable.size <= (resolvedBindings?.maxBindings ?? 0), 'invalid-storage')
    for (const [key, record] of bindingTable.entries()) {
      requireIngest(key === record.bindingId && record.challenge.organizationId === organizationId
        && record.challenge.audience === resolvedBindings?.audience, 'invalid-storage')
    }
    const table = domain.table('disclosures')
    requireIngest(table.size <= resolvedLimits.maxDisclosures, 'invalid-storage')
    for (const [key, record] of table.entries()) {
      const identity = record.kind === 'disclosure' ? record.access : record
      requireIngest(identity.organizationId === organizationId && key === recordKey(organizationId, identity.disclosureId), 'invalid-storage')
    }
    const journalTable = domain.table('audit')
    let journalOwner: JournalOwner | undefined
    if (resolvedJournal !== undefined) {
      requireIngest(domain.putMany !== undefined && journalTable.size <= resolvedJournal.maxOperations, 'invalid-storage')
      journalOwner = { config: resolvedJournal, putMany: domain.putMany.bind(domain) }
      for (const [key, record] of journalTable.entries()) {
        requireIngest(record.organizationId === organizationId && key === record.operationId, 'invalid-storage')
      }
    }
    const owner = domain.table('owner')
    if (owner.size === 0) {
      requireIngest(table.size === 0 && journalTable.size === 0 && bindingTable.size === 0, 'invalid-storage')
      try {
        await owner.put('organization', Object.freeze({ organizationId,
          directory: resolvedDirectory === undefined ? null : initialDirectory(resolvedDirectory) }))
      } catch {
        // Even a committed-then-rejected initialization must close before a fresh owner can inspect it.
        throw new RegistryIngestError('storage-unavailable')
      }
    } else requireIngest(owner.size === 1 && owner.get('organization')?.organizationId === organizationId, 'invalid-storage')
    return new RegistryIngest(domain, organizationId, resolvedLimits, journalOwner, resolvedDirectory, resolvedBindings)
  } catch (error) {
    try { await domain.close() } catch {
      // A failed close leaves ownership unresolved; consumers must not retry this facility.
      throw new RegistryIngestError('invalid-storage')
    }
    throw error instanceof RegistryIngestError ? error : new RegistryIngestError('invalid-storage')
  }
}

/**
 * Owns one domain and its serialized operations. All input authority comes from trusted adapters,
 * not JSON flags; every write rejection after update transformation isolates this owner until reopen.
 * With journaling enabled, rejected input snapshots and entry options also wait for serialized, unattributed audit.
 * Closure, journal capacity or persistence failures can replace the original input error; authority is not requested.
 */
export class RegistryIngest {
  private chain: Promise<void> = Promise.resolve()
  private unavailable = false
  private closing = false
  private disposal: Promise<void> | undefined
  private readonly metadataCursor = new MetadataCursor()
  private readonly table
  private readonly journalTable
  private activeAudit: ActiveAudit | undefined
  private readonly invalidations = new Set<{ readonly listener: (event: RegistryDisclosureInvalidation) => void | Promise<void> }>()
  private readonly auditCompletions = new Set<{ readonly listener: (record: RegistryAuditRecord) => void | Promise<void> }>()
  private readonly bindingInvalidations = new Set<{ readonly listener: (event: RegistryBindingInvalidation) => void | Promise<void> }>()
  private directoryMembers = new Map<MemberId, RegistryDirectoryMember>()

  /** @param domain - Validated exclusive domain; use openRegistryIngest rather than constructing manually.
   * @param organizationId - Organization whose singleton binding was durably verified before construction.
   * @param limits - Explicit limits validated by the opener.
   * @param journal - Optional validated journal and atomic batch writer, captured by the opener.
   * @param directoryConfig - Optional validated directory bounds, captured by the opener.
   * @param bindingConfig - Optional validated enrollment bounds, captured by the opener. */
  constructor(private readonly domain: Domain<ReturnType<typeof specification>>, private readonly organizationId: OrganizationId,
    private readonly limits: RegistryIngestLimits,
    private readonly journal?: JournalOwner,
    private readonly directoryConfig?: RegistryDirectoryConfig,
    private readonly bindingConfig?: RegistryBindingConfig) {
    this.table = domain.table('disclosures')
    this.journalTable = domain.table('audit')
    const directory = domain.table('owner').get('organization')?.directory
    if (directory !== null && directory !== undefined) {
      this.directoryMembers = new Map(directory.members.map(member => [member.memberId, member]))
    }
  }

  /** Persist a bounded enrollment attempt before returning its one-time code.
   * @param request - Untrusted public key, instance-name suggestion and requested device functions, captured before queuing.
   * @returns One-time code, server challenge and attempt ID; no credential is issued. */
  startBinding(request: RegistryBindingRequest): Promise<RegistryBindingTicket> {
    const admission = this.input(request)
    if (!admission.accepted) return this.rejectInput('binding-start', null, admission.code)
    return this.enqueue(async () => {
      const bindingConfig = this.bindingConfig
      requireIngest(bindingConfig !== undefined, 'not-found')
      await this.pruneOneExpiredBinding(Date.now())
      return this.audited('binding-start', null, async () => {
        requireIngest(this.domain.table('bindings').size < bindingConfig.maxBindings, 'limit')
        const { code, record } = startBinding(this.organizationId, bindingConfig.audience,
          admission.value, Date.now(), bindingConfig)
        await this.complete({ kind: 'binding', bindingId: record.bindingId, phase: 'pending' }, undefined, undefined, record)
        return structuredClone({ bindingId: record.bindingId, code, challenge: record.challenge })
      })
    })
  }

  /** Commit account approval using the current persisted organization membership.
   * @param authority - Fresh trusted account mapping; approval does not authenticate the device.
   * @param bindingId - Server-generated attempt ID.
   * @param code - One-time code supplied by the confirming user.
   * @param instanceName - Account-selected name; all immutable requested scopes are accepted together, not disclosure grants.
   * @returns Persisted approved phase, including exact same-member retries. */
  approveBinding(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId, code: string,
    instanceName: string): Promise<RegistryBindingReceipt> {
    return this.enqueue(() => this.audited('binding-approve', null, async () => {
      const subject = await this.bindingSubject(authority)
      const previous = this.binding(bindingId)
      requireIngest(this.bindingConfig !== undefined, 'not-found')
      const next = approveBinding(previous, subject, code, instanceName, Date.now(), this.bindingConfig)
      await this.complete({ kind: 'binding', bindingId, phase: 'approved' }, undefined, undefined,
        next === previous ? undefined : next)
      return structuredClone({ bindingId, state: next.state })
    }))
  }

  /** Return bounded confirmation metadata only after current membership and exact code checks.
   * @param authority - Fresh trusted account mapping; current stored membership decides visibility.
   * @param bindingId - Server-generated attempt ID.
   * @param code - Exact enrollment code supplied by the confirming user.
   * @param maxResponseBytes - Trusted bound on the complete JSON response.
   * @returns Detached fingerprint and lifecycle metadata, not a credential or full challenge. */
  reviewBinding(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId, code: string,
    maxResponseBytes: number): Promise<RegistryBindingReview> {
    return this.enqueue(() => this.audited('binding-review', null, async () => {
      this.positive(maxResponseBytes)
      const subject = await this.bindingSubject(authority)
      const result = this.boundedMetadata(reviewBinding(this.binding(bindingId), subject, code, Date.now()), maxResponseBytes)
      await this.complete({ kind: 'binding', bindingId, phase: result.phase })
      return structuredClone(result)
    }))
  }

  /** Inspect an owning account's confirmed or revoked instance without retaining an enrollment code.
   * @param authority - Fresh trusted account identity; current persisted membership and ownership decide visibility.
   * @param bindingId - Selected confirmed or revoked binding, never a bearer credential.
   * @param maxResponseBytes - Trusted complete JSON response bound.
   * @returns Detached binding metadata after enabled review-audit completion; no key bytes, digest or nonce. */
  inspectBinding(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId,
    maxResponseBytes: number): Promise<RegistryBindingReview> {
    return this.enqueue(() => this.audited('binding-review', null, async () => {
      this.positive(maxResponseBytes)
      const subject = await this.bindingSubject(authority)
      const result = this.boundedMetadata(inspectBinding(this.binding(bindingId), subject, Date.now()), maxResponseBytes)
      await this.complete({ kind: 'binding', bindingId, phase: result.phase })
      return structuredClone(result)
    }))
  }

  /** Atomically record a current member's refusal of a pending attempt and its enabled audit completion.
   * @param authority - Fresh trusted account mapping; current directory membership is required.
   * @param bindingId - Server-generated attempt ID.
   * @param code - Exact enrollment code.
   * @returns Durable rejection or exact same-member retry; approved/confirmed attempts cannot be rejected. */
  rejectBinding(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId, code: string): Promise<RegistryBindingReceipt> {
    return this.enqueue(() => this.audited('binding-reject', null, async () => {
      const subject = await this.bindingSubject(authority)
      const previous = this.binding(bindingId)
      const next = rejectBinding(previous, subject, code, Date.now())
      await this.complete({ kind: 'binding', bindingId, phase: 'rejected' }, undefined, undefined,
        next === previous ? undefined : next)
      return structuredClone({ bindingId, state: next.state })
    }))
  }

  /** Revoke the current account's confirmed instance binding and deny its subsequent producer operations.
   * @param authority - Fresh external account authentication; the stored directory supplies active membership.
   * @param bindingId - Selected instance binding, never an enrollment code or a bearer credential.
   * @returns Durable terminal receipt; retries preserve revocation time.
   * Post-commit instance notifications let the transport close matching sockets; subsequent reads deny the source.
   * Reader leases and disclosure content deletion remain separate responsibilities. */
  revokeBinding(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId): Promise<RegistryBindingReceipt> {
    return this.enqueue(() => this.audited('binding-revoke', null, async () => {
      const subject = await this.bindingSubject(authority)
      const previous = this.binding(bindingId)
      const next = revokeBinding(previous, subject, Date.now())
      await this.complete({ kind: 'binding', bindingId, phase: 'revoked' }, undefined, undefined,
        next === previous ? undefined : next)
      if (next !== previous) this.publishBindingInvalidation(next)
      return structuredClone({ bindingId, state: next.state })
    }))
  }

  /** Rename a currently confirmed instance for its active owning account, without changing device permissions.
   * @param authority - Fresh external account authentication; persisted membership and ownership decide access.
   * @param bindingId - Selected confirmed instance binding; no enrollment code is required.
   * @param instanceName - Exact account-selected name within the configured UTF-8 bound.
   * @returns Receipt after atomic name and enabled audit commit; matching-name retries leave the binding unchanged. */
  renameBinding(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId,
    instanceName: string): Promise<RegistryBindingReceipt> {
    return this.enqueue(() => this.audited('binding-rename', null, async () => {
      const subject = await this.bindingSubject(authority)
      const previous = this.binding(bindingId)
      requireIngest(this.bindingConfig !== undefined, 'not-found')
      const next = renameBinding(previous, subject, instanceName, Date.now(), this.bindingConfig)
      await this.complete({ kind: 'binding', bindingId, phase: 'confirmed' }, undefined, undefined,
        next === previous ? undefined : next)
      return structuredClone({ bindingId, state: next.state })
    }))
  }

  /** List the current account's confirmed and revoked bindings without exposing other members or enrollment attempts.
   * @param authority - Fresh authenticated identity, checked against current directory membership inside the owner queue.
   * @param maxResponseBytes - Positive safe integer bounding the complete JSON array; overflow rejects the whole result.
   * @returns Detached metadata ordered by binding ID after enabled audit completion, including expired enrollment challenges.
   * Work is bounded by configured maxBindings; this is not the public instance directory or a presence report. */
  listBindings(authority: FreshRegistryDirectoryAuthority, maxResponseBytes: number): Promise<readonly RegistryBindingReview[]> {
    return this.enqueue(() => this.audited('binding-list', null, async () => {
      this.positive(maxResponseBytes)
      const subject = await this.bindingSubject(authority)
      requireIngest(this.bindingConfig !== undefined, 'not-found')
      const now = Date.now()
      const records = [...this.domain.table('bindings').entries()].map(([, record]) => record)
        .filter(record => (record.state.kind === 'confirmed' || record.state.kind === 'revoked')
          && record.state.memberId === subject.memberId)
        .sort((left, right) => left.bindingId < right.bindingId ? -1 : left.bindingId > right.bindingId ? 1 : 0)
      const result = this.boundedMetadata(records.map(record => inspectBinding(record, subject, now)), maxResponseBytes)
      await this.complete({ kind: 'observed', authorizationVersion: null, recordHash: null })
      return structuredClone(result)
    }))
  }

  private async bindingSubject(authority: FreshRegistryDirectoryAuthority): Promise<DisclosureSubject> {
    const current = await this.authenticate(authority)
    this.requireOrganization(current.subject.organizationId)
    const subject = directorySubject(this.directory(), current.subject)
    this.attributeMember(subject)
    return subject
  }

  /** Persist device possession after account approval, without issuing upload or reader authority.
   * @param bindingId - Server-generated attempt ID.
   * @param proof - Untrusted exact challenge signature, captured before entering the owner queue.
   * @returns Durable confirmed phase; a reverified retry does not advance confirmation time. */
  confirmBinding(bindingId: RegistryBindingId, proof: unknown): Promise<RegistryBindingReceipt> {
    const admission = this.input(proof)
    if (!admission.accepted) return this.rejectInput('binding-confirm', null, admission.code)
    return this.enqueue(() => this.audited('binding-confirm', null, async () => {
      const previous = this.binding(bindingId)
      requireIngest(previous.state.kind === 'approved' || previous.state.kind === 'confirmed', 'not-found')
      const memberId = previous.state.memberId
      const member = this.directory().members.find(candidate => candidate.memberId === memberId)
      requireIngest(member !== undefined, 'not-found')
      const next = confirmBinding(previous, member, admission.value, Date.now())
      if (this.activeAudit !== undefined) {
        const { organizationId, instanceId, keyId } = previous.challenge
        this.activeAudit.actor = { kind: 'enrollment', organizationId, instanceId, keyId }
      }
      await this.complete({ kind: 'binding', bindingId, phase: 'confirmed' }, undefined, undefined,
        next === previous ? undefined : next)
      return structuredClone({ bindingId, state: next.state })
    }))
  }

  private binding(bindingId: RegistryBindingId): RegistryBindingRecord {
    requireIngest(this.bindingConfig !== undefined, 'not-found')
    const record = this.domain.table('bindings').get(bindingId)
    requireIngest(record !== undefined, 'not-found')
    return record
  }

  /** Read directory metadata without granting disclosure access.
   * @param authority - Current externally authenticated member identity and server time; stored roles decide access.
   * @param scope - Audience returns active members and their teams; administration additionally requires a stored Owner/Admin role.
   * @param maxResponseBytes - Consumer-selected bound on the complete JSON response.
   * @returns Detached directory data, not account authentication, key history, or a disclosure grant. */
  readDirectory(authority: FreshRegistryDirectoryAuthority, scope: 'audience' | 'administration',
    maxResponseBytes: number): Promise<RegistryDirectoryState> {
    return this.enqueue(() => this.audited('directory-read', null, async () => {
      this.positive(maxResponseBytes)
      const current = await this.authenticate(authority)
      this.requireOrganization(current.subject.organizationId)
      const directory = this.directory()
      const subject = directorySubject(directory, current.subject)
      this.attributeMember(subject)
      requireIngest(scope === 'audience' || subject.role === 'owner' || subject.role === 'admin', 'not-found')
      const members = scope === 'administration' ? directory.members : directory.members.filter(member => member.state === 'active')
      const visible = new Set(members.map(member => member.memberId))
      const value = this.boundedMetadata({ ...directory, members,
        teams: directory.teams.map(team => ({ ...team, memberIds: team.memberIds.filter(id => visible.has(id)) })) }, maxResponseBytes)
      await this.complete({ kind: 'observed', authorizationVersion: null, recordHash: null })
      return structuredClone(value)
    }))
  }

  /** Atomically commit directory state, authorization versions and an enabled operation-journal completion.
   * @param authority - Fresh external authentication only; stored current roles decide management authority.
   * @param command - Complete command captured before queuing; no browser or producer credential supplies authority.
   * @param expectedRevision - Optimistic directory revision, checked inside the owner queue.
   * @returns Directory revision and count of invalidated retained disclosures. Exact no-ops do not advance versions.
   * All non-tombstone disclosures are conservatively invalidated; notifications follow the same confirmed atomic write.
   * Members losing active status additionally invalidate every confirmed binding, including instances with no disclosures.
   * A rejected write isolates this owner until reopen, including committed-then-rejected outcomes. */
  changeDirectory(authority: FreshRegistryDirectoryAuthority, command: RegistryDirectoryChange,
    expectedRevision: number): Promise<RegistryDirectoryReceipt> {
    const admission = this.input(command)
    if (!admission.accepted) return this.rejectInput('directory-change', null, admission.code)
    const input = admission.value
    return this.enqueue(() => this.audited('directory-change', null, async () => {
      const current = await this.authenticate(authority)
      this.requireOrganization(current.subject.organizationId)
      requireIngest(Number.isSafeInteger(current.now) && current.now >= 0, 'not-found')
      const directory = this.directory()
      this.attributeMember(directorySubject(directory, current.subject))
      requireIngest(this.directoryConfig !== undefined, 'not-found')
      const next = changeDirectory(directory, current.subject, input, expectedRevision, this.directoryConfig)
      const records: { readonly key: string; readonly record: IngestRecord }[] = []
      if (next !== directory) {
        for (const [key, record] of this.table.entries()) {
          if (record.kind === 'tombstone') continue
          const access = this.transition(() => invalidateDisclosureAuthorization(record.access, record.access.authorizationVersion))
          const updated = audit({ ...record, access }, 'access', current.now, this.limits)
          requireIngest(Math.max(byteLength(updated), stopReserveBytes(updated)) <= this.limits.maxAggregateBytes, 'limit')
          this.decode(updated)
          records.push({ key, record: updated })
        }
      }
      const result = { revision: next.revision, invalidatedDisclosures: records.length }
      await this.complete({ kind: 'directory', ...result, changed: next !== directory }, undefined,
        next === directory ? undefined : { state: next, records })
      if (next !== directory) this.directoryMembers = new Map(next.members.map(member => [member.memberId, member]))
      for (const record of records) this.publishInvalidation(record.record)
      if (next !== directory) {
        const activeMembers = new Set(next.members.filter(member => member.state === 'active').map(member => member.memberId))
        const lostMembers = new Set(directory.members.filter(member => member.state === 'active'
          && !activeMembers.has(member.memberId)).map(member => member.memberId))
        for (const [, binding] of this.domain.table('bindings').entries()) {
          if (binding.state.kind === 'confirmed' && lostMembers.has(binding.state.memberId)) this.publishBindingInvalidation(binding)
        }
      }
      return result
    }))
  }

  private directory(): RegistryDirectoryState {
    const directory = this.domain.table('owner').get('organization')?.directory
    requireIngest(directory != null, 'not-found')
    return directory
  }

  /**
   * Register a disclosure owned by the current authenticated source instance.
   * @param authority - Fresh trusted producer authentication, run after earlier writes settle.
   * @param registration - Initial grants and immutable conversation/policy identity.
   * @returns Durable metadata; an exact retry of the unchanged initial record returns its original receipt.
   * A changed, progressed, terminal or deleted identity cannot be registered again or resurrected.
   */
  async register(authority: FreshProducerAuthority, registration: RegistryDisclosureRegistration): Promise<RegistryIngestReceipt> {
    const admission = this.input(registration)
    if (!admission.accepted) return this.rejectInput('register', null, admission.code)
    const input = admission.value
    return this.enqueue(() => this.audited('register', input.access.disclosureId, async () => {
      const current = await this.authenticateProducer(authority)
      const record = this.decode({ kind: 'disclosure', ...input, events: [], checkpoints: [],
        audit: [{ action: 'registered', at: current.connection.now, authorizationVersion: input.access.authorizationVersion }] })
      const active = live(record)
      owns(active, current)
      requireIngest(active.access.control === 'active' && active.access.ingest === 'pending'
        && active.access.checkpointHash === null && active.access.authorizationVersion === 0, 'invalid-input')
      upload(active, current)
      const key = recordKey(active.access.organizationId, active.access.disclosureId)
      const retained = this.table.get(key)
      if (retained !== undefined) {
        owns(retained, current)
        requireIngest(exactPristineRegistration(retained, active), 'conflict')
        const receipt = receiptOf(retained)
        await this.complete({ kind: 'unchanged', authorizationVersion: receipt.authorizationVersion,
          recordHash: null })
        return receipt
      }
      requireIngest(this.table.size < this.limits.maxDisclosures, 'limit')
      requireIngest(stopReserveBytes(active) <= this.limits.maxAggregateBytes, 'limit')
      await this.complete({ kind: 'committed', effect: 'registered', authorizationVersion: 0, recordHash: null }, { key, record: active })
      return receiptOf(active)
    }))
  }

  /** Read source-owned durable synchronization metadata without requiring upload or reader access.
   * @param authority - Fresh current membership, connection and key history from the trusted producer adapter.
   * @param disclosureId - Resource selected within the authenticated organization's source instance.
   * @returns Retained state, stored expiry and trusted observation time, or a deleted identity with no chain acknowledgement.
   * The result is not an authorization lease; every later upload must obtain fresh authority.
   * Missing resources and invalid current authority are uniformly not-found. The disclosure record is unchanged. */
  getSyncStatus(authority: FreshProducerAuthority, disclosureId: DisclosureId): Promise<RegistryProducerSyncStatus> {
    return this.enqueue(() => this.audited('status', disclosureId, async () => {
      const current = await this.authenticateProducer(authority)
      const record = this.table.get(recordKey(current.connection.organizationId, disclosureId))
      requireIngest(record !== undefined, 'not-found')
      owns(record, current)
      const receipt = receiptOf(record)
      await this.complete({ kind: 'observed', authorizationVersion: receipt.authorizationVersion,
        recordHash: receipt.checkpointHash ?? receipt.lastEventHash })
      return record.kind === 'tombstone'
        ? { kind: 'deleted', disclosureId: record.disclosureId, authorizationVersion: record.authorizationVersion }
        : { kind: 'live', expiresAt: record.access.expiresAt, observedAt: current.connection.now, receipt: receiptOf(record) }
    }))
  }

  /**
   * Verify and append one encrypted envelope; authenticated conflicts commit a frozen record before rejecting.
   * @param authority - Current connection and key history, never request-selected.
   * @param disclosureId - Organization-local resource selected independently of envelope fields.
   * @param input - Untrusted JSON envelope; canonical decoded bytes define idempotency.
   * @returns Highest durable contiguous event and currently published checkpoint.
   */
  async ingestEvent(authority: FreshProducerAuthority, disclosureId: DisclosureId, input: unknown): Promise<RegistryIngestReceipt> {
    const admission = this.input(input)
    if (!admission.accepted) return this.rejectInput('event', disclosureId, admission.code)
    const snapshot = admission.value
    return this.mutate('event', authority, disclosureId, (record, current) => {
      const active = live(record)
      upload(active, current)
      const candidate = this.verify(() => decodeDisclosureEventEnvelope(snapshot))
      const previous = active.events.find(receipt => receipt.value.eventId === candidate.eventId)
      const event = this.verifySignature(() => verifyDisclosureEvent(candidate, current.history,
        retryContext(candidate, previous, current.connection)))
      requireIngest(event.disclosureId === disclosureId, 'not-found')
      if (this.activeAudit !== undefined) this.activeAudit.recordHash = event.eventHash
      return appendEvent(active, event, current.connection, this.limits)
    })
  }

  /**
   * Verify a checkpoint and publish only its complete durable prefix.
   * @param authority - Fresh authenticated source connection and Registry-owned key history.
   * @param disclosureId - Organization-local resource, not a payload-selected tenant.
   * @param input - Untrusted signed checkpoint JSON.
   * @returns This request's accepted hash and durable metadata; checkpointHash can select a newer publication.
   * Gaps request retransmission and do not publish partial history.
   */
  async ingestCheckpoint(authority: FreshProducerAuthority, disclosureId: DisclosureId,
    input: unknown): Promise<RegistryCheckpointReceipt> {
    const admission = this.input(input)
    if (!admission.accepted) return this.rejectInput('checkpoint', disclosureId, admission.code)
    const snapshot = admission.value
    const receipt = await this.mutate('checkpoint', authority, disclosureId, (record, current) => {
      const active = live(record)
      upload(active, current)
      const candidate = this.verify(() => decodeDisclosureCheckpoint(snapshot))
      const previous = active.checkpoints.find(receipt => receipt.value.checkpointHash === candidate.checkpointHash)
      const checkpoint = this.verifySignature(() => verifyDisclosureCheckpoint(candidate, current.history,
        retryContext(candidate, previous, current.connection)))
      requireIngest(checkpoint.disclosureId === disclosureId, 'not-found')
      if (this.activeAudit !== undefined) this.activeAudit.recordHash = checkpoint.checkpointHash
      return appendCheckpoint(active, checkpoint, current.connection, this.limits)
    })
    // Successful mutation verified this detached admission snapshot and durably retained its exact checkpoint.
    return { ...receipt, acceptedCheckpointHash: (snapshot as DisclosureCheckpoint).checkpointHash }
  }

  /**
   * Return only the selected signed prefix after current membership, capabilities and device checks.
   * @param authority - Fresh member and source history; the adapter authenticates these facts.
   * @param disclosureId - Resource selected within the subject's organization.
   * @param action - Read or derivation capability being checked; this method does not execute a branch.
   * @param checkpointHash - Exact retained checkpoint; omission selects the latest prefix. A missing selection never falls back.
   * @returns Detached complete prefix, never unconfirmed events; all access denials are not-found.
   */
  read(authority: FreshReaderAuthority, disclosureId: DisclosureId, action: DisclosureAction = 'read',
    checkpointHash?: DisclosureHash): Promise<RegistryConfirmedPrefix> {
    return this.enqueue(() => this.audited('read', disclosureId, async () => {
      const current = await this.authenticateReader(authority)
      this.attributeMember(current.subject)
      const record = this.table.get(recordKey(current.subject.organizationId, disclosureId))
      const prefix = confirmedPrefix(record, current.subject, current.now, action, instanceId => this.readableHistory(
        instanceId, current.now, () => current.history), checkpointHash)
      requireIngest(prefix !== null, 'not-found')
      await this.complete({ kind: 'observed', authorizationVersion: prefix.access.authorizationVersion, recordHash: prefix.checkpoint.checkpointHash })
      return structuredClone({ authorizationVersion: prefix.access.authorizationVersion,
        conversationId: brandString<DisclosureConversationId>(prefix.conversationId),
        checkpoint: prefix.checkpoint, events: prefix.events.map(receipt => receipt.value) })
    }))
  }

  /** Return one selected prefix using the same organization-scoped resolver snapshot as metadata reads.
   * The caller-selected source instance is rechecked against the retained disclosure inside this owner operation. */
  readWithResolver(authority: FreshRegistryMetadataAuthority, disclosureId: DisclosureId,
    expectedSourceInstanceId: DshInstanceId, action: Extract<DisclosureAction, 'read' | 'import' | 'ask'>,
    checkpointHash: DisclosureHash): Promise<RegistryConfirmedPrefix> {
    return this.enqueue(() => this.audited('read', disclosureId, async () => {
      const current = await this.authenticateReader(authority)
      this.attributeMember(current.subject)
      const record = this.table.get(recordKey(current.subject.organizationId, disclosureId))
      requireIngest(record?.kind === 'disclosure' && record.access.instanceId === expectedSourceInstanceId, 'not-found')
      const prefix = confirmedPrefix(record, current.subject, current.now, action,
        instanceId => this.readableHistory(instanceId, current.now, () => current.historyFor(instanceId)), checkpointHash)
      requireIngest(prefix !== null, 'not-found')
      await this.complete({ kind: 'observed', authorizationVersion: prefix.access.authorizationVersion,
        recordHash: prefix.checkpoint.checkpointHash })
      return structuredClone({ authorizationVersion: prefix.access.authorizationVersion,
        conversationId: brandString<DisclosureConversationId>(prefix.conversationId),
        checkpoint: prefix.checkpoint, events: prefix.events.map(receipt => receipt.value) })
    }))
  }

  /** Read only metadata after the same current authorization and full signature checks as read().
   * @param authority - Fresh trusted member and source-key snapshot.
   * @param disclosureId - Resource selected within that member's organization.
   * @param options - Trusted complete-response byte limit and optional exact checkpoint selection.
   * @returns Body-free selected-prefix metadata; inaccessible resources are uniformly not-found. */
  async readMetadata(authority: FreshReaderAuthority, disclosureId: DisclosureId,
    options: RegistryMetadataReadOptions): Promise<RegistryDisclosureMetadata> {
    const admission = this.input(options, (input) => { this.positive(input.maxResponseBytes) })
    if (!admission.accepted) return this.rejectInput('metadata-read', disclosureId, admission.code)
    const input = admission.value
    return this.enqueue(() => this.audited('metadata-read', disclosureId, async () => {
      const current = await this.authenticateReader(authority)
      this.attributeMember(current.subject)
      const record = this.table.get(recordKey(current.subject.organizationId, disclosureId))
      const prefix = confirmedPrefix(record, current.subject, current.now, 'read', instanceId => this.readableHistory(
        instanceId, current.now, () => current.history), input.checkpointHash)
      requireIngest(prefix !== null, 'not-found')
      const metadata = this.boundedMetadata(metadataOf(prefix, current.subject, current.now), input.maxResponseBytes)
      await this.complete({ kind: 'observed', authorizationVersion: metadata.authorizationVersion, recordHash: metadata.checkpoint.checkpointHash })
      return metadata
    }))
  }

  /** Read point metadata with an organization-scoped source-key resolver and one selected action.
   * @param authority - Fresh trusted member, clock and synchronous source-key resolver snapshot.
   * @param disclosureId - Resource selected within that member's organization.
   * @param action - Read, import or ask authorization required for this point observation.
   * @param options - Trusted complete-response byte limit and optional exact checkpoint selection.
   * @returns Body-free selected-prefix metadata and effective actions from the same authority snapshot. */
  async readMetadataWithResolver(authority: FreshRegistryMetadataAuthority, disclosureId: DisclosureId,
    action: Extract<DisclosureAction, 'read' | 'import' | 'ask'>,
    options: RegistryMetadataReadOptions): Promise<RegistryDisclosureMetadata> {
    const admission = this.input(options, (input) => { this.positive(input.maxResponseBytes) })
    if (!admission.accepted) return this.rejectInput('metadata-read', disclosureId, admission.code)
    const input = admission.value
    return this.enqueue(() => this.audited('metadata-read', disclosureId, async () => {
      const current = await this.authenticateReader(authority)
      this.attributeMember(current.subject)
      const record = this.table.get(recordKey(current.subject.organizationId, disclosureId))
      const prefix = confirmedPrefix(record, current.subject, current.now, action,
        instanceId => this.readableHistory(instanceId, current.now, () => current.historyFor(instanceId)), input.checkpointHash)
      requireIngest(prefix !== null, 'not-found')
      const metadata = this.boundedMetadata(metadataOf(prefix, current.subject, current.now), input.maxResponseBytes)
      await this.complete({ kind: 'observed', authorizationVersion: metadata.authorizationVersion,
        recordHash: metadata.checkpoint.checkpointHash })
      return metadata
    }))
  }

  /** List only currently readable metadata; every page scans the bounded store and rechecks signatures.
   * @param authority - One current subject/clock snapshot with a synchronous organization-scoped key resolver.
   * @param options - Requested page size/cursor and trusted maximum page/output bounds.
   * @returns ID-ordered authorized rows and an owner-local anchor only when another authorized row exists.
   * No total, hidden-row continuation, plaintext, or snapshot guarantee is provided. */
  async listMetadata(authority: FreshRegistryMetadataAuthority, options: RegistryMetadataListOptions): Promise<RegistryMetadataPage> {
    const admission = this.input(options, (input) => {
      this.positive(input.pageSize)
      this.positive(input.maxPageSize)
      this.positive(input.maxResponseBytes)
      requireIngest(input.pageSize <= input.maxPageSize, 'limit')
    })
    if (!admission.accepted) return this.rejectInput('metadata-list', null, admission.code)
    const input = admission.value
    return this.enqueue(() => this.audited('metadata-list', null, async () => {
      const current = await this.authenticateReader(authority)
      this.attributeMember(current.subject)
      requireIngest(current.subject.authenticated && current.subject.membership === 'active' && Number.isFinite(current.now), 'not-found')
      const anchor = input.cursor === undefined ? null : this.metadataCursor.open(current.subject, input.cursor)
      const candidates: DisclosureId[] = []
      for (const [, record] of this.table.entries()) {
        if (record.kind === 'disclosure' && (anchor === null || record.access.disclosureId > anchor)) candidates.push(record.access.disclosureId)
      }
      candidates.sort()
      const readable: RegistryDisclosureMetadata[] = []
      // Open/register enforce maxDisclosures; each prefix has at most maxEvents and maxCheckpoints receipts.
      for (const disclosureId of candidates) {
        const record = this.table.get(recordKey(current.subject.organizationId, disclosureId))
        const prefix = confirmedPrefix(record, current.subject, current.now, 'read',
          instanceId => this.readableHistory(instanceId, current.now, () => current.historyFor(instanceId)))
        if (prefix !== null) {
          readable.push(metadataOf(prefix, current.subject, current.now))
          if (readable.length > input.pageSize) break
        }
      }
      const items = readable.slice(0, input.pageSize)
      // Positive pageSize and an additional readable row guarantee a last returned item.
      const nextCursor = readable.length > input.pageSize
        ? this.metadataCursor.seal(current.subject, (items.at(-1) as RegistryDisclosureMetadata).disclosureId) : null
      const page = this.boundedMetadata({ items, nextCursor }, input.maxResponseBytes)
      await this.complete({ kind: 'observed', authorizationVersion: null, recordHash: null })
      return page
    }))
  }

  /**
   * Replace explicit reader grants as the authenticated source owner.
   * @param authority - Fresh source-owner authentication.
   * @param disclosureId - Resource within the authenticated organization.
   * @param update - Replacement expiry, grants and capabilities.
   * @param expectedVersion - Optimistic authorization version, rechecked inside atomic update.
   * @returns Durable access metadata with its new version.
   */
  async updateAccess(authority: FreshProducerAuthority, disclosureId: DisclosureId,
    update: DisclosureAccessUpdate, expectedVersion: number): Promise<RegistryIngestReceipt> {
    const admission = this.input(update)
    if (!admission.accepted) return this.rejectInput('access', disclosureId, admission.code)
    const snapshot = admission.value
    return this.mutate('access', authority, disclosureId, (record, current) => {
      const active = live(record)
      requireIngest(active.access.authorizationVersion === expectedVersion, 'version-conflict')
      const next = this.transition(() => updateDisclosureAccess(active.access, snapshot, expectedVersion, current.connection.now))
      return { record: next === active.access ? active : audit({ ...active, access: next }, 'access', current.connection.now, this.limits) }
    })
  }

  /**
   * Reject an access update that a trusted Host wrapper could not snapshot before this owner was entered.
   * @param disclosureId - Owner-selected resource identifier; no rejected payload, exception, action, code or actor is accepted.
   * @returns A promise that rejects after admitted audit work; closure, capacity or journal failure may take precedence.
   * This narrow adapter hook never requests authority, reads a disclosure or publishes invalidation.
   */
  rejectAccessInput(disclosureId: DisclosureId): Promise<never> {
    return this.rejectInput('access', disclosureId, 'invalid-input')
  }

  /** Reject a directory command that a trusted Host wrapper could not copy before queuing.
   * @returns A rejection after optional journal completion; closure, capacity or persistence failure may take precedence.
   * No payload, exception, actor or authority is accepted, and no directory mutation or invalidation occurs. */
  rejectDirectoryInput(): Promise<never> {
    return this.rejectInput('directory-change', null, 'invalid-input')
  }

  /** Record a Host proof-copy failure without retaining caller data or asserting device possession.
   * @returns A queued rejection; closure, journal capacity or persistence failure can take precedence. */
  rejectBindingProofInput(): Promise<never> {
    return this.rejectInput('binding-confirm', null, 'invalid-input')
  }

  /** Record a Host enrollment-request copy failure without retaining caller data.
   * @returns A queued rejection subject to closure, journal capacity and storage availability. */
  rejectBindingStartInput(): Promise<never> {
    return this.rejectInput('binding-start', null, 'invalid-input')
  }

  /**
   * Change upload/read control without erasing confirmed history; deletion uses delete instead.
   * @param authority - Fresh authenticated source owner.
   * @param disclosureId - Organization-local disclosure.
   * @param target - Requested non-deleted control state.
   * @param expectedVersion - Version checked in the atomic update.
   * @returns Durable control metadata; terminal states cannot reactivate.
   */
  transitionControl(authority: FreshProducerAuthority, disclosureId: DisclosureId, target: Exclude<DisclosureControlState, 'deleted'>, expectedVersion: number): Promise<RegistryIngestReceipt> {
    return this.mutate('control', authority, disclosureId, (record, current) => {
      const active = live(record)
      requireIngest(active.access.authorizationVersion === expectedVersion, 'version-conflict')
      const next = this.transition(() => transitionDisclosureControl(active.access, target, expectedVersion, current.connection.now))
      return { record: next === active.access ? active : audit({ ...active, access: next }, 'control', current.connection.now, this.limits),
        safetyStop: next.control !== 'active' }
    })
  }

  /**
   * Erase every ciphertext and source field held by this package in one atomic tombstone replacement.
   * @param authority - Fresh authenticated source owner; a revoked device cannot delete evidence.
   * @param disclosureId - Organization-local disclosure.
   * @param expectedVersion - Current version; exact tombstone retries are idempotent.
   * @returns Deleted metadata; backend backups, exported copies and physical media erasure are outside this library.
   */
  delete(authority: FreshProducerAuthority, disclosureId: DisclosureId, expectedVersion: number): Promise<RegistryIngestReceipt> {
    return this.mutate('delete', authority, disclosureId, (record, current) => {
      if (record.kind === 'tombstone') {
        requireIngest(record.authorizationVersion === expectedVersion, 'version-conflict')
        return { record, safetyStop: true }
      }
      requireIngest(record.access.authorizationVersion === expectedVersion, 'version-conflict')
      return this.deletion(record, current.connection.now, 'revoked')
    })
  }

  /** Process one organization's durable retired/expired queue without relying on an online source device.
   * @param options - Trusted server organization, clock, batch bound and admission cancellation.
   * @returns Only committed deletions and whether eligible work remains; repeated batches skip tombstones.
   * @throws RegistryIngestError; uncertain I/O isolates the owner, and committed earlier items are not rolled back.
   * Invalid bounds or cancellation handles are rejected before disclosure selection and retain no caller data.
   * A foreign organization is rejected before selection and, when configured, journaled without its identifier.
   * This erases only this package's aggregate, not local copies, replies, other stores or backups.
   * Version exhaustion is a deterministic invalid-transition failure, not a retryable storage failure. */
  async processDeletionBatch(options: RegistryDeletionBatchOptions): Promise<RegistryDeletionBatchReceipt> {
    const admission = this.deletionBatchInput(options)
    if (!admission.accepted) return this.rejectInput('delete', null, admission.code)
    const { organizationId, now, maxItems, cancelled } = admission.value
    return this.enqueue(async () => {
      if (organizationId !== this.organizationId) {
        // Keep the owner-queue lifecycle and journal precedence without retaining the caller organization in the record.
        return this.audited('delete', null, () => Promise.reject(new RegistryIngestError('not-found')))
      }
      let deleted = 0
      for (const [key, record] of this.table.entries()) {
        if (!this.pendingDeletion(record, now)) continue
        if (deleted === maxItems || cancelled()) return { deleted, hasMore: true }
        await this.audited('delete', live(record).access.disclosureId, async () => {
          if (this.activeAudit !== undefined) this.activeAudit.actor = { kind: 'maintenance', organizationId }
          return this.updateRecord('delete', key, current => this.deletion(live(current), now, 'expired'))
        })
        deleted += 1
      }
      return { deleted, hasMore: false }
    })
  }

  private pendingDeletion(record: IngestRecord, now: number): boolean {
    return record.kind === 'disclosure'
      && (record.access.control === 'revoked' || record.access.control === 'expired' || record.access.control === 'deleting'
        || ((record.access.control === 'active' || record.access.control === 'paused') && now >= record.access.expiresAt))
  }

  private deletion(record: LiveRecord, now: number, initial: 'revoked' | 'expired'): Mutation {
    let access = record.access
    if (access.control === 'active' || access.control === 'paused') {
      access = this.transition(() => transitionDisclosureControl(access, initial, access.authorizationVersion, now))
    }
    if (access.control === 'revoked' || access.control === 'expired') {
      access = this.transition(() => transitionDisclosureControl(access, 'deleting', access.authorizationVersion, now))
    }
    access = this.transition(() => transitionDisclosureControl(access, 'deleted', access.authorizationVersion, now))
    return { safetyStop: true, record: { kind: 'tombstone', organizationId: access.organizationId, disclosureId: access.disclosureId,
      instanceId: access.instanceId, authorizationVersion: access.authorizationVersion,
      audit: [{ action: 'deleted', at: now, authorizationVersion: access.authorizationVersion }] } }
  }

  /** Stop admission, drain accepted work and release the domain; a fresh open revalidates uncertain storage.
   * @returns Settlement after the domain is closed; repeated closes share one promise. */
  close(): Promise<void> {
    this.closing = true
    this.disposal ??= this.chain.then(async () => {
      try { await this.domain.close(); this.metadataCursor.close() } finally {
        this.invalidations.clear()
        this.auditCompletions.clear()
        this.bindingInvalidations.clear()
      }
    })
    return this.disposal
  }

  /** Observe confirmed authorization-version changes from this owner without reading grants or content.
   * @param listener - Trusted server observer, invoked synchronously after a confirmed commit; returned promises are not awaited.
   * Failures are contained with a fixed diagnostic. This subscription grants no resource access and replays no history.
   * @returns Idempotent disposer preventing later callback starts; already-started asynchronous work is not cancelled.
   * New subscriptions do not join an active publication, and removal before a callback starts skips that callback.
   * Closure drains accepted writes before clearing subscriptions; closed or uncertain owners reject new subscriptions. */
  subscribeInvalidation(listener: (event: RegistryDisclosureInvalidation) => void | Promise<void>): () => void {
    requireIngest(!this.closing, 'closed')
    requireIngest(!this.unavailable, 'storage-unavailable')
    const subscription = { listener }
    this.invalidations.add(subscription)
    return () => { this.invalidations.delete(subscription) }
  }

  /** Observe committed instance-binding revocation or loss of its approving membership, even without a journal.
   * @param listener - Receives only immutable organization and instance IDs; failures are contained.
   * @returns Idempotent disposer. No history is replayed; close drains writes and removes listeners.
   * Listeners are invoked synchronously after commit; returned promises are not awaited. */
  subscribeBindingInvalidation(listener: (event: RegistryBindingInvalidation) => void | Promise<void>): () => void {
    requireIngest(!this.closing, 'closed')
    requireIngest(!this.unavailable, 'storage-unavailable')
    const subscription = { listener }
    this.bindingInvalidations.add(subscription)
    return () => { this.bindingInvalidations.delete(subscription) }
  }

  /** Check producer identity for connection admission or heartbeat without selecting a disclosure.
   * @param authority - Fresh external authentication inside the caller's active connection lease.
   * @returns Settlement after current key, membership and configured binding checks; grants no reusable authority.
   * Connection admission is not an audited disclosure operation. */
  verifyProducer(authority: FreshProducerAuthority): Promise<void> {
    return this.enqueue(async () => { await this.authenticateProducer(authority) })
  }

  /** Check that the current device still owns any confirmed active binding before admitting a command stream.
   * @param authority - Fresh external authentication inside the caller's active connection lease.
   * @returns Settlement after current key, membership and binding checks; grants no operation scope. */
  verifyConnection(authority: FreshProducerAuthority): Promise<void> {
    return this.enqueue(async () => { await this.authenticateConnection(authority) })
  }

  /** Check the current device's confirmed `a2a.receive` scope before delivering a Registry-owned command.
   * @param authority - Fresh external authentication inside the caller's active connection lease.
   * @returns Settlement after current key, membership, binding and receiver-scope checks. */
  verifyReceiver(authority: FreshProducerAuthority): Promise<void> {
    return this.enqueue(async () => { await this.authenticateConnection(authority, 'a2a.receive') })
  }

  /** Resolve a device-only secret commitment to current confirmed authority inside the binding owner queue.
   * Both hashes must come from the same presented raw secret; V6 uses the bridge-domain hash to reject reuse.
   * This is transport-provider input, never a browser review or reusable authorization snapshot. */
  authenticateBindingCredential(bindingId: RegistryBindingId,
    presentedHash: RegistryDeviceSecretHash,
    sameRawBridgeHash: RegistryBridgeSecretHash): Promise<RegistryProducerAuthority> {
    return this.enqueue(async () => {
      const bindingConfig = this.bindingConfig
      requireIngest(bindingConfig !== undefined, 'not-found')
      const record = this.binding(bindingId)
      requireIngest(record.challenge.organizationId === this.organizationId, 'not-found')
      const state = record.state
      requireIngest(state.kind === 'confirmed', 'not-found')
      const member = this.directoryMembers.get(state.memberId)
      requireIngest(member !== undefined, 'not-found')
      return structuredClone(resolveBindingCredential(record, member, presentedHash, sameRawBridgeHash,
        Date.now(), bindingConfig.audience))
    })
  }

  /** Resolve a v6 dshb1 bearer in O(1) binding lookup for one HTTPS bridge request.
   * Both hashes must come from the same presented raw secret; the device-domain hash rejects reuse. The
   * confirmed state, active member, tenant, instance and disclosure.sync scope are also rechecked. */
  authenticateBridgeCredential(bindingId: RegistryBindingId,
    presentedHash: RegistryBridgeSecretHash,
    sameRawDeviceHash: RegistryDeviceSecretHash): Promise<RegistryBridgeAuthority> {
    return this.enqueue(async () => {
      const bindingConfig = this.bindingConfig
      requireIngest(bindingConfig !== undefined, 'not-found')
      const record = this.binding(bindingId)
      requireIngest(record.bindingId === bindingId && record.challenge.organizationId === this.organizationId
        && record.requestedScopes.includes('disclosure.sync'), 'not-found')
      const state = record.state
      requireIngest(state.kind === 'confirmed', 'not-found')
      const member = this.directoryMembers.get(state.memberId)
      requireIngest(member !== undefined, 'not-found')
      const producer = resolveBridgeCredential(record, member, presentedHash, sameRawDeviceHash,
        Date.now(), bindingConfig.audience)
      const { organizationId, instanceId } = producer.connection
      requireIngest(organizationId === this.organizationId && instanceId === record.challenge.instanceId, 'not-found')
      return structuredClone({ bindingId, organizationId, instanceId, memberId: member.memberId, producer })
    })
  }

  /** Observe confirmed journal completions for trusted server diagnostics; no history is replayed.
   * @param listener - Administrative consumer receiving immutable metadata only after durable completion.
   * Returned promises are not awaited, and failures cannot reverse the operation or skip other observers.
   * @returns Idempotent disposer preventing later callback starts, not cancelling already-started work.
   * An absent journal emits nothing. Closure drains admitted writes before clearing listeners;
   * closed or uncertain owners refuse new subscriptions. This method grants no browser or reader authority. */
  subscribeAudit(listener: (record: RegistryAuditRecord) => void | Promise<void>): () => void {
    requireIngest(!this.closing, 'closed')
    requireIngest(!this.unavailable, 'storage-unavailable')
    const subscription = { listener }
    this.auditCompletions.add(subscription)
    return () => { this.auditCompletions.delete(subscription) }
  }

  /** Inspect retained operation metadata from this exclusively owned server handle.
   * @returns A detached snapshot, including unfinished attempts; no reader or transport route exposes this method.
   * Callers must provide their own administrative authorization. Uncertain owners refuse inspection until reopen. */
  inspectAudit(): readonly RegistryAuditRecord[] {
    requireIngest(!this.unavailable, 'storage-unavailable')
    return structuredClone([...this.journalTable.entries()].map(([, record]) => record))
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    if (this.closing) return Promise.reject(new RegistryIngestError('closed'))
    const result = this.chain.then(() => {
      requireIngest(!this.unavailable, 'storage-unavailable')
      return operation()
    })
    this.chain = result.then(() => {}, () => { /* The caller receives the failure; queued operations still observe isolation. */ })
    return result
  }

  private mutate(action: MutationAction, authority: FreshProducerAuthority, disclosureId: DisclosureId,
    transform: (record: IngestRecord, authority: RegistryProducerAuthority) => Mutation): Promise<RegistryIngestReceipt> {
    return this.enqueue(() => this.audited(action, disclosureId, async () => {
      const current = await this.authenticateProducer(authority)
      const key = recordKey(current.connection.organizationId, disclosureId)
      return this.updateRecord(action, key, (record) => {
        owns(record, current)
        return transform(record, current)
      })
    }))
  }

  private async updateRecord(action: MutationAction, key: string,
    transform: (record: IngestRecord) => Mutation): Promise<RegistryIngestReceipt> {
    const previous = this.table.get(key)
    requireIngest(previous !== undefined, 'not-found')
    let mutation: Mutation
    let safetyStop = false
    try {
      mutation = transform(previous)
      safetyStop = mutation.safetyStop === true
      if (safetyStop) {
        mutation = { ...mutation, record: fitStopRecord(mutation.record, this.limits.maxAggregateBytes) }
      } else if (mutation.record !== previous) {
        requireIngest(Math.max(byteLength(mutation.record), stopReserveBytes(mutation.record)) <= this.limits.maxAggregateBytes, 'limit')
      }
      this.decode(mutation.record)
    } catch (error) {
      if (safetyStop) {
        this.unavailable = true
        throw new RegistryIngestError('storage-unavailable')
      }
      throw error
    }
    const receipt = receiptOf(mutation.record)
    const priorReceipt = receiptOf(previous)
    const metadata = { authorizationVersion: receipt.authorizationVersion,
      recordHash: this.activeAudit?.recordHash ?? priorReceipt.checkpointHash ?? priorReceipt.lastEventHash }
    const outcome: RegistryAuditOutcome = mutation.record === previous ? { kind: 'unchanged', ...metadata }
      : { kind: 'committed', effect: mutation.error === undefined ? (action === 'delete' ? 'deleted' : action) : 'frozen', ...metadata }
    await this.complete(outcome, { key, record: mutation.record })
    if (receipt.authorizationVersion !== priorReceipt.authorizationVersion) this.publishInvalidation(mutation.record)
    if (mutation.error !== undefined) throw new RegistryIngestError(mutation.error)
    return receipt
  }

  private publishBindingInvalidation(binding: RegistryBindingRecord): void {
    const event = Object.freeze({ organizationId: this.organizationId, instanceId: binding.challenge.instanceId })
    for (const subscription of [...this.bindingInvalidations]) {
      if (!this.bindingInvalidations.has(subscription)) continue
      try { void Promise.resolve(subscription.listener(event)).catch(reportInvalidationListenerFailure) }
      catch { reportInvalidationListenerFailure() }
    }
  }

  /** Remove at most one expired, never-confirmed attempt before admitting a replacement.
   * Each delete is durable and serialized; failure isolates the owner before a new attempt exists. */
  private async pruneOneExpiredBinding(now: number): Promise<void> {
    const table = this.domain.table('bindings')
    const expired = [...table.entries()]
      .filter(([, record]) => record.state.kind !== 'confirmed' && record.state.kind !== 'revoked'
        && record.challenge.expiresAt <= now)
      .sort((left, right) => left[1].challenge.expiresAt - right[1].challenge.expiresAt
        || (left[0] < right[0] ? -1 : left[0] > right[0] ? 1 : 0))[0]
    if (expired === undefined) return
    await this.durable(async () => {
      if (!await table.delete(expired[0])) throw new Error('expired Registry binding disappeared during serialized cleanup')
    })
  }

  private publishInvalidation(record: IngestRecord): void {
    const identity = record.kind === 'disclosure' ? record.access : record
    const event: RegistryDisclosureInvalidation = Object.freeze({ organizationId: this.organizationId,
      instanceId: identity.instanceId, disclosureId: identity.disclosureId, authorizationVersion: identity.authorizationVersion })
    for (const subscription of [...this.invalidations]) {
      if (!this.invalidations.has(subscription)) continue
      try {
        void Promise.resolve(subscription.listener(event)).catch(reportInvalidationListenerFailure)
      } catch {
        reportInvalidationListenerFailure()
      }
    }
  }

  private async audited<T>(action: RegistryAuditAction, disclosureId: DisclosureId | null, operation: () => Promise<T>): Promise<T> {
    if (this.journal === undefined) return operation()
    requireIngest(this.journalTable.size < this.journal.config.maxOperations, 'limit')
    const attempt = createAuditAttempt(this.organizationId, action, disclosureId, Date.now(), this.journal.config)
    await this.durable(() => this.journalTable.put(attempt.operationId, attempt))
    const active: ActiveAudit = { attempt, journal: this.journal, actor: { kind: 'unattributed' },
      completed: false, recordHash: null, signatureFailure: false }
    this.activeAudit = active
    try {
      return await operation()
    } catch (error) {
      if (!active.completed && !this.unavailable) {
        const code = error instanceof RegistryIngestError ? error.code : 'invalid-input'
        await this.complete({ kind: 'rejected', code, ...(active.signatureFailure ? { category: 'signature-failure' as const } : {}) })
      }
      throw error instanceof RegistryIngestError ? error : new RegistryIngestError('invalid-input')
    } finally {
      this.activeAudit = undefined
    }
  }

  private async complete(outcome: RegistryAuditOutcome, write?: { readonly key: string; readonly record: IngestRecord },
    directory?: { readonly state: RegistryDirectoryState
      readonly records: readonly { readonly key: string; readonly record: IngestRecord }[] },
    binding?: RegistryBindingRecord): Promise<void> {
    const active = this.activeAudit
    const writes: DomainRecordWrite<ReturnType<typeof specification>>[] = []
    if (binding !== undefined) {
      requireIngest(this.bindingConfig !== undefined, 'not-found')
      requireIngest(byteLength(binding) <= this.bindingConfig.maxRecordBytes, 'limit')
      writes.push({ table: 'bindings', key: binding.bindingId, value: parseBinding(binding, this.bindingConfig) })
    }
    if (write !== undefined) writes.push({ table: 'disclosures', key: write.key, value: write.record })
    if (directory !== undefined) {
      writes.push({ table: 'owner', key: 'organization', value: { organizationId: this.organizationId, directory: directory.state } })
      for (const item of directory.records) writes.push({ table: 'disclosures', key: item.key, value: item.record })
    }
    if (active === undefined) {
      if (directory !== undefined || binding !== undefined) {
        const putMany = this.domain.putMany?.bind(this.domain)
        requireIngest(putMany !== undefined, 'invalid-storage')
        await this.durable(() => putMany(writes))
      } else if (write !== undefined) await this.durable(() => this.table.put(write.key, write.record))
      return
    }
    const completed = completeAuditAttempt(active.attempt,
      { completedAt: Date.now(), actor: active.actor, outcome }, active.journal.config)
    await this.durable(() => active.journal.putMany([
      ...writes,
      { table: 'audit', key: completed.operationId, value: completed },
    ]))
    active.completed = true
    for (const subscription of [...this.auditCompletions]) {
      if (!this.auditCompletions.has(subscription)) continue
      try {
        void Promise.resolve(subscription.listener(completed)).catch(reportAuditListenerFailure)
      } catch { reportAuditListenerFailure() }
    }
  }

  private readableHistory(instanceId: DshInstanceId, now: number,
    external: () => InstanceKeyHistory | null): InstanceKeyHistory | null {
    if (this.bindingConfig === undefined) return external()
    return this.currentBindingHistory(instanceId, now, 'disclosure.sync', external)
  }

  private currentBindingHistory(instanceId: DshInstanceId, now: number,
    requiredScope?: RegistryBindingScope, external?: () => InstanceKeyHistory | null): InstanceKeyHistory | null {
    const bindingConfig = this.bindingConfig
    if (bindingConfig === undefined) return null
    const matches = [...this.domain.table('bindings').entries()]
      .map(([, record]) => record).filter(record => record.challenge.instanceId === instanceId)
    if (matches.length !== 1) return null
    const binding = matches[0]
    if (binding === undefined) return null
    const state = binding.state
    if (state.kind !== 'confirmed') return null
    const members = this.directory().members.filter(member => member.memberId === state.memberId)
    if (members.length !== 1 || members[0] === undefined) return null
    try {
      const legacyHistory = binding.version === 4 ? external?.() : undefined
      return confirmedBindingHistory(binding, members[0], this.organizationId, now,
        bindingConfig.audience, requiredScope, legacyHistory)
    } catch { return null }
  }

  private async authenticateProducer(authority: FreshProducerAuthority): Promise<RegistryProducerAuthority> {
    return this.authenticateConnection(authority, 'disclosure.sync')
  }

  private async authenticateConnection(authority: FreshProducerAuthority,
    requiredScope?: RegistryBindingScope): Promise<RegistryProducerAuthority> {
    let current = await this.authenticate(authority)
    this.requireOrganization(current.connection.organizationId)
    producer(current)
    if (this.bindingConfig !== undefined) {
      const history = this.currentBindingHistory(current.connection.instanceId, current.connection.now,
        requiredScope, () => current.history)
      requireIngest(history !== null, 'not-found')
      const bindingKey = history.keys.find(key => key.keyId === current.connection.keyId)
      const key = current.history.keys.find(key => key.keyId === current.connection.keyId)
      requireIngest(bindingKey !== undefined && key !== undefined
        && key.keyId === bindingKey.keyId && key.publicKeySpki === bindingKey.publicKeySpki, 'not-found')
      current = { connection: current.connection, history }
    }
    if (this.activeAudit !== undefined) {
      const { organizationId, instanceId, keyId } = current.connection
      this.activeAudit.actor = { kind: 'producer', organizationId, instanceId, keyId }
    }
    return current
  }

  private async authenticateReader<T extends { readonly subject: DisclosureSubject }>(authority: () => T | Promise<T>): Promise<T> {
    const current = await this.authenticate(authority)
    this.requireOrganization(current.subject.organizationId)
    return this.directoryConfig === undefined ? current
      : { ...current, subject: directorySubject(this.directory(), current.subject) }
  }

  private attributeMember(subject: DisclosureSubject): void {
    this.requireOrganization(subject.organizationId)
    if (this.activeAudit !== undefined && subject.authenticated) {
      this.activeAudit.actor = { kind: 'member', organizationId: subject.organizationId, memberId: subject.memberId }
    }
  }

  private requireOrganization(organizationId: OrganizationId): void {
    requireIngest(organizationId === this.organizationId, 'not-found')
  }

  private async durable(write: () => Promise<void>): Promise<void> {
    try {
      await write()
    } catch {
      // A backend may commit and then reject; stale in-memory state must not serve another request.
      this.unavailable = true
      throw new RegistryIngestError('storage-unavailable')
    }
  }

  private async authenticate<T>(authority: () => T | Promise<T>): Promise<T> {
    try {
      return await authority()
    } catch {
      // Session/device lookup failures provide no authenticated identity and disclose no adapter diagnostics.
      throw new RegistryIngestError('not-found')
    }
  }

  private input<T>(value: T, validate?: (snapshot: T) => void): InputAdmission<T> {
    try {
      requireIngest(byteLength(value) <= this.limits.maxInputBytes, 'limit')
      const snapshot = structuredClone(value)
      validate?.(snapshot)
      return { accepted: true, value: snapshot }
    } catch (error) {
      // Failed snapshots and their exceptions may retain caller data; only the fixed code leaves admission.
      return { accepted: false, code: error instanceof RegistryIngestError ? error.code : 'invalid-input' }
    }
  }

  private deletionBatchInput(options: RegistryDeletionBatchOptions): InputAdmission<DeletionBatchInput> {
    try {
      // Capture primitives once; queued checks call only the platform getter, never caller-overridable properties.
      const organizationId = options.organizationId
      const now = options.now
      const maxItems = options.maxItems
      const signal = options.signal
      requireIngest(Number.isSafeInteger(now) && now >= 0, 'invalid-input')
      this.positive(maxItems)
      if (signal === undefined) return { accepted: true, value: { organizationId, now, maxItems, cancelled: () => false } }
      const aborted = abortState(signal)
      requireIngest(typeof aborted === 'boolean', 'invalid-input')
      return { accepted: true, value: { organizationId, now, maxItems, cancelled: () => {
        try { return abortState(signal) === true } catch { return true }
      } } }
    } catch {
      // Rejected options and getter diagnostics may retain caller data; only the fixed code leaves admission.
      return { accepted: false, code: 'invalid-input' }
    }
  }

  private rejectInput(action: RegistryAuditAction, disclosureId: DisclosureId | null, code: RegistryIngestErrorCode): Promise<never> {
    if (this.journal === undefined) return Promise.reject(new RegistryIngestError(code))
    // No failed input or original exception enters this queued closure, and no authority is requested.
    return this.enqueue(() => this.audited(action, disclosureId, () => Promise.reject(new RegistryIngestError(code))))
  }

  private positive(value: number): void {
    requireIngest(Number.isSafeInteger(value) && value > 0, 'invalid-input')
  }

  private boundedMetadata<T>(value: T, maximum: number): T {
    requireIngest(byteLength(value) <= maximum, 'limit')
    return value
  }

  private decode(value: unknown): IngestRecord {
    return this.verify(() => parseRecord(value, this.limits))
  }

  private verify<T>(operation: () => T): T {
    try {
      return operation()
    } catch (error) {
      if (error instanceof RegistryIngestError) throw error
      throw new RegistryIngestError('invalid-input')
    }
  }

  private verifySignature<T>(operation: () => T): T {
    try {
      return operation()
    } catch (error) {
      // Only the serialized upload's cryptographic verification can attribute this audit fact.
      if (error instanceof InstanceSignatureError && this.activeAudit !== undefined) this.activeAudit.signatureFailure = true
      throw new RegistryIngestError('invalid-input')
    }
  }

  private transition<T>(operation: () => T): T {
    try {
      return operation()
    } catch {
      // Domain diagnostics remain internal; callers receive one transition category.
      throw new RegistryIngestError('invalid-transition')
    }
  }
}
