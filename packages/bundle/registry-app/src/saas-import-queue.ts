/** Tenant-owned durable context-import queue delivered only to authenticated Registry Sync receivers. */
import { createHash } from 'node:crypto'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { RegistryConnectionAuthority } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import { RegistryIngestError, type FreshRegistryMetadataAuthority,
  type RegistryIngestStorageScope } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryImportDelivery, RegistryImportOutcome } from '@deepseek-ai/dsh-a2a-registry-sync'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { defineDomain, domainTable, type Domain, type DomainFacility, type KvTable } from '@deepseek-ai/dsh-storage-domain'
import { z } from 'zod'
import type { RegistryImportBroker } from './import-broker.ts'
import type { RegistryDisclosureReader } from './reader.ts'
import type { RegistryRuntimeStore } from './runtime-store.ts'
import type { RegistryTenantRuntimeRouter } from './tenant-runtime-router.ts'
import type { RegistryDisclosureImportResult, RegistryDisclosureOperations,
  RegistryDisclosureOperationSelection, RegistryImportOperationId,
  RegistryImportedSessionId } from './operations.ts'

const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u

/** Explicit per-organization queue bounds. No completed or failed record is silently evicted. */
export interface RegistrySaasImportQueueConfig {
  readonly maxOperations: number
  readonly maxRecordBytes: number
  readonly maxAuthorizationResponseBytes: number
  /** Maximum UTF-8 JSON bytes of the delivery object before the WSS frame envelope is added. */
  readonly maxDeliveryBytes: number
  /** Maximum target-side WSS processing time before the connection is failed and work remains queued. */
  readonly deliveryTimeoutMs: number
}

const commonRecord = {
  operationId: z.string().regex(IDENTIFIER),
  requestHash: z.string().regex(/^[0-9a-f]{64}$/u),
  organizationId: z.string().regex(IDENTIFIER),
  memberId: z.string().regex(IDENTIFIER),
  disclosureId: z.string().regex(IDENTIFIER),
  sourceInstanceId: z.string().regex(IDENTIFIER),
  checkpointHash: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  authorizationVersion: z.number().int().nonnegative(),
  targetInstanceId: z.string().regex(IDENTIFIER),
  createdAt: z.number().int().nonnegative(),
  updatedAt: z.number().int().nonnegative(),
}
const importRecordSchema = z.discriminatedUnion('status', [
  z.strictObject({ ...commonRecord, status: z.literal('queued') }).readonly(),
  z.strictObject({ ...commonRecord, status: z.literal('failed') }).readonly(),
  z.strictObject({ ...commonRecord, status: z.literal('completed'),
    sessionId: z.string().regex(IDENTIFIER) }).readonly(),
])
type ImportRecord = z.infer<typeof importRecordSchema>

function byteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

function importDomainName(storage?: RegistryIngestStorageScope): string {
  return storage?.domainName === undefined ? 'a2a_registry_saas_imports' : `${storage.domainName}_imports`
}

function specification(storage: RegistryIngestStorageScope | undefined, maxRecordBytes: number) {
  return defineDomain({ name: importDomainName(storage), version: 1, layout: 'single',
    ...(storage?.tenantId === undefined ? {} : { tenantId: storage.tenantId }), tables: {
    imports: domainTable<RegistryImportOperationId, ImportRecord>(importRecordSchema.superRefine((record, context) => {
      if (byteLength(record) > maxRecordBytes) {
        context.addIssue({ code: 'custom', message: 'record exceeds configured limit' })
      }
    })),
  } })
}

function operationId(selection: RegistryDisclosureOperationSelection,
  idempotencyKey: string): RegistryImportOperationId {
  const digest = createHash('sha256').update([
    selection.subject.organizationId,
    selection.subject.memberId,
    idempotencyKey,
  ].join('\0'), 'utf8').digest('hex')
  return brandString<RegistryImportOperationId>(`import-${digest}`)
}

function requestHash(selection: RegistryDisclosureOperationSelection, targetInstanceId: DshInstanceId): string {
  return createHash('sha256').update(JSON.stringify([
    selection.subject.organizationId,
    selection.subject.memberId,
    selection.disclosure.organizationId,
    selection.disclosure.disclosureId,
    selection.disclosure.instanceId,
    selection.disclosure.checkpoint.checkpointHash,
    selection.disclosure.authorizationVersion,
    targetInstanceId,
  ]), 'utf8').digest('hex')
}

function stableSessionId(instanceId: string, importOperationId: string): string {
  const digest = createHash('sha256').update(`${instanceId}\0${importOperationId}`, 'utf8').digest('hex')
  return `a2a-import-${digest}`
}

function sameOwner(record: ImportRecord, selection: RegistryDisclosureOperationSelection): boolean {
  return record.organizationId === selection.subject.organizationId
    && record.memberId === selection.subject.memberId
    && record.disclosureId === selection.disclosure.disclosureId
}

function resultOf(record: ImportRecord): RegistryDisclosureImportResult {
  return record.status === 'completed'
    ? { operationId: brandString<RegistryImportOperationId>(record.operationId), status: record.status,
      sessionId: brandString<RegistryImportedSessionId>(record.sessionId) }
    : { operationId: brandString<RegistryImportOperationId>(record.operationId), status: record.status }
}

function requirePositive(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0 || Object.is(value, -0)) {
    throw new Error('Registry SaaS import queue limits must be positive safe integers')
  }
}

/** One serialized, restart-safe queue for exactly one Registry organization. */
export class RegistrySaasImportQueue implements RegistryDisclosureOperations, RegistryImportBroker {
  private readonly table: KvTable<RegistryImportOperationId, ImportRecord>
  private readonly abort = new AbortController()
  private chain = Promise.resolve()
  private closing: Promise<void> | undefined
  private unavailable = false

  private constructor(private readonly domain: Domain<ReturnType<typeof specification>>,
    private readonly organizationId: OrganizationId, private readonly store: RegistryRuntimeStore,
    private readonly reader: RegistryDisclosureReader, private readonly config: RegistrySaasImportQueueConfig) {
    this.table = domain.table('imports')
  }

  /** Open and validate every retained queue item before making the tenant runtime available. */
  static async open(facility: DomainFacility, organizationId: OrganizationId, store: RegistryRuntimeStore,
    reader: RegistryDisclosureReader, config: RegistrySaasImportQueueConfig,
    storage?: RegistryIngestStorageScope): Promise<RegistrySaasImportQueue> {
    const resolved = Object.freeze(structuredClone(config))
    requirePositive(resolved.maxOperations)
    requirePositive(resolved.maxRecordBytes)
    requirePositive(resolved.maxAuthorizationResponseBytes)
    requirePositive(resolved.maxDeliveryBytes)
    requirePositive(resolved.deliveryTimeoutMs)
    let domain: Domain<ReturnType<typeof specification>>
    try { domain = await facility.open(specification(storage, resolved.maxRecordBytes)) } catch {
      throw new Error('Registry SaaS import queue is unavailable')
    }
    const owner = new RegistrySaasImportQueue(domain, organizationId, store, reader, resolved)
    if (owner.table.size > resolved.maxOperations
      || [...owner.table.entries()].some(([key, record]) => key !== record.operationId
        || record.organizationId !== organizationId)) {
      await domain.close()
      throw new Error('Registry SaaS import queue is invalid')
    }
    return owner
  }

  /** List this member's confirmed receive-capable devices, including devices with no live presence observation. */
  listImportTargets(selection: RegistryDisclosureOperationSelection, signal: AbortSignal) {
    return this.run(async () => {
      this.requireSelection(selection)
      signal.throwIfAborted()
      const targets = await selection.listAuthorizedTargets(signal)
      const instances = new Set<string>()
      for (const target of targets) {
        if (instances.has(target.instanceId)) throw new RegistryIngestError('invalid-input')
        instances.add(target.instanceId)
      }
      return structuredClone(targets)
    })
  }

  /** Persist an import before returning; absence of a live target connection never rejects queue admission. */
  importDisclosure(selection: RegistryDisclosureOperationSelection,
    input: { readonly targetInstanceId: DshInstanceId; readonly idempotencyKey: string }, signal: AbortSignal) {
    return this.run(async () => {
      this.requireSelection(selection)
      signal.throwIfAborted()
      if (!IDENTIFIER.test(input.idempotencyKey)) throw new RegistryIngestError('invalid-input')
      const id = operationId(selection, input.idempotencyKey)
      const expectedRequestHash = requestHash(selection, input.targetInstanceId)
      const retained = this.table.get(id)
      if (retained !== undefined) {
        if (retained.requestHash !== expectedRequestHash) throw new RegistryIngestError('conflict')
        await selection.authorizeTarget(input.targetInstanceId, signal)
        return resultOf(retained)
      }
      await selection.authorizeTarget(input.targetInstanceId, signal)
      if (this.table.size >= this.config.maxOperations) throw new RegistryIngestError('limit')
      const now = Date.now()
      const record: ImportRecord = {
        operationId: id,
        requestHash: expectedRequestHash,
        organizationId: selection.subject.organizationId,
        memberId: selection.subject.memberId,
        disclosureId: selection.disclosure.disclosureId,
        sourceInstanceId: selection.disclosure.instanceId,
        checkpointHash: selection.disclosure.checkpoint.checkpointHash,
        authorizationVersion: selection.disclosure.authorizationVersion,
        targetInstanceId: input.targetInstanceId,
        status: 'queued',
        createdAt: now,
        updatedAt: now,
      }
      await this.put(id, record)
      return resultOf(record)
    })
  }

  /** Read only the owning member's operation after current target-binding authorization. */
  readImport(selection: RegistryDisclosureOperationSelection, id: RegistryImportOperationId, signal: AbortSignal) {
    return this.run(async () => {
      this.requireSelection(selection)
      signal.throwIfAborted()
      const record = this.table.get(id)
      if (record === undefined || !sameOwner(record, selection)) throw new RegistryIngestError('not-found')
      await selection.authorizeTarget(brandString<DshInstanceId>(record.targetInstanceId), signal)
      return resultOf(record)
    })
  }

  /** Deliver the oldest queued item for one authenticated receiver; retry and disconnect retain it unchanged. */
  dispatch(target: RegistryConnectionAuthority,
    receive: (delivery: RegistryImportDelivery) => Promise<RegistryImportOutcome>,
    signal: AbortSignal): Promise<boolean> {
    return this.run(async () => {
      this.requireTarget(target)
      signal.throwIfAborted()
      const record = [...this.table.entries()].map(([, candidate]) => candidate)
        .filter((candidate): candidate is Extract<ImportRecord, { status: 'queued' }> => candidate.status === 'queued'
          && candidate.targetInstanceId === target.connection.instanceId)
        .sort((left, right) => left.createdAt - right.createdAt
          || left.operationId.localeCompare(right.operationId))[0]
      if (record === undefined) return false
      const subject = { authenticated: true as const, organizationId: this.organizationId,
        memberId: brandString<MemberId>(record.memberId), membership: 'active' as const,
        role: 'member' as const, currentTeamIds: [] }
      const authority: FreshRegistryMetadataAuthority = () => {
        signal.throwIfAborted()
        this.requireTarget(target)
        // RegistryIngest rebuilds current v5 source history from its persisted binding. Returning null here
        // deliberately leaves legacy v4 without a stale external authority, so background delivery fails closed.
        return { subject, now: Date.now(), historyFor: () => null }
      }
      const receiveRequirement = { authority: () => {
        signal.throwIfAborted()
        this.requireTarget(target)
        return { subject, now: Date.now() }
      }, instanceId: brandString<DshInstanceId>(record.targetInstanceId),
      maxResponseBytes: this.config.maxAuthorizationResponseBytes }
      const selected = await this.reader.withAuthorizedPrefix(authority,
        brandString<DisclosureId>(record.disclosureId), brandString<DshInstanceId>(record.sourceInstanceId),
        'import', brandString<DisclosureHash>(record.checkpointHash), this.config.maxAuthorizationResponseBytes,
        receiveRequirement, async (snapshot) => {
          if (snapshot === null || snapshot.metadata.organizationId !== record.organizationId
            || snapshot.metadata.instanceId !== record.sourceInstanceId
            || snapshot.metadata.disclosureId !== record.disclosureId
            || snapshot.metadata.checkpoint.checkpointHash !== record.checkpointHash
            || snapshot.prefix.authorizationVersion < record.authorizationVersion) {
            await this.fail(record)
            return null
          }
          const delivery = {
            operationId: record.operationId,
            targetInstanceId: brandString<DshInstanceId>(record.targetInstanceId),
            organizationId: this.organizationId,
            disclosureId: brandString<DisclosureId>(record.disclosureId),
            sourceInstanceId: brandString<DshInstanceId>(record.sourceInstanceId),
            checkpointHash: brandString<DisclosureHash>(record.checkpointHash),
            prefix: snapshot.prefix,
            source: { instanceName: record.sourceInstanceId,
              conversationTitle: String(snapshot.prefix.conversationId) },
          } satisfies RegistryImportDelivery
          if (byteLength(delivery) > this.config.maxDeliveryBytes) {
            await this.fail(record)
            return null
          }
          return delivery
        })
      if (selected === null) return false
      const outcome = await this.receive(receive, selected, signal)
      signal.throwIfAborted()
      this.requireTarget(target)
      await this.reader.withAuthorizedPrefix(authority,
        brandString<DisclosureId>(record.disclosureId), brandString<DshInstanceId>(record.sourceInstanceId),
        'import', brandString<DisclosureHash>(record.checkpointHash), this.config.maxAuthorizationResponseBytes,
        receiveRequirement, async (snapshot) => {
          if (snapshot === null || snapshot.metadata.organizationId !== record.organizationId
            || snapshot.metadata.instanceId !== record.sourceInstanceId
            || snapshot.metadata.disclosureId !== record.disclosureId
            || snapshot.metadata.checkpoint.checkpointHash !== record.checkpointHash
            || snapshot.prefix.authorizationVersion < record.authorizationVersion) {
            await this.fail(record)
            return
          }
          if (outcome.status === 'completed') {
            if (outcome.sessionId !== stableSessionId(record.targetInstanceId, record.operationId)) {
              await this.fail(record)
              throw new RegistryIngestError('invalid-input')
            }
            await this.put(brandString<RegistryImportOperationId>(record.operationId),
              { ...record, status: 'completed', sessionId: outcome.sessionId, updatedAt: Date.now() })
          }
        })
      return true
    })
  }

  /** Stop admission and close the durable queue after already admitted work drains. */
  close(): Promise<void> {
    this.abort.abort()
    this.closing ??= this.chain.then(() => this.domain.close())
    return this.closing
  }

  private requireSelection(selection: RegistryDisclosureOperationSelection): void {
    if (!selection.subject.authenticated || selection.subject.organizationId !== this.organizationId
      || selection.subject.membership !== 'active' || selection.disclosure.organizationId !== this.organizationId
      || !selection.disclosure.authorizedActions.includes('import')) throw new RegistryIngestError('not-found')
  }

  private requireTarget(target: RegistryConnectionAuthority): void {
    if (target.connection.organizationId !== this.organizationId
      || target.history.organizationId !== this.organizationId
      || target.connection.instanceId !== target.history.instanceId
      || target.history.status !== 'active') throw new RegistryIngestError('not-found')
  }

  private run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.abort.signal.aborted || this.unavailable || !this.store.active()) {
      return Promise.reject(new RegistryIngestError('closed'))
    }
    const result = this.chain.then(async () => {
      if (this.abort.signal.aborted || this.unavailable || !this.store.active()) {
        throw new RegistryIngestError('closed')
      }
      return operation()
    })
    this.chain = result.then(() => {}, () => {})
    return result
  }

  private async put(id: RegistryImportOperationId, record: ImportRecord): Promise<void> {
    if (byteLength(record) > this.config.maxRecordBytes) throw new RegistryIngestError('limit')
    try { await this.table.put(id, Object.freeze(record)) } catch {
      this.unavailable = true
      this.abort.abort()
      throw new RegistryIngestError('storage-unavailable')
    }
  }

  private fail(record: Extract<ImportRecord, { status: 'queued' }>): Promise<void> {
    return this.put(brandString<RegistryImportOperationId>(record.operationId),
      { ...record, status: 'failed', updatedAt: Date.now() })
  }

  private async receive(callback: (delivery: RegistryImportDelivery) => Promise<RegistryImportOutcome>,
    delivery: RegistryImportDelivery, signal: AbortSignal): Promise<RegistryImportOutcome> {
    signal.throwIfAborted()
    let timer: NodeJS.Timeout | undefined
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => { reject(new RegistryIngestError('storage-unavailable')) }, this.config.deliveryTimeoutMs)
    })
    try { return await Promise.race([callback(delivery), timeout]) }
    finally { clearTimeout(timer) }
  }
}

/** Process-global delegator; tenant selection comes only from authenticated operation or device authority. */
export class RegistrySaasImportRouter implements RegistryDisclosureOperations, RegistryImportBroker {
  constructor(private readonly router: RegistryTenantRuntimeRouter) {}

  listImportTargets(selection: RegistryDisclosureOperationSelection, signal: AbortSignal) {
    return this.withQueue(selection.subject.organizationId,
      queue => queue.listImportTargets(selection, signal))
  }

  importDisclosure(selection: RegistryDisclosureOperationSelection,
    input: { readonly targetInstanceId: DshInstanceId; readonly idempotencyKey: string }, signal: AbortSignal) {
    return this.withQueue(selection.subject.organizationId,
      queue => queue.importDisclosure(selection, input, signal))
  }

  readImport(selection: RegistryDisclosureOperationSelection, id: RegistryImportOperationId,
    signal: AbortSignal) {
    return this.withQueue(selection.subject.organizationId,
      queue => queue.readImport(selection, id, signal))
  }

  dispatch(target: RegistryConnectionAuthority,
    receive: (delivery: RegistryImportDelivery) => Promise<RegistryImportOutcome>, signal: AbortSignal) {
    return this.withQueue(target.connection.organizationId,
      queue => queue.dispatch(target, receive, signal))
  }

  private async withQueue<T>(organizationId: OrganizationId,
    operation: (queue: RegistrySaasImportQueue) => Promise<T>): Promise<T> {
    const lease = await this.router.acquireRuntime(organizationId)
    try {
      const queue = lease.runtime.imports
      if (queue === undefined) throw new RegistryIngestError('not-found')
      return await operation(queue)
    } finally { lease.release() }
  }
}
