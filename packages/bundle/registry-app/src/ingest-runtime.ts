/** One opt-in storage lifecycle shared by Registry directory, enrollment, maintenance and synchronization. */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import { RegistryIngestError, type RegistryAuditConfig, type RegistryBindingConfig,
  type RegistryDirectoryConfig, type RegistryIngestLimits,
  type RegistryIngestStorageScope } from '@deepseek-ai/dsh-a2a-registry-ingest'
import { decodeRegistryAudience } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type {} from '@deepseek-ai/dsh-storage-domain'
import { Config as MaintenanceSchema, runRegistryMaintenance, type MaintenanceConfig } from './maintenance.ts'
import { Config as SyncConfig, type RegistrySyncConfig } from './sync-config.ts'
import { installRegistrySync } from './sync.ts'
import { RegistryRuntimeStore } from './runtime-store.ts'
import type { RegistryDisclosureControl } from './control.ts'
import type { RegistryDisclosureReader } from './reader.ts'
import type { FreshRegistryAuditAuthority, RegistryAuditMetadata, RegistryAuditPage,
  RegistryAuditReader } from './audit-reader.ts'
import type { RegistryDirectory } from './directory.ts'
import type { RegistryEnrollment } from './enrollment.ts'
import { RegistryOperationalAlertExporter, RegistryOperationalAlertsConfigSchema,
  type RegistryOperationalAlertsConfig, type RegistryOperationalRateLimitScope } from './operational-alerts.ts'
import { RegistrySaasImportQueue, type RegistrySaasImportQueueConfig } from './saas-import-queue.ts'
import { RegistrySaasQuestionMailbox, type RegistrySaasQuestionMailboxConfig } from './saas-question-mailbox.ts'

const IMPORT_DELIVERY_ENVELOPE_BYTES = 1024
const QUESTION_DELIVERY_ENVELOPE_BYTES = 1024

function boundedObservation<T>(value: T, maximum: number): T {
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') > maximum) throw new RegistryIngestError('limit')
  return value
}

/** Private plugin name; profile composition remains owned by registry-app. */
export const name = 'registry-ingest-runtime'
/** Storage replacement disposes the shared owner before the next consumer can enter. */
export const inject = ['storageDomain']

/** Complete limits shared by every enabled consumer of the exclusive Registry domain. */
export interface RegistryIngestRuntimeConfig {
  /** Canonical organization permanently bound to this physical Registry domain. */
  organizationId: OrganizationId
  /** One set of complete storage bounds for every configured consumer. */
  limits: RegistryIngestLimits
  /** Explicit durable journal; block-all includes withdrawals and deletions. No policy is selected when absent. */
  audit?: RegistryAuditConfig
  /** Optional bounded HTTPS export of selected metadata-only journal failures. Requires audit. */
  alerts?: RegistryOperationalAlertsConfig
  /** Explicit bounded directory and first-open owner; this does not configure account authentication. */
  directory?: RegistryDirectoryConfig
  /** Explicit enrollment candidates; requires directory configuration and does not issue credentials. */
  bindings?: RegistryBindingConfig
  /** Trusted organization-scoped background deletion, absent by default. */
  maintenance?: MaintenanceConfig
  /** Authenticated producer endpoint, requiring an external identity provider. */
  sync?: RegistrySyncConfig
  /** Optional tenant-owned durable context-import queue delivered through Registry Sync. */
  imports?: RegistrySaasImportQueueConfig
  /** Optional tenant-owned encrypted text-question mailbox delivered through Registry Sync. */
  questions?: RegistrySaasQuestionMailboxConfig
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const schema: z<RegistryIngestRuntimeConfig> = z.object({
  organizationId: z.transform(z.string().pattern(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$(?![\s\S])/).required(),
    value => brandString<OrganizationId>(value)).required(),
  limits: z.object({ maxInputBytes: positive(), maxAggregateBytes: positive(), maxEvents: positive(),
    maxCheckpoints: positive(), maxDisclosures: positive(), maxAuditEntries: positive() }).required(),
  audit: z.union([z.object({ failurePolicy: z.const('block-all').required(), maxOperations: positive(), maxRecordBytes: positive() })]),
  alerts: z.union([RegistryOperationalAlertsConfigSchema]),
  directory: z.union([z.object({ maxMembers: positive(), maxTeams: positive(), maxTeamMembers: positive(),
    maxNameBytes: positive(), maxBytes: positive(), bootstrapOwner: z.object({
      memberId: z.transform(z.string().pattern(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$(?![\s\S])/).required(),
        value => brandString<MemberId>(value)).required(),
      displayName: z.string().required(),
    }).required() })]),
  bindings: z.union([z.object({ audience: z.string().required(), ttlMs: positive(),
    maxRecordBytes: positive(), maxBindings: positive(), maxNameBytes: positive() })]),
  maintenance: z.union([MaintenanceSchema]), sync: z.union([SyncConfig]),
  imports: z.union([z.object({ maxOperations: positive(), maxRecordBytes: positive(),
    maxAuthorizationResponseBytes: positive(), maxDeliveryBytes: positive(),
    deliveryTimeoutMs: positive() }).required()]),
  questions: z.union([z.object({
    mailboxKeyEnv: z.string().role('credential-ref').required(),
    maxAuthorizationResponseBytes: positive(), maxDeliveryBytes: positive(),
    operationTimeoutMs: positive(), executionLeaseMs: positive(),
    limits: z.object({
      maxTextBytes: positive(), maxTextCharacters: positive(), maxCiphertextBytes: positive(),
      maxAggregateBytes: positive(), maxRequests: positive(), maxRetainedRequests: positive(),
      maxPendingOperations: positive(), maxLifetimeMs: positive(),
    }).required(),
    expiryMaintenance: z.object({ intervalMs: positive(), maxItems: positive() }).required(),
  }).required()]),
})
export const Config: z<RegistryIngestRuntimeConfig> = z.transform(schema, (value) => {
  if (value.bindings !== undefined) {
    if (value.directory === undefined) throw new z.ValidationError('Registry enrollment requires directory', {})
    try { decodeRegistryAudience(value.bindings.audience) } catch {
      throw new z.ValidationError('Registry enrollment requires a canonical WSS audience', {})
    }
    if (value.sync !== undefined && value.sync.audience !== value.bindings.audience) {
      throw new z.ValidationError('Registry enrollment and sync require the same audience', {})
    }
  }
  if (value.maintenance === undefined && value.sync === undefined && value.directory === undefined) {
    throw new z.ValidationError('Registry ingest requires maintenance, sync or directory', {})
  }
  if (value.alerts !== undefined && value.audit === undefined) {
    throw new z.ValidationError('Registry operational alerts require durable audit', {})
  }
  if (value.imports !== undefined
    && (value.directory === undefined || value.bindings === undefined || value.sync === undefined)) {
    throw new z.ValidationError('Registry tenant imports require directory, bindings and sync', {})
  }
  if (value.imports !== undefined && value.sync !== undefined
    && value.imports.maxDeliveryBytes > value.sync.maxFrameBytes - IMPORT_DELIVERY_ENVELOPE_BYTES) {
    throw new z.ValidationError('Registry tenant import delivery exceeds the sync frame bound', {})
  }
  if (value.questions !== undefined
    && (value.directory === undefined || value.bindings === undefined || value.sync === undefined)) {
    throw new z.ValidationError('Registry tenant questions require directory, bindings and sync', {})
  }
  if (value.questions !== undefined && value.questions.maxAuthorizationResponseBytes > value.sync!.maxFrameBytes) {
    throw new z.ValidationError('Registry tenant question authorization exceeds the sync frame bound', {})
  }
  if (value.questions !== undefined
    && value.questions.maxDeliveryBytes > value.sync!.maxFrameBytes - QUESTION_DELIVERY_ENVELOPE_BYTES) {
    throw new z.ValidationError('Registry tenant question delivery exceeds the sync frame bound', {})
  }
  return value
})

function auditMetadata(record: ReturnType<import('@deepseek-ai/dsh-a2a-registry-ingest').RegistryIngest['inspectAudit']>[number]): RegistryAuditMetadata {
  const completion = record.completion
  const actor = completion?.actor
  const actorId = actor?.kind === 'member' ? actor.memberId
    : actor?.kind === 'producer' || actor?.kind === 'enrollment' ? actor.instanceId : null
  return {
    operationId: record.operationId,
    occurredAt: completion?.completedAt ?? record.startedAt,
    actorKind: actor?.kind ?? 'unattributed',
    actorId,
    instanceId: actor?.kind === 'producer' || actor?.kind === 'enrollment' ? actor.instanceId : null,
    objectId: record.requestedDisclosureId,
    action: record.action,
    result: completion === null ? 'pending' : completion.outcome.kind === 'rejected' ? 'rejected' : 'succeeded',
  }
}

function auditPage(records: ReturnType<import('@deepseek-ai/dsh-a2a-registry-ingest').RegistryIngest['inspectAudit']>,
  options: import('./audit-reader.ts').RegistryAuditListOptions): RegistryAuditPage {
  if (!Number.isSafeInteger(options.pageSize) || options.pageSize <= 0
    || !Number.isSafeInteger(options.maxPageSize) || options.maxPageSize <= 0
    || !Number.isSafeInteger(options.maxResponseBytes) || options.maxResponseBytes <= 0) {
    throw new RegistryIngestError('invalid-input')
  }
  const pageSize = Math.min(options.pageSize, options.maxPageSize)
  const ordered = [...records].reverse()
  let start = 0
  if (options.cursor !== undefined) {
    const anchor = ordered.findIndex(record => record.operationId === options.cursor)
    if (anchor < 0) throw new RegistryIngestError('invalid-input')
    start = anchor + 1
  }
  const items: RegistryAuditMetadata[] = []
  let index = start
  while (index < ordered.length && items.length < pageSize) {
    const record = ordered[index]
    if (record === undefined) throw new RegistryIngestError('invalid-storage')
    const item = auditMetadata(record)
    const candidate = { items: [...items, item], nextCursor: null }
    if (Buffer.byteLength(JSON.stringify(candidate), 'utf8') > options.maxResponseBytes) {
      if (items.length === 0) throw new RegistryIngestError('limit')
      break
    }
    items.push(item)
    index += 1
  }
  const last = items.at(-1)
  const page = { items, nextCursor: index < ordered.length && last !== undefined ? last.operationId : null }
  if (Buffer.byteLength(JSON.stringify(page), 'utf8') > options.maxResponseBytes) {
    throw new RegistryIngestError('limit')
  }
  return structuredClone(page)
}

/** One organization-owned runtime. A tenant router may hold many of these without replacing global services. */
export interface RegistryTenantRuntime {
  readonly organizationId: OrganizationId
  readonly store: RegistryRuntimeStore
  readonly control: RegistryDisclosureControl
  readonly reader: RegistryDisclosureReader
  readonly auditReader?: RegistryAuditReader
  readonly directory?: RegistryDirectory
  readonly enrollment?: RegistryEnrollment
  readonly imports?: RegistrySaasImportQueue
  readonly questions?: RegistrySaasQuestionMailbox
  readonly signal: AbortSignal
  readonly reportRateLimit?: (scope: RegistryOperationalRateLimitScope) => void
  close(): Promise<void>
}

export interface RegistryTenantRuntimeOpenOptions {
  readonly storage?: RegistryIngestStorageScope
  /** A multi-tenant router owns one shared exporter instead of opening the same outbox per organization. */
  readonly alerts?: RegistryOperationalAlertExporter
}

/** Open one isolated organization runtime without publishing process-global Cordis services. */
export async function openRegistryTenantRuntime(ctx: Context, config: RegistryIngestRuntimeConfig,
  openOptions: RegistryTenantRuntimeOpenOptions = {}): Promise<RegistryTenantRuntime> {
  const options = structuredClone(config)
  const abort = new AbortController()
  const ownAlerts = openOptions.alerts === undefined && options.alerts !== undefined
  const alerts = openOptions.alerts ?? (options.alerts === undefined
    ? undefined : new RegistryOperationalAlertExporter(ctx, options.alerts))
  const store = new RegistryRuntimeStore(ctx, ctx.storageDomain, options.organizationId, options.limits, abort,
    options.audit, options.directory, options.bindings, alerts, openOptions.storage)
  let imports: RegistrySaasImportQueue | undefined
  let questions: RegistrySaasQuestionMailbox | undefined
  let worker = Promise.resolve()
  let closing: Promise<void> | undefined
  const close = (): Promise<void> => {
    closing ??= (async () => {
      abort.abort()
      const outcomes = await Promise.allSettled([worker, questions?.close(), imports?.close(), store.close(),
        ownAlerts ? alerts?.close() : undefined])
      if (outcomes.some(outcome => outcome.status === 'rejected')) {
        ctx.logger.error('Registry tenant runtime cleanup failed')
        throw new Error('Registry tenant runtime cleanup failed')
      }
    })()
    return closing
  }
  try {
    await store.run(async () => {})
    if (!store.active()) throw new RegistryIngestError('closed')
  } catch (error) {
    await close().catch(() => undefined)
    throw error
  }
  const control = Object.freeze<RegistryDisclosureControl>({
    register(authority, registration) {
      let captured: typeof registration
      try { captured = structuredClone(registration) } catch {
        return Promise.reject(new RegistryIngestError('invalid-input'))
      }
      return store.run(ingest => ingest.register(authority, captured))
    },
    getSyncStatus: (authority, id) => store.run(ingest => ingest.getSyncStatus(authority, id)),
    updateAccess(authority, id, update, expectedVersion) {
      let captured: typeof update
      try { captured = structuredClone(update) } catch {
        return store.rejectAccessInput(id)
      }
      return store.run(ingest => ingest.updateAccess(authority, id, captured, expectedVersion))
    },
    transitionControl: (authority, id, target, expectedVersion) =>
      store.run(ingest => ingest.transitionControl(authority, id, target, expectedVersion)),
    delete: (authority, id, expectedVersion) => store.run(ingest => ingest.delete(authority, id, expectedVersion)),
  })
  const reader = Object.freeze<RegistryDisclosureReader>({
    list: (authority, options) => store.run(ingest => ingest.listMetadata(authority, options)),
    readMetadata: (authority, disclosureId, action, options) =>
      store.run(ingest => ingest.readMetadataWithResolver(authority, disclosureId, action, options)),
    readPrefix: (authority, disclosureId, sourceInstanceId, action, checkpointHash) =>
      store.run(ingest => ingest.readWithResolver(authority, disclosureId, sourceInstanceId, action, checkpointHash)),
    withAuthorizedPrefix: (authority, disclosureId, sourceInstanceId, action, checkpointHash,
      maxMetadataBytes, receive, callback) => store.run(async (ingest) => {
      let metadata: Awaited<ReturnType<typeof ingest.readMetadataWithResolver>>
      let prefix: Awaited<ReturnType<typeof ingest.read>>
      try {
        if (receive !== undefined) {
          const bindings = await ingest.listBindings(receive.authority, receive.maxResponseBytes)
          const matches = bindings.filter(binding => binding.instanceId === receive.instanceId)
          if (matches.length !== 1 || matches[0]?.phase !== 'confirmed'
            || !matches[0].requestedScopes.includes('a2a.receive')) throw new RegistryIngestError('not-found')
        }
        metadata = await ingest.readMetadataWithResolver(authority, disclosureId, action,
          { checkpointHash, maxResponseBytes: maxMetadataBytes })
        prefix = await ingest.readWithResolver(authority, disclosureId, sourceInstanceId, action, checkpointHash)
      } catch (error) {
        if (error instanceof RegistryIngestError && error.code === 'not-found') return callback(null)
        throw error
      }
      return callback({ metadata, prefix })
    }),
  })
  const auditReader: RegistryAuditReader | undefined = options.audit === undefined ? undefined
    : Object.freeze<RegistryAuditReader>({
      list: (authority: FreshRegistryAuditAuthority, listOptions) => store.run(async (ingest) => {
        let subject: Awaited<ReturnType<FreshRegistryAuditAuthority>>
        try { subject = await authority() } catch { throw new RegistryIngestError('not-found') }
        if (!subject.authenticated || subject.organizationId !== store.organizationId
          || subject.membership !== 'active' || (subject.role !== 'owner' && subject.role !== 'admin')) {
          throw new RegistryIngestError('not-found')
        }
        return auditPage(ingest.inspectAudit(), listOptions)
      }),
    })
  const directory: RegistryDirectory | undefined = options.directory === undefined ? undefined
    : Object.freeze<RegistryDirectory>({
      read: (authority, scope, maxResponseBytes) => store.run(ingest => ingest.readDirectory(authority, scope, maxResponseBytes)),
      change(authority, command, expectedRevision) {
        let captured: typeof command
        try { captured = structuredClone(command) } catch {
          return store.run(ingest => ingest.rejectDirectoryInput())
        }
        return store.run(ingest => ingest.changeDirectory(authority, captured, expectedRevision))
      },
    })
  const enrollment: RegistryEnrollment | undefined = options.bindings === undefined ? undefined
    : Object.freeze<RegistryEnrollment>({
      start(request) {
        let captured: typeof request
        try { captured = structuredClone(request) } catch {
          return store.run(ingest => ingest.rejectBindingStartInput())
        }
        return store.run(ingest => ingest.startBinding(captured))
      },
      review: (authority, bindingId, code, maxResponseBytes) =>
        store.run(ingest => ingest.reviewBinding(authority, bindingId, code, maxResponseBytes)),
      reject: (authority, bindingId, code) => store.run(ingest => ingest.rejectBinding(authority, bindingId, code)),
      revoke: (authority, bindingId) => store.run(ingest => ingest.revokeBinding(authority, bindingId)),
      inspect: (authority, bindingId, maxResponseBytes) => store.run(async (ingest) => {
        const binding = await ingest.inspectBinding(authority, bindingId, maxResponseBytes)
        return boundedObservation({ ...binding, transport: store.transport.read(binding.instanceId) }, maxResponseBytes)
      }),
      list: (authority, maxResponseBytes) => store.run(async (ingest) => {
        const bindings = await ingest.listBindings(authority, maxResponseBytes)
        return boundedObservation(bindings.map(binding => ({ ...binding, transport: store.transport.read(binding.instanceId) })),
          maxResponseBytes)
      }),
      rename: (authority, bindingId, instanceName) => store.run(ingest => ingest.renameBinding(authority, bindingId, instanceName)),
      approve: (authority, bindingId, code, instanceName) =>
        store.run(ingest => ingest.approveBinding(authority, bindingId, code, instanceName)),
      confirm(bindingId, proof) {
        let captured: unknown
        try { captured = structuredClone(proof) } catch {
          return store.run(ingest => ingest.rejectBindingProofInput())
        }
        return store.run(ingest => ingest.confirmBinding(bindingId, captured))
      },
    })
  if (options.imports !== undefined) {
    if (options.directory === undefined || options.bindings === undefined || options.sync === undefined) {
      await close().catch(() => undefined)
      throw new Error('Registry SaaS imports require directory, bindings and sync')
    }
    if (options.imports.maxDeliveryBytes > options.sync.maxFrameBytes - IMPORT_DELIVERY_ENVELOPE_BYTES) {
      await close().catch(() => undefined)
      throw new Error('Registry SaaS import delivery exceeds the sync frame bound')
    }
    try {
      imports = await RegistrySaasImportQueue.open(ctx.storageDomain, options.organizationId, store, reader,
        options.imports, openOptions.storage)
    } catch (error) {
      await close().catch(() => undefined)
      throw error
    }
  }
  if (options.questions !== undefined) {
    const credentials = ctx.get('credentials')
    if (credentials === undefined || options.directory === undefined
      || options.bindings === undefined || options.sync === undefined) {
      await close().catch(() => undefined)
      throw new Error('Registry SaaS questions require credentials, directory, bindings and sync')
    }
    if (options.questions.maxAuthorizationResponseBytes > options.sync.maxFrameBytes) {
      await close().catch(() => undefined)
      throw new Error('Registry SaaS question authorization exceeds the sync frame bound')
    }
    if (options.questions.maxDeliveryBytes > options.sync.maxFrameBytes - QUESTION_DELIVERY_ENVELOPE_BYTES) {
      await close().catch(() => undefined)
      throw new Error('Registry SaaS question delivery exceeds the sync frame bound')
    }
    try {
      questions = await RegistrySaasQuestionMailbox.open(ctx, ctx.storageDomain, credentials,
        options.organizationId, store, reader, options.questions, openOptions.storage)
    } catch (error) {
      await close().catch(() => undefined)
      throw error
    }
  }
  if (options.maintenance !== undefined) {
    worker = runRegistryMaintenance(ctx, options.organizationId, options.maintenance, store, abort.signal)
  }
  return Object.freeze({
    organizationId: options.organizationId,
    store,
    control,
    reader,
    ...(auditReader === undefined ? {} : { auditReader }),
    ...(directory === undefined ? {} : { directory }),
    ...(enrollment === undefined ? {} : { enrollment }),
    ...(imports === undefined ? {} : { imports }),
    ...(questions === undefined ? {} : { questions }),
    signal: abort.signal,
    ...(alerts === undefined ? {} : {
      reportRateLimit: (scope: RegistryOperationalRateLimitScope) => { alerts.reportRateLimit(options.organizationId, scope) },
    }),
    close,
  })
}

/** Mount one legacy fixed-organization owner and publish its services process-wide. */
export async function apply(ctx: Context, config: RegistryIngestRuntimeConfig): Promise<void> {
  const options = structuredClone(config)
  const provider = ctx.get('registryProducerAuthenticator')
  let sync: { config: RegistrySyncConfig; provider: NonNullable<typeof provider> } | undefined
  if (options.sync !== undefined) {
    if (provider === undefined) throw new Error('Registry sync requires registryProducerAuthenticator')
    sync = { config: options.sync, provider }
  }
  const runtime = await openRegistryTenantRuntime(ctx, options)
  let stopSync: (() => Promise<void>) | undefined
  if (sync !== undefined) stopSync = installRegistrySync(ctx, sync.config, sync.provider, runtime.store, runtime.signal)
  ctx.effect(() => async () => {
    const outcomes = await Promise.allSettled([stopSync?.(), runtime.close()])
    if (outcomes.some(outcome => outcome.status === 'rejected')) ctx.logger.error('Registry ingest runtime cleanup failed')
  }, 'registry-app: exclusive ingest lifecycle')
  ctx.provide('registryDisclosureControl', runtime.control)
  ctx.provide('registryDisclosureReader', runtime.reader)
  if (runtime.auditReader !== undefined) ctx.provide('registryAuditReader', runtime.auditReader)
  if (runtime.directory !== undefined) ctx.provide('registryDirectory', runtime.directory)
  if (runtime.enrollment !== undefined) ctx.provide('registryEnrollment', runtime.enrollment)
  if (runtime.reportRateLimit !== undefined) {
    ctx.provide('registryOperationalAlertReporter', Object.freeze({ reportRateLimit: runtime.reportRateLimit }))
  }
}
