/** Bounded metadata-only HTTPS export for Registry operational failures. */
import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { credentialRef, type CredentialRef } from '@deepseek-ai/dsh-credentials'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { RegistryAuditAction, RegistryAuditOperationId,
  RegistryAuditRecord } from '@deepseek-ai/dsh-a2a-registry-ingest'
import z from '@deepseek-ai/schemastery'
import { RegistryOperationalAlertOutbox, RegistryOperationalAlertOutboxConfigSchema,
  type RegistryOperationalAlertClaim,
  type RegistryOperationalAlertOutboxConfig } from './operational-alert-outbox-sqlite.ts'

/** Deployment-selected HTTPS delivery and bounded in-process queue limits. */
export interface RegistryOperationalAlertsConfig {
  /** Absolute HTTPS endpoint without embedded credentials, query or fragment. */
  readonly endpoint: string
  /** Optional credential reference resolved again for every delivery attempt and sent as a bearer token. */
  readonly bearerTokenEnv?: string
  /** Maximum accepted alerts, including one currently being delivered. */
  readonly maxPendingAlerts: number
  /** Maximum delivery attempts for one alert before a sanitized local diagnostic. */
  readonly deliveryAttempts: number
  /** Per-attempt network timeout. */
  readonly timeoutMs: number
  /** Fixed delay between failed attempts. */
  readonly retryDelayMs: number
  /** Optional dedicated crash-durable same-host delivery outbox. */
  readonly outbox?: RegistryOperationalAlertOutboxConfig
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const configSchema: z<RegistryOperationalAlertsConfig> = z.object({
  endpoint: z.string().required(), bearerTokenEnv: z.string(), maxPendingAlerts: positive(),
  deliveryAttempts: positive(), timeoutMs: positive(), retryDelayMs: positive(),
  outbox: z.union([RegistryOperationalAlertOutboxConfigSchema]),
})

/** Strict Registry operational alert exporter configuration. */
export const RegistryOperationalAlertsConfigSchema: z<RegistryOperationalAlertsConfig> = z.transform(
  configSchema,
  (config) => {
    let endpoint: URL
    try { endpoint = new URL(config.endpoint) } catch {
      throw new z.ValidationError('Registry operational alerts require an absolute HTTPS endpoint', {})
    }
    if (endpoint.protocol !== 'https:' || endpoint.username !== '' || endpoint.password !== ''
      || endpoint.search !== '' || endpoint.hash !== '') {
      throw new z.ValidationError('Registry operational alerts require HTTPS without credentials, query or fragment', {})
    }
    if (config.bearerTokenEnv !== undefined) {
      try { credentialRef(config.bearerTokenEnv) } catch {
        throw new z.ValidationError('Registry operational alert bearerTokenEnv must be a credential reference', {})
      }
    }
    if (config.outbox !== undefined && config.outbox.leaseMs <= config.timeoutMs) {
      throw new z.ValidationError('Registry operational alert outbox leaseMs must exceed timeoutMs', {})
    }
    return { ...config, endpoint: endpoint.href }
  },
)

/** Closed categories exported without request or disclosure content. */
export type RegistryOperationalAlertCategory = 'signature-failure' | 'ingest-conflict'
  | 'access-rejected' | 'deletion-failure' | 'storage-unavailable' | 'rate-limit-exhausted'

/** Browser admission scope reported without its identifying rate key. */
export type RegistryOperationalRateLimitScope = 'client-address' | 'account'

/** Stable metadata-only payload sent to the configured operations endpoint. */
export interface RegistryOperationalAlert {
  readonly version: 1
  readonly category: RegistryOperationalAlertCategory
  readonly severity: 'warning' | 'critical'
  readonly organizationId: OrganizationId
  readonly occurredAt: number
  readonly operationId: RegistryAuditOperationId | null
  readonly action: RegistryAuditAction | 'storage' | 'rate-limit-client-address' | 'rate-limit-account'
  readonly disclosureId: string | null
  readonly actorKind: 'enrollment' | 'producer' | 'member' | 'maintenance' | 'unattributed'
}

interface QueuedOperationalAlert {
  readonly id: string
  readonly alert: RegistryOperationalAlert
}

/** Narrow lifecycle service used by HTTP admission without exposing exporter control. */
export interface RegistryOperationalAlertReporter {
  /** Queue one metadata-only notification after a browser admission bucket rejects work. */
  reportRateLimit(scope: RegistryOperationalRateLimitScope): void
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    registryOperationalAlertReporter: RegistryOperationalAlertReporter
  }
}

const CONFLICT_CODES = new Set(['conflict', 'gap', 'version-conflict'])

/** Select an externally actionable alert from one completed durable audit record.
 * @param record - Trusted parsed metadata-only Registry audit record.
 * @returns A detached alert, or null when the completion does not need operational export. */
export function operationalAlertFromAudit(record: RegistryAuditRecord): RegistryOperationalAlert | null {
  const completion = record.completion
  if (completion?.outcome.kind !== 'rejected') return null
  const outcome = completion.outcome
  const category: RegistryOperationalAlertCategory | null = outcome.category === 'signature-failure'
    ? 'signature-failure'
    : record.action === 'delete'
      ? 'deletion-failure'
      : CONFLICT_CODES.has(outcome.code)
        ? 'ingest-conflict'
        : outcome.code === 'not-found'
          ? 'access-rejected'
          : null
  if (category === null) return null
  return Object.freeze({
    version: 1,
    category,
    severity: category === 'deletion-failure' ? 'critical' : 'warning',
    organizationId: record.organizationId,
    occurredAt: completion.completedAt,
    operationId: record.operationId,
    action: record.action,
    disclosureId: record.requestedDisclosureId,
    actorKind: completion.actor.kind,
  })
}

function safeLog(ctx: Context, message: string, category: RegistryOperationalAlertCategory | 'exporter-internal',
  operationId: RegistryAuditOperationId | null): void {
  try { ctx.logger.error(message, category, operationId ?? 'none') } catch {
    // A failed diagnostic cannot affect Registry admission or exporter quiescence.
  }
}

const CATEGORIES = new Set<RegistryOperationalAlertCategory>([
  'signature-failure', 'ingest-conflict', 'access-rejected', 'deletion-failure',
  'storage-unavailable', 'rate-limit-exhausted',
])
const SEVERITIES = new Set<RegistryOperationalAlert['severity']>(['warning', 'critical'])
const ACTIONS = new Set<RegistryOperationalAlert['action']>([
  'register', 'status', 'event', 'checkpoint', 'read', 'metadata-read', 'metadata-list',
  'access', 'control', 'delete', 'directory-read', 'directory-change',
  'binding-start', 'binding-approve', 'binding-confirm', 'binding-review', 'binding-reject',
  'binding-revoke', 'binding-rename', 'binding-list',
  'storage', 'rate-limit-client-address', 'rate-limit-account',
])
const ACTOR_KINDS = new Set<RegistryOperationalAlert['actorKind']>([
  'enrollment', 'producer', 'member', 'maintenance', 'unattributed',
])

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.isWellFormed()
    && Buffer.byteLength(value, 'utf8') <= maximum
}

/** Reconstruct only the fixed envelope before a persisted row may cross the network boundary. */
function decodePersistedAlert(payload: string): RegistryOperationalAlert {
  let value: unknown
  try { value = JSON.parse(payload) } catch { throw new Error('invalid persisted alert') }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('invalid persisted alert')
  const input = value as Record<string, unknown>
  if (input.version !== 1 || !CATEGORIES.has(input.category as RegistryOperationalAlertCategory)
    || !SEVERITIES.has(input.severity as RegistryOperationalAlert['severity'])
    || !boundedString(input.organizationId, 128)
    || !Number.isSafeInteger(input.occurredAt) || (input.occurredAt as number) < 0
    || (input.operationId !== null && !boundedString(input.operationId, 128))
    || !ACTIONS.has(input.action as RegistryOperationalAlert['action'])
    || (input.disclosureId !== null && !boundedString(input.disclosureId, 256))
    || !ACTOR_KINDS.has(input.actorKind as RegistryOperationalAlert['actorKind'])) {
    throw new Error('invalid persisted alert')
  }
  return Object.freeze({ version: 1,
    category: input.category as RegistryOperationalAlertCategory,
    severity: input.severity as RegistryOperationalAlert['severity'],
    organizationId: input.organizationId as OrganizationId,
    occurredAt: input.occurredAt as number,
    operationId: input.operationId as RegistryAuditOperationId | null,
    action: input.action as RegistryOperationalAlert['action'],
    disclosureId: input.disclosureId,
    actorKind: input.actorKind as RegistryOperationalAlert['actorKind'],
  })
}

/** One bounded serial exporter. Business operations enqueue without awaiting external delivery. */
export class RegistryOperationalAlertExporter {
  private readonly config: RegistryOperationalAlertsConfig
  private readonly tokenRef: CredentialRef | undefined
  private readonly queue: QueuedOperationalAlert[] = []
  private readonly outbox: RegistryOperationalAlertOutbox | undefined
  private worker: Promise<void> | undefined
  private wakePersistentWorker: (() => void) | undefined
  private accepting = true

  /** @param ctx - Registry lifecycle context used for credentials and sanitized diagnostics.
   * @param config - Validated HTTPS destination and queue/retry limits. */
  constructor(private readonly ctx: Context, config: RegistryOperationalAlertsConfig) {
    this.config = structuredClone(config)
    this.tokenRef = config.bearerTokenEnv === undefined ? undefined : credentialRef(config.bearerTokenEnv)
    this.outbox = config.outbox === undefined ? undefined : RegistryOperationalAlertOutbox.open(config.outbox, {
      endpoint: config.endpoint, maxPendingAlerts: config.maxPendingAlerts,
      deliveryAttempts: config.deliveryAttempts, timeoutMs: config.timeoutMs,
      retryDelayMs: config.retryDelayMs,
    })
    if (this.outbox !== undefined) this.startPersistentWorker()
  }

  /** Enqueue one audit-derived alert when its outcome is externally actionable.
   * @param record - Trusted parsed Registry audit record. */
  reportAudit(record: RegistryAuditRecord): void {
    const alert = operationalAlertFromAudit(record)
    if (alert !== null) this.enqueue(alert)
  }

  /** Enqueue the fail-closed storage signal that cannot rely on another journal write.
   * @param organizationId - Physical Registry domain owner. */
  reportStorageUnavailable(organizationId: OrganizationId): void {
    this.enqueue(Object.freeze({ version: 1, category: 'storage-unavailable', severity: 'critical',
      organizationId, occurredAt: Date.now(), operationId: null, action: 'storage', disclosureId: null,
      actorKind: 'unattributed' }))
  }

  /** Enqueue a rate-limit signal without the client address, account tuple or request selector.
   * @param organizationId - Physical Registry domain owner.
   * @param scope - Rejected browser admission tier; its actual rate key is deliberately omitted. */
  reportRateLimit(organizationId: OrganizationId, scope: RegistryOperationalRateLimitScope): void {
    this.enqueue(Object.freeze({ version: 1, category: 'rate-limit-exhausted', severity: 'warning',
      organizationId, occurredAt: Date.now(), operationId: null,
      action: scope === 'account' ? 'rate-limit-account' : 'rate-limit-client-address', disclosureId: null,
      actorKind: scope === 'account' ? 'member' : 'unattributed' }))
  }

  /** Stop admission and wait until every already accepted alert reaches a terminal delivery result.
   * @returns Quiescence after the bounded queue drains. */
  async close(): Promise<void> {
    this.accepting = false
    this.wakePersistentWorker?.()
    while (this.worker !== undefined) await this.worker
    this.outbox?.close()
  }

  private enqueue(alert: RegistryOperationalAlert): void {
    if (!this.accepting) {
      safeLog(this.ctx, 'Registry operational alert dropped: category=%s operationId=%s',
        alert.category, alert.operationId)
      return
    }
    if (this.outbox !== undefined) {
      try {
        const id = this.outbox.enqueue(JSON.stringify(alert))
        if (id !== null) { this.wakePersistentWorker?.(); return }
      } catch {
        // A content-free diagnostic below is the only fallback; the data-plane result remains authoritative.
      }
      safeLog(this.ctx, 'Registry operational alert dropped: category=%s operationId=%s',
        alert.category, alert.operationId)
      return
    }
    if (this.queue.length + (this.worker === undefined ? 0 : 1) >= this.config.maxPendingAlerts) {
      safeLog(this.ctx, 'Registry operational alert dropped: category=%s operationId=%s',
        alert.category, alert.operationId)
      return
    }
    this.queue.push(Object.freeze({ id: randomUUID(), alert: structuredClone(alert) }))
    this.startWorker()
  }

  private startWorker(): void {
    if (this.worker !== undefined) return
    const worker = this.drain().catch(() => {
      this.queue.length = 0
      safeLog(this.ctx, 'Registry operational alert exporter stopped: category=%s operationId=%s',
        'exporter-internal', null)
    })
    this.worker = worker
    void worker.then(() => {
      if (this.worker === worker) this.worker = undefined
      if (this.queue.length > 0) this.startWorker()
    })
  }

  private async drain(): Promise<void> {
    for (let queued = this.queue.shift(); queued !== undefined; queued = this.queue.shift()) {
      let delivered = false
      for (let attempt = 1; attempt <= this.config.deliveryAttempts; attempt += 1) {
        try {
          await this.deliver(queued.alert, queued.id)
          delivered = true
          break
        } catch {
          if (attempt < this.config.deliveryAttempts) {
            await new Promise<void>(resolve => setTimeout(resolve, this.config.retryDelayMs))
          }
        }
      }
      if (!delivered) {
        safeLog(this.ctx, 'Registry operational alert delivery failed: category=%s operationId=%s',
          queued.alert.category, queued.alert.operationId)
      }
    }
  }

  private startPersistentWorker(): void {
    const worker = this.drainPersistent().catch(() => {
      safeLog(this.ctx, 'Registry operational alert exporter stopped: category=%s operationId=%s',
        'exporter-internal', null)
    })
    this.worker = worker
    void worker.then(() => { if (this.worker === worker) this.worker = undefined })
  }

  private async drainPersistent(): Promise<void> {
    const outbox = this.outbox
    if (outbox === undefined) return
    while (this.accepting) {
      let claim: RegistryOperationalAlertClaim | null
      try { claim = outbox.claim() } catch {
        safeLog(this.ctx, 'Registry operational alert outbox unavailable: category=%s operationId=%s',
          'exporter-internal', null)
        await this.waitForPersistentWork()
        continue
      }
      if (claim === null) { await this.waitForPersistentWork(); continue }
      let alert: RegistryOperationalAlert
      try { alert = decodePersistedAlert(claim.payload) } catch {
        try { outbox.failClaim(claim, true) } catch { /* A stale lease will be recovered without content. */ }
        safeLog(this.ctx, 'Registry operational alert retained invalid row: category=%s operationId=%s',
          'exporter-internal', null)
        continue
      }
      try {
        await this.deliver(alert, claim.id)
        try { outbox.complete(claim) } catch {
          safeLog(this.ctx, 'Registry operational alert acknowledgement failed: category=%s operationId=%s',
            alert.category, alert.operationId)
        }
      } catch {
        try {
          if (outbox.failClaim(claim) === 'failed') {
            safeLog(this.ctx, 'Registry operational alert delivery failed: category=%s operationId=%s',
              alert.category, alert.operationId)
          }
        } catch {
          safeLog(this.ctx, 'Registry operational alert retry persistence failed: category=%s operationId=%s',
            alert.category, alert.operationId)
        }
      }
    }
  }

  private async waitForPersistentWork(): Promise<void> {
    const delay = Math.max(1, Math.min(1_000, this.config.retryDelayMs))
    await new Promise<void>((resolve) => {
      let settled = false
      const finish = (): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (this.wakePersistentWorker === finish) this.wakePersistentWorker = undefined
        resolve()
      }
      const timer = setTimeout(finish, delay)
      this.wakePersistentWorker = finish
    })
  }

  private async deliver(alert: RegistryOperationalAlert, idempotencyKey: string): Promise<void> {
    const headers: Record<string, string> = {
      'content-type': 'application/json; charset=utf-8',
      'idempotency-key': idempotencyKey,
    }
    if (this.tokenRef !== undefined) {
      const credentials = this.ctx.get('credentials', false)
      const resolved = await credentials?.resolve(this.tokenRef)
      if (resolved === undefined) throw new Error('Registry operational alert credential unavailable')
      headers.authorization = `Bearer ${resolved.value}`
    }
    const response = await fetch(this.config.endpoint, { method: 'POST', redirect: 'error',
      headers, body: JSON.stringify(alert), signal: AbortSignal.timeout(this.config.timeoutMs) })
    const accepted = response.ok
    if (response.body !== null) {
      try { await response.body.cancel() } catch {
        // The exporter ignores response content; a failed body cancellation does not change the HTTP status.
      }
    }
    if (!accepted) throw new Error('Registry operational alert endpoint rejected delivery')
  }
}
