/** One private Registry ingest lifecycle shared by all explicitly configured Host consumers. */
import type { Context, FiberState } from '@deepseek-ai/cordis'
import type { RegistryBridgeSecretHash, RegistryDeviceSecretHash } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DisclosureId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import { openRegistryIngest, RegistryIngestError, type RegistryAuditConfig, type RegistryDisclosureInvalidation,
  type RegistryBindingConfig, type RegistryBindingId, type RegistryBindingInvalidation, type RegistryDirectoryConfig,
  type RegistryBridgeAuthority, type RegistryIngest, type RegistryIngestLimits,
  type RegistryProducerAuthority } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryIngestStorageScope } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { DomainFacility } from '@deepseek-ai/dsh-storage-domain'
import type { RegistryOperationalAlertExporter } from './operational-alerts.ts'
import { RegistryTransportObservations } from './transport-observation.ts'

// Cordis const enums have no runtime export; keep these typed values aligned with the pinned framework.
const FIBER_LOADING = 1 as FiberState.LOADING
const FIBER_ACTIVE = 2 as FiberState.ACTIVE

/** Confirmed access changes identify one resource; an uncertain or closing owner invalidates every connection. */
export type RegistryRuntimeInvalidation =
  | { readonly kind: 'authorization'; readonly change: RegistryDisclosureInvalidation }
  | { readonly kind: 'binding'; readonly change: RegistryBindingInvalidation }
  | { readonly kind: 'owner-unavailable' }

interface Subscription {
  readonly listener: (notice: RegistryRuntimeInvalidation) => void | Promise<void>
}

/** Serializes access to the exclusive domain and reloads uncertain writes before another consumer enters. */
export class RegistryRuntimeStore {
  /** Private runtime observations; only authenticated sync writers and account-checked enrollment readers use these. */
  readonly transport = new RegistryTransportObservations()
  private store: {
    readonly ingest: RegistryIngest
    readonly unsubscribe: () => void
    readonly unsubscribeBinding: () => void
    readonly unsubscribeAudit: () => void
  } | undefined
  private chain: Promise<void> = Promise.resolve()
  private disposal: Promise<void> | undefined
  private closeFailure: Error | undefined
  private readonly subscriptions = new Set<Subscription>()

  /** @param ctx - Exact provider context whose facility lifetime is observed.
   * @param facility - One injected facility, never a second writer against the same path.
   * @param organizationId - Immutable organization checked on every physical domain open.
   * @param limits - Complete deployment-selected retained-data bounds.
   * @param abort - Shared runtime admission and shutdown controller.
   * @param audit - Explicit optional durable-journal bounds and block-all policy.
   * @param directory - Explicit optional directory bounds and first-open owner.
   * @param bindings - Explicit optional enrollment limits and audience.
   * @param alerts - Optional bounded external exporter for selected audit failures and storage isolation. */
  constructor(private readonly ctx: Context, private readonly facility: DomainFacility,
    readonly organizationId: OrganizationId,
    private readonly limits: RegistryIngestLimits, private readonly abort: AbortController,
    private readonly audit?: RegistryAuditConfig, private readonly directory?: RegistryDirectoryConfig,
    private readonly bindings?: RegistryBindingConfig,
    private readonly alerts?: RegistryOperationalAlertExporter,
    private readonly storage?: RegistryIngestStorageScope) {}

  /** Detect disposal or silent provider replacement before the next owned operation.
   * @returns Whether this exact runtime can admit another operation. */
  active(): boolean {
    if (this.ctx.fiber.uid === null
      || (this.ctx.fiber.state !== FIBER_LOADING && this.ctx.fiber.state !== FIBER_ACTIVE)
      || this.ctx.get('storageDomain') !== this.facility) this.abort.abort()
    return !this.abort.signal.aborted
  }

  /** Subscribe a connection to this runtime's confirmed changes and owner loss; no history is replayed.
   * @param listener - Synchronous invalidation action; returned promises are contained but never awaited.
   * Listener failure stops and drains the whole runtime without reversing a commit; a failed close remains terminal.
   * @returns Idempotent disposer. New listeners wait until the next publication; removed listeners do not start. */
  subscribeInvalidation(listener: Subscription['listener']): () => void {
    if (!this.active()) throw new RegistryIngestError('closed')
    const subscription = { listener }
    this.subscriptions.add(subscription)
    return () => { this.subscriptions.delete(subscription) }
  }

  /** Execute against the sole current ingest handle after earlier consumers settle.
   * @param operation - Private operation; it must not retain or close the handle.
   * @returns The operation's actual result; uncertain writes reject after closing the isolated handle. */
  run<T>(operation: (store: RegistryIngest) => Promise<T>): Promise<T> {
    if (!this.active()) return Promise.reject(new RegistryIngestError('closed'))
    const result = this.chain.then(async () => {
      if (!this.active()) throw new RegistryIngestError('closed')
      try {
        if (this.store === undefined) {
          try {
            const ingest = await openRegistryIngest(this.facility, this.organizationId, this.limits,
              this.audit, this.directory, this.bindings, this.storage)
            const unsubscribe = ingest.subscribeInvalidation((change) => {
              this.publish(Object.freeze({ kind: 'authorization', change }))
            })
            const unsubscribeBinding = ingest.subscribeBindingInvalidation((change) => {
              this.publish(Object.freeze({ kind: 'binding', change }))
            })
            const unsubscribeAudit = ingest.subscribeAudit((record) => {
              this.alerts?.reportAudit(record)
              const completion = record.completion
              if (completion?.outcome.kind !== 'rejected' || completion.outcome.category !== 'signature-failure') return
              this.ctx.logger.warn('Registry signature verification failed: %j', {
                organizationId: record.organizationId, operationId: record.operationId,
                action: record.action, disclosureId: record.requestedDisclosureId,
                completedAt: completion.completedAt, actor: completion.actor,
              })
            })
            this.store = { ingest, unsubscribe, unsubscribeBinding, unsubscribeAudit }
          }
          catch (error) { this.abort.abort(); throw error }
        }
        if (!this.active()) throw new RegistryIngestError('closed')
        return await operation(this.store.ingest)
      } catch (error) {
        if (error instanceof RegistryIngestError && error.code === 'storage-unavailable') {
          this.reportAuditedStorageFailure()
          await this.release()
        }
        throw error
      } finally {
        if (!this.active()) await this.release()
      }
    })
    this.chain = result.then(() => {}, () => { /* The operation's caller receives its failure; later work rechecks admission. */ })
    return result
  }

  /** Resolve one confirmed v5/v6 device credential and reject V6 cross-protocol secret reuse. */
  authenticateBindingCredential(bindingId: RegistryBindingId,
    presentedHash: RegistryDeviceSecretHash,
    sameRawBridgeHash: RegistryBridgeSecretHash): Promise<RegistryProducerAuthority> {
    return this.run(store => store.authenticateBindingCredential(bindingId, presentedHash, sameRawBridgeHash))
  }

  /** Recheck one dshb1 bearer, cross-protocol secret independence and current v6 authority. */
  authenticateBridgeCredential(bindingId: RegistryBindingId,
    presentedHash: RegistryBridgeSecretHash,
    sameRawDeviceHash: RegistryDeviceSecretHash): Promise<RegistryBridgeAuthority> {
    return this.run(store => store.authenticateBridgeCredential(bindingId, presentedHash, sameRawDeviceHash))
  }

  /** Reject a Host access snapshot failure through this owner's admission and optional journal.
   * @param disclosureId - Independently selected resource identifier; caller payload and exception are never accepted.
   * @returns A promise that rejects; owner closure, audit limits or journal failure may take precedence over invalid-input. */
  rejectAccessInput(disclosureId: DisclosureId): Promise<never> {
    return this.run(ingest => ingest.rejectAccessInput(disclosureId))
  }

  /** Stop admission and wait for consumers and the exclusive domain to close.
   * @returns One shared disposal result; a failed close is never treated as successful recovery. */
  close(): Promise<void> {
    this.abort.abort()
    this.disposal ??= this.chain.then(async () => {
      try {
        await this.release()
        if (this.closeFailure !== undefined) throw this.closeFailure
      } finally { this.subscriptions.clear() }
    })
    return this.disposal
  }

  private async release(): Promise<void> {
    this.transport.clear()
    const owned = this.store
    this.store = undefined
    if (owned === undefined) return
    owned.unsubscribe()
    owned.unsubscribeBinding()
    owned.unsubscribeAudit()
    this.publish(Object.freeze({ kind: 'owner-unavailable' }))
    try { await owned.ingest.close() } catch {
      // Backend errors can contain persisted bodies or paths; this owner exposes only the close outcome.
      this.closeFailure = new Error('Registry ingest store close failed')
      this.abort.abort()
      throw this.closeFailure
    }
  }

  private publish(notice: RegistryRuntimeInvalidation): void {
    for (const subscription of [...this.subscriptions]) {
      if (!this.subscriptions.has(subscription)) continue
      try {
        const result = subscription.listener(notice)
        if (result !== undefined) void result.catch(() => { this.listenerFailed(subscription) })
      } catch { this.listenerFailed(subscription) }
    }
  }

  private listenerFailed(subscription: Subscription): void {
    this.subscriptions.delete(subscription)
    this.reportListenerFailure()
    // The commit callback cannot await the queue containing itself. Close admits no further work and drains independently.
    void this.close().catch(() => { this.reportListenerFailure() })
  }

  private reportListenerFailure(): void {
    try { this.ctx.logger.error('Registry runtime invalidation listener failed') } catch {
      // A failed diagnostic must not reverse a committed write or prevent runtime isolation.
    }
  }

  private reportAuditedStorageFailure(): void {
    if (this.audit === undefined) return
    this.alerts?.reportStorageUnavailable(this.organizationId)
    try { this.ctx.logger.error('Registry audit-enabled storage unavailable; runtime owner isolated') } catch {
      // Logger failure cannot replace the storage result or prevent owner isolation.
    }
  }
}
