/** Opt-in Registry mailbox-expiry scheduling over one exclusive maintenance owner. */
import { setTimeout as delay } from 'node:timers/promises'
import type { Context, FiberState } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import {
  MailboxError,
  openA2aMailboxMaintenance,
  type A2aMailboxMaintenance,
  type MailboxLimits,
} from '@deepseek-ai/dsh-a2a-mailbox'
import type { DomainFacility } from '@deepseek-ai/dsh-storage-domain'

/** Private plugin name; registry-app owns whether this worker is installed. */
export const name = 'registry-mailbox-maintenance'
/** Storage replacement disposes the mailbox owner before another round can enter. */
export const inject = ['storageDomain']

/** Complete opt-in mailbox cleanup configuration; no field has a deployment default. */
export interface RegistryMailboxMaintenanceConfig {
  /** Organization selected from the Registry-owned multi-organization mailbox domain. */
  organizationId: OrganizationId
  /** Exact persisted-record and operation bounds used to validate the mailbox domain. */
  limits: MailboxLimits
  /** Positive delay after each bounded round or recoverable storage failure. */
  intervalMs: number
  /** Maximum ciphertext-cleanup commits in one round. */
  maxItems: number
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
/** Complete mailbox maintenance schema. */
export const Config: z<RegistryMailboxMaintenanceConfig> = z.object({
  organizationId: z.transform(z.string().pattern(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$(?![\s\S])/).required(),
    value => brandString<OrganizationId>(value)).required(),
  limits: z.object({
    maxTextBytes: positive(),
    maxTextCharacters: positive(),
    maxCiphertextBytes: positive(),
    maxAggregateBytes: positive(),
    maxRequests: positive(),
    maxRetainedRequests: positive(),
    maxPendingOperations: positive(),
    maxLifetimeMs: positive(),
  }).required(),
  intervalMs: positive().max(2 ** 31 - 1),
  maxItems: positive(),
})

// Cordis const enums have no runtime export; keep these typed values aligned with the pinned framework.
const FIBER_LOADING = 1 as FiberState.LOADING
const FIBER_ACTIVE = 2 as FiberState.ACTIVE

/** Serializes access to one facility-bound mailbox owner and reloads ambiguous writes from disk. */
class RegistryMailboxMaintenanceStore {
  private owner: A2aMailboxMaintenance | undefined
  private chain: Promise<void> = Promise.resolve()
  private disposal: Promise<void> | undefined
  private closeFailure: Error | undefined

  /** @param ctx - Exact consumer context whose storage dependency is observed.
   * @param facility - Initially injected facility; replacement never redirects this owner.
   * @param limits - Complete validated mailbox storage bounds.
   * @param abort - Shared admission and shutdown controller. */
  constructor(private readonly ctx: Context, private readonly facility: DomainFacility,
    private readonly limits: MailboxLimits, private readonly abort: AbortController) {}

  /** Detect consumer disposal or silent provider replacement before another owned operation.
   * @returns Whether this runtime may admit work. */
  active(): boolean {
    if (this.ctx.fiber.uid === null
      || (this.ctx.fiber.state !== FIBER_LOADING && this.ctx.fiber.state !== FIBER_ACTIVE)
      || this.ctx.get('storageDomain') !== this.facility) this.abort.abort()
    return !this.abort.signal.aborted
  }

  /** Run one operation after earlier rounds, opening a freshly validated owner when required.
   * @param operation - Borrowed operation that must not retain or close the mailbox handle.
   * @returns The operation result after any required open.
  */
  run<T>(operation: (owner: A2aMailboxMaintenance) => Promise<T>): Promise<T> {
    if (!this.active()) return this.close().then(() => { throw new MailboxError('closed') })
    const result = this.chain.then(async () => {
      if (!this.active()) throw new MailboxError('closed')
      try {
        if (this.owner === undefined) {
          try {
            this.owner = await openA2aMailboxMaintenance(this.facility, this.limits, this.abort.signal)
          } catch (error) {
            this.abort.abort()
            throw error instanceof MailboxError ? error : new MailboxError('invalid-storage')
          }
        }
        if (!this.active()) throw new MailboxError('closed')
        return await operation(this.owner)
      } catch (error) {
        if (error instanceof MailboxError && error.code === 'storage-failed') await this.release()
        throw error
      } finally {
        if (!this.active()) await this.release()
      }
    })
    this.chain = result.then(() => {}, () => { /* The worker receives failure; later work rechecks admission. */ })
    return result
  }

  /** Stop admission and wait for opening, cleanup and storage close to settle.
   * @returns One idempotent quiescent disposal result. */
  close(): Promise<void> {
    this.abort.abort()
    this.disposal ??= this.chain.then(async () => {
      await this.release()
      if (this.closeFailure !== undefined) throw this.closeFailure
    })
    return this.disposal
  }

  private async release(): Promise<void> {
    const owned = this.owner
    this.owner = undefined
    if (owned === undefined) return
    try { await owned.close() } catch {
      this.closeFailure = new Error('Registry mailbox maintenance store close failed')
      this.abort.abort()
      throw this.closeFailure
    }
  }
}

/** Run nonoverlapping organization-scoped expiry sweeps through the facility-bound owner.
 * @param ctx - Private logging and lifecycle context.
 * @param config - Validated organization, mailbox limits and scheduling bounds.
 * @param store - Sole runtime owner for the mailbox domain.
 * @param signal - Stops later admissions while an accepted write drains.
 * @returns Worker settlement; deterministic errors stop with a content-free diagnostic. */
async function runMailboxMaintenance(ctx: Context, config: RegistryMailboxMaintenanceConfig,
  store: RegistryMailboxMaintenanceStore, signal: AbortSignal): Promise<void> {
  const options = structuredClone(config)
  while (store.active()) {
    try {
      const now = Date.now()
      await store.run(owner => owner.processExpiryBatch({
        organizationId: options.organizationId,
        now,
        maxItems: options.maxItems,
        signal,
      }))
    } catch (error) {
      if (!store.active() && error instanceof MailboxError && error.code === 'closed') return
      const code = error instanceof MailboxError ? error.code : 'unexpected-failure'
      ctx.logger.error('Registry mailbox maintenance stopped or deferred: %s', code)
      if (code !== 'storage-failed') return
    }
    if (!store.active()) return
    await delay(options.intervalMs, undefined, { signal }).catch(() => {
      // Fixed validated timer arguments leave only AbortError from the owned cancellation signal.
    })
  }
}

/** Pre-open the mailbox store, then publish the optional worker for this child lifetime.
 * @param ctx - Dependency-scoped lifecycle with one configured storage facility.
 * @param config - Complete opt-in cleanup configuration.
 * @returns Startup only after durable mailbox validation succeeds. */
export async function apply(ctx: Context, config: RegistryMailboxMaintenanceConfig): Promise<void> {
  const options = structuredClone(config)
  const abort = new AbortController()
  const store = new RegistryMailboxMaintenanceStore(ctx, ctx.storageDomain, options.limits, abort)
  let worker = Promise.resolve()
  ctx.effect(() => async () => {
    abort.abort()
    const outcomes = await Promise.allSettled([worker, store.close()])
    if (outcomes.some(outcome => outcome.status === 'rejected')) {
      ctx.logger.error('Registry mailbox maintenance cleanup failed')
    }
  }, 'registry-app: exclusive mailbox maintenance lifecycle')
  await store.run(async () => {})
  if (!store.active()) throw new MailboxError('closed')
  worker = runMailboxMaintenance(ctx, options, store, abort.signal)
}
