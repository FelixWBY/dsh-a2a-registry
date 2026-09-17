/** Single-owner serialized admission; failed writes quarantine cached state until fresh-backend reopen. */
import { defineDomain, domainTable, type Domain, type DomainFacility } from '@deepseek-ai/dsh-storage-domain'
import { z } from 'zod'
import { MailboxError, requireMailbox, validateLimits } from './record.ts'
import type { MailboxLimits } from './types.ts'

function specification<T>(name: string, tenantId: string | undefined, parse: (value: unknown) => T) {
  return defineDomain({ name, version: 1, layout: 'single',
    ...(tenantId === undefined ? {} : { tenantId }),
    tables: { records: domainTable<string, T>(z.unknown().transform(parse)) } })
}

/** Internal owner shared by Registry queue and separate instance-local receipt facility. */
export class RecordOwner<T> {
  readonly table
  readonly controller = new AbortController()
  private chain: Promise<void> = Promise.resolve()
  private pending = 0
  private unavailable = false
  private disposal: Promise<void> | undefined
  private readonly abort: () => void

  /** @param domain - Exclusive domain handle.
   * @param limits - Validated bounds.
   * @param signal - Consumer scope; the caller must still await close on teardown. */
  constructor(private readonly domain: Domain<ReturnType<typeof specification<T>>>,
    readonly limits: MailboxLimits, readonly signal: AbortSignal) {
    this.table = domain.table('records')
    this.abort = () => { this.controller.abort() }
    signal.addEventListener('abort', this.abort, { once: true })
    if (signal.aborted) this.abort()
  }

  /** Reject operations after scope release or ambiguous persistence. */
  assertLive(): void {
    requireMailbox(!this.unavailable, 'unavailable')
    requireMailbox(!this.controller.signal.aborted, 'closed')
  }

  /** Disable all cached reads and body release after uncertain effects. */
  isolate(): void { this.unavailable = true; this.controller.abort() }

  /** Serialize one complete consumer operation with bounded admission.
   * @param job - Operation that must settle on scope abort.
   * @returns Its result after earlier operations settle. */
  async run<R>(job: () => R | Promise<R>): Promise<R> {
    this.assertLive()
    requireMailbox(this.pending < this.limits.maxPendingOperations, 'limit')
    this.pending++
    const result = this.chain.then(() => { this.assertLive(); return job() })
    this.chain = result.then(() => { this.pending-- }, () => { this.pending-- })
    return result
  }

  /** Commit one record; a rejecting backend may already have committed it.
   * @param key - Exact aggregate key.
   * @param value - Validated detached aggregate. */
  async put(key: string, value: T): Promise<void> {
    this.assertLive()
    try { await this.table.put(key, value) } catch {
      this.isolate()
      throw new MailboxError('storage-failed')
    }
    this.assertLive()
  }

  /** Abort admission, drain queued work, and release the unit exactly once.
   * @returns Resolution after pending adapters and storage have settled. */
  close(): Promise<void> {
    if (this.disposal === undefined) {
      this.controller.abort()
      this.signal.removeEventListener('abort', this.abort)
      this.disposal = this.chain.then(() => this.domain.close())
    }
    return this.disposal
  }
}

/** Open one domain and validate every key/aggregate before publishing it.
 * @param facility - Sole writer's real storage-domain facility.
 * @param name - Package-owned domain name.
 * @param limits - Explicit bounds.
 * @param signal - Consumer lifecycle.
 * @param parse - Strict durable parser.
 * @param keyOf - Aggregate identity key.
 * @returns Validated owner; caller must await close. */
export async function openOwner<T>(facility: DomainFacility, name: string, limits: MailboxLimits, signal: AbortSignal,
  parse: (value: unknown) => T, keyOf: (value: T) => string,
  occupiesRequestCapacity: (value: T) => boolean = () => true,
  tenantId?: string): Promise<RecordOwner<T>> {
  validateLimits(limits)
  requireMailbox(!signal.aborted, 'closed')
  let domain: Domain<ReturnType<typeof specification<T>>>
  try { domain = await facility.open(specification(name, tenantId, parse)) } catch { throw new MailboxError('invalid-storage') }
  try {
    requireMailbox(!signal.aborted, 'closed')
    const table = domain.table('records')
    requireMailbox(table.size <= limits.maxRetainedRequests, 'invalid-storage')
    let occupied = 0
    for (const [key, record] of table.entries()) {
      requireMailbox(key === keyOf(record), 'invalid-storage')
      if (occupiesRequestCapacity(record)) occupied++
    }
    requireMailbox(occupied <= limits.maxRequests, 'invalid-storage')
    return new RecordOwner(domain, limits, signal)
  } catch (error) {
    await domain.close()
    if (error instanceof MailboxError && error.code === 'closed') throw error
    throw new MailboxError('invalid-storage')
  }
}
