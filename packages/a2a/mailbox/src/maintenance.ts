/** Ciphertext cleanup without codec or plaintext access over the durable mailbox owner. */
import { transitionA2aRequest } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { DomainFacility } from '@deepseek-ai/dsh-storage-domain'
import { openOwner, type RecordOwner } from './owner.ts'
import { isMailboxTombstone, MailboxError, parseMailboxOrganization, parseRecord, recordKey, requireMailbox, type MailboxRecord } from './record.ts'
import type { MailboxExpiryBatchOptions, MailboxExpiryBatchReceipt, MailboxLimits } from './types.ts'

interface ExpiryBatchInput {
  readonly organizationId: MailboxExpiryBatchOptions['organizationId']
  readonly now: number
  readonly maxItems: number
  readonly cancelled: () => boolean
}

function abortState(signal: AbortSignal): unknown {
  return Reflect.get(AbortSignal.prototype, 'aborted', signal)
}

function batchInput(options: MailboxExpiryBatchOptions): ExpiryBatchInput {
  try {
    const candidate: unknown = options
    requireMailbox(typeof candidate === 'object' && candidate !== null, 'invalid-input')
    const keys = Reflect.ownKeys(candidate)
    requireMailbox(keys.length >= 3 && keys.length <= 4
      && keys.every(key => typeof key === 'string' && (key === 'organizationId' || key === 'now'
        || key === 'maxItems' || key === 'signal'))
      && keys.includes('organizationId') && keys.includes('now') && keys.includes('maxItems'), 'invalid-input')
    const organizationId = parseMailboxOrganization((candidate as MailboxExpiryBatchOptions).organizationId)
    const now = (candidate as MailboxExpiryBatchOptions).now
    const maxItems = (candidate as MailboxExpiryBatchOptions).maxItems
    const signal = (candidate as MailboxExpiryBatchOptions).signal
    requireMailbox(Number.isSafeInteger(now) && now >= 0 && now < Number.MAX_SAFE_INTEGER && !Object.is(now, -0)
      && Number.isSafeInteger(maxItems) && maxItems > 0, 'invalid-input')
    if (signal === undefined) return { organizationId, now, maxItems, cancelled: () => false }
    requireMailbox(typeof abortState(signal) === 'boolean', 'invalid-input')
    return { organizationId, now, maxItems, cancelled: () => abortState(signal) === true }
  } catch {
    throw new MailboxError('invalid-input')
  }
}

function needsExpiry(record: MailboxRecord, input: ExpiryBatchInput): boolean {
  return record.binding.organizationId === input.organizationId && input.now >= record.binding.expiresAt
    && (record.state === 'queued' || record.state === 'delivered' || record.state === 'running' || record.reply !== null)
}

/** Build the one-record stop mutation shared by authorized dispatch and unattended expiry.
 * @param record - Current validated aggregate.
 * @param reason - Authorization loss cancels queued work; time expiry uses the expiry terminal.
 * @param now - Trusted operation time.
 * @returns The unchanged record or its next complete aggregate. */
export function stoppedRecord(record: MailboxRecord, reason: 'cancel' | 'expire', now: number): MailboxRecord {
  let state = record.state
  if (record.state === 'queued') state = reason === 'cancel' ? 'cancelled' : 'expired'
  else if (record.state === 'delivered' || record.state === 'running') state = 'failed'
  else if (record.reply === null) return record
  requireMailbox(record.version < Number.MAX_SAFE_INTEGER, 'limit')
  return { ...record, state: transitionA2aRequest(record.state, state), version: record.version + 1,
    updatedAt: now, question: null, reply: state === 'completed' ? null : record.reply }
}

/** Process one bounded expiry batch on an already exclusive mailbox owner. */
export async function processExpiryBatch(owner: RecordOwner<MailboxRecord>,
  options: MailboxExpiryBatchOptions): Promise<MailboxExpiryBatchReceipt> {
  const input = batchInput(options)
  return owner.run(async () => {
    let cleaned = 0
    for (const [key, record] of owner.table.entries()) {
      if (!needsExpiry(record, input)) continue
      if (cleaned === input.maxItems || input.cancelled()) return { cleaned, hasMore: true }
      const next = parseRecord(stoppedRecord(record, 'expire', input.now), owner.limits)
      await owner.put(key, next)
      cleaned++
    }
    return { cleaned, hasMore: false }
  })
}

/** Open a cleanup-only facade without an encryption codec or authorization provider.
 * @param facility - Sole writer's real storage-domain facility.
 * @param limits - Complete retained-record and owner-admission bounds.
 * @param signal - Consumer lifecycle; close must still be awaited.
 * @returns An owner exposing only expiry cleanup and quiescent close. */
export async function openA2aMailboxMaintenance(facility: DomainFacility, limits: MailboxLimits,
  signal: AbortSignal): Promise<A2aMailboxMaintenance> {
  const resolved = Object.freeze({ ...limits })
  const owner = await openOwner(facility, 'a2a_mailbox', resolved, signal,
    value => parseRecord(value, resolved), record => recordKey(record.binding), record => !isMailboxTombstone(record))
  return new A2aMailboxMaintenance(owner)
}

/** Restricted mailbox facade that can remove expired ciphertext but cannot expose message bodies. */
export class A2aMailboxMaintenance {
  /** @param owner - Validated exclusive mailbox owner from openA2aMailboxMaintenance. */
  constructor(private readonly owner: RecordOwner<MailboxRecord>) {}

  /** Remove expired ciphertext with one atomic write per changed record.
   * @param options - Trusted organization, server clock, batch bound and cancellation.
   * @returns Committed record count and whether another eligible record remains. */
  processExpiryBatch(options: MailboxExpiryBatchOptions): Promise<MailboxExpiryBatchReceipt> {
    return processExpiryBatch(this.owner, options)
  }

  /** Stop admission and drain accepted writes before releasing the domain.
   * @returns Idempotent teardown completion. */
  close(): Promise<void> { return this.owner.close() }
}
