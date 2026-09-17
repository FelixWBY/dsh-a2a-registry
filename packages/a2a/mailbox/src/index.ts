/** Encrypted per-request queue; a trusted authorization owner supplies cross-owner commit leases. */
import type { DomainFacility } from '@deepseek-ai/dsh-storage-domain'
import { evaluateA2aDispatch, transitionA2aRequest } from '@deepseek-ai/dsh-a2a-registry-domain'
import { openOwner, type RecordOwner } from './owner.ts'
import { processExpiryBatch, stoppedRecord } from './maintenance.ts'
import { bodyAad, bytes, checkCiphertext, isMailboxTombstone, MailboxError, parseBinding, parseRecord, parseTransition,
  receiptOf, recordKey, requireMailbox, textHash, type MailboxRecord } from './record.ts'
import type { MailboxAuthorizationLease, MailboxBinding, MailboxDispatch, MailboxExpiryBatchOptions, MailboxExpiryBatchReceipt,
  MailboxOperation, MailboxOptions, MailboxReceipt, MailboxReply, MailboxTransition } from './types.ts'

export type * from './types.ts'
export { MailboxError } from './record.ts'
export { openA2aConsumerReceipts, A2aConsumerReceipts } from './receipts.ts'
export { openA2aMailboxMaintenance, A2aMailboxMaintenance } from './maintenance.ts'

type Fence = (() => void) & { readonly signal: AbortSignal }

function inputBinding(value: MailboxBinding): MailboxBinding {
  try { return parseBinding(value) } catch { throw new MailboxError('invalid-input') }
}

function sameBinding(left: MailboxBinding, right: MailboxBinding): boolean { return bodyAad(left, 'question') === bodyAad(right, 'question') }

/** Whether a running receipt has lost its Registry-owned execution lease at the supplied server time. */
export function isMailboxExecutionLeaseExpired(
  receipt: Pick<MailboxReceipt, 'state' | 'updatedAt'>,
  now: number,
  executionLeaseMs: number,
): boolean {
  requireMailbox(Number.isSafeInteger(now) && now >= 0
    && Number.isSafeInteger(executionLeaseMs) && executionLeaseMs > 0, 'invalid-input')
  return receipt.state === 'running' && now >= receipt.updatedAt && now - receipt.updatedAt >= executionLeaseMs
}

/**
 * Open the encrypted Registry-side queue; no network, identity, codec, or authorization owner is invented.
 * @param facility - Sole writer's real storage-domain facility; fresh backend required after uncertain writes.
 * @param options - Explicit limits, mandatory AEAD codec, trusted authority lease, and consumer scope.
 * @returns An owner that must be closed and drained on consumer teardown.
 */
export async function openA2aMailbox(facility: DomainFacility, options: MailboxOptions): Promise<A2aMailbox> {
  requireMailbox(Number.isSafeInteger(options.executionLeaseMs) && options.executionLeaseMs > 0
    && options.executionLeaseMs <= 2_147_483_647, 'invalid-input')
  const resolved = { ...options, limits: Object.freeze({ ...options.limits }),
    codec: Object.freeze({ seal: options.codec.seal.bind(options.codec), open: options.codec.open.bind(options.codec) }) }
  const owner = await openOwner(facility, resolved.storage?.domainName ?? 'a2a_mailbox', resolved.limits, resolved.signal,
    value => parseRecord(value, resolved.limits), record => recordKey(record.binding),
    record => !isMailboxTombstone(record), resolved.storage?.tenantId)
  return new A2aMailbox(owner, resolved)
}

/** Durable queue kernel; all plaintext access requires a current, single-use authorization lease. */
export class A2aMailbox {
  /** @param owner - Validated owner supplied by openA2aMailbox.
   * @param options - Frozen opening dependencies. */
  constructor(private readonly owner: RecordOwner<MailboxRecord>, private readonly options: MailboxOptions) {}

  /**
   * Enqueue one immutable question, including while its source is offline; exact retries never re-encrypt.
   * @param binding - Current requester, organization, source, checkpoint, initial version, and expiry.
   * @param question - Complete plain text; no attachment or tool-execution fields are accepted.
   * @returns Committed metadata; different content under an existing request ID rejects.
   */
  async enqueue(binding: MailboxBinding, question: string): Promise<MailboxReceipt> {
    const identity = inputBinding(binding)
    const digest = textHash(question, this.options.limits)
    return this.owner.run(() => this.authorized(identity, 'enqueue', async (lease, fence) => {
      const existing = this.owner.table.get(recordKey(identity))
      if (existing !== undefined) {
        requireMailbox(sameBinding(existing.binding, identity) && existing.questionHash === digest, 'conflict')
        this.allowed(existing, lease)
        return receiptOf(existing)
      }
      const candidate: MailboxRecord = { binding: identity, state: 'queued', version: 1,
        authorizationVersion: identity.authorizationVersion, questionHash: digest, replyHash: null,
        updatedAt: lease.now, question: null, reply: null }
      this.allowed(candidate, lease)
      requireMailbox(lease.access?.authorizationVersion === identity.authorizationVersion, 'conflict')
      requireMailbox(identity.expiresAt - lease.now <= this.options.limits.maxLifetimeMs, 'limit')
      requireMailbox(this.owner.table.size < this.options.limits.maxRetainedRequests, 'limit')
      await this.makeRoom(lease.now, fence)
      const ciphertext = await this.seal(question, candidate, 'question', fence)
      const next = { ...candidate, question: ciphertext }
      // Stops remove ciphertext, but reserve widest metadata so full records remain stoppable.
      requireMailbox(bytes({ ...next, version: Number.MAX_SAFE_INTEGER, updatedAt: Number.MAX_SAFE_INTEGER,
        authorizationVersion: Number.MAX_SAFE_INTEGER }) <= this.options.limits.maxAggregateBytes, 'limit')
      await this.commit(next, fence)
      return receiptOf(next)
    }))
  }

  /**
   * Reauthorize and durably deliver, wait, cancel, or expire; delivered retries return the same question.
   * @param binding - Exact immutable request identity from a queue receipt.
   * @param expectedVersion - Conditional queue version; a repeated delivered request accepts an older version.
   * @returns Metadata and question only for an authorized online delivered request.
   */
  async dispatch(binding: MailboxBinding, expectedVersion: number): Promise<MailboxDispatch> {
    const identity = inputBinding(binding)
    return this.owner.run(() => this.authorized(identity, 'dispatch', async (lease, fence) => {
      let record = this.get(identity)
      this.version(record, expectedVersion, record.state === 'delivered')
      const decision = this.decision(record, lease)
      if (decision.kind === 'cancel' || decision.kind === 'expire') {
        record = await this.stop(record, decision.kind, lease.now, fence)
        return { receipt: receiptOf(record), question: null }
      }
      if (record.state === 'queued') {
        const changed = decision.request.state !== record.state || decision.request.authorizationVersion !== record.authorizationVersion
        if (changed) record = await this.change(record, decision.request.state, decision.request.authorizationVersion, lease.now, fence)
      }
      const question = (record.state === 'delivered' || record.state === 'running')
        && lease.sourceOnline && lease.actor.kind === 'source'
        ? await this.open(record, 'question', fence) : null
      return { receipt: receiptOf(record), question }
    }))
  }

  /**
   * Reserve execution for a delivered request, or take over an expired running lease, before starting its local Agent.
   * @param binding - Exact source-authenticated request identity.
   * @param expectedVersion - Delivered receipt version; retries may supply its older version.
   * @returns Current receipt, whether this call acquired execution, and the server-selected renewal interval.
   * An unexpired running or terminal retry never grants another execution. An uncertain write rejects.
   */
  async startExecution(binding: MailboxBinding, expectedVersion: number): Promise<{
    receipt: MailboxReceipt
    started: boolean
    renewAfterMs: number
  }> {
    const identity = inputBinding(binding)
    return this.owner.run(() => this.authorized(identity, 'running', async (lease, fence) => {
      const record = this.get(identity)
      this.version(record, expectedVersion, record.state !== 'delivered')
      const authorizationVersion = this.allowed(record, lease)
      const renewAfterMs = this.renewAfterMs()
      if (record.state !== 'delivered' && !this.executionLeaseExpired(record, lease.now)) {
        return { receipt: receiptOf(record), started: false, renewAfterMs }
      }
      requireMailbox(lease.sourceOnline, 'unavailable')
      const next = await this.change(record, 'running', authorizationVersion, lease.now, fence)
      return { receipt: receiptOf(next), started: true, renewAfterMs }
    }))
  }

  /**
   * Renew the current running execution lease and advance its version fence.
   * @param binding - Exact source-authenticated request identity.
   * @param expectedVersion - Exact current execution version; stale owners cannot renew.
   * @returns The newly committed receipt and server-selected next renewal interval.
   */
  async renewExecution(binding: MailboxBinding, expectedVersion: number): Promise<{
    receipt: MailboxReceipt
    renewAfterMs: number
  }> {
    const identity = inputBinding(binding)
    return this.owner.run(() => this.authorized(identity, 'running', async (lease, fence) => {
      const record = this.get(identity)
      this.version(record, expectedVersion, false)
      const authorizationVersion = this.allowed(record, lease)
      requireMailbox(record.state === 'running' && !this.executionLeaseExpired(record, lease.now), 'conflict')
      requireMailbox(lease.sourceOnline, 'unavailable')
      const next = await this.change(record, 'running', authorizationVersion, lease.now, fence)
      return { receipt: receiptOf(next), renewAfterMs: this.renewAfterMs() }
    }))
  }

  /**
   * Read current metadata with a fresh requester or source authorization lease; no body is decrypted.
   * @param binding - Exact immutable request identity authenticated by the lease owner.
   * @returns Detached current metadata while the pinned ask authorization remains valid.
   * Revoked or expired requests are stopped and hidden as not-found, matching protected reply reads.
   */
  async status(binding: MailboxBinding): Promise<MailboxReceipt> {
    const identity = inputBinding(binding)
    return this.owner.run(() => this.authorized(identity, 'status', async (lease, fence) => {
      const record = this.get(identity)
      const decision = this.decision(record, lease)
      if (decision.kind === 'cancel' || decision.kind === 'expire') {
        await this.stop(record, decision.kind, lease.now, fence)
        throw new MailboxError('not-found')
      }
      return receiptOf(record)
    }))
  }

  /**
   * Advance the text-only lifecycle; all mutations reauthorize, and replies replace question ciphertext.
   * @param binding - Fixed request identity, authenticated by the host lease.
   * @param expectedVersion - Current queue version; exact same-state retries are no-op receipts.
   * @param transition - Running, completed text, failed, or queued cancellation.
   * @returns Committed metadata; a stale or forbidden transition makes no mutation.
   */
  async transition(binding: MailboxBinding, expectedVersion: number, transition: MailboxTransition): Promise<MailboxReceipt> {
    const identity = inputBinding(binding)
    const update = parseTransition(transition)
    const digest = update.state === 'completed' ? textHash(update.reply, this.options.limits) : null
    return this.owner.run(() => this.authorized(identity, update.state, async (lease, fence) => {
      const record = this.get(identity)
      this.version(record, expectedVersion, record.state === update.state)
      const authorizationVersion = this.allowed(record, lease)
      requireMailbox(record.state === update.state || expectedVersion === record.version, 'conflict')
      try { transitionA2aRequest(record.state, update.state) } catch { throw new MailboxError('conflict') }
      if (record.state === update.state) {
        requireMailbox(record.replyHash === digest, 'conflict')
        return receiptOf(record)
      }
      requireMailbox(record.state !== 'running' || !this.executionLeaseExpired(record, lease.now), 'conflict')
      const reply = update.state === 'completed' ? await this.seal(update.reply, record, 'reply', fence) : null
      const next = await this.change(record, update.state, authorizationVersion, lease.now, fence,
        { reply, replyHash: digest })
      return receiptOf(next)
    }))
  }

  /**
   * Read a completed reply only with current authorization; an expired/revoked reply is purged.
   * @param binding - Exact immutable request identity.
   * @returns Complete text and its metadata receipt; previously returned copies cannot be recalled.
   */
  async reply(binding: MailboxBinding): Promise<MailboxReply> {
    const identity = inputBinding(binding)
    return this.owner.run(() => this.authorized(identity, 'reply', async (lease, fence) => {
      const record = this.get(identity)
      const decision = this.decision(record, lease)
      if (decision.kind === 'cancel' || decision.kind === 'expire') {
        await this.stop(record, decision.kind, lease.now, fence)
        throw new MailboxError('not-found')
      }
      requireMailbox(record.state === 'completed', 'not-found')
      return { receipt: receiptOf(record), text: record.reply === null ? null : await this.open(record, 'reply', fence) }
    }))
  }

  /** Internal metadata-only scan, bounded by maxRetainedRequests; it grants no plaintext access.
   * @returns Detached receipts for maintenance, including terminal reply cleanup after expiry. */
  async pending(): Promise<readonly MailboxReceipt[]> {
    return this.owner.run(() => [...this.owner.table.entries()].map(([, record]) => receiptOf(record)))
  }

  /** Remove expired ciphertext without authentication or decryption; retained receipts remain durable.
   * @param options - Trusted organization, server clock, batch bound and cancellation.
   * @returns Committed record count and whether another eligible record remains. */
  processExpiryBatch(options: MailboxExpiryBatchOptions): Promise<MailboxExpiryBatchReceipt> {
    return processExpiryBatch(this.owner, options)
  }

  /** Abort admission and drain all adapters/storage before releasing the domain.
   * @returns Idempotent teardown completion. */
  close(): Promise<void> { return this.owner.close() }

  private get(binding: MailboxBinding): MailboxRecord {
    const record = this.owner.table.get(recordKey(binding))
    requireMailbox(record !== undefined && sameBinding(record.binding, binding), 'not-found')
    return record
  }

  private version(record: MailboxRecord, expected: number, retry: boolean): void {
    requireMailbox(Number.isSafeInteger(expected) && expected > 0 && (expected === record.version || retry && expected < record.version), 'conflict')
  }

  private executionLeaseExpired(record: MailboxRecord, now: number): boolean {
    return isMailboxExecutionLeaseExpired(record, now, this.options.executionLeaseMs)
  }

  private renewAfterMs(): number { return Math.max(1, Math.floor(this.options.executionLeaseMs / 3)) }

  private decision(record: MailboxRecord, lease: MailboxAuthorizationLease) {
    const access = lease.access?.instanceId === record.binding.instanceId ? lease.access : null
    return evaluateA2aDispatch({ ...record.binding, authorizationVersion: record.authorizationVersion, state: 'queued' },
      lease.subject, access, lease.now, lease.sourceOnline && lease.actor.kind === 'source', lease.checkpoint)
  }

  private allowed(record: MailboxRecord, lease: MailboxAuthorizationLease): number {
    const decision = this.decision(record, lease)
    requireMailbox(decision.kind === 'deliver' || decision.kind === 'wait', 'not-found')
    return decision.request.authorizationVersion
  }

  private async stop(record: MailboxRecord, reason: 'cancel' | 'expire', now: number, fence: Fence): Promise<MailboxRecord> {
    const next = stoppedRecord(record, reason, now)
    if (next === record) return record
    await this.commit(next, fence)
    return next
  }

  /** Reclaim one oldest terminal body while retaining its immutable idempotency tombstone. */
  private async makeRoom(now: number, fence: Fence): Promise<void> {
    const retained = [...this.owner.table.entries()].filter(([, record]) => !isMailboxTombstone(record))
    if (retained.length < this.options.limits.maxRequests) return
    const candidates = retained.filter(([, record]) => record.state === 'completed')
      .sort(([leftKey, left], [rightKey, right]) => left.updatedAt - right.updatedAt
        || (leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0))
    const oldest = candidates[0]
    requireMailbox(oldest !== undefined, 'limit')
    const [key, record] = oldest
    const tombstone = stoppedRecord(record, 'expire', now)
    requireMailbox(isMailboxTombstone(tombstone), 'limit')
    fence()
    await this.owner.put(key, parseRecord(tombstone, this.options.limits))
    fence()
  }

  private async change(record: MailboxRecord, state: MailboxRecord['state'], authorizationVersion: number, now: number,
    fence: Fence, extra: Partial<Pick<MailboxRecord, 'reply' | 'replyHash'>> = {}): Promise<MailboxRecord> {
    requireMailbox(record.version < Number.MAX_SAFE_INTEGER, 'limit')
    const active = state === 'queued' || state === 'delivered' || state === 'running'
    const next = { ...record, ...extra, state: transitionA2aRequest(record.state, state),
      authorizationVersion, version: record.version + 1, updatedAt: now, question: active ? record.question : null }
    await this.commit(next, fence)
    return next
  }

  private async commit(record: MailboxRecord, fence: Fence): Promise<void> {
    const validated = parseRecord(record, this.options.limits)
    fence()
    await this.owner.put(recordKey(record.binding), validated)
    fence()
  }

  private async seal(text: string, record: MailboxRecord, kind: 'question' | 'reply', fence: Fence): Promise<string> {
    fence()
    let ciphertext: string
    try { ciphertext = await this.options.codec.seal(text, bodyAad(record.binding, kind), fence.signal) }
    catch { throw new MailboxError('codec-failed') }
    fence()
    checkCiphertext(ciphertext, this.options.limits)
    return ciphertext
  }

  private async open(record: MailboxRecord, kind: 'question' | 'reply', fence: Fence): Promise<string> {
    fence()
    const ciphertext = record[kind]
    requireMailbox(ciphertext !== null, 'not-found')
    let text: string
    try {
      text = await this.options.codec.open(ciphertext, bodyAad(record.binding, kind), fence.signal)
      requireMailbox(textHash(text, this.options.limits) === (kind === 'question' ? record.questionHash : record.replyHash), 'codec-failed')
    } catch { throw new MailboxError('codec-failed') }
    fence()
    return text
  }

  private async authorized<T>(binding: MailboxBinding, operationKind: MailboxOperation,
    job: (lease: MailboxAuthorizationLease, fence: Fence) => Promise<T>): Promise<T> {
    let active = true
    const scope: { called: boolean; settled: boolean; result?: { value: T } } = { called: false, settled: false }
    let operation: Promise<void> | undefined
    try {
      await this.options.withAuthorization(Object.freeze({ ...binding }), operationKind, (lease) => {
        if (!active || scope.called) {
          this.owner.isolate()
          return Promise.reject(new MailboxError('authority-failed'))
        }
        scope.called = true
        const authorizationVersion = lease.access?.authorizationVersion ?? null
        const fence = Object.assign(() => {
          this.owner.assertLive()
          requireMailbox(active && !lease.signal.aborted, 'authority-failed')
          lease.assertCurrent(authorizationVersion)
        }, { signal: AbortSignal.any([this.owner.controller.signal, lease.signal]) })
        operation = (async () => {
          try {
            fence()
            const actor = lease.actor
            const source = operationKind === 'running' || operationKind === 'completed' || operationKind === 'failed'
            requireMailbox(actor.organizationId === binding.organizationId && (actor.kind === 'requester'
              ? actor.memberId === binding.requesterId && !source
              : actor.instanceId === binding.instanceId
                && (source || operationKind === 'dispatch' || operationKind === 'status')), 'not-found')
            const value = await job(lease, fence)
            fence()
            scope.result = { value }
          }
          finally { scope.settled = true }
        })()
        // Observe abandoned provider callbacks while retaining the original rejection for its caller.
        void operation.catch(() => {})
        return operation
      }, this.owner.controller.signal)
      requireMailbox(scope.called && scope.settled && scope.result !== undefined, 'authority-failed')
      this.owner.assertLive()
      return scope.result.value
    } catch (failure) {
      if (failure instanceof MailboxError) {
        if (failure.code === 'authority-failed') this.owner.isolate()
        throw failure
      }
      this.owner.isolate()
      throw new MailboxError('authority-failed')
    } finally {
      active = false
      // Never expose a delayed commit capability after the lease provider returns.
      if (operation !== undefined) await operation.catch(() => {})
    }
  }
}
