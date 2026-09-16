/** Instance-local durable claims assign one stable branch ID without creating or executing a Session. */
import { randomUUID } from 'node:crypto'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { DomainFacility } from '@deepseek-ai/dsh-storage-domain'
import type { DshInstanceId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { SessionId } from '@deepseek-ai/dsh-session'
import { openOwner, type RecordOwner } from './owner.ts'
import { bodyAad, MailboxError, parseBinding, parseClaim, recordKey, requireMailbox, textHash } from './record.ts'
import type { MailboxBinding, MailboxConsumerClaim, MailboxDispatch, MailboxLimits } from './types.ts'

/**
 * Open the instance-local claim ledger on a separate instance-owned facility/backend.
 * @param facility - Exclusive local storage, not the Registry queue's persistence.
 * @param instanceId - Actual authenticated local instance; every retained claim must name it.
 * @param limits - Retained claim and complete record bounds; claims are never automatically evicted.
 * @param signal - Consumer lifetime; caller must close and drain on teardown.
 * @returns An owner that reserves IDs only; it does not create/import/run independent branches.
 */
export async function openA2aConsumerReceipts(facility: DomainFacility, instanceId: DshInstanceId,
  limits: MailboxLimits, signal: AbortSignal): Promise<A2aConsumerReceipts> {
  const resolved = Object.freeze({ ...limits })
  return new A2aConsumerReceipts(await openOwner(facility, 'a2a_mailbox_claims', resolved, signal,
    value => parseClaim(value, resolved), (claim) => {
      requireMailbox(claim.binding.instanceId === instanceId, 'invalid-storage')
      return recordKey(claim.binding)
    }), instanceId)
}

/** Metadata-only stable-ID reservation; creation/resumption at that ID belongs to a trusted importer. */
export class A2aConsumerReceipts {
  /** @param owner - Validated instance-local owner from openA2aConsumerReceipts.
   * @param instanceId - Actual authenticated local instance fixed at open. */
  constructor(private readonly owner: RecordOwner<MailboxConsumerClaim>, private readonly instanceId: DshInstanceId) {}

  /**
   * Verify a delivered question before reserving its stable local branch identity.
   * @param delivery - Decoded delivery from the authenticated adapter, authorized for this instance and requester.
   * @returns A durable metadata-only claim after complete text bounds and the receipt's digest match.
   * This does not establish current authorization, create a Session or start execution; the adapter retains those duties.
   */
  async claimDelivery(delivery: MailboxDispatch): Promise<MailboxConsumerClaim> {
    const { receipt, question } = delivery
    requireMailbox((receipt.state === 'delivered' || receipt.state === 'running')
      && question !== null && receipt.replyHash === null, 'not-found')
    const digest = textHash(question, this.owner.limits)
    requireMailbox(digest === receipt.questionHash, 'conflict')
    if (receipt.state === 'delivered') return this.claim(receipt.binding, digest)
    const existing = await this.read(receipt.binding)
    requireMailbox(existing.questionHash === digest, 'conflict')
    return existing
  }

  /**
   * Reserve one durable session ID before branch creation; repeated deliveries reuse it across restarts.
   * @param binding - Delivery identity validated by the instance's authenticated transport adapter.
   * @param questionHash - Exact delivered text digest, independently checked by that adapter.
   * @returns The existing or freshly persisted fixed session ID; mismatched repeats reject.
   */
  async claim(binding: MailboxBinding, questionHash: string): Promise<MailboxConsumerClaim> {
    let candidate: MailboxConsumerClaim
    try { candidate = parseClaim({ binding, questionHash, sessionId: brandString<SessionId>(randomUUID()) }, this.owner.limits) }
    catch { throw new MailboxError('invalid-input') }
    requireMailbox(candidate.binding.instanceId === this.instanceId, 'not-found')
    return this.owner.run(async () => {
      const existing = this.owner.table.get(recordKey(candidate.binding))
      if (existing !== undefined) {
        requireMailbox(bodyAad(existing.binding, 'question') === bodyAad(candidate.binding, 'question') && existing.questionHash === questionHash, 'conflict')
        return structuredClone(existing)
      }
      requireMailbox(this.owner.table.size < this.owner.limits.maxRequests, 'limit')
      await this.owner.put(recordKey(candidate.binding), candidate)
      return structuredClone(candidate)
    })
  }

  /** Read one existing claim through this instance's serialized owner.
   * @param binding - Exact retained request identity; another instance is never readable.
   * @returns A detached metadata-only claim. */
  async read(binding: MailboxBinding): Promise<MailboxConsumerClaim> {
    let identity: MailboxBinding
    try { identity = parseBinding(binding) } catch { throw new MailboxError('invalid-input') }
    requireMailbox(identity.instanceId === this.instanceId, 'not-found')
    return this.owner.run(() => {
      const existing = this.owner.table.get(recordKey(identity))
      requireMailbox(existing !== undefined && bodyAad(existing.binding, 'question') === bodyAad(identity, 'question'), 'not-found')
      return structuredClone(existing)
    })
  }

  /** Return a complete bounded snapshot of this instance's retained claims.
   * @param maxItems - Positive caller ceiling; overflow rejects rather than silently omitting recovery work.
   * @returns Detached metadata-only claims; no question or reply body is retained here. */
  async list(maxItems: number): Promise<readonly MailboxConsumerClaim[]> {
    requireMailbox(Number.isSafeInteger(maxItems) && maxItems > 0 && maxItems <= this.owner.limits.maxRequests, 'invalid-input')
    return this.owner.run(() => {
      requireMailbox(this.owner.table.size <= maxItems, 'limit')
      return [...this.owner.table.entries()].map(([, claim]) => structuredClone(claim))
    })
  }

  /** Abort admission and drain persistence before releasing the claim ledger.
   * @returns Idempotent teardown completion. */
  close(): Promise<void> { return this.owner.close() }
}
