/** Tenant-owned encrypted question mailbox routed through authenticated Registry Sync connections. */
import { AsyncLocalStorage } from 'node:async_hooks'
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import type { Context } from '@deepseek-ai/cordis'
import { brandString } from '@deepseek-ai/dsh-brand'
import { credentialRef, type CredentialProvider, type CredentialRef } from '@deepseek-ai/dsh-credentials'
import type { RegistryConnectionAuthority } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import { isMailboxExecutionLeaseExpired, MailboxError, openA2aMailbox, type A2aMailbox,
  type MailboxAuthorizationLease, type MailboxBinding, type MailboxLimits, type MailboxOperation,
  type MailboxReceipt, type MailboxStorageScope, type MailboxTextCodec, type MailboxTransition,
  type WithMailboxAuthorization } from '@deepseek-ai/dsh-a2a-mailbox'
import type { DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { A2aRequestId, DisclosureAccess, DisclosureSubject, MemberId,
  VerifiedDisclosureCheckpoint } from '@deepseek-ai/dsh-a2a-registry-domain'
import { RegistryIngestError, type FreshRegistryMetadataAuthority,
  type RegistryConfirmedPrefix, type RegistryIngestStorageScope } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryQuestionDelivery } from '@deepseek-ai/dsh-a2a-registry-sync'
import type { DomainFacility } from '@deepseek-ai/dsh-storage-domain'
import type { RegistryDisclosureOperationSelection, RegistryDisclosureOperations,
  RegistryDisclosureQuestionInput, RegistryDisclosureQuestionListOptions,
  RegistryDisclosureQuestionListScope, RegistryDisclosureQuestionMetadata,
  RegistryDisclosureQuestionPage, RegistryDisclosureQuestionResult } from './operations.ts'
import type { RegistryAuthorizedPrefixSnapshot, RegistryDisclosureReader } from './reader.ts'
import type { RegistryQuestionBroker } from './question-broker.ts'
import type { RegistryRuntimeStore } from './runtime-store.ts'
import type { RegistryTenantRuntimeRouter } from './tenant-runtime-router.ts'

const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const BASE64URL = /^[A-Za-z0-9_-]+$/u

/** Complete per-organization mailbox limits and maintenance cadence. */
export interface RegistrySaasQuestionMailboxConfig {
  /** Credential reference containing one base64url 32-byte Registry root key. */
  readonly mailboxKeyEnv: string
  readonly maxAuthorizationResponseBytes: number
  /** Maximum UTF-8 JSON bytes of the delivery before its WSS frame envelope. */
  readonly maxDeliveryBytes: number
  /** Maximum WSS question-authorization release wait. */
  readonly operationTimeoutMs: number
  readonly executionLeaseMs: number
  readonly limits: MailboxLimits
  readonly expiryMaintenance: {
    readonly intervalMs: number
    readonly maxItems: number
  }
}

type CallScope = {
  readonly actor: 'requester' | 'source'
  readonly signal: AbortSignal
  readonly selection?: RegistryDisclosureOperationSelection
  readonly source?: RegistryConnectionAuthority
  prefix?: RegistryConfirmedPrefix
}

function requirePositive(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 2_147_483_647) {
    throw new Error('Registry SaaS question mailbox limits must be positive bounded integers')
  }
}

function requestId(selection: RegistryDisclosureOperationSelection, idempotencyKey: string): A2aRequestId {
  const digest = createHash('sha256').update([
    selection.subject.organizationId,
    selection.subject.memberId,
    idempotencyKey,
  ].join('\0'), 'utf8').digest('hex')
  return brandString<A2aRequestId>(`question-${digest}`)
}

function sameBinding(left: MailboxBinding, right: MailboxBinding): boolean {
  return left.requestId === right.requestId && left.organizationId === right.organizationId
    && left.disclosureId === right.disclosureId && left.requesterId === right.requesterId
    && left.checkpointHash === right.checkpointHash && left.authorizationVersion === right.authorizationVersion
    && left.expiresAt === right.expiresAt && left.instanceId === right.instanceId
}

function questionResult(receipt: MailboxReceipt, reply?: string): RegistryDisclosureQuestionResult {
  if (receipt.state === 'created') throw new MailboxError('invalid-storage')
  return { requestId: receipt.binding.requestId, checkpointHash: receipt.binding.checkpointHash,
    status: receipt.state, ...(reply === undefined ? {} : { reply }) }
}

function exactRootKey(value: string): Buffer {
  if (typeof value !== 'string' || !BASE64URL.test(value)) {
    throw new Error('Registry SaaS mailbox key is unavailable')
  }
  const key = Buffer.from(value, 'base64url')
  if (key.byteLength !== 32 || key.toString('base64url') !== value) {
    key.fill(0)
    throw new Error('Registry SaaS mailbox key is unavailable')
  }
  return key
}

function tenantKey(root: Buffer, organizationId: OrganizationId): Buffer {
  return createHmac('sha256', root).update('dsh-a2a-registry-mailbox-v1\0', 'utf8')
    .update(organizationId, 'utf8').digest()
}

/** Fail startup before any tenant is opened when the mandatory mailbox root key is absent or malformed. */
export async function validateRegistrySaasMailboxCredential(credentials: CredentialProvider,
  mailboxKeyEnv: string): Promise<void> {
  let credential: Awaited<ReturnType<CredentialProvider['resolve']>>
  try { credential = await credentials.resolve(credentialRef(mailboxKeyEnv)) } catch {
    throw new Error('Registry SaaS mailbox key is unavailable')
  }
  if (credential === undefined) throw new Error('Registry SaaS mailbox key is unavailable')
  const root = exactRootKey(credential.value)
  root.fill(0)
}

function codec(credentials: CredentialProvider, keyRef: CredentialRef,
  organizationId: OrganizationId): MailboxTextCodec {
  async function key(signal: AbortSignal): Promise<Buffer> {
    signal.throwIfAborted()
    const credential = await credentials.resolve(keyRef)
    signal.throwIfAborted()
    if (credential === undefined) throw new Error('Registry SaaS mailbox key is unavailable')
    const root = exactRootKey(credential.value)
    try { return tenantKey(root, organizationId) } finally { root.fill(0) }
  }
  return {
    async seal(text, aad, signal) {
      const material = await key(signal)
      try {
        const nonce = randomBytes(12)
        const cipher = createCipheriv('aes-256-gcm', material, nonce)
        cipher.setAAD(Buffer.from(aad, 'utf8'))
        const body = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])
        return Buffer.concat([nonce, cipher.getAuthTag(), body]).toString('base64url')
      } finally { material.fill(0) }
    },
    async open(encoded, aad, signal) {
      signal.throwIfAborted()
      if (!BASE64URL.test(encoded)) throw new Error('invalid ciphertext')
      const body = Buffer.from(encoded, 'base64url')
      if (body.byteLength < 28 || body.toString('base64url') !== encoded) throw new Error('invalid ciphertext')
      const material = await key(signal)
      try {
        const decipher = createDecipheriv('aes-256-gcm', material, body.subarray(0, 12))
        decipher.setAAD(Buffer.from(aad, 'utf8'))
        decipher.setAuthTag(body.subarray(12, 28))
        return new TextDecoder('utf-8', { fatal: true })
          .decode(Buffer.concat([decipher.update(body.subarray(28)), decipher.final()]))
      } finally { material.fill(0) }
    },
  }
}

function mailboxStorage(organizationId: OrganizationId,
  storage?: RegistryIngestStorageScope): MailboxStorageScope {
  return {
    domainName: storage?.domainName === undefined ? 'a2a_registry_saas_mailbox' : `${storage.domainName}_mailbox`,
    tenantId: storage?.tenantId ?? organizationId,
  }
}

function ownedBySelection(binding: MailboxBinding, selection: RegistryDisclosureOperationSelection): boolean {
  return binding.organizationId === selection.subject.organizationId
    && binding.requesterId === selection.subject.memberId
    && binding.disclosureId === selection.disclosure.disclosureId
    && binding.instanceId === selection.disclosure.instanceId
}

function sameEnqueueSelection(binding: MailboxBinding,
  selection: RegistryDisclosureOperationSelection): boolean {
  return ownedBySelection(binding, selection)
    && binding.checkpointHash === selection.disclosure.checkpoint.checkpointHash
    && binding.authorizationVersion === selection.disclosure.authorizationVersion
}

/** One restart-safe encrypted mailbox for exactly one organization runtime. */
export class RegistrySaasQuestionMailbox implements RegistryDisclosureOperations, RegistryQuestionBroker {
  private readonly calls = new AsyncLocalStorage<CallScope>()
  private readonly lifetime = new AbortController()
  private askChain: Promise<void> = Promise.resolve()
  private pendingAsks = 0
  private maintenance = Promise.resolve()
  private closing: Promise<void> | undefined

  private constructor(private readonly mailbox: A2aMailbox,
    private readonly organizationId: OrganizationId,
    private readonly store: RegistryRuntimeStore,
    private readonly reader: RegistryDisclosureReader,
    private readonly config: RegistrySaasQuestionMailboxConfig) {}

  /** Open the tenant-isolated owner and validate every retained binding before admission. */
  static async open(ctx: Context, facility: DomainFacility, credentials: CredentialProvider,
    organizationId: OrganizationId, store: RegistryRuntimeStore, reader: RegistryDisclosureReader,
    config: RegistrySaasQuestionMailboxConfig,
    storage?: RegistryIngestStorageScope): Promise<RegistrySaasQuestionMailbox> {
    const resolved = structuredClone(config)
    requirePositive(resolved.maxAuthorizationResponseBytes)
    requirePositive(resolved.maxDeliveryBytes)
    requirePositive(resolved.operationTimeoutMs)
    requirePositive(resolved.executionLeaseMs)
    requirePositive(resolved.expiryMaintenance.intervalMs)
    requirePositive(resolved.expiryMaintenance.maxItems)
    if (storage?.tenantId !== undefined && storage.tenantId !== organizationId) {
      throw new Error('Registry SaaS question mailbox organization does not match storage')
    }
    const keyRef = credentialRef(resolved.mailboxKeyEnv)
    await validateRegistrySaasMailboxCredential(credentials, resolved.mailboxKeyEnv)
    const ownerCell: { current?: RegistrySaasQuestionMailbox } = {}
    const lifetime = new AbortController()
    const authorize: WithMailboxAuthorization = (binding, operation, commit, signal) => {
      const owner = ownerCell.current
      if (owner === undefined) throw new MailboxError('authority-failed')
      return owner.authorize(binding, operation, commit, signal)
    }
    const mailbox = await openA2aMailbox(facility, {
      limits: resolved.limits,
      executionLeaseMs: resolved.executionLeaseMs,
      codec: codec(credentials, keyRef, organizationId),
      withAuthorization: authorize,
      signal: lifetime.signal,
      storage: mailboxStorage(organizationId, storage),
    })
    const owner = new RegistrySaasQuestionMailbox(mailbox, organizationId, store, reader, resolved)
    ownerCell.current = owner
    // The mailbox kernel owns the passed signal; mirror its lifetime so close remains one-way.
    lifetime.signal.addEventListener('abort', () => { owner.lifetime.abort() }, { once: true })
    try {
      const retained = await mailbox.pending()
      if (retained.some(receipt => receipt.binding.organizationId !== organizationId)) {
        throw new Error('Registry SaaS question mailbox organization does not match storage')
      }
      owner.maintenance = owner.runExpiryMaintenance(ctx)
      return owner
    } catch (error) {
      lifetime.abort()
      await mailbox.close().catch(() => undefined)
      throw error
    }
  }

  /** Persist one exact checkpoint-pinned text question before returning to the browser. */
  askDisclosure(selection: RegistryDisclosureOperationSelection, input: RegistryDisclosureQuestionInput,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult> {
    signal.throwIfAborted()
    if (this.lifetime.signal.aborted) return Promise.reject(new RegistryIngestError('closed'))
    if (this.pendingAsks >= this.config.limits.maxPendingOperations) {
      return Promise.reject(new RegistryIngestError('limit'))
    }
    this.pendingAsks += 1
    const result = this.askChain.then(() => {
      if (this.lifetime.signal.aborted) throw new RegistryIngestError('closed')
      signal.throwIfAborted()
      return this.browserCall(selection, signal, async () => {
        this.requireSelection(selection)
        if (!IDENTIFIER.test(input.idempotencyKey)) throw new RegistryIngestError('invalid-input')
        const id = requestId(selection, input.idempotencyKey)
        const existing = (await this.mailbox.pending()).find(receipt => receipt.binding.requestId === id)
        let binding: MailboxBinding
        if (existing === undefined) {
          const now = Date.now()
          binding = {
            requestId: id,
            organizationId: selection.subject.organizationId,
            disclosureId: selection.disclosure.disclosureId,
            requesterId: selection.subject.memberId,
            checkpointHash: selection.disclosure.checkpoint.checkpointHash,
            authorizationVersion: selection.disclosure.authorizationVersion,
            expiresAt: Math.min(selection.disclosure.expiresAt, now + this.config.limits.maxLifetimeMs),
            instanceId: selection.disclosure.instanceId,
          }
        } else {
          if (!sameEnqueueSelection(existing.binding, selection)) throw new RegistryIngestError('conflict')
          binding = existing.binding
        }
        return questionResult(await this.mailbox.enqueue(binding, input.question))
      })
    })
    this.askChain = result.then(() => {}, () => {})
    return result.finally(() => { this.pendingAsks -= 1 })
  }

  /** List metadata only after independently reauthorizing every candidate disclosure/checkpoint. */
  async listQuestions(scope: RegistryDisclosureQuestionListScope,
    options: RegistryDisclosureQuestionListOptions, signal: AbortSignal): Promise<RegistryDisclosureQuestionPage> {
    signal.throwIfAborted()
    if (!scope.subject.authenticated || scope.subject.membership !== 'active'
      || scope.subject.organizationId !== this.organizationId) throw new RegistryIngestError('not-found')
    if (!Number.isSafeInteger(options.pageSize) || options.pageSize < 1
      || options.pageSize > this.config.limits.maxRetainedRequests
      || options.cursor !== undefined && !IDENTIFIER.test(options.cursor)) {
      throw new RegistryIngestError('invalid-input')
    }
    const candidates = (await this.mailbox.pending())
      .filter(receipt => receipt.binding.organizationId === this.organizationId
        && receipt.binding.requesterId === scope.subject.memberId)
      .sort((left, right) => left.binding.requestId.localeCompare(right.binding.requestId))
    let start = 0
    if (options.cursor !== undefined) {
      const anchor = candidates.findIndex(receipt => receipt.binding.requestId === options.cursor)
      if (anchor < 0) throw new RegistryIngestError('invalid-input')
      start = anchor + 1
    }
    const authorized: RegistryDisclosureQuestionMetadata[] = []
    for (let index = start; index < candidates.length && authorized.length <= options.pageSize; index += 1) {
      signal.throwIfAborted()
      const candidate = candidates[index]
      if (candidate === undefined) continue
      try {
        const selection = await scope.selectDisclosure(candidate.binding.disclosureId,
          candidate.binding.instanceId, signal)
        this.requireSelection(selection)
        if (!ownedBySelection(candidate.binding, selection)) throw new RegistryIngestError('not-found')
        const receipt = await this.browserCall(selection, signal,
          () => this.mailbox.status(candidate.binding))
        if (receipt.state === 'created') throw new MailboxError('invalid-storage')
        authorized.push({
          requestId: receipt.binding.requestId,
          disclosureId: receipt.binding.disclosureId,
          sourceInstanceId: receipt.binding.instanceId,
          checkpointHash: receipt.binding.checkpointHash,
          status: receipt.state,
          expiresAt: receipt.binding.expiresAt,
          updatedAt: receipt.updatedAt,
        })
      } catch (error) {
        if (error instanceof RegistryIngestError && error.code === 'not-found') continue
        throw error
      }
    }
    const hasMore = authorized.length > options.pageSize
    const items = hasMore ? authorized.slice(0, options.pageSize) : authorized
    return { items, nextCursor: hasMore ? items.at(-1)?.requestId ?? null : null }
  }

  /** Reauthorize the owner and pinned checkpoint before releasing any completed reply text. */
  readQuestion(selection: RegistryDisclosureOperationSelection, id: A2aRequestId,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult> {
    return this.browserCall(selection, signal, async () => {
      this.requireSelection(selection)
      const binding = await this.bindingFor(selection, id)
      const receipt = await this.mailbox.status(binding)
      if (receipt.state !== 'completed') return questionResult(receipt)
      const reply = await this.mailbox.reply(binding)
      return questionResult(reply.receipt, reply.text ?? undefined)
    })
  }

  /** Cancel only currently queued work through the mailbox's version-fenced state machine. */
  cancelQuestion(selection: RegistryDisclosureOperationSelection, id: A2aRequestId,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult> {
    return this.browserCall(selection, signal, async () => {
      this.requireSelection(selection)
      const binding = await this.bindingFor(selection, id)
      let receipt = await this.mailbox.status(binding)
      if (receipt.state !== 'queued') return questionResult(receipt)
      try { receipt = await this.mailbox.transition(binding, receipt.version, { state: 'cancelled' }) }
      catch (error) {
        if (!(error instanceof MailboxError) || error.code !== 'conflict') throw error
        receipt = await this.mailbox.status(binding)
      }
      return questionResult(receipt)
    })
  }

  /** Select the oldest eligible request for exactly the authenticated source instance. */
  async dispatch(source: RegistryConnectionAuthority, excludeRequestIds: readonly string[],
    signal: AbortSignal): Promise<RegistryQuestionDelivery | null> {
    this.requireSource(source)
    if (excludeRequestIds.length > this.config.limits.maxRequests
      || new Set(excludeRequestIds).size !== excludeRequestIds.length
      || excludeRequestIds.some(id => !IDENTIFIER.test(id))) throw new MailboxError('invalid-input')
    await this.mailbox.processExpiryBatch({ organizationId: this.organizationId, now: Date.now(),
      maxItems: Math.min(10, this.config.expiryMaintenance.maxItems), signal })
    const excluded = new Set(excludeRequestIds)
    const now = Date.now()
    const candidates = (await this.mailbox.pending())
      .filter(receipt => receipt.binding.organizationId === this.organizationId
        && receipt.binding.instanceId === source.connection.instanceId
        && (receipt.state === 'queued' || receipt.state === 'delivered'
          || isMailboxExecutionLeaseExpired(receipt, now, this.config.executionLeaseMs))
        && !excluded.has(receipt.binding.requestId))
      .sort((left, right) => this.dispatchRank(left, now) - this.dispatchRank(right, now)
        || left.updatedAt - right.updatedAt || left.binding.requestId.localeCompare(right.binding.requestId))
    for (const candidate of candidates) {
      try {
        const dispatched = await this.sourceCall(source, signal,
          () => this.mailbox.dispatch(candidate.binding, candidate.version))
        if (dispatched.value.question === null || dispatched.prefix === undefined) continue
        const delivery = this.delivery(candidate.binding, dispatched.value.receipt,
          dispatched.value.question, dispatched.prefix)
        if (Buffer.byteLength(JSON.stringify(delivery), 'utf8') > this.config.maxDeliveryBytes) {
          await this.failOversized(source, candidate.binding, dispatched.value.receipt, signal)
          continue
        }
        return delivery
      } catch (error) {
        if (error instanceof MailboxError && (error.code === 'not-found' || error.code === 'conflict')) continue
        throw error
      }
    }
    return null
  }

  async start(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    signal: AbortSignal) {
    const selected = await this.retainedBinding(source, binding)
    return (await this.sourceCall(source, signal,
      () => this.mailbox.startExecution(selected, expectedVersion))).value
  }

  async renew(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    signal: AbortSignal) {
    const selected = await this.retainedBinding(source, binding)
    return (await this.sourceCall(source, signal,
      () => this.mailbox.renewExecution(selected, expectedVersion))).value
  }

  async status(source: RegistryConnectionAuthority, binding: MailboxBinding,
    signal: AbortSignal): Promise<MailboxReceipt> {
    const selected = await this.retainedBinding(source, binding)
    return (await this.sourceCall(source, signal, () => this.mailbox.status(selected))).value
  }

  async transition(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    transition: MailboxTransition, signal: AbortSignal): Promise<MailboxReceipt> {
    if (transition.state !== 'completed' && transition.state !== 'failed') throw new MailboxError('invalid-input')
    const selected = await this.retainedBinding(source, binding)
    return (await this.sourceCall(source, signal,
      () => this.mailbox.transition(selected, expectedVersion, transition))).value
  }

  /** Release the ingest owner before waiting on WSS, then require a second fresh authorization. */
  async withAuthorization(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    receive: (delivery: RegistryQuestionDelivery, signal: AbortSignal) => Promise<void>,
    signal: AbortSignal): Promise<void> {
    const selected = await this.retainedBinding(source, binding)
    const retained = (await this.mailbox.pending()).find(receipt => receipt.binding.requestId === selected.requestId)
    if (retained === undefined) throw new MailboxError('not-found')
    const admissible = retained.state === 'delivered' && retained.version === expectedVersion
      || retained.state === 'running' && retained.version === expectedVersion + 1
    if (!admissible) throw new MailboxError('conflict')
    const dispatched = await this.sourceCall(source, signal,
      () => this.mailbox.dispatch(selected, retained.version))
    if (dispatched.value.question === null || dispatched.prefix === undefined) throw new MailboxError('not-found')
    const delivery = this.delivery(selected, dispatched.value.receipt,
      dispatched.value.question, dispatched.prefix)
    if (Buffer.byteLength(JSON.stringify(delivery), 'utf8') > this.config.maxDeliveryBytes) {
      await this.failOversized(source, selected, dispatched.value.receipt, signal)
      throw new MailboxError('limit')
    }
    const operationSignal = AbortSignal.any([signal, this.lifetime.signal,
      AbortSignal.timeout(this.config.operationTimeoutMs)])
    try { await receive(delivery, operationSignal) }
    catch (error) {
      if (operationSignal.aborted) throw new MailboxError('unavailable')
      throw error
    }
    operationSignal.throwIfAborted()
    await this.sourceCall(source, operationSignal, () => this.mailbox.status(selected))
  }

  /** Stop new work, expiry scheduling and the durable owner after admitted operations drain. */
  close(): Promise<void> {
    this.lifetime.abort()
    this.closing ??= Promise.allSettled([this.maintenance, this.askChain, this.mailbox.close()]).then((outcomes) => {
      if (outcomes.some(outcome => outcome.status === 'rejected')) {
        throw new Error('Registry SaaS question mailbox cleanup failed')
      }
    })
    return this.closing
  }

  private delivery(binding: MailboxBinding, receipt: MailboxReceipt,
    question: string, prefix: RegistryConfirmedPrefix): RegistryQuestionDelivery {
    return { binding, receipt: { ...receipt, authorizationVersion: prefix.authorizationVersion }, question, prefix,
      source: { instanceName: binding.instanceId, conversationTitle: String(prefix.conversationId) } }
  }

  private requireSelection(selection: RegistryDisclosureOperationSelection): void {
    if (!selection.subject.authenticated || selection.subject.membership !== 'active'
      || selection.subject.organizationId !== this.organizationId
      || selection.disclosure.organizationId !== this.organizationId
      || !selection.disclosure.authorizedActions.includes('ask')) throw new RegistryIngestError('not-found')
  }

  private requireSource(source: RegistryConnectionAuthority): void {
    if (source.connection.organizationId !== this.organizationId
      || source.history.organizationId !== this.organizationId
      || source.connection.instanceId !== source.history.instanceId
      || source.history.status !== 'active') throw new MailboxError('not-found')
  }

  private async bindingFor(selection: RegistryDisclosureOperationSelection, id: A2aRequestId): Promise<MailboxBinding> {
    const retained = (await this.mailbox.pending()).find(receipt => receipt.binding.requestId === id)
    if (retained === undefined || !ownedBySelection(retained.binding, selection)) {
      throw new RegistryIngestError('not-found')
    }
    return retained.binding
  }

  private async retainedBinding(source: RegistryConnectionAuthority, binding: MailboxBinding): Promise<MailboxBinding> {
    this.requireSource(source)
    const retained = (await this.mailbox.pending()).find(receipt => receipt.binding.requestId === binding.requestId)
    if (retained === undefined || !sameBinding(retained.binding, binding)
      || binding.organizationId !== this.organizationId
      || binding.instanceId !== source.connection.instanceId) throw new MailboxError('not-found')
    return retained.binding
  }

  private async failOversized(source: RegistryConnectionAuthority, binding: MailboxBinding,
    receipt: MailboxReceipt, signal: AbortSignal): Promise<void> {
    try {
      await this.sourceCall(source, signal,
        () => this.mailbox.transition(binding, receipt.version, { state: 'failed' }))
    } catch (error) {
      if (!(error instanceof MailboxError) || error.code !== 'conflict' || receipt.state !== 'running') throw error
      const takeover = await this.sourceCall(source, signal,
        () => this.mailbox.startExecution(binding, receipt.version))
      if (!takeover.value.started) throw error
      await this.sourceCall(source, signal,
        () => this.mailbox.transition(binding, takeover.value.receipt.version, { state: 'failed' }))
    }
  }

  private async browserCall<T>(selection: RegistryDisclosureOperationSelection, signal: AbortSignal,
    operation: () => Promise<T>): Promise<T> {
    signal.throwIfAborted()
    try { return await this.calls.run({ actor: 'requester', selection, signal }, operation) } catch (error) {
      if (error instanceof MailboxError) {
        if (error.code === 'not-found') throw new RegistryIngestError('not-found')
        if (error.code === 'conflict') throw new RegistryIngestError('conflict')
        if (error.code === 'invalid-input') throw new RegistryIngestError('invalid-input')
        if (error.code === 'limit') throw new RegistryIngestError('limit')
        if (error.code === 'closed') throw new RegistryIngestError('closed')
      }
      throw error
    }
  }

  private async sourceCall<T>(source: RegistryConnectionAuthority, signal: AbortSignal,
    operation: () => Promise<T>): Promise<{ value: T; prefix?: RegistryConfirmedPrefix }> {
    this.requireSource(source)
    const scope: CallScope = { actor: 'source', source, signal }
    const value = await this.calls.run(scope, operation)
    return { value, ...(scope.prefix === undefined ? {} : { prefix: scope.prefix }) }
  }

  private async authorize(binding: Readonly<MailboxBinding>, _operation: MailboxOperation,
    commit: (lease: MailboxAuthorizationLease) => Promise<void>, ownerSignal: AbortSignal): Promise<void> {
    const scope = this.calls.getStore()
    if (scope === undefined) throw new MailboxError('authority-failed')
    const signal = AbortSignal.any([ownerSignal, this.lifetime.signal, scope.signal])
    try {
      signal.throwIfAborted()
      if (!this.store.active()) throw new MailboxError('authority-failed')
      const selection = scope.selection
      const source = scope.source
      let accountPrefix: RegistryConfirmedPrefix | undefined
      const validActor = binding.organizationId === this.organizationId
        && (scope.actor === 'requester'
          ? selection !== undefined && ownedBySelection(binding, selection)
          : source !== undefined && source.connection.instanceId === binding.instanceId)
      const subject: DisclosureSubject = scope.actor === 'requester' && selection !== undefined
        ? selection.subject
        : { authenticated: true, organizationId: this.organizationId, memberId: binding.requesterId,
          membership: 'active', role: 'member', currentTeamIds: [] }
      const useSnapshot = async (snapshot: RegistryAuthorizedPrefixSnapshot | null): Promise<void> => {
        let access: DisclosureAccess | null = null
        let checkpoint: VerifiedDisclosureCheckpoint | null = null
        if (snapshot !== null) {
          const metadata = snapshot.metadata
          const prefix = snapshot.prefix
          const valid = metadata.organizationId === binding.organizationId
            && metadata.instanceId === binding.instanceId
            && metadata.disclosureId === binding.disclosureId
            && metadata.checkpoint.checkpointHash === binding.checkpointHash
            && metadata.authorizedActions.includes('ask')
            && prefix.authorizationVersion === metadata.authorizationVersion
            && prefix.checkpoint.organizationId === binding.organizationId
            && prefix.checkpoint.instanceId === binding.instanceId
            && prefix.checkpoint.disclosureId === binding.disclosureId
            && prefix.checkpoint.checkpointHash === binding.checkpointHash
            && (scope.actor !== 'requester' || accountPrefix !== undefined
              && accountPrefix.authorizationVersion === prefix.authorizationVersion
              && accountPrefix.checkpoint.organizationId === prefix.checkpoint.organizationId
              && accountPrefix.checkpoint.instanceId === prefix.checkpoint.instanceId
              && accountPrefix.checkpoint.disclosureId === prefix.checkpoint.disclosureId
              && accountPrefix.checkpoint.checkpointHash === prefix.checkpoint.checkpointHash)
          if (valid) {
            access = { organizationId: metadata.organizationId, disclosureId: metadata.disclosureId,
              instanceId: metadata.instanceId, control: metadata.control, producer: metadata.producer,
              ingest: metadata.ingest, expiresAt: metadata.expiresAt,
              authorizationVersion: metadata.authorizationVersion,
              capabilities: ['conversation.read', 'branch.create'],
              checkpointHash: metadata.checkpoint.checkpointHash,
              grants: [{ target: { kind: 'member', memberId: binding.requesterId }, state: 'active',
                capabilities: ['conversation.read', 'branch.create'], expiresAt: metadata.expiresAt }] }
            checkpoint = { authorizationVersion: prefix.authorizationVersion, checkpoint: {
              organizationId: prefix.checkpoint.organizationId,
              instanceId: prefix.checkpoint.instanceId,
              disclosureId: prefix.checkpoint.disclosureId,
              checkpointHash: prefix.checkpoint.checkpointHash,
            } }
            scope.prefix = prefix
          }
        }
        let active = true
        const authorizationVersion = access?.authorizationVersion ?? null
        try {
          await commit({ actor: scope.actor === 'source'
            ? { kind: 'source', organizationId: this.organizationId, instanceId: binding.instanceId }
            : { kind: 'requester', organizationId: this.organizationId, memberId: binding.requesterId },
          subject, access, checkpoint, now: Date.now(), sourceOnline: scope.actor === 'source', signal,
          assertCurrent(version) {
            signal.throwIfAborted()
            if (!active || version !== authorizationVersion) throw new MailboxError('authority-failed')
          } })
        } finally { active = false }
      }
      if (!validActor) return useSnapshot(null)
      if (scope.actor === 'requester' && selection !== undefined) {
        try {
          accountPrefix = await selection.readAuthorizedPrefix({ sourceInstanceId: binding.instanceId,
            checkpointHash: binding.checkpointHash }, signal)
        } catch (error) {
          if (signal.aborted) throw new MailboxError('closed')
          if (error instanceof RegistryIngestError && error.code === 'not-found') return useSnapshot(null)
          throw error
        }
        if (accountPrefix.checkpoint.organizationId !== binding.organizationId
          || accountPrefix.checkpoint.instanceId !== binding.instanceId
          || accountPrefix.checkpoint.disclosureId !== binding.disclosureId
          || accountPrefix.checkpoint.checkpointHash !== binding.checkpointHash) return useSnapshot(null)
      }
      const authority: FreshRegistryMetadataAuthority = () => {
        signal.throwIfAborted()
        if (scope.actor === 'source' && source !== undefined) this.requireSource(source)
        return { subject, now: Date.now(), historyFor: () => null }
      }
      await this.reader.withAuthorizedPrefix(authority, binding.disclosureId, binding.instanceId,
        'ask', binding.checkpointHash, this.config.maxAuthorizationResponseBytes, undefined, useSnapshot)
    } catch (error) {
      if (signal.aborted) throw new MailboxError('closed')
      throw error
    }
  }

  private async runExpiryMaintenance(ctx: Context): Promise<void> {
    while (!this.lifetime.signal.aborted) {
      try {
        await this.mailbox.processExpiryBatch({ organizationId: this.organizationId, now: Date.now(),
          maxItems: this.config.expiryMaintenance.maxItems, signal: this.lifetime.signal })
      } catch (error) {
        if (error instanceof MailboxError && error.code === 'closed') return
        ctx.logger.error('Registry SaaS mailbox expiry maintenance stopped')
        return
      }
      try { await delay(this.config.expiryMaintenance.intervalMs, undefined, { signal: this.lifetime.signal }) }
      catch { return }
    }
  }

  private dispatchRank(receipt: MailboxReceipt, now: number): number {
    if (receipt.state === 'delivered') return 0
    if (isMailboxExecutionLeaseExpired(receipt, now, this.config.executionLeaseMs)) return 1
    return 2
  }
}

/** Process-global delegator; tenant selection comes only from browser or authenticated device authority. */
export class RegistrySaasQuestionRouter implements RegistryDisclosureOperations, RegistryQuestionBroker {
  constructor(private readonly router: RegistryTenantRuntimeRouter) {}

  listQuestions(scope: RegistryDisclosureQuestionListScope, options: RegistryDisclosureQuestionListOptions,
    signal: AbortSignal) {
    return this.withMailbox(scope.subject.organizationId,
      mailbox => mailbox.listQuestions(scope, options, signal))
  }

  askDisclosure(selection: RegistryDisclosureOperationSelection, input: RegistryDisclosureQuestionInput,
    signal: AbortSignal) {
    return this.withMailbox(selection.subject.organizationId,
      mailbox => mailbox.askDisclosure(selection, input, signal))
  }

  readQuestion(selection: RegistryDisclosureOperationSelection, id: A2aRequestId, signal: AbortSignal) {
    return this.withMailbox(selection.subject.organizationId,
      mailbox => mailbox.readQuestion(selection, id, signal))
  }

  cancelQuestion(selection: RegistryDisclosureOperationSelection, id: A2aRequestId, signal: AbortSignal) {
    return this.withMailbox(selection.subject.organizationId,
      mailbox => mailbox.cancelQuestion(selection, id, signal))
  }

  dispatch(source: RegistryConnectionAuthority, excluded: readonly string[], signal: AbortSignal) {
    return this.withMailbox(source.connection.organizationId,
      mailbox => mailbox.dispatch(source, excluded, signal))
  }

  start(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    signal: AbortSignal) {
    return this.withMailbox(source.connection.organizationId,
      mailbox => mailbox.start(source, binding, expectedVersion, signal))
  }

  renew(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    signal: AbortSignal) {
    return this.withMailbox(source.connection.organizationId,
      mailbox => mailbox.renew(source, binding, expectedVersion, signal))
  }

  status(source: RegistryConnectionAuthority, binding: MailboxBinding, signal: AbortSignal) {
    return this.withMailbox(source.connection.organizationId,
      mailbox => mailbox.status(source, binding, signal))
  }

  transition(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    transition: MailboxTransition, signal: AbortSignal) {
    return this.withMailbox(source.connection.organizationId,
      mailbox => mailbox.transition(source, binding, expectedVersion, transition, signal))
  }

  withAuthorization(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    receive: (delivery: RegistryQuestionDelivery, signal: AbortSignal) => Promise<void>, signal: AbortSignal) {
    return this.withMailbox(source.connection.organizationId,
      mailbox => mailbox.withAuthorization(source, binding, expectedVersion, receive, signal))
  }

  private async withMailbox<T>(organizationId: OrganizationId,
    operation: (mailbox: RegistrySaasQuestionMailbox) => Promise<T>): Promise<T> {
    const lease = await this.router.acquireRuntime(organizationId)
    try {
      const mailbox = lease.runtime.questions
      if (mailbox === undefined) throw new RegistryIngestError('not-found')
      return await operation(mailbox)
    } finally { lease.release() }
  }
}
