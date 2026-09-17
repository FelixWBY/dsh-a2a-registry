/** One bounded, sequential producer connection; every durable operation uses a current authority lease. */
import { symbols, type Context } from '@deepseek-ai/cordis'
import WebSocket from 'ws'
import { assertNever } from '@deepseek-ai/dsh-util-values'
import type { RegistryProducerAuthenticator, RegistryChallengeAttempt, AuthenticatedRegistryConnection,
  FreshRegistryConnectionAuthority, RegistryConnectionAuthority } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import { RegistryIngestError, type RegistryDisclosureRegistration,
  type RegistryIngestReceipt } from '@deepseek-ai/dsh-a2a-registry-ingest'
import { DISCLOSURE_CAPABILITIES, type DisclosureAccessUpdate,
  type DisclosureGrant } from '@deepseek-ai/dsh-a2a-registry-domain'
import { MailboxError } from '@deepseek-ai/dsh-a2a-mailbox'
import { decodeDisclosureCheckpoint, decodeDisclosureEventEnvelope, type DisclosureId,
  type OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import { decodeRegistryClientFrame, encodeRegistryServerFrame, RegistrySyncProtocolError,
  type RegistryClientFrame, type RegistryInstanceReport, type RegistryProducerAccessUpdate,
  type RegistryProducerRegistration, type RegistryServerFrame, type RegistrySyncErrorCode } from '@deepseek-ai/dsh-a2a-registry-sync'
import type { RegistryRuntimeStore } from './runtime-store.ts'
import type { RegistrySyncConfig } from './sync-config.ts'
import type { RegistrySyncAdmission } from './sync-admission.ts'
import type { RegistryQuestionBroker } from './question-broker.ts'
import type { RegistryImportBroker } from './import-broker.ts'

class Unauthorized extends Error {}
class Busy extends Error {}
class StaleDisclosure extends Error {}
class QuestionRejected extends Error {
  constructor(readonly code: RegistrySyncErrorCode, readonly requestId: number, readonly fatal = false) {
    super(code)
  }
}
class ImportRejected extends Error {
  constructor(readonly code: RegistrySyncErrorCode, readonly requestId: number, readonly fatal = false) {
    super(code)
  }
}
type ResourceResponse = Extract<RegistryServerFrame, { type: 'status' | 'event-ack' | 'checkpoint-ack' }>
type RegistryInboundFrame = Exclude<RegistryClientFrame, { type: 'event' | 'checkpoint' }>
  | Omit<Extract<RegistryClientFrame, { type: 'event' }>, 'envelope'> & { readonly envelope: unknown }
  | Omit<Extract<RegistryClientFrame, { type: 'checkpoint' }>, 'checkpoint'> & { readonly checkpoint: unknown }
type RejectedRecordFrame = Extract<RegistryInboundFrame, { type: 'event' | 'checkpoint' }>
type QuestionFrame = Extract<RegistryInboundFrame, { type:
  | 'question-dispatch' | 'question-start' | 'question-renew' | 'question-status'
  | 'question-transition' | 'question-authorize' }>
type QuestionReleaseFrame = Extract<RegistryInboundFrame, { type: 'question-authorize-release' }>
type ImportFrame = Extract<RegistryInboundFrame, { type: 'import-dispatch' }>
type ImportReleaseFrame = Extract<RegistryInboundFrame, { type: 'import-release' }>
type ReleaseFrame = QuestionReleaseFrame | ImportReleaseFrame
type ProducerCommandFrame = Extract<RegistryInboundFrame, { type:
  | 'producer-register' | 'producer-update-access' | 'producer-transition-control' | 'producer-delete' }>

function producerGrants(input: RegistryProducerRegistration | RegistryProducerAccessUpdate): readonly DisclosureGrant[] {
  return input.targets.map(target => ({ target: { ...target }, state: 'active',
    capabilities: [...DISCLOSURE_CAPABILITIES], expiresAt: input.expiresAt }))
}

function producerRegistration(frame: Extract<ProducerCommandFrame, { type: 'producer-register' }>,
  authority: RegistryConnectionAuthority): RegistryDisclosureRegistration {
  return {
    conversationId: frame.registration.conversationId,
    policyVersion: frame.registration.policyVersion,
    access: {
      organizationId: authority.connection.organizationId,
      instanceId: authority.connection.instanceId,
      disclosureId: frame.disclosureId,
      control: 'active',
      producer: 'idle',
      ingest: 'pending',
      expiresAt: frame.registration.expiresAt,
      authorizationVersion: 0,
      capabilities: [...DISCLOSURE_CAPABILITIES],
      grants: producerGrants(frame.registration),
      checkpointHash: null,
    },
  }
}

function producerAccessUpdate(input: RegistryProducerAccessUpdate): DisclosureAccessUpdate {
  return { expiresAt: input.expiresAt, capabilities: [...DISCLOSURE_CAPABILITIES], grants: producerGrants(input) }
}

function questionError(error: MailboxError): RegistrySyncErrorCode {
  if (error.code === 'not-found' || error.code === 'authority-failed') return 'not-found'
  if (error.code === 'conflict') return 'conflict'
  if (error.code === 'limit') return 'limit'
  if (error.code === 'invalid-input') return 'invalid-input'
  if (error.code === 'invalid-storage' || error.code === 'codec-failed') return 'invalid-storage'
  if (error.code === 'closed') return 'closed'
  return 'storage-unavailable'
}

/** Recover only a valid outer resource selection whose nested signed record failed strict decoding. */
function recoverRejectedRecordFrame(text: string, maxBytes: number): RejectedRecordFrame | undefined {
  try {
    const input: unknown = JSON.parse(text)
    if (input === null || typeof input !== 'object' || Array.isArray(input)) return undefined
    const value = input as Record<string, unknown>
    if (value.type !== 'event' && value.type !== 'checkpoint') return undefined
    const nestedKey = value.type === 'event' ? 'envelope' : 'checkpoint'
    const keys = ['protocolVersion', 'requestId', 'type', 'disclosureId', nestedKey]
    if (Object.keys(value).length !== keys.length || !keys.every(key => Object.hasOwn(value, key))) return undefined
    const header = decodeRegistryClientFrame(JSON.stringify({ protocolVersion: value.protocolVersion,
      requestId: value.requestId, type: 'status', disclosureId: value.disclosureId }), maxBytes)
    /* v8 ignore next -- the synthesized type is status; its strict decoder either returns status or throws. */
    if (header.type !== 'status') return undefined
    try {
      if (value.type === 'event') decodeDisclosureEventEnvelope(value.envelope)
      else decodeDisclosureCheckpoint(value.checkpoint)
      return undefined
    } catch {
      return value.type === 'event'
        ? { protocolVersion: 1, requestId: header.requestId, type: value.type,
          disclosureId: header.disclosureId, envelope: value.envelope }
        : { protocolVersion: 1, requestId: header.requestId, type: value.type,
          disclosureId: header.disclosureId, checkpoint: value.checkpoint }
    }
  } catch {
    // Raw JSON and nested decoder diagnostics may contain private input; recovery has no diagnostic output.
    return undefined
  }
}

/** Resolve the exact provider behind Cordis's per-read context proxies.
 * @param value - Current or captured provider, with absence preserved.
 * @returns The original service instance used only for lifetime identity comparison. */
export function registryAuthenticatorTarget(value: RegistryProducerAuthenticator | undefined): RegistryProducerAuthenticator | undefined {
  return (value as (RegistryProducerAuthenticator & { [symbols.original]?: RegistryProducerAuthenticator }) | undefined)?.[symbols.original]
    ?? value
}

/** Resolve the organization runtime only after the device identity provider has authenticated the organization. */
export interface RegistryRuntimeStoreLease {
  readonly store: RegistryRuntimeStore
  release(): void
}

/** Resolve a store lease held until the authenticated WebSocket connection has fully drained. */
export type RegistryRuntimeStoreResolver = (organizationId: OrganizationId) => Promise<RegistryRuntimeStoreLease>

/** Own the socket, handshake handles, request cancellation and final provider cleanup. */
export class RegistrySyncConnection {
  private readonly abort = new AbortController()
  private attempt: RegistryChallengeAttempt | undefined
  private authority: AuthenticatedRegistryConnection | undefined
  private recordHeartbeat: ((observedAt: number, report?: RegistryInstanceReport) => void) | undefined
  private lastRequestId = 0
  private pending: Promise<void> | undefined
  private release: {
    readonly type: ReleaseFrame['type']
    readonly authorizationRequestId: number
    readonly settle: (frame: ReleaseFrame | undefined) => void
  } | undefined
  private timer: NodeJS.Timeout | undefined
  private readonly disclosures = new Set<DisclosureId>()
  private readonly resolveStore: RegistryRuntimeStoreResolver
  private store: RegistryRuntimeStore | undefined
  private storeLease: RegistryRuntimeStoreLease | undefined
  private unsubscribe: (() => void) | undefined

  /** @param ctx - Context for detecting replacement of the injected provider.
   * @param socket - Already upgraded socket owned exclusively by this connection.
   * @param config - Validated immutable deployment bounds.
   * @param provider - Exact provider owning this attempt and its authority leases.
   * @param store - Fixed legacy owner or post-authentication tenant resolver.
   * @param signal - Runtime cancellation.
   * @param admission - Rate budgets shared by every connection in the installed endpoint. */
  constructor(private readonly ctx: Context, private readonly socket: WebSocket,
    private readonly config: RegistrySyncConfig, private readonly provider: RegistryProducerAuthenticator,
    store: RegistryRuntimeStore | RegistryRuntimeStoreResolver, private readonly signal: AbortSignal,
    private readonly admission: RegistrySyncAdmission) {
    this.resolveStore = typeof store === 'function' ? store : async () => ({ store, release: () => {} })
  }

  /** Serve until disconnected, then drain the admitted operation and all identity resources.
   * @returns Quiescent cleanup; provider close failures are reported only as a fixed category. */
  async run(): Promise<void> {
    const closed = Promise.withResolvers<undefined>()
    const stop = (): void => { this.stop() }
    this.socket.once('close', () => { this.abort.abort(); closed.resolve(undefined) })
    this.socket.on('error', stop)
    this.socket.on('message', (data, binary) => { this.receive(data as Buffer, binary) })
    this.signal.addEventListener('abort', stop, { once: true })
    this.timer = setTimeout(stop, this.config.handshakeTimeoutMs)
    await closed.promise
    try { this.unsubscribe?.() } catch { /* Cleanup continues so the runtime lease is never stranded. */ }
    clearTimeout(this.timer)
    this.signal.removeEventListener('abort', stop)
    let pendingFailed = false
    try { await this.pending } catch { pendingFailed = true }
    this.authority?.invalidated.removeEventListener('abort', this.invalidate)
    const outcomes = await Promise.allSettled([
      Promise.resolve().then(() => this.attempt?.close()),
      Promise.resolve().then(() => this.authority?.close()),
    ])
    this.storeLease?.release()
    this.storeLease = undefined
    if (pendingFailed || outcomes.some(outcome => outcome.status === 'rejected')) {
      throw new Error('Registry identity cleanup failed')
    }
  }

  private readonly invalidate = (): void => { this.stop() }

  private stop(): void {
    this.abort.abort()
    this.socket.terminate()
  }

  private async selectStore(organizationId: OrganizationId): Promise<void> {
    if (this.store !== undefined) throw new RegistrySyncProtocolError()
    let lease: RegistryRuntimeStoreLease
    try { lease = await this.resolveStore(organizationId) } catch { throw new Unauthorized() }
    if (!lease.store.active() || lease.store.organizationId !== organizationId) {
      lease.release()
      throw new Unauthorized()
    }
    try {
      this.storeLease = lease
      this.store = lease.store
      this.unsubscribe = lease.store.subscribeInvalidation((notice) => {
        if (notice.kind === 'owner-unavailable') { this.stop(); return }
        const identity = this.authority?.identity ?? this.attempt?.challenge
        if (identity !== undefined && notice.change.organizationId === identity.organizationId
          && notice.change.instanceId === identity.instanceId
          && (notice.kind === 'binding' || this.disclosures.has(notice.change.disclosureId))) this.stop()
      })
    } catch {
      this.store = undefined
      this.storeLease = undefined
      lease.release()
      throw new Unauthorized()
    }
  }

  private runtimeStore(): RegistryRuntimeStore {
    const store = this.store
    if (store === undefined || !store.active()) throw new Unauthorized()
    return store
  }

  private current(): void {
    const current = registryAuthenticatorTarget(this.ctx.get('registryProducerAuthenticator'))
    const expected = registryAuthenticatorTarget(this.provider)
    if (this.abort.signal.aborted || (this.store !== undefined && !this.store.active())
      || current !== expected
      || this.authority?.invalidated.aborted === true) throw new Unauthorized()
  }

  private receive(data: Buffer, binary: boolean): void {
    if (this.abort.signal.aborted) return
    let frame: RegistryInboundFrame
    try {
      this.current()
      if (!this.admission.admitFrame(data.byteLength)) throw new Busy()
      if (binary) throw new RegistrySyncProtocolError()
      // ws supplies text messages as UTF-8-validated Buffers and enforces maxPayload before this callback.
      const text = data.toString('utf8')
      try { frame = decodeRegistryClientFrame(text, this.config.maxFrameBytes) }
      catch {
        const rejected = this.authority === undefined
          ? undefined : recoverRejectedRecordFrame(text, this.config.maxFrameBytes)
        if (rejected === undefined) throw new RegistrySyncProtocolError()
        frame = rejected
      }
      if (frame.requestId <= this.lastRequestId) {
        if (this.authority !== undefined) {
          this.ctx.logger.warn('Registry request sequence rejected: %j', {
            organizationId: this.runtimeStore().organizationId, instanceId: this.authority.identity.instanceId,
            keyId: this.authority.identity.keyId, previousRequestId: this.lastRequestId, receivedRequestId: frame.requestId,
          })
        }
        throw new RegistrySyncProtocolError()
      }
      this.lastRequestId = frame.requestId
      if (this.pending !== undefined) {
        const release = this.release
        if (release === undefined || frame.type !== release.type
          || frame.authorizationRequestId !== release.authorizationRequestId || this.authority === undefined
          || !this.admission.admitRequest(this.authority.identity, undefined, data.byteLength)) {
          throw new RegistrySyncProtocolError()
        }
        this.release = undefined
        release.settle(frame)
        return
      }
    } catch {
      // Unadmitted or invalid frames have no trusted request identifier to echo.
      this.stop()
      return
    }
    // An admitted authenticated operation owns its own cancellation bounds; the idle timer resumes after settlement.
    if (this.authority !== undefined) clearTimeout(this.timer)
    const task = this.handle(frame, data.byteLength).catch(async (error: unknown) => {
      if (error instanceof StaleDisclosure) { this.stop(); return }
      if (error instanceof QuestionRejected) {
        try { await this.send({ protocolVersion: 1, requestId: error.requestId, type: 'error', code: error.code }) }
        catch { this.stop(); return }
        if (error.fatal) this.stop()
        else this.resetIdle()
        return
      }
      if (error instanceof ImportRejected) {
        try { await this.send({ protocolVersion: 1, requestId: error.requestId, type: 'error', code: error.code }) }
        catch { this.stop(); return }
        if (error.fatal) this.stop()
        else this.resetIdle()
        return
      }
      const code: RegistrySyncErrorCode = error instanceof RegistryIngestError ? error.code
        : error instanceof RegistrySyncProtocolError ? 'protocol' : error instanceof Unauthorized ? 'unauthorized'
          : error instanceof Busy ? 'busy' : 'storage-unavailable'
      try { await this.send({ protocolVersion: 1, requestId: frame.requestId, type: 'error', code }) } catch {
        // An error frame cannot repair a closed connection or an exhausted output bound.
      }
      this.stop()
    })
    this.pending = task
    void task.then(() => { this.pending = undefined })
  }

  private async handle(frame: RegistryInboundFrame, bytes: number): Promise<void> {
    this.current()
    const base = { protocolVersion: 1 as const, requestId: frame.requestId }
    if (this.authority === undefined) {
      if (this.attempt === undefined && frame.type === 'hello') {
        if (!this.admission.admitHandshake()) throw new Busy()
        try { this.attempt = await this.provider.begin(frame.token, this.config.audience, this.abort.signal) }
        catch { throw new Unauthorized() }
        this.current()
        await this.send({ ...base, type: 'challenge', challenge: this.attempt.challenge })
      } else if (this.attempt !== undefined && frame.type === 'prove') {
        if (!this.admission.admitHandshake()) throw new Busy()
        try { this.authority = await this.attempt.complete(frame.signature, this.abort.signal) }
        catch { throw new Unauthorized() }
        this.authority.invalidated.addEventListener('abort', this.invalidate, { once: true })
        await this.selectStore(this.authority.identity.organizationId)
        this.current()
        const authority = this.authority
        await this.withAuthority(authority, async (fresh) => {
          await this.verifyConnection(() => this.checked(fresh, authority))
          await this.send({ ...base, type: 'authenticated', identity: authority.identity })
        })
        this.current()
        this.recordHeartbeat = this.runtimeStore().transport.connect(authority.identity.instanceId, this.abort.signal)
        this.resetIdle()
      } else throw new RegistrySyncProtocolError()
      return
    }
    if (frame.type === 'hello' || frame.type === 'prove') throw new RegistrySyncProtocolError()
    const authority = this.authority
    const producerCommand = frame.type === 'producer-register' || frame.type === 'producer-update-access'
      || frame.type === 'producer-transition-control' || frame.type === 'producer-delete'
    const disclosureId = frame.type === 'status' || frame.type === 'event' || frame.type === 'checkpoint'
      || producerCommand
      ? frame.disclosureId
      : frame.type === 'question-start' || frame.type === 'question-renew' || frame.type === 'question-status'
        || frame.type === 'question-transition' || frame.type === 'question-authorize'
        ? frame.binding.disclosureId : undefined
    if (!this.admission.admitRequest(authority.identity, disclosureId, bytes)) {
      throw new Busy()
    }
    // Producer commands use a short authenticated request but do not subscribe that same connection to
    // the authorization invalidation they commit. Other connections that observed the resource still close.
    if (disclosureId !== undefined && !producerCommand) this.disclosures.add(disclosureId)
    await this.withAuthority(authority, async (fresh) => {
      const checked = (): Promise<RegistryConnectionAuthority> => this.checked(fresh, authority)
      if (frame.type === 'heartbeat') {
        await this.verifyProducer(checked)
        const observedAt = (await checked()).connection.now
        await this.send({ ...base, type: 'heartbeat-ack', observedAt })
        this.current()
        this.recordHeartbeat?.(observedAt, frame.report)
        return
      }
      if (frame.type === 'question-authorize-release' || frame.type === 'import-release') {
        throw new RegistrySyncProtocolError()
      }
      if (frame.type === 'question-dispatch' || frame.type === 'question-start' || frame.type === 'question-renew'
        || frame.type === 'question-status' || frame.type === 'question-transition'
        || frame.type === 'question-authorize') {
        await this.handleQuestion(frame, checked)
        return
      }
      if (frame.type === 'import-dispatch') {
        await this.handleImport(frame, checked)
        return
      }
      if (producerCommand) {
        await this.handleProducerCommand(frame, checked)
        return
      }
      let response: ResourceResponse
      switch (frame.type) {
        case 'status':
          response = { ...base, type: 'status', status: await this.runtimeStore().run(store => store.getSyncStatus(checked, frame.disclosureId)) }
          break
        case 'event':
          response = { ...base, type: 'event-ack', receipt: await this.runtimeStore().run(store =>
            store.ingestEvent(checked, frame.disclosureId, frame.envelope)) }
          break
        case 'checkpoint':
          response = { ...base, type: 'checkpoint-ack', receipt: await this.runtimeStore().run(store =>
            store.ingestCheckpoint(checked, frame.disclosureId, frame.checkpoint)) }
          break
        /* v8 ignore next -- closed-union exhaustiveness guard after strict or exact-outer decoding */
        default: return assertNever(frame, 'Registry authenticated request')
      }
      await checked()
      const { delivery } = await this.runtimeStore().run(async (store) => {
        const status = await store.getSyncStatus(checked, frame.disclosureId)
        const current = await checked()
        const originalVersion = response.type === 'status'
          ? response.status.kind === 'live' ? response.status.receipt.authorizationVersion : response.status.authorizationVersion
          : response.receipt.authorizationVersion
        const version = status.kind === 'live' ? status.receipt.authorizationVersion : status.authorizationVersion
        if (version !== originalVersion) throw new StaleDisclosure()
        if (response.type !== 'status' && (status.kind !== 'live' || status.receipt.control !== 'active'
          || status.receipt.ingest === 'frozen' || current.connection.now >= status.expiresAt)) throw new StaleDisclosure()
        const outgoing = response.type === 'status'
          ? { ...response, status: status.kind === 'live' ? { ...status, observedAt: current.connection.now } : status }
          : response
        // The sole runtime queue excludes other commits until send is enqueued, not until network delivery finishes.
        // ACKs retain the original committed request receipt; a final status read does not replace that fact.
        return { delivery: this.send(outgoing) }
      })
      await delivery
    })
    this.resetIdle()
  }

  private async handleProducerCommand(frame: ProducerCommandFrame,
    checked: () => Promise<RegistryConnectionAuthority>): Promise<void> {
    const base = { protocolVersion: 1 as const, requestId: frame.requestId }
    let receipt: RegistryIngestReceipt
    switch (frame.type) {
      case 'producer-register': {
        const current = await checked()
        receipt = await this.runtimeStore().run(store => store.register(checked, producerRegistration(frame, current)))
        break
      }
      case 'producer-update-access':
        receipt = await this.runtimeStore().run(store => store.updateAccess(checked, frame.disclosureId,
          producerAccessUpdate(frame.update), frame.expectedAuthorizationVersion))
        break
      case 'producer-transition-control':
        receipt = await this.runtimeStore().run(store => store.transitionControl(checked, frame.disclosureId,
          frame.target, frame.expectedAuthorizationVersion))
        break
      case 'producer-delete':
        receipt = await this.runtimeStore().run(store => store.delete(checked, frame.disclosureId,
          frame.expectedAuthorizationVersion))
        break
      /* v8 ignore next -- strict frame decoding leaves no other producer command. */
      default: return assertNever(frame, 'Registry producer command')
    }
    await checked()
    const { delivery } = await this.runtimeStore().run(async (store) => {
      const status = await store.getSyncStatus(checked, frame.disclosureId)
      const current = await checked()
      const version = status.kind === 'live' ? status.receipt.authorizationVersion : status.authorizationVersion
      if (receipt.disclosureId !== frame.disclosureId || version !== receipt.authorizationVersion
        || frame.type === 'producer-delete' && status.kind !== 'deleted'
        || frame.type !== 'producer-delete' && status.kind !== 'live') throw new StaleDisclosure()
      const observed = status.kind === 'live' ? { ...status, observedAt: current.connection.now } : status
      const response: RegistryServerFrame = frame.type === 'producer-register'
        ? { ...base, type: 'producer-register-ack', status: observed }
        : frame.type === 'producer-update-access'
          ? { ...base, type: 'producer-update-access-ack', status: observed }
          : frame.type === 'producer-transition-control'
            ? { ...base, type: 'producer-transition-control-ack', status: observed }
            : { ...base, type: 'producer-delete-ack', status: observed }
      return { delivery: this.send(response) }
    })
    await delivery
  }

  private async handleQuestion(frame: QuestionFrame,
    checked: () => Promise<RegistryConnectionAuthority>): Promise<void> {
    const broker: RegistryQuestionBroker | undefined = this.ctx.get('registryQuestionBroker', false)
    if (broker === undefined) throw new QuestionRejected('not-found', frame.requestId)
    const base = { protocolVersion: 1 as const, requestId: frame.requestId }
    let release: QuestionReleaseFrame | undefined
    try {
      await this.verifyReceiver(checked)
      const source = await checked()
      switch (frame.type) {
        case 'question-dispatch': {
          const delivery = await broker.dispatch(source, frame.excludeRequestIds ?? [], this.abort.signal)
          if (delivery !== null) this.disclosures.add(delivery.binding.disclosureId)
          await checked()
          await this.send({ ...base, type: 'question-dispatch', delivery })
          return
        }
        case 'question-start': {
          const result = await broker.start(source, frame.binding, frame.expectedVersion, this.abort.signal)
          await checked()
          await this.send({ ...base, type: 'question-start', ...result })
          return
        }
        case 'question-renew': {
          const result = await broker.renew(source, frame.binding, frame.expectedVersion, this.abort.signal)
          await checked()
          await this.send({ ...base, type: 'question-renew', ...result })
          return
        }
        case 'question-status': {
          const receipt = await broker.status(source, frame.binding, this.abort.signal)
          await checked()
          await this.send({ ...base, type: 'question-status', receipt })
          return
        }
        case 'question-transition': {
          const receipt = await broker.transition(source, frame.binding, frame.expectedVersion,
            frame.transition, this.abort.signal)
          await checked()
          await this.send({ ...base, type: 'question-transition', receipt })
          return
        }
        case 'question-authorize': {
          await broker.withAuthorization(source, frame.binding, frame.expectedVersion, async (delivery) => {
            this.disclosures.add(delivery.binding.disclosureId)
            const waiting = this.waitForQuestionRelease(frame.requestId)
            try { await this.send({ ...base, type: 'question-authorized', delivery }) }
            catch (error) {
              this.stop()
              await waiting.catch(() => undefined)
              throw error
            }
            release = await waiting
          }, this.abort.signal)
          if (release === undefined) throw new RegistrySyncProtocolError()
          await checked()
          await this.send({ protocolVersion: 1, requestId: release.requestId,
            type: 'question-authorize-released', authorizationRequestId: frame.requestId })
          return
        }
        default: return assertNever(frame, 'Registry question request')
      }
    } catch (error) {
      if (error instanceof MailboxError) {
        throw new QuestionRejected(questionError(error), release?.requestId ?? frame.requestId, release !== undefined)
      }
      if (release !== undefined) {
        throw new QuestionRejected(error instanceof Unauthorized ? 'unauthorized' : 'storage-unavailable',
          release.requestId, true)
      }
      throw error
    }
  }

  private async handleImport(frame: ImportFrame,
    checked: () => Promise<RegistryConnectionAuthority>): Promise<void> {
    const broker: RegistryImportBroker | undefined = this.ctx.get('registryImportBroker', false)
    if (broker === undefined) throw new ImportRejected('not-found', frame.requestId)
    const base = { protocolVersion: 1 as const, requestId: frame.requestId }
    let release: ImportReleaseFrame | undefined
    try {
      await this.verifyReceiver(checked)
      const target = await checked()
      const delivered = await broker.dispatch(target, async (delivery) => {
        this.disclosures.add(delivery.disclosureId)
        const waiting = this.waitForImportRelease(frame.requestId)
        try { await this.send({ ...base, type: 'import-dispatch', delivery }) }
        catch (error) {
          this.stop()
          await waiting.catch(() => undefined)
          throw error
        }
        release = await waiting
        return release.outcome
      }, this.abort.signal)
      if (!delivered) {
        await checked()
        await this.send({ ...base, type: 'import-dispatch', delivery: null })
        this.resetIdle()
        return
      }
      if (release === undefined) throw new RegistrySyncProtocolError()
      await checked()
      await this.send({ protocolVersion: 1, requestId: release.requestId,
        type: 'import-released', authorizationRequestId: frame.requestId })
      this.resetIdle()
    } catch (error) {
      if (release !== undefined) {
        const code = error instanceof RegistryIngestError ? error.code
          : error instanceof Unauthorized ? 'unauthorized' : 'storage-unavailable'
        throw new ImportRejected(code, release.requestId, true)
      }
      throw error
    }
  }

  private waitForQuestionRelease(authorizationRequestId: number): Promise<QuestionReleaseFrame> {
    if (this.release !== undefined || this.abort.signal.aborted) return Promise.reject(new RegistrySyncProtocolError())
    return new Promise((resolve, reject) => {
      let settled = false
      const settle = (frame: ReleaseFrame | undefined): void => {
        if (settled) return
        settled = true
        this.abort.signal.removeEventListener('abort', abort)
        if (this.release?.settle === settle) this.release = undefined
        if (frame === undefined || frame.type !== 'question-authorize-release') reject(new Unauthorized())
        else resolve(frame)
      }
      const abort = (): void => { settle(undefined) }
      this.release = { type: 'question-authorize-release', authorizationRequestId, settle }
      this.abort.signal.addEventListener('abort', abort, { once: true })
      if (this.abort.signal.aborted) abort()
    })
  }

  private waitForImportRelease(authorizationRequestId: number): Promise<ImportReleaseFrame> {
    if (this.release !== undefined || this.abort.signal.aborted) return Promise.reject(new RegistrySyncProtocolError())
    return new Promise((resolve, reject) => {
      let settled = false
      const settle = (frame: ReleaseFrame | undefined): void => {
        if (settled) return
        settled = true
        this.abort.signal.removeEventListener('abort', abort)
        if (this.release?.settle === settle) this.release = undefined
        if (frame === undefined || frame.type !== 'import-release') reject(new Unauthorized())
        else resolve(frame)
      }
      const abort = (): void => { settle(undefined) }
      this.release = { type: 'import-release', authorizationRequestId, settle }
      this.abort.signal.addEventListener('abort', abort, { once: true })
      if (this.abort.signal.aborted) abort()
    })
  }

  private async checked(fresh: FreshRegistryConnectionAuthority,
    authority: AuthenticatedRegistryConnection): Promise<RegistryConnectionAuthority> {
    this.current()
    let current: RegistryConnectionAuthority
    try { current = await fresh() } catch { throw new Unauthorized() }
    this.current()
    const identity = authority.identity
    if (identity.organizationId !== this.runtimeStore().organizationId
      || current.connection.organizationId !== identity.organizationId || current.connection.instanceId !== identity.instanceId
      || current.connection.keyId !== identity.keyId) throw new Unauthorized()
    return current
  }

  private async withAuthority(authority: AuthenticatedRegistryConnection,
    perform: (fresh: FreshRegistryConnectionAuthority) => Promise<void>): Promise<void> {
    let callbackFailure: { error: unknown } | undefined
    try {
      await authority.withAuthority(async (fresh) => {
        try { await perform(fresh) } catch (error) { callbackFailure = { error }; throw error }
      }, this.abort.signal)
    } catch (error) {
      // Storage/protocol failures belong to the callback; provider admission or lease failures are authentication failures.
      if (callbackFailure !== undefined && callbackFailure.error === error) throw error
      throw new Unauthorized()
    }
  }

  private async verifyProducer(fresh: FreshRegistryConnectionAuthority): Promise<void> {
    try { await this.runtimeStore().run(store => store.verifyProducer(fresh)) } catch (error) {
      if (error instanceof RegistryIngestError && error.code === 'not-found') throw new Unauthorized()
      throw error
    }
  }

  private async verifyConnection(fresh: FreshRegistryConnectionAuthority): Promise<void> {
    try { await this.runtimeStore().run(store => store.verifyConnection(fresh)) } catch (error) {
      if (error instanceof RegistryIngestError && error.code === 'not-found') throw new Unauthorized()
      throw error
    }
  }

  private async verifyReceiver(fresh: FreshRegistryConnectionAuthority): Promise<void> {
    try { await this.runtimeStore().run(store => store.verifyReceiver(fresh)) } catch (error) {
      if (error instanceof RegistryIngestError && error.code === 'not-found') throw new Unauthorized()
      throw error
    }
  }

  private resetIdle(): void {
    clearTimeout(this.timer)
    this.timer = setTimeout(() => { this.stop() }, this.config.idleTimeoutMs)
  }

  private send(frame: RegistryServerFrame): Promise<void> {
    this.current()
    const text = encodeRegistryServerFrame(frame, this.config.maxFrameBytes)
    if (this.socket.readyState !== WebSocket.OPEN
      || this.socket.bufferedAmount + Buffer.byteLength(text) > this.config.maxSendBufferBytes) throw new RegistrySyncProtocolError()
    return new Promise((resolve, reject) => {
      this.socket.send(text, (error) => {
        if (error) reject(new Error('Registry response delivery failed'))
        else resolve()
      })
    })
  }
}
