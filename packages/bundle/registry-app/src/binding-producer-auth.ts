/** Tenant-routed Registry producer authentication backed by confirmed device bindings. */
import { randomBytes } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { DisclosureSignature, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { RegistryBindingId } from '@deepseek-ai/dsh-a2a-registry-ingest'
import {
  REGISTRY_DEVICE_TOKEN_MAX_BYTES,
  RegistryProducerAuthenticator,
  decodeRegistryAudience,
  decodeRegistryDeviceToken,
  hashRegistryBridgeSecret,
  hashRegistryDeviceSecret,
  verifyRegistryChallenge,
  type AuthenticatedRegistryConnection,
  type FreshRegistryConnectionAuthority,
  type RegistryChallenge,
  type RegistryChallengeAttempt,
  type RegistryConnectionAuthority,
  type RegistryConnectionIdentity,
  type RegistryBridgeSecretHash,
  type RegistryDeviceSecretHash,
} from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { RegistryRuntimeInvalidation } from './runtime-store.ts'
import type { RegistryRuntimeStoreLease, RegistryRuntimeStoreResolver } from './sync-connection.ts'

/** Trusted synchronization bounds used when decoding credentials and issuing challenges. */
export interface RegistryBindingProducerAuthenticatorConfig {
  readonly audience: string
  readonly handshakeTimeoutMs: number
  readonly maxFrameBytes: number
}

/** Resolve one tenant only after the untrusted token selector has passed canonical decoding. */
export type RegistryBindingProducerRuntimeResolver = RegistryRuntimeStoreResolver

interface ProviderHandle {
  close(): Promise<void>
}

function rejectAuthentication(): never {
  throw new Error('Registry device authentication failed')
}

function requireAuthentication(condition: boolean): asserts condition {
  if (!condition) rejectAuthentication()
}

function sameIdentity(left: RegistryConnectionIdentity, right: RegistryConnectionIdentity): boolean {
  return left.organizationId === right.organizationId && left.instanceId === right.instanceId
    && left.keyId === right.keyId
}

function checkedAuthority(authority: RegistryConnectionAuthority, organizationId: OrganizationId,
  expected?: RegistryConnectionIdentity): RegistryConnectionAuthority {
  const identity = authority.connection
  requireAuthentication(identity.organizationId === organizationId
    && authority.history.organizationId === identity.organizationId
    && authority.history.instanceId === identity.instanceId
    && authority.history.status === 'active'
    && Number.isSafeInteger(identity.now) && identity.now >= 0
    && (expected === undefined || sameIdentity(identity, expected)))
  return authority
}

function throwIfAborted(...signals: readonly AbortSignal[]): void {
  for (const signal of signals) signal.throwIfAborted()
}

function providerContext(ctx: Context, config: RegistryBindingProducerAuthenticatorConfig): Context {
  try {
    requireAuthentication(Number.isSafeInteger(config.maxFrameBytes) && config.maxFrameBytes > 0
      && Number.isSafeInteger(config.handshakeTimeoutMs) && config.handshakeTimeoutMs > 0
      && decodeRegistryAudience(config.audience) === config.audience)
  } catch { rejectAuthentication() }
  return ctx
}

/** One tenant-runtime reference and invalidation subscription transferred from attempt to connection. */
class BindingCredentialLease {
  readonly invalidated = new AbortController()
  private readonly removeAbortListeners: (() => void)[] = []
  private unsubscribe: (() => void) | undefined
  private released = false
  identity: RegistryConnectionIdentity | undefined

  constructor(readonly runtime: RegistryRuntimeStoreLease, readonly organizationId: OrganizationId,
    readonly bindingId: RegistryBindingId, readonly presentedHash: RegistryDeviceSecretHash,
    readonly sameRawBridgeHash: RegistryBridgeSecretHash,
    signals: readonly AbortSignal[]) {
    const stop = (): void => { this.invalidated.abort() }
    for (const signal of signals) {
      if (signal.aborted) stop()
      else {
        signal.addEventListener('abort', stop, { once: true })
        this.removeAbortListeners.push(() => { signal.removeEventListener('abort', stop) })
      }
    }
    try {
      this.unsubscribe = runtime.store.subscribeInvalidation((notice) => { this.onInvalidation(notice) })
    } catch (error) {
      this.release()
      throw error
    }
  }

  authenticate(): Promise<RegistryConnectionAuthority> {
    return this.runtime.store.authenticateBindingCredential(this.bindingId, this.presentedHash,
      this.sameRawBridgeHash)
  }

  release(): void {
    if (this.released) return
    this.released = true
    this.invalidated.abort()
    for (const remove of this.removeAbortListeners.splice(0)) remove()
    try { this.unsubscribe?.() } finally {
      this.unsubscribe = undefined
      this.runtime.release()
    }
  }

  private onInvalidation(notice: RegistryRuntimeInvalidation): void {
    if (notice.kind === 'owner-unavailable') {
      this.invalidated.abort()
      return
    }
    if (notice.kind !== 'binding' || notice.change.organizationId !== this.organizationId) return
    // Before the first owner-queue authentication, conservatively reject any concurrent binding change.
    if (this.identity === undefined || notice.change.instanceId === this.identity.instanceId) {
      this.invalidated.abort()
    }
  }
}

class BindingAuthenticatedConnection implements AuthenticatedRegistryConnection, ProviderHandle {
  readonly identity: RegistryConnectionIdentity
  readonly invalidated: AbortSignal
  private tail: Promise<void> = Promise.resolve()
  private closing: Promise<void> | undefined
  private accepting = true

  constructor(private readonly owner: RegistryBindingProducerAuthenticator,
    private readonly lease: BindingCredentialLease, identity: RegistryConnectionIdentity) {
    this.identity = Object.freeze({ organizationId: identity.organizationId,
      instanceId: identity.instanceId, keyId: identity.keyId })
    this.invalidated = lease.invalidated.signal
  }

  withAuthority<T>(perform: (fresh: FreshRegistryConnectionAuthority) => Promise<T>, signal: AbortSignal): Promise<T> {
    if (!this.accepting || this.invalidated.aborted || signal.aborted) return Promise.reject(new Error('closed'))
    const result = this.tail.then(async () => {
      throwIfAborted(this.invalidated, signal)
      const current = checkedAuthority(await this.lease.authenticate(), this.identity.organizationId, this.identity)
      throwIfAborted(this.invalidated, signal)
      let resolverActive = true
      let lastObservedAt = current.connection.now
      const fresh: FreshRegistryConnectionAuthority = () => {
        requireAuthentication(resolverActive)
        throwIfAborted(this.invalidated, signal)
        const observedAt = Date.now()
        requireAuthentication(Number.isSafeInteger(observedAt) && observedAt >= lastObservedAt)
        lastObservedAt = observedAt
        // The callback's operations enter this same runtime owner queue. Returning the authority resolved
        // immediately before admission avoids recursively entering RegistryRuntimeStore.run and deadlocking.
        // Refreshing only trusted server time keeps expiry checks current while that owner queue rechecks the
        // binding, member and scope against its latest durable state.
        return structuredClone({ ...current, connection: { ...current.connection, now: observedAt } })
      }
      try {
        const value = await perform(fresh)
        throwIfAborted(this.invalidated, signal)
        return value
      } finally { resolverActive = false }
    })
    this.tail = result.then(() => undefined, () => undefined)
    return result
  }

  close(): Promise<void> {
    this.accepting = false
    this.lease.invalidated.abort()
    this.closing ??= this.tail.then(() => {
      this.lease.release()
      this.owner.forget(this)
    }, () => {
      this.lease.release()
      this.owner.forget(this)
    })
    return this.closing
  }
}

class BindingChallengeAttempt implements RegistryChallengeAttempt, ProviderHandle {
  readonly challenge: RegistryChallenge
  private consumed = false
  private transferred = false
  private completion: Promise<AuthenticatedRegistryConnection> | undefined
  private closing: Promise<void> | undefined

  constructor(private readonly owner: RegistryBindingProducerAuthenticator,
    private readonly lease: BindingCredentialLease, challenge: RegistryChallenge) {
    this.challenge = Object.freeze({ ...challenge })
  }

  complete(signature: DisclosureSignature, signal: AbortSignal): Promise<AuthenticatedRegistryConnection> {
    if (this.consumed || this.closing !== undefined) return Promise.reject(new Error('closed'))
    this.consumed = true
    this.completion = this.finish(signature, signal)
    return this.completion
  }

  close(): Promise<void> {
    if (this.transferred) {
      this.owner.forget(this)
      return Promise.resolve()
    }
    this.lease.invalidated.abort()
    this.closing ??= Promise.resolve(this.completion).then(() => {
      if (!this.transferred) this.lease.release()
      this.owner.forget(this)
    }, () => {
      if (!this.transferred) this.lease.release()
      this.owner.forget(this)
    })
    return this.closing
  }

  private async finish(signature: DisclosureSignature, signal: AbortSignal): Promise<AuthenticatedRegistryConnection> {
    throwIfAborted(this.lease.invalidated.signal, signal)
    const current = checkedAuthority(await this.lease.authenticate(), this.challenge.organizationId, this.challenge)
    throwIfAborted(this.lease.invalidated.signal, signal)
    verifyRegistryChallenge(this.challenge, signature, current.history, current.connection,
      { audience: this.challenge.audience, nonce: this.challenge.nonce })
    throwIfAborted(this.lease.invalidated.signal, signal)
    const connection = new BindingAuthenticatedConnection(this.owner, this.lease, this.challenge)
    requireAuthentication(this.owner.adopt(this, connection))
    this.transferred = true
    return connection
  }
}

/** Built-in SaaS authenticator. Tokens route only to a binding owner; all authority is reloaded from that owner. */
export class RegistryBindingProducerAuthenticator extends RegistryProducerAuthenticator {
  private readonly lifetime = new AbortController()
  private readonly handles = new Set<ProviderHandle>()
  private readonly beginnings = new Set<Promise<RegistryChallengeAttempt>>()
  private readonly maxTokenBytes: number
  private readonly config: RegistryBindingProducerAuthenticatorConfig
  private accepting = true
  private closing: Promise<void> | undefined

  constructor(ctx: Context, config: RegistryBindingProducerAuthenticatorConfig,
    private readonly resolveRuntime: RegistryBindingProducerRuntimeResolver) {
    super(providerContext(ctx, config))
    this.config = Object.freeze({ ...config })
    this.maxTokenBytes = Math.min(config.maxFrameBytes, REGISTRY_DEVICE_TOKEN_MAX_BYTES)
  }

  begin(token: string, audience: string, signal: AbortSignal): Promise<RegistryChallengeAttempt> {
    if (!this.accepting || this.lifetime.signal.aborted || signal.aborted) return Promise.reject(new Error('closed'))
    const pending = this.open(token, audience, signal)
    this.beginnings.add(pending)
    void pending.then(() => { this.beginnings.delete(pending) }, () => { this.beginnings.delete(pending) })
    return pending
  }

  /** Stop admission, invalidate every handle and release tenant runtime references after admitted work drains. */
  close(): Promise<void> {
    this.accepting = false
    this.lifetime.abort()
    this.closing ??= (async () => {
      await Promise.allSettled([...this.beginnings])
      const outcomes = await Promise.allSettled([...this.handles].map(handle => handle.close()))
      if (outcomes.some(outcome => outcome.status === 'rejected')) {
        throw new Error('Registry binding authenticator cleanup failed')
      }
    })()
    return this.closing
  }

  /** @internal Transfer one runtime lease from its consumed attempt to the authenticated connection. */
  adopt(attempt: ProviderHandle, connection: ProviderHandle): boolean {
    if (!this.accepting || this.lifetime.signal.aborted || !this.handles.has(attempt)) return false
    this.handles.delete(attempt)
    this.handles.add(connection)
    return true
  }

  /** @internal Remove a settled handle without affecting another handle sharing its transferred lease. */
  forget(handle: ProviderHandle): void {
    this.handles.delete(handle)
  }

  private async open(token: string, audience: string, signal: AbortSignal): Promise<RegistryChallengeAttempt> {
    requireAuthentication(audience === this.config.audience)
    const decoded = decodeRegistryDeviceToken(token, this.maxTokenBytes)
    const presentedHash = hashRegistryDeviceSecret(decoded.secret)
    const sameRawBridgeHash = hashRegistryBridgeSecret(decoded.secret)
    const bindingId = brandString<RegistryBindingId>(decoded.bindingId)
    throwIfAborted(this.lifetime.signal, signal)
    const runtime = await this.resolveRuntime(decoded.organizationId)
    let lease: BindingCredentialLease | undefined
    try {
      requireAuthentication(runtime.store.active() && runtime.store.organizationId === decoded.organizationId)
      lease = new BindingCredentialLease(runtime, decoded.organizationId, bindingId, presentedHash,
        sameRawBridgeHash,
        [this.lifetime.signal, signal])
      const authority = checkedAuthority(await lease.authenticate(), decoded.organizationId)
      lease.identity = Object.freeze({ organizationId: authority.connection.organizationId,
        instanceId: authority.connection.instanceId, keyId: authority.connection.keyId })
      throwIfAborted(this.lifetime.signal, signal, lease.invalidated.signal)
      const now = authority.connection.now
      requireAuthentication(now < Number.MAX_SAFE_INTEGER)
      const challengeLifetimeMs = Math.min(this.config.handshakeTimeoutMs, 60_000)
      const expiresAt = now > Number.MAX_SAFE_INTEGER - challengeLifetimeMs
        ? Number.MAX_SAFE_INTEGER : now + challengeLifetimeMs
      requireAuthentication(expiresAt > now)
      const challenge: RegistryChallenge = {
        version: 1,
        audience: this.config.audience,
        ...lease.identity,
        nonce: randomBytes(32).toString('base64url'),
        expiresAt,
      }
      const attempt = new BindingChallengeAttempt(this, lease, challenge)
      if (!this.accepting || this.lifetime.signal.aborted || signal.aborted || lease.invalidated.signal.aborted) {
        await attempt.close()
        rejectAuthentication()
      }
      this.handles.add(attempt)
      return attempt
    } catch (error) {
      lease?.release()
      if (lease === undefined) runtime.release()
      throw error
    }
  }
}
