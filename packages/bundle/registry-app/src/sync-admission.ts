/** Synchronization budgets; an optional shared owner coordinates same-host Registry processes. */
import { performance } from 'node:perf_hooks'
import type { RegistryConnectionIdentity } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { DisclosureId } from '@deepseek-ai/dsh-a2a-protocol'
import type { RegistrySharedAdmission, RegistrySharedAdmissionCharge } from './shared-admission-sqlite.ts'
import type { RegistrySyncAdmissionConfig, RegistrySyncBucketConfig, RegistrySyncFrameBudgetConfig } from './sync-config.ts'

interface BucketState {
  tokens: number
  at: number
}

interface FrameState {
  requests: BucketState
  bytes: BucketState
}

interface ScopedCharge {
  entries: Map<string, FrameState>
  key: string
  replacement: string | undefined
  next: FrameState
}

type Scope = 'organizations' | 'instances' | 'disclosures'
type Single = 'upgrades' | 'handshakes'

type UpgradeAdmissionDecision =
  | { readonly admitted: true }
  | { readonly admitted: false; readonly retryAfterSeconds: number }

const UPGRADE_ADMITTED: UpgradeAdmissionDecision = { admitted: true }

function available(state: BucketState, config: RegistrySyncBucketConfig, now: number): number {
  return Math.min(config.capacity, state.tokens + (now - state.at) / 1000 * config.refillPerSecond)
}

function waitFor(tokens: number, config: RegistrySyncBucketConfig): number {
  return Math.max(1, Math.min(2 ** 31 - 1, Math.ceil((1 - tokens) / config.refillPerSecond)))
}

function full(config: RegistrySyncFrameBudgetConfig, now: number): FrameState {
  return { requests: { tokens: config.requests.capacity, at: now }, bytes: { tokens: config.bytes.capacity, at: now } }
}

function charge(state: FrameState, config: RegistrySyncFrameBudgetConfig, bytes: number, now: number): FrameState | undefined {
  const requests = available(state.requests, config.requests, now)
  const remaining = available(state.bytes, config.bytes, now)
  if (requests < 1 || remaining < bytes) return undefined
  return { requests: { tokens: requests - 1, at: now }, bytes: { tokens: remaining - bytes, at: now } }
}

/** One route owner; reconnects share its budgets, and optional SQLite coordinates sibling processes. */
export class RegistrySyncAdmission {
  private readonly config: RegistrySyncAdmissionConfig
  private readonly singles: Record<Single, BucketState>
  private frames: FrameState
  private readonly scopes: Record<Scope, Map<string, FrameState>> = {
    organizations: new Map(), instances: new Map(), disclosures: new Map(),
  }

  /** @param config - Fully validated deployment budgets, copied so later config mutation cannot replenish credit.
   * @param clock - Trusted finite monotonic milliseconds; the production owner uses the process performance clock.
   * @param shared - Optional same-host multi-process owner; absent deployments remain process-local. */
  constructor(config: RegistrySyncAdmissionConfig, private readonly clock: () => number = () => performance.now(),
    private readonly shared?: RegistrySharedAdmission) {
    this.config = structuredClone(config)
    const now = this.clock()
    this.singles = { upgrades: { tokens: this.config.upgrades.capacity, at: now },
      handshakes: { tokens: this.config.handshakes.capacity, at: now } }
    this.frames = full(this.config.frames, now)
  }

  /** Charge one accepted upgrade attempt before allocating its connection resources.
   * @returns Admission or a bounded integer delay suitable for an HTTP Retry-After header. */
  admitUpgrade(): UpgradeAdmissionDecision {
    if (this.shared !== undefined) return this.shared.charge([{
      scope: 'sync-upgrades', key: 'global', maxEntries: 1,
      requests: { ...this.config.upgrades, cost: 1 },
    }])
    const now = this.clock()
    const tokens = available(this.singles.upgrades, this.config.upgrades, now)
    if (tokens < 1) return { admitted: false, retryAfterSeconds: waitFor(tokens, this.config.upgrades) }
    this.singles.upgrades = { tokens: tokens - 1, at: now }
    return UPGRADE_ADMITTED
  }

  /** Charge one identity begin or complete call before invoking the provider.
   * @returns Whether one token was consumed. */
  admitHandshake(): boolean {
    if (this.shared !== undefined) return this.shared.charge([{
      scope: 'sync-handshakes', key: 'global', maxEntries: 1,
      requests: { ...this.config.handshakes, cost: 1 },
    }]).admitted
    return this.admitSingle('handshakes')
  }

  /** Charge complete WebSocket data messages independently of decoding, authentication and scoped request admission.
   * @param bytes - Complete received Buffer length, including malformed or empty frames.
   * @returns Whether both frame buckets were charged; rejection changes neither bucket. */
  admitFrame(bytes: number): boolean {
    if (this.shared !== undefined) return this.shared.charge([{
      scope: 'sync-frames', key: 'global', maxEntries: 1,
      requests: { ...this.config.frames.requests, cost: 1 },
      bytes: { ...this.config.frames.bytes, cost: bytes },
    }]).admitted
    const next = charge(this.frames, this.config.frames, bytes, this.clock())
    if (next === undefined) return false
    this.frames = next
    return true
  }

  /** Atomically charge current authenticated scopes; rejection neither consumes credit nor changes retained keys.
   * @param identity - Provider-authenticated organization and instance; key rotation never selects another budget.
   * @param disclosureId - Decoded requested ID, namespaced by the authenticated instance, or absent for heartbeat.
   * @param bytes - Complete received frame Buffer length, including its JSON wrapper.
   * @returns Whether all applicable scopes admit immediately; never waits, grants authority or touches storage. */
  admitRequest(identity: RegistryConnectionIdentity, disclosureId: DisclosureId | undefined, bytes: number): boolean {
    const { organizationId, instanceId } = identity
    if (this.shared !== undefined) {
      const sharedCharges: RegistrySharedAdmissionCharge[] = [
        this.sharedRequest('sync-organizations', organizationId, this.config.organizations, bytes),
        this.sharedRequest('sync-instances', JSON.stringify([organizationId, instanceId]),
          this.config.instances, bytes),
      ]
      if (disclosureId !== undefined) sharedCharges.push(this.sharedRequest('sync-disclosures',
        JSON.stringify([organizationId, instanceId, disclosureId]), this.config.disclosures, bytes))
      return this.shared.charge(sharedCharges).admitted
    }
    const now = this.clock()
    const charges = [
      this.prepare('organizations', organizationId, bytes, now),
      this.prepare('instances', JSON.stringify([organizationId, instanceId]), bytes, now),
    ]
    if (disclosureId !== undefined) charges.push(this.prepare('disclosures', JSON.stringify([organizationId, instanceId, disclosureId]), bytes, now))
    if (!charges.every(candidate => candidate !== undefined)) return false
    for (const candidate of charges) {
      if (candidate.replacement !== undefined) candidate.entries.delete(candidate.replacement)
      candidate.entries.set(candidate.key, candidate.next)
    }
    return true
  }

  private admitSingle(kind: Single): boolean {
    const now = this.clock()
    const tokens = available(this.singles[kind], this.config[kind], now)
    if (tokens < 1) return false
    this.singles[kind] = { tokens: tokens - 1, at: now }
    return true
  }

  private sharedRequest(scope: string, key: string, config: RegistrySyncFrameBudgetConfig & { maxEntries: number },
    bytes: number): RegistrySharedAdmissionCharge {
    return { scope, key, maxEntries: config.maxEntries,
      requests: { ...config.requests, cost: 1 }, bytes: { ...config.bytes, cost: bytes } }
  }

  private prepare(scope: Scope, key: string, bytes: number, now: number): ScopedCharge | undefined {
    const entries = this.scopes[scope]
    const config = this.config[scope]
    const previous = entries.get(key)
    const next = charge(previous ?? full(config, now), config, bytes, now)
    if (next === undefined) return undefined
    let replacement: string | undefined
    if (previous === undefined && entries.size >= config.maxEntries) {
      // Forgetting a partly depleted entry would let identity churn replenish its budget early.
      for (const [candidate, state] of entries) {
        if (available(state.requests, config.requests, now) === config.requests.capacity
          && available(state.bytes, config.bytes, now) === config.bytes.capacity) {
          replacement = candidate
          break
        }
      }
      if (replacement === undefined) return undefined
    }
    return { entries, key, replacement, next }
  }
}
