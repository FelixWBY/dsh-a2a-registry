/** Browser-operation request budgets; an optional shared owner coordinates same-host Registry processes. */
import { performance } from 'node:perf_hooks'
import ipaddr from 'ipaddr.js'
import type { RegistrySharedAdmission } from './shared-admission-sqlite.ts'

/** Explicit token capacity and continuous refill rate for one browser-operation scope. */
export interface RegistryBrowserAdmissionBucketConfig {
  /** Maximum accumulated tokens and initial burst allowance. */
  readonly capacity: number
  /** Tokens restored per second of monotonic elapsed time, capped at capacity. */
  readonly refillPerSecond: number
  /** Maximum retained direct-peer or account keys. */
  readonly maxEntries: number
}

/** Independent direct-peer and authenticated-account budgets. */
export interface RegistryBrowserAdmissionConfig {
  /** Client-address budget; defaults to the direct TCP peer unless explicit proxy trust applies. */
  readonly directPeer: RegistryBrowserAdmissionBucketConfig
  /** Authenticated organization-member tuple budget. */
  readonly account: RegistryBrowserAdmissionBucketConfig
  /** Optional bounded X-Forwarded-For trust rooted only in explicit proxy networks. */
  readonly trustedProxy?: RegistryBrowserTrustedProxyConfig
}

/** Explicit proxy networks and parsing bounds for deriving an original client rate key. */
export interface RegistryBrowserTrustedProxyConfig {
  /** IPv4 or IPv6 CIDRs whose direct connections may supply X-Forwarded-For. */
  readonly cidrs: string[]
  /** Maximum UTF-8 bytes accepted in the complete X-Forwarded-For value. */
  readonly maxForwardedBytes: number
  /** Maximum comma-separated addresses accepted in the forwarding chain. */
  readonly maxForwardedEntries: number
}

export type RegistryBrowserAdmissionScope = 'direct-peer' | 'account'

/** A rejection includes a bounded integer delay suitable for Retry-After. */
export type RegistryBrowserAdmissionDecision =
  | { readonly admitted: true }
  | { readonly admitted: false; readonly retryAfterSeconds: number }

interface BucketState {
  readonly tokens: number
  readonly at: number
}

const ADMITTED: RegistryBrowserAdmissionDecision = { admitted: true }

type IpAddress = ipaddr.IPv4 | ipaddr.IPv6

interface TrustedProxyRange {
  readonly address: IpAddress
  readonly prefix: number
}

class RegistryBrowserAddressError extends Error {
  constructor() {
    super('Registry browser client address unavailable')
    this.name = 'RegistryBrowserAddressError'
  }
}

function parseAddress(value: string): IpAddress {
  if (value === '' || value !== value.trim()) throw new RegistryBrowserAddressError()
  let parsed: IpAddress
  try { parsed = ipaddr.parse(value) } catch { throw new RegistryBrowserAddressError() }
  if (parsed instanceof ipaddr.IPv6) {
    if (parsed.zoneId !== undefined) throw new RegistryBrowserAddressError()
    if (parsed.isIPv4MappedAddress()) return parsed.toIPv4Address()
  }
  return parsed
}

function parseRange(value: string): TrustedProxyRange {
  if (value === '' || value !== value.trim()) throw new RegistryBrowserAddressError()
  let parsed: [IpAddress, number]
  try { parsed = ipaddr.parseCIDR(value) } catch { throw new RegistryBrowserAddressError() }
  const [address, prefix] = parsed
  if (address instanceof ipaddr.IPv6 && (address.zoneId !== undefined || address.isIPv4MappedAddress())) {
    throw new RegistryBrowserAddressError()
  }
  return { address, prefix }
}

function inRange(address: IpAddress, range: TrustedProxyRange): boolean {
  return address.kind() === range.address.kind() && address.match(range.address, range.prefix)
}

class TrustedProxyAddressResolver {
  private readonly ranges: readonly TrustedProxyRange[]

  constructor(private readonly config: RegistryBrowserTrustedProxyConfig) {
    if (config.cidrs.length === 0 || !Number.isSafeInteger(config.maxForwardedBytes)
      || config.maxForwardedBytes < 1 || !Number.isSafeInteger(config.maxForwardedEntries)
      || config.maxForwardedEntries < 1) throw new RegistryBrowserAddressError()
    this.ranges = config.cidrs.map(parseRange)
  }

  resolve(directAddress: string, forwarded: string | string[] | undefined): string {
    const direct = parseAddress(directAddress)
    if (!this.ranges.some(range => inRange(direct, range)) || forwarded === undefined) return direct.toString()
    if (Array.isArray(forwarded) || Buffer.byteLength(forwarded, 'utf8') > this.config.maxForwardedBytes) {
      throw new RegistryBrowserAddressError()
    }
    const entries = forwarded.split(',')
    if (entries.length === 0 || entries.length > this.config.maxForwardedEntries) {
      throw new RegistryBrowserAddressError()
    }
    let selected = direct
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const entry = entries[index]
      if (entry === undefined) throw new RegistryBrowserAddressError()
      selected = parseAddress(entry.trim())
      if (!this.ranges.some(range => inRange(selected, range))) return selected.toString()
    }
    return selected.toString()
  }
}

function available(state: BucketState, config: RegistryBrowserAdmissionBucketConfig, now: number): number {
  const elapsed = Math.max(0, now - state.at)
  return Math.min(config.capacity, state.tokens + elapsed / 1000 * config.refillPerSecond)
}

function waitFor(tokens: number, target: number, refillPerSecond: number): number {
  return Math.max(1, Math.min(2 ** 31 - 1, Math.ceil((target - tokens) / refillPerSecond)))
}

class KeyedAdmission {
  private readonly entries = new Map<string, BucketState>()

  constructor(private readonly config: RegistryBrowserAdmissionBucketConfig) {}

  admit(key: string, now: number): RegistryBrowserAdmissionDecision {
    const previous = this.entries.get(key)
    if (previous === undefined && this.entries.size >= this.config.maxEntries) {
      let replacement: string | undefined
      let retryAfterSeconds = 2 ** 31 - 1
      for (const [candidate, state] of this.entries) {
        const tokens = available(state, this.config, now)
        if (tokens === this.config.capacity) {
          replacement = candidate
          break
        }
        retryAfterSeconds = Math.min(retryAfterSeconds,
          waitFor(tokens, this.config.capacity, this.config.refillPerSecond))
      }
      if (replacement === undefined) return { admitted: false, retryAfterSeconds }
      this.entries.delete(replacement)
    }
    const state = previous ?? { tokens: this.config.capacity, at: now }
    const tokens = available(state, this.config, now)
    if (tokens < 1) return {
      admitted: false,
      retryAfterSeconds: waitFor(tokens, 1, this.config.refillPerSecond),
    }
    this.entries.set(key, { tokens: tokens - 1, at: now })
    return ADMITTED
  }
}

/** One browser API owner; reinstallation intentionally starts with full process-local buckets. */
export class RegistryBrowserAdmission {
  private readonly config: RegistryBrowserAdmissionConfig
  private readonly peers: KeyedAdmission
  private readonly accounts: KeyedAdmission
  private readonly proxy: TrustedProxyAddressResolver | undefined

  /** @param config - Fully validated explicit deployment budgets.
   * @param clock - Trusted finite monotonic milliseconds; production uses the process performance clock.
   * @param shared - Optional same-host multi-process owner; absent deployments remain process-local. */
  constructor(config: RegistryBrowserAdmissionConfig, private readonly clock: () => number = () => performance.now(),
    private readonly shared?: RegistrySharedAdmission) {
    const copied = structuredClone(config)
    this.config = copied
    this.peers = new KeyedAdmission(copied.directPeer)
    this.accounts = new KeyedAdmission(copied.account)
    this.proxy = copied.trustedProxy === undefined ? undefined : new TrustedProxyAddressResolver(copied.trustedProxy)
  }

  /** Charge one operation submission to its direct peer or safely derived forwarded client.
   * @param address - Direct socket peer; this is always authoritative outside configured proxy CIDRs.
   * @param forwarded - Complete X-Forwarded-For header supplied by Node.
   * @returns Admission result for the canonical selected IP address. */
  admitDirectPeer(address: string, forwarded?: string | string[]): RegistryBrowserAdmissionDecision {
    const selected = this.proxy?.resolve(address, forwarded) ?? parseAddress(address).toString()
    if (this.shared !== undefined) return this.shared.charge([{
      scope: 'browser-client-address', key: selected, maxEntries: this.config.directPeer.maxEntries,
      requests: { capacity: this.config.directPeer.capacity,
        refillPerSecond: this.config.directPeer.refillPerSecond, cost: 1 },
    }])
    return this.peers.admit(selected, this.clock())
  }

  /** Charge one operation submission to its authenticated organization-member tuple. */
  admitAccount(organizationId: string, memberId: string): RegistryBrowserAdmissionDecision {
    const key = JSON.stringify([organizationId, memberId])
    if (this.shared !== undefined) return this.shared.charge([{
      scope: 'browser-account', key, maxEntries: this.config.account.maxEntries,
      requests: { capacity: this.config.account.capacity,
        refillPerSecond: this.config.account.refillPerSecond, cost: 1 },
    }])
    return this.accounts.admit(key, this.clock())
  }
}
