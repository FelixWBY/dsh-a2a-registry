/** Bounded, single-flight readiness probing for public health-check callers. */
import { performance } from 'node:perf_hooks'

const DEFAULT_CACHE_TTL_MS = 1_000
const DEFAULT_TIMEOUT_MS = 2_000

interface RegistryReadinessProbeOptions {
  readonly cacheTtlMs?: number
  readonly timeoutMs?: number
  readonly now?: () => number
}

interface CachedDecision {
  readonly checkedAt: number
  readonly ready: boolean
}

/**
 * Coalesce all concurrent callers into one authoritative probe, cache both
 * outcomes briefly, and fail closed before an unhealthy dependency can hold an
 * HTTP readiness response open indefinitely. A timed-out probe remains the
 * sole in-flight dependency operation and may publish recovery when it settles.
 */
export class RegistryReadinessProbe {
  private readonly cacheTtlMs: number
  private readonly timeoutMs: number
  private readonly now: () => number
  private cached: CachedDecision | undefined
  private dependencyProbe: Promise<boolean> | undefined
  private decision: Promise<boolean> | undefined

  constructor(private readonly probe: () => boolean | Promise<boolean>,
    options: RegistryReadinessProbeOptions = {}) {
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.now = options.now ?? (() => performance.now())
    if (!Number.isSafeInteger(this.cacheTtlMs) || this.cacheTtlMs < 1 || this.cacheTtlMs > 60_000
      || !Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 60_000) {
      throw new Error('Registry readiness bounds are invalid')
    }
  }

  ready(): Promise<boolean> {
    const cached = this.cached
    const now = this.now()
    if (cached !== undefined && now >= cached.checkedAt && now - cached.checkedAt < this.cacheTtlMs) {
      return Promise.resolve(cached.ready)
    }
    if (this.decision !== undefined) return this.decision
    const dependencyProbe = this.dependencyProbe ?? this.startDependencyProbe()
    const bounded = this.withTimeout(dependencyProbe).then((ready) => {
      this.cached = { checkedAt: this.now(), ready }
      return ready
    })
    const decision = bounded.finally(() => {
      if (this.decision === decision) this.decision = undefined
    })
    this.decision = decision
    return decision
  }

  private startDependencyProbe(): Promise<boolean> {
    let running: Promise<boolean>
    running = Promise.resolve().then(this.probe).then(value => value === true, () => false).then((ready) => {
      this.cached = { checkedAt: this.now(), ready }
      return ready
    }).finally(() => {
      if (this.dependencyProbe === running) this.dependencyProbe = undefined
    })
    this.dependencyProbe = running
    return running
  }

  private withTimeout(probe: Promise<boolean>): Promise<boolean> {
    return new Promise((resolve) => {
      let settled = false
      const timer = setTimeout(() => {
        if (settled) return
        settled = true
        resolve(false)
      }, this.timeoutMs)
      timer.unref()
      void probe.then((ready) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(ready)
      })
    })
  }
}
