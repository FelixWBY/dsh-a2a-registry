/** Ephemeral authenticated connection observations and producer reports, not derived availability or historical presence. */
import type { DshInstanceId } from '@deepseek-ai/dsh-a2a-protocol'
import type { RegistryInstanceReport } from '@deepseek-ai/dsh-a2a-registry-sync'

/** Only currently observed authenticated connections are represented; absence does not prove the device is offline. */
export type RegistryTransportObservation =
  | { readonly kind: 'not-observed' }
  | { readonly kind: 'connected'; readonly lastHeartbeatAt: number | null; readonly report?: RegistryInstanceReport }

interface Entry {
  readonly instanceId: DshInstanceId
  heartbeat: number | null
  report: RegistryInstanceReport | undefined
  readonly close: () => void
}

/** Runtime-local observations bounded by the endpoint's admitted connection lifetimes. */
export class RegistryTransportObservations {
  private readonly entries = new Set<Entry>()

  /** Track one successfully authenticated connection until its signal aborts or the owner clears it.
   * @param instanceId - Instance selected by verified connection authority, within the runtime's fixed organization.
   * @param signal - Connection lifetime; an already aborted signal creates no observation.
   * @returns Heartbeat recorder; older timestamps are ignored and an omitted report clears the previous report.
   * After closure the recorder cannot resurrect or update any connection. */
  connect(instanceId: DshInstanceId, signal: AbortSignal): (observedAt: number, report?: RegistryInstanceReport) => void {
    const entry: Entry = { instanceId, heartbeat: null, report: undefined, close: () => {
      this.entries.delete(entry)
      signal.removeEventListener('abort', entry.close)
    } }
    if (!signal.aborted) {
      this.entries.add(entry)
      signal.addEventListener('abort', entry.close, { once: true })
    }
    return (observedAt, report) => {
      if (this.entries.has(entry) && (entry.heartbeat === null || observedAt >= entry.heartbeat)) {
        entry.heartbeat = observedAt
        entry.report = report === undefined ? undefined : { ...report }
      }
    }
  }

  /** Read only currently tracked connections; callers must establish account authorization separately.
   * @param instanceId - Authorized instance selection, not a credential.
   * @returns Detached transport observation with the latest confirmed heartbeat among live connections.
   * The report belongs to that heartbeat; equal timestamps select the later registered connection.
   * Null means no confirmed heartbeat on those connections; no historical observation survives their closure. */
  read(instanceId: DshInstanceId): RegistryTransportObservation {
    const entries = [...this.entries].filter(entry => entry.instanceId === instanceId)
    if (entries.length === 0) return { kind: 'not-observed' }
    let lastHeartbeatAt: number | null = null
    let report: RegistryInstanceReport | undefined
    for (const entry of entries) {
      if (entry.heartbeat !== null && (lastHeartbeatAt === null || entry.heartbeat >= lastHeartbeatAt)) {
        lastHeartbeatAt = entry.heartbeat
        report = entry.report
      }
    }
    return { kind: 'connected', lastHeartbeatAt, ...(report === undefined ? {} : { report: { ...report } }) }
  }

  /** Remove observations and lifetime listeners before the runtime owner is released. */
  clear(): void {
    for (const entry of this.entries) entry.close()
  }
}
