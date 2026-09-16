/** Opt-in Registry deletion scheduling; the ingest owner retains all record and authorization decisions. */
import { setTimeout as delay } from 'node:timers/promises'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import { RegistryIngestError } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryRuntimeStore } from './runtime-store.ts'

/** Explicit maintenance scheduling bounds; organization ownership is supplied by the shared runtime. */
export interface MaintenanceConfig {
  /** Positive delay after each round or recoverable storage failure, at most 2^31-1 milliseconds. */
  intervalMs: number
  /** Maximum deletions per round. */
  maxItems: number
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
/** Complete opt-in configuration; omitted fields do not choose deployment defaults. */
export const Config: z<MaintenanceConfig> = z.object({
  intervalMs: positive().max(2 ** 31 - 1),
  maxItems: positive(),
})

/** Run nonoverlapping organization sweeps through the runtime's shared ingest owner.
 * @param ctx - Private logging context; no account or device authority is manufactured.
 * @param organizationId - Immutable physical-domain organization from the shared runtime configuration.
 * @param config - Validated maintenance scheduling bounds.
 * @param store - Shared runtime handle; this consumer never opens, closes or retains its underlying domain.
 * @param signal - Stops admission and waits for an already-started record update.
 * @returns Worker settlement; deterministic errors stop the worker with a content-free diagnostic. */
export async function runRegistryMaintenance(ctx: Context, organizationId: OrganizationId, config: MaintenanceConfig,
  store: RegistryRuntimeStore, signal: AbortSignal): Promise<void> {
  const options = structuredClone(config)
  const report = (code: string): void => {
    ctx.logger.error('Registry maintenance stopped or deferred: %s', code)
  }
  while (store.active()) {
    try {
      const now = Date.now()
      for (let count = 0; count < options.maxItems; count++) {
        if (!store.active()) return
        const receipt = await store.run(ingest => ingest.processDeletionBatch({ organizationId, now, maxItems: 1, signal }))
        if (!receipt.hasMore) break
      }
    } catch (error) {
      if (!store.active() && error instanceof RegistryIngestError && error.code === 'closed') return
      const code = error instanceof RegistryIngestError ? error.code : 'unexpected-failure'
      report(code)
      if (code !== 'storage-unavailable') return
    }
    if (!store.active()) return
    await delay(options.intervalMs, undefined, { signal }).catch(() => {
      // Fixed validated timer arguments leave only AbortError from the owned cancellation signal.
    })
  }
}
