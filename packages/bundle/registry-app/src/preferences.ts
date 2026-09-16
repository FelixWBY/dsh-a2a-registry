/** Lifecycle-owned public configuration for the Registry's two browser preferences. */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-modules'

const TARGETS = ['@deepseek-ai/dsh-client-locale', '@deepseek-ai/dsh-client-ui-theme'] as const

interface Contribution {
  dispose: () => void
  /** Stable frozen snapshot published by this exact registration, not a copied business value. */
  config: object
}

/** Contribute session-only preferences whenever the exact current browser targets exist.
 * @param ctx - The runtime fiber owning these explicit public contributions.
 * @param onChanged - Rechecks presentation readiness after a successful reconciliation.
 * @returns A live gate over the current graph and owned contribution identities.
 */
export function installRegistryPreferences(ctx: Context, onChanged: () => void): () => boolean {
  const contributions = new Map<string, Contribution>()
  let checking = false
  let active = true
  const reconcile = (): void => {
    // register/dispose synchronously notify the same graph listeners.
    if (checking || !active) return
    checking = true
    try {
      const entries = ctx.clientModules.graph().entries
      for (const [id, owner] of contributions) {
        if (entries.find(row => row.id === id)?.config === owner.config) continue
        contributions.delete(id)
        owner.dispose()
      }
      for (const id of TARGETS) {
        if (contributions.has(id) || !entries.some(row => row.id === id)) continue
        const dispose = ctx.clientModules.registerClientConfig(id, { preferenceSource: 'session' })
        // Registration synchronously publishes its frozen snapshot before returning.
        const config = ctx.clientModules.graph().entries.find(row => row.id === id)?.config
        if (config === undefined) {
          dispose()
          throw new Error('registry-app: preference registration did not publish its configuration')
        }
        contributions.set(id, { dispose, config })
      }
      onChanged()
    } finally {
      checking = false
    }
  }
  ctx.effect(() => {
    const unsubscribe = ctx.clientModules.onGraphChanged(reconcile)
    return () => {
      active = false
      unsubscribe()
      for (const owner of contributions.values()) owner.dispose()
      contributions.clear()
    }
  }, 'registry-app: public preference contributions')
  // Subscribe before checking: rows may appear after the module service activates.
  reconcile()
  return () => TARGETS.every((id) => {
    const owner = contributions.get(id)
    return owner !== undefined && ctx.clientModules.graph().entries.find(row => row.id === id)?.config === owner.config
  })
}
