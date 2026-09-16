/** Host half: publishes presentation-only flags, with no session or business access. */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-modules'
import { Config } from './config.ts'

export { Config }
export type { Config as RegistryUiConfig } from './config.ts'

const PACKAGE_ID = '@deepseek-ai/dsh-client-ui-registry'

/** The module host is the sole explicit bridge from Host configuration to the browser boot graph. */
export const inject = ['clientModules']

/** Publish the validated presentation flags when this package's browser row becomes available. */
export function apply(ctx: Context, config: Config = Config({})): void {
  let contribution: { readonly dispose: () => void; readonly config: object } | undefined
  let reconciling = false
  let active = true
  const reconcile = (): void => {
    if (!active || reconciling) return
    reconciling = true
    try {
      const current = ctx.clientModules.graph().entries.find(row => row.id === PACKAGE_ID)
      if (contribution !== undefined && current?.config !== contribution.config) {
        const stale = contribution
        contribution = undefined
        stale.dispose()
      }
      if (contribution !== undefined) return
      if (!ctx.clientModules.graph().entries.some(row => row.id === PACKAGE_ID)) return
      const dispose = ctx.clientModules.registerClientConfig(PACKAGE_ID, {
        localTestIdentityBanner: config.localTestIdentityBanner,
        defaultTheme: config.defaultTheme,
      })
      const published = ctx.clientModules.graph().entries.find(row => row.id === PACKAGE_ID)?.config
      if (published === undefined) {
        dispose()
        throw new Error('ui-registry: public presentation configuration was not published')
      }
      contribution = { dispose, config: published }
    } finally {
      reconciling = false
    }
  }
  ctx.effect(() => {
    const unsubscribe = ctx.clientModules.onGraphChanged(reconcile)
    reconcile()
    return () => {
      active = false
      unsubscribe()
      const owned = contribution
      contribution = undefined
      owned?.dispose()
    }
  }, 'ui-registry: public presentation configuration')
}
