import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-theme/client'
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import { createSnapshotStore } from '@deepseek-ai/dsh-client-store'
import { RegistryRoot } from './RegistryRoot.tsx'
import { RegistryPage } from './RegistryPage.tsx'
import type { RegistryInjected, RegistryPageInjected } from './contract.ts'
import { parseRegistryPage } from './navigation.ts'
import { en, NS, zh } from './locales.ts'
import { createRegistryApi } from './registry-api.ts'
import { Config } from '../config.ts'

export type { RegistryRootProps, RegistryPageProps } from './contract.ts'
export { Config }
export type { Config as RegistryUiConfig } from '../config.ts'

/** Only rendering and display preferences; no Local Remote dependency. */
export const inject = ['slots', 'locale', 'theme']

/**
 * Register an independent root and lifetime-owned browser navigation.
 * @param ctx - Registry composition with real locale and theme providers.
 * @param config - Explicit browser-only presentation flags.
 */
export function apply(ctx: Context, config: Config = Config({})): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'registry: dictionaries')
  if (ctx.theme.getTheme().preference === 'system' && config.defaultTheme !== 'system') {
    ctx.theme.setTheme(config.defaultTheme)
  }
  const api = createRegistryApi()
  const readStatus: RegistryPageInjected['readStatus'] = signal => api.readStatus(signal)
  const readDirectory: RegistryPageInjected['readDirectory'] = signal => api.readDirectory(signal)
  const listInstances: RegistryPageInjected['listInstances'] = signal => api.listInstances(signal)
  const renameInstance: RegistryPageInjected['renameInstance'] = (bindingId, instanceName, signal) =>
    api.renameInstance(bindingId, instanceName, signal)
  const revokeInstance: RegistryPageInjected['revokeInstance'] = (bindingId, signal) =>
    api.revokeInstance(bindingId, signal)
  const reviewBinding: RegistryPageInjected['reviewBinding'] = (bindingId, code, signal) =>
    api.reviewBinding(bindingId, code, signal)
  const approveBinding: RegistryPageInjected['approveBinding'] = (bindingId, code, instanceName, signal) =>
    api.approveBinding(bindingId, code, instanceName, signal)
  const rejectBinding: RegistryPageInjected['rejectBinding'] = (bindingId, code, signal) =>
    api.rejectBinding(bindingId, code, signal)
  const listAudit: RegistryPageInjected['listAudit'] = (request, signal) => api.listAudit(request, signal)
  const listBranches: RegistryPageInjected['listBranches'] = (request, signal) => api.listBranches(request, signal)
  const listDisclosures: RegistryPageInjected['listDisclosures'] = (request, signal) => api.listDisclosures(request, signal)
  const readDisclosure: RegistryPageInjected['readDisclosure'] = (disclosureId, signal) => api.readDisclosure(disclosureId, signal)
  const readDisclosureContent: RegistryPageInjected['readDisclosureContent'] = (disclosureId, checkpointHash, signal) =>
    api.readDisclosureContent(disclosureId, checkpointHash, signal)
  const listImportTargets: RegistryPageInjected['listImportTargets'] = (disclosureId, signal) => api.listImportTargets(disclosureId, signal)
  const importDisclosure: RegistryPageInjected['importDisclosure'] = (disclosureId, request, signal) => api.importDisclosure(disclosureId, request, signal)
  const readImport: RegistryPageInjected['readImport'] = (disclosureId, operationId, signal) => api.readImport(disclosureId, operationId, signal)
  const askDisclosure: RegistryPageInjected['askDisclosure'] = (disclosureId, request, signal) => api.askDisclosure(disclosureId, request, signal)
  const readQuestion: RegistryPageInjected['readQuestion'] = (disclosureId, requestId, signal) => api.readQuestion(disclosureId, requestId, signal)
  const cancelQuestion: RegistryPageInjected['cancelQuestion'] = (disclosureId, requestId, signal) => api.cancelQuestion(disclosureId, requestId, signal)
  const page = createSnapshotStore(parseRegistryPage(typeof window === 'undefined' ? '' : window.location.hash))
  const theme = createSnapshotStore(ctx.theme.getTheme())
  ctx.on('theme/change', (snapshot) => { theme.set(snapshot) })
  if (typeof window !== 'undefined') {
    ctx.effect(() => {
      const sync = (): void => { page.set(parseRegistryPage(window.location.hash)) }
      window.addEventListener('hashchange', sync)
      return () => { window.removeEventListener('hashchange', sync) }
    }, 'registry: browser route')
  }
  ctx.slots.register({
    name: 'root', locale: NS,
    children: { 'registry.page': { kind: 'single', scope: 'root' } },
    inject: (): RegistryInjected => ({
      hooks: { page, locale: ctx.locale },
      setLocale: (id) => { ctx.locale.setLocale(id) },
      localTestIdentityBanner: config.localTestIdentityBanner,
    }),
  }, RegistryRoot)
  ctx.slots.register({
    name: 'registry.page', locale: NS,
    inject: (): RegistryPageInjected => ({
      hooks: { theme },
      setTheme: (preference) => { ctx.theme.setTheme(preference) },
      localTestIdentityBanner: config.localTestIdentityBanner,
      readStatus,
      readDirectory,
      listInstances,
      renameInstance,
      revokeInstance,
      reviewBinding,
      approveBinding,
      rejectBinding,
      listAudit,
      listBranches,
      listDisclosures,
      readDisclosure,
      readDisclosureContent,
      listImportTargets,
      importDisclosure,
      readImport,
      askDisclosure,
      readQuestion,
      cancelQuestion,
    }),
  }, RegistryPage)
  if (typeof document !== 'undefined') ctx.effect(() => ctx.theme.present(), 'registry: theme presenter')
}
