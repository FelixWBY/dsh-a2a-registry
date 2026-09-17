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
  const readAccount: RegistryPageInjected['readAccount'] = signal => api.readAccount(signal)
  const createOrganization: RegistryPageInjected['createOrganization'] = (request, signal) =>
    api.createOrganization(request, signal)
  const readDirectory: RegistryPageInjected['readDirectory'] = (organizationId, signal) =>
    api.readDirectory(organizationId, signal)
  const changeDirectory: RegistryPageInjected['changeDirectory'] = (organizationId, expectedRevision, change, signal) =>
    api.changeDirectory(organizationId, expectedRevision, change, signal)
  const listInvitations: RegistryPageInjected['listInvitations'] = (organizationId, signal) =>
    api.listInvitations(organizationId, signal)
  const createInvitation: RegistryPageInjected['createInvitation'] = (organizationId, request, signal) =>
    api.createInvitation(organizationId, request, signal)
  const revokeInvitation: RegistryPageInjected['revokeInvitation'] = (organizationId, invitationId, signal) =>
    api.revokeInvitation(organizationId, invitationId, signal)
  const readInvitation: RegistryPageInjected['readInvitation'] = (token, signal) => api.readInvitation(token, signal)
  const acceptInvitation: RegistryPageInjected['acceptInvitation'] = (token, signal) => api.acceptInvitation(token, signal)
  const declineInvitation: RegistryPageInjected['declineInvitation'] = (token, signal) => api.declineInvitation(token, signal)
  const listBillingPlans: RegistryPageInjected['listBillingPlans'] = (organizationId, signal) =>
    api.listBillingPlans(organizationId, signal)
  const listBillingOrders: RegistryPageInjected['listBillingOrders'] = (organizationId, signal) =>
    api.listBillingOrders(organizationId, signal)
  const createBillingCheckout: RegistryPageInjected['createBillingCheckout'] = (organizationId, request, signal) =>
    api.createBillingCheckout(organizationId, request, signal)
  const listInstances: RegistryPageInjected['listInstances'] = (organizationId, signal) =>
    api.listInstances(organizationId, signal)
  const renameInstance: RegistryPageInjected['renameInstance'] = (organizationId, bindingId, instanceName, signal) =>
    api.renameInstance(organizationId, bindingId, instanceName, signal)
  const revokeInstance: RegistryPageInjected['revokeInstance'] = (organizationId, bindingId, signal) =>
    api.revokeInstance(organizationId, bindingId, signal)
  const reviewBinding: RegistryPageInjected['reviewBinding'] = (organizationId, bindingId, code, signal) =>
    api.reviewBinding(organizationId, bindingId, code, signal)
  const approveBinding: RegistryPageInjected['approveBinding'] = (organizationId, bindingId, code, instanceName, signal) =>
    api.approveBinding(organizationId, bindingId, code, instanceName, signal)
  const rejectBinding: RegistryPageInjected['rejectBinding'] = (organizationId, bindingId, code, signal) =>
    api.rejectBinding(organizationId, bindingId, code, signal)
  const listAudit: RegistryPageInjected['listAudit'] = (organizationId, request, signal) =>
    api.listAudit(organizationId, request, signal)
  const listBranches: RegistryPageInjected['listBranches'] = (organizationId, request, signal) =>
    api.listBranches(organizationId, request, signal)
  const listDisclosures: RegistryPageInjected['listDisclosures'] = (organizationId, request, signal) =>
    api.listDisclosures(organizationId, request, signal)
  const readDisclosure: RegistryPageInjected['readDisclosure'] = (organizationId, disclosureId, signal) =>
    api.readDisclosure(organizationId, disclosureId, signal)
  const readDisclosureContent: RegistryPageInjected['readDisclosureContent'] =
    (organizationId, disclosureId, checkpointHash, signal) =>
      api.readDisclosureContent(organizationId, disclosureId, checkpointHash, signal)
  const listImportTargets: RegistryPageInjected['listImportTargets'] = (organizationId, disclosureId, signal) =>
    api.listImportTargets(organizationId, disclosureId, signal)
  const importDisclosure: RegistryPageInjected['importDisclosure'] = (organizationId, disclosureId, request, signal) =>
    api.importDisclosure(organizationId, disclosureId, request, signal)
  const readImport: RegistryPageInjected['readImport'] = (organizationId, disclosureId, operationId, signal) =>
    api.readImport(organizationId, disclosureId, operationId, signal)
  const askDisclosure: RegistryPageInjected['askDisclosure'] = (organizationId, disclosureId, request, signal) =>
    api.askDisclosure(organizationId, disclosureId, request, signal)
  const readQuestion: RegistryPageInjected['readQuestion'] = (organizationId, disclosureId, requestId, signal) =>
    api.readQuestion(organizationId, disclosureId, requestId, signal)
  const cancelQuestion: RegistryPageInjected['cancelQuestion'] = (organizationId, disclosureId, requestId, signal) =>
    api.cancelQuestion(organizationId, disclosureId, requestId, signal)
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
      readAccount: signal => api.readAccount(signal),
    }),
  }, RegistryRoot)
  ctx.slots.register({
    name: 'registry.page', locale: NS,
    inject: (): RegistryPageInjected => ({
      hooks: { theme },
      setTheme: (preference) => { ctx.theme.setTheme(preference) },
      localTestIdentityBanner: config.localTestIdentityBanner,
      readStatus,
      readAccount,
      createOrganization,
      readDirectory,
      changeDirectory,
      listInvitations,
      createInvitation,
      revokeInvitation,
      readInvitation,
      acceptInvitation,
      declineInvitation,
      listBillingPlans,
      listBillingOrders,
      createBillingCheckout,
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
