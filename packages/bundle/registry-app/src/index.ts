/** Independent Registry application bundle with optional deployment-configured OIDC account authentication. */
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/cordis-plugin-loader'
import type {} from '@deepseek-ai/dsh-client-modules'
import type {} from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { installRegistryStatic } from './static.ts'
import { installRegistryPreferences } from './preferences.ts'
import { Config as BrowserApiSchema, installRegistryBrowserApi, type RegistryBrowserApiConfig } from './browser-api.ts'
import * as ingestRuntime from './ingest-runtime.ts'
import type { RegistryIngestRuntimeConfig } from './ingest-runtime.ts'
import * as mailboxMaintenance from './mailbox-maintenance.ts'
import type { RegistryMailboxMaintenanceConfig } from './mailbox-maintenance.ts'
import * as localHarnessOperations from './local-harness-operations.ts'
import type { LocalHarnessOperationsConfig } from './local-harness-operations.ts'
import { RegistrySharedAdmission, RegistrySharedAdmissionConfigSchema,
  type RegistrySharedAdmissionConfig } from './shared-admission-sqlite.ts'
import { RegistryOidcAccountAuthenticator, RegistryOidcAccountAuthConfigSchema,
  type RegistryOidcAccountAuthConfig } from './oidc-account-auth.ts'
export type { RegistryDisclosureControl } from './control.ts'
export type { RegistryDirectory } from './directory.ts'
export type { RegistryEnrollment } from './enrollment.ts'
export { RegistryAccountAuthenticator, type RegistryAuthenticatedAccount } from './account-auth.ts'
export { RegistryBillingProvider } from './billing.ts'
export type { RegistryBillingCheckout, RegistryBillingCheckoutInput, RegistryBillingPlan,
  RegistryBillingProviderName } from './billing.ts'
export { RegistryOidcAccountAuthenticator, RegistryOidcAccountAuthConfigSchema } from './oidc-account-auth.ts'
export type { RegistryOidcAccountAuthConfig } from './oidc-account-auth.ts'
export type { RegistryAuthorizedPrefixSnapshot, RegistryDisclosureReader,
  RegistryReceiveBindingRequirement } from './reader.ts'
export type { FreshRegistryAuditAuthority, RegistryAuditActorKind, RegistryAuditListOptions,
  RegistryAuditMetadata, RegistryAuditPage, RegistryAuditReader, RegistryAuditResult } from './audit-reader.ts'
export type { RegistryDisclosureOperations, RegistryDisclosureOperationSelection, RegistryDisclosureImportInput,
  RegistryDisclosureImportResult, RegistryDisclosureImportStatus, RegistryDisclosureImportTarget,
  RegistryDisclosureContent, RegistryDisclosureContentEvent,
  RegistryDisclosureQuestionInput, RegistryDisclosureQuestionResult,
  RegistryDisclosureQuestionStatus, RegistryImportOperationId, RegistryImportedSessionId } from './operations.ts'
export type { RegistryBrowserApiConfig } from './browser-api.ts'
export type { RegistryBrowserAdmissionBucketConfig, RegistryBrowserAdmissionConfig,
  RegistryBrowserTrustedProxyConfig } from './browser-admission.ts'
export { RegistrySharedAdmission, RegistrySharedAdmissionConfigSchema,
  RegistrySharedAdmissionError } from './shared-admission-sqlite.ts'
export type { RegistrySharedAdmissionAuditConfig, RegistrySharedAdmissionAuditReason,
  RegistrySharedAdmissionAuditRecord, RegistrySharedAdmissionCharge, RegistrySharedAdmissionConfig,
  RegistrySharedAdmissionDecision, RegistrySharedAdmissionDimension } from './shared-admission-sqlite.ts'
export { RegistryOperationalAlertExporter, RegistryOperationalAlertsConfigSchema,
  operationalAlertFromAudit } from './operational-alerts.ts'
export type { RegistryOperationalAlert, RegistryOperationalAlertCategory,
  RegistryOperationalAlertReporter, RegistryOperationalAlertsConfig,
  RegistryOperationalRateLimitScope } from './operational-alerts.ts'
export { RegistryOperationalAlertOutbox, RegistryOperationalAlertOutboxConfigSchema,
  RegistryOperationalAlertOutboxError } from './operational-alert-outbox-sqlite.ts'
export type { RegistryOperationalAlertClaim, RegistryOperationalAlertOutboxConfig,
  RegistryOperationalAlertOutboxPolicy } from './operational-alert-outbox-sqlite.ts'
export { LocalHarnessOperations } from './local-harness-operations.ts'
export type { LocalHarnessOperationsConfig } from './local-harness-operations.ts'
export { A2A_LOOPBACK_QUESTIONS_PATH, LocalHarnessQuestionOperations } from './local-harness-question-operations.ts'
export type { LocalHarnessQuestionOperationsConfig } from './local-harness-question-operations.ts'
export { A2A_LOOPBACK_DISCLOSURES_PATH, A2A_LOOPBACK_DISCLOSURE_KEYS_PATH,
  A2A_LOOPBACK_DISCLOSURE_STATUS_PATH,
  A2A_LOOPBACK_DISCLOSURE_CONTROL_PATH,
  LocalHarnessDisclosureRegistration } from './local-harness-disclosure-registration.ts'
export type { LocalHarnessDisclosureRegistrationConfig } from './local-harness-disclosure-registration.ts'
export { A2A_LOOPBACK_DISCLOSURE_REFRESH_PATH,
  LocalHarnessDisclosureRefresh } from './local-harness-disclosure-refresh.ts'
export type { LocalHarnessDisclosureRefreshConfig } from './local-harness-disclosure-refresh.ts'

/** Stable Cordis runtime plugin name. */
export const name = 'registry-app'
/** The profile Loader and HTTP service own readiness and disposal. */
export const inject = ['webServer', 'loader', 'clientModules']

/** Registry runtime presentation configuration. Network binding belongs to the webserver row. */
export interface Config {
  /** Print the clean loopback URL after the profile has settled. */
  printUrl: boolean
  /** Same-origin metadata API limits; identity and durable ingest remain separate required providers. */
  api?: RegistryBrowserApiConfig
  /** Optional standards-based browser identity; current membership remains owned by ingest.directory. */
  oidc?: RegistryOidcAccountAuthConfig
  /** Optional dedicated same-host SQLite owner shared by browser and producer-sync admission. */
  sharedAdmission?: RegistrySharedAdmissionConfig
  /** Requires storageDomain; sync additionally requires registryProducerAuthenticator. Both remain opt-in. */
  ingest?: RegistryIngestRuntimeConfig
  /** Requires storageDomain and opens only a Registry-side mailbox cleanup owner. */
  mailboxMaintenance?: RegistryMailboxMaintenanceConfig
  /** Explicit signed loopback import bridge; requires storageDomain, credentials, enrollment and the browser API. */
  localHarness?: LocalHarnessOperationsConfig
}
const schema: z<Config> = z.object({
  printUrl: z.boolean().default(true),
  api: z.union([BrowserApiSchema]),
  oidc: z.union([RegistryOidcAccountAuthConfigSchema]),
  sharedAdmission: z.union([RegistrySharedAdmissionConfigSchema]),
  ingest: z.union([ingestRuntime.Config]),
  mailboxMaintenance: z.union([mailboxMaintenance.Config]),
  localHarness: z.union([localHarnessOperations.Config]),
})
export const Config: z<Config> = z.transform(schema, (value) => {
  if (value.ingest !== undefined && value.mailboxMaintenance !== undefined
    && value.ingest.organizationId !== value.mailboxMaintenance.organizationId) {
    throw new z.ValidationError('Registry storage owners require one organization', {})
  }
  if (value.localHarness !== undefined && (value.ingest === undefined || value.api === undefined)) {
    throw new z.ValidationError('Registry Local Harness operations require ingest and api configuration', {})
  }
  if (value.localHarness !== undefined && value.ingest?.bindings === undefined) {
    throw new z.ValidationError('Registry Local Harness operations require ingest.bindings configuration', {})
  }
  if (value.oidc !== undefined && (value.api === undefined || value.ingest?.directory === undefined)) {
    throw new z.ValidationError('Registry OIDC requires api and ingest.directory configuration', {})
  }
  if (value.oidc !== undefined && value.oidc.organizationId !== value.ingest?.organizationId) {
    throw new z.ValidationError('Registry OIDC requires the ingest organization', {})
  }
  if (value.oidc !== undefined && value.localHarness?.testOnlyRevoke !== undefined) {
    throw new z.ValidationError('Registry OIDC cannot own the test-only seed withdrawal identity', {})
  }
  if (value.localHarness?.question !== undefined
    && value.localHarness.question.organizationId !== value.ingest?.organizationId) {
    throw new z.ValidationError('Registry Local Harness question owner requires the ingest organization', {})
  }
  if (value.localHarness?.registration !== undefined
    && value.localHarness.registration.organizationId !== value.ingest?.organizationId) {
    throw new z.ValidationError('Registry Local Harness registration owner requires the ingest organization', {})
  }
  if (value.localHarness?.refresh !== undefined
    && value.localHarness.refresh.organizationId !== value.ingest?.organizationId) {
    throw new z.ValidationError('Registry Local Harness refresh owner requires the ingest organization', {})
  }
  if (value.localHarness?.refresh !== undefined
    && value.localHarness.refresh.targetInstanceId !== value.localHarness.targetInstanceId) {
    throw new z.ValidationError('Registry Local Harness refresh requires the import target instance', {})
  }
  if (value.localHarness?.question !== undefined && value.mailboxMaintenance !== undefined) {
    throw new z.ValidationError('Registry Local Harness questions and mailbox maintenance cannot own the same mailbox', {})
  }
  return value
})

/** Mount the fixed public frontend and publish a clean URL only after Loader readiness.
 * @param ctx - The independent Registry profile context.
 * @param config - Validated runtime presentation configuration.
 * @returns Startup after any configured durable Registry owner has initialized.
 */
export async function apply(ctx: Context, config: Config): Promise<void> {
  if (config.sharedAdmission !== undefined) {
    if (ctx.get('credentials') === undefined) {
      throw new Error('Registry shared admission requires registry-runtime inject: [credentials]')
    }
    const sharedAdmission = await RegistrySharedAdmission.open(ctx, config.sharedAdmission)
    const withdraw = ctx.provide('registrySharedAdmission', sharedAdmission)
    ctx.effect(() => async () => {
      await Promise.resolve().then(withdraw)
      sharedAdmission.close()
    }, 'registry-app: shared admission database lifetime')
  }
  if (config.ingest !== undefined || config.mailboxMaintenance !== undefined || config.localHarness !== undefined) {
    if (ctx.get('storageDomain') === undefined) {
      const owner = config.mailboxMaintenance === undefined ? 'ingest' : 'mailbox maintenance'
      throw new Error(`Registry ${owner} requires registry-runtime inject: [storageDomain] and configured storage providers`)
    }
  }
  if (config.ingest !== undefined) {
    if (config.ingest.sync !== undefined && ctx.get('registryProducerAuthenticator') === undefined) {
      throw new Error('Registry sync requires registry-runtime inject: [storageDomain, registryProducerAuthenticator]')
    }
    if (config.ingest.sync !== undefined && ctx.webServer.host !== '127.0.0.1') {
      throw new Error('Registry sync TLS proxy requires a 127.0.0.1 HTTP listener')
    }
    await ctx.plugin(ingestRuntime, config.ingest)
  }
  if (config.oidc !== undefined) {
    if (ctx.get('credentials') === undefined) {
      throw new Error('Registry OIDC requires registry-runtime inject: [credentials]')
    }
    if (ctx.get('registryAccountAuthenticator') !== undefined) {
      throw new Error('Registry OIDC cannot replace another account authenticator')
    }
    new RegistryOidcAccountAuthenticator(ctx, structuredClone(config.oidc))
  }
  if (config.mailboxMaintenance !== undefined) {
    await ctx.plugin(mailboxMaintenance, config.mailboxMaintenance)
  }
  if (config.localHarness !== undefined) {
    if (ctx.get('credentials') === undefined) {
      throw new Error('Registry Local Harness operations require registry-runtime inject: [storageDomain, credentials]')
    }
    if (config.localHarness.testOnlyRevoke !== undefined
      && (ctx.get('registryAccountAuthenticator') === undefined || ctx.get('registryDisclosureControl') === undefined)) {
      throw new Error('Registry Local Harness test withdrawal requires account identity and disclosure control')
    }
    await ctx.plugin(localHarnessOperations, config.localHarness)
  }
  if (config.api !== undefined) {
    const api = structuredClone(config.api)
    ctx.effect(() => installRegistryBrowserApi(ctx, api, {
      deploymentMode: config.localHarness?.testOnlyRevoke === undefined ? 'standard' : 'test-only',
      identityProvider: config.oidc === undefined
        ? (config.localHarness?.testOnlyRevoke === undefined ? 'external' : 'local-test')
        : 'oidc',
      disclosureCleanup: config.ingest?.maintenance !== undefined,
      mailboxCleanup: config.mailboxMaintenance !== undefined
        || config.localHarness?.question?.expiryMaintenance !== undefined,
      ...(config.localHarness?.testOnlyRevoke === undefined
        ? {} : { testOnlyRevoke: structuredClone(config.localHarness.testOnlyRevoke) }),
    }), 'registry-app: browser metadata API')
  }
  const require = createRequire(import.meta.url)
  const distIndex = join(dirname(require.resolve('@deepseek-ai/dsh-web-frontend/package.json')), 'dist', 'index.html')
  let active = true
  let loaderReady = false
  let announced = false
  const announce = (): void => {
    if (!active || !config.printUrl || !loaderReady || !preferences() || announced) return
    announced = true
    console.log(`dsh registry: http://127.0.0.1:${String(ctx.webServer.port)}/`)
  }
  ctx.effect(() => () => { active = false }, 'registry-app: readiness lifetime')
  const preferences = installRegistryPreferences(ctx, announce)
  installRegistryStatic(ctx, distIndex, preferences)
  void ctx.loader.await().then(() => {
    loaderReady = true
    announce()
  }, () => {
    // The Loader reports failed initialization; this runtime publishes no ready URL.
  })
}
