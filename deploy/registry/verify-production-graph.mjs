#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { realpathSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { composeEntries, loadOverlayPatches } from '@deepseek-ai/dsh-app-boot'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const BUNDLE_PATCH = resolve(ROOT, 'packages/bundle/registry-app/cordis.patch.yml')
const CREDENTIALS_PROVIDER = '@deepseek-ai/dsh-credentials-local'
const DISCLOSURE_CONTENT_PROVIDER_ENTRY = 'registry-disclosure-content-provider'
const DISCLOSURE_CONTENT_PROVIDER_SERVICE = 'registryDisclosureContentProvider'
const DISCLOSURE_KEY_PROVIDER_ENTRY = 'registry-disclosure-key-provider'
const DISCLOSURE_KEY_PROVIDER_NAME = '@deepseek-ai/dsh-registry-kms-software-app'
const DISCLOSURE_KEY_PROVIDER_SERVICE = 'registryDisclosureKeyProvider'
const BILLING_PROVIDER_ENTRY = 'registry-billing-provider'
const BILLING_PROVIDER_SERVICE = 'registryBillingProvider'
const TEST_CONFIGURATION_VALUES = new Set(['test-only', 'local-test', 'loopback-development'])
const TEST_ENTRY = /(?:^|[/@_.-])(?:test|mock|fixture)(?:$|[/@_.-])|(?:^|[/@_.-])local-(?:oidc|harness)(?:$|[/@_.-])/iu

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : undefined
}

function activeEntries(entries, issues, output = []) {
  for (const entry of entries) {
    const selected = record(entry)
    if (selected === undefined) continue
    if (selected.disabled === true) continue
    if (selected.disabled !== undefined && selected.disabled !== false && selected.disabled !== null) {
      issues.push(`entry ${String(selected.id ?? '<unknown>')}.disabled must be a literal boolean`)
    }
    output.push(selected)
    if (selected.group === true && Array.isArray(selected.config)) activeEntries(selected.config, issues, output)
  }
  return output
}

function containsTestConfiguration(value, seen = new WeakSet()) {
  if (typeof value === 'string') return TEST_CONFIGURATION_VALUES.has(value)
  if (value === null || typeof value !== 'object') return false
  if (seen.has(value)) return false
  seen.add(value)
  if (Array.isArray(value)) return value.some(entry => containsTestConfiguration(entry, seen))
  return Object.values(value).some(entry => containsTestConfiguration(entry, seen))
}

function selectedEntry(entries, id, name, issues) {
  const matches = entries.filter(entry => entry.id === id)
  if (matches.length !== 1) {
    issues.push(`${id} must have exactly one active entry`)
    return undefined
  }
  const [entry] = matches
  if (entry.name !== name) issues.push(`${id} must use ${name}`)
  const providers = entries.filter(candidate => candidate.name === name)
  if (providers.length !== 1 || providers[0] !== entry) {
    issues.push(`${name} must have exactly one active entry with id ${id}`)
  }
  return entry
}

function objectConfig(entry, label, issues) {
  const config = record(entry?.config)
  if (config === undefined) issues.push(`${label} must have a mapping config`)
  return config
}

function requiredRecord(value, label, issues) {
  const selected = record(value)
  if (selected === undefined) issues.push(`${label} must be configured`)
  return selected
}

function isExactExpression(value, source) {
  const selected = record(value)
  return selected !== undefined && Object.keys(selected).length === 1 && selected.__jsExpr === source
}

function unsafeSharedDatabase(value, label, issues) {
  if (value !== undefined && value !== false) {
    issues.push(`${label}.allowUnsafeSharedDatabase must be false or omitted`)
  }
}

/** Return every fail-closed production invariant violated by one already-composed entry graph. */
export function productionGraphIssues(composedEntries, composeWarnings = []) {
  const issues = composeWarnings.map(message => `configuration patch did not apply cleanly: ${message}`)
  const entries = activeEntries(composedEntries, issues)

  const credentials = entries.filter(entry => entry.name === CREDENTIALS_PROVIDER)
  if (credentials.length !== 1) {
    issues.push(`exactly one ${CREDENTIALS_PROVIDER} provider is required`)
  } else {
    const config = objectConfig(credentials[0], 'production credentials provider', issues)
    if (config?.environmentOnly !== true) {
      issues.push('production credentials provider must set environmentOnly: true')
    }
  }
  const otherCredentials = entries.filter(entry => entry.name !== CREDENTIALS_PROVIDER
    && typeof entry.name === 'string' && entry.name.toLowerCase().includes('credentials'))
  if (otherCredentials.length > 0) {
    issues.push(`unapproved credentials providers are active: ${otherCredentials.map(entry => entry.id).join(', ')}`)
  }

  const webserver = selectedEntry(entries, 'registry-webserver', '@deepseek-ai/dsh-host-webserver', issues)
  const webConfig = objectConfig(webserver, 'registry-webserver', issues)
  if (webConfig?.host !== '127.0.0.1') issues.push('registry-webserver.host must be 127.0.0.1')

  const domain = selectedEntry(entries, 'registry-storage-domain', '@deepseek-ai/dsh-storage-domain', issues)
  const domainConfig = objectConfig(domain, 'registry-storage-domain', issues)
  if (domainConfig?.backend !== 'postgres') issues.push('registry-storage-domain.backend must be postgres')
  const routes = domainConfig?.routes
  if (routes !== undefined) {
    const routeMap = record(routes)
    if (routeMap === undefined || Object.values(routeMap).some(value => value !== 'postgres')) {
      issues.push('every registry-storage-domain route must use postgres')
    }
  }

  const postgres = selectedEntry(entries, 'registry-storage-postgres', '@deepseek-ai/dsh-storage-postgres', issues)
  const postgresConfig = objectConfig(postgres, 'registry-storage-postgres', issues)
  if (postgresConfig?.schemaMode !== 'validate') {
    issues.push('registry-storage-postgres.schemaMode must be validate')
  }
  if (!isExactExpression(postgresConfig?.connectionString, 'process.env.DSH_REGISTRY_POSTGRES_URL')) {
    issues.push('registry-storage-postgres.connectionString must use DSH_REGISTRY_POSTGRES_URL')
  }
  unsafeSharedDatabase(postgresConfig?.allowUnsafeSharedDatabase, 'registry-storage-postgres', issues)

  const runtime = selectedEntry(entries, 'registry-runtime', '@deepseek-ai/dsh-registry-app', issues)
  const runtimeConfig = objectConfig(runtime, 'registry-runtime', issues)
  if (!Array.isArray(runtime?.inject) || !runtime.inject.includes('storageDomain')
    || !runtime.inject.includes('credentials')) {
    issues.push('registry-runtime must inject storageDomain and credentials')
  }
  const saas = requiredRecord(runtimeConfig?.saas, 'registry-runtime.saas', issues)
  const disclosureContentProviders = entries.filter(entry => entry.id === DISCLOSURE_CONTENT_PROVIDER_ENTRY)
  const injectsDisclosureContentProvider = Array.isArray(runtime?.inject)
    && runtime.inject.includes(DISCLOSURE_CONTENT_PROVIDER_SERVICE)
  const enablesDisclosureContentProvider = saas?.disclosureContentProvider === true
  if (saas?.disclosureContentProvider !== undefined
    && saas.disclosureContentProvider !== true && saas.disclosureContentProvider !== false) {
    issues.push('registry-runtime.saas.disclosureContentProvider must be a literal boolean')
  }
  if (enablesDisclosureContentProvider !== injectsDisclosureContentProvider) {
    issues.push(`registry-runtime.saas.disclosureContentProvider and ${DISCLOSURE_CONTENT_PROVIDER_SERVICE} injection must be enabled together`)
  }
  if (enablesDisclosureContentProvider ? disclosureContentProviders.length !== 1
    : disclosureContentProviders.length !== 0) {
    issues.push(`enabled disclosure content requires exactly one active ${DISCLOSURE_CONTENT_PROVIDER_ENTRY} entry; disabled disclosure content requires none`)
  }
  const disclosureKeyProviders = entries.filter(entry => entry.id === DISCLOSURE_KEY_PROVIDER_ENTRY)
  const softwareKeyProviders = entries.filter(entry => entry.name === DISCLOSURE_KEY_PROVIDER_NAME)
  const injectsDisclosureKeyProvider = Array.isArray(runtime?.inject)
    && runtime.inject.includes(DISCLOSURE_KEY_PROVIDER_SERVICE)
  const enablesDisclosureKeyProvider = saas?.disclosureKeyProvider === true
  if (saas?.disclosureKeyProvider !== undefined
    && saas.disclosureKeyProvider !== true && saas.disclosureKeyProvider !== false) {
    issues.push('registry-runtime.saas.disclosureKeyProvider must be a literal boolean')
  }
  if (enablesDisclosureKeyProvider !== injectsDisclosureKeyProvider) {
    issues.push(`registry-runtime.saas.disclosureKeyProvider and ${DISCLOSURE_KEY_PROVIDER_SERVICE} injection must be enabled together`)
  }
  if (enablesDisclosureKeyProvider ? disclosureKeyProviders.length !== 1 : disclosureKeyProviders.length !== 0) {
    issues.push(`enabled disclosure keys require exactly one active ${DISCLOSURE_KEY_PROVIDER_ENTRY} entry; disabled disclosure keys require none`)
  }
  if (enablesDisclosureKeyProvider ? softwareKeyProviders.length !== 1
    || softwareKeyProviders[0] !== disclosureKeyProviders[0] : softwareKeyProviders.length !== 0) {
    issues.push(`enabled disclosure keys require one ${DISCLOSURE_KEY_PROVIDER_NAME} at ${DISCLOSURE_KEY_PROVIDER_ENTRY}; disabled disclosure keys require none`)
  }
  if (disclosureKeyProviders.length === 1) {
    const provider = disclosureKeyProviders[0]
    if (provider.name !== DISCLOSURE_KEY_PROVIDER_NAME) {
      issues.push(`${DISCLOSURE_KEY_PROVIDER_ENTRY} must use ${DISCLOSURE_KEY_PROVIDER_NAME}`)
    }
    if (!Array.isArray(provider.inject) || !provider.inject.includes('storageDomain')
      || !provider.inject.includes('credentials')) {
      issues.push(`${DISCLOSURE_KEY_PROVIDER_ENTRY} must inject storageDomain and credentials`)
    }
    const providerConfig = objectConfig(provider, DISCLOSURE_KEY_PROVIDER_ENTRY, issues)
    if (providerConfig?.singleInstance !== true) {
      issues.push(`${DISCLOSURE_KEY_PROVIDER_ENTRY}.singleInstance must be true`)
    }
    if (!isExactExpression(providerConfig?.rootKeyId,
      'process.env.DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID')) {
      issues.push(`${DISCLOSURE_KEY_PROVIDER_ENTRY}.rootKeyId must use DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID`)
    }
  }
  const disclosureBridge = requiredRecord(runtimeConfig?.productionDisclosureBridge,
    'registry-runtime.productionDisclosureBridge', issues)
  if (disclosureBridge !== undefined && !enablesDisclosureKeyProvider) {
    issues.push('registry-runtime.productionDisclosureBridge requires the disclosure key provider')
  }
  const billingProviders = entries.filter(entry => entry.id === BILLING_PROVIDER_ENTRY)
  const injectsBillingProvider = Array.isArray(runtime?.inject) && runtime.inject.includes(BILLING_PROVIDER_SERVICE)
  const enablesBillingProvider = saas?.billingProvider === true
  if (saas?.billingProvider !== undefined
    && saas.billingProvider !== true && saas.billingProvider !== false) {
    issues.push('registry-runtime.saas.billingProvider must be a literal boolean')
  }
  if (enablesBillingProvider !== injectsBillingProvider) {
    issues.push(`registry-runtime.saas.billingProvider and ${BILLING_PROVIDER_SERVICE} injection must be enabled together`)
  }
  if (enablesBillingProvider ? billingProviders.length !== 1 : billingProviders.length !== 0) {
    issues.push(`enabled billing requires exactly one active ${BILLING_PROVIDER_ENTRY} entry; disabled billing requires none`)
  }
  if (enablesBillingProvider && record(record(runtimeConfig?.api)?.admission) === undefined) {
    issues.push('enabled billing requires registry-runtime.api.admission for unauthenticated webhook requests')
  }
  if (saas?.schemaMode !== 'validate') issues.push('registry-runtime.saas.schemaMode must be validate')
  if (saas?.databaseUrlEnv !== 'DSH_REGISTRY_POSTGRES_URL') {
    issues.push('registry-runtime.saas.databaseUrlEnv must be DSH_REGISTRY_POSTGRES_URL')
  }
  unsafeSharedDatabase(saas?.allowUnsafeSharedDatabase, 'registry-runtime.saas', issues)
  if (postgresConfig !== undefined && saas !== undefined) {
    const storageSchema = postgresConfig.schema ?? 'registry'
    const tenancySchema = saas.schema ?? 'registry'
    if (typeof storageSchema !== 'string' || typeof tenancySchema !== 'string'
      || storageSchema !== tenancySchema) {
      issues.push('PostgreSQL storage and SaaS tenancy must use the same literal schema')
    }
  }

  const oidc = requiredRecord(runtimeConfig?.oidc, 'registry-runtime.oidc', issues)
  if (oidc?.mode !== 'production') issues.push('registry-runtime.oidc.mode must be production')
  if (oidc?.sessionValidation !== 'introspection') {
    issues.push('registry-runtime.oidc.sessionValidation must be introspection')
  }
  if (oidc?.clientSecretEnv !== 'DSH_REGISTRY_OIDC_CLIENT_SECRET'
    || oidc?.sessionSecretEnv !== 'DSH_REGISTRY_SESSION_SECRET') {
    issues.push('registry-runtime.oidc secrets must use the production environment references')
  }
  const sharedAdmission = requiredRecord(runtimeConfig?.sharedAdmission,
    'registry-runtime.sharedAdmission', issues)
  if (sharedAdmission?.keySecretEnv !== 'DSH_REGISTRY_ADMISSION_HMAC') {
    issues.push('registry-runtime.sharedAdmission must use DSH_REGISTRY_ADMISSION_HMAC')
  }
  const ingest = requiredRecord(runtimeConfig?.ingest, 'registry-runtime.ingest', issues)
  const sync = requiredRecord(ingest?.sync, 'registry-runtime.ingest.sync', issues)
  if (sync?.tlsTermination !== 'loopback-proxy') {
    issues.push('registry-runtime.ingest.sync.tlsTermination must be loopback-proxy')
  }
  const alerts = requiredRecord(ingest?.alerts, 'registry-runtime.ingest.alerts', issues)
  if (alerts?.bearerTokenEnv !== 'DSH_REGISTRY_ALERT_BEARER_TOKEN') {
    issues.push('registry-runtime.ingest.alerts must use DSH_REGISTRY_ALERT_BEARER_TOKEN')
  }
  requiredRecord(ingest?.bindings, 'registry-runtime.ingest.bindings', issues)
  requiredRecord(ingest?.imports, 'registry-runtime.ingest.imports', issues)
  const questions = requiredRecord(ingest?.questions, 'registry-runtime.ingest.questions', issues)
  if (questions?.mailboxKeyEnv !== 'DSH_REGISTRY_MAILBOX_KEY') {
    issues.push('registry-runtime.ingest.questions must use DSH_REGISTRY_MAILBOX_KEY')
  }
  if (runtimeConfig !== undefined && Object.hasOwn(runtimeConfig, 'localHarness')) {
    issues.push('registry-runtime.localHarness must not be present in production')
  }

  for (const entry of entries) {
    const identity = `${String(entry.id ?? '')} ${String(entry.name ?? '')}`
    if (TEST_ENTRY.test(identity) || containsTestConfiguration(entry.config)) {
      issues.push(`local or test-only entry is active: ${String(entry.id ?? '<unknown>')}`)
    }
  }
  return [...new Set(issues)]
}

export function assertProductionGraph(composedEntries, composeWarnings = []) {
  const issues = productionGraphIssues(composedEntries, composeWarnings)
  if (issues.length === 0) return
  throw new Error([
    `registry-production-graph: failed (${issues.length})`,
    ...issues.map(issue => `- ${issue}`),
  ].join('\n'))
}

function checkNodeRuntime() {
  const [major = 0, minor = 0] = process.versions.node.split('.').map(Number)
  if (!(major === 22 && minor >= 19) && major < 24) {
    throw new Error('registry-production-graph: Node ^22.19.0 or >=24.0.0 is required')
  }
}

function usage(message) {
  if (message !== undefined) process.stderr.write(`registry-production-graph: ${message}\n`)
  process.stderr.write('usage: node --import tsx/esm deploy/registry/verify-production-graph.mjs --patch <path> [--patch <path> ...]\n')
  process.exitCode = 2
}

function main() {
  let patches
  try {
    const parsed = parseArgs({
      options: { patch: { type: 'string', multiple: true } },
      allowPositionals: false,
      strict: true,
    })
    patches = parsed.values.patch ?? []
  } catch (error) {
    usage(error instanceof Error ? error.message : 'invalid arguments')
    return
  }
  if (patches.length === 0) {
    usage('at least one --patch is required')
    return
  }
  try {
    checkNodeRuntime()
    const paths = [BUNDLE_PATCH, ...patches.map(path => resolve(path))]
    const layers = paths.map(path => loadOverlayPatches('registry-production-graph', path))
    const warnings = []
    const entries = composeEntries(layers, warning => warnings.push(warning))
    assertProductionGraph(entries, warnings)
    process.stdout.write([
      'registry-production-graph: passed',
      `- checked patch layers: ${String(patches.length)}`,
      '- credentials: inherited environment only; writable stores disabled',
      '- listener: 127.0.0.1; authoritative storage and tenancy: PostgreSQL validate mode',
      '- identity: production OIDC with per-request token introspection',
      '- local and test-only providers: absent',
      '',
    ].join('\n'))
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'registry-production-graph: failed'}\n`)
    process.exitCode = 1
  }
}

if (process.argv[1] !== undefined
  && realpathSync.native(resolve(process.argv[1])) === realpathSync.native(fileURLToPath(import.meta.url))) main()
