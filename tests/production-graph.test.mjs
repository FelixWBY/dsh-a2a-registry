import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { composeEntries, loadOverlayPatches } from '@deepseek-ai/dsh-app-boot'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import LocalCredentialProvider from '@deepseek-ai/dsh-credentials-local'
import { createLaunchEnvironmentSnapshot, DSH_LAUNCH_ENVIRONMENT_KEY } from '@deepseek-ai/dsh-launch-environment'
import { productionGraphIssues } from '../deploy/registry/verify-production-graph.mjs'

const patchPaths = [
  'packages/bundle/registry-app/cordis.patch.yml',
  'deploy/registry/registry-single-host.example.patch.yml',
  'deploy/registry/registry-postgres.example.patch.yml',
  'deploy/registry/registry-production.example.patch.yml',
]

function productionEntries() {
  return composeEntries(patchPaths.map(path => loadOverlayPatches('production-graph-test', resolve(path))))
}

function entry(entries, id) {
  return entries.find(candidate => candidate.id === id)
}

test('installable production graph is closed and rejects unsafe deployment mutations', () => {
  const accepted = productionEntries()
  assert.deepEqual(productionGraphIssues(accepted), [])

  const cases = [
    ['missing credentials', entries => entries.splice(entries.findIndex(row => row.id === 'registry-production-credentials'), 1),
      /exactly one .*credentials-local provider is required/u],
    ['dynamic listener disable', entries => {
      entry(entries, 'registry-webserver').disabled = { __jsExpr: 'true' }
      entries.push({ id: 'replacement-webserver', name: '@deepseek-ai/dsh-host-webserver',
        config: { host: '0.0.0.0' } })
    }, /disabled must be a literal boolean/u],
    ['second web listener', entries => entries.push({
      id: 'replacement-webserver', name: '@deepseek-ai/dsh-host-webserver', config: { host: '0.0.0.0' },
    }), /dsh-host-webserver must have exactly one active entry/u],
    ['public listener', entries => { entry(entries, 'registry-webserver').config.host = '0.0.0.0' },
      /registry-webserver\.host must be 127\.0\.0\.1/u],
    ['SQLite authority', entries => { entry(entries, 'registry-storage-domain').config.backend = 'sqlite' },
      /registry-storage-domain\.backend must be postgres/u],
    ['storage migration mode', entries => { entry(entries, 'registry-storage-postgres').config.schemaMode = 'migrate' },
      /registry-storage-postgres\.schemaMode must be validate/u],
    ['embedded database URL', entries => {
      entry(entries, 'registry-storage-postgres').config.connectionString = 'postgresql://embedded'
    }, /registry-storage-postgres\.connectionString must use DSH_REGISTRY_POSTGRES_URL/u],
    ['tenancy migration mode', entries => { entry(entries, 'registry-runtime').config.saas.schemaMode = 'migrate' },
      /registry-runtime\.saas\.schemaMode must be validate/u],
    ['unsafe shared database', entries => {
      entry(entries, 'registry-storage-postgres').config.allowUnsafeSharedDatabase = true
    }, /registry-storage-postgres\.allowUnsafeSharedDatabase must be false/u],
    ['development identity', entries => { entry(entries, 'registry-runtime').config.oidc.mode = 'loopback-development' },
      /registry-runtime\.oidc\.mode must be production/u],
    ['non-introspected sessions', entries => { entry(entries, 'registry-runtime').config.oidc.sessionValidation = 'userinfo' },
      /registry-runtime\.oidc\.sessionValidation must be introspection/u],
    ['missing WSS sync graph', entries => { delete entry(entries, 'registry-runtime').config.ingest.sync },
      /registry-runtime\.ingest\.sync must be configured/u],
    ['wrong alert secret', entries => {
      entry(entries, 'registry-runtime').config.ingest.alerts.bearerTokenEnv = 'DSH_REGISTRY_POSTGRES_URL'
    }, /alerts must use DSH_REGISTRY_ALERT_BEARER_TOKEN/u],
    ['wrong mailbox secret', entries => {
      entry(entries, 'registry-runtime').config.ingest.questions.mailboxKeyEnv = 'DSH_REGISTRY_POSTGRES_URL'
    }, /questions must use DSH_REGISTRY_MAILBOX_KEY/u],
    ['disclosure content provider missing runtime injection', entries => {
      entries.push({
        id: 'registry-disclosure-content-provider', name: '@example/registry-disclosure-content-provider',
      })
      entry(entries, 'registry-runtime').config.saas.disclosureContentProvider = true
    }, /disclosureContentProvider and registryDisclosureContentProvider injection must be enabled together/u],
    ['orphan disclosure content provider injection', entries => {
      entry(entries, 'registry-runtime').inject.push('registryDisclosureContentProvider')
    }, /disclosureContentProvider and registryDisclosureContentProvider injection must be enabled together/u],
    ['provider entry without explicit enablement', entries => entries.push({
      id: 'registry-disclosure-content-provider', name: '@example/registry-disclosure-content-provider',
    }), /disabled disclosure content requires none/u],
    ['enabled provider missing fixed entry', entries => {
      entry(entries, 'registry-runtime').config.saas.disclosureContentProvider = true
      entry(entries, 'registry-runtime').inject.push('registryDisclosureContentProvider')
    }, /requires exactly one active registry-disclosure-content-provider entry/u],
    ['billing provider missing runtime injection', entries => {
      entries.push({ id: 'registry-billing-provider', name: '@example/registry-billing-provider' })
      entry(entries, 'registry-runtime').config.saas.billingProvider = true
    }, /billingProvider and registryBillingProvider injection must be enabled together/u],
    ['orphan billing provider injection', entries => {
      entry(entries, 'registry-runtime').inject.push('registryBillingProvider')
    }, /billingProvider and registryBillingProvider injection must be enabled together/u],
    ['billing provider entry without explicit enablement', entries => entries.push({
      id: 'registry-billing-provider', name: '@example/registry-billing-provider',
    }), /disabled billing requires none/u],
    ['enabled billing provider missing fixed entry', entries => {
      entry(entries, 'registry-runtime').config.saas.billingProvider = true
      entry(entries, 'registry-runtime').inject.push('registryBillingProvider')
    }, /requires exactly one active registry-billing-provider entry/u],
    ['enabled billing provider missing admission', entries => {
      entries.push({ id: 'registry-billing-provider', name: '@example/registry-billing-provider' })
      entry(entries, 'registry-runtime').config.saas.billingProvider = true
      entry(entries, 'registry-runtime').inject.push('registryBillingProvider')
      delete entry(entries, 'registry-runtime').config.api.admission
    }, /enabled billing requires registry-runtime\.api\.admission/u],
    ['local Harness', entries => { entry(entries, 'registry-runtime').config.localHarness = {} },
      /registry-runtime\.localHarness must not be present/u],
    ['test plugin', entries => entries.push({ id: 'registry-test-fixture', name: '@example/registry-test-fixture' }),
      /local or test-only entry is active/u],
  ]
  for (const [label, mutate, expected] of cases) {
    const entries = structuredClone(accepted)
    mutate(entries)
    assert.match(productionGraphIssues(entries).join('\n'), expected, label)
  }

  const withDisclosureContentProvider = structuredClone(accepted)
  withDisclosureContentProvider.push({
    id: 'registry-disclosure-content-provider', name: '@example/registry-disclosure-content-provider',
  })
  entry(withDisclosureContentProvider, 'registry-runtime').config.saas.disclosureContentProvider = true
  entry(withDisclosureContentProvider, 'registry-runtime').inject.push('registryDisclosureContentProvider')
  assert.deepEqual(productionGraphIssues(withDisclosureContentProvider), [])

  const withBillingProvider = structuredClone(accepted)
  withBillingProvider.push({ id: 'registry-billing-provider', name: '@example/registry-billing-provider' })
  entry(withBillingProvider, 'registry-runtime').config.saas.billingProvider = true
  entry(withBillingProvider, 'registry-runtime').inject.push('registryBillingProvider')
  assert.deepEqual(productionGraphIssues(withBillingProvider), [])

  const unit = readFileSync(new URL('../deploy/registry/dsh-registry.service.example', import.meta.url), 'utf8')
  assert.match(unit, /^ExecStartPre=.*verify-production-graph\.mjs .*registry-single-host\.example\.patch\.yml .*registry-postgres\.example\.patch\.yml .*registry-production\.patch\.yml$/mu)
  assert.match(unit, /^ExecStart=.*registry-single-host\.example\.patch\.yml .*registry-postgres\.example\.patch\.yml .*registry-production\.patch\.yml$/mu)
})

test('production credentials mode exposes inherited secrets without file or write fallbacks', async () => {
  const context = new Context()
  context.provide(DSH_LAUNCH_ENVIRONMENT_KEY, createLaunchEnvironmentSnapshot([
    { source: 'process', values: { REGISTRY_SECRET: 'inherited-secret' } },
    { source: 'project-env', path: resolve('.env'), values: { FILE_SECRET: 'must-not-resolve' } },
  ]))
  const provider = new LocalCredentialProvider(context, { environmentOnly: true })
  assert.deepEqual(await provider.resolve(credentialRef('REGISTRY_SECRET')),
    { value: 'inherited-secret', source: 'env' })
  assert.equal(await provider.resolve(credentialRef('FILE_SECRET')), undefined)
  assert.deepEqual(await provider.describe(credentialRef('FILE_SECRET')), { configured: false, writable: false })
  await assert.rejects(provider.set(credentialRef('NEW_SECRET'), 'value'), /environment-only mode is read-only/u)
  await assert.rejects(provider.unset(credentialRef('NEW_SECRET')), /environment-only mode is read-only/u)
})
