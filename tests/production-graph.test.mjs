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
      entry(entries, 'registry-runtime').inject = entry(entries, 'registry-runtime').inject
        .filter(value => value !== 'registryDisclosureContentProvider')
    }, /registry-runtime must inject registryDisclosureContentProvider/u],
    ['disclosure content provider not explicitly enabled', entries => {
      delete entry(entries, 'registry-runtime').config.saas.disclosureContentProvider
    }, /registry-runtime\.saas\.disclosureContentProvider must be true/u],
    ['disclosure content provider missing fixed entry', entries => {
      entries.splice(entries.findIndex(row => row.id === 'registry-disclosure-content-provider'), 1)
    }, /registry-disclosure-content-provider must have exactly one active entry/u],
    ['disclosure content provider wrong package', entries => {
      entry(entries, 'registry-disclosure-content-provider').name = '@example/registry-disclosure-content-provider'
    }, /must use @deepseek-ai\/dsh-registry-disclosure-content-app/u],
    ['duplicate disclosure content package', entries => entries.push({
      id: 'shadow-disclosure-content-provider',
      name: '@deepseek-ai/dsh-registry-disclosure-content-app',
      inject: ['registryDisclosureKeyProvider'],
      config: { maxContentEvents: 1, crypto: {
        maxPlaintextBytes: 1, maxCiphertextBytes: 1, maxTrustedKeys: 1,
      } },
    }), /must have exactly one active entry with id registry-disclosure-content-provider/u],
    ['disclosure content provider missing key injection', entries => {
      entry(entries, 'registry-disclosure-content-provider').inject = []
    }, /must inject registryDisclosureKeyProvider/u],
    ['disclosure content provider has an extra injection', entries => {
      entry(entries, 'registry-disclosure-content-provider').inject.push('credentials')
    }, /and no other service/u],
    ['disclosure content provider missing event bound', entries => {
      delete entry(entries, 'registry-disclosure-content-provider').config.maxContentEvents
    }, /maxContentEvents must be a positive safe integer/u],
    ['disclosure content provider has an unknown top-level setting', entries => {
      entry(entries, 'registry-disclosure-content-provider').config.maxBufferedEvents = 1000
    }, /must contain exactly crypto, maxContentEvents/u],
    ['disclosure content provider invalid crypto mapping', entries => {
      entry(entries, 'registry-disclosure-content-provider').config.crypto = []
    }, /\.crypto must be configured/u],
    ['disclosure content provider invalid plaintext bound', entries => {
      entry(entries, 'registry-disclosure-content-provider').config.crypto.maxPlaintextBytes = 0
    }, /maxPlaintextBytes must be a positive safe integer/u],
    ['disclosure content provider undersized ciphertext bound', entries => {
      entry(entries, 'registry-disclosure-content-provider').config.crypto.maxCiphertextBytes = 1024
    }, /maxCiphertextBytes must be at least maxPlaintextBytes/u],
    ['disclosure content provider invalid trusted-key bound', entries => {
      entry(entries, 'registry-disclosure-content-provider').config.crypto.maxTrustedKeys = 1.5
    }, /maxTrustedKeys must be a positive safe integer/u],
    ['disclosure content provider crypto cannot shadow the event bound', entries => {
      entry(entries, 'registry-disclosure-content-provider').config.crypto.maxEvents = Number.MAX_SAFE_INTEGER
    }, /\.crypto must contain exactly maxCiphertextBytes, maxPlaintextBytes, maxTrustedKeys/u],
    ['disclosure key provider missing runtime injection', entries => {
      entry(entries, 'registry-runtime').inject = entry(entries, 'registry-runtime').inject
        .filter(value => value !== 'registryDisclosureKeyProvider')
    }, /disclosureKeyProvider and registryDisclosureKeyProvider injection must be enabled together/u],
    ['disclosure key provider missing fixed entry', entries => {
      entries.splice(entries.findIndex(row => row.id === 'registry-disclosure-key-provider'), 1)
    }, /enabled disclosure keys require exactly one active registry-disclosure-key-provider entry/u],
    ['disclosure key provider wrong package', entries => {
      entry(entries, 'registry-disclosure-key-provider').name = '@example/registry-disclosure-key-provider'
    }, /must use @deepseek-ai\/dsh-registry-kms-software-app/u],
    ['duplicate software disclosure key provider', entries => entries.push({
      id: 'shadow-disclosure-key-provider', name: '@deepseek-ai/dsh-registry-kms-software-app',
      inject: ['storageDomain', 'credentials'], config: { singleInstance: true, rootKeyId: 'shadow' },
    }), /require one @deepseek-ai\/dsh-registry-kms-software-app/u],
    ['disclosure key provider without single-instance acknowledgement', entries => {
      entry(entries, 'registry-disclosure-key-provider').config.singleInstance = false
    }, /singleInstance must be true/u],
    ['disclosure key provider embedded root id', entries => {
      entry(entries, 'registry-disclosure-key-provider').config.rootKeyId = 'root-v1'
    }, /rootKeyId must use DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID/u],
    ['disclosure key provider embedded previous root id', entries => {
      entry(entries, 'registry-disclosure-key-provider').config.previousRootKeyId = 'root-v0'
    }, /previousRootKeyId must use DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID/u],
    ['production bridge missing', entries => {
      delete entry(entries, 'registry-runtime').config.productionDisclosureBridge
    }, /registry-runtime\.productionDisclosureBridge must be configured/u],
    ['production bridge without key provider enablement', entries => {
      entry(entries, 'registry-runtime').config.saas.disclosureKeyProvider = false
      entry(entries, 'registry-runtime').inject = entry(entries, 'registry-runtime').inject
        .filter(value => value !== 'registryDisclosureKeyProvider')
      entries.splice(entries.findIndex(row => row.id === 'registry-disclosure-key-provider'), 1)
    }, /productionDisclosureBridge requires the disclosure key provider/u],
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

  const disclosureContentProvider = entry(accepted, 'registry-disclosure-content-provider')
  assert.equal(disclosureContentProvider.name, '@deepseek-ai/dsh-registry-disclosure-content-app')
  assert.deepEqual(disclosureContentProvider.inject, ['registryDisclosureKeyProvider'])
  assert.deepEqual(disclosureContentProvider.config, {
    maxContentEvents: 1000,
    crypto: { maxPlaintextBytes: 65536, maxCiphertextBytes: 262144, maxTrustedKeys: 4 },
  })

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
