import test from 'node:test'
import assert from 'node:assert/strict'
import { createSecretKey } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import Storage from '@deepseek-ai/dsh-storage'
import * as jsonStorage from '@deepseek-ai/dsh-storage-json'
import * as storageDomain from '@deepseek-ai/dsh-storage-domain'
import {
  openSoftwareLocalDisclosureKeyStore,
  softwareLocalDisclosureKeyDomainName,
  SoftwareLocalKmsError,
} from '@deepseek-ai/dsh-a2a-registry-kms-software'
import {
  configurationFromEnvironment,
  parseArguments,
  requireExactStoragePolicies,
  requireExactTenancyPolicies,
  runOfflineKmsRootRewrap,
  safeMessage,
} from '../deploy/registry/rewrap-software-kms-root.mjs'
import { fingerprintTenancyPolicies } from '../packages/bundle/registry-app/src/tenancy-postgres.ts'

const PREFIX = 'a2a_registry_disclosure_keys'
const SCHEMA = 'registry'

function rootKey(byte, keyId) {
  return Object.freeze({ keyId, key: createSecretKey(Buffer.alloc(32, byte)) })
}

function scope(organizationId) {
  return Object.freeze({ organizationId, instanceId: 'source', conversationId: 'conversation',
    disclosureId: 'disclosure' })
}

function dataKey(grantScope, byte) {
  return Object.freeze({
    keyId: 'data-key:retained',
    scope: Object.freeze({ organizationId: grantScope.organizationId,
      instanceId: grantScope.instanceId, conversationId: grantScope.conversationId }),
    key: createSecretKey(Buffer.alloc(32, byte)),
  })
}

async function seededUnit(organizationId, root) {
  const home = await mkdtemp(join(tmpdir(), 'registry-kms-rewrap-command-seed-'))
  const ctx = new Context()
  try {
    await ctx.plugin(Storage).await()
    await ctx.plugin(jsonStorage, { root: home }).await()
    await ctx.plugin(storageDomain, { backend: 'json' }).await()
    const grantScope = scope(organizationId)
    const store = await openSoftwareLocalDisclosureKeyStore(ctx.storageDomain, {
      organizationId,
      rootKey: root,
      storage: { domainNamePrefix: PREFIX, tenantId: organizationId },
      limits: { maxDataKeys: 8, maxPendingOperations: 2 },
      signal: new AbortController().signal,
    })
    await store.publishDataKey(grantScope, dataKey(grantScope, 0x55), new AbortController().signal)
    await store.close()
    const unit = softwareLocalDisclosureKeyDomainName(PREFIX, organizationId)
    const document = JSON.parse(await readFile(join(home, `${unit}.json`), 'utf8'))
    const records = Object.entries(document.tables).flatMap(([table_name, values]) =>
      Object.entries(values).map(([key, value]) => ({ table_name, key, value })))
    return { present: true, version: 1, globalCount: 0, records }
  } finally {
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
}

class FakeMaintenanceDatabase {
  constructor(organizations, units = new Map(), activeConnections = 0, globalRecords) {
    this.organizations = organizations
    this.units = units
    this.activeConnections = activeConnections
    this.globalRecords = globalRecords
    this.calls = []
    this.replaceCount = 0
  }

  mark(name) { this.calls.push(name) }
  async begin() { this.mark('begin') }
  async configureTransaction() { this.mark('configure') }
  async requireSafeRole() { this.mark('role') }
  async acquireMaintenanceLock() { this.mark('lock') }
  async activeRegistryConnections() { this.mark('sessions'); return this.activeConnections }
  async lockAuthoritativeTables() { this.mark('tables') }
  async listOrganizations() { this.mark('organizations'); return structuredClone(this.organizations) }
  async listGlobalKmsRecords() {
    this.mark('inventory')
    if (this.globalRecords !== undefined) return structuredClone(this.globalRecords)
    const rows = []
    for (const [organizationId, snapshot] of this.units) {
      const unit = softwareLocalDisclosureKeyDomainName(PREFIX, organizationId)
      for (const record of snapshot.records ?? []) rows.push({
        tenant_id: organizationId,
        unit,
        version: snapshot.version,
        table_name: record.table_name,
        key: record.key,
        value: record.value,
        global_count: snapshot.globalCount,
      })
    }
    return structuredClone(rows)
  }
  async loadKmsUnit(_schema, organizationId) {
    this.mark(`load:${organizationId}`)
    return structuredClone(this.units.get(organizationId) ?? { present: false })
  }
  async replaceOwner(_schema, organizationId, _unit, expected, next) {
    this.mark(`replace:${organizationId}`)
    const snapshot = this.units.get(organizationId)
    const owner = snapshot.records.find(record => record.table_name === 'owner' && record.key === 'owner')
    assert.deepEqual(owner.value, expected)
    owner.value = structuredClone(next)
    this.replaceCount += 1
  }
  async commit() { this.mark('commit') }
  async rollback() { this.mark('rollback') }
  async close() { this.mark('close') }
}

function configuration(execute, activeRootKey, previousRootKey) {
  return Object.freeze({
    help: false,
    execute,
    schema: SCHEMA,
    domainNamePrefix: PREFIX,
    connectionString: 'not-observed-by-fake',
    activeRootKey,
    previousRootKey,
    operatorAttestedQuiescence: execute,
    operatorAttestedBackupVerification: execute,
  })
}

async function runWith(database, selectedConfiguration) {
  return runOfflineKmsRootRewrap(selectedConfiguration, async (connectionString) => {
    assert.equal(connectionString, 'not-observed-by-fake')
    return database
  })
}

function assertMetadataOnly(value) {
  if (value === null || typeof value !== 'object') return
  for (const [key, nested] of Object.entries(value)) {
    assert.equal(['ciphertext', 'nonce', 'tag', 'wrappedOrganizationKey', 'wrappedDataKey',
      'material', 'key'].includes(key), false)
    assertMetadataOnly(nested)
  }
}

test('offline command accepts no secret arguments and resolves only dedicated environment slots', () => {
  const input = parseArguments(['--schema', SCHEMA, '--domain-name-prefix', PREFIX])
  const active = Buffer.alloc(32, 0x61).toString('base64url')
  const previous = Buffer.alloc(32, 0x62).toString('base64url')
  const migrator = 'postgresql://registry_migrator:fixture-password@127.0.0.1:5432/registry'
  const environment = {
    DSH_REGISTRY_POSTGRES_MIGRATOR_URL: migrator,
    DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID: 'root-key:active',
    DSH_REGISTRY_DISCLOSURE_ROOT_KEY: active,
    DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID: 'root-key:previous',
    DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY: previous,
  }
  const selected = configurationFromEnvironment(input, environment)
  assert.equal(selected.activeRootKey.keyId, 'root-key:active')
  assert.equal(selected.previousRootKey.keyId, 'root-key:previous')
  assert.throws(() => parseArguments(['--root-key', active]), /command-line secrets/iu)
  assert.throws(() => configurationFromEnvironment(input,
    { ...environment, DSH_REGISTRY_POSTGRES_URL: 'postgresql://registry_app:secret@localhost/db' }),
  /must not be present/iu)
  assert.throws(() => configurationFromEnvironment(input,
    { ...environment, DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY: undefined }), /is required/iu)
  const sanitized = safeMessage(new Error(`${migrator} ${active} ${previous}`), environment)
  assert.equal(sanitized, 'offline KMS root rewrap failed')
})

test('offline command rejects storage and tenancy policy drift before inventory can be trusted', () => {
  const storagePolicies = ['units', 'unit_globals', 'unit_records'].map(table_name => ({
    table_name,
    policy_name: 'tenant_isolation',
    all_commands: true,
    permissive: true,
    public_only: true,
    qualification: "(tenant_id = current_setting('app.tenant_id'::text, true))",
    check_expression: "(tenant_id = current_setting('app.tenant_id'::text, true))",
  }))
  assert.doesNotThrow(() => requireExactStoragePolicies(storagePolicies))
  assert.throws(() => requireExactStoragePolicies(storagePolicies.slice(1)), /tenant-isolation/iu)
  assert.throws(() => requireExactStoragePolicies([
    { ...storagePolicies[0], qualification: 'false' }, ...storagePolicies.slice(1),
  ]), /tenant-isolation/iu)

  const descriptors = [
    ['organizations', 'select', 'r', true, false],
    ['organizations', 'insert', 'a', false, true],
    ['organizations', 'update', 'w', true, true],
    ['organization_memberships', 'select', 'r', true, false],
    ['organization_memberships', 'insert', 'a', false, true],
    ['organization_memberships', 'update', 'w', true, true],
    ['organization_creations', 'select', 'r', true, false],
    ['organization_creations', 'insert', 'a', false, true],
    ['organization_invitations', 'select', 'r', true, false],
    ['organization_invitations', 'insert', 'a', false, true],
    ['organization_invitations', 'update', 'w', true, true],
    ['billing_orders', 'select', 'r', true, false],
    ['billing_orders', 'insert', 'a', false, true],
    ['billing_orders', 'update', 'w', true, true],
    ['billing_provider_events', 'select', 'r', true, false],
    ['billing_provider_events', 'insert', 'a', false, true],
  ]
  const tenancyPolicies = descriptors.map(([table_name, action, command, has_using, has_check]) => ({
    table_name,
    policy_name: `${table_name}_${action}`,
    command,
    permissive: true,
    public_only: true,
    has_using,
    has_check,
    roles_definition: '["PUBLIC"]',
    using_definition: has_using ? 'true' : null,
    check_definition: has_check ? 'true' : null,
  }))
  const fingerprint = fingerprintTenancyPolicies(tenancyPolicies)
  assert.doesNotThrow(() => requireExactTenancyPolicies(fingerprint, tenancyPolicies))
  assert.throws(() => requireExactTenancyPolicies(fingerprint, tenancyPolicies.slice(1)), /fingerprint/iu)
  assert.throws(() => requireExactTenancyPolicies(fingerprint, [
    { ...tenancyPolicies[0], using_definition: 'false' }, ...tenancyPolicies.slice(1),
  ]), /fingerprint/iu)
})

test('plan and execute process the authoritative list, skip absent owners, and exact retry is a no-op', async () => {
  const previous = rootKey(0x63, 'root-key:previous')
  const active = rootKey(0x64, 'root-key:active')
  const previousOrganization = 'organization-previous'
  const activeOrganization = 'organization-active'
  const absentOrganization = 'organization-no-owner'
  const units = new Map([
    [previousOrganization, await seededUnit(previousOrganization, previous)],
    [activeOrganization, await seededUnit(activeOrganization, active)],
    [absentOrganization, { present: true, version: 1, globalCount: 0, records: [] }],
  ])
  const organizations = [previousOrganization, activeOrganization, absentOrganization]
    .toSorted().map(id => ({ id, state: 'active' }))

  const planningDatabase = new FakeMaintenanceDatabase(organizations, units)
  const plan = await runWith(planningDatabase, configuration(false, active, previous))
  assert.equal(plan.mode, 'plan')
  assert.equal(plan.committed, false)
  assert.deepEqual(plan.summary, { organizations: 3, owners: 2, noOwner: 1,
    rewrapped: 0, wouldRewrap: 1, alreadyActive: 1, dataKeys: 2 })
  assert.deepEqual(plan.receipts.map(receipt => receipt.outcome).toSorted(),
    ['already-active', 'no-owner', 'would-rewrap'])
  assert.equal(planningDatabase.replaceCount, 0)
  assert.ok(planningDatabase.calls.indexOf('lock') < planningDatabase.calls.indexOf('sessions'))
  assert.ok(planningDatabase.calls.includes('rollback'))

  const executionDatabase = new FakeMaintenanceDatabase(organizations, units)
  const executed = await runWith(executionDatabase, configuration(true, active, previous))
  assert.equal(executed.committed, true)
  assert.deepEqual(executed.summary, { organizations: 3, owners: 2, noOwner: 1,
    rewrapped: 1, wouldRewrap: 0, alreadyActive: 1, dataKeys: 2 })
  assert.equal(executionDatabase.replaceCount, 1)
  assert.ok(executionDatabase.calls.includes('commit'))
  assertMetadataOnly(executed)

  const retryDatabase = new FakeMaintenanceDatabase(organizations, units)
  const retry = await runWith(retryDatabase, configuration(true, active, previous))
  assert.equal(retry.summary.rewrapped, 0)
  assert.equal(retry.summary.alreadyActive, 2)
  assert.equal(retryDatabase.replaceCount, 0)
})

test('an ownerless non-empty KMS unit fails instead of bootstrapping and active sessions stop the command', async () => {
  const previous = rootKey(0x65, 'root-key:previous')
  const active = rootKey(0x66, 'root-key:active')
  const organizationId = 'organization-malformed'
  const malformed = { present: true, version: 1, globalCount: 0,
    records: [{ table_name: 'data_keys', key: 'orphan', value: {} }] }
  const database = new FakeMaintenanceDatabase(
    [{ id: organizationId, state: 'active' }], new Map([[organizationId, malformed]]))
  await assert.rejects(() => runWith(database, configuration(true, active, previous)),
    /data keys exist without an owner/iu)
  assert.equal(database.replaceCount, 0)
  assert.ok(database.calls.includes('rollback'))

  const online = new FakeMaintenanceDatabase([{ id: organizationId, state: 'active' }], new Map(), 1)
  await assert.rejects(() => runWith(online, configuration(false, active, previous)),
    /sessions are active/iu)
  assert.equal(online.calls.includes('organizations'), false)
  assert.equal(online.calls.includes('tables'), false)
  assert.ok(online.calls.includes('rollback'))
})

test('unknown owner root identifiers remain closed through the offline command', async () => {
  const retained = rootKey(0x67, 'root-key:unconfigured')
  const previous = rootKey(0x68, 'root-key:previous')
  const active = rootKey(0x69, 'root-key:active')
  const organizationId = 'organization-unknown-root'
  const database = new FakeMaintenanceDatabase(
    [{ id: organizationId, state: 'active' }],
    new Map([[organizationId, await seededUnit(organizationId, retained)]]),
  )
  await assert.rejects(() => runWith(database, configuration(true, active, previous)),
    error => error instanceof SoftwareLocalKmsError && error.code === 'root-key-unavailable')
  assert.equal(database.replaceCount, 0)
  assert.ok(database.calls.includes('rollback'))
})

test('global inventory rejects orphan tenants, stale prefixes, and DEKs without an owner', async () => {
  const previous = rootKey(0x6a, 'root-key:previous')
  const active = rootKey(0x6b, 'root-key:active')
  const organizationId = 'organization-inventory'
  const snapshot = await seededUnit(organizationId, previous)
  const expectedUnit = softwareLocalDisclosureKeyDomainName(PREFIX, organizationId)
  const rows = snapshot.records.map(record => ({ tenant_id: organizationId, unit: expectedUnit,
    version: 1, table_name: record.table_name, key: record.key, value: record.value, global_count: 0 }))
  const organizations = [{ id: organizationId, state: 'active' }]

  const orphan = new FakeMaintenanceDatabase(organizations, new Map(), 0,
    rows.map(row => ({ ...row, tenant_id: 'organization-orphan' })))
  await assert.rejects(() => runWith(orphan, configuration(true, active, previous)),
    /outside the authoritative/iu)
  assert.ok(orphan.calls.includes('rollback'))

  const stalePrefix = new FakeMaintenanceDatabase(organizations, new Map(), 0,
    rows.map(row => ({ ...row, unit: `legacy_${row.unit.slice(-32)}` })))
  await assert.rejects(() => runWith(stalePrefix, configuration(true, active, previous)),
    /does not match the configured/iu)
  assert.ok(stalePrefix.calls.includes('rollback'))

  const dataOnly = new FakeMaintenanceDatabase(organizations, new Map(), 0,
    rows.filter(row => row.table_name === 'data_keys'))
  await assert.rejects(() => runWith(dataOnly, configuration(true, active, previous)),
    /without an owner/iu)
  assert.ok(dataOnly.calls.includes('rollback'))
})
