import assert from 'node:assert/strict'
import test from 'node:test'
import {
  fingerprintTenancyPolicies,
  PostgresRegistryTenancy,
  TENANCY_POLICY_CATALOG_QUERY,
  TENANCY_POLICY_DEPARSE_QUOTE_ALL_IDENTIFIERS,
  TENANCY_POLICY_DEPARSE_SEARCH_PATH,
  TENANCY_POLICY_DEPARSE_SETTINGS_QUERY,
} from '../packages/bundle/registry-app/src/tenancy-postgres.ts'

const policies = [
  {
    table_name: 'organizations',
    policy_name: 'organizations_select',
    command: 'r',
    permissive: true,
    public_only: true,
    has_using: true,
    has_check: false,
    roles_definition: '["PUBLIC"]',
    using_definition: "((current_setting('app.account_id'::text, true) = '__registry_control_plane__'::text) OR (SubPlan 1))",
    check_definition: null,
  },
  {
    table_name: 'organization_memberships',
    policy_name: 'organization_memberships_update',
    command: 'w',
    permissive: true,
    public_only: true,
    has_using: true,
    has_check: true,
    roles_definition: '["PUBLIC"]',
    using_definition: "((organization_id = nullif(current_setting('app.organization_id'::text, true), ''::text)) AND (current_setting('app.account_id'::text, true) = '__registry_control_plane__'::text))",
    check_definition: "((organization_id = nullif(current_setting('app.organization_id'::text, true), ''::text)) AND (current_setting('app.account_id'::text, true) = '__registry_control_plane__'::text))",
  },
]

test('tenancy policy fingerprint is restore-stable and detects semantic changes', () => {
  const beforeDump = fingerprintTenancyPolicies(policies)
  const afterRestore = fingerprintTenancyPolicies(structuredClone(policies).reverse())

  assert.match(beforeDump, /^[0-9a-f]{64}$/u)
  assert.equal(afterRestore, beforeDump)
  assert.notEqual(fingerprintTenancyPolicies([
    { ...policies[0], using_definition: 'false' },
    policies[1],
  ]), beforeDump)
  assert.notEqual(fingerprintTenancyPolicies([
    { ...policies[0], roles_definition: '["registry_reader"]', public_only: false },
    policies[1],
  ]), beforeDump)
})

test('tenancy policy catalog query fixes deparse settings and avoids pg_node_tree OIDs', () => {
  assert.equal(TENANCY_POLICY_DEPARSE_SEARCH_PATH, 'pg_catalog')
  assert.equal(TENANCY_POLICY_DEPARSE_QUOTE_ALL_IDENTIFIERS, 'off')
  assert.match(TENANCY_POLICY_DEPARSE_SETTINGS_QUERY,
    /pg_catalog\.set_config\('search_path', \$1, true\) as search_path/u)
  assert.match(TENANCY_POLICY_DEPARSE_SETTINGS_QUERY,
    /pg_catalog\.set_config\('quote_all_identifiers', \$2, true\) as quote_all_identifiers/u)
  assert.match(TENANCY_POLICY_CATALOG_QUERY,
    /pg_catalog\.pg_get_expr\(p\.polqual, p\.polrelid, false\)/u)
  assert.match(TENANCY_POLICY_CATALOG_QUERY,
    /pg_catalog\.pg_get_expr\(p\.polwithcheck, p\.polrelid, false\)/u)
  assert.match(TENANCY_POLICY_CATALOG_QUERY, /role\.rolname/u)
  assert.doesNotMatch(TENANCY_POLICY_CATALOG_QUERY, /p\.pol(?:qual|withcheck)::text/u)
  assert.doesNotMatch(TENANCY_POLICY_CATALOG_QUERY, /p\.polroles::text/u)
})

test('tenancy policy reader verifies canonical deparse settings before catalog access', async () => {
  const store = Object.create(PostgresRegistryTenancy.prototype)
  Object.defineProperty(store, 'schemaName', { value: 'registry_saas' })
  const calls = []
  const client = {
    async query(statement, values) {
      calls.push({ statement, values })
      if (statement === TENANCY_POLICY_DEPARSE_SETTINGS_QUERY) {
        return { rows: [{ search_path: 'pg_catalog', quote_all_identifiers: 'off' }] }
      }
      assert.equal(statement, TENANCY_POLICY_CATALOG_QUERY)
      return { rows: policies }
    },
  }

  assert.deepEqual(await store.readPolicies(client), policies)
  assert.deepEqual(calls.map(call => call.values), [
    ['pg_catalog', 'off'],
    ['registry_saas', ['organizations', 'organization_memberships',
      'organization_creations', 'organization_invitations']],
  ])

  await assert.rejects(store.readPolicies({
    async query() {
      return { rows: [{ search_path: 'pg_catalog', quote_all_identifiers: 'on' }] }
    },
  }), error => error?.code === 'unavailable')
})
