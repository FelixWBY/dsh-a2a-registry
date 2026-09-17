import assert from 'node:assert/strict'
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'

import { createBackupSet, parseCreate, readBillingState, safeMessage,
  verifyBackupSet, verifyRestoredBilling } from '../deploy/registry/backup-postgres-saas-state.mjs'

const BILLING_ROWS = Object.freeze({
  billing_orders: Object.freeze([Object.freeze({
    order_id: '00000000-0000-4000-8000-000000000001',
    organization_id: 'org-fixture',
    idempotency_key: 'idempotency-fixture',
    request_hash: 'a'.repeat(64),
    provider: 'fixture-provider',
    plan_id: 'fixture-plan',
    currency: 'CNY',
    unit_amount: '1200',
    interval: 'month',
    state: 'paid',
    provider_checkout_id: null,
    checkout_expires_at: null,
    paid_at: '2026-09-18T02:03:04.123456Z',
    refunded_at: null,
    disputed_at: null,
    last_event_at: '2026-09-18T02:03:04.123456Z',
    created_at: '2026-09-18T01:00:00.000001Z',
    updated_at: '2026-09-18T02:03:04.123456Z',
  })]),
  billing_provider_events: Object.freeze([Object.freeze({
    provider: 'fixture-provider',
    event_id: 'event-fixture',
    organization_id: 'org-fixture',
    order_id: '00000000-0000-4000-8000-000000000001',
    event_type: 'paid',
    payload_hash: 'b'.repeat(64),
    occurred_at: null,
    received_at: '2026-09-18T02:03:05.654321Z',
  })]),
})

function billingToc(schema = 'registry_saas', owner = 'registry_migrator') {
  return [
    '; Archive created by pg_dump',
    `100; 1259 51001 TABLE ${schema} billing_orders ${owner}`,
    `101; 0 51001 TABLE DATA ${schema} billing_orders ${owner}`,
    `102; 1259 51002 TABLE ${schema} billing_provider_events ${owner}`,
    `103; 0 51002 TABLE DATA ${schema} billing_provider_events ${owner}`,
    '',
  ].join('\n')
}

function sqlite(path, version, value) {
  const database = new DatabaseSync(path)
  try {
    database.exec(`PRAGMA user_version = ${String(version)}; create table state (value text not null);`)
    database.prepare('insert into state (value) values (?)').run(value)
  } finally {
    database.close()
  }
}

function migratorPostgres() {
  return Object.freeze({
    async query(statement) {
      if (statement.includes('pg_try_advisory')) return { rows: [{ acquired: true }] }
      if (statement === 'begin' || statement === 'commit' || statement === 'rollback'
        || statement.startsWith('lock table ') || statement.startsWith('set local lock_timeout')) return { rows: [] }
      if (statement.includes("select format('%I.%I'")) {
        return { rows: [{ qualified: '"registry_saas"."storage_meta"' }] }
      }
      if (statement.includes('select current_user')) return { rows: [{
        current_user: 'registry_migrator', can_read_all_stats: true, dangerous: false,
      }] }
      if (statement.includes('from pg_namespace')) return { rows: [{ owner: 'registry_migrator' }] }
      if (statement.includes('as invalid_owner')) return { rows: [{ invalid_owner: 0 }] }
      if (statement.includes('as table_name')) return { rows: [
        'storage_meta', 'units', 'unit_globals', 'unit_records',
        'tenancy_meta', 'accounts', 'account_identities', 'organizations', 'organization_memberships',
        'organization_creations', 'organization_invitations', 'billing_orders', 'billing_provider_events',
      ].map(table_name => ({ table_name })) }
      if (statement.includes('as storage_version')) {
        return { rows: [{ storage_version: 2, tenancy_version: 3 }] }
      }
      if (statement.includes('from pg_stat_activity')) return { rows: [{ count: 0 }] }
      if (statement.includes('pg_current_wal_lsn')) return { rows: [{ wal_lsn: '16/B374D848' }] }
      throw new Error('unexpected PostgreSQL fixture query')
    },
    async close() {},
  })
}

function backupPostgres({ extraDefaultAclItems = 0, inspectDefaultAclQuery = () => {},
  inspectQuery = () => {}, billing = BILLING_ROWS } = {}) {
  return Object.freeze({
    async query(statement, values = []) {
      inspectQuery(statement)
      if (statement === 'begin isolation level repeatable read read only'
        || statement === 'commit' || statement === 'rollback') return { rows: [] }
      if (statement.includes('from pg_roles as selected_role')) return { rows: [{
        current_user: 'registry_backup', can_login: true, inherits: false, connection_limit: 2,
        superuser: false, bypass_rls: true,
        create_database: false, create_role: false, replication: false, can_read_all_stats: true,
        unexpected_membership: false, can_create_database_object: false, can_create_temporary_object: false,
      }] }
      if (statement.includes('from pg_database')) {
        return { rows: [{ can_connect: true, can_connect_outside: false, has_other_user_database: false,
          direct_connect: true, invalid_direct: false }] }
      }
      if (statement.includes('has_schema_privilege') && statement.includes('direct_usage')) {
        return { rows: [{ can_use: true, can_create: false, direct_usage: true, invalid_direct: false }] }
      }
      if (statement.includes('from pg_default_acl')) {
        inspectDefaultAclQuery(statement)
        return { rows: [{ total_items: 2 + extraDefaultAclItems, allowed_items: 2, exact_types: 2 }] }
      }
      if (statement.includes("namespace.nspname <> $1")) return { rows: [{ accessible: 0 }] }
      if (statement.includes("relation.relkind in ('r', 'p', 'v', 'm', 'f')")) {
        return { rows: [{ count: 13, missing_select: 0, missing_direct_select: 0,
          invalid_direct: 0, column_acl: 0, writable: 0 }] }
      }
      if (statement.includes("relation.relkind = 'S'")) {
        return { rows: [{ count: 0, missing_select: 0, missing_direct_select: 0,
          invalid_direct: 0, writable: 0 }] }
      }
      if (statement.includes('from pg_sequences')) return { rows: [] }
      if (statement.includes('.billing_orders')) {
        const [cursor, limit] = values
        return { rows: billing.billing_orders.filter(row => cursor === null || row.order_id > cursor)
          .slice(0, limit) }
      }
      if (statement.includes('.billing_provider_events')) {
        const [provider, eventId, limit] = values
        return { rows: billing.billing_provider_events.filter(row => provider === null
          || row.provider > provider || (row.provider === provider && row.event_id > eventId)).slice(0, limit) }
      }
      throw new Error('unexpected registry_backup fixture query')
    },
    async close() {},
  })
}

test('backup role provisioning keeps global default ACLs in its exact scan', () => {
  const sql = readFileSync(new URL('../deploy/postgres/provision-registry-backup-role.sql', import.meta.url), 'utf8')
  const scans = [...sql.matchAll(/from pg_default_acl as defaults([\s\S]*?)(?:\\gexec|;)/gu)]
  assert.equal(scans.length, 2)
  for (const scan of scans) assert.match(scan[1], /left join pg_namespace as namespace/u)
  assert.match(sql, /when defaults\.defaclnamespace = 0 then format/u)
  assert.match(sql, /defaults\.defaclobjtype in \('r', 'S', 'f', 'T', 'n', 'L'\)/u)
  assert.match(sql, /default_acl_count <> 2 or allowed_default_acl_count <> 2/u)
  assert.match(sql, /allowed_default_acl_types <> 2/u)
})

test('backup CLI preserves the explicit quiesced assertion', () => {
  assert.deepEqual(parseCreate([
    '--schema', 'registry_saas', '--quiesced', '/secure/registry-backup',
  ]), {
    schema: 'registry_saas',
    destination: '/secure/registry-backup',
    quiesced: true,
  })
})

test('billing digests are canonical, bounded-query, and sensitive to nulls and microseconds', async () => {
  const queries = []
  const baseline = await readBillingState(backupPostgres({ inspectQuery: query => queries.push(query) }),
    'registry_saas')
  const repeated = await readBillingState(backupPostgres(), 'registry_saas')
  assert.deepEqual(repeated, baseline)
  assert.equal(baseline.tables.billing_orders.rowCount, '1')
  assert.equal(baseline.tables.billing_provider_events.rowCount, '1')
  assert.match(baseline.tables.billing_orders.sha256, /^[0-9a-f]{64}$/u)
  assert.match(queries.find(query => query.includes('.billing_orders')), /limit \$2/u)
  assert.match(queries.find(query => query.includes('.billing_orders')), /HH24:MI:SS\.US/u)
  assert.match(queries.find(query => query.includes('.billing_provider_events')), /collate "C"/u)

  const empty = await readBillingState(backupPostgres({ billing: {
    billing_orders: [], billing_provider_events: [],
  } }), 'registry_saas')
  assert.equal(empty.tables.billing_orders.rowCount, '0')
  assert.equal(empty.tables.billing_provider_events.rowCount, '0')
  assert.notEqual(empty.tables.billing_orders.sha256, baseline.tables.billing_orders.sha256)

  const nullChanged = { ...BILLING_ROWS, billing_orders: [
    { ...BILLING_ROWS.billing_orders[0], paid_at: null },
  ] }
  const nullDigest = await readBillingState(backupPostgres({ billing: nullChanged }), 'registry_saas')
  assert.notEqual(nullDigest.tables.billing_orders.sha256, baseline.tables.billing_orders.sha256)

  const microsecondChanged = { ...BILLING_ROWS, billing_provider_events: [
    { ...BILLING_ROWS.billing_provider_events[0], received_at: '2026-09-18T02:03:05.654322Z' },
  ] }
  const microsecondDigest = await readBillingState(
    backupPostgres({ billing: microsecondChanged }), 'registry_saas')
  assert.notEqual(microsecondDigest.tables.billing_provider_events.sha256,
    baseline.tables.billing_provider_events.sha256)

  const pagedBilling = { ...BILLING_ROWS, billing_orders: Array.from({ length: 257 }, (_, index) => ({
    ...BILLING_ROWS.billing_orders[0],
    order_id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
  })) }
  let orderPages = 0
  const paged = await readBillingState(backupPostgres({ billing: pagedBilling,
    inspectQuery: query => { if (query.includes('.billing_orders')) orderPages += 1 } }), 'registry_saas')
  assert.equal(paged.tables.billing_orders.rowCount, '257')
  assert.equal(orderPages, 2)
})

test('PostgreSQL SaaS backup set is exact, secret-free, independently verifiable, and tamper evident', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-postgres-saas-backup-'))
  try {
    const admission = join(root, 'source-admission.sqlite')
    const outbox = join(root, 'source-outbox.sqlite')
    const destination = join(root, 'backup')
    sqlite(admission, 3, 'admission')
    sqlite(outbox, 7, 'outbox')
    const password = 'fixture-migrator-not-a-real-secret'
    const backupPassword = 'fixture-backup-not-a-real-secret'
    const connectionString = `postgresql://registry_migrator:${password}@127.0.0.1:5432/registry`
    const backupConnectionString = `postgresql://registry_backup:${backupPassword}@127.0.0.1:5432/registry`
    const environment = {
      ...process.env,
      DSH_REGISTRY_POSTGRES_MIGRATOR_URL: connectionString,
      DSH_REGISTRY_POSTGRES_BACKUP_URL: backupConnectionString,
      DSH_REGISTRY_ADMISSION_SQLITE_PATH: admission,
      DSH_REGISTRY_ALERT_OUTBOX_SQLITE_PATH: outbox,
      DSH_REGISTRY_SESSION_SECRET: 'unrelated-runtime-secret',
      REGISTRY_BACKUP_PASSWORD: 'provisioning-secret-must-not-reach-tools',
      PGPASSFILE: join(root, 'must-not-be-used.pgpass'),
    }
    const invocations = []
    const runCommand = async (command, arguments_, options) => {
      invocations.push({ command, arguments_: [...arguments_], environment: { ...options.environment } })
      if (arguments_.length === 1 && arguments_[0] === '--version') {
        return { stdout: `${command} (PostgreSQL) 18.6\n`, stderr: '' }
      }
      if (arguments_.includes('--format=custom')) {
        const fileIndex = arguments_.indexOf('--file')
        assert.notEqual(fileIndex, -1)
        writeFileSync(arguments_[fileIndex + 1], 'PGDMP fixture archive')
        return { stdout: '', stderr: '' }
      }
      if (arguments_[0] === '--list') {
        assert.match(readFileSync(arguments_[1], 'utf8'), /^PGDMP/u)
        return { stdout: billingToc(), stderr: '' }
      }
      throw new Error('unexpected PostgreSQL tool fixture invocation')
    }
    let defaultAclQuery = ''
    await assert.rejects(createBackupSet({
      schema: 'registry_saas',
      destination: join(root, 'global-default-acl-rejected'),
      quiesced: true,
      environment,
      openPostgres: async value => value === backupConnectionString
        ? backupPostgres({
          extraDefaultAclItems: 1,
          inspectDefaultAclQuery: statement => { defaultAclQuery = statement },
        }) : migratorPostgres(),
      runCommand,
    }), /default privileges must be target-only SELECT/u)
    assert.match(defaultAclQuery, /left join pg_namespace/u)
    assert.match(defaultAclQuery, /defaults\.defaclnamespace <> 0/u)
    assert.match(defaultAclQuery, /count\(\*\)::integer as total_items/u)
    const openedConnections = []
    const backupQueries = []
    const created = await createBackupSet({
      schema: 'registry_saas',
      destination,
      quiesced: true,
      environment,
      openPostgres: async (value, applicationName) => {
        openedConnections.push({ value, applicationName })
        return value === backupConnectionString
          ? backupPostgres({ inspectQuery: query => backupQueries.push(query) }) : migratorPostgres()
      },
      runCommand,
    })
    assert.deepEqual(openedConnections.map(value => value.value), [connectionString, backupConnectionString])
    const dump = invocations.find(invocation => invocation.arguments_.includes('--format=custom'))
    assert.ok(dump)
    assert.equal(dump.arguments_.includes('--no-password'), true)
    assert.equal(dump.arguments_.includes('--no-tablespaces'), true)
    assert.equal(dump.arguments_.includes('--no-owner'), false)
    assert.equal(dump.arguments_.includes('--no-acl'), false)
    assert.equal(dump.environment.PGPASSWORD, backupPassword)
    assert.deepEqual(created.files.sort(), ['admission', 'alertOutbox', 'postgres'])
    const snapshotStart = backupQueries.indexOf('begin isolation level repeatable read read only')
    const billingRead = backupQueries.findIndex(query => query.includes('.billing_orders'))
    assert.notEqual(snapshotStart, -1)
    assert.ok(billingRead > snapshotStart)
    assert.ok(backupQueries.indexOf('commit') > billingRead)
    assert.equal(backupQueries.includes('rollback'), false)
    const manifestText = readFileSync(join(destination, 'manifest.json'), 'utf8')
    const manifest = JSON.parse(manifestText)
    assert.deepEqual(Object.keys(manifest).sort(),
      ['billing', 'createdAt', 'files', 'format', 'quiescence', 'schema', 'tools', 'version'])
    assert.deepEqual(Object.keys(manifest.files).sort(), ['admission', 'alertOutbox', 'postgres'])
    assert.equal(manifest.schema, 'registry_saas')
    assert.equal(manifest.version, 2)
    assert.equal(manifest.billing.tables.billing_orders.rowCount, '1')
    assert.equal(manifest.billing.tables.billing_provider_events.rowCount, '1')
    assert.match(manifest.billing.tables.billing_orders.sha256, /^[0-9a-f]{64}$/u)
    assert.equal(manifestText.includes('org-fixture'), false)
    assert.equal(manifestText.includes('idempotency-fixture'), false)
    assert.equal(manifestText.includes(password), false)
    assert.equal(manifestText.includes(backupPassword), false)
    assert.equal(manifestText.includes(connectionString), false)
    assert.equal(manifestText.includes(backupConnectionString), false)
    for (const invocation of invocations) {
      assert.equal(JSON.stringify(invocation.arguments_).includes(password), false)
      assert.equal(JSON.stringify(invocation.arguments_).includes(backupPassword), false)
      assert.equal(JSON.stringify(invocation.arguments_).includes(connectionString), false)
      assert.equal(JSON.stringify(invocation.arguments_).includes(backupConnectionString), false)
      assert.equal('DSH_REGISTRY_POSTGRES_MIGRATOR_URL' in invocation.environment, false)
      assert.equal('DSH_REGISTRY_POSTGRES_BACKUP_URL' in invocation.environment, false)
      assert.equal('DSH_REGISTRY_SESSION_SECRET' in invocation.environment, false)
      assert.equal('REGISTRY_BACKUP_PASSWORD' in invocation.environment, false)
      assert.equal('PGPASSFILE' in invocation.environment, false)
    }
    const restoreStart = invocations.length
    const verified = await verifyBackupSet({ directory: destination, environment, runCommand })
    assert.equal(verified.verified, true)
    assert.equal(verified.schema, 'registry_saas')
    assert.equal(verified.billing.tables.billing_orders.rowCount, '1')
    for (const invocation of invocations.slice(restoreStart)) {
      assert.equal('PGPASSWORD' in invocation.environment, false)
      assert.equal('DSH_REGISTRY_POSTGRES_MIGRATOR_URL' in invocation.environment, false)
      assert.equal('DSH_REGISTRY_POSTGRES_BACKUP_URL' in invocation.environment, false)
    }

    for (const invalidToc of [
      '; TABLE registry_saas billing_orders registry_migrator\n'
        + '200; 1259 60001 TABLE registry_saas billing_orders_shadow registry_migrator\n',
      billingToc('wrong_schema'),
      billingToc('registry_saas', 'wrong_owner'),
      `${billingToc()}104; 1259 51001 TABLE registry_saas billing_orders registry_migrator\n`,
      billingToc().replace('101; 0 51001 TABLE DATA', '101; 0 51999 TABLE DATA'),
    ]) {
      await assert.rejects(verifyBackupSet({
        directory: destination,
        environment,
        runCommand: async (command, arguments_, options) => {
          const result = await runCommand(command, arguments_, options)
          return arguments_[0] === '--list' ? { ...result, stdout: invalidToc } : result
        },
      }), /PostgreSQL archive/u)
    }

    const restored = await verifyRestoredBilling({
      directory: destination,
      environment,
      openPostgres: async value => value === backupConnectionString
        ? backupPostgres() : migratorPostgres(),
      runCommand,
    })
    assert.equal(restored.verified, true)
    assert.equal(restored.billing.tables.billing_orders.rowCount, '1')
    const changedTarget = { ...BILLING_ROWS, billing_provider_events: [
      { ...BILLING_ROWS.billing_provider_events[0], received_at: '2026-09-18T02:03:05.654322Z' },
    ] }
    await assert.rejects(verifyRestoredBilling({
      directory: destination,
      environment,
      openPostgres: async value => value === backupConnectionString
        ? backupPostgres({ billing: changedTarget }) : migratorPostgres(),
      runCommand,
    }), /restored billing_provider_events content differs/u)
    assert.equal(JSON.stringify(restored).includes('org-fixture'), false)
    assert.equal(JSON.stringify(restored).includes(connectionString), false)

    writeFileSync(join(destination, 'manifest.json'), `${JSON.stringify({
      ...manifest,
      billing: { ...manifest.billing, tables: {
        ...manifest.billing.tables,
        billing_orders: { ...manifest.billing.tables.billing_orders, unexpected: true },
      } },
    }, undefined, 2)}\n`)
    await assert.rejects(verifyBackupSet({ directory: destination, environment, runCommand }),
      /billing_orders digest is invalid/u)
    writeFileSync(join(destination, 'manifest.json'), manifestText)

    const redacted = safeMessage(
      new Error(`failed ${connectionString} ${password} ${backupConnectionString} ${backupPassword}`),
      [connectionString, password, backupConnectionString, backupPassword])
    assert.equal(redacted.includes(password), false)
    assert.equal(redacted.includes(backupPassword), false)
    assert.equal(redacted.includes(connectionString), false)
    assert.equal(redacted.includes(backupConnectionString), false)
    appendFileSync(join(destination, 'registry.pgdump'), 'tamper')
    await assert.rejects(verifyBackupSet({ directory: destination, environment, runCommand }),
      /PostgreSQL archive verification failed/u)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
