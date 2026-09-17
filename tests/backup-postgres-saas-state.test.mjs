import assert from 'node:assert/strict'
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'

import { createBackupSet, parseCreate, safeMessage,
  verifyBackupSet } from '../deploy/registry/backup-postgres-saas-state.mjs'

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
        'organization_creations', 'organization_invitations',
      ].map(table_name => ({ table_name })) }
      if (statement.includes('as storage_version')) {
        return { rows: [{ storage_version: 2, tenancy_version: 2 }] }
      }
      if (statement.includes('from pg_stat_activity')) return { rows: [{ count: 0 }] }
      if (statement.includes('pg_current_wal_lsn')) return { rows: [{ wal_lsn: '16/B374D848' }] }
      throw new Error('unexpected PostgreSQL fixture query')
    },
    async close() {},
  })
}

function backupPostgres({ extraDefaultAclItems = 0, inspectDefaultAclQuery = () => {} } = {}) {
  return Object.freeze({
    async query(statement) {
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
        return { rows: [{ count: 11, missing_select: 0, missing_direct_select: 0,
          invalid_direct: 0, column_acl: 0, writable: 0 }] }
      }
      if (statement.includes("relation.relkind = 'S'")) {
        return { rows: [{ count: 0, missing_select: 0, missing_direct_select: 0,
          invalid_direct: 0, writable: 0 }] }
      }
      if (statement.includes('from pg_sequences')) return { rows: [] }
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
        return { stdout: '; Archive created by pg_dump\n', stderr: '' }
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
    const created = await createBackupSet({
      schema: 'registry_saas',
      destination,
      quiesced: true,
      environment,
      openPostgres: async (value, applicationName) => {
        openedConnections.push({ value, applicationName })
        return value === backupConnectionString ? backupPostgres() : migratorPostgres()
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
    const manifestText = readFileSync(join(destination, 'manifest.json'), 'utf8')
    const manifest = JSON.parse(manifestText)
    assert.deepEqual(Object.keys(manifest).sort(),
      ['createdAt', 'files', 'format', 'quiescence', 'schema', 'tools', 'version'])
    assert.deepEqual(Object.keys(manifest.files).sort(), ['admission', 'alertOutbox', 'postgres'])
    assert.equal(manifest.schema, 'registry_saas')
    assert.equal(manifest.version, 1)
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
    for (const invocation of invocations.slice(restoreStart)) {
      assert.equal('PGPASSWORD' in invocation.environment, false)
      assert.equal('DSH_REGISTRY_POSTGRES_MIGRATOR_URL' in invocation.environment, false)
      assert.equal('DSH_REGISTRY_POSTGRES_BACKUP_URL' in invocation.environment, false)
    }
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
