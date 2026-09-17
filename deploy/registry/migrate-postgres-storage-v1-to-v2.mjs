#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { Pool } from 'pg'

const SCHEMA_NAME = /^[a-z][a-z0-9_]*$/u
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const MIGRATION_LOCK_KEY = createHash('sha256')
  .update('dsh-a2a-registry-postgres-storage-v1-v2', 'utf8')
  .digest().readBigInt64BE(0).toString()
const REGISTRY_APPLICATIONS = ['dsh-a2a-registry', 'dsh-a2a-registry-tenancy']

const HELP = `
为一个明确的 PostgreSQL schema 规划或执行 Registry storage v1 -> v2 原地迁移。

默认只做 plan 并回滚；追加 --execute 才会写入。连接串只从
DSH_REGISTRY_POSTGRES_URL 读取，不接受命令行连接串。

用法：
  node deploy/registry/migrate-postgres-storage-v1-to-v2.mjs \\
    --schema <schema> \\
    --legacy-tenant-id <唯一旧组织 ID> \\
    --expect-units <数量> \\
    --expect-globals <数量> \\
    --expect-records <数量> \\
    [--execute --confirm-quiesced --confirm-backup-verified]

--execute 同时要求两个确认标志，并且数据库中不能存在 Registry 活跃连接。
连接检查只是附加保护，不能证明已停服；执行前仍须由运维人员停止所有 Registry 进程。
不要使用历史版本中硬编码 registry 的 002-tenant-scope-rls.sql。
`.trim()

function fail(message) {
  throw new Error(message)
}

function parseCount(value, name) {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) fail(`${name} must be a non-negative integer`)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed)) fail(`${name} exceeds the safe integer range`)
  return parsed
}

function parseArguments(argv) {
  if (argv.includes('--help') || argv.includes('-h')) return { help: true }
  const valueOptions = new Set([
    '--schema', '--legacy-tenant-id', '--expect-units', '--expect-globals', '--expect-records',
  ])
  const flagOptions = new Set(['--execute', '--confirm-quiesced', '--confirm-backup-verified'])
  const values = new Map()
  const flags = new Set()
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (flagOptions.has(argument)) {
      if (flags.has(argument)) fail(`duplicate ${argument}`)
      flags.add(argument)
      continue
    }
    if (!valueOptions.has(argument)) fail('unknown or positional argument')
    if (values.has(argument)) fail(`duplicate ${argument}`)
    const value = argv[index + 1]
    if (value === undefined || value.startsWith('--')) fail(`missing ${argument}`)
    values.set(argument, value)
    index += 1
  }
  for (const option of valueOptions) if (!values.has(option)) fail(`missing ${option}`)
  const schema = values.get('--schema')
  const legacyTenantId = values.get('--legacy-tenant-id')
  if (!SCHEMA_NAME.test(schema)) fail('schema name is invalid')
  if (!IDENTIFIER.test(legacyTenantId)) fail('legacy tenant ID is invalid')
  const execute = flags.has('--execute')
  if (!execute && (flags.has('--confirm-quiesced') || flags.has('--confirm-backup-verified'))) {
    fail('confirmation flags require --execute')
  }
  if (execute && (!flags.has('--confirm-quiesced') || !flags.has('--confirm-backup-verified'))) {
    fail('--execute requires --confirm-quiesced and --confirm-backup-verified')
  }
  return {
    help: false,
    execute,
    schema,
    legacyTenantId,
    expected: {
      units: parseCount(values.get('--expect-units'), '--expect-units'),
      globals: parseCount(values.get('--expect-globals'), '--expect-globals'),
      records: parseCount(values.get('--expect-records'), '--expect-records'),
    },
  }
}

function quoteIdentifier(value) {
  if (!SCHEMA_NAME.test(value)) fail('schema name is invalid')
  return `"${value}"`
}

function appendDigestValue(hash, value) {
  const bytes = Buffer.from(String(value), 'utf8')
  hash.update(String(bytes.length), 'ascii').update(':', 'ascii').update(bytes).update('\n', 'ascii')
}

function summarize(rows) {
  const hash = createHash('sha256')
  for (const row of rows.units) {
    for (const value of ['unit', row.name, row.version]) appendDigestValue(hash, value)
  }
  for (const row of rows.globals) {
    for (const value of ['global', row.unit, row.value_text]) appendDigestValue(hash, value)
  }
  for (const row of rows.records) {
    for (const value of ['record', row.unit, row.table_name, row.key, row.value_text]) appendDigestValue(hash, value)
  }
  return {
    units: rows.units.length,
    globals: rows.globals.length,
    records: rows.records.length,
    sha256: hash.digest('hex'),
  }
}

async function readStorage(client, schema, tenantId) {
  const qualified = quoteIdentifier(schema)
  const clause = tenantId === undefined ? '' : ' where tenant_id = $1'
  const parameters = tenantId === undefined ? [] : [tenantId]
  const units = await client.query(
    `select name, version from ${qualified}.units${clause} order by name`, parameters)
  const globals = await client.query(
    `select unit, value::text as value_text from ${qualified}.unit_globals${clause} order by unit`, parameters)
  const records = await client.query(
    `select unit, table_name, key, value::text as value_text
     from ${qualified}.unit_records${clause} order by unit, table_name, key`, parameters)
  return { units: units.rows, globals: globals.rows, records: records.rows }
}

function requireExpected(summary, expected) {
  for (const name of ['units', 'globals', 'records']) {
    if (summary[name] !== expected[name]) fail(`source ${name} count differs from the explicit expectation`)
  }
}

function requireOrganization(rows, legacyTenantId) {
  const ownerRows = rows.records.filter(row => row.unit === 'a2a_registry_ingest'
    && row.table_name === 'owner' && row.key === 'organization')
  if (ownerRows.length !== 1) fail('source has no unique Registry organization owner record')
  let owner
  try { owner = JSON.parse(ownerRows[0].value_text) } catch {
    fail('source Registry organization owner record is malformed')
  }
  if (owner === null || typeof owner !== 'object' || owner.organizationId !== legacyTenantId) {
    fail('source organization ID differs from the explicit legacy tenant ID')
  }
}

async function activeRegistryConnections(client) {
  const result = await client.query(
    `select count(*)::integer as count from pg_stat_activity
     where datname = current_database() and pid <> pg_backend_pid()
       and application_name = any($1::text[])`, [REGISTRY_APPLICATIONS])
  return result.rows[0]?.count ?? 0
}

async function requireSafeRole(client) {
  const result = await client.query(
    'select rolsuper, rolbypassrls from pg_roles where rolname = current_user')
  if (result.rows.length !== 1 || result.rows[0]?.rolsuper || result.rows[0]?.rolbypassrls) {
    fail('migration requires a non-superuser role without BYPASSRLS')
  }
}

async function acquireMigrationLock(client) {
  const result = await client.query(
    'select pg_try_advisory_xact_lock($1::bigint) as acquired', [MIGRATION_LOCK_KEY])
  if (result.rows[0]?.acquired !== true) fail('another Registry storage migration is running')
}

async function requireRelations(client, schema) {
  for (const table of ['storage_meta', 'units', 'unit_globals', 'unit_records']) {
    const result = await client.query('select to_regclass($1) is not null as present', [`${schema}.${table}`])
    if (result.rows[0]?.present !== true) fail(`required table ${schema}.${table} is missing`)
  }
}

async function requireVersion(client, schema, expected) {
  const qualified = quoteIdentifier(schema)
  const result = await client.query(
    `select schema_version from ${qualified}.storage_meta where singleton = true`)
  if (result.rows.length !== 1 || result.rows[0]?.schema_version !== expected) {
    fail(`expected storage schema version ${String(expected)}`)
  }
}

async function requireColumns(client, schema, version) {
  const expected = version === 1 ? {
    units: ['name', 'version'],
    unit_globals: ['unit', 'value'],
    unit_records: ['unit', 'table_name', 'key', 'value'],
  } : {
    units: ['tenant_id', 'name', 'version'],
    unit_globals: ['tenant_id', 'unit', 'value'],
    unit_records: ['tenant_id', 'unit', 'table_name', 'key', 'value'],
  }
  const result = await client.query(
    `select table_name, column_name from information_schema.columns
     where table_schema = $1 and table_name = any($2::text[]) order by table_name, ordinal_position`,
    [schema, Object.keys(expected)],
  )
  const actual = new Map(Object.keys(expected).map(table => [table, []]))
  for (const row of result.rows) actual.get(row.table_name)?.push(row.column_name)
  for (const [table, columns] of Object.entries(expected)) {
    if (JSON.stringify(actual.get(table)?.toSorted()) !== JSON.stringify(columns.toSorted())) {
      fail(`unexpected ${schema}.${table} layout`)
    }
  }
}

function normalizeConstraint(definition, schema) {
  return definition.replaceAll('"', '').replaceAll(`${schema}.`, '').replace(/\s+/gu, ' ').trim()
}

async function requireConstraints(client, schema, version) {
  const expected = version === 1 ? new Map([
    ['units_pkey', ['p', 'PRIMARY KEY (name)']],
    ['unit_globals_pkey', ['p', 'PRIMARY KEY (unit)']],
    ['unit_globals_unit_fkey', ['f', 'FOREIGN KEY (unit) REFERENCES units(name) ON DELETE CASCADE']],
    ['unit_records_pkey', ['p', 'PRIMARY KEY (unit, table_name, key)']],
    ['unit_records_unit_fkey', ['f', 'FOREIGN KEY (unit) REFERENCES units(name) ON DELETE CASCADE']],
  ]) : new Map([
    ['units_pkey', ['p', 'PRIMARY KEY (tenant_id, name)']],
    ['unit_globals_pkey', ['p', 'PRIMARY KEY (tenant_id, unit)']],
    ['unit_globals_unit_fkey', ['f', 'FOREIGN KEY (tenant_id, unit) REFERENCES units(tenant_id, name) ON DELETE CASCADE']],
    ['unit_records_pkey', ['p', 'PRIMARY KEY (tenant_id, unit, table_name, key)']],
    ['unit_records_unit_fkey', ['f', 'FOREIGN KEY (tenant_id, unit) REFERENCES units(tenant_id, name) ON DELETE CASCADE']],
  ])
  const result = await client.query(
    `select c.conname, c.contype, pg_get_constraintdef(c.oid) as definition
     from pg_constraint as c
     join pg_class as relation on relation.oid = c.conrelid
     join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = $1 and c.conname = any($2::text[])`,
    [schema, [...expected.keys()]],
  )
  if (result.rows.length !== expected.size) fail('required storage constraints are missing')
  for (const row of result.rows) {
    const requirement = expected.get(row.conname)
    if (requirement === undefined || row.contype !== requirement[0]
      || normalizeConstraint(row.definition, schema) !== requirement[1]) {
      fail('storage constraints differ from the expected schema')
    }
  }
}

async function requireForcedRls(client, schema) {
  const tables = ['units', 'unit_globals', 'unit_records']
  const relations = await client.query(
    `select relation.relname, relation.relrowsecurity, relation.relforcerowsecurity
     from pg_class as relation join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = $1 and relation.relname = any($2::text[])`, [schema, tables])
  if (relations.rows.length !== tables.length
    || relations.rows.some(row => row.relrowsecurity !== true || row.relforcerowsecurity !== true)) {
    fail('storage tables do not all enforce RLS')
  }
  const policies = await client.query(
    `select tablename, policyname, cmd, qual, with_check
     from pg_policies where schemaname = $1 and tablename = any($2::text[])`, [schema, tables])
  if (policies.rows.length !== tables.length || policies.rows.some(row => row.policyname !== 'tenant_isolation'
    || row.cmd !== 'ALL' || !String(row.qual).includes('app.tenant_id')
    || !String(row.with_check).includes('app.tenant_id'))) {
    fail('storage tenant RLS policies are incomplete')
  }
}

async function lockStorageTables(client, schema) {
  const qualified = quoteIdentifier(schema)
  await client.query(`lock table ${qualified}.storage_meta, ${qualified}.unit_globals,
    ${qualified}.unit_records, ${qualified}.units in access exclusive mode nowait`)
}

async function migrateSchema(client, schema, legacyTenantId) {
  const qualified = quoteIdentifier(schema)
  await client.query(`alter table ${qualified}.units add column tenant_id text`)
  await client.query(`alter table ${qualified}.unit_globals add column tenant_id text`)
  await client.query(`alter table ${qualified}.unit_records add column tenant_id text`)
  await client.query(`update ${qualified}.units set tenant_id = $1`, [legacyTenantId])
  await client.query(`update ${qualified}.unit_globals set tenant_id = $1`, [legacyTenantId])
  await client.query(`update ${qualified}.unit_records set tenant_id = $1`, [legacyTenantId])
  for (const table of ['units', 'unit_globals', 'unit_records']) {
    await client.query(`alter table ${qualified}.${quoteIdentifier(table)} alter column tenant_id set not null`)
  }
  await client.query(`alter table ${qualified}.unit_globals drop constraint unit_globals_unit_fkey`)
  await client.query(`alter table ${qualified}.unit_records drop constraint unit_records_unit_fkey`)
  await client.query(`alter table ${qualified}.unit_globals drop constraint unit_globals_pkey`)
  await client.query(`alter table ${qualified}.unit_records drop constraint unit_records_pkey`)
  await client.query(`alter table ${qualified}.units drop constraint units_pkey`)
  await client.query(`alter table ${qualified}.units
    add constraint units_pkey primary key (tenant_id, name)`)
  await client.query(`alter table ${qualified}.unit_globals
    add constraint unit_globals_pkey primary key (tenant_id, unit),
    add constraint unit_globals_unit_fkey foreign key (tenant_id, unit)
      references ${qualified}.units (tenant_id, name) on delete cascade`)
  await client.query(`alter table ${qualified}.unit_records
    add constraint unit_records_pkey primary key (tenant_id, unit, table_name, key),
    add constraint unit_records_unit_fkey foreign key (tenant_id, unit)
      references ${qualified}.units (tenant_id, name) on delete cascade`)
  for (const table of ['units', 'unit_globals', 'unit_records']) {
    await client.query(`alter table ${qualified}.${quoteIdentifier(table)} enable row level security`)
    await client.query(`alter table ${qualified}.${quoteIdentifier(table)} force row level security`)
    await client.query(`drop policy if exists tenant_isolation on ${qualified}.${quoteIdentifier(table)}`)
    await client.query(`create policy tenant_isolation on ${qualified}.${quoteIdentifier(table)}
      using (tenant_id = current_setting('app.tenant_id', true))
      with check (tenant_id = current_setting('app.tenant_id', true))`)
  }
  await client.query(
    `update ${qualified}.storage_meta set schema_version = 2 where singleton = true`)
}

async function preflight(client, input) {
  await requireRelations(client, input.schema)
  await requireVersion(client, input.schema, 1)
  await requireColumns(client, input.schema, 1)
  await requireConstraints(client, input.schema, 1)
  const rows = await readStorage(client, input.schema)
  const summary = summarize(rows)
  requireExpected(summary, input.expected)
  requireOrganization(rows, input.legacyTenantId)
  return summary
}

async function run(input, connectionString) {
  const pool = new Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 30_000,
    statement_timeout: 60_000,
    idle_in_transaction_session_timeout: 60_000,
    application_name: 'dsh-registry-storage-v1-v2-migration',
  })
  const client = await pool.connect()
  let transaction = false
  try {
    await client.query(input.execute
      ? 'begin isolation level serializable'
      : 'begin isolation level repeatable read read only')
    transaction = true
    await client.query("set local lock_timeout = '2s'")
    await client.query("set local statement_timeout = '60s'")
    await requireSafeRole(client)
    await acquireMigrationLock(client)

    if (!input.execute) {
      const before = await preflight(client, input)
      const connections = await activeRegistryConnections(client)
      await client.query('rollback')
      transaction = false
      return {
        mode: 'plan',
        schema: input.schema,
        legacyTenantId: input.legacyTenantId,
        schemaVersion: 1,
        summary: before,
        checks: {
          expectedCounts: true,
          organizationMatches: true,
          advisoryLock: true,
          observedRegistryConnections: connections,
          noRegistryConnectionsObserved: connections === 0,
        },
        operatorQuiescenceStillRequired: true,
        committed: false,
      }
    }

    if (await activeRegistryConnections(client) !== 0) {
      fail('Registry database connections are still active; refusing --execute')
    }
    await requireRelations(client, input.schema)
    await lockStorageTables(client, input.schema)
    if (await activeRegistryConnections(client) !== 0) {
      fail('Registry connected during migration startup; refusing --execute')
    }
    const before = await preflight(client, input)
    await client.query(`select set_config('app.tenant_id', $1, true)`, [input.legacyTenantId])
    await migrateSchema(client, input.schema, input.legacyTenantId)
    await requireVersion(client, input.schema, 2)
    await requireColumns(client, input.schema, 2)
    await requireConstraints(client, input.schema, 2)
    await requireForcedRls(client, input.schema)
    const after = summarize(await readStorage(client, input.schema, input.legacyTenantId))
    requireExpected(after, input.expected)
    if (before.sha256 !== after.sha256) fail('post-migration storage digest differs from the source digest')
    if (await activeRegistryConnections(client) !== 0) {
      fail('Registry connected before migration commit; rolling back')
    }
    await client.query('commit')
    transaction = false
    return {
      mode: 'execute',
      schema: input.schema,
      legacyTenantId: input.legacyTenantId,
      before,
      after,
      checks: {
        expectedCounts: true,
        organizationMatches: true,
        constraints: true,
        forcedRls: true,
        digestMatches: true,
        observedRegistryConnections: 0,
        operatorAttestedQuiescence: true,
        operatorAttestedBackupVerification: true,
      },
      committed: true,
    }
  } catch (error) {
    if (transaction) {
      try { await client.query('rollback') } catch (rollbackError) {
        throw new AggregateError([error, rollbackError], 'migration rollback failed')
      }
    }
    throw error
  } finally {
    client.release()
    await pool.end().catch(() => undefined)
  }
}

function safeMessage(error) {
  const message = error instanceof Error ? error.message : 'unknown migration failure'
  return message.replace(/(postgres(?:ql)?:\/\/)[^@\s]+@/giu, '$1<redacted>@')
}

async function main() {
  const input = parseArguments(process.argv.slice(2))
  if (input.help) {
    process.stdout.write(`${HELP}\n`)
    return
  }
  const connectionString = process.env.DSH_REGISTRY_POSTGRES_URL
  if (connectionString === undefined || connectionString.length === 0) {
    fail('DSH_REGISTRY_POSTGRES_URL is required')
  }
  process.stdout.write(`${JSON.stringify(await run(input, connectionString))}\n`)
}

await main().catch((error) => {
  process.stderr.write(`registry-postgres-migration: ${safeMessage(error)}\n`)
  process.exitCode = 1
})
