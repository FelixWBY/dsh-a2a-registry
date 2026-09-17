#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import { chmodSync, createReadStream, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync,
  renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { backup, DatabaseSync } from 'node:sqlite'
import { Pool } from 'pg'

const FORMAT = 'dsh-registry-postgres-saas-backup-set'
const VERSION = 2
const MANIFEST = 'manifest.json'
const ARCHIVE = 'registry.pgdump'
const MAX_MANIFEST_BYTES = 64 * 1024
const MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
const COMMAND_TIMEOUT_MS = 30 * 60 * 1000
const VERSION_TIMEOUT_MS = 30 * 1000
const BILLING_DIGEST_FORMAT = 'dsh-registry-billing-digest'
const BILLING_DIGEST_VERSION = 1
const BILLING_PAGE_SIZE = 256
const MAX_BILLING_CANONICAL_BYTES = 64 * 1024
const SCHEMA_NAME = /^[a-z][a-z0-9_]*$/u
const SHA256 = /^[0-9a-f]{64}$/u
const REGISTRY_APPLICATIONS = ['dsh-a2a-registry', 'dsh-a2a-registry-tenancy']
const REGISTRY_TABLES = Object.freeze([
  'storage_meta', 'units', 'unit_globals', 'unit_records',
  'tenancy_meta', 'accounts', 'account_identities', 'organizations', 'organization_memberships',
  'organization_creations', 'organization_invitations', 'billing_orders', 'billing_provider_events',
])
const BILLING_TABLES = Object.freeze({
  billing_orders: Object.freeze([
    ['order_id', 'uuid'], ['organization_id', 'text'], ['idempotency_key', 'text'],
    ['request_hash', 'text'], ['provider', 'text'], ['plan_id', 'text'], ['currency', 'text'],
    ['unit_amount', 'bigint'], ['interval', 'text'], ['state', 'text'], ['provider_checkout_id', 'text'],
    ['checkout_expires_at', 'timestamptz'], ['paid_at', 'timestamptz'], ['refunded_at', 'timestamptz'],
    ['disputed_at', 'timestamptz'], ['last_event_at', 'timestamptz'], ['created_at', 'timestamptz'],
    ['updated_at', 'timestamptz'],
  ].map(column => Object.freeze(column))),
  billing_provider_events: Object.freeze([
    ['provider', 'text'], ['event_id', 'text'], ['organization_id', 'text'], ['order_id', 'uuid'],
    ['event_type', 'text'], ['payload_hash', 'text'], ['occurred_at', 'timestamptz'],
    ['received_at', 'timestamptz'],
  ].map(column => Object.freeze(column))),
})
const SQLITE_DATABASES = Object.freeze([
  { role: 'admission', environment: 'DSH_REGISTRY_ADMISSION_SQLITE_PATH', file: 'admission.sqlite' },
  { role: 'alertOutbox', environment: 'DSH_REGISTRY_ALERT_OUTBOX_SQLITE_PATH', file: 'alert-outbox.sqlite' },
])

function fail(message) {
  throw new Error(`registry-postgres-saas-backup: ${message}`)
}

function absolutePath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`)
  }
  return value
}

function exactObject(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) fail(`${label} is invalid`)
  return value
}

function inside(root, path) {
  const selected = relative(root, path)
  return selected === '' || (!selected.startsWith('..') && !isAbsolute(selected))
}

function fileObservation(path) {
  if (!existsSync(path)) return null
  const value = statSync(path)
  if (!value.isFile()) fail('SQLite database or sidecar is not a file')
  return { sizeBytes: value.size, modifiedAtMs: value.mtimeMs }
}

async function durableFileObservation(path) {
  const observed = fileObservation(path)
  return observed === null ? null : Object.freeze({ ...observed, sha256: await digest(path) })
}

async function sourceObservation(path) {
  const wal = fileObservation(`${path}-wal`)
  fileObservation(`${path}-shm`)
  return Object.freeze({ database: await durableFileObservation(path),
    wal: wal?.sizeBytes === 0 ? null : await durableFileObservation(`${path}-wal`) })
}

function sameObservation(left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function removeTransientSidecars(path) {
  const wal = fileObservation(`${path}-wal`)
  if (wal !== null && wal.sizeBytes !== 0) fail('backup produced a non-empty WAL sidecar')
  rmSync(`${path}-wal`, { force: true })
  rmSync(`${path}-shm`, { force: true })
}

function databaseFacts(database) {
  const check = database.prepare('PRAGMA quick_check').all()
  if (check.length !== 1 || check[0]?.quick_check !== 'ok') fail('SQLite quick_check failed')
  const userVersion = database.prepare('PRAGMA user_version').get()?.user_version
  const pages = database.prepare('PRAGMA page_count').get()?.page_count
  if (!Number.isSafeInteger(userVersion) || userVersion < 0 || !Number.isSafeInteger(pages) || pages < 0) {
    fail('SQLite metadata is invalid')
  }
  return { userVersion, pages }
}

async function digest(path) {
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(path)) hash.update(chunk)
  return hash.digest('hex')
}

function sourcesFromEnvironment(environment) {
  const sources = SQLITE_DATABASES.map(database => {
    const selected = environment[database.environment]
    if (typeof selected !== 'string' || selected.length === 0) fail(`${database.environment} is required`)
    const path = absolutePath(selected, database.environment)
    if (!existsSync(path) || !lstatSync(path).isFile()) fail(`${database.environment} is not a database file`)
    return Object.freeze({ ...database, path })
  })
  if (new Set(sources.map(source => source.path.toLowerCase())).size !== sources.length) {
    fail('SQLite source paths must be distinct')
  }
  return sources
}

async function backupSqlite(source, destination) {
  let sourceDatabase
  let storedDatabase
  try {
    sourceDatabase = new DatabaseSync(source, { readOnly: true })
    const sourceFacts = databaseFacts(sourceDatabase)
    const copiedPages = await backup(sourceDatabase, destination, { rate: 256 })
    storedDatabase = new DatabaseSync(destination, { readOnly: true })
    const storedFacts = databaseFacts(storedDatabase)
    if (sourceFacts.userVersion !== storedFacts.userVersion || sourceFacts.pages !== storedFacts.pages) {
      fail('SQLite backup metadata differs from source')
    }
    storedDatabase.close()
    storedDatabase = undefined
    removeTransientSidecars(destination)
    chmodSync(destination, 0o600)
    const info = statSync(destination)
    return Object.freeze({ file: basename(destination), format: 'sqlite', sha256: await digest(destination),
      sizeBytes: info.size, copiedPages, userVersion: storedFacts.userVersion, pages: storedFacts.pages })
  } finally {
    storedDatabase?.close()
    sourceDatabase?.close()
  }
}

function decoded(value, label) {
  let result
  try { result = decodeURIComponent(value) } catch { fail(`${label} is invalid`) }
  if (result.length === 0 || result.includes('\0')) fail(`${label} is invalid`)
  return result
}

function postgresConnection(environment, environmentName, expectedUser) {
  const raw = environment[environmentName]?.trim() ?? ''
  if (raw.length === 0) fail(`${environmentName} is required`)
  let parsed
  try { parsed = new URL(raw) } catch { fail(`${environmentName} is invalid`) }
  const user = decoded(parsed.username, `${environmentName} user`)
  const password = decoded(parsed.password, `${environmentName} password`)
  const database = decoded(parsed.pathname.slice(1), `${environmentName} database`)
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol) || parsed.hostname.length === 0
    || user.toLowerCase() !== expectedUser || parsed.pathname.length <= 1
    || parsed.search.length > 0 || parsed.hash.length > 0) {
    fail(`${environmentName} must be an absolute PostgreSQL URL for ${expectedUser}`)
  }
  const host = parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']')
    ? parsed.hostname.slice(1, -1) : parsed.hostname
  return Object.freeze({ raw, user, password, database, host,
    port: parsed.port.length === 0 ? undefined : parsed.port })
}

function samePostgresTarget(left, right) {
  return left.host.toLowerCase() === right.host.toLowerCase()
    && (left.port ?? '5432') === (right.port ?? '5432')
    && left.database === right.database
}

function cleanEnvironment(environment) {
  const selected = {}
  const exact = new Set(['PATH', 'Path', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'HOME',
    'USERPROFILE', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LANGUAGE'])
  for (const [name, value] of Object.entries(environment)) {
    if (typeof value === 'string' && (exact.has(name) || name.startsWith('LC_') || name.startsWith('PGSSL'))) {
      selected[name] = value
    }
  }
  return selected
}

function dumpEnvironment(environment, connection) {
  return {
    ...cleanEnvironment(environment),
    PGHOST: connection.host,
    ...(connection.port === undefined ? {} : { PGPORT: connection.port }),
    PGUSER: connection.user,
    PGPASSWORD: connection.password,
    PGDATABASE: connection.database,
    PGAPPNAME: 'dsh-registry-postgres-saas-backup',
  }
}

function toolPath(environment, environmentName, executable) {
  const selected = environment[environmentName]?.trim()
  if (selected === undefined || selected.length === 0) return executable
  const path = absolutePath(selected, environmentName)
  const allowed = new Set([executable.toLowerCase(), `${executable.toLowerCase()}.exe`])
  if (!allowed.has(basename(path).toLowerCase()) || !existsSync(path) || !lstatSync(path).isFile()) {
    fail(`${environmentName} must point to the ${executable} executable`)
  }
  return path
}

function redact(value, secrets = []) {
  let result = String(value).replace(/(postgres(?:ql)?:\/\/)[^@\s]+@/giu, '$1<redacted>@')
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length > 0) result = result.split(secret).join('<redacted>')
  }
  return result
}

export function safeMessage(error, secrets = []) {
  return redact(error instanceof Error ? error.message : 'unknown PostgreSQL SaaS backup failure', secrets)
}

function connectionPassword(value) {
  try {
    const parsed = new URL(value ?? '')
    return parsed.password.length === 0 ? undefined : decodeURIComponent(parsed.password)
  } catch {
    return undefined
  }
}

export async function runBoundedCommand(command, arguments_, options) {
  const { environment, timeoutMs, label, secrets = [] } = options
  return await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, arguments_, {
      env: environment,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })
    const chunks = { stdout: [], stderr: [] }
    let bytes = 0
    let forcedFailure
    let settled = false
    let timer
    const finish = (error, value) => {
      if (settled) return
      settled = true
      if (timer !== undefined) clearTimeout(timer)
      if (error === undefined) resolvePromise(value)
      else rejectPromise(error)
    }
    const receive = stream => chunk => {
      bytes += chunk.length
      if (bytes > MAX_COMMAND_OUTPUT_BYTES) {
        forcedFailure = new Error(`${label} output exceeded the safety limit`)
        child.kill()
        return
      }
      chunks[stream].push(chunk)
    }
    child.stdout.on('data', receive('stdout'))
    child.stderr.on('data', receive('stderr'))
    child.once('error', error => finish(new Error(`${label} could not start: ${redact(error.message, secrets)}`)))
    child.once('close', (code, signal) => {
      if (forcedFailure !== undefined) return finish(forcedFailure)
      const stdout = Buffer.concat(chunks.stdout).toString('utf8')
      const stderr = Buffer.concat(chunks.stderr).toString('utf8')
      if (code !== 0) {
        const detail = redact(`${stderr}\n${stdout}`, secrets).trim()
        return finish(new Error(`${label} failed${signal === null ? '' : ` (${signal})`}${detail.length === 0 ? '' : `: ${detail}`}`))
      }
      finish(undefined, { stdout, stderr })
    })
    timer = setTimeout(() => {
      forcedFailure = new Error(`${label} exceeded the time limit`)
      child.kill()
    }, timeoutMs)
    timer.unref()
  })
}

async function toolVersion(command, label, environment, runCommand) {
  const result = await runCommand(command, ['--version'], {
    environment: cleanEnvironment(environment), timeoutMs: VERSION_TIMEOUT_MS, label,
  })
  const value = `${result.stdout}\n${result.stderr}`.trim()
  if (value.length === 0 || value.length > 256 || /[\r\n]/u.test(value)) fail(`${label} returned an invalid version`)
  return value
}

async function defaultOpenPostgres(connectionString, applicationName) {
  const pool = new Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 10_000,
    statement_timeout: 15_000,
    application_name: applicationName,
  })
  let client
  try {
    client = await pool.connect()
  } catch (error) {
    await pool.end().catch(() => {})
    throw error
  }
  return Object.freeze({
    query: (...arguments_) => client.query(...arguments_),
    close: async () => {
      client.release()
      await pool.end()
    },
  })
}

async function acquireBackupLock(database, schema) {
  const result = await database.query(
    `select pg_try_advisory_xact_lock(
       hashtextextended('dsh-registry-schema:' || $1::text, 0)
     ) as acquired`, [schema])
  if (result.rows.length !== 1 || result.rows[0]?.acquired !== true) {
    fail('another offline operation is using the target schema')
  }
}

async function lockSchemaTables(database, schema) {
  const result = await database.query(
    `select format('%I.%I', namespace.nspname, relation.relname) as qualified
     from pg_class as relation
     join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = $1 and relation.relkind in ('r', 'p')
     order by relation.oid`, [schema])
  if (!Array.isArray(result.rows)) fail('target schema relation inventory is invalid')
  for (const row of result.rows) {
    if (typeof row?.qualified !== 'string' || row.qualified.length === 0) {
      fail('target schema relation inventory is invalid')
    }
    await database.query(`lock table ${row.qualified} in share mode`)
  }
}

function canonicalTimestamp(column) {
  return `case when ${column} is null then null else
    to_char(${column} at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end`
}

const BILLING_TYPE_MARKERS = Object.freeze({ text: 1, uuid: 2, bigint: 3, timestamptz: 4 })

function uint64(value, label) {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffff_ffff_ffff_ffffn) fail(`${label} is invalid`)
  const encoded = Buffer.allocUnsafe(8)
  encoded.writeBigUInt64BE(value)
  return encoded
}

async function digestBillingTable(table, columns, readPage) {
  const hash = createHash('sha256')
  hash.update(`${BILLING_DIGEST_FORMAT}\0${String(BILLING_DIGEST_VERSION)}\0${table}\0`, 'utf8')
  for (const [column, type] of columns) hash.update(`${column}\0${type}\0`, 'utf8')
  let cursor
  let rowCount = 0n
  while (true) {
    const page = await readPage(cursor)
    if (!Array.isArray(page) || page.length > BILLING_PAGE_SIZE) fail(`${table} digest page is invalid`)
    for (const row of page) {
      hash.update(Buffer.from([0x52]))
      for (const [column, type] of columns) {
        const marker = BILLING_TYPE_MARKERS[type]
        if (marker === undefined) fail(`${table} digest column type is invalid`)
        const value = row?.[column]
        hash.update(Buffer.from([marker, value === null ? 0 : 1]))
        if (value === null) continue
        if (typeof value !== 'string') fail(`${table} digest row is invalid`)
        const bytes = Buffer.from(value, 'utf8')
        if (bytes.length > MAX_BILLING_CANONICAL_BYTES) {
          fail(`${table} contains a row field that cannot be safely summarized`)
        }
        hash.update(uint64(BigInt(bytes.length), `${table} field length`))
        hash.update(bytes)
      }
      rowCount += 1n
      if (rowCount > 0xffff_ffff_ffff_ffffn) fail(`${table} row count exceeds the safety limit`)
    }
    if (page.length < BILLING_PAGE_SIZE) break
    const next = page.at(-1)?.cursor
    if (!Array.isArray(next) || next.length === 0 || next.some(value => typeof value !== 'string')
      || JSON.stringify(next) === JSON.stringify(cursor)) fail(`${table} digest cursor is invalid`)
    cursor = next
  }
  hash.update(Buffer.from([0x45]))
  hash.update(uint64(rowCount, `${table} row count`))
  return Object.freeze({ columns: Object.freeze(columns.map(([column, type]) => `${column}:${type}`)),
    rowCount: rowCount.toString(10), sha256: hash.digest('hex') })
}

export async function readBillingState(database, schema) {
  if (typeof schema !== 'string' || !SCHEMA_NAME.test(schema)) fail('schema name is invalid')
  const qualified = `"${schema}"`
  const orderColumns = BILLING_TABLES.billing_orders
  const eventColumns = BILLING_TABLES.billing_provider_events
  const orders = await digestBillingTable('billing_orders', orderColumns, async cursor => {
    const result = await database.query(
      `select order_id::text as order_id, organization_id, idempotency_key, request_hash, provider, plan_id,
         currency, unit_amount::text as unit_amount, interval, state, provider_checkout_id,
         ${canonicalTimestamp('checkout_expires_at')} as checkout_expires_at,
         ${canonicalTimestamp('paid_at')} as paid_at,
         ${canonicalTimestamp('refunded_at')} as refunded_at,
         ${canonicalTimestamp('disputed_at')} as disputed_at,
         ${canonicalTimestamp('last_event_at')} as last_event_at,
         ${canonicalTimestamp('created_at')} as created_at,
         ${canonicalTimestamp('updated_at')} as updated_at
       from ${qualified}.billing_orders
       where $1::uuid is null or order_id > $1::uuid
       order by order_id
       limit $2`, [cursor?.[0] ?? null, BILLING_PAGE_SIZE])
    return result.rows.map(row => ({ ...row, cursor: [row.order_id] }))
  })
  const events = await digestBillingTable('billing_provider_events', eventColumns, async cursor => {
    const result = await database.query(
      `select provider, event_id, organization_id, order_id::text as order_id, event_type, payload_hash,
         ${canonicalTimestamp('occurred_at')} as occurred_at,
         ${canonicalTimestamp('received_at')} as received_at
       from ${qualified}.billing_provider_events
       where $1::text is null
         or provider collate "C" > ($1::text collate "C")
         or (provider collate "C" = ($1::text collate "C")
           and event_id collate "C" > ($2::text collate "C"))
       order by provider collate "C", event_id collate "C"
       limit $3`,
      [cursor?.[0] ?? null, cursor?.[1] ?? null, BILLING_PAGE_SIZE])
    return result.rows.map(row => ({ ...row, cursor: [row.provider, row.event_id] }))
  })
  return Object.freeze({
    format: BILLING_DIGEST_FORMAT,
    version: BILLING_DIGEST_VERSION,
    tables: Object.freeze({ billing_orders: orders, billing_provider_events: events }),
  })
}

async function postgresState(database, schema) {
  const role = await database.query(
    `select current_user as current_user,
       pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER') as can_read_all_stats,
       (exists (
         select 1 from pg_roles as role
         where (role.rolname = current_user
                or pg_has_role(current_user, role.oid, 'MEMBER')
                or pg_has_role(current_user, role.oid, 'SET'))
           and (role.rolsuper or role.rolbypassrls or role.rolcreatedb
                or role.rolcreaterole or role.rolreplication
                or (role.rolname <> current_user and role.rolname <> 'pg_read_all_stats'))
       ) or has_database_privilege(current_user, current_database(), 'CREATE')
         or has_database_privilege(current_user, current_database(), 'TEMP')) as dangerous`)
  if (role.rows.length !== 1 || role.rows[0]?.current_user !== 'registry_migrator'
    || role.rows[0]?.can_read_all_stats !== true || role.rows[0]?.dangerous !== false) {
    fail('backup requires the restricted registry_migrator role with pg_read_all_stats')
  }
  const namespace = await database.query(
    `select pg_get_userbyid(namespace.nspowner) as owner
     from pg_namespace as namespace where namespace.nspname = $1`, [schema])
  if (namespace.rows.length !== 1 || namespace.rows[0]?.owner !== 'registry_migrator') {
    fail('target schema must exist and be owned by registry_migrator')
  }
  const ownership = await database.query(
    `select count(*) filter (where pg_get_userbyid(relation.relowner) <> 'registry_migrator')::integer
       as invalid_owner
     from pg_class as relation
     join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = $1 and relation.relkind in ('r', 'p', 'i', 'I', 'S', 'v', 'm', 'f')`,
    [schema])
  if (ownership.rows.length !== 1 || ownership.rows[0]?.invalid_owner !== 0) {
    fail('every target schema relation must be owned by registry_migrator')
  }
  const tables = await database.query(
    `select relation.relname as table_name
     from pg_class as relation
     join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = $1 and relation.relkind in ('r', 'p')
       and relation.relname = any($2::text[])
     order by relation.relname`, [schema, REGISTRY_TABLES])
  if (tables.rows.length !== REGISTRY_TABLES.length
    || REGISTRY_TABLES.some(name => !tables.rows.some(row => row.table_name === name))) {
    fail('target schema is missing a required Registry table')
  }
  const qualified = `"${schema}"`
  const versions = await database.query(
    `select (select schema_version from ${qualified}.storage_meta where singleton = true)
       as storage_version,
       (select schema_version from ${qualified}.tenancy_meta where singleton = true)
       as tenancy_version`)
  if (versions.rows.length !== 1 || versions.rows[0]?.storage_version !== 2
    || versions.rows[0]?.tenancy_version !== 3) {
    fail('target schema must contain storage schema version 2 and tenancy schema version 3')
  }
  const active = await database.query(
    `select count(*)::integer as count
     from pg_stat_activity
     where datname = current_database() and pid <> pg_backend_pid()
       and backend_type = 'client backend'
       and (usename = 'registry_app' or application_name = any($1::text[]))`,
    [REGISTRY_APPLICATIONS])
  if (active.rows.length !== 1 || active.rows[0]?.count !== 0) {
    fail('Registry runtime database connections are still active')
  }
}

async function backupRoleState(database, schema) {
  const role = await database.query(
    `select selected_role.rolname as current_user,
       selected_role.rolcanlogin as can_login,
       selected_role.rolinherit as inherits,
       selected_role.rolconnlimit as connection_limit,
       selected_role.rolsuper as superuser,
       selected_role.rolbypassrls as bypass_rls,
       selected_role.rolcreatedb as create_database,
       selected_role.rolcreaterole as create_role,
       selected_role.rolreplication as replication,
       exists (
         select 1 from pg_auth_members as membership
         where membership.member = selected_role.oid or membership.roleid = selected_role.oid
       ) as unexpected_membership,
       has_database_privilege(current_user, current_database(), 'CREATE') as can_create_database_object,
       has_database_privilege(current_user, current_database(), 'TEMP') as can_create_temporary_object
     from pg_roles as selected_role where selected_role.rolname = current_user`)
  const selectedRole = role.rows[0]
  if (role.rows.length !== 1 || selectedRole?.current_user !== 'registry_backup'
    || selectedRole.can_login !== true || selectedRole.inherits !== false
    || selectedRole.connection_limit !== 2 || selectedRole.superuser !== false
    || selectedRole.bypass_rls !== true || selectedRole.create_database !== false
    || selectedRole.create_role !== false || selectedRole.replication !== false
    || selectedRole.unexpected_membership !== false
    || selectedRole.can_create_database_object !== false
    || selectedRole.can_create_temporary_object !== false) {
    fail('backup connection must use the restricted registry_backup role')
  }
  const databaseAccess = await database.query(
    `select has_database_privilege(current_user, database.oid, 'CONNECT') as can_connect,
       exists (
         select 1 from pg_database as other_database
         where other_database.datname <> current_database()
           and has_database_privilege(current_user, other_database.oid, 'CONNECT')
       ) as can_connect_outside,
       exists (
         select 1 from pg_database as other_database
         where other_database.datname <> current_database()
           and other_database.datname <> 'postgres' and not other_database.datistemplate
       ) as has_other_user_database,
       exists (
         select 1 from aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) as acl
         where acl.grantee = (select oid from pg_roles where rolname = current_user)
           and acl.privilege_type = 'CONNECT' and not acl.is_grantable
       ) as direct_connect,
       exists (
         select 1 from aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) as acl
         where acl.grantee = (select oid from pg_roles where rolname = current_user)
           and (acl.privilege_type <> 'CONNECT' or acl.is_grantable)
       ) as invalid_direct
     from pg_database as database where database.datname = current_database()`)
  if (databaseAccess.rows.length !== 1 || databaseAccess.rows[0]?.can_connect !== true
    || databaseAccess.rows[0]?.can_connect_outside !== false
    || databaseAccess.rows[0]?.has_other_user_database !== false
    || databaseAccess.rows[0]?.direct_connect !== true || databaseAccess.rows[0]?.invalid_direct !== false) {
    fail('registry_backup must have only a direct non-grantable CONNECT privilege on the selected database')
  }
  const namespace = await database.query(
    `select has_schema_privilege(current_user, namespace.oid, 'USAGE') as can_use,
       has_schema_privilege(current_user, namespace.oid, 'CREATE') as can_create,
       exists (
         select 1 from aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) as acl
         where acl.grantee = (select oid from pg_roles where rolname = current_user)
           and acl.privilege_type = 'USAGE' and not acl.is_grantable
       ) as direct_usage,
       exists (
         select 1 from aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) as acl
         where acl.grantee = (select oid from pg_roles where rolname = current_user)
           and (acl.privilege_type <> 'USAGE' or acl.is_grantable)
       ) as invalid_direct
     from pg_namespace as namespace where namespace.nspname = $1`, [schema])
  if (namespace.rows.length !== 1 || namespace.rows[0]?.can_use !== true
    || namespace.rows[0]?.can_create !== false || namespace.rows[0]?.direct_usage !== true
    || namespace.rows[0]?.invalid_direct !== false) {
    fail('registry_backup must have USAGE but not CREATE on the target schema')
  }
  const relations = await database.query(
    `select count(*)::integer as count,
       count(*) filter (where not has_table_privilege(current_user, relation.oid, 'SELECT'))::integer
         as missing_select,
       count(*) filter (where not exists (
         select 1 from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) as acl
         where acl.grantee = (select oid from pg_roles where rolname = current_user)
           and acl.privilege_type = 'SELECT' and not acl.is_grantable
       ))::integer as missing_direct_select,
       count(*) filter (where exists (
         select 1 from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) as acl
         where acl.grantee = (select oid from pg_roles where rolname = current_user)
           and (acl.privilege_type <> 'SELECT' or acl.is_grantable)
       ))::integer as invalid_direct,
       count(*) filter (where exists (
         select 1 from pg_attribute as attribute
         cross join lateral aclexplode(attribute.attacl) as acl
         where attribute.attrelid = relation.oid and attribute.attnum > 0
           and not attribute.attisdropped
           and acl.grantee = (select oid from pg_roles where rolname = current_user)
       ))::integer as column_acl,
       count(*) filter (where
         has_table_privilege(current_user, relation.oid, 'INSERT')
         or has_table_privilege(current_user, relation.oid, 'UPDATE')
         or has_table_privilege(current_user, relation.oid, 'DELETE')
         or has_table_privilege(current_user, relation.oid, 'TRUNCATE')
         or has_table_privilege(current_user, relation.oid, 'REFERENCES')
         or has_table_privilege(current_user, relation.oid, 'TRIGGER')
         or has_table_privilege(current_user, relation.oid, 'MAINTAIN')
         or has_any_column_privilege(current_user, relation.oid, 'INSERT')
         or has_any_column_privilege(current_user, relation.oid, 'UPDATE')
         or has_any_column_privilege(current_user, relation.oid, 'REFERENCES'))::integer as writable
     from pg_class as relation
     join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = $1 and relation.relkind in ('r', 'p', 'v', 'm', 'f')`, [schema])
  if (relations.rows.length !== 1 || !Number.isInteger(relations.rows[0]?.count)
    || relations.rows[0]?.missing_select !== 0 || relations.rows[0]?.missing_direct_select !== 0
    || relations.rows[0]?.invalid_direct !== 0 || relations.rows[0]?.column_acl !== 0
    || relations.rows[0]?.writable !== 0) {
    fail('registry_backup must have read-only access to every target schema relation')
  }
  const sequences = await database.query(
    `select count(*)::integer as count,
       count(*) filter (where not has_sequence_privilege(current_user, relation.oid, 'SELECT'))::integer
         as missing_select,
       count(*) filter (where not exists (
         select 1 from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) as acl
         where acl.grantee = (select oid from pg_roles where rolname = current_user)
           and acl.privilege_type = 'SELECT' and not acl.is_grantable
       ))::integer as missing_direct_select,
       count(*) filter (where exists (
         select 1 from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) as acl
         where acl.grantee = (select oid from pg_roles where rolname = current_user)
           and (acl.privilege_type <> 'SELECT' or acl.is_grantable)
       ))::integer as invalid_direct,
       count(*) filter (where has_sequence_privilege(current_user, relation.oid, 'USAGE')
         or has_sequence_privilege(current_user, relation.oid, 'UPDATE'))::integer as writable
     from pg_class as relation
     join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname = $1 and relation.relkind = 'S'`, [schema])
  if (sequences.rows.length !== 1 || !Number.isInteger(sequences.rows[0]?.count)
    || sequences.rows[0]?.missing_select !== 0 || sequences.rows[0]?.missing_direct_select !== 0
    || sequences.rows[0]?.invalid_direct !== 0 || sequences.rows[0]?.writable !== 0) {
    fail('registry_backup must have read-only access to every target schema sequence')
  }
  const outside = await database.query(
    `select count(*) filter (where
       has_table_privilege(current_user, relation.oid, 'SELECT')
       or has_table_privilege(current_user, relation.oid, 'INSERT')
       or has_table_privilege(current_user, relation.oid, 'UPDATE')
       or has_table_privilege(current_user, relation.oid, 'DELETE')
       or has_table_privilege(current_user, relation.oid, 'TRUNCATE')
       or has_table_privilege(current_user, relation.oid, 'REFERENCES')
       or has_table_privilege(current_user, relation.oid, 'TRIGGER')
       or has_table_privilege(current_user, relation.oid, 'MAINTAIN')
       or has_any_column_privilege(current_user, relation.oid, 'SELECT')
       or has_any_column_privilege(current_user, relation.oid, 'INSERT')
       or has_any_column_privilege(current_user, relation.oid, 'UPDATE')
       or has_any_column_privilege(current_user, relation.oid, 'REFERENCES'))::integer as accessible
     from pg_class as relation
     join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname <> $1
       and namespace.nspname <> 'information_schema'
       and namespace.nspname !~ '^pg_' and relation.relkind in ('r', 'p', 'v', 'm', 'f')`, [schema])
  if (outside.rows.length !== 1 || outside.rows[0]?.accessible !== 0) {
    fail('registry_backup must not access relations outside the target schema')
  }
  const outsideSequences = await database.query(
    `select count(*) filter (where
       has_sequence_privilege(current_user, relation.oid, 'SELECT')
       or has_sequence_privilege(current_user, relation.oid, 'USAGE')
       or has_sequence_privilege(current_user, relation.oid, 'UPDATE'))::integer as accessible
     from pg_class as relation
     join pg_namespace as namespace on namespace.oid = relation.relnamespace
     where namespace.nspname <> $1
       and namespace.nspname <> 'information_schema'
       and namespace.nspname !~ '^pg_' and relation.relkind = 'S'`, [schema])
  if (outsideSequences.rows.length !== 1 || outsideSequences.rows[0]?.accessible !== 0) {
    fail('registry_backup must not access sequences outside the target schema')
  }
  const outsideSchemas = await database.query(
    `select count(*) filter (where
       has_schema_privilege(current_user, namespace.oid, 'USAGE')
       or has_schema_privilege(current_user, namespace.oid, 'CREATE'))::integer as accessible
     from pg_namespace as namespace
     where namespace.nspname <> $1
       and namespace.nspname <> 'information_schema'
       and namespace.nspname !~ '^pg_'`, [schema])
  if (outsideSchemas.rows.length !== 1 || outsideSchemas.rows[0]?.accessible !== 0) {
    fail('registry_backup must not access schemas outside the target schema')
  }
  const defaults = await database.query(
    `select count(*)::integer as total_items,
       count(*) filter (where defaults.defaclnamespace <> 0
         and owner.rolname = 'registry_migrator' and namespace.nspname = $1
         and defaults.defaclobjtype in ('r', 'S')
         and acl.privilege_type = 'SELECT' and not acl.is_grantable)::integer as allowed_items,
       count(distinct defaults.defaclobjtype) filter (where
         defaults.defaclnamespace <> 0
         and owner.rolname = 'registry_migrator' and namespace.nspname = $1
         and defaults.defaclobjtype in ('r', 'S')
         and acl.privilege_type = 'SELECT' and not acl.is_grantable)::integer as exact_types
     from pg_default_acl as defaults
     left join pg_roles as owner on owner.oid = defaults.defaclrole
     left join pg_namespace as namespace on namespace.oid = defaults.defaclnamespace
     cross join lateral aclexplode(defaults.defaclacl) as acl
     where acl.grantee = (select oid from pg_roles where rolname = current_user)`, [schema])
  if (defaults.rows.length !== 1 || defaults.rows[0]?.total_items !== 2
    || defaults.rows[0]?.allowed_items !== 2
    || defaults.rows[0]?.exact_types !== 2) {
    fail('registry_backup default privileges must be target-only SELECT')
  }
  const sequenceState = await database.query(
    `select sequencename, last_value::text as last_value
     from pg_sequences where schemaname = $1 order by sequencename`, [schema])
  if (!Array.isArray(sequenceState.rows)
    || sequenceState.rows.some(row => typeof row?.sequencename !== 'string'
      || !(row.last_value === null || typeof row.last_value === 'string'))) {
    fail('target schema sequence state is invalid')
  }
  return Object.freeze({ sequenceState: JSON.stringify(sequenceState.rows) })
}

function archiveRecord(path) {
  const info = statSync(path)
  if (!info.isFile() || info.size <= 0) fail('pg_dump did not produce a custom archive')
  return info
}

function manifestDocument(schema, tools, files, billing) {
  return Object.freeze({
    format: FORMAT,
    version: VERSION,
    createdAt: new Date().toISOString(),
    schema,
    quiescence: 'operator-asserted-runtime-stopped-and-sources-stable',
    tools: Object.freeze({ node: process.version, pgDump: tools.pgDump, pgRestore: tools.pgRestore }),
    files: Object.freeze(files),
    billing,
  })
}

function requireBillingArchiveToc(value, schema) {
  if (typeof value !== 'string') fail('pg_restore table of contents is invalid')
  const found = new Map(Object.keys(BILLING_TABLES).flatMap(table => [
    [`TABLE\0${table}`, []], [`TABLE DATA\0${table}`, []],
  ]))
  const dumpIds = new Set()
  for (const line of value.split(/\r?\n/u)) {
    const match = /^(\d+);\s+(\d+)\s+(\d+)\s+(TABLE DATA|TABLE)\s+(\S+)\s+(\S+)\s+(\S+)\s*$/u.exec(line)
    if (match === null || !Object.hasOwn(BILLING_TABLES, match[6])) continue
    const [, dumpId, catalogOid, objectOid, descriptor, entrySchema, table, owner] = match
    if (entrySchema !== schema || owner !== 'registry_migrator'
      || (descriptor === 'TABLE' ? catalogOid !== '1259' : catalogOid !== '0')
      || !/^[1-9][0-9]*$/u.test(dumpId) || !/^[1-9][0-9]*$/u.test(objectOid)
      || dumpIds.has(dumpId)) {
      fail('PostgreSQL archive contains an invalid billing table entry')
    }
    dumpIds.add(dumpId)
    found.get(`${descriptor}\0${table}`).push(objectOid)
  }
  if ([...found.values()].some(entries => entries.length !== 1)
    || Object.keys(BILLING_TABLES).some(table =>
      found.get(`TABLE\0${table}`)[0] !== found.get(`TABLE DATA\0${table}`)[0])) {
    fail('PostgreSQL archive must contain exactly one TABLE and TABLE DATA entry for each billing table')
  }
}

export async function createBackupSet({ schema, destination, quiesced, environment = process.env,
  openPostgres = defaultOpenPostgres, runCommand = runBoundedCommand }) {
  if (typeof schema !== 'string' || !SCHEMA_NAME.test(schema)) fail('schema name is invalid')
  if (quiesced !== true) fail('quiesced operator assertion is required')
  const selectedDestination = absolutePath(destination, 'destination directory')
  if (existsSync(selectedDestination)) fail('destination directory already exists')
  const parent = dirname(selectedDestination)
  if (!existsSync(parent) || !lstatSync(parent).isDirectory()) {
    fail('destination parent directory must already exist with restricted access')
  }
  const sources = sourcesFromEnvironment(environment)
  if (sources.some(source => inside(selectedDestination, source.path))) {
    fail('destination cannot contain a SQLite source database')
  }
  const migratorConnection = postgresConnection(environment,
    'DSH_REGISTRY_POSTGRES_MIGRATOR_URL', 'registry_migrator')
  const backupConnection = postgresConnection(environment,
    'DSH_REGISTRY_POSTGRES_BACKUP_URL', 'registry_backup')
  if (!samePostgresTarget(migratorConnection, backupConnection)) {
    fail('migrator and backup URLs must select the same PostgreSQL server and database')
  }
  const pgDump = toolPath(environment, 'DSH_REGISTRY_PG_DUMP_PATH', 'pg_dump')
  const pgRestore = toolPath(environment, 'DSH_REGISTRY_PG_RESTORE_PATH', 'pg_restore')
  const partial = `${selectedDestination}.partial-${randomUUID()}`
  mkdirSync(partial, { mode: 0o700 })
  let database
  let backupDatabase
  let transaction = false
  let backupTransaction = false
  let primaryError
  try {
    const tools = {
      pgDump: await toolVersion(pgDump, 'pg_dump --version', environment, runCommand),
      pgRestore: await toolVersion(pgRestore, 'pg_restore --version', environment, runCommand),
    }
    database = await openPostgres(migratorConnection.raw,
      'dsh-registry-postgres-saas-backup-guard')
    backupDatabase = await openPostgres(backupConnection.raw,
      'dsh-registry-postgres-saas-backup-reader')
    await postgresState(database, schema)
    await backupRoleState(backupDatabase, schema)
    await database.query('begin')
    transaction = true
    await database.query("set local lock_timeout = '10s'")
    await acquireBackupLock(database, schema)
    await lockSchemaTables(database, schema)
    await postgresState(database, schema)
    await backupDatabase.query('begin isolation level repeatable read read only')
    backupTransaction = true
    const beforeBackup = await backupRoleState(backupDatabase, schema)
    const billing = await readBillingState(backupDatabase, schema)
    await backupDatabase.query('commit')
    backupTransaction = false
    const beforeSqlite = new Map(await Promise.all(sources.map(async source =>
      [source.role, await sourceObservation(source.path)])))
    const archivePath = join(partial, ARCHIVE)
    await runCommand(pgDump,
      ['--format=custom', '--no-tablespaces', '--no-password', '--schema', schema,
        '--file', archivePath], {
        environment: dumpEnvironment(environment, backupConnection), timeoutMs: COMMAND_TIMEOUT_MS,
        label: 'pg_dump', secrets: [backupConnection.raw, backupConnection.password,
          migratorConnection.raw, migratorConnection.password],
      })
    const files = {}
    const archiveInfo = archiveRecord(archivePath)
    chmodSync(archivePath, 0o600)
    files.postgres = Object.freeze({ file: ARCHIVE, format: 'postgresql-custom',
      sha256: await digest(archivePath), sizeBytes: archiveInfo.size })
    for (const source of sources) {
      files[source.role] = await backupSqlite(source.path, join(partial, source.file))
    }
    const archiveToc = await runCommand(pgRestore, ['--list', archivePath], {
      environment: cleanEnvironment(environment), timeoutMs: COMMAND_TIMEOUT_MS, label: 'pg_restore --list',
    })
    requireBillingArchiveToc(archiveToc.stdout, schema)
    await postgresState(database, schema)
    const afterBackup = await backupRoleState(backupDatabase, schema)
    if (beforeBackup.sequenceState !== afterBackup.sequenceState) {
      fail('PostgreSQL sequences changed during the asserted quiescent backup')
    }
    for (const source of sources) {
      if (!sameObservation(beforeSqlite.get(source.role), await sourceObservation(source.path))) {
        fail(`${source.role} changed during the asserted quiescent backup`)
      }
    }
    const manifest = manifestDocument(schema, tools, files, billing)
    const document = `${JSON.stringify(manifest, undefined, 2)}\n`
    if (Buffer.byteLength(document, 'utf8') > MAX_MANIFEST_BYTES) fail('manifest exceeds the size limit')
    const manifestPath = join(partial, MANIFEST)
    writeFileSync(manifestPath, document, { flag: 'wx', mode: 0o600 })
    for (const source of sources) {
      if (!sameObservation(beforeSqlite.get(source.role), await sourceObservation(source.path))) {
        fail(`${source.role} changed before the quiescent backup could be published`)
      }
    }
    await database.query('commit')
    transaction = false
    await backupDatabase.close()
    backupDatabase = undefined
    await database.close()
    database = undefined
    renameSync(partial, selectedDestination)
    return Object.freeze({ created: true, destination: selectedDestination,
      manifest: join(selectedDestination, MANIFEST), schema, files: Object.keys(files) })
  } catch (error) {
    primaryError = error
    if (backupTransaction) {
      try { await backupDatabase?.query('rollback') } catch { /* Preserve the primary backup failure. */ }
      backupTransaction = false
    }
    if (transaction) {
      try { await database?.query('rollback') } catch { /* Preserve the primary backup failure. */ }
      transaction = false
    }
    rmSync(partial, { recursive: true, force: true })
    throw error
  } finally {
    let closeError
    if (database !== undefined) {
      try { await database.close() } catch (error) {
        if (primaryError === undefined) closeError = error
      }
    }
    if (backupDatabase !== undefined) {
      try { await backupDatabase.close() } catch (error) {
        if (primaryError === undefined && closeError === undefined) closeError = error
      }
    }
    if (closeError !== undefined) throw closeError
  }
}

function validToolVersion(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\r\n]/u.test(value)
}

function readBillingManifest(value) {
  exactObject(value, ['format', 'version', 'tables'], 'billing digest')
  if (value.format !== BILLING_DIGEST_FORMAT || value.version !== BILLING_DIGEST_VERSION) {
    fail('billing digest header is invalid')
  }
  exactObject(value.tables, Object.keys(BILLING_TABLES), 'billing digest tables')
  const tables = {}
  for (const [table, columns] of Object.entries(BILLING_TABLES)) {
    const record = exactObject(value.tables[table], ['columns', 'rowCount', 'sha256'], `${table} digest`)
    const expectedColumns = columns.map(([column, type]) => `${column}:${type}`)
    if (!Array.isArray(record.columns) || record.columns.length !== expectedColumns.length
      || record.columns.some((column, index) => column !== expectedColumns[index])
      || typeof record.rowCount !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(record.rowCount)
      || BigInt(record.rowCount) > 0xffff_ffff_ffff_ffffn
      || typeof record.sha256 !== 'string' || !SHA256.test(record.sha256)) {
      fail(`${table} digest is invalid`)
    }
    tables[table] = Object.freeze({ columns: Object.freeze([...record.columns]),
      rowCount: record.rowCount, sha256: record.sha256 })
  }
  return Object.freeze({ format: value.format, version: value.version, tables: Object.freeze(tables) })
}

function readManifest(directory) {
  const manifestPath = join(directory, MANIFEST)
  if (!existsSync(manifestPath) || !lstatSync(manifestPath).isFile()
    || statSync(manifestPath).size > MAX_MANIFEST_BYTES) fail('manifest is missing or invalid')
  let manifest
  try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) } catch { fail('manifest is invalid') }
  exactObject(manifest,
    ['format', 'version', 'createdAt', 'schema', 'quiescence', 'tools', 'files', 'billing'], 'manifest')
  if (manifest.format !== FORMAT || manifest.version !== VERSION || Number.isNaN(Date.parse(manifest.createdAt))
    || !SCHEMA_NAME.test(manifest.schema)
    || manifest.quiescence !== 'operator-asserted-runtime-stopped-and-sources-stable') {
    fail('manifest header is invalid')
  }
  exactObject(manifest.tools, ['node', 'pgDump', 'pgRestore'], 'tool versions')
  if (!validToolVersion(manifest.tools.node) || !validToolVersion(manifest.tools.pgDump)
    || !validToolVersion(manifest.tools.pgRestore)) fail('tool versions are invalid')
  exactObject(manifest.files, ['postgres', ...SQLITE_DATABASES.map(database => database.role)], 'file map')
  manifest.billing = readBillingManifest(manifest.billing)
  return manifest
}

function verifyFileRecord(directory, value, expectedFile, expectedFormat, label) {
  const record = exactObject(value, ['file', 'format', 'sha256', 'sizeBytes'], `${label} record`)
  if (record.file !== expectedFile || record.format !== expectedFormat || !SHA256.test(record.sha256)
    || !Number.isSafeInteger(record.sizeBytes) || record.sizeBytes <= 0) fail(`${label} record is invalid`)
  const path = resolve(directory, record.file)
  if (!inside(directory, path) || !existsSync(path) || !lstatSync(path).isFile()) fail(`${label} file is missing`)
  return { path, record }
}

async function verifySqliteRecord(directory, value, database) {
  const record = exactObject(value,
    ['file', 'format', 'sha256', 'sizeBytes', 'copiedPages', 'userVersion', 'pages'], `${database.role} record`)
  if (record.file !== database.file || record.format !== 'sqlite' || !SHA256.test(record.sha256)
    || !Number.isSafeInteger(record.sizeBytes) || record.sizeBytes <= 0
    || !Number.isSafeInteger(record.copiedPages) || record.copiedPages < 0
    || !Number.isSafeInteger(record.userVersion) || record.userVersion < 0
    || !Number.isSafeInteger(record.pages) || record.pages < 0) fail(`${database.role} record is invalid`)
  const path = resolve(directory, record.file)
  if (!inside(directory, path) || !existsSync(path) || !lstatSync(path).isFile()) {
    fail(`${database.role} backup is missing`)
  }
  if (existsSync(`${path}-wal`) || existsSync(`${path}-shm`)) {
    fail(`${database.role} backup contains an unexpected SQLite sidecar`)
  }
  const stored = new DatabaseSync(path, { readOnly: true })
  let facts
  try { facts = databaseFacts(stored) } finally {
    stored.close()
    removeTransientSidecars(path)
  }
  const info = statSync(path)
  if (facts.userVersion !== record.userVersion || facts.pages !== record.pages
    || info.size !== record.sizeBytes || await digest(path) !== record.sha256) {
    fail(`${database.role} backup verification failed`)
  }
  return Object.freeze({ userVersion: facts.userVersion, pages: facts.pages, sizeBytes: info.size })
}

export async function verifyBackupSet({ directory, environment = process.env, runCommand = runBoundedCommand }) {
  const selectedDirectory = absolutePath(directory, 'backup directory')
  if (!existsSync(selectedDirectory) || !lstatSync(selectedDirectory).isDirectory()) {
    fail('backup directory is missing')
  }
  const manifest = readManifest(selectedDirectory)
  const postgres = verifyFileRecord(selectedDirectory, manifest.files.postgres,
    ARCHIVE, 'postgresql-custom', 'PostgreSQL archive')
  const archiveInfo = statSync(postgres.path)
  if (archiveInfo.size !== postgres.record.sizeBytes || await digest(postgres.path) !== postgres.record.sha256) {
    fail('PostgreSQL archive verification failed')
  }
  const sqlite = {}
  for (const database of SQLITE_DATABASES) {
    sqlite[database.role] = await verifySqliteRecord(selectedDirectory, manifest.files[database.role], database)
  }
  const pgRestore = toolPath(environment, 'DSH_REGISTRY_PG_RESTORE_PATH', 'pg_restore')
  const pgRestoreVersion = await toolVersion(pgRestore, 'pg_restore --version', environment, runCommand)
  const archiveToc = await runCommand(pgRestore, ['--list', postgres.path], {
    environment: cleanEnvironment(environment), timeoutMs: COMMAND_TIMEOUT_MS, label: 'pg_restore --list',
  })
  requireBillingArchiveToc(archiveToc.stdout, manifest.schema)
  return Object.freeze({ verified: true, directory: selectedDirectory, createdAt: manifest.createdAt,
    schema: manifest.schema, pgRestoreVersion, billing: manifest.billing, files: Object.freeze({
      postgres: Object.freeze({ sizeBytes: archiveInfo.size }), ...sqlite,
    }) })
}

function requireMatchingBillingState(expected, actual) {
  for (const table of Object.keys(BILLING_TABLES)) {
    const expectedTable = expected.tables[table]
    const actualTable = actual.tables[table]
    if (actualTable.rowCount !== expectedTable.rowCount || actualTable.sha256 !== expectedTable.sha256) {
      fail(`restored ${table} content differs from the backup manifest`)
    }
  }
}

export async function verifyRestoredBilling({ directory, environment = process.env,
  openPostgres = defaultOpenPostgres, runCommand = runBoundedCommand }) {
  const offline = await verifyBackupSet({ directory, environment, runCommand })
  const migratorConnection = postgresConnection(environment,
    'DSH_REGISTRY_POSTGRES_MIGRATOR_URL', 'registry_migrator')
  const backupConnection = postgresConnection(environment,
    'DSH_REGISTRY_POSTGRES_BACKUP_URL', 'registry_backup')
  if (!samePostgresTarget(migratorConnection, backupConnection)) {
    fail('migrator and backup URLs must select the same PostgreSQL server and database')
  }
  let database
  let backupDatabase
  let transaction = false
  let backupTransaction = false
  let primaryError
  try {
    database = await openPostgres(migratorConnection.raw,
      'dsh-registry-postgres-saas-restored-billing-guard')
    backupDatabase = await openPostgres(backupConnection.raw,
      'dsh-registry-postgres-saas-restored-billing-reader')
    await postgresState(database, offline.schema)
    await backupRoleState(backupDatabase, offline.schema)
    await database.query('begin')
    transaction = true
    await database.query("set local lock_timeout = '10s'")
    await acquireBackupLock(database, offline.schema)
    await lockSchemaTables(database, offline.schema)
    await postgresState(database, offline.schema)
    await backupDatabase.query('begin isolation level repeatable read read only')
    backupTransaction = true
    await backupRoleState(backupDatabase, offline.schema)
    const actual = await readBillingState(backupDatabase, offline.schema)
    requireMatchingBillingState(offline.billing, actual)
    await backupDatabase.query('commit')
    backupTransaction = false
    await database.query('commit')
    transaction = false
    return Object.freeze({ verified: true, directory: offline.directory, schema: offline.schema, billing: actual })
  } catch (error) {
    primaryError = error
    if (backupTransaction) {
      try { await backupDatabase?.query('rollback') } catch { /* Preserve the primary verification failure. */ }
      backupTransaction = false
    }
    if (transaction) {
      try { await database?.query('rollback') } catch { /* Preserve the primary verification failure. */ }
      transaction = false
    }
    throw error
  } finally {
    let closeError
    if (database !== undefined) {
      try { await database.close() } catch (error) {
        if (primaryError === undefined) closeError = error
      }
    }
    if (backupDatabase !== undefined) {
      try { await backupDatabase.close() } catch (error) {
        if (primaryError === undefined && closeError === undefined) closeError = error
      }
    }
    if (closeError !== undefined) throw closeError
  }
}

export function parseCreate(arguments_) {
  let schema
  let quiesced = false
  let destination
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index]
    if (argument === '--schema') {
      if (schema !== undefined) fail('duplicate --schema')
      schema = arguments_[index + 1]
      if (schema === undefined || schema.startsWith('--')) fail('missing --schema')
      index += 1
    } else if (argument === '--quiesced') {
      if (quiesced) fail('duplicate --quiesced')
      quiesced = true
    } else if (argument.startsWith('--') || destination !== undefined) {
      fail('unknown or duplicate create argument')
    } else {
      destination = argument
    }
  }
  if (schema === undefined || destination === undefined || !quiesced) {
    fail('usage: create --schema <schema> --quiesced <absolute-new-directory>')
  }
  return { schema, destination, quiesced }
}

export async function main(arguments_ = process.argv.slice(2), environment = process.env) {
  const [command, ...rest] = arguments_
  if (command === 'create') {
    const result = await createBackupSet({ ...parseCreate(rest), environment })
    process.stdout.write(`${JSON.stringify(result)}\n`)
  } else if (command === 'verify') {
    const [directory, ...extra] = rest
    if (directory === undefined || extra.length !== 0) fail('usage: verify <absolute-backup-directory>')
    const result = await verifyBackupSet({ directory, environment })
    process.stdout.write(`${JSON.stringify(result)}\n`)
  } else if (command === 'verify-restored') {
    const [directory, ...extra] = rest
    if (directory === undefined || extra.length !== 0) fail('usage: verify-restored <absolute-backup-directory>')
    const result = await verifyRestoredBilling({ directory, environment })
    process.stdout.write(`${JSON.stringify(result)}\n`)
  } else {
    fail('usage: create --schema <schema> --quiesced <absolute-new-directory> | verify <absolute-backup-directory> | verify-restored <absolute-backup-directory>')
  }
}

const invoked = process.argv[1]
if (invoked !== undefined
  && realpathSync.native(resolve(invoked)) === realpathSync.native(fileURLToPath(import.meta.url))) {
  await main().catch((error) => {
    process.stderr.write(`${safeMessage(error, [process.env.DSH_REGISTRY_POSTGRES_MIGRATOR_URL,
      process.env.DSH_REGISTRY_POSTGRES_BACKUP_URL,
      connectionPassword(process.env.DSH_REGISTRY_POSTGRES_MIGRATOR_URL),
      connectionPassword(process.env.DSH_REGISTRY_POSTGRES_BACKUP_URL),
      process.env.REGISTRY_BACKUP_PASSWORD])}\n`)
    process.exitCode = 1
  })
}
