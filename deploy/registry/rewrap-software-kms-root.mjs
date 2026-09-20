#!/usr/bin/env node
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import Storage from '@deepseek-ai/dsh-storage'
import { DomainFacility } from '@deepseek-ai/dsh-storage-domain'
import { Pool } from 'pg'
import {
  openSoftwareLocalDisclosureKeyStore,
  softwareLocalDisclosureKeyDomainName,
  SoftwareLocalKmsError,
} from '@deepseek-ai/dsh-a2a-registry-kms-software'
import {
  DISCLOSURE_PREVIOUS_ROOT_KEY_ENV,
  DISCLOSURE_ROOT_KEY_ENV,
  parseDisclosureRootKey,
} from '@deepseek-ai/dsh-registry-kms-software-app'
import {
  fingerprintTenancyPolicies,
  matchesExpectedTenancyPolicies,
  TENANCY_POLICY_CATALOG_QUERY,
  TENANCY_POLICY_DEPARSE_QUOTE_ALL_IDENTIFIERS,
  TENANCY_POLICY_DEPARSE_SEARCH_PATH,
  TENANCY_POLICY_DEPARSE_SETTINGS_QUERY,
  TENANCY_POLICY_TABLE_NAMES,
} from '@deepseek-ai/dsh-registry-app/src/tenancy-postgres.ts'

const ACTIVE_ROOT_KEY_ID_ENV = 'DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID'
const PREVIOUS_ROOT_KEY_ID_ENV = 'DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID'
const MIGRATOR_URL_ENV = 'DSH_REGISTRY_POSTGRES_MIGRATOR_URL'
const RUNTIME_URL_ENV = 'DSH_REGISTRY_POSTGRES_URL'
const CONTROL_ACCOUNT_CONTEXT = '__registry_control_plane__'
const SCHEMA_NAME = /^[a-z][a-z0-9_]*$/u
const DOMAIN_PREFIX = /^[a-z][a-z0-9_]*$/u
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const APPLICATION_NAMES = ['dsh-a2a-registry', 'dsh-a2a-registry-tenancy']
const BACKEND_NAME = 'offline-software-kms-root-rewrap'
const FORMAT = 'dsh-registry-software-kms-root-rewrap'
const STORAGE_TENANT_TABLES = Object.freeze(['units', 'unit_globals', 'unit_records'])
const SHA256 = /^[0-9a-f]{64}$/u

const HELP = `
停服规划或执行 software-local KMS 跨组织 root-key 重包裹。

敏感输入只读取环境变量：
  DSH_REGISTRY_POSTGRES_MIGRATOR_URL
  DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID
  DSH_REGISTRY_DISCLOSURE_ROOT_KEY
  DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID
  DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY

用法：
  node --import tsx/esm deploy/registry/rewrap-software-kms-root.mjs [--schema registry]
    [--domain-name-prefix a2a_registry_disclosure_keys]
    [--execute --confirm-quiesced --confirm-backup-verified]

默认 plan 会获取同一排他维护锁、确认 Registry 无在线数据库会话并认证全部已有 KMS 层次，
精确核对 tenancy/storage RLS，并在表锁保护下完成跨租户 owner/DEK 全局对账，但最终回滚。
execute 在同一事务内逐组织写入；没有 KMS owner 的组织只报告 no-owner，不会创建 unit 或
owner。执行前必须停止 Registry 并禁用自动重启。命令拒绝在线 DSH_REGISTRY_POSTGRES_URL
和任何命令行 secret。
`.trim()

class OfflineKmsRootRewrapError extends Error {
  constructor(message) {
    super(message)
    this.name = 'OfflineKmsRootRewrapError'
  }
}

function fail(message) {
  throw new OfflineKmsRootRewrapError(message)
}

function exactEnvironment(environment, name) {
  const value = environment[name]
  if (typeof value !== 'string' || value.length === 0) fail(`${name} is required`)
  return value
}

function quoteIdentifier(value) {
  if (!SCHEMA_NAME.test(value)) fail('schema name is invalid')
  return `"${value}"`
}

function normalizePolicyExpression(expression) {
  let normalized = expression.replace(/\s+/gu, '').replace(/::text/gu, '')
  if (normalized.startsWith('(') && normalized.endsWith(')')) normalized = normalized.slice(1, -1)
  return normalized
}

/** Reject any storage-policy shape that differs from the online storage v2 validator. */
export function requireExactStoragePolicies(policies) {
  const expectedExpression = "tenant_id=current_setting('app.tenant_id',true)"
  for (const table of STORAGE_TENANT_TABLES) {
    const selected = policies.filter(policy => policy.table_name === table)
    if (selected.length !== 1 || selected[0]?.policy_name !== 'tenant_isolation'
      || selected[0]?.all_commands !== true || selected[0]?.permissive !== true
      || selected[0]?.public_only !== true
      || normalizePolicyExpression(selected[0]?.qualification ?? '') !== expectedExpression
      || normalizePolicyExpression(selected[0]?.check_expression ?? '') !== expectedExpression) {
      fail('Registry storage tenant-isolation policy does not match the production schema')
    }
  }
}

/** Bind the current exact tenancy policy catalog to the fingerprint persisted by migration. */
export function requireExactTenancyPolicies(policyFingerprint, policies) {
  if (!SHA256.test(policyFingerprint) || !matchesExpectedTenancyPolicies(policies)
    || fingerprintTenancyPolicies(policies) !== policyFingerprint) {
    fail('Registry tenancy policy fingerprint does not match the production schema')
  }
}

/** Parse non-secret switches only; every credential and root slot remains environment-owned. */
export function parseArguments(arguments_) {
  if (arguments_.includes('--help') || arguments_.includes('-h')) return Object.freeze({ help: true })
  let schema = 'registry'
  let domainNamePrefix = 'a2a_registry_disclosure_keys'
  let execute = false
  let quiesced = false
  let backupVerified = false
  const seen = new Set()
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index]
    if (seen.has(argument)) fail(`duplicate ${argument}`)
    seen.add(argument)
    if (argument === '--execute') execute = true
    else if (argument === '--confirm-quiesced') quiesced = true
    else if (argument === '--confirm-backup-verified') backupVerified = true
    else if (argument === '--schema' || argument === '--domain-name-prefix') {
      const value = arguments_[index + 1]
      if (value === undefined || value.startsWith('--')) fail(`missing ${argument}`)
      if (argument === '--schema') schema = value
      else domainNamePrefix = value
      index += 1
    } else fail('unknown or positional argument; command-line secrets are not accepted')
  }
  if (!SCHEMA_NAME.test(schema)) fail('schema name is invalid')
  if (!DOMAIN_PREFIX.test(domainNamePrefix)) fail('domain name prefix is invalid')
  if (!execute && (quiesced || backupVerified)) fail('confirmation flags require --execute')
  if (execute && (!quiesced || !backupVerified)) {
    fail('--execute requires --confirm-quiesced and --confirm-backup-verified')
  }
  return Object.freeze({ help: false, schema, domainNamePrefix, execute,
    operatorAttestedQuiescence: quiesced,
    operatorAttestedBackupVerification: backupVerified })
}

/** Resolve the dedicated migrator URL and both root slots without accepting a fallback source. */
export function configurationFromEnvironment(input, environment) {
  if (typeof environment[RUNTIME_URL_ENV] === 'string'
    && environment[RUNTIME_URL_ENV].trim().length > 0) {
    fail(`${RUNTIME_URL_ENV} must not be present in the offline maintenance environment`)
  }
  const connectionString = exactEnvironment(environment, MIGRATOR_URL_ENV)
  let parsed
  try { parsed = new URL(connectionString) } catch { fail(`${MIGRATOR_URL_ENV} is invalid`) }
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol)
    || parsed.username !== 'registry_migrator' || parsed.password.length === 0
    || parsed.hostname.length === 0 || parsed.pathname.length <= 1
    || parsed.search.length > 0 || parsed.hash.length > 0) {
    fail(`${MIGRATOR_URL_ENV} must select the dedicated registry_migrator role`)
  }
  const rootKeyId = exactEnvironment(environment, ACTIVE_ROOT_KEY_ID_ENV)
  const previousRootKeyId = exactEnvironment(environment, PREVIOUS_ROOT_KEY_ID_ENV)
  if (!IDENTIFIER.test(rootKeyId) || !IDENTIFIER.test(previousRootKeyId)
    || rootKeyId === previousRootKeyId) fail('root key identifiers are invalid or not distinct')
  const encodedRootKey = exactEnvironment(environment, DISCLOSURE_ROOT_KEY_ENV)
  const encodedPreviousRootKey = exactEnvironment(environment, DISCLOSURE_PREVIOUS_ROOT_KEY_ENV)
  if (encodedRootKey === encodedPreviousRootKey) fail('active and previous root keys must be independent')
  return Object.freeze({
    ...input,
    connectionString,
    activeRootKey: Object.freeze({ keyId: rootKeyId,
      key: parseDisclosureRootKey(encodedRootKey, DISCLOSURE_ROOT_KEY_ENV) }),
    previousRootKey: Object.freeze({ keyId: previousRootKeyId,
      key: parseDisclosureRootKey(encodedPreviousRootKey, DISCLOSURE_PREVIOUS_ROOT_KEY_ENV) }),
  })
}

class PostgresMaintenanceDatabase {
  constructor(pool, client) {
    this.pool = pool
    this.client = client
  }

  query(text, parameters = []) { return this.client.query(text, parameters) }
  begin() { return this.query('begin isolation level serializable') }
  commit() { return this.query('commit') }
  rollback() { return this.query('rollback') }

  async configureTransaction() {
    await this.query("set local lock_timeout = '2s'")
    await this.query("set local statement_timeout = '5min'")
    await this.query("set local idle_in_transaction_session_timeout = '5min'")
  }

  async requireSafeRole(schema) {
    const role = await this.query(
      `select current_user,
       pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER') as can_read_all_stats,
       exists (
         select 1 from pg_roles as role
         where (role.rolname = current_user
                or pg_has_role(current_user, role.oid, 'MEMBER')
                or pg_has_role(current_user, role.oid, 'SET'))
           and (role.rolsuper or role.rolbypassrls or role.rolcreatedb
                or role.rolcreaterole or role.rolreplication
                or (role.rolname <> current_user and role.rolname <> 'pg_read_all_stats'))
       ) as dangerous`)
    if (role.rows.length !== 1 || role.rows[0]?.current_user !== 'registry_migrator'
      || role.rows[0]?.can_read_all_stats !== true || role.rows[0]?.dangerous !== false) {
      fail('offline rewrap requires the restricted registry_migrator role with pg_read_all_stats')
    }
    const namespace = await this.query(
      `select pg_get_userbyid(nspowner) as owner from pg_namespace where nspname = $1`, [schema])
    if (namespace.rows.length !== 1 || namespace.rows[0]?.owner !== 'registry_migrator') {
      fail('target schema must exist and be owned by registry_migrator')
    }
    const tenantRelations = new Set(['organizations', 'units', 'unit_globals', 'unit_records'])
    const requiredRelations = ['storage_meta', 'tenancy_meta', ...tenantRelations]
    const relations = await this.query(
      `select relation.relname, pg_get_userbyid(relation.relowner) as owner,
              relation.relrowsecurity, relation.relforcerowsecurity
       from pg_class as relation join pg_namespace as namespace on namespace.oid = relation.relnamespace
       where namespace.nspname = $1 and relation.relkind in ('r', 'p')
         and relation.relname = any($2::text[])`,
      [schema, requiredRelations],
    )
    if (relations.rows.length !== requiredRelations.length
      || relations.rows.some(row => row.owner !== 'registry_migrator'
        || (tenantRelations.has(row.relname)
          && (row.relrowsecurity !== true || row.relforcerowsecurity !== true)))) {
      fail('required Registry relations are missing, unsafe, or not owned by registry_migrator')
    }
    const versions = await this.query(
      `select
        (select schema_version from ${quoteIdentifier(schema)}.storage_meta where singleton = true)
          as storage_version,
        (select schema_version from ${quoteIdentifier(schema)}.tenancy_meta where singleton = true)
          as tenancy_version,
        (select policy_fingerprint from ${quoteIdentifier(schema)}.tenancy_meta where singleton = true)
          as policy_fingerprint`)
    if (versions.rows.length !== 1 || versions.rows[0]?.storage_version !== 2
      || versions.rows[0]?.tenancy_version !== 3) {
      fail('Registry PostgreSQL schema versions are not supported by offline KMS rewrap')
    }
    const tenantColumns = await this.query(
      `select relation.relname as table_name
       from pg_class as relation
       join pg_namespace as namespace on namespace.oid = relation.relnamespace
       join pg_attribute as attribute on attribute.attrelid = relation.oid
       where namespace.nspname = $1 and relation.relname = any($2::text[])
         and relation.relkind in ('r', 'p') and attribute.attname = 'tenant_id'
         and attribute.atttypid = 'text'::regtype and attribute.attnotnull
         and not attribute.attisdropped`, [schema, STORAGE_TENANT_TABLES])
    if (tenantColumns.rows.length !== STORAGE_TENANT_TABLES.length) {
      fail('Registry storage tenant columns do not match the production schema')
    }
    const storagePolicies = await this.query(
      `select relation.relname as table_name, policy.polname as policy_name,
              policy.polcmd = '*' as all_commands, policy.polpermissive as permissive,
              policy.polroles = array[0::oid] as public_only,
              coalesce(pg_get_expr(policy.polqual, policy.polrelid), '') as qualification,
              coalesce(pg_get_expr(policy.polwithcheck, policy.polrelid), '') as check_expression
       from pg_policy as policy join pg_class as relation on relation.oid = policy.polrelid
       join pg_namespace as namespace on namespace.oid = relation.relnamespace
       where namespace.nspname = $1 and relation.relname = any($2::text[])
       order by relation.relname, policy.polname`, [schema, STORAGE_TENANT_TABLES])
    requireExactStoragePolicies(storagePolicies.rows)
    const deparseSettings = await this.query(TENANCY_POLICY_DEPARSE_SETTINGS_QUERY,
      [TENANCY_POLICY_DEPARSE_SEARCH_PATH, TENANCY_POLICY_DEPARSE_QUOTE_ALL_IDENTIFIERS])
    if (deparseSettings.rows.length !== 1
      || deparseSettings.rows[0]?.search_path !== TENANCY_POLICY_DEPARSE_SEARCH_PATH
      || deparseSettings.rows[0]?.quote_all_identifiers !== TENANCY_POLICY_DEPARSE_QUOTE_ALL_IDENTIFIERS) {
      fail('Registry tenancy policy deparse settings are unavailable')
    }
    const tenancyPolicies = await this.query(TENANCY_POLICY_CATALOG_QUERY,
      [schema, TENANCY_POLICY_TABLE_NAMES])
    requireExactTenancyPolicies(versions.rows[0]?.policy_fingerprint, tenancyPolicies.rows)
  }

  async acquireMaintenanceLock(schema) {
    const result = await this.query(
      `select pg_try_advisory_xact_lock(
         hashtextextended('dsh-registry-schema:' || $1::text, 0)
       ) as acquired`, [schema])
    if (result.rows[0]?.acquired !== true) fail('another offline operation owns the Registry schema lock')
  }

  async activeRegistryConnections() {
    const result = await this.query(
      `select count(*)::integer as count from pg_stat_activity
       where datname = current_database() and pid <> pg_backend_pid()
         and backend_type = 'client backend'
         and (usename = 'registry_app' or application_name = any($1::text[]))`,
      [APPLICATION_NAMES],
    )
    return result.rows[0]?.count
  }

  async lockAuthoritativeTables(schema) {
    const qualified = quoteIdentifier(schema)
    await this.query(`lock table ${qualified}.organizations, ${qualified}.units,
      ${qualified}.unit_globals, ${qualified}.unit_records in access exclusive mode nowait`)
  }

  async listOrganizations(schema) {
    await this.query(`select set_config('app.account_id', $1, true),
      set_config('app.organization_id', '', true)`, [CONTROL_ACCOUNT_CONTEXT])
    const result = await this.query(
      `select id, state from ${quoteIdentifier(schema)}.organizations order by id`)
    return result.rows
  }

  async listGlobalKmsRecords(schema) {
    const qualified = quoteIdentifier(schema)
    for (const table of STORAGE_TENANT_TABLES) {
      await this.query(`alter table ${qualified}.${table} no force row level security`)
    }
    let result
    try {
      result = await this.query(
        `select record.tenant_id, record.unit, unit.version, record.table_name,
                record.key, record.value,
                (select count(*)::integer from ${qualified}.unit_globals as global
                 where global.tenant_id = record.tenant_id and global.unit = record.unit) as global_count
         from ${qualified}.unit_records as record
         join ${qualified}.units as unit
           on unit.tenant_id = record.tenant_id and unit.name = record.unit
         where (record.table_name = 'owner' and record.key = 'owner'
                and (record.value ? 'wrappedOrganizationKey'
                     or record.value ? 'organizationKeyId' or record.value ? 'rootKeyId'))
            or (record.table_name = 'data_keys'
                and (record.value ? 'wrappedDataKey'
                     or record.value ? 'organizationKeyId' or record.value ? 'scope'))
         order by record.tenant_id, record.unit, record.table_name, record.key`)
    } finally {
      for (const table of STORAGE_TENANT_TABLES) {
        await this.query(`alter table ${qualified}.${table} force row level security`)
      }
    }
    const forced = await this.query(
      `select relation.relname as table_name, relation.relforcerowsecurity
       from pg_class as relation join pg_namespace as namespace on namespace.oid = relation.relnamespace
       where namespace.nspname = $1 and relation.relname = any($2::text[])
         and relation.relkind in ('r', 'p')`, [schema, STORAGE_TENANT_TABLES])
    if (forced.rows.length !== STORAGE_TENANT_TABLES.length
      || forced.rows.some(row => row.relforcerowsecurity !== true)) {
      fail('Registry storage FORCE RLS could not be restored after global inventory')
    }
    return result.rows
  }

  async loadKmsUnit(schema, organizationId, unit) {
    await this.query(`select set_config('app.tenant_id', $1, true)`, [organizationId])
    const selectedUnit = await this.query(
      `select version from ${quoteIdentifier(schema)}.units
       where tenant_id = $1 and name = $2`, [organizationId, unit])
    if (selectedUnit.rows.length === 0) return Object.freeze({ present: false })
    if (selectedUnit.rows.length !== 1) fail('KMS unit identity is ambiguous')
    const records = await this.query(
      `select table_name, key, value from ${quoteIdentifier(schema)}.unit_records
       where tenant_id = $1 and unit = $2 order by table_name, key`, [organizationId, unit])
    const globals = await this.query(
      `select count(*)::integer as count from ${quoteIdentifier(schema)}.unit_globals
       where tenant_id = $1 and unit = $2`, [organizationId, unit])
    return Object.freeze({ present: true, version: selectedUnit.rows[0]?.version,
      records: records.rows, globalCount: globals.rows[0]?.count })
  }

  async replaceOwner(schema, organizationId, unit, expected, next) {
    await this.query(`select set_config('app.tenant_id', $1, true)`, [organizationId])
    const result = await this.query(
      `update ${quoteIdentifier(schema)}.unit_records set value = $1::jsonb
       where tenant_id = $2 and unit = $3 and table_name = 'owner' and key = 'owner'
         and value = $4::jsonb`,
      [JSON.stringify(next), organizationId, unit, JSON.stringify(expected)],
    )
    if (result.rowCount !== 1) fail('KMS owner changed or disappeared during the offline transaction')
  }

  async close() {
    this.client.release()
    await this.pool.end()
  }
}

async function defaultOpenDatabase(connectionString) {
  const pool = new Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 30_000,
    statement_timeout: 300_000,
    idle_in_transaction_session_timeout: 300_000,
    application_name: 'dsh-registry-offline-kms-root-rewrap',
  })
  try { return new PostgresMaintenanceDatabase(pool, await pool.connect()) } catch (error) {
    await pool.end().catch(() => undefined)
    throw error
  }
}

function normalizeUnit(snapshot) {
  if (snapshot.present !== true) return Object.freeze({ present: false })
  if (snapshot.version !== 1 || snapshot.globalCount !== 0 || !Array.isArray(snapshot.records)) {
    fail('existing KMS unit has an incompatible format')
  }
  const tables = { owner: Object.create(null), data_keys: Object.create(null) }
  const identities = new Set()
  for (const record of snapshot.records) {
    if (record === null || typeof record !== 'object'
      || !['owner', 'data_keys'].includes(record.table_name)
      || typeof record.key !== 'string' || record.key.length === 0) {
      fail('existing KMS unit contains an undeclared or malformed record')
    }
    const identity = `${record.table_name}\0${record.key}`
    if (identities.has(identity)) fail('existing KMS unit contains duplicate records')
    identities.add(identity)
    tables[record.table_name][record.key] = record.value
  }
  const ownerKeys = Object.keys(tables.owner)
  if (ownerKeys.length === 0) {
    if (Object.keys(tables.data_keys).length !== 0) fail('KMS data keys exist without an owner')
    return Object.freeze({ present: true, ownerPresent: false })
  }
  if (ownerKeys.length !== 1 || ownerKeys[0] !== 'owner') fail('KMS owner identity is invalid')
  return Object.freeze({ present: true, ownerPresent: true, tables })
}

class ExistingOwnerBackend {
  constructor(database, schema, execute) {
    this.database = database
    this.schema = schema
    this.execute = execute
    this.staged = undefined
    this.opened = false
    this.kv = Object.freeze({ open: descriptor => this.open(descriptor) })
  }

  stage(organizationId, unit, tables) {
    if (this.staged !== undefined || this.opened) fail('offline KMS backend is already in use')
    this.staged = { organizationId, unit, tables, owner: tables.owner.owner }
  }

  async open(descriptor) {
    const staged = this.staged
    this.staged = undefined
    if (staged === undefined || this.opened || descriptor.tenantId !== staged.organizationId
      || descriptor.name !== staged.unit || descriptor.version !== 1
      || descriptor.hasGlobal !== false || descriptor.layout !== 'single'
      || JSON.stringify([...descriptor.tables].sort()) !== JSON.stringify(['data_keys', 'owner'])) {
      fail('offline KMS domain descriptor is invalid')
    }
    this.opened = true
    let closed = false
    return {
      loadAll: async () => ({ tables: staged.tables, global: null }),
      putRecord: async (table, key, value) => {
        if (closed) fail('offline KMS unit is closed')
        if (!this.execute || table !== 'owner' || key !== 'owner') {
          fail('offline KMS backend rejected a non-owner or plan-mode write')
        }
        await this.database.replaceOwner(
          this.schema, staged.organizationId, staged.unit, staged.owner, value,
        )
        staged.owner = value
      },
      deleteRecord: async () => { fail('offline KMS backend forbids deletion') },
      setGlobal: async () => { fail('offline KMS backend forbids global writes') },
      close: async () => {
        if (!closed) { closed = true; this.opened = false }
      },
    }
  }

  close() {
    if (this.opened || this.staged !== undefined) fail('offline KMS backend closed while in use')
    return Promise.resolve()
  }
}

async function createKmsRuntime(database, schema, execute) {
  const ctx = new Context()
  try {
    await ctx.plugin(Storage).await()
    const backend = new ExistingOwnerBackend(database, schema, execute)
    const unregister = ctx.storage.backend.register(BACKEND_NAME, backend)
    const facility = new DomainFacility(ctx, { backend: BACKEND_NAME })
    return { backend, facility, async close() {
      let cleanupFailed = false
      try { await facility.closeAll() } catch { cleanupFailed = true }
      try { unregister() } catch { cleanupFailed = true }
      try { await backend.close() } catch { cleanupFailed = true }
      try { await ctx.fiber.dispose() } catch { cleanupFailed = true }
      if (cleanupFailed) fail('offline KMS runtime cleanup failed')
    } }
  } catch (error) {
    await ctx.fiber.dispose()
    throw error
  }
}

function planReceipt(verification, activeRootKeyId) {
  return Object.freeze({
    version: 1,
    assurance: 'software-local',
    organizationId: verification.organizationId,
    outcome: verification.rootKeyId === activeRootKeyId ? 'already-active' : 'would-rewrap',
    before: verification,
  })
}

function noOwnerReceipt(organizationId) {
  return Object.freeze({ version: 1, assurance: 'software-local', organizationId, outcome: 'no-owner' })
}

function reconcileGlobalKmsInventory(organizations, rows, domainNamePrefix) {
  if (!Array.isArray(rows)) fail('global KMS owner inventory is invalid')
  const organizationIds = new Set(organizations.map(organization => organization.id))
  const units = new Map()
  for (const row of rows) {
    if (row === null || typeof row !== 'object' || !IDENTIFIER.test(row.tenant_id)
      || typeof row.unit !== 'string' || row.unit.length === 0
      || !['owner', 'data_keys'].includes(row.table_name)
      || typeof row.key !== 'string' || row.key.length === 0
      || row.value === null || typeof row.value !== 'object') {
      fail('global KMS owner inventory is invalid')
    }
    if (!organizationIds.has(row.tenant_id)) {
      fail('KMS storage exists for a tenant outside the authoritative organization inventory')
    }
    const expectedUnit = softwareLocalDisclosureKeyDomainName(domainNamePrefix, row.tenant_id)
    if (row.unit !== expectedUnit) {
      fail('KMS storage unit does not match the configured organization domain')
    }
    if (row.version !== 1 || row.global_count !== 0) {
      fail('existing KMS unit has an incompatible format')
    }
    const identity = `${row.tenant_id}\0${row.unit}`
    let selected = units.get(identity)
    if (selected === undefined) {
      selected = { owner: 0, dataKeys: 0 }
      units.set(identity, selected)
    }
    if (row.table_name === 'owner') {
      if (row.key !== 'owner' || row.value.organizationId !== row.tenant_id) {
        fail('KMS owner identity does not match its storage tenant')
      }
      selected.owner += 1
    } else selected.dataKeys += 1
  }
  for (const unit of units.values()) {
    if (unit.owner !== 1) fail('KMS data keys exist without an owner')
  }
  return Object.freeze({ units: units.size, records: rows.length })
}

function summarize(receipts) {
  const summary = { organizations: receipts.length, owners: 0, noOwner: 0,
    rewrapped: 0, wouldRewrap: 0, alreadyActive: 0, dataKeys: 0 }
  for (const receipt of receipts) {
    if (receipt.outcome === 'no-owner') summary.noOwner += 1
    else {
      summary.owners += 1
      summary.dataKeys += receipt.after?.dataKeyCount ?? receipt.before.dataKeyCount
      if (receipt.outcome === 'rewrapped') summary.rewrapped += 1
      else if (receipt.outcome === 'would-rewrap') summary.wouldRewrap += 1
      else summary.alreadyActive += 1
    }
  }
  return Object.freeze(summary)
}

/** Run one all-or-nothing offline plan/execute transaction over the authoritative organization list. */
export async function runOfflineKmsRootRewrap(configuration, openDatabase = defaultOpenDatabase) {
  if (!SCHEMA_NAME.test(configuration.schema) || !DOMAIN_PREFIX.test(configuration.domainNamePrefix)
    || typeof configuration.execute !== 'boolean'
    || (configuration.execute && (configuration.operatorAttestedQuiescence !== true
      || configuration.operatorAttestedBackupVerification !== true))) {
    fail('offline KMS rewrap configuration or operator attestations are invalid')
  }
  const database = await openDatabase(configuration.connectionString)
  let transaction = false
  let runtime
  let primaryError
  let result
  try {
    await database.begin()
    transaction = true
    await database.configureTransaction()
    await database.requireSafeRole(configuration.schema)
    await database.acquireMaintenanceLock(configuration.schema)
    if (await database.activeRegistryConnections() !== 0) {
      fail('Registry database sessions are active; stop Registry before running this command')
    }
    await database.lockAuthoritativeTables(configuration.schema)
    if (await database.activeRegistryConnections() !== 0) {
      fail('Registry connected while offline KMS maintenance was starting')
    }
    const organizations = await database.listOrganizations(configuration.schema)
    if (!Array.isArray(organizations)) fail('authoritative organization inventory is invalid')
    const seen = new Set()
    for (const organization of organizations) {
      if (organization === null || typeof organization !== 'object'
        || !IDENTIFIER.test(organization.id) || !['provisioning', 'active', 'failed'].includes(organization.state)
        || seen.has(organization.id)) fail('authoritative organization inventory is invalid')
      seen.add(organization.id)
    }
    const globalInventory = reconcileGlobalKmsInventory(organizations,
      await database.listGlobalKmsRecords(configuration.schema), configuration.domainNamePrefix)
    runtime = await createKmsRuntime(database, configuration.schema, configuration.execute)
    const receipts = []
    for (const organization of organizations) {
      const unit = softwareLocalDisclosureKeyDomainName(configuration.domainNamePrefix, organization.id)
      const normalized = normalizeUnit(await database.loadKmsUnit(
        configuration.schema, organization.id, unit,
      ))
      if (normalized.present !== true || normalized.ownerPresent !== true) {
        receipts.push(noOwnerReceipt(organization.id))
        continue
      }
      runtime.backend.stage(organization.id, unit, normalized.tables)
      const lifecycle = new AbortController()
      const store = await openSoftwareLocalDisclosureKeyStore(runtime.facility, {
        organizationId: organization.id,
        rootKey: configuration.activeRootKey,
        previousRootKey: configuration.previousRootKey,
        storage: { domainNamePrefix: configuration.domainNamePrefix, tenantId: organization.id },
        limits: { maxDataKeys: 100_000, maxPendingOperations: 1 },
        signal: lifecycle.signal,
      })
      try {
        const signal = new AbortController().signal
        receipts.push(configuration.execute
          ? await store.rewrapOwnerRootKey(signal)
          : planReceipt(await store.verifyRetainedKeys(signal), configuration.activeRootKey.keyId))
      } finally { await store.close() }
    }
    if (await database.activeRegistryConnections() !== 0) {
      fail('Registry connected before offline KMS maintenance could finish')
    }
    if (configuration.execute) await database.commit()
    else await database.rollback()
    transaction = false
    result = Object.freeze({
      format: FORMAT,
      version: 1,
      mode: configuration.execute ? 'execute' : 'plan',
      schema: configuration.schema,
      rootTransition: Object.freeze({
        previousRootKeyId: configuration.previousRootKey.keyId,
        activeRootKeyId: configuration.activeRootKey.keyId,
      }),
      receipts: Object.freeze(receipts),
      summary: summarize(receipts),
      checks: Object.freeze({ maintenanceLock: true, registrySessions: 0,
        authoritativeOrganizations: true, existingOwnersOnly: true,
        globalKmsInventory: true, globalKmsUnits: globalInventory.units,
        globalKmsRecords: globalInventory.records,
        operatorAttestedQuiescence: configuration.operatorAttestedQuiescence,
        operatorAttestedBackupVerification: configuration.operatorAttestedBackupVerification }),
      committed: configuration.execute,
    })
  } catch (error) {
    if (transaction) {
      try { await database.rollback() } catch { /* Preserve the primary sanitized failure. */ }
      transaction = false
    }
    primaryError = error instanceof OfflineKmsRootRewrapError || error instanceof SoftwareLocalKmsError
      ? error : new OfflineKmsRootRewrapError('offline KMS root rewrap failed')
  }
  let cleanupFailed = false
  try { await runtime?.close() } catch { cleanupFailed = true }
  try { await database.close() } catch { cleanupFailed = true }
  if (primaryError !== undefined) throw primaryError
  if (cleanupFailed) throw new OfflineKmsRootRewrapError('offline KMS database cleanup failed')
  return result
}

function connectionPassword(value) {
  try { return new URL(value).password } catch { return undefined }
}

export function safeMessage(error, environment) {
  let message = error instanceof OfflineKmsRootRewrapError || error instanceof SoftwareLocalKmsError
    ? error.message : 'offline KMS root rewrap failed'
  for (const secret of [
    environment[MIGRATOR_URL_ENV], connectionPassword(environment[MIGRATOR_URL_ENV]),
    environment[DISCLOSURE_ROOT_KEY_ENV], environment[DISCLOSURE_PREVIOUS_ROOT_KEY_ENV],
  ]) if (typeof secret === 'string' && secret.length > 0) message = message.replaceAll(secret, '<redacted>')
  return message.replace(/(postgres(?:ql)?:\/\/)[^@\s]+@/giu, '$1<redacted>@')
}

export async function main(arguments_ = process.argv.slice(2), environment = process.env) {
  const input = parseArguments(arguments_)
  if (input.help) return HELP
  const result = await runOfflineKmsRootRewrap(configurationFromEnvironment(input, environment))
  return JSON.stringify(result)
}

const invoked = process.argv[1]
if (invoked !== undefined
  && realpathSync.native(resolve(invoked)) === realpathSync.native(fileURLToPath(import.meta.url))) {
  main().then(output => { process.stdout.write(`${output}\n`) }, (error) => {
    process.stderr.write(`registry-software-kms-root-rewrap: ${safeMessage(error, process.env)}\n`)
    process.exitCode = 1
  })
}
