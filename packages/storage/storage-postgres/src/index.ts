/** PostgreSQL-backed tenant-scoped KV storage for independently deployed Registry domains. */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { Pool, type PoolClient } from 'pg'
import { StorageError, UNIT_NAME_RE, storageBackendServiceKey } from '@deepseek-ai/dsh-storage'
import type { KvFacet, KvRecordWrite, KvUnit, KvUnitDescriptor, StorageBackend } from '@deepseek-ai/dsh-storage'

export const name = 'storage-postgres'
export const inject = ['storage']
export const STORAGE_POSTGRES_SCHEMA_VERSION = 2
const READINESS_QUERY_TIMEOUT_MS = 1_500

const GLOBAL_TENANT_ID = ''
const TENANT_POLICY = 'tenant_isolation'
const STORAGE_TABLES = ['storage_meta', 'units', 'unit_globals', 'unit_records'] as const
const TENANT_TABLES = ['units', 'unit_globals', 'unit_records'] as const
const REGISTRY_META_TABLES = ['storage_meta', 'tenancy_meta'] as const
const REGISTRY_BUSINESS_TABLES = [
  'units', 'unit_globals', 'unit_records',
  'accounts', 'account_identities', 'organizations', 'organization_memberships',
  'organization_creations', 'organization_invitations',
] as const

export type PostgresSchemaMode = 'migrate' | 'validate'

export interface Config {
  /** PostgreSQL connection string supplied by the deployment secret store. */
  connectionString: string
  /** Dedicated application schema. The online role must not own it. */
  schema?: string
  /**
   * `migrate` retains the legacy bootstrap/upgrade behavior for compatibility.
   * Internet-facing Registry processes must set `validate`: that path is a
   * read-only schema check and can never run DDL.
   */
  schemaMode?: PostgresSchemaMode
  /** Local migration escape hatch; production must leave this false. */
  allowUnsafeSharedDatabase?: boolean
  /**
   * Explicit destination for every row in a populated schema-v1 database.
   * It is used only by the transactional v1-to-v2 migration and never inferred
   * from JSON values. An empty string explicitly selects the global scope.
   */
  legacyTenantId?: string
  /** Small process-local pool; a production pooler may sit in front of this connection. */
  maxConnections?: number
  idleTimeoutMs?: number
  statementTimeoutMs?: number
}

export const Config: z<Config> = z.object({
  connectionString: z.string().required(),
  schema: z.string().default('registry'),
  schemaMode: z.union(['migrate', 'validate'] as const).default('migrate'),
  allowUnsafeSharedDatabase: z.boolean().default(false),
  legacyTenantId: z.string(),
  maxConnections: z.number().min(1).max(32).step(1).default(8),
  idleTimeoutMs: z.number().min(1_000).max(600_000).step(1).default(30_000),
  statementTimeoutMs: z.number().min(1_000).max(120_000).step(1).default(15_000),
})

export type PostgresSchemaMigrationConfig = Omit<Config, 'schemaMode'>
export type PostgresSchemaValidationConfig = Omit<Config, 'schemaMode' | 'legacyTenantId'>

function quoteIdentifier(value: string): string {
  if (!UNIT_NAME_RE.test(value)) throw new Error(`PostgreSQL schema '${value}' violates ${UNIT_NAME_RE}`)
  return `"${value}"`
}

function captureJson(value: unknown): string {
  const encoded = JSON.stringify(value)
  if (encoded === undefined) throw new Error('PostgreSQL storage values must be JSON serializable')
  return encoded
}

function tenantIdOf(descriptor: KvUnitDescriptor): string {
  if (descriptor.tenantId !== undefined && typeof descriptor.tenantId !== 'string') {
    throw new Error('PostgreSQL tenantId must be a string when present')
  }
  return descriptor.tenantId ?? GLOBAL_TENANT_ID
}

function openUnitKey(tenantId: string, name: string): string {
  return JSON.stringify([tenantId, name])
}

async function rollback(client: PoolClient, original: unknown): Promise<never> {
  try { await client.query('rollback') } catch (rollbackError) {
    throw new AggregateError([original, rollbackError], 'PostgreSQL transaction rollback failed')
  }
  throw original
}

function createPostgresPool(config: Pick<Config, 'connectionString' | 'maxConnections' | 'idleTimeoutMs' | 'statementTimeoutMs'>,
  applicationName: string, maxConnections = config.maxConnections ?? 8): Pool {
  return new Pool({
    connectionString: config.connectionString,
    max: maxConnections,
    idleTimeoutMillis: config.idleTimeoutMs ?? 30_000,
    connectionTimeoutMillis: 10_000,
    query_timeout: config.statementTimeoutMs ?? 15_000,
    statement_timeout: config.statementTimeoutMs ?? 15_000,
    idle_in_transaction_session_timeout: 30_000,
    application_name: applicationName,
  })
}

async function assertSafeRoleChain(client: PoolClient, allowedGroupRoles: readonly string[]): Promise<void> {
  const role = await client.query<{ readonly dangerous: boolean }>(
    `select exists (
       select 1 from pg_roles candidate
       where (candidate.rolname = current_user
              or pg_has_role(current_user, candidate.oid, 'MEMBER')
              or pg_has_role(current_user, candidate.oid, 'SET'))
         and (candidate.rolsuper or candidate.rolbypassrls or candidate.rolcreatedb
           or candidate.rolcreaterole or candidate.rolreplication
           or (candidate.rolname <> current_user and not (candidate.rolname = any($1::text[]))))
     ) as dangerous`, [allowedGroupRoles],
  )
  if (role.rows.length !== 1 || role.rows[0]?.dangerous) {
    throw new Error('PostgreSQL storage role chain contains an administrative or unexpected group role')
  }
}

async function assertRuntimeDatabasePrivileges(client: PoolClient,
  allowUnsafeSharedDatabase: boolean): Promise<void> {
  const privileges = await client.query<{ readonly unsafe: boolean }>(
    `select exists (
       select 1 from pg_roles candidate
       where (candidate.rolname = current_user
              or pg_has_role(current_user, candidate.oid, 'MEMBER')
              or pg_has_role(current_user, candidate.oid, 'SET'))
         and (candidate.rolname <> current_user
           or candidate.rolname = 'pg_read_all_stats'
           or has_database_privilege(candidate.oid, current_database(), 'CREATE')
           or has_database_privilege(candidate.oid, current_database(), 'TEMP')
           or (not $1::boolean and exists (
             select 1 from pg_namespace namespace
             where has_schema_privilege(candidate.oid, namespace.oid, 'CREATE')
           )))
     ) as unsafe`, [allowUnsafeSharedDatabase],
  )
  if (privileges.rows.length !== 1 || privileges.rows[0]?.unsafe) {
    throw new Error('PostgreSQL runtime role chain must not have database/schema CREATE, TEMP, or all-session stats privileges')
  }
}

async function assertExactRegistryBackupRole(client: PoolClient): Promise<number> {
  const state = await client.query<{ readonly oid: number; readonly unsafe: boolean }>(
    `with backup_role as (
       select oid, rolcanlogin, rolinherit, rolconnlimit, rolbypassrls,
              rolsuper, rolcreatedb, rolcreaterole, rolreplication
       from pg_roles where rolname = 'registry_backup'
     )
     select backup_role.oid,
       not backup_role.rolcanlogin
       or backup_role.rolinherit
       or backup_role.rolconnlimit <> 2
       or not backup_role.rolbypassrls
       or backup_role.rolsuper
       or backup_role.rolcreatedb
       or backup_role.rolcreaterole
       or backup_role.rolreplication
       or exists (
         select 1 from pg_auth_members membership
         where membership.member = backup_role.oid or membership.roleid = backup_role.oid
       )
       or not has_database_privilege(backup_role.oid, current_database(), 'CONNECT')
       or has_database_privilege(backup_role.oid, current_database(), 'CREATE')
       or has_database_privilege(backup_role.oid, current_database(), 'TEMP')
       or exists (
         select 1 from pg_database database
         where database.datname <> current_database()
           and has_database_privilege(backup_role.oid, database.oid, 'CONNECT')
       )
       or exists (
         select 1 from pg_database database
         where database.datname <> current_database()
           and database.datname <> 'postgres' and not database.datistemplate
       )
       or not exists (
         select 1
         from pg_database database
         cross join lateral aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) acl
         where database.datname = current_database()
           and acl.grantee = backup_role.oid
           and acl.privilege_type = 'CONNECT'
           and not acl.is_grantable
       )
       or exists (
         select 1
         from pg_database database
         cross join lateral aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) acl
         where database.datname = current_database()
           and acl.grantee = backup_role.oid
           and (acl.privilege_type <> 'CONNECT' or acl.is_grantable)
       )
       or exists (
         select 1
         from pg_namespace namespace
         where namespace.nspname <> 'information_schema'
           and namespace.nspname !~ '^pg_'
           and (
             has_schema_privilege(backup_role.oid, namespace.oid, 'CREATE')
             or exists (
               select 1
               from aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) acl
               where acl.grantee = backup_role.oid
                 and (acl.privilege_type <> 'USAGE' or acl.is_grantable)
             )
           )
       )
       or exists (
         select 1
         from pg_class relation
         join pg_namespace namespace on namespace.oid = relation.relnamespace
         where namespace.nspname <> 'information_schema'
           and namespace.nspname !~ '^pg_'
           and relation.relkind in ('r', 'p', 'v', 'm', 'f')
           and (
             has_table_privilege(backup_role.oid, relation.oid,
               'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
             or has_any_column_privilege(backup_role.oid, relation.oid, 'INSERT, UPDATE, REFERENCES')
             or exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) acl
               where acl.grantee = backup_role.oid
                 and (acl.privilege_type <> 'SELECT' or acl.is_grantable)
             )
             or exists (
               select 1
               from pg_attribute attribute
               cross join lateral aclexplode(attribute.attacl) acl
               where attribute.attrelid = relation.oid
                 and attribute.attnum > 0
                 and not attribute.attisdropped
                 and acl.grantee = backup_role.oid
             )
           )
       )
       or exists (
         select 1
         from pg_sequence sequence
         join pg_class relation on relation.oid = sequence.seqrelid
         join pg_namespace namespace on namespace.oid = relation.relnamespace
         where namespace.nspname <> 'information_schema'
           and namespace.nspname !~ '^pg_'
           and (
             has_sequence_privilege(backup_role.oid, relation.oid, 'USAGE, UPDATE')
             or exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) acl
               where acl.grantee = backup_role.oid
                 and (acl.privilege_type <> 'SELECT' or acl.is_grantable)
             )
           )
       ) as unsafe
     from backup_role`,
  )
  const selected = state.rows[0]
  if (state.rows.length !== 1 || selected?.unsafe || selected.oid === undefined) {
    throw new Error('PostgreSQL registry_backup role must be isolated and have only exact backup privileges')
  }
  return selected.oid
}

async function assertRegistryBackupTargetIsolation(client: PoolClient, schemaName: string,
  backupRoleOid: number): Promise<void> {
  const state = await client.query<{ readonly unsafe: boolean }>(
    `select exists (
       select 1
       from pg_namespace namespace
       where namespace.nspname <> $1
         and namespace.nspname <> 'information_schema'
         and namespace.nspname !~ '^pg_'
         and (
           has_schema_privilege($2::oid, namespace.oid, 'USAGE')
           or has_schema_privilege($2::oid, namespace.oid, 'CREATE')
           or exists (
             select 1
             from aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) acl
             where acl.grantee = $2::oid
           )
         )
     ) or exists (
       select 1
       from pg_class relation
       join pg_namespace namespace on namespace.oid = relation.relnamespace
       where namespace.nspname <> $1
         and namespace.nspname <> 'information_schema'
         and namespace.nspname !~ '^pg_'
         and relation.relkind in ('r', 'p', 'v', 'm', 'f')
         and (
           has_table_privilege($2::oid, relation.oid,
             'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
           or has_any_column_privilege($2::oid, relation.oid,
             'SELECT, INSERT, UPDATE, REFERENCES')
         )
     ) or exists (
       select 1
       from pg_sequence sequence
       join pg_class relation on relation.oid = sequence.seqrelid
       join pg_namespace namespace on namespace.oid = relation.relnamespace
       where namespace.nspname <> $1
         and namespace.nspname <> 'information_schema'
         and namespace.nspname !~ '^pg_'
         and has_sequence_privilege($2::oid, relation.oid, 'USAGE, SELECT, UPDATE')
     ) as unsafe`,
    [schemaName, backupRoleOid],
  )
  if (state.rows.length !== 1 || state.rows[0]?.unsafe) {
    throw new Error('PostgreSQL registry_backup role must not reach objects outside the selected schema')
  }
}

async function assertRegistryBackupDefaultPrivileges(client: PoolClient, schemaName: string,
  backupRoleOid: number, backupEnabled: boolean): Promise<void> {
  const state = await client.query<{ readonly unsafe: boolean }>(
    `select exists (
       select 1
       from pg_default_acl defaults
       join pg_roles owner on owner.oid = defaults.defaclrole
       left join pg_namespace namespace on namespace.oid = defaults.defaclnamespace
       cross join lateral aclexplode(defaults.defaclacl) acl
       where acl.grantee = $2::oid
         and (defaults.defaclnamespace = 0
           or owner.rolname <> 'registry_migrator'
           or defaults.defaclobjtype not in ('r', 'S')
           or acl.privilege_type <> 'SELECT'
           or acl.is_grantable
           or ((namespace.nspname is not distinct from $1) <> $3::boolean))
     ) or ($3::boolean and (
       select count(distinct defaults.defaclobjtype)
       from pg_default_acl defaults
       join pg_roles owner on owner.oid = defaults.defaclrole
       join pg_namespace namespace on namespace.oid = defaults.defaclnamespace
       cross join lateral aclexplode(defaults.defaclacl) acl
       where owner.rolname = 'registry_migrator'
         and namespace.nspname = $1
         and defaults.defaclobjtype in ('r', 'S')
         and acl.grantee = $2::oid
         and acl.privilege_type = 'SELECT'
         and not acl.is_grantable
     ) <> 2) as unsafe`,
    [schemaName, backupRoleOid, backupEnabled],
  )
  if (state.rows.length !== 1 || state.rows[0]?.unsafe) {
    throw new Error('PostgreSQL registry_backup default privileges must match the selected schema state')
  }
}

async function assertExactRegistryObjectPrivileges(client: PoolClient, schemaName: string,
  backupRoleOid: number, backupEnabled: boolean): Promise<void> {
  const state = await client.query<{ readonly unsafe: boolean }>(
    `with runtime_role as (
       select oid from pg_roles where rolname = current_user
     )
     select not exists (select 1 from runtime_role)
       or exists (
         select 1
         from pg_class relation
         join pg_namespace namespace on namespace.oid = relation.relnamespace
         cross join runtime_role
         where namespace.nspname = $1 and relation.relkind in ('r', 'p', 'v', 'm', 'f')
           and (
             pg_get_userbyid(relation.relowner) <> 'registry_migrator'
             or exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) acl
               where acl.grantee not in (relation.relowner, runtime_role.oid, $4::oid)
                 or (acl.grantee = runtime_role.oid and (
                   acl.is_grantable
                   or case
                     when relation.relname = any($2::text[]) then acl.privilege_type <> 'SELECT'
                     when relation.relname = any($3::text[]) then not (
                       acl.privilege_type = any(array['SELECT', 'INSERT', 'UPDATE', 'DELETE']::text[])
                     )
                     else true
                   end
                 ))
                 or (acl.grantee = $4::oid and (
                   not $5::boolean or acl.privilege_type <> 'SELECT' or acl.is_grantable
                 ))
             )
             or exists (
               select 1
               from pg_attribute attribute
               cross join lateral aclexplode(attribute.attacl) acl
               where attribute.attrelid = relation.oid and attribute.attnum > 0
                 and not attribute.attisdropped and acl.grantee <> relation.relowner
             )
             or ($5::boolean and not exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) acl
               where acl.grantee = $4::oid
                 and acl.privilege_type = 'SELECT'
                 and not acl.is_grantable
             ))
             or has_table_privilege($4::oid, relation.oid, 'SELECT') <> $5::boolean
             or has_table_privilege($4::oid, relation.oid, 'INSERT')
             or has_table_privilege($4::oid, relation.oid, 'UPDATE')
             or has_table_privilege($4::oid, relation.oid, 'DELETE')
             or has_table_privilege($4::oid, relation.oid, 'TRUNCATE')
             or has_table_privilege($4::oid, relation.oid, 'REFERENCES')
             or has_table_privilege($4::oid, relation.oid, 'TRIGGER')
             or has_table_privilege($4::oid, relation.oid, 'MAINTAIN')
             or case
               when relation.relname = any($2::text[]) then
                 not has_table_privilege(runtime_role.oid, relation.oid, 'SELECT')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'INSERT')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'UPDATE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'DELETE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'TRUNCATE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'REFERENCES')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'TRIGGER')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'MAINTAIN')
               when relation.relname = any($3::text[]) then
                 not has_table_privilege(runtime_role.oid, relation.oid, 'SELECT')
                 or not has_table_privilege(runtime_role.oid, relation.oid, 'INSERT')
                 or not has_table_privilege(runtime_role.oid, relation.oid, 'UPDATE')
                 or not has_table_privilege(runtime_role.oid, relation.oid, 'DELETE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'TRUNCATE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'REFERENCES')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'TRIGGER')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'MAINTAIN')
               else has_table_privilege(runtime_role.oid, relation.oid,
                 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
             end
           )
       )
       or exists (
         select 1
         from pg_sequence sequence
         join pg_class relation on relation.oid = sequence.seqrelid
         join pg_namespace namespace on namespace.oid = relation.relnamespace
         cross join runtime_role
         where namespace.nspname = $1
           and (
             pg_get_userbyid(relation.relowner) <> 'registry_migrator'
             or exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) acl
               where acl.grantee not in (relation.relowner, $4::oid)
                 or (acl.grantee = $4::oid and (
                   not $5::boolean or acl.privilege_type <> 'SELECT' or acl.is_grantable
                 ))
             )
             or has_sequence_privilege(runtime_role.oid, relation.oid, 'USAGE, SELECT, UPDATE')
             or ($5::boolean and not exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) acl
               where acl.grantee = $4::oid
                 and acl.privilege_type = 'SELECT'
                 and not acl.is_grantable
             ))
             or has_sequence_privilege($4::oid, relation.oid, 'SELECT') <> $5::boolean
             or has_sequence_privilege($4::oid, relation.oid, 'USAGE')
             or has_sequence_privilege($4::oid, relation.oid, 'UPDATE')
           )
       ) as unsafe`,
    [schemaName, [...REGISTRY_META_TABLES], [...REGISTRY_BUSINESS_TABLES], backupRoleOid, backupEnabled],
  )
  if (state.rows.length !== 1 || state.rows[0]?.unsafe) {
    throw new Error('PostgreSQL schema objects must expose only exact registry_app and registry_backup ACLs')
  }
}

async function migrateV1(client: PoolClient, schema: string, legacyTenantId: string | undefined): Promise<void> {
  const retained = await client.query<{ has_data: boolean }>(
    `select exists (select 1 from ${schema}.units) as has_data`,
  )
  if (retained.rows[0]?.has_data && legacyTenantId === undefined) {
    throw new StorageError('version-mismatch',
      'PostgreSQL schema v1 contains data; configure legacyTenantId explicitly before migration')
  }
  const tenantId = legacyTenantId ?? GLOBAL_TENANT_ID
  await client.query(`alter table ${schema}.units add column tenant_id text`)
  await client.query(`alter table ${schema}.unit_globals add column tenant_id text`)
  await client.query(`alter table ${schema}.unit_records add column tenant_id text`)
  await client.query(`update ${schema}.units set tenant_id = $1`, [tenantId])
  await client.query(`update ${schema}.unit_globals set tenant_id = $1`, [tenantId])
  await client.query(`update ${schema}.unit_records set tenant_id = $1`, [tenantId])
  await client.query(`alter table ${schema}.units alter column tenant_id set not null`)
  await client.query(`alter table ${schema}.unit_globals alter column tenant_id set not null`)
  await client.query(`alter table ${schema}.unit_records alter column tenant_id set not null`)
  await client.query(`alter table ${schema}.unit_globals drop constraint unit_globals_unit_fkey`)
  await client.query(`alter table ${schema}.unit_records drop constraint unit_records_unit_fkey`)
  await client.query(`alter table ${schema}.unit_globals drop constraint unit_globals_pkey`)
  await client.query(`alter table ${schema}.unit_records drop constraint unit_records_pkey`)
  await client.query(`alter table ${schema}.units drop constraint units_pkey`)
  await client.query(`alter table ${schema}.units
    add constraint units_pkey primary key (tenant_id, name)`)
  await client.query(`alter table ${schema}.unit_globals
    add constraint unit_globals_pkey primary key (tenant_id, unit),
    add constraint unit_globals_unit_fkey foreign key (tenant_id, unit)
      references ${schema}.units (tenant_id, name) on delete cascade`)
  await client.query(`alter table ${schema}.unit_records
    add constraint unit_records_pkey primary key (tenant_id, unit, table_name, key),
    add constraint unit_records_unit_fkey foreign key (tenant_id, unit)
      references ${schema}.units (tenant_id, name) on delete cascade`)
  await client.query(`update ${schema}.storage_meta set schema_version = $1 where singleton = true`,
    [STORAGE_POSTGRES_SCHEMA_VERSION])
}

async function createV2Tables(client: PoolClient, schema: string): Promise<void> {
  await client.query(`create table if not exists ${schema}.units (
    tenant_id text not null,
    name text not null,
    version integer not null check (version >= 0),
    constraint units_pkey primary key (tenant_id, name)
  )`)
  await client.query(`create table if not exists ${schema}.unit_globals (
    tenant_id text not null,
    unit text not null,
    value jsonb not null,
    constraint unit_globals_pkey primary key (tenant_id, unit),
    constraint unit_globals_unit_fkey foreign key (tenant_id, unit)
      references ${schema}.units (tenant_id, name) on delete cascade
  )`)
  await client.query(`create table if not exists ${schema}.unit_records (
    tenant_id text not null,
    unit text not null,
    table_name text not null,
    key text not null,
    value jsonb not null,
    constraint unit_records_pkey primary key (tenant_id, unit, table_name, key),
    constraint unit_records_unit_fkey foreign key (tenant_id, unit)
      references ${schema}.units (tenant_id, name) on delete cascade
  )`)
}

async function installTenantPolicies(client: PoolClient, schema: string): Promise<void> {
  for (const table of TENANT_TABLES) {
    await client.query(`alter table ${schema}.${table} enable row level security`)
    await client.query(`alter table ${schema}.${table} force row level security`)
    await client.query(`drop policy if exists ${TENANT_POLICY} on ${schema}.${table}`)
    await client.query(`create policy ${TENANT_POLICY} on ${schema}.${table}
      using (tenant_id = current_setting('app.tenant_id', true))
      with check (tenant_id = current_setting('app.tenant_id', true))`)
  }
}

async function migratePostgresSchema(pool: Pool, schemaName: string, legacyTenantId: string | undefined): Promise<void> {
  const schema = quoteIdentifier(schemaName)
  const client = await pool.connect()
  try {
    await client.query('begin')
    const lock = await client.query<{ acquired: boolean }>(
      `select pg_try_advisory_xact_lock(
         hashtextextended('dsh-registry-schema:' || $1::text, 0)
       ) as acquired`, [schemaName])
    if (lock.rows[0]?.acquired !== true) {
      throw new Error(`PostgreSQL schema '${schemaName}' is already being changed by another offline operation`)
    }
    await assertSafeRoleChain(client, ['pg_read_all_stats'])
    await client.query(`create table if not exists ${schema}.storage_meta (
      singleton boolean primary key default true check (singleton), schema_version integer not null check (schema_version > 0)
    )`)
    await client.query(`insert into ${schema}.storage_meta (singleton, schema_version) values (true, $1)
      on conflict (singleton) do nothing`, [STORAGE_POSTGRES_SCHEMA_VERSION])
    const meta = await client.query<{ schema_version: number }>(
      `select schema_version from ${schema}.storage_meta where singleton = true`,
    )
    const version = meta.rows[0]?.schema_version
    if (meta.rows.length !== 1 || (version !== 1 && version !== STORAGE_POSTGRES_SCHEMA_VERSION)) {
      throw new StorageError('version-mismatch', 'PostgreSQL storage schema version is incompatible with this build')
    }
    if (version === 1) await migrateV1(client, schema, legacyTenantId)
    await createV2Tables(client, schema)
    await installTenantPolicies(client, schema)
    await client.query('commit')
  } catch (error) {
    await rollback(client, error)
  } finally {
    client.release()
  }
}

function schemaValidationError(reason: string): StorageError {
  return new StorageError('version-mismatch', `PostgreSQL storage schema validation failed: ${reason}`)
}

function normalizePolicyExpression(expression: string): string {
  let normalized = expression.replace(/\s+/g, '').replace(/::text/g, '')
  if (normalized.startsWith('(') && normalized.endsWith(')')) normalized = normalized.slice(1, -1)
  return normalized
}

async function validatePostgresSchema(pool: Pool, schemaName: string,
  allowUnsafeSharedDatabase = false): Promise<void> {
  const client = await pool.connect()
  try {
    await client.query('begin isolation level repeatable read read only')
    const runtimeIdentity = await client.query<{ readonly expected: boolean }>(
      `select current_user = 'registry_app' as expected`)
    if (runtimeIdentity.rows.length !== 1 || runtimeIdentity.rows[0]?.expected !== true) {
      throw new Error('PostgreSQL runtime connection must authenticate as registry_app')
    }
    await assertSafeRoleChain(client, [])
    await assertRuntimeDatabasePrivileges(client, allowUnsafeSharedDatabase)
    const backupRoleOid = await assertExactRegistryBackupRole(client)

    const schemaAccess = await client.query<{
      readonly acl_is_exact: boolean
      readonly backup_can_create: boolean
      readonly backup_can_use: boolean
      readonly backup_enabled: boolean
      readonly can_create: boolean
      readonly can_use: boolean
      readonly owner_is_migrator: boolean
    }>(
      `select exists (
         select 1 from pg_roles candidate
         where pg_has_role(current_user, candidate.oid, 'MEMBER')
           and has_schema_privilege(candidate.oid, namespace.oid, 'CREATE')
       ) as can_create,
       has_schema_privilege(current_user, namespace.oid, 'USAGE') as can_use,
       has_schema_privilege($2::oid, namespace.oid, 'CREATE') as backup_can_create,
       has_schema_privilege($2::oid, namespace.oid, 'USAGE') as backup_can_use,
       exists (
         select 1
         from aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) acl
         where acl.grantee = $2::oid
           and acl.privilege_type = 'USAGE'
           and not acl.is_grantable
       ) as backup_enabled,
       pg_get_userbyid(namespace.nspowner) = 'registry_migrator' as owner_is_migrator,
       not exists (
         select 1
         from aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) acl
         where acl.grantee not in (
             namespace.nspowner, (select oid from pg_roles where rolname = current_user), $2::oid
           )
           or (acl.grantee = (select oid from pg_roles where rolname = current_user)
             and (acl.privilege_type <> 'USAGE' or acl.is_grantable))
           or (acl.grantee = $2::oid
             and (acl.privilege_type <> 'USAGE' or acl.is_grantable))
       ) as acl_is_exact
       from pg_namespace namespace where namespace.nspname = $1`,
      [schemaName, backupRoleOid],
    )
    if (schemaAccess.rows.length !== 1) throw schemaValidationError('configured schema does not exist')
    const selectedSchema = schemaAccess.rows[0]
    if (selectedSchema?.can_create || !selectedSchema?.can_use || selectedSchema?.backup_can_create
      || selectedSchema?.backup_can_use !== selectedSchema?.backup_enabled
      || !selectedSchema?.owner_is_migrator || !selectedSchema?.acl_is_exact) {
      throw new Error('PostgreSQL storage schema must have exact registry_app and optional registry_backup USAGE ACLs')
    }
    if (selectedSchema.backup_enabled) {
      await assertRegistryBackupTargetIsolation(client, schemaName, backupRoleOid)
    }
    await assertRegistryBackupDefaultPrivileges(client, schemaName, backupRoleOid,
      selectedSchema.backup_enabled)
    await assertExactRegistryObjectPrivileges(client, schemaName, backupRoleOid, selectedSchema.backup_enabled)

    const tables = await client.query<{
      readonly table_name: string
      readonly row_security: boolean
      readonly force_row_security: boolean
      readonly may_assume_owner: boolean
      readonly can_select: boolean
      readonly can_insert: boolean
      readonly can_update: boolean
      readonly can_delete: boolean
      readonly reachable_insert: boolean
      readonly reachable_update: boolean
      readonly reachable_delete: boolean
      readonly reachable_truncate: boolean
      readonly reachable_references: boolean
      readonly reachable_trigger: boolean
      readonly reachable_maintain: boolean
    }>(
      `select c.relname as table_name, c.relrowsecurity as row_security,
              c.relforcerowsecurity as force_row_security,
              pg_has_role(current_user, c.relowner, 'MEMBER') as may_assume_owner,
              has_table_privilege(current_user, c.oid, 'SELECT') as can_select,
              has_table_privilege(current_user, c.oid, 'INSERT') as can_insert,
              has_table_privilege(current_user, c.oid, 'UPDATE') as can_update,
              has_table_privilege(current_user, c.oid, 'DELETE') as can_delete,
              exists (
                select 1 from pg_roles candidate
                where (candidate.rolname = current_user
                       or pg_has_role(current_user, candidate.oid, 'MEMBER')
                       or pg_has_role(current_user, candidate.oid, 'SET'))
                  and (has_table_privilege(candidate.oid, c.oid, 'INSERT')
                       or has_any_column_privilege(candidate.oid, c.oid, 'INSERT'))
              ) as reachable_insert,
              exists (
                select 1 from pg_roles candidate
                where (candidate.rolname = current_user
                       or pg_has_role(current_user, candidate.oid, 'MEMBER')
                       or pg_has_role(current_user, candidate.oid, 'SET'))
                  and (has_table_privilege(candidate.oid, c.oid, 'UPDATE')
                       or has_any_column_privilege(candidate.oid, c.oid, 'UPDATE'))
              ) as reachable_update,
              exists (
                select 1 from pg_roles candidate
                where (candidate.rolname = current_user
                       or pg_has_role(current_user, candidate.oid, 'MEMBER')
                       or pg_has_role(current_user, candidate.oid, 'SET'))
                  and has_table_privilege(candidate.oid, c.oid, 'DELETE')
              ) as reachable_delete,
              exists (
                select 1 from pg_roles candidate
                where (candidate.rolname = current_user
                       or pg_has_role(current_user, candidate.oid, 'MEMBER')
                       or pg_has_role(current_user, candidate.oid, 'SET'))
                  and has_table_privilege(candidate.oid, c.oid, 'TRUNCATE')
              ) as reachable_truncate,
              exists (
                select 1 from pg_roles candidate
                where (candidate.rolname = current_user
                       or pg_has_role(current_user, candidate.oid, 'MEMBER')
                       or pg_has_role(current_user, candidate.oid, 'SET'))
                  and (has_table_privilege(candidate.oid, c.oid, 'REFERENCES')
                       or has_any_column_privilege(candidate.oid, c.oid, 'REFERENCES'))
              ) as reachable_references,
              exists (
                select 1 from pg_roles candidate
                where (candidate.rolname = current_user
                       or pg_has_role(current_user, candidate.oid, 'MEMBER')
                       or pg_has_role(current_user, candidate.oid, 'SET'))
                  and has_table_privilege(candidate.oid, c.oid, 'TRIGGER')
              ) as reachable_trigger,
              exists (
                select 1 from pg_roles candidate
                where (candidate.rolname = current_user
                       or pg_has_role(current_user, candidate.oid, 'MEMBER')
                       or pg_has_role(current_user, candidate.oid, 'SET'))
                  and has_table_privilege(candidate.oid, c.oid, 'MAINTAIN')
              ) as reachable_maintain
       from pg_class c join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = $1 and c.relname = any($2::text[]) and c.relkind in ('r', 'p')
       order by c.relname`,
      [schemaName, [...STORAGE_TABLES]],
    )
    if (tables.rows.length !== STORAGE_TABLES.length
      || STORAGE_TABLES.some(name => !tables.rows.some(row => row.table_name === name))) {
      throw schemaValidationError('required v2 tables are missing')
    }
    if (tables.rows.some(row => row.may_assume_owner)) {
      throw new Error('PostgreSQL runtime role must not own or be a member of an owner role for storage tables')
    }
    for (const relation of tables.rows) {
      const hasUnsafeDdl = relation.reachable_truncate || relation.reachable_references
        || relation.reachable_trigger || relation.reachable_maintain
      if (relation.table_name === 'storage_meta') {
        if (!relation.can_select || relation.reachable_insert || relation.reachable_update
          || relation.reachable_delete || hasUnsafeDdl) {
          throw schemaValidationError("table 'storage_meta' must grant only SELECT to the runtime role")
        }
      } else if (!relation.can_select || !relation.can_insert || !relation.can_update || !relation.can_delete
        || hasUnsafeDdl) {
        throw schemaValidationError(`table '${relation.table_name}' must grant runtime CRUD and forbid DDL privileges`)
      }
    }
    for (const table of TENANT_TABLES) {
      const relation = tables.rows.find(row => row.table_name === table)
      if (!relation?.row_security || !relation.force_row_security) {
        throw schemaValidationError(`table '${table}' must enable and force row-level security`)
      }
    }

    const meta = await client.query<{ readonly schema_version: number }>(
      `select schema_version from ${quoteIdentifier(schemaName)}.storage_meta where singleton = true`,
    )
    if (meta.rows.length !== 1 || meta.rows[0]?.schema_version !== STORAGE_POSTGRES_SCHEMA_VERSION) {
      throw schemaValidationError(`schema version must equal ${STORAGE_POSTGRES_SCHEMA_VERSION}`)
    }

    const tenantColumns = await client.query<{ readonly table_name: string }>(
      `select c.relname as table_name
       from pg_class c join pg_namespace n on n.oid = c.relnamespace
       join pg_attribute a on a.attrelid = c.oid
       where n.nspname = $1 and c.relname = any($2::text[]) and c.relkind in ('r', 'p')
         and a.attname = 'tenant_id' and a.atttypid = 'text'::regtype and a.attnotnull and not a.attisdropped`,
      [schemaName, [...TENANT_TABLES]],
    )
    if (tenantColumns.rows.length !== TENANT_TABLES.length) {
      throw schemaValidationError('tenant tables must contain a non-null text tenant_id column')
    }

    const policies = await client.query<{
      readonly table_name: string
      readonly policy_name: string
      readonly all_commands: boolean
      readonly permissive: boolean
      readonly public_only: boolean
      readonly qualification: string
      readonly check_expression: string
    }>(
      `select c.relname as table_name, p.polname as policy_name, p.polcmd = '*' as all_commands,
              p.polpermissive as permissive, p.polroles = array[0::oid] as public_only,
              coalesce(pg_get_expr(p.polqual, p.polrelid), '') as qualification,
              coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') as check_expression
       from pg_policy p join pg_class c on c.oid = p.polrelid
       join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = $1 and c.relname = any($2::text[])
       order by c.relname, p.polname`,
      [schemaName, [...TENANT_TABLES]],
    )
    const expectedExpression = "tenant_id=current_setting('app.tenant_id',true)"
    for (const table of TENANT_TABLES) {
      const policy = policies.rows.filter(row => row.table_name === table)
      if (policy.length !== 1 || policy[0]?.policy_name !== TENANT_POLICY || !policy[0]?.all_commands
        || !policy[0]?.permissive || !policy[0]?.public_only
        || normalizePolicyExpression(policy[0]?.qualification ?? '') !== expectedExpression
        || normalizePolicyExpression(policy[0]?.check_expression ?? '') !== expectedExpression) {
        throw schemaValidationError(`table '${table}' does not have the exact tenant-isolation policy`)
      }
    }
    await client.query('commit')
  } catch (error) {
    await rollback(client, error)
  } finally {
    client.release()
  }
}

/** Run schema creation/upgrades as an explicit offline operation, then close every connection. */
export async function migratePostgresStorageSchema(config: PostgresSchemaMigrationConfig): Promise<void> {
  const pool = createPostgresPool(config, 'dsh-a2a-registry-schema-migrator', 1)
  try {
    await migratePostgresSchema(pool, config.schema ?? 'registry', config.legacyTenantId)
  } finally {
    await pool.end()
  }
}

/** Run the same read-only schema/role checks used by an online `validate` backend. */
export async function validatePostgresStorageSchema(config: PostgresSchemaValidationConfig): Promise<void> {
  const pool = createPostgresPool(config, 'dsh-a2a-registry-schema-validator', 1)
  try {
    await validatePostgresSchema(pool, config.schema ?? 'registry', config.allowUnsafeSharedDatabase ?? false)
  } finally {
    await pool.end()
  }
}

async function tenantTransaction<T>(pool: Pool, tenantId: string,
  operation: (client: PoolClient) => Promise<T>, readOnly = false): Promise<T> {
  const client = await pool.connect()
  try {
    await client.query(readOnly ? 'begin isolation level repeatable read read only' : 'begin')
    await client.query(`select set_config('app.tenant_id', $1, true)`, [tenantId])
    const result = await operation(client)
    await client.query('commit')
    return result
  } catch (error) {
    return rollback(client, error)
  } finally {
    client.release()
  }
}

class PostgresKvUnit implements KvUnit {
  private closed = false

  constructor(
    private readonly pool: Pool,
    private readonly schema: string,
    private readonly tenantId: string,
    private readonly descriptor: KvUnitDescriptor,
    private readonly onClose: () => void,
  ) {}

  async loadAll(): Promise<{ tables: Record<string, Record<string, unknown>>; global: unknown }> {
    this.ensureOpen()
    return tenantTransaction(this.pool, this.tenantId, async (client) => {
      const records = await client.query<{ table_name: string; key: string; value: unknown }>(
        `select table_name, key, value from ${this.schema}.unit_records
         where tenant_id = $1 and unit = $2 order by table_name, key`,
        [this.tenantId, this.descriptor.name],
      )
      const globals = this.descriptor.hasGlobal
        ? await client.query<{ value: unknown }>(
          `select value from ${this.schema}.unit_globals where tenant_id = $1 and unit = $2`,
          [this.tenantId, this.descriptor.name],
        )
        : { rows: [] as Array<{ value: unknown }> }
      const tables: Record<string, Record<string, unknown>> = Object.create(null) as Record<string, Record<string, unknown>>
      for (const table of this.descriptor.tables) tables[table] = Object.create(null) as Record<string, unknown>
      for (const row of records.rows) {
        const table = tables[row.table_name]
        if (table === undefined) throw new StorageError('malformed-medium', `PostgreSQL unit '${this.descriptor.name}' contains an undeclared table`)
        table[row.key] = row.value
      }
      return { tables, global: globals.rows[0]?.value ?? null }
    }, true)
  }

  async putRecord(table: string, key: string, value: unknown): Promise<void> {
    this.ensureTable(table)
    await tenantTransaction(this.pool, this.tenantId, async (client) => {
      await client.query(
        `insert into ${this.schema}.unit_records (tenant_id, unit, table_name, key, value)
         values ($1, $2, $3, $4, $5::jsonb)
         on conflict (tenant_id, unit, table_name, key) do update set value = excluded.value`,
        [this.tenantId, this.descriptor.name, table, key, captureJson(value)],
      )
    })
  }

  async putRecords(records: readonly KvRecordWrite[]): Promise<void> {
    this.ensureOpen()
    const seen = new Set<string>()
    const tables: string[] = []
    const keys: string[] = []
    const values: string[] = []
    for (const record of records) {
      this.ensureTable(record.table)
      const identity = JSON.stringify([record.table, record.key])
      if (seen.has(identity)) throw new Error('atomic record batch contains a duplicate table/key pair')
      seen.add(identity)
      tables.push(record.table)
      keys.push(record.key)
      values.push(captureJson(record.value))
    }
    if (records.length === 0) return
    await tenantTransaction(this.pool, this.tenantId, async (client) => {
      await client.query(
        `insert into ${this.schema}.unit_records (tenant_id, unit, table_name, key, value)
         select $1, $2, input.table_name, input.key, input.value::jsonb
         from unnest($3::text[], $4::text[], $5::text[]) as input(table_name, key, value)
         on conflict (tenant_id, unit, table_name, key) do update set value = excluded.value`,
        [this.tenantId, this.descriptor.name, tables, keys, values],
      )
    })
  }

  async deleteRecord(table: string, key: string): Promise<void> {
    this.ensureTable(table)
    await tenantTransaction(this.pool, this.tenantId, async (client) => {
      await client.query(
        `delete from ${this.schema}.unit_records
         where tenant_id = $1 and unit = $2 and table_name = $3 and key = $4`,
        [this.tenantId, this.descriptor.name, table, key],
      )
    })
  }

  async setGlobal(value: unknown): Promise<void> {
    this.ensureOpen()
    if (!this.descriptor.hasGlobal) throw new Error(`kv unit '${this.descriptor.name}' declared no global slot`)
    await tenantTransaction(this.pool, this.tenantId, async (client) => {
      await client.query(
        `insert into ${this.schema}.unit_globals (tenant_id, unit, value) values ($1, $2, $3::jsonb)
         on conflict (tenant_id, unit) do update set value = excluded.value`,
        [this.tenantId, this.descriptor.name, captureJson(value)],
      )
    })
  }

  close(): Promise<void> {
    if (!this.closed) {
      this.closed = true
      this.onClose()
    }
    return Promise.resolve()
  }

  private ensureTable(table: string): void {
    this.ensureOpen()
    if (!this.descriptor.tables.includes(table)) throw new Error(`kv unit '${this.descriptor.name}' declared no table '${table}'`)
  }

  private ensureOpen(): void {
    if (this.closed) throw new StorageError('closed', `kv unit '${this.descriptor.name}' is closed`)
  }
}

export class PostgresStorageBackend implements StorageBackend {
  readonly kv: KvFacet = { open: descriptor => this.openUnit(descriptor) }
  private readonly pool: Pool
  private readonly schema: string
  private readonly ready: Promise<void>
  private readonly units = new Map<string, Promise<PostgresKvUnit>>()
  private closing?: Promise<void>

  constructor(config: Config) {
    const schemaName = config.schema ?? 'registry'
    this.schema = quoteIdentifier(schemaName)
    const schemaMode = config.schemaMode ?? 'migrate'
    if (schemaMode !== 'migrate' && schemaMode !== 'validate') {
      throw new Error("PostgreSQL schemaMode must be either 'migrate' or 'validate'")
    }
    if (schemaMode === 'validate' && config.legacyTenantId !== undefined) {
      throw new Error('PostgreSQL legacyTenantId is valid only when schemaMode is migrate')
    }
    this.pool = createPostgresPool(config, 'dsh-a2a-registry')
    this.ready = schemaMode === 'validate'
      ? validatePostgresSchema(this.pool, schemaName, config.allowUnsafeSharedDatabase ?? false)
      : migratePostgresSchema(this.pool, schemaName, config.legacyTenantId)
    this.ready.catch(() => {})
  }

  /** Live read through the actual storage pool; the client-side timeout also
   * evicts a stuck pooled connection instead of leaving readiness wedged. */
  async checkReadiness(): Promise<boolean> {
    if (this.closing !== undefined) return false
    try {
      await this.ready
      const result = await this.pool.query<{ readonly schema_version: number }>({
        text: `select schema_version from ${this.schema}.storage_meta where singleton = true`,
        query_timeout: READINESS_QUERY_TIMEOUT_MS,
      } as { readonly text: string; readonly query_timeout: number })
      return result.rows.length === 1
        && result.rows[0]?.schema_version === STORAGE_POSTGRES_SCHEMA_VERSION
    } catch {
      return false
    }
  }

  private openUnit(descriptor: KvUnitDescriptor): Promise<KvUnit> {
    if (this.closing !== undefined) return Promise.reject(new StorageError('closed', 'postgres storage backend is closed'))
    if (!UNIT_NAME_RE.test(descriptor.name)) return Promise.reject(new Error(`kv unit name '${descriptor.name}' violates ${UNIT_NAME_RE}`))
    for (const table of descriptor.tables) {
      if (!UNIT_NAME_RE.test(table)) return Promise.reject(new Error(`kv table name '${table}' in unit '${descriptor.name}' violates ${UNIT_NAME_RE}`))
    }
    let tenantId: string
    try { tenantId = tenantIdOf(descriptor) } catch (error) { return Promise.reject(error) }
    const unitKey = openUnitKey(tenantId, descriptor.name)
    if (this.units.has(unitKey)) return Promise.reject(new Error(`kv unit '${descriptor.name}' is already open for this tenant (double-open is a caller bug)`))
    const pending = this.materializeUnit(descriptor, tenantId, unitKey)
    this.units.set(unitKey, pending)
    pending.catch(() => this.units.delete(unitKey))
    return pending
  }

  private async materializeUnit(descriptor: KvUnitDescriptor, tenantId: string,
    unitKey: string): Promise<PostgresKvUnit> {
    await this.ready
    const result = await tenantTransaction(this.pool, tenantId, client => client.query<{ version: number }>(
      `insert into ${this.schema}.units (tenant_id, name, version) values ($1, $2, $3)
       on conflict (tenant_id, name) do update set name = excluded.name returning version`,
      [tenantId, descriptor.name, descriptor.version],
    ))
    if (result.rows[0]?.version !== descriptor.version) {
      throw new StorageError('version-mismatch', `kv unit '${descriptor.name}' has an incompatible PostgreSQL version stamp`)
    }
    return new PostgresKvUnit(this.pool, this.schema, tenantId, descriptor, () => { this.units.delete(unitKey) })
  }

  close(): Promise<void> {
    this.closing ??= this.doClose()
    return this.closing
  }

  private async doClose(): Promise<void> {
    await this.ready.catch(() => undefined)
    for (const pending of [...this.units.values()]) await (await pending.catch(() => undefined))?.close()
    await this.pool.end()
  }
}

export function apply(ctx: Context, config: Config) {
  const backend = new PostgresStorageBackend(config)
  ctx.effect(() => {
    const dispose = ctx.storage.backend.register('postgres', backend)
    return async () => {
      dispose()
      await backend.close()
    }
  }, 'storage-postgres.registerBackend')
  ctx.provide(storageBackendServiceKey('postgres'), backend)
}
