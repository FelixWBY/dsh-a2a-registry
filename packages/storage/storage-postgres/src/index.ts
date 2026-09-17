/** PostgreSQL-backed tenant-scoped KV storage for independently deployed Registry domains. */
import { createHash } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { Pool, type PoolClient } from 'pg'
import { StorageError, UNIT_NAME_RE, storageBackendServiceKey } from '@deepseek-ai/dsh-storage'
import type { KvFacet, KvRecordWrite, KvUnit, KvUnitDescriptor, StorageBackend } from '@deepseek-ai/dsh-storage'

export const name = 'storage-postgres'
export const inject = ['storage']
export const STORAGE_POSTGRES_SCHEMA_VERSION = 2

const GLOBAL_TENANT_ID = ''
const TENANT_POLICY = 'tenant_isolation'

export interface Config {
  /** PostgreSQL connection string supplied by the deployment secret store. */
  connectionString: string
  /** Dedicated application schema owned by the non-superuser Registry role. */
  schema?: string
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
  legacyTenantId: z.string(),
  maxConnections: z.number().min(1).max(32).step(1).default(8),
  idleTimeoutMs: z.number().min(1_000).max(600_000).step(1).default(30_000),
  statementTimeoutMs: z.number().min(1_000).max(120_000).step(1).default(15_000),
})

function quoteIdentifier(value: string): string {
  if (!UNIT_NAME_RE.test(value)) throw new Error(`PostgreSQL schema '${value}' violates ${UNIT_NAME_RE}`)
  return `"${value}"`
}

function schemaAdvisoryLockKey(value: string): string {
  const digest = createHash('sha256').update('dsh-storage-postgres-schema-v2\0', 'utf8').update(value, 'utf8').digest()
  return digest.readBigInt64BE(0).toString()
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
  private readonly schemaLockKey: string
  private readonly ready: Promise<void>
  private readonly units = new Map<string, Promise<PostgresKvUnit>>()
  private closing?: Promise<void>

  constructor(config: Config) {
    const schemaName = config.schema ?? 'registry'
    this.schema = quoteIdentifier(schemaName)
    this.schemaLockKey = schemaAdvisoryLockKey(schemaName)
    this.pool = new Pool({
      connectionString: config.connectionString,
      max: config.maxConnections ?? 8,
      idleTimeoutMillis: config.idleTimeoutMs ?? 30_000,
      connectionTimeoutMillis: 10_000,
      statement_timeout: config.statementTimeoutMs ?? 15_000,
      idle_in_transaction_session_timeout: 30_000,
      application_name: 'dsh-a2a-registry',
    })
    this.ready = this.initialize(config.legacyTenantId)
    this.ready.catch(() => {})
  }

  private async initialize(legacyTenantId: string | undefined): Promise<void> {
    const client = await this.pool.connect()
    try {
      await client.query('begin')
      await client.query('select pg_advisory_xact_lock($1::bigint)', [this.schemaLockKey])
      const role = await client.query<{ readonly rolsuper: boolean; readonly rolbypassrls: boolean }>(
        'select rolsuper, rolbypassrls from pg_roles where rolname = current_user',
      )
      if (role.rows.length !== 1 || role.rows[0]?.rolsuper || role.rows[0]?.rolbypassrls) {
        throw new Error('PostgreSQL storage requires a non-superuser role without BYPASSRLS')
      }
      await client.query(`create table if not exists ${this.schema}.storage_meta (
        singleton boolean primary key default true check (singleton), schema_version integer not null check (schema_version > 0)
      )`)
      await client.query(`insert into ${this.schema}.storage_meta (singleton, schema_version) values (true, $1)
        on conflict (singleton) do nothing`, [STORAGE_POSTGRES_SCHEMA_VERSION])
      const meta = await client.query<{ schema_version: number }>(
        `select schema_version from ${this.schema}.storage_meta where singleton = true`,
      )
      const version = meta.rows[0]?.schema_version
      if (meta.rows.length !== 1 || (version !== 1 && version !== STORAGE_POSTGRES_SCHEMA_VERSION)) {
        throw new StorageError('version-mismatch', 'PostgreSQL storage schema version is incompatible with this build')
      }
      if (version === 1) await this.migrateV1(client, legacyTenantId)
      await this.createV2Tables(client)
      await this.installTenantPolicies(client)
      await client.query('commit')
    } catch (error) {
      await rollback(client, error)
    } finally {
      client.release()
    }
  }

  private async migrateV1(client: PoolClient, legacyTenantId: string | undefined): Promise<void> {
    const retained = await client.query<{ has_data: boolean }>(
      `select exists (select 1 from ${this.schema}.units) as has_data`,
    )
    if (retained.rows[0]?.has_data && legacyTenantId === undefined) {
      throw new StorageError('version-mismatch',
        'PostgreSQL schema v1 contains data; configure legacyTenantId explicitly before migration')
    }
    const tenantId = legacyTenantId ?? GLOBAL_TENANT_ID
    await client.query(`alter table ${this.schema}.units add column tenant_id text`)
    await client.query(`alter table ${this.schema}.unit_globals add column tenant_id text`)
    await client.query(`alter table ${this.schema}.unit_records add column tenant_id text`)
    await client.query(`update ${this.schema}.units set tenant_id = $1`, [tenantId])
    await client.query(`update ${this.schema}.unit_globals set tenant_id = $1`, [tenantId])
    await client.query(`update ${this.schema}.unit_records set tenant_id = $1`, [tenantId])
    await client.query(`alter table ${this.schema}.units alter column tenant_id set not null`)
    await client.query(`alter table ${this.schema}.unit_globals alter column tenant_id set not null`)
    await client.query(`alter table ${this.schema}.unit_records alter column tenant_id set not null`)
    await client.query(`alter table ${this.schema}.unit_globals drop constraint unit_globals_unit_fkey`)
    await client.query(`alter table ${this.schema}.unit_records drop constraint unit_records_unit_fkey`)
    await client.query(`alter table ${this.schema}.unit_globals drop constraint unit_globals_pkey`)
    await client.query(`alter table ${this.schema}.unit_records drop constraint unit_records_pkey`)
    await client.query(`alter table ${this.schema}.units drop constraint units_pkey`)
    await client.query(`alter table ${this.schema}.units
      add constraint units_pkey primary key (tenant_id, name)`)
    await client.query(`alter table ${this.schema}.unit_globals
      add constraint unit_globals_pkey primary key (tenant_id, unit),
      add constraint unit_globals_unit_fkey foreign key (tenant_id, unit)
        references ${this.schema}.units (tenant_id, name) on delete cascade`)
    await client.query(`alter table ${this.schema}.unit_records
      add constraint unit_records_pkey primary key (tenant_id, unit, table_name, key),
      add constraint unit_records_unit_fkey foreign key (tenant_id, unit)
        references ${this.schema}.units (tenant_id, name) on delete cascade`)
    await client.query(`update ${this.schema}.storage_meta set schema_version = $1 where singleton = true`,
      [STORAGE_POSTGRES_SCHEMA_VERSION])
  }

  private async createV2Tables(client: PoolClient): Promise<void> {
    await client.query(`create table if not exists ${this.schema}.units (
      tenant_id text not null,
      name text not null,
      version integer not null check (version >= 0),
      constraint units_pkey primary key (tenant_id, name)
    )`)
    await client.query(`create table if not exists ${this.schema}.unit_globals (
      tenant_id text not null,
      unit text not null,
      value jsonb not null,
      constraint unit_globals_pkey primary key (tenant_id, unit),
      constraint unit_globals_unit_fkey foreign key (tenant_id, unit)
        references ${this.schema}.units (tenant_id, name) on delete cascade
    )`)
    await client.query(`create table if not exists ${this.schema}.unit_records (
      tenant_id text not null,
      unit text not null,
      table_name text not null,
      key text not null,
      value jsonb not null,
      constraint unit_records_pkey primary key (tenant_id, unit, table_name, key),
      constraint unit_records_unit_fkey foreign key (tenant_id, unit)
        references ${this.schema}.units (tenant_id, name) on delete cascade
    )`)
  }

  private async installTenantPolicies(client: PoolClient): Promise<void> {
    for (const table of ['units', 'unit_globals', 'unit_records']) {
      await client.query(`alter table ${this.schema}.${table} enable row level security`)
      await client.query(`alter table ${this.schema}.${table} force row level security`)
      await client.query(`drop policy if exists ${TENANT_POLICY} on ${this.schema}.${table}`)
      await client.query(`create policy ${TENANT_POLICY} on ${this.schema}.${table}
        using (tenant_id = current_setting('app.tenant_id', true))
        with check (tenant_id = current_setting('app.tenant_id', true))`)
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
