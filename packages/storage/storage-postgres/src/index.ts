/** PostgreSQL-backed KV storage for independently deployed Registry domains. */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { Pool, type PoolClient } from 'pg'
import { StorageError, UNIT_NAME_RE, storageBackendServiceKey } from '@deepseek-ai/dsh-storage'
import type { KvFacet, KvRecordWrite, KvUnit, KvUnitDescriptor, StorageBackend } from '@deepseek-ai/dsh-storage'

export const name = 'storage-postgres'
export const inject = ['storage']
export const STORAGE_POSTGRES_SCHEMA_VERSION = 1

export interface Config {
  /** PostgreSQL connection string supplied by the deployment secret store. */
  connectionString: string
  /** Dedicated application schema owned by the non-superuser Registry role. */
  schema?: string
  /** Small process-local pool; a production pooler may sit in front of this connection. */
  maxConnections?: number
  idleTimeoutMs?: number
  statementTimeoutMs?: number
}

export const Config: z<Config> = z.object({
  connectionString: z.string().required(),
  schema: z.string().default('registry'),
  maxConnections: z.number().min(1).max(32).step(1).default(8),
  idleTimeoutMs: z.number().min(1_000).max(600_000).step(1).default(30_000),
  statementTimeoutMs: z.number().min(1_000).max(120_000).step(1).default(15_000),
})

function quoteIdentifier(value: string): string {
  if (!UNIT_NAME_RE.test(value)) throw new Error(`PostgreSQL schema '${value}' violates ${UNIT_NAME_RE}`)
  return `"${value}"`
}

function captureJson(value: unknown): string {
  const encoded = JSON.stringify(value)
  if (encoded === undefined) throw new Error('PostgreSQL storage values must be JSON serializable')
  return encoded
}

async function rollback(client: PoolClient, original: unknown): Promise<never> {
  try { await client.query('rollback') } catch (rollbackError) {
    throw new AggregateError([original, rollbackError], 'PostgreSQL transaction rollback failed')
  }
  throw original
}

class PostgresKvUnit implements KvUnit {
  private closed = false

  constructor(
    private readonly pool: Pool,
    private readonly schema: string,
    private readonly descriptor: KvUnitDescriptor,
    private readonly onClose: () => void,
  ) {}

  async loadAll(): Promise<{ tables: Record<string, Record<string, unknown>>; global: unknown }> {
    this.ensureOpen()
    const client = await this.pool.connect()
    try {
      await client.query('begin isolation level repeatable read read only')
      const records = await client.query<{ table_name: string; key: string; value: unknown }>(
        `select table_name, key, value from ${this.schema}.unit_records where unit = $1 order by table_name, key`,
        [this.descriptor.name],
      )
      const globals = this.descriptor.hasGlobal
        ? await client.query<{ value: unknown }>(`select value from ${this.schema}.unit_globals where unit = $1`, [this.descriptor.name])
        : { rows: [] as Array<{ value: unknown }> }
      const tables: Record<string, Record<string, unknown>> = Object.create(null) as Record<string, Record<string, unknown>>
      for (const table of this.descriptor.tables) tables[table] = Object.create(null) as Record<string, unknown>
      for (const row of records.rows) {
        const table = tables[row.table_name]
        if (table === undefined) throw new StorageError('malformed-medium', `PostgreSQL unit '${this.descriptor.name}' contains an undeclared table`)
        table[row.key] = row.value
      }
      await client.query('commit')
      return { tables, global: globals.rows[0]?.value ?? null }
    } catch (error) {
      return rollback(client, error)
    } finally {
      client.release()
    }
  }

  async putRecord(table: string, key: string, value: unknown): Promise<void> {
    this.ensureTable(table)
    await this.pool.query(
      `insert into ${this.schema}.unit_records (unit, table_name, key, value) values ($1, $2, $3, $4::jsonb)
       on conflict (unit, table_name, key) do update set value = excluded.value`,
      [this.descriptor.name, table, key, captureJson(value)],
    )
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
    await this.pool.query(
      `insert into ${this.schema}.unit_records (unit, table_name, key, value)
       select $1, input.table_name, input.key, input.value::jsonb
       from unnest($2::text[], $3::text[], $4::text[]) as input(table_name, key, value)
       on conflict (unit, table_name, key) do update set value = excluded.value`,
      [this.descriptor.name, tables, keys, values],
    )
  }

  async deleteRecord(table: string, key: string): Promise<void> {
    this.ensureTable(table)
    await this.pool.query(
      `delete from ${this.schema}.unit_records where unit = $1 and table_name = $2 and key = $3`,
      [this.descriptor.name, table, key],
    )
  }

  async setGlobal(value: unknown): Promise<void> {
    this.ensureOpen()
    if (!this.descriptor.hasGlobal) throw new Error(`kv unit '${this.descriptor.name}' declared no global slot`)
    await this.pool.query(
      `insert into ${this.schema}.unit_globals (unit, value) values ($1, $2::jsonb)
       on conflict (unit) do update set value = excluded.value`,
      [this.descriptor.name, captureJson(value)],
    )
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
    this.schema = quoteIdentifier(config.schema ?? 'registry')
    this.pool = new Pool({
      connectionString: config.connectionString,
      max: config.maxConnections ?? 8,
      idleTimeoutMillis: config.idleTimeoutMs ?? 30_000,
      connectionTimeoutMillis: 10_000,
      statement_timeout: config.statementTimeoutMs ?? 15_000,
      idle_in_transaction_session_timeout: 30_000,
      application_name: 'dsh-a2a-registry',
    })
    this.ready = this.initialize()
    this.ready.catch(() => {})
  }

  private async initialize(): Promise<void> {
    const client = await this.pool.connect()
    try {
      await client.query('begin')
      await client.query(`create table if not exists ${this.schema}.storage_meta (
        singleton boolean primary key default true check (singleton), schema_version integer not null check (schema_version > 0)
      )`)
      await client.query(`insert into ${this.schema}.storage_meta (singleton, schema_version) values (true, $1)
        on conflict (singleton) do nothing`, [STORAGE_POSTGRES_SCHEMA_VERSION])
      const meta = await client.query<{ schema_version: number }>(`select schema_version from ${this.schema}.storage_meta where singleton = true`)
      if (meta.rows.length !== 1 || meta.rows[0]?.schema_version !== STORAGE_POSTGRES_SCHEMA_VERSION) {
        throw new StorageError('version-mismatch', 'PostgreSQL storage schema version is incompatible with this build')
      }
      await client.query(`create table if not exists ${this.schema}.units (
        name text primary key, version integer not null check (version >= 0)
      )`)
      await client.query(`create table if not exists ${this.schema}.unit_globals (
        unit text primary key references ${this.schema}.units(name) on delete cascade, value jsonb not null
      )`)
      await client.query(`create table if not exists ${this.schema}.unit_records (
        unit text not null references ${this.schema}.units(name) on delete cascade,
        table_name text not null,
        key text not null,
        value jsonb not null,
        primary key (unit, table_name, key)
      )`)
      await client.query('commit')
    } catch (error) {
      await rollback(client, error)
    } finally {
      client.release()
    }
  }

  private openUnit(descriptor: KvUnitDescriptor): Promise<KvUnit> {
    if (this.closing !== undefined) return Promise.reject(new StorageError('closed', 'postgres storage backend is closed'))
    if (!UNIT_NAME_RE.test(descriptor.name)) return Promise.reject(new Error(`kv unit name '${descriptor.name}' violates ${UNIT_NAME_RE}`))
    for (const table of descriptor.tables) {
      if (!UNIT_NAME_RE.test(table)) return Promise.reject(new Error(`kv table name '${table}' in unit '${descriptor.name}' violates ${UNIT_NAME_RE}`))
    }
    if (this.units.has(descriptor.name)) return Promise.reject(new Error(`kv unit '${descriptor.name}' is already open (double-open is a caller bug)`))
    const pending = this.materializeUnit(descriptor)
    this.units.set(descriptor.name, pending)
    pending.catch(() => this.units.delete(descriptor.name))
    return pending
  }

  private async materializeUnit(descriptor: KvUnitDescriptor): Promise<PostgresKvUnit> {
    await this.ready
    const result = await this.pool.query<{ version: number }>(
      `insert into ${this.schema}.units (name, version) values ($1, $2)
       on conflict (name) do update set name = excluded.name returning version`,
      [descriptor.name, descriptor.version],
    )
    if (result.rows[0]?.version !== descriptor.version) {
      throw new StorageError('version-mismatch', `kv unit '${descriptor.name}' has an incompatible PostgreSQL version stamp`)
    }
    return new PostgresKvUnit(this.pool, this.schema, descriptor, () => { this.units.delete(descriptor.name) })
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
