#!/usr/bin/env node
import { resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { Pool } from 'pg'
import { PostgresStorageBackend } from '@deepseek-ai/dsh-storage-postgres'

const args = process.argv.slice(2)
const value = (name) => {
  const index = args.indexOf(name)
  if (index === -1 || args[index + 1] === undefined) throw new Error(`missing ${name}`)
  return args[index + 1]
}
if (!args.includes('--confirm-empty-target')) {
  throw new Error('refusing migration without --confirm-empty-target')
}
const sourcePath = resolve(value('--sqlite'))
const schema = args.includes('--schema') ? value('--schema') : 'registry'
if (!/^[a-z][a-z0-9_]*$/u.test(schema)) throw new Error('invalid PostgreSQL schema')
const connectionString = process.env.DSH_REGISTRY_POSTGRES_URL
if (!connectionString) throw new Error('DSH_REGISTRY_POSTGRES_URL is required')
const globalTenantId = ''

const sqlite = new DatabaseSync(sourcePath, { readOnly: true })
const pool = new Pool({ connectionString, max: 1, statement_timeout: 30_000,
  idle_in_transaction_session_timeout: 30_000, application_name: 'dsh-registry-migration-check' })
let backend
try {
  const integrity = sqlite.prepare('pragma quick_check').get()
  if (integrity?.quick_check !== 'ok') throw new Error('source SQLite quick_check failed')
  const targetClient = await pool.connect()
  try {
    await targetClient.query('begin isolation level repeatable read read only')
    await targetClient.query(`select set_config('app.tenant_id', $1, true)`, [globalTenantId])
    const target = await targetClient.query(`select to_regclass($1) as relation`, [`${schema}.units`])
    if (target.rows[0]?.relation === null) {
      throw new Error('target PostgreSQL storage is not initialized; run the offline schema migration before copying SQLite data')
    }
    const count = await targetClient.query(
      `select count(*)::integer as count from "${schema}".units where tenant_id = $1`,
      [globalTenantId],
    )
    if (count.rows[0]?.count !== 0) throw new Error('target PostgreSQL global tenant is not empty')
    await targetClient.query('commit')
  } catch (error) {
    try { await targetClient.query('rollback') } catch (rollbackError) {
      throw new AggregateError([error, rollbackError], 'target PostgreSQL preflight rollback failed')
    }
    throw error
  } finally {
    targetClient.release()
  }
  await pool.end()

  const units = sqlite.prepare('select name, version from units order by name').all()
  const physicalTables = sqlite.prepare("select name from sqlite_master where type = 'table' and name like 'u\\_%' escape '\\' order by name").all()
  const globals = new Map(sqlite.prepare('select unit, value from unit_globals').all().map(row => [row.unit, JSON.parse(row.value)]))
  const tableNames = new Map(units.map(unit => [unit.name, []]))
  for (const row of physicalTables) {
    const owner = units.map(unit => unit.name)
      .filter(name => row.name.startsWith(`u_${name}_`))
      .sort((left, right) => right.length - left.length)[0]
    if (owner === undefined) throw new Error('source SQLite contains an unowned unit table')
    tableNames.get(owner).push(row.name.slice(`u_${owner}_`.length))
  }
  const descriptors = units.map(unit => ({ tenantId: globalTenantId, name: unit.name, version: unit.version,
    tables: tableNames.get(unit.name), hasGlobal: globals.has(unit.name) }))
  backend = new PostgresStorageBackend({ connectionString, schema, maxConnections: 2,
    idleTimeoutMs: 30_000, statementTimeoutMs: 30_000, schemaMode: 'validate' })
  let records = 0
  for (const descriptor of descriptors) {
    const unit = await backend.kv.open(descriptor)
    const batch = []
    for (const table of descriptor.tables) {
      const physical = `u_${descriptor.name}_${table}`
      for (const row of sqlite.prepare(`select key, value from "${physical}" order by key`).all()) {
        batch.push({ table, key: row.key, value: JSON.parse(row.value) })
      }
    }
    if (batch.length > 0) await unit.putRecords(batch)
    if (descriptor.hasGlobal) await unit.setGlobal(globals.get(descriptor.name))
    records += batch.length
    await unit.close()
  }
  process.stdout.write(`${JSON.stringify({ migratedUnits: descriptors.length, migratedRecords: records })}\n`)
} finally {
  sqlite.close()
  await backend?.close().catch(() => undefined)
  await pool.end().catch(() => undefined)
}
