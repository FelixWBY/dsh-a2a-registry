#!/usr/bin/env node
import { migratePostgresStorageSchema } from '@deepseek-ai/dsh-storage-postgres'
import { PostgresRegistryTenancy } from '@deepseek-ai/dsh-registry-app'
import { Pool } from 'pg'

const SCHEMA_NAME = /^[a-z][a-z0-9_]*$/u
const REGISTRY_APPLICATIONS = ['dsh-a2a-registry', 'dsh-a2a-registry-tenancy']

const HELP = `
使用独立迁移账号初始化或升级 Registry PostgreSQL schema。

连接串只从 DSH_REGISTRY_POSTGRES_MIGRATOR_URL 读取。这个命令不接受在线应用连接串，
也不负责迁移已有数据的 storage v1；填充过的 v1 必须先使用受保护的 v1→v2 工具。

用法：
  node --import tsx/esm deploy/registry/migrate-postgres-schemas.mjs \\
    --schema <schema> --execute --confirm-runtime-stopped
`.trim()

function fail(message) {
  throw new Error(message)
}

function parseArguments(argv) {
  if (argv.includes('--help') || argv.includes('-h')) return { help: true }
  let schema
  let execute = false
  let stopped = false
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--schema') {
      if (schema !== undefined) fail('duplicate --schema')
      schema = argv[index + 1]
      if (schema === undefined || schema.startsWith('--')) fail('missing --schema')
      index += 1
    } else if (argument === '--execute') {
      if (execute) fail('duplicate --execute')
      execute = true
    } else if (argument === '--confirm-runtime-stopped') {
      if (stopped) fail('duplicate --confirm-runtime-stopped')
      stopped = true
    } else {
      fail('unknown or positional argument')
    }
  }
  if (schema === undefined || !SCHEMA_NAME.test(schema)) fail('a valid --schema is required')
  if (!execute || !stopped) fail('--execute and --confirm-runtime-stopped are required')
  return { help: false, schema }
}

function migrationUrl() {
  const value = process.env.DSH_REGISTRY_POSTGRES_MIGRATOR_URL?.trim() ?? ''
  if (value.length === 0) fail('DSH_REGISTRY_POSTGRES_MIGRATOR_URL is required')
  let parsed
  try { parsed = new URL(value) } catch { fail('migrator URL is invalid') }
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol) || parsed.hostname.length === 0
    || parsed.username.toLowerCase() !== 'registry_migrator' || parsed.password.length === 0
    || parsed.pathname.length <= 1 || parsed.search.length > 0 || parsed.hash.length > 0) {
    fail('migrator URL must be an absolute PostgreSQL URL for registry_migrator')
  }
  return value
}

function safeMessage(error) {
  const message = error instanceof Error ? error.message : 'unknown schema migration failure'
  return message.replace(/(postgres(?:ql)?:\/\/)[^@\s]+@/giu, '$1<redacted>@')
}

async function requireRuntimeStopped(connectionString) {
  const pool = new Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 10_000,
    idleTimeoutMillis: 10_000,
    statement_timeout: 15_000,
    application_name: 'dsh-registry-schema-stop-guard',
  })
  try {
    const visibility = await pool.query(
      `select pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER') as complete`)
    if (visibility.rows.length !== 1 || visibility.rows[0]?.complete !== true) {
      fail('registry_migrator must be a member of pg_read_all_stats to prove the runtime is stopped')
    }
    const result = await pool.query(
      `select count(*)::integer as count
       from pg_stat_activity
       where datname = current_database() and pid <> pg_backend_pid()
         and backend_type = 'client backend'
         and (usename = 'registry_app' or application_name = any($1::text[]))`,
      [REGISTRY_APPLICATIONS],
    )
    if (result.rows.length !== 1 || result.rows[0]?.count !== 0) {
      fail('Registry runtime database connections are still active')
    }
  } finally {
    await pool.end()
  }
}

async function main() {
  const input = parseArguments(process.argv.slice(2))
  if (input.help) {
    process.stdout.write(`${HELP}\n`)
    return
  }
  const connectionString = migrationUrl()
  const common = {
    connectionString,
    schema: input.schema,
    maxConnections: 1,
    idleTimeoutMs: 10_000,
    statementTimeoutMs: 60_000,
  }
  await requireRuntimeStopped(connectionString)
  await migratePostgresStorageSchema(common)
  await requireRuntimeStopped(connectionString)
  await PostgresRegistryTenancy.migrateSchema({ ...common, maxOrganizationsPerAccount: 5 })
  await requireRuntimeStopped(connectionString)
  process.stdout.write(`${JSON.stringify({
    schema: input.schema,
    storageSchemaVersion: 2,
    tenancySchemaVersion: 2,
    migrated: true,
  })}\n`)
}

await main().catch((error) => {
  process.stderr.write(`registry-postgres-schema-migration: ${safeMessage(error)}\n`)
  process.exitCode = 1
})
