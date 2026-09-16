#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, copyFileSync, createReadStream, existsSync, mkdirSync, readFileSync, renameSync, rmSync,
  statSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { backup, DatabaseSync } from 'node:sqlite'

const FORMAT = 'dsh-registry-sqlite-backup-set'
const VERSION = 1
const MANIFEST = 'manifest.json'
const MAX_MANIFEST_BYTES = 64 * 1024
const DATABASES = Object.freeze([
  { role: 'registry', environment: 'DSH_REGISTRY_SQLITE_PATH', file: 'registry.sqlite' },
  { role: 'admission', environment: 'DSH_REGISTRY_ADMISSION_SQLITE_PATH', file: 'admission.sqlite' },
  { role: 'alertOutbox', environment: 'DSH_REGISTRY_ALERT_OUTBOX_SQLITE_PATH', file: 'alert-outbox.sqlite' },
])

function fail(message) {
  throw new Error(`registry-backup-set: ${message}`)
}

function absolutePath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`)
  }
  return value
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

function fileObservation(path) {
  if (!existsSync(path)) return null
  const value = statSync(path)
  if (!value.isFile()) fail('database or SQLite sidecar is not a file')
  return { size: value.size, modifiedAt: value.mtimeMs }
}

function sourceObservation(path) {
  const wal = fileObservation(`${path}-wal`)
  // A read-only connection updates or creates SQLite's regenerable SHM file
  // and may create an empty WAL file. Neither is durable application state.
  // Every committed change still changes the main database or a non-empty WAL.
  fileObservation(`${path}-shm`)
  return Object.freeze({ database: fileObservation(path), wal: wal?.size === 0 ? null : wal })
}

function sameObservation(left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function removeTransientSidecars(path) {
  const wal = fileObservation(`${path}-wal`)
  if (wal !== null && wal.size !== 0) fail('backup produced a non-empty WAL sidecar')
  rmSync(`${path}-wal`, { force: true })
  rmSync(`${path}-shm`, { force: true })
}

async function backupDatabase(source, destination) {
  let sourceDatabase
  let backupDatabase
  try {
    sourceDatabase = new DatabaseSync(source, { readOnly: true })
    const sourceFacts = databaseFacts(sourceDatabase)
    const copiedPages = await backup(sourceDatabase, destination, { rate: 256 })
    backupDatabase = new DatabaseSync(destination, { readOnly: true })
    const restoredFacts = databaseFacts(backupDatabase)
    if (sourceFacts.userVersion !== restoredFacts.userVersion || sourceFacts.pages !== restoredFacts.pages) {
      fail('backup metadata differs from source')
    }
    backupDatabase.close()
    backupDatabase = undefined
    removeTransientSidecars(destination)
    chmodSync(destination, 0o600)
    const info = statSync(destination)
    return Object.freeze({ file: destination.split(/[\\/]/u).at(-1), sha256: await digest(destination),
      copiedPages, userVersion: restoredFacts.userVersion, pages: restoredFacts.pages, sizeBytes: info.size })
  } finally {
    backupDatabase?.close()
    sourceDatabase?.close()
  }
}

function sourcesFromEnvironment() {
  const sources = DATABASES.map(database => {
    const selected = process.env[database.environment]
    if (selected === undefined || selected.length === 0) fail(`${database.environment} is required`)
    const path = absolutePath(selected, database.environment)
    if (!existsSync(path) || !statSync(path).isFile()) fail(`${database.environment} is not a database file`)
    return Object.freeze({ ...database, path })
  })
  if (new Set(sources.map(source => source.path.toLowerCase())).size !== sources.length) {
    fail('database source paths must be distinct')
  }
  return sources
}

function inside(root, path) {
  const selected = relative(root, path)
  return selected === '' || (!selected.startsWith('..') && !isAbsolute(selected))
}

async function createSet(destinationInput) {
  const destination = absolutePath(destinationInput, 'destination directory')
  if (existsSync(destination)) fail('destination directory already exists')
  const sources = sourcesFromEnvironment()
  if (sources.some(source => inside(destination, source.path))) fail('destination cannot contain a source database')
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 })
  const partial = `${destination}.partial-${randomUUID()}`
  mkdirSync(partial, { mode: 0o700 })
  try {
    const before = new Map(sources.map(source => [source.role, sourceObservation(source.path)]))
    const records = {}
    for (const source of sources) {
      records[source.role] = await backupDatabase(source.path, join(partial, source.file))
    }
    for (const source of sources) {
      if (!sameObservation(before.get(source.role), sourceObservation(source.path))) {
        fail(`${source.role} changed during the asserted quiescent backup`)
      }
    }
    const manifest = Object.freeze({ format: FORMAT, version: VERSION, createdAt: new Date().toISOString(),
      quiescence: 'operator-asserted-and-files-stable', databases: records })
    const manifestPath = join(partial, MANIFEST)
    writeFileSync(manifestPath, `${JSON.stringify(manifest, undefined, 2)}\n`, { flag: 'wx', mode: 0o600 })
    renameSync(partial, destination)
    process.stdout.write(`${JSON.stringify({ created: true, destination,
      manifest: join(destination, MANIFEST), databases: Object.keys(records) })}\n`)
  } catch (error) {
    rmSync(partial, { recursive: true, force: true })
    throw error
  }
}

function exactObject(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) fail(`${label} is invalid`)
  return value
}

async function readVerifiedSet(directoryInput) {
  const directory = absolutePath(directoryInput, 'backup directory')
  const manifestPath = join(directory, MANIFEST)
  if (!existsSync(manifestPath)) fail('manifest is missing')
  const info = statSync(manifestPath)
  if (!info.isFile() || info.size > MAX_MANIFEST_BYTES) fail('manifest is invalid')
  let manifest
  try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) } catch { fail('manifest is invalid') }
  exactObject(manifest, ['format', 'version', 'createdAt', 'quiescence', 'databases'], 'manifest')
  if (manifest.format !== FORMAT || manifest.version !== VERSION
    || manifest.quiescence !== 'operator-asserted-and-files-stable'
    || Number.isNaN(Date.parse(manifest.createdAt))) fail('manifest header is invalid')
  exactObject(manifest.databases, DATABASES.map(database => database.role), 'database map')
  const verified = {}
  for (const database of DATABASES) {
    const expected = exactObject(manifest.databases[database.role],
      ['file', 'sha256', 'copiedPages', 'userVersion', 'pages', 'sizeBytes'], `${database.role} record`)
    if (expected.file !== database.file || !/^[0-9a-f]{64}$/u.test(expected.sha256)
      || !Number.isSafeInteger(expected.copiedPages) || expected.copiedPages < 0
      || !Number.isSafeInteger(expected.userVersion) || expected.userVersion < 0
      || !Number.isSafeInteger(expected.pages) || expected.pages < 0
      || !Number.isSafeInteger(expected.sizeBytes) || expected.sizeBytes < 0) fail(`${database.role} record is invalid`)
    const path = resolve(directory, expected.file)
    if (!inside(directory, path) || !existsSync(path) || !statSync(path).isFile()) {
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
    const storedInfo = statSync(path)
    if (facts.userVersion !== expected.userVersion || facts.pages !== expected.pages
      || storedInfo.size !== expected.sizeBytes || await digest(path) !== expected.sha256) {
      fail(`${database.role} backup verification failed`)
    }
    verified[database.role] = Object.freeze({ userVersion: facts.userVersion, pages: facts.pages,
      sizeBytes: storedInfo.size })
  }
  return Object.freeze({ directory, createdAt: manifest.createdAt, databases: verified })
}

async function verifySet(directoryInput) {
  const result = await readVerifiedSet(directoryInput)
  process.stdout.write(`${JSON.stringify({ verified: true, ...result })}\n`)
}

async function restoreSet(backupInput, destinationInput) {
  const source = absolutePath(backupInput, 'backup directory')
  const destination = absolutePath(destinationInput, 'restore directory')
  if (existsSync(destination)) fail('restore directory already exists')
  if (inside(source, destination) || inside(destination, source)) {
    fail('backup and restore directories cannot contain one another')
  }
  await readVerifiedSet(source)
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 })
  const partial = `${destination}.partial-${randomUUID()}`
  mkdirSync(partial, { mode: 0o700 })
  try {
    for (const database of DATABASES) {
      const restored = join(partial, database.file)
      copyFileSync(join(source, database.file), restored)
      chmodSync(restored, 0o600)
    }
    const restoredManifest = join(partial, MANIFEST)
    copyFileSync(join(source, MANIFEST), restoredManifest)
    chmodSync(restoredManifest, 0o600)
    await readVerifiedSet(partial)
    renameSync(partial, destination)
    process.stdout.write(`${JSON.stringify({ restored: true, destination,
      environment: Object.fromEntries(DATABASES.map(database => [database.environment,
        join(destination, database.file)])) })}\n`)
  } catch (error) {
    rmSync(partial, { recursive: true, force: true })
    throw error
  }
}

const [command, ...arguments_] = process.argv.slice(2)
if (command === 'create') {
  const [acknowledgement, directory, ...rest] = arguments_
  if (acknowledgement !== '--quiesced' || directory === undefined || rest.length !== 0) {
    fail('usage: node backup-registry-state.mjs create --quiesced <absolute-new-directory>')
  }
  await createSet(directory)
} else if (command === 'verify') {
  const [directory, ...rest] = arguments_
  if (directory === undefined || rest.length !== 0) {
    fail('usage: node backup-registry-state.mjs verify <absolute-backup-directory>')
  }
  await verifySet(directory)
} else if (command === 'restore') {
  const [backup, destination, ...rest] = arguments_
  if (backup === undefined || destination === undefined || rest.length !== 0) {
    fail('usage: node backup-registry-state.mjs restore <absolute-backup-directory> <absolute-new-directory>')
  }
  await restoreSet(backup, destination)
} else {
  fail('usage: create --quiesced <absolute-new-directory> | verify <absolute-backup-directory> | restore <absolute-backup-directory> <absolute-new-directory>')
}
