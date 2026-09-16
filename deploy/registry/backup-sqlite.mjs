#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto'
import { createReadStream, existsSync, mkdirSync, renameSync, rmSync, statSync, chmodSync } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'
import { backup, DatabaseSync } from 'node:sqlite'

function fail(message) {
  throw new Error(`registry-backup: ${message}`)
}

function databaseFacts(database) {
  const check = database.prepare('PRAGMA quick_check').all()
  if (check.length !== 1 || check[0]?.quick_check !== 'ok') fail('SQLite quick_check failed')
  const version = database.prepare('PRAGMA user_version').get()?.user_version
  const pages = database.prepare('PRAGMA page_count').get()?.page_count
  if (!Number.isSafeInteger(version) || !Number.isSafeInteger(pages)) fail('SQLite metadata is invalid')
  return { userVersion: version, pages }
}

function removeTransientSidecars(path) {
  const wal = `${path}-wal`
  if (existsSync(wal) && (!statSync(wal).isFile() || statSync(wal).size !== 0)) {
    fail('backup produced a non-empty WAL sidecar')
  }
  rmSync(wal, { force: true })
  rmSync(`${path}-shm`, { force: true })
}

async function digest(path) {
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(path)) hash.update(chunk)
  return hash.digest('hex')
}

const [sourceInput, destinationInput, ...rest] = process.argv.slice(2)
if (sourceInput === undefined || destinationInput === undefined || rest.length !== 0) {
  fail('usage: node backup-sqlite.mjs <absolute-source.db> <absolute-destination.db>')
}
if (!isAbsolute(sourceInput) || !isAbsolute(destinationInput)) fail('both paths must be absolute')
const source = resolve(sourceInput)
const destination = resolve(destinationInput)
if (source === destination) fail('source and destination must differ')
if (!existsSync(source) || !statSync(source).isFile()) fail('source database is not a file')
if (existsSync(destination)) fail('destination already exists')

mkdirSync(dirname(destination), { recursive: true, mode: 0o700 })
const partial = `${destination}.partial-${randomUUID()}`
let sourceDatabase
let backupDatabase
try {
  sourceDatabase = new DatabaseSync(source, { readOnly: true })
  const sourceFacts = databaseFacts(sourceDatabase)
  const copiedPages = await backup(sourceDatabase, partial, { rate: 256 })
  backupDatabase = new DatabaseSync(partial, { readOnly: true })
  const backupFacts = databaseFacts(backupDatabase)
  if (sourceFacts.userVersion !== backupFacts.userVersion) fail('backup user_version differs from source')
  backupDatabase.close()
  backupDatabase = undefined
  removeTransientSidecars(partial)
  chmodSync(partial, 0o600)
  renameSync(partial, destination)
  process.stdout.write(`${JSON.stringify({ destination, sha256: await digest(destination), copiedPages,
    userVersion: backupFacts.userVersion, pages: backupFacts.pages })}\n`)
} catch (error) {
  try { backupDatabase?.close() } catch { /* Preserve the backup failure. */ }
  backupDatabase = undefined
  try { sourceDatabase?.close() } catch { /* Preserve the backup failure. */ }
  sourceDatabase = undefined
  rmSync(partial, { force: true })
  rmSync(`${partial}-wal`, { force: true })
  rmSync(`${partial}-shm`, { force: true })
  throw error
} finally {
  backupDatabase?.close()
  sourceDatabase?.close()
}
