#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync,
  readdirSync, renameSync, rmSync, statSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

const STORAGE_SCHEMA_VERSION = 1
const MAX_UNIT_BYTES = 256 * 1024 * 1024
const UNIT_NAME = /^[a-z][a-z0-9_]*$/u

function fail(message) {
  throw new Error(`registry-json-migration: ${message}`)
}

function absolutePath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`)
  }
  return value
}

function inside(root, path) {
  const selected = relative(root, path)
  return selected === '' || (!selected.startsWith('..') && !isAbsolute(selected))
}

function object(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`)
  return value
}

function sourceFiles(root) {
  const directory = lstatSync(root)
  if (!directory.isDirectory() || directory.isSymbolicLink()) fail('source directory is not a real directory')
  const files = readdirSync(root, { withFileTypes: true })
    .filter(entry => entry.name.endsWith('.json'))
    .sort((left, right) => left.name.localeCompare(right.name, 'en'))
  if (files.length === 0) fail('source directory contains no whole-unit JSON files')
  if (files.some(entry => !entry.isFile() || entry.isSymbolicLink())) fail('a JSON source is not a regular file')
  return files.map(entry => {
    const path = join(root, entry.name)
    const info = statSync(path)
    if (info.size > MAX_UNIT_BYTES) fail(`JSON unit '${entry.name}' exceeds the size limit`)
    const sha256 = createHash('sha256').update(readFileSync(path)).digest('hex')
    return Object.freeze({ name: entry.name, path, size: info.size, modifiedAt: info.mtimeMs, sha256 })
  })
}

function sameSources(left, right) {
  return JSON.stringify(left.map(({ name, size, modifiedAt, sha256 }) => ({ name, size, modifiedAt, sha256 })))
    === JSON.stringify(right.map(({ name, size, modifiedAt, sha256 }) => ({ name, size, modifiedAt, sha256 })))
}

function parseUnit(file) {
  let input
  try { input = JSON.parse(readFileSync(file.path, 'utf8')) } catch { fail(`JSON unit '${file.name}' is invalid`) }
  const document = object(input, `JSON unit '${file.name}'`)
  const header = object(document.unit, `JSON unit '${file.name}' header`)
  const tables = object(document.tables, `JSON unit '${file.name}' tables`)
  const expectedName = basename(file.name, '.json')
  if (header.name !== expectedName || !UNIT_NAME.test(expectedName)) fail(`JSON unit '${file.name}' has a foreign name`)
  if (!Number.isSafeInteger(header.version) || header.version < 0) fail(`JSON unit '${file.name}' has an invalid version`)
  const records = []
  for (const [table, raw] of Object.entries(tables)) {
    if (!UNIT_NAME.test(table)) fail(`JSON unit '${file.name}' has an invalid table name`)
    const rows = object(raw, `JSON unit '${file.name}' table '${table}'`)
    for (const [key, value] of Object.entries(rows)) records.push(Object.freeze({ table, key, value }))
  }
  return Object.freeze({ name: expectedName, version: header.version, global: document.global ?? null,
    tables: Object.keys(tables), records })
}

function createDatabase(path, units) {
  closeSync(openSync(path, 'wx', 0o600))
  const database = new DatabaseSync(path)
  try {
    database.exec('PRAGMA foreign_keys = ON')
    database.exec('PRAGMA journal_mode = DELETE')
    database.exec('PRAGMA synchronous = FULL')
    database.exec(`
      CREATE TABLE units (
        name    TEXT PRIMARY KEY,
        version INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE unit_globals (
        unit  TEXT PRIMARY KEY REFERENCES units(name),
        value TEXT NOT NULL
      ) STRICT;
    `)
    const insertUnit = database.prepare('INSERT INTO units (name, version) VALUES (?, ?)')
    const insertGlobal = database.prepare('INSERT INTO unit_globals (unit, value) VALUES (?, ?)')
    database.exec('BEGIN IMMEDIATE')
    try {
      for (const unit of units) {
        insertUnit.run(unit.name, unit.version)
        if (unit.global !== null) insertGlobal.run(unit.name, JSON.stringify(unit.global))
        const statements = new Map()
        for (const table of unit.tables) {
          const physical = `u_${unit.name}_${table}`
          database.exec(`CREATE TABLE "${physical}" (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT`)
          statements.set(table, database.prepare(`INSERT INTO "${physical}" (key, value) VALUES (?, ?)`))
        }
        for (const record of unit.records) statements.get(record.table).run(record.key, JSON.stringify(record.value))
      }
      database.exec(`PRAGMA user_version = ${String(STORAGE_SCHEMA_VERSION)}`)
      database.exec('COMMIT')
    } catch (error) {
      if (database.isTransaction) database.exec('ROLLBACK')
      throw error
    }
    const check = database.prepare('PRAGMA quick_check').all()
    if (check.length !== 1 || check[0]?.quick_check !== 'ok') fail('created SQLite database failed quick_check')
    const version = database.prepare('PRAGMA user_version').get()?.user_version
    if (version !== STORAGE_SCHEMA_VERSION) fail('created SQLite database has an unexpected schema version')
  } finally {
    database.close()
  }
}

const [acknowledgement, sourceInput, destinationInput, ...rest] = process.argv.slice(2)
if (acknowledgement !== '--quiesced' || sourceInput === undefined || destinationInput === undefined || rest.length !== 0) {
  fail('usage: node migrate-json-storage-to-sqlite.mjs --quiesced <absolute-json-directory> <absolute-new-sqlite-path>')
}
const source = absolutePath(sourceInput, 'source directory')
const destination = absolutePath(destinationInput, 'destination database')
if (!existsSync(source)) fail('source directory does not exist')
if (existsSync(destination)) fail('destination database already exists')
if (inside(source, destination)) fail('destination database cannot be inside the source directory')
mkdirSync(dirname(destination), { recursive: true, mode: 0o700 })
const before = sourceFiles(source)
const units = before.map(parseUnit)
if (new Set(units.map(unit => unit.name)).size !== units.length) fail('source contains duplicate unit names')
const partial = `${destination}.partial-${randomUUID()}`
try {
  createDatabase(partial, units)
  if (!sameSources(before, sourceFiles(source))) fail('JSON source changed during the asserted quiescent migration')
  chmodSync(partial, 0o600)
  renameSync(partial, destination)
  process.stdout.write(`${JSON.stringify({ migrated: true, destination, units: units.length,
    tables: units.reduce((count, unit) => count + unit.tables.length, 0),
    records: units.reduce((count, unit) => count + unit.records.length, 0),
    storageSchemaVersion: STORAGE_SCHEMA_VERSION })}\n`)
} catch (error) {
  rmSync(partial, { force: true })
  rmSync(`${partial}-wal`, { force: true })
  rmSync(`${partial}-shm`, { force: true })
  throw error
}
