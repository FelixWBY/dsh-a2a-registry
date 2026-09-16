/**
 * One opened SQLite KV unit: prepared per-table statements over the
 * `u_<unit>_<table>` record tables plus this unit's row in the shared
 * `unit_globals` table. Single writes use statement atomicity; record batches
 * use one synchronous transaction. Write ordering stays the caller's
 * responsibility; no transaction or write queue is exposed.
 * @module @deepseek-ai/dsh-storage-sqlite/unit
 */

import type { DatabaseSync, StatementSync } from 'node:sqlite'
import { StorageError } from '@deepseek-ai/dsh-storage'
import type { KvRecordWrite, KvUnit, KvUnitDescriptor } from '@deepseek-ai/dsh-storage'
import { recordTableName } from './schema.ts'

/** Prepared statements for one declared table. */
interface TableStatements {
  upsert: StatementSync
  remove: StatementSync
  selectAll: StatementSync
}

/** A failed rollback makes every unit sharing this connection unavailable until backend close/reopen. */
const isolatedDatabases = new WeakMap<DatabaseSync, AggregateError>()

/** Reject an isolated connection before unit operations or materialization touch SQLite.
 * @param db - Backend-owned connection shared by all its units. */
export function assertSqliteDatabaseAvailable(db: DatabaseSync): void {
  const failure = isolatedDatabases.get(db)
  if (failure !== undefined) throw failure
}

/**
 * The SQLite {@link KvUnit}. Constructed by the backend AFTER the unit's
 * record tables exist; statements are prepared once here and reused for every
 * primitive. Values are stored as JSON text in the `value` column.
 */
export class SqliteKvUnit implements KvUnit {
  private readonly tables = new Map<string, TableStatements>()
  private readonly globalUpsert: StatementSync | undefined
  private readonly globalSelect: StatementSync | undefined
  private closed = false

  /**
   * @param db - Open database handle owned by the backend (never closed here).
   * @param descriptor - Validated descriptor whose record tables already exist.
   * @param onClose - Backend callback releasing this unit's open-name slot.
   */
  constructor(
    private readonly db: DatabaseSync,
    private readonly descriptor: KvUnitDescriptor,
    private readonly onClose: () => void,
  ) {
    for (const table of descriptor.tables) {
      // Both name segments are validated against UNIT_NAME_RE by the backend,
      // so the physical identifier is safe to interpolate into statement text.
      const physical = recordTableName(descriptor.name, table)
      this.tables.set(table, {
        upsert: db.prepare(
          `INSERT INTO "${physical}" (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        ),
        remove: db.prepare(`DELETE FROM "${physical}" WHERE key = ?`),
        selectAll: db.prepare(`SELECT key, value FROM "${physical}"`),
      })
    }
    this.globalUpsert = descriptor.hasGlobal
      ? db.prepare(
        'INSERT INTO unit_globals (unit, value) VALUES (?, ?) ON CONFLICT(unit) DO UPDATE SET value = excluded.value',
      )
      : undefined
    this.globalSelect = descriptor.hasGlobal
      ? db.prepare('SELECT value FROM unit_globals WHERE unit = ?')
      : undefined
  }

  loadAll(): Promise<{ tables: Record<string, Record<string, unknown>>; global: unknown }> {
    return this.settle(() => {
      const tables: Record<string, Record<string, unknown>> = {}
      for (const [name, statements] of this.tables) {
        // Null prototype: record keys are arbitrary strings, so '__proto__'
        // must land as an own property instead of mutating the prototype.
        const records: Record<string, unknown> = Object.create(null) as Record<string, unknown>
        for (const row of statements.selectAll.all() as unknown as Array<{ key: string; value: string }>) {
          records[row.key] = this.parseValue(row.value, `table '${name}' key '${row.key}'`)
        }
        tables[name] = records
      }
      let global: unknown = null
      if (this.globalSelect !== undefined) {
        const row = this.globalSelect.get(this.descriptor.name) as { value: string } | undefined
        if (row !== undefined) global = this.parseValue(row.value, 'global slot')
      }
      return { tables, global }
    })
  }

  /** Parse one stored value column, mapping bad JSON to `malformed-medium`. */
  private parseValue(text: string, slot: string): unknown {
    try {
      return JSON.parse(text)
    } catch (error) {
      throw new StorageError(
        'malformed-medium',
        `kv unit '${this.descriptor.name}' holds unparsable JSON at ${slot}`,
        { cause: error },
      )
    }
  }

  putRecord(table: string, key: string, value: unknown): Promise<void> {
    return this.settle(() => {
      this.statementsFor(table).upsert.run(key, JSON.stringify(value))
    })
  }

  putRecords(records: readonly KvRecordWrite[]): Promise<void> {
    return this.settle(() => {
      const captured = records.map(({ table, key, value }) => ({ table, key, value }))
      const seen = new Set<string>()
      const prepared = captured.map(({ table, key, value }) => {
        const identity = JSON.stringify([table, key])
        if (seen.has(identity)) throw new Error('atomic record batch contains a duplicate table/key pair')
        seen.add(identity)
        return { statement: this.statementsFor(table).upsert, key, value }
      }).map(({ statement, key, value }) => ({ statement, key, json: JSON.stringify(value) }))
      if (prepared.length === 0) return
      this.db.exec('BEGIN IMMEDIATE')
      try {
        for (const { statement, key, json } of prepared) statement.run(key, json)
        this.db.exec('COMMIT')
      } catch (error) {
        // SQLite may already have rolled back the transaction, for example on RAISE(ROLLBACK).
        if (this.db.isTransaction) {
          try { this.db.exec('ROLLBACK') } catch (rollbackError) {
            const failure = new AggregateError([error, rollbackError], 'SQLite record batch rollback failed')
            isolatedDatabases.set(this.db, failure)
            throw failure
          }
        }
        throw error
      }
    })
  }

  deleteRecord(table: string, key: string): Promise<void> {
    return this.settle(() => {
      this.statementsFor(table).remove.run(key)
    })
  }

  setGlobal(value: unknown): Promise<void> {
    return this.settle(() => {
      if (this.globalUpsert === undefined) {
        throw new Error(`kv unit '${this.descriptor.name}' declared no global slot`)
      }
      this.globalUpsert.run(this.descriptor.name, JSON.stringify(value))
    })
  }

  close(): Promise<void> {
    if (!this.closed) {
      this.closed = true
      this.onClose()
    }
    return Promise.resolve()
  }

  /**
   * Run one synchronous primitive behind the closed guard, mapping a throw to
   * a rejection so the Promise-returning contract never throws synchronously.
   */
  private settle<T>(operation: () => T): Promise<T> {
    try {
      this.ensureOpen()
      return Promise.resolve(operation())
    } catch (error) {
      // Non-Error throws can only enter through JSON.stringify propagating a
      // value's own toJSON throw; wrap those, preserve every real Error.
      return Promise.reject(error instanceof Error ? error : new Error(String(error)))
    }
  }

  private ensureOpen(): void {
    if (this.closed) {
      throw new StorageError('closed', `kv unit '${this.descriptor.name}' is closed`)
    }
    assertSqliteDatabaseAvailable(this.db)
  }

  private statementsFor(table: string): TableStatements {
    const statements = this.tables.get(table)
    if (statements === undefined) {
      throw new Error(`kv unit '${this.descriptor.name}' declared no table '${table}'`)
    }
    return statements
  }
}
