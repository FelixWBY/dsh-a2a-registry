/** Optional same-host multi-process Registry admission owner backed by a dedicated SQLite database. */
import { createHmac, timingSafeEqual } from 'node:crypto'
import { open, mkdir } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'
import { DatabaseSync, type StatementSync } from 'node:sqlite'
import type { Context } from '@deepseek-ai/cordis'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import z from '@deepseek-ai/schemastery'

const APPLICATION_ID = 0x44534841
const SCHEMA_VERSION = 2
const PREVIOUS_SCHEMA_VERSION = 1
const SCOPE = /^[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?$/u
const NAMESPACE = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const MAX_KEY_BYTES = 4_096
const RETRY_MAXIMUM = 2 ** 31 - 1

/** Dedicated SQLite medium, privacy key and lock wait selected by the deployment. */
export interface RegistrySharedAdmissionConfig {
  /** Absolute path to a dedicated local SQLite database shared by Registry processes on this host. */
  readonly path: string
  /** Stable deployment namespace; different policies must use different namespaces. */
  readonly namespace: string
  /** Credential reference containing exactly 32 canonical base64url bytes used only to HMAC rate keys. */
  readonly keySecretEnv: string
  /** Maximum synchronous SQLite lock wait for one admission decision. */
  readonly busyTimeoutMs: number
  /** Durable SQLite journal mode; WAL is intended only for a local filesystem. */
  readonly journalMode: 'wal' | 'delete' | 'truncate' | 'persist'
  /** Bounded key-free aggregation retained with the same atomic admission owner. */
  readonly audit: RegistrySharedAdmissionAuditConfig
}

/** Persistent rejection aggregation; selectors and HMAC hashes are deliberately absent. */
export interface RegistrySharedAdmissionAuditConfig {
  /** Maximum aggregate rows retained for this deployment namespace. */
  readonly maxEntries: number
  /** Milliseconds grouped into one scope-and-reason aggregate row. */
  readonly aggregationWindowMs: number
}

const positive = () => z.number().step(1).min(1).max(Number.MAX_SAFE_INTEGER).required()
const rawSchema: z<RegistrySharedAdmissionConfig> = z.object({
  path: z.string().required(), namespace: z.string().pattern(NAMESPACE).required(),
  keySecretEnv: z.string().role('credential-ref').required(),
  busyTimeoutMs: positive().max(2 ** 31 - 1),
  journalMode: z.union(['wal', 'delete', 'truncate', 'persist'] as const).required(),
  audit: z.object({ maxEntries: positive(), aggregationWindowMs: positive() }).required(),
})

/** Validate the explicit shared-admission storage and credential selection. */
export const RegistrySharedAdmissionConfigSchema: z<RegistrySharedAdmissionConfig> = z.transform(rawSchema, (config) => {
  if (!isAbsolute(config.path) || resolve(config.path) !== config.path) {
    throw new z.ValidationError('Registry shared admission requires an absolute normalized database path', {})
  }
  try { credentialRef(config.keySecretEnv) } catch {
    throw new z.ValidationError('Registry shared admission keySecretEnv must be a credential reference', {})
  }
  return config
})

/** One token dimension charged as part of an atomic shared decision. */
export interface RegistrySharedAdmissionDimension {
  readonly capacity: number
  readonly refillPerSecond: number
  readonly cost: number
}

/** One independently bounded key table participating in a possibly multi-scope atomic decision. */
export interface RegistrySharedAdmissionCharge {
  readonly scope: string
  readonly key: string
  readonly maxEntries: number
  readonly requests: RegistrySharedAdmissionDimension
  readonly bytes?: RegistrySharedAdmissionDimension
}

/** Shared admission returns a bounded delay without exposing the selected HMAC key. */
export type RegistrySharedAdmissionDecision = { readonly admitted: true }
  | { readonly admitted: false; readonly retryAfterSeconds: number }

/** Why a shared decision rejected work before any configured bucket was consumed. */
export type RegistrySharedAdmissionAuditReason = 'budget-exhausted' | 'key-capacity-exhausted'

/** Bounded persistent rejection evidence without an IP, account, organization, instance, disclosure or key hash. */
export interface RegistrySharedAdmissionAuditRecord {
  readonly scope: string
  readonly reason: RegistrySharedAdmissionAuditReason
  readonly windowStartedAt: number
  readonly lastOccurredAt: number
  readonly rejectedCount: number
  readonly retryAfterSeconds: number
}

interface PolicyRow {
  request_capacity: number
  request_refill: number
  byte_capacity: number | null
  byte_refill: number | null
  max_entries: number
}

interface BucketRow {
  key_hash: string
  request_tokens: number
  byte_tokens: number | null
  updated_at: number
}

interface PreparedCharge {
  readonly input: RegistrySharedAdmissionCharge
  readonly keyHash: string
  readonly requestTokens: number
  readonly byteTokens: number | null
  readonly updatedAt: number
  readonly replacement: string | undefined
}

interface RejectionAuditRow {
  readonly scope: string
  readonly reason: RegistrySharedAdmissionAuditReason
  readonly window_started_at: number
  readonly last_occurred_at: number
  readonly rejected_count: number
  readonly retry_after_seconds: number
}

/** Content-free failure for unavailable, mismatched or malformed shared admission state. */
export class RegistrySharedAdmissionError extends Error {
  constructor() {
    super('Registry shared admission unavailable')
    this.name = 'RegistrySharedAdmissionError'
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    registrySharedAdmission: RegistrySharedAdmission
  }
}

function fail(): never { throw new RegistrySharedAdmissionError() }

function secret(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) fail()
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.byteLength !== 32 || bytes.toString('base64url') !== value) { bytes.fill(0); fail() }
  return bytes
}

async function ensureFile(path: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  try {
    const handle = await open(path, 'wx', 0o600)
    await handle.close()
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
}

function rollback(db: DatabaseSync): void {
  try { db.exec('ROLLBACK') } catch {
    // Preserve the original content-free shared-store failure.
  }
}

function validDimension(value: RegistrySharedAdmissionDimension): boolean {
  return Number.isSafeInteger(value.capacity) && value.capacity > 0
    && Number.isSafeInteger(value.refillPerSecond) && value.refillPerSecond > 0
    && Number.isSafeInteger(value.cost) && value.cost >= 0
}

function available(tokens: number, capacity: number, refill: number, at: number, now: number): number {
  return Math.min(capacity, tokens + Math.max(0, now - at) / 1_000 * refill)
}

function waitFor(tokens: number, target: number, refill: number, capacity: number): number {
  if (target <= tokens) return 1
  if (target > capacity) return RETRY_MAXIMUM
  return Math.max(1, Math.min(RETRY_MAXIMUM, Math.ceil((target - tokens) / refill)))
}

function shortage(requestTokens: number, byteTokens: number | null,
  input: RegistrySharedAdmissionCharge): number | undefined {
  const requestWait = requestTokens < input.requests.cost
    ? waitFor(requestTokens, input.requests.cost, input.requests.refillPerSecond, input.requests.capacity) : undefined
  const byteWait = input.bytes !== undefined && (byteTokens === null || byteTokens < input.bytes.cost)
    ? waitFor(byteTokens ?? 0, input.bytes.cost, input.bytes.refillPerSecond, input.bytes.capacity) : undefined
  if (requestWait === undefined && byteWait === undefined) return undefined
  return Math.max(requestWait ?? 1, byteWait ?? 1)
}

/** Dedicated SQLite owner. Its synchronous transactions make one decision atomic across Registry processes. */
export class RegistrySharedAdmission {
  private closed = false
  private readonly selectPolicy: StatementSync
  private readonly insertPolicy: StatementSync
  private readonly selectBucket: StatementSync
  private readonly listBuckets: StatementSync
  private readonly deleteBucket: StatementSync
  private readonly upsertBucket: StatementSync
  private readonly upsertRejectionAudit: StatementSync
  private readonly trimRejectionAudit: StatementSync
  private readonly listRejectionAudit: StatementSync

  private constructor(private readonly db: DatabaseSync, private readonly config: RegistrySharedAdmissionConfig,
    private readonly keySecret: Buffer, private readonly clock: () => number) {
    this.selectPolicy = db.prepare(`SELECT request_capacity, request_refill, byte_capacity, byte_refill, max_entries
      FROM admission_policies WHERE namespace = ? AND scope = ?`)
    this.insertPolicy = db.prepare(`INSERT INTO admission_policies
      (namespace, scope, request_capacity, request_refill, byte_capacity, byte_refill, max_entries)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
    this.selectBucket = db.prepare(`SELECT key_hash, request_tokens, byte_tokens, updated_at
      FROM admission_buckets WHERE namespace = ? AND scope = ? AND key_hash = ?`)
    this.listBuckets = db.prepare(`SELECT key_hash, request_tokens, byte_tokens, updated_at
      FROM admission_buckets WHERE namespace = ? AND scope = ?`)
    this.deleteBucket = db.prepare(`DELETE FROM admission_buckets
      WHERE namespace = ? AND scope = ? AND key_hash = ?`)
    this.upsertBucket = db.prepare(`INSERT INTO admission_buckets
      (namespace, scope, key_hash, request_tokens, byte_tokens, updated_at) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(namespace, scope, key_hash) DO UPDATE SET
      request_tokens = excluded.request_tokens, byte_tokens = excluded.byte_tokens, updated_at = excluded.updated_at`)
    this.upsertRejectionAudit = db.prepare(`INSERT INTO admission_rejection_audit
      (namespace, scope, reason, window_started_at, last_occurred_at, rejected_count, retry_after_seconds)
      VALUES (?, ?, ?, ?, ?, 1, ?)
      ON CONFLICT(namespace, scope, reason, window_started_at) DO UPDATE SET
      last_occurred_at = MAX(admission_rejection_audit.last_occurred_at, excluded.last_occurred_at),
      rejected_count = CASE WHEN admission_rejection_audit.rejected_count < 9007199254740991
        THEN admission_rejection_audit.rejected_count + 1 ELSE admission_rejection_audit.rejected_count END,
      retry_after_seconds = MAX(admission_rejection_audit.retry_after_seconds, excluded.retry_after_seconds)`)
    this.trimRejectionAudit = db.prepare(`DELETE FROM admission_rejection_audit WHERE rowid IN (
      SELECT rowid FROM admission_rejection_audit WHERE namespace = ?
      ORDER BY last_occurred_at ASC, window_started_at ASC, scope ASC, reason ASC
      LIMIT (SELECT CASE WHEN COUNT(*) > ? THEN COUNT(*) - ? ELSE 0 END
        FROM admission_rejection_audit WHERE namespace = ?)
    )`)
    this.listRejectionAudit = db.prepare(`SELECT scope, reason, window_started_at, last_occurred_at,
      rejected_count, retry_after_seconds FROM admission_rejection_audit WHERE namespace = ?
      ORDER BY last_occurred_at DESC, window_started_at DESC, scope ASC, reason ASC`)
  }

  /** Open and bind one deployment namespace to its HMAC key.
   * @param ctx - Registry context with the deployment Credentials provider.
   * @param input - Dedicated database, namespace, secret reference and SQLite settings.
   * @param clock - Shared wall-clock milliseconds; production uses Date.now.
   * @returns Ready shared admission owner. */
  static async open(ctx: Context, input: RegistrySharedAdmissionConfig,
    clock: () => number = () => Date.now()): Promise<RegistrySharedAdmission> {
    const config = RegistrySharedAdmissionConfigSchema(input)
    const resolved = await ctx.credentials.resolve(credentialRef(config.keySecretEnv))
    if (resolved === undefined) fail()
    const key = secret(resolved.value)
    let db: DatabaseSync | undefined
    try {
      await ensureFile(config.path)
      db = new DatabaseSync(config.path, { timeout: config.busyTimeoutMs })
      configure(db, config, key)
      return new RegistrySharedAdmission(db, structuredClone(config), key, clock)
    } catch {
      key.fill(0)
      try { db?.close() } catch { /* The open failure remains authoritative. */ }
      return fail()
    }
  }

  /** Atomically charge all supplied scopes or none of them.
   * @param inputs - Complete scope, key, policy and cost set for one request.
   * @returns Shared decision with a bounded retry delay on rejection. */
  charge(inputs: readonly RegistrySharedAdmissionCharge[]): RegistrySharedAdmissionDecision {
    if (this.closed || inputs.length === 0) return fail()
    const now = this.clock()
    if (!Number.isSafeInteger(now) || now < 0) return fail()
    const copied = inputs.map(input => structuredClone(input))
    const unique = new Set<string>()
    for (const input of copied) {
      if (!SCOPE.test(input.scope) || input.key.length === 0 || input.key !== input.key.trim()
        || !input.key.isWellFormed() || Buffer.byteLength(input.key, 'utf8') > MAX_KEY_BYTES
        || !Number.isSafeInteger(input.maxEntries) || input.maxEntries < 1
        || !validDimension(input.requests) || (input.bytes !== undefined && !validDimension(input.bytes))) return fail()
      if (unique.has(input.scope)) return fail()
      unique.add(input.scope)
    }
    try {
      this.db.exec('BEGIN IMMEDIATE')
      const prepared: PreparedCharge[] = []
      for (const input of copied) {
        this.ensurePolicy(input)
        const keyHash = this.hash(input.scope, input.key)
        const row = this.selectBucket.get(this.config.namespace, input.scope, keyHash) as BucketRow | undefined
        const requestTokens = available(row?.request_tokens ?? input.requests.capacity,
          input.requests.capacity, input.requests.refillPerSecond, row?.updated_at ?? now, now)
        const byteTokens = input.bytes === undefined ? null : available(row?.byte_tokens ?? input.bytes.capacity,
          input.bytes.capacity, input.bytes.refillPerSecond, row?.updated_at ?? now, now)
        const delayed = shortage(requestTokens, byteTokens, input)
        if (delayed !== undefined) return this.reject(input.scope, 'budget-exhausted', delayed, now)
        const replacement = row === undefined ? this.replacement(input, now) : undefined
        if (replacement === null) return this.reject(input.scope, 'key-capacity-exhausted',
          this.replacementWait(input, now), now)
        prepared.push({ input, keyHash, requestTokens: requestTokens - input.requests.cost,
          byteTokens: input.bytes === undefined ? null : (byteTokens ?? 0) - input.bytes.cost,
          updatedAt: Math.max(row?.updated_at ?? now, now),
          replacement: replacement ?? undefined })
      }
      for (const value of prepared) {
        if (value.replacement !== undefined) {
          this.deleteBucket.run(this.config.namespace, value.input.scope, value.replacement)
        }
        this.upsertBucket.run(this.config.namespace, value.input.scope, value.keyHash,
          value.requestTokens, value.byteTokens, value.updatedAt)
      }
      this.db.exec('COMMIT')
      return { admitted: true }
    } catch {
      rollback(this.db)
      return fail()
    }
  }

  /** Close the SQLite handle and erase the in-memory HMAC key. */
  close(): void {
    if (this.closed) return
    this.closed = true
    this.keySecret.fill(0)
    try { this.db.close() } catch { return fail() }
  }

  /** Read bounded key-free rejection aggregates for deployment-owned diagnostics.
   * @returns Detached newest-first records for this owner's namespace. */
  inspectRejectionAudit(): readonly RegistrySharedAdmissionAuditRecord[] {
    if (this.closed) return fail()
    try {
      const rows = this.listRejectionAudit.all(this.config.namespace) as unknown as RejectionAuditRow[]
      return rows.map(row => Object.freeze({
        scope: row.scope,
        reason: row.reason,
        windowStartedAt: row.window_started_at,
        lastOccurredAt: row.last_occurred_at,
        rejectedCount: row.rejected_count,
        retryAfterSeconds: row.retry_after_seconds,
      }))
    } catch { return fail() }
  }

  private hash(scope: string, key: string): string {
    return createHmac('sha256', this.keySecret).update('dsh.registry.shared-admission.v1\0')
      .update(this.config.namespace).update('\0').update(scope).update('\0').update(key).digest('hex')
  }

  private reject(scope: string, reason: RegistrySharedAdmissionAuditReason,
    retryAfterSeconds: number, now: number): RegistrySharedAdmissionDecision {
    const { aggregationWindowMs, maxEntries } = this.config.audit
    const windowStartedAt = Math.floor(now / aggregationWindowMs) * aggregationWindowMs
    this.upsertRejectionAudit.run(this.config.namespace, scope, reason, windowStartedAt, now, retryAfterSeconds)
    this.trimRejectionAudit.run(this.config.namespace, maxEntries, maxEntries, this.config.namespace)
    this.db.exec('COMMIT')
    return { admitted: false, retryAfterSeconds }
  }

  private ensurePolicy(input: RegistrySharedAdmissionCharge): void {
    const row = this.selectPolicy.get(this.config.namespace, input.scope) as PolicyRow | undefined
    const bytes = input.bytes
    if (row === undefined) {
      this.insertPolicy.run(this.config.namespace, input.scope, input.requests.capacity,
        input.requests.refillPerSecond, bytes?.capacity ?? null, bytes?.refillPerSecond ?? null, input.maxEntries)
      return
    }
    if (row.request_capacity !== input.requests.capacity || row.request_refill !== input.requests.refillPerSecond
      || row.byte_capacity !== (bytes?.capacity ?? null) || row.byte_refill !== (bytes?.refillPerSecond ?? null)
      || row.max_entries !== input.maxEntries) fail()
  }

  private rows(input: RegistrySharedAdmissionCharge): BucketRow[] {
    return this.listBuckets.all(this.config.namespace, input.scope) as unknown as BucketRow[]
  }

  private replacement(input: RegistrySharedAdmissionCharge, now: number): string | null | undefined {
    const rows = this.rows(input)
    if (rows.length < input.maxEntries) return undefined
    for (const row of rows) {
      const requests = available(row.request_tokens, input.requests.capacity,
        input.requests.refillPerSecond, row.updated_at, now)
      const bytes = input.bytes === undefined ? null : available(row.byte_tokens ?? 0, input.bytes.capacity,
        input.bytes.refillPerSecond, row.updated_at, now)
      if (requests >= input.requests.capacity && (input.bytes === undefined || (bytes ?? 0) >= input.bytes.capacity)) {
        return row.key_hash
      }
    }
    return null
  }

  private replacementWait(input: RegistrySharedAdmissionCharge, now: number): number {
    let result = RETRY_MAXIMUM
    for (const row of this.rows(input)) {
      const requests = available(row.request_tokens, input.requests.capacity,
        input.requests.refillPerSecond, row.updated_at, now)
      const requestWait = waitFor(requests, input.requests.capacity,
        input.requests.refillPerSecond, input.requests.capacity)
      const byteWait = input.bytes === undefined ? 1 : waitFor(available(row.byte_tokens ?? 0,
        input.bytes.capacity, input.bytes.refillPerSecond, row.updated_at, now),
      input.bytes.capacity, input.bytes.refillPerSecond, input.bytes.capacity)
      result = Math.min(result, Math.max(requestWait, byteWait))
    }
    return result
  }
}

function configure(db: DatabaseSync, config: RegistrySharedAdmissionConfig, key: Buffer): void {
  const app = db.prepare('PRAGMA application_id').get() as { application_id: number }
  const version = db.prepare('PRAGMA user_version').get() as { user_version: number }
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all()
  if ((app.application_id !== 0 && app.application_id !== APPLICATION_ID)
    || (version.user_version !== 0 && version.user_version !== PREVIOUS_SCHEMA_VERSION
      && version.user_version !== SCHEMA_VERSION)
    || (app.application_id === 0 && tables.length > 0)) fail()
  db.exec('PRAGMA foreign_keys = ON')
  db.exec('PRAGMA trusted_schema = OFF')
  const journal = db.prepare(`PRAGMA journal_mode = ${config.journalMode.toUpperCase()}`).get() as {
    journal_mode: string
  }
  if (journal.journal_mode.toLowerCase() !== config.journalMode) fail()
  db.exec('PRAGMA synchronous = FULL')
  db.exec('BEGIN IMMEDIATE')
  try {
    db.exec(`PRAGMA application_id = ${String(APPLICATION_ID)}`)
    db.exec(`PRAGMA user_version = ${String(SCHEMA_VERSION)}`)
    db.exec(`
      CREATE TABLE IF NOT EXISTS admission_namespaces (
        namespace TEXT PRIMARY KEY,
        key_check TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS admission_policies (
        namespace TEXT NOT NULL REFERENCES admission_namespaces(namespace),
        scope TEXT NOT NULL,
        request_capacity INTEGER NOT NULL,
        request_refill INTEGER NOT NULL,
        byte_capacity INTEGER,
        byte_refill INTEGER,
        max_entries INTEGER NOT NULL,
        PRIMARY KEY(namespace, scope)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS admission_buckets (
        namespace TEXT NOT NULL,
        scope TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        request_tokens REAL NOT NULL,
        byte_tokens REAL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY(namespace, scope, key_hash),
        FOREIGN KEY(namespace, scope) REFERENCES admission_policies(namespace, scope)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS admission_audit_policies (
        namespace TEXT PRIMARY KEY REFERENCES admission_namespaces(namespace),
        aggregation_window_ms INTEGER NOT NULL,
        max_entries INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS admission_rejection_audit (
        namespace TEXT NOT NULL,
        scope TEXT NOT NULL,
        reason TEXT NOT NULL CHECK(reason IN ('budget-exhausted', 'key-capacity-exhausted')),
        window_started_at INTEGER NOT NULL,
        last_occurred_at INTEGER NOT NULL,
        rejected_count INTEGER NOT NULL,
        retry_after_seconds INTEGER NOT NULL,
        PRIMARY KEY(namespace, scope, reason, window_started_at),
        FOREIGN KEY(namespace, scope) REFERENCES admission_policies(namespace, scope)
      ) STRICT;
      CREATE INDEX IF NOT EXISTS admission_rejection_audit_recent
        ON admission_rejection_audit(namespace, last_occurred_at);
    `)
    const check = createHmac('sha256', key).update('dsh.registry.shared-admission.key-check.v1\0')
      .update(config.namespace).digest()
    const row = db.prepare('SELECT key_check FROM admission_namespaces WHERE namespace = ?')
      .get(config.namespace) as { key_check: string } | undefined
    if (row === undefined) {
      db.prepare('INSERT INTO admission_namespaces (namespace, key_check) VALUES (?, ?)')
        .run(config.namespace, check.toString('hex'))
    } else {
      if (!/^[0-9a-f]{64}$/u.test(row.key_check)) { check.fill(0); fail() }
      const retained = Buffer.from(row.key_check, 'hex')
      const matches = retained.byteLength === check.byteLength && timingSafeEqual(retained, check)
      retained.fill(0)
      if (!matches) { check.fill(0); fail() }
    }
    check.fill(0)
    const auditPolicy = db.prepare(`SELECT aggregation_window_ms, max_entries
      FROM admission_audit_policies WHERE namespace = ?`).get(config.namespace) as {
      aggregation_window_ms: number
      max_entries: number
    } | undefined
    if (auditPolicy === undefined) {
      db.prepare(`INSERT INTO admission_audit_policies
        (namespace, aggregation_window_ms, max_entries) VALUES (?, ?, ?)`)
        .run(config.namespace, config.audit.aggregationWindowMs, config.audit.maxEntries)
    } else if (auditPolicy.aggregation_window_ms !== config.audit.aggregationWindowMs
      || auditPolicy.max_entries !== config.audit.maxEntries) fail()
    db.exec('COMMIT')
  } catch {
    rollback(db)
    fail()
  }
}
