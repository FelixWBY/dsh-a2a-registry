/** Optional crash-durable same-host outbox for metadata-only Registry operational alerts. */
import { createHash, randomUUID } from 'node:crypto'
import { closeSync, mkdirSync, openSync } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'
import { DatabaseSync, type StatementSync } from 'node:sqlite'
import z from '@deepseek-ai/schemastery'

const APPLICATION_ID = 0x4453484f
const SCHEMA_VERSION = 1
const MAX_ALERT_BYTES = 8_192
const NAMESPACE = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u

/** Dedicated SQLite medium and bounded failed-delivery retention selected by the deployment. */
export interface RegistryOperationalAlertOutboxConfig {
  /** Absolute path to a dedicated local SQLite database shared by Registry exporter processes. */
  readonly path: string
  /** Stable destination-policy namespace. Change it when the endpoint or delivery policy changes. */
  readonly namespace: string
  /** Claim lifetime; it must be longer than one configured HTTP attempt timeout. */
  readonly leaseMs: number
  /** How long terminal delivery failures retain their metadata-only payload. */
  readonly failedRetentionMs: number
  /** Maximum synchronous SQLite lock wait for one outbox transaction. */
  readonly busyTimeoutMs: number
  /** Durable SQLite journal mode; WAL is intended only for a local filesystem. */
  readonly journalMode: 'wal' | 'delete' | 'truncate' | 'persist'
}

const positive = () => z.number().step(1).min(1).max(Number.MAX_SAFE_INTEGER).required()
const schema: z<RegistryOperationalAlertOutboxConfig> = z.object({
  path: z.string().required(), namespace: z.string().pattern(NAMESPACE).required(),
  leaseMs: positive(), failedRetentionMs: positive(),
  busyTimeoutMs: positive().max(2 ** 31 - 1),
  journalMode: z.union(['wal', 'delete', 'truncate', 'persist'] as const).required(),
})

/** Validate the explicit dedicated alert-outbox storage selection. */
export const RegistryOperationalAlertOutboxConfigSchema: z<RegistryOperationalAlertOutboxConfig> = z.transform(
  schema,
  (config) => {
    if (!isAbsolute(config.path) || resolve(config.path) !== config.path) {
      throw new z.ValidationError('Registry operational alert outbox requires an absolute normalized database path', {})
    }
    return config
  },
)

/** Delivery policy pinned to one namespace so concurrent processes cannot silently disagree. */
export interface RegistryOperationalAlertOutboxPolicy {
  readonly endpoint: string
  readonly maxPendingAlerts: number
  readonly deliveryAttempts: number
  readonly timeoutMs: number
  readonly retryDelayMs: number
}

/** One leased metadata envelope. The opaque ID remains stable across every network retry. */
export interface RegistryOperationalAlertClaim {
  readonly id: string
  readonly leaseToken: string
  readonly payload: string
}

interface OutboxRow {
  id: string
  payload: string
  attempts: number
}

interface FailureRow { attempts: number }

/** Content-free failure for unavailable, foreign or policy-mismatched outbox state. */
export class RegistryOperationalAlertOutboxError extends Error {
  constructor() {
    super('Registry operational alert outbox unavailable')
    this.name = 'RegistryOperationalAlertOutboxError'
  }
}

function fail(): never { throw new RegistryOperationalAlertOutboxError() }

function rollback(db: DatabaseSync): void {
  try { db.exec('ROLLBACK') } catch {
    // Preserve the original content-free outbox failure.
  }
}

function nowFrom(clock: () => number): number {
  const now = clock()
  if (!Number.isSafeInteger(now) || now < 0) return fail()
  return now
}

function later(now: number, delay: number): number {
  const result = now + delay
  if (!Number.isSafeInteger(result)) return fail()
  return result
}

function ensureFile(path: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  try { closeSync(openSync(path, 'wx', 0o600)) } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
}

function policyHash(policy: RegistryOperationalAlertOutboxPolicy,
  config: RegistryOperationalAlertOutboxConfig): string {
  return createHash('sha256').update('dsh.registry.operational-alert-outbox.policy.v1\0')
    .update(JSON.stringify([policy.endpoint, policy.maxPendingAlerts, policy.deliveryAttempts,
      policy.timeoutMs, policy.retryDelayMs, config.leaseMs, config.failedRetentionMs,
      config.journalMode])).digest('hex')
}

function validPolicy(policy: RegistryOperationalAlertOutboxPolicy): boolean {
  return boundedPolicyInteger(policy.maxPendingAlerts) && boundedPolicyInteger(policy.deliveryAttempts)
    && boundedPolicyInteger(policy.timeoutMs) && boundedPolicyInteger(policy.retryDelayMs)
    && policy.endpoint.length > 0 && policy.endpoint.isWellFormed()
    && Buffer.byteLength(policy.endpoint, 'utf8') <= 4_096
}

function boundedPolicyInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0
}

/** Dedicated SQLite owner with atomic enqueue, cross-process claims and bounded dead-letter retention. */
export class RegistryOperationalAlertOutbox {
  private closed = false
  private readonly insert: StatementSync
  private readonly countPending: StatementSync
  private readonly selectClaim: StatementSync
  private readonly claimRow: StatementSync
  private readonly completeClaim: StatementSync
  private readonly selectFailure: StatementSync
  private readonly retryClaim: StatementSync
  private readonly rejectClaim: StatementSync
  private readonly expireFailures: StatementSync
  private readonly trimFailures: StatementSync

  private constructor(private readonly db: DatabaseSync,
    private readonly config: RegistryOperationalAlertOutboxConfig,
    private readonly policy: RegistryOperationalAlertOutboxPolicy,
    private readonly clock: () => number) {
    this.insert = db.prepare(`INSERT INTO operational_alert_outbox
      (id, namespace, payload, attempts, next_attempt_at, lease_token, lease_until, state, failed_at, created_at)
      VALUES (?, ?, ?, 0, ?, NULL, NULL, 'pending', NULL, ?)`)
    this.countPending = db.prepare(`SELECT COUNT(*) AS count FROM operational_alert_outbox
      WHERE namespace = ? AND state = 'pending'`)
    this.selectClaim = db.prepare(`SELECT id, payload, attempts FROM operational_alert_outbox
      WHERE namespace = ? AND state = 'pending' AND next_attempt_at <= ?
        AND (lease_until IS NULL OR lease_until <= ?)
      ORDER BY next_attempt_at, created_at, id LIMIT 1`)
    this.claimRow = db.prepare(`UPDATE operational_alert_outbox SET lease_token = ?, lease_until = ?
      WHERE namespace = ? AND id = ? AND state = 'pending'
        AND (lease_until IS NULL OR lease_until <= ?)`)
    this.completeClaim = db.prepare(`DELETE FROM operational_alert_outbox
      WHERE namespace = ? AND id = ? AND state = 'pending' AND lease_token = ?`)
    this.selectFailure = db.prepare(`SELECT attempts FROM operational_alert_outbox
      WHERE namespace = ? AND id = ? AND state = 'pending' AND lease_token = ?`)
    this.retryClaim = db.prepare(`UPDATE operational_alert_outbox
      SET attempts = ?, next_attempt_at = ?, lease_token = NULL, lease_until = NULL
      WHERE namespace = ? AND id = ? AND state = 'pending' AND lease_token = ?`)
    this.rejectClaim = db.prepare(`UPDATE operational_alert_outbox
      SET attempts = ?, lease_token = NULL, lease_until = NULL, state = 'failed', failed_at = ?
      WHERE namespace = ? AND id = ? AND state = 'pending' AND lease_token = ?`)
    this.expireFailures = db.prepare(`DELETE FROM operational_alert_outbox
      WHERE namespace = ? AND state = 'failed' AND failed_at <= ?`)
    this.trimFailures = db.prepare(`DELETE FROM operational_alert_outbox WHERE id IN (
      SELECT id FROM operational_alert_outbox WHERE namespace = ? AND state = 'failed'
      ORDER BY failed_at DESC, id DESC LIMIT -1 OFFSET ?
    )`)
  }

  /** Open the dedicated store and bind its namespace to one exact destination policy. */
  static open(input: RegistryOperationalAlertOutboxConfig, policy: RegistryOperationalAlertOutboxPolicy,
    clock: () => number = () => Date.now()): RegistryOperationalAlertOutbox {
    const config = RegistryOperationalAlertOutboxConfigSchema(input)
    if (!validPolicy(policy)) return fail()
    let db: DatabaseSync | undefined
    try {
      ensureFile(config.path)
      db = new DatabaseSync(config.path, { timeout: config.busyTimeoutMs })
      configure(db, config, policyHash(policy, config))
      return new RegistryOperationalAlertOutbox(db, structuredClone(config), structuredClone(policy), clock)
    } catch {
      try { db?.close() } catch { /* The open failure remains authoritative. */ }
      return fail()
    }
  }

  /** Persist one payload before reporting acceptance to its caller.
   * @returns Its stable delivery ID, or null when the configured pending capacity is already full. */
  enqueue(payload: string): string | null {
    if (this.closed || !payload.isWellFormed() || Buffer.byteLength(payload, 'utf8') > MAX_ALERT_BYTES) return fail()
    const now = nowFrom(this.clock)
    try {
      this.db.exec('BEGIN IMMEDIATE')
      this.prune(now)
      const row = this.countPending.get(this.config.namespace) as { count: number }
      if (!Number.isSafeInteger(row.count) || row.count < 0) return fail()
      if (row.count >= this.policy.maxPendingAlerts) { rollback(this.db); return null }
      const id = randomUUID()
      this.insert.run(id, this.config.namespace, payload, now, now)
      this.db.exec('COMMIT')
      return id
    } catch {
      rollback(this.db)
      return fail()
    }
  }

  /** Atomically claim one due record across every process sharing this database and namespace. */
  claim(): RegistryOperationalAlertClaim | null {
    if (this.closed) return fail()
    const now = nowFrom(this.clock)
    try {
      this.db.exec('BEGIN IMMEDIATE')
      const row = this.selectClaim.get(this.config.namespace, now, now) as OutboxRow | undefined
      if (row === undefined) { this.db.exec('COMMIT'); return null }
      if (!Number.isSafeInteger(row.attempts) || row.attempts < 0 || row.attempts >= this.policy.deliveryAttempts
        || !UUID.test(row.id) || typeof row.payload !== 'string'
        || !row.payload.isWellFormed() || Buffer.byteLength(row.payload, 'utf8') > MAX_ALERT_BYTES) return fail()
      const leaseToken = randomUUID()
      const result = this.claimRow.run(leaseToken, later(now, this.config.leaseMs),
        this.config.namespace, row.id, now)
      if (result.changes !== 1) return fail()
      this.db.exec('COMMIT')
      return Object.freeze({ id: row.id, leaseToken, payload: row.payload })
    } catch {
      rollback(this.db)
      return fail()
    }
  }

  /** Delete a record only when this exact lease still owns it. */
  complete(claim: RegistryOperationalAlertClaim): boolean {
    if (this.closed) return fail()
    try {
      return this.completeClaim.run(this.config.namespace, claim.id, claim.leaseToken).changes === 1
    } catch { return fail() }
  }

  /** Persist a failed attempt, scheduling retry or retaining a bounded terminal failure.
   * @param terminal - Immediately retain malformed local state without sending it to the endpoint.
   * @returns `retry`, `failed`, or `stale` when another lease already owns the record. */
  failClaim(claim: RegistryOperationalAlertClaim, terminal = false): 'retry' | 'failed' | 'stale' {
    if (this.closed) return fail()
    const now = nowFrom(this.clock)
    try {
      this.db.exec('BEGIN IMMEDIATE')
      const row = this.selectFailure.get(this.config.namespace, claim.id, claim.leaseToken) as FailureRow | undefined
      if (row === undefined) { this.db.exec('COMMIT'); return 'stale' }
      if (!Number.isSafeInteger(row.attempts) || row.attempts < 0) return fail()
      const attempts = row.attempts + 1
      const failed = terminal || attempts >= this.policy.deliveryAttempts
      const result = failed
        ? this.rejectClaim.run(attempts, now, this.config.namespace, claim.id, claim.leaseToken)
        : this.retryClaim.run(attempts, later(now, this.policy.retryDelayMs),
          this.config.namespace, claim.id, claim.leaseToken)
      if (result.changes !== 1) return fail()
      this.prune(now)
      this.db.exec('COMMIT')
      return failed ? 'failed' : 'retry'
    } catch {
      rollback(this.db)
      return fail()
    }
  }

  /** Close this process handle. Pending rows and unexpired failures stay durable. */
  close(): void {
    if (this.closed) return
    this.closed = true
    try { this.db.close() } catch { return fail() }
  }

  private prune(now: number): void {
    const cutoff = now < this.config.failedRetentionMs ? -1 : now - this.config.failedRetentionMs
    this.expireFailures.run(this.config.namespace, cutoff)
    this.trimFailures.run(this.config.namespace, this.policy.maxPendingAlerts)
  }
}

function configure(db: DatabaseSync, config: RegistryOperationalAlertOutboxConfig, expectedPolicyHash: string): void {
  const app = db.prepare('PRAGMA application_id').get() as { application_id: number }
  const version = db.prepare('PRAGMA user_version').get() as { user_version: number }
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all()
  if ((app.application_id !== 0 && app.application_id !== APPLICATION_ID)
    || (version.user_version !== 0 && version.user_version !== SCHEMA_VERSION)
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
      CREATE TABLE IF NOT EXISTS operational_alert_namespaces (
        namespace TEXT PRIMARY KEY,
        policy_hash TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS operational_alert_outbox (
        id TEXT PRIMARY KEY,
        namespace TEXT NOT NULL REFERENCES operational_alert_namespaces(namespace),
        payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) <= ${String(MAX_ALERT_BYTES)}),
        attempts INTEGER NOT NULL CHECK(attempts >= 0),
        next_attempt_at INTEGER NOT NULL,
        lease_token TEXT,
        lease_until INTEGER,
        state TEXT NOT NULL CHECK(state IN ('pending', 'failed')),
        failed_at INTEGER,
        created_at INTEGER NOT NULL,
        CHECK((lease_token IS NULL) = (lease_until IS NULL)),
        CHECK((state = 'pending' AND failed_at IS NULL) OR (state = 'failed' AND failed_at IS NOT NULL))
      ) STRICT;
      CREATE INDEX IF NOT EXISTS operational_alert_due
        ON operational_alert_outbox(namespace, state, next_attempt_at, lease_until, created_at);
      CREATE INDEX IF NOT EXISTS operational_alert_failed
        ON operational_alert_outbox(namespace, state, failed_at);
    `)
    const row = db.prepare('SELECT policy_hash FROM operational_alert_namespaces WHERE namespace = ?')
      .get(config.namespace) as { policy_hash: string } | undefined
    if (row === undefined) {
      db.prepare('INSERT INTO operational_alert_namespaces (namespace, policy_hash) VALUES (?, ?)')
        .run(config.namespace, expectedPolicyHash)
    } else if (row.policy_hash !== expectedPolicyHash) fail()
    db.exec('COMMIT')
  } catch {
    rollback(db)
    fail()
  }
}
