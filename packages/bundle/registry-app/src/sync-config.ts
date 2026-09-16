/** Explicit bounds for the private producer endpoint behind a deployment-owned TLS proxy. */
import z from '@deepseek-ai/schemastery'
import { REGISTRY_SYNC_PATH } from '@deepseek-ai/dsh-a2a-registry-sync'
import { decodeRegistryAudience } from '@deepseek-ai/dsh-a2a-device-identity/runtime'

/** Explicit token capacity and continuous refill rate; all values are positive safe integers. */
export interface RegistrySyncBucketConfig {
  /** Maximum accumulated tokens and initial burst allowance. */
  capacity: number
  /** Tokens restored per second of monotonic elapsed time, capped at capacity. */
  refillPerSecond: number
}

/** Both request count and complete incoming UTF-8 frame bytes must be available. */
export interface RegistrySyncFrameBudgetConfig {
  /** One token per admitted frame or authenticated operation. */
  requests: RegistrySyncBucketConfig
  /** One token per byte of the complete incoming frame. */
  bytes: RegistrySyncBucketConfig
}

/** Bounded keyed budgets; top-level sharedAdmission may persist them across same-host processes. */
export interface RegistrySyncScopedBudgetConfig extends RegistrySyncFrameBudgetConfig {
  /** Maximum retained keys; only entries whose request and byte buckets are full may be replaced. */
  maxEntries: number
}

/** One shared admission owner for all connections on the private synchronization route. */
export interface RegistrySyncAdmissionConfig {
  /** Global accepted HTTP upgrade attempts. */
  upgrades: RegistrySyncBucketConfig
  /** Complete WebSocket data messages, including malformed/binary/unauthenticated payloads, charged before decoding. */
  frames: RegistrySyncFrameBudgetConfig
  /** Global identity begin and complete calls, each charged before invoking the provider. */
  handshakes: RegistrySyncBucketConfig
  /** Authenticated organization budgets shared across its instances and connections. */
  organizations: RegistrySyncScopedBudgetConfig
  /** Authenticated organization-instance tuples; key rotation does not select a new budget. */
  instances: RegistrySyncScopedBudgetConfig
  /** Organization-instance-disclosure tuples; a supplied disclosure ID cannot consume another instance's budget. */
  disclosures: RegistrySyncScopedBudgetConfig
}

/** No listener, timeout, connection or byte defaults are selected by the Registry sync consumer. */
export interface RegistrySyncConfig {
  /** Canonical full wss URL with the fixed sync path; never inferred from request headers. */
  audience: string
  /** Requires the Host HTTP listener to bind only 127.0.0.1 behind a trusted TLS proxy. */
  tlsTermination: 'loopback-proxy'
  /** Maximum accepted connections, including handshakes and draining operations. */
  maxConnections: number
  /** Complete incoming and outgoing JSON frame UTF-8 byte limit. */
  maxFrameBytes: number
  /** Buffered plus next encoded frame byte limit, at least maxFrameBytes. */
  maxSendBufferBytes: number
  /** Entire handshake deadline, a positive integer no greater than 2^31-1 milliseconds. */
  handshakeTimeoutMs: number
  /** Deadline without a completed authenticated request, at most 2^31-1 milliseconds. */
  idleTimeoutMs: number
  /** Required admission budgets; independent of retained-data and concurrent-connection limits. */
  admission: RegistrySyncAdmissionConfig
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const timer = () => positive().max(2 ** 31 - 1)
const bucket: z<RegistrySyncBucketConfig> = z.object({ capacity: positive(), refillPerSecond: positive() }).required()
const frameBudget: z<RegistrySyncFrameBudgetConfig> = z.object({ requests: bucket, bytes: bucket }).required()
const scopedBudget: z<RegistrySyncScopedBudgetConfig> = z.object({
  maxEntries: positive(), requests: bucket, bytes: bucket,
}).required()
const admission: z<RegistrySyncAdmissionConfig> = z.object({
  upgrades: bucket, frames: frameBudget, handshakes: bucket,
  organizations: scopedBudget, instances: scopedBudget, disclosures: scopedBudget,
}).required()

const schema: z<RegistrySyncConfig> = z.object({
  audience: z.string().required(), tlsTermination: z.const('loopback-proxy').required(),
  maxConnections: positive(), maxFrameBytes: positive(), maxSendBufferBytes: positive(),
  handshakeTimeoutMs: timer(), idleTimeoutMs: timer(),
  admission,
})

/** Validate the complete deployment configuration before registering an upgrade route. */
export const Config: z<RegistrySyncConfig> = z.transform(schema, (input) => {
  try { decodeRegistryAudience(input.audience) } catch {
    throw new z.ValidationError('Registry sync requires a canonical WSS audience', {})
  }
  if (new URL(input.audience).pathname !== REGISTRY_SYNC_PATH || input.maxFrameBytes > input.maxSendBufferBytes) {
    throw new z.ValidationError('Registry sync path or byte bounds are invalid', {})
  }
  return input
})
