/** Pure registry decisions. Storage owners commit decisions, version fences, and audit atomically. */
import type {
  A2aDispatchDecision, A2aRequestState, DisclosureAccess, DisclosureAccessUpdate,
  DisclosureAction, DisclosureAuthorization, DisclosureCapability, DisclosureControlState,
  DisclosureSubject, DshInstanceId, OrganizationId, ProducerSyncState, QueuedA2aRequest,
  RegistryIngestState, VerifiedDisclosureCheckpoint,
} from './types.ts'

export type * from './types.ts'

/** Canonical control vocabulary for validators and authenticated UI mirrors. */
export const DISCLOSURE_CONTROL_STATES: readonly DisclosureControlState[] = Object.freeze(['active', 'paused', 'revoked', 'expired', 'deleting', 'deleted'])
/** Canonical producer progress vocabulary, independent from disclosure authorization. */
export const PRODUCER_SYNC_STATES: readonly ProducerSyncState[] = Object.freeze(['idle', 'backfilling', 'live', 'offline', 'error_retryable', 'error_conflict'])
/** Canonical ingest publication vocabulary for persisted validators. */
export const REGISTRY_INGEST_STATES: readonly RegistryIngestState[] = Object.freeze(['pending', 'ready', 'frozen'])
/** Version-one capability allowlist; unsupported capabilities must not be enabled by a consumer. */
export const DISCLOSURE_CAPABILITIES: readonly DisclosureCapability[] = Object.freeze(['conversation.read', 'branch.create'])
const controls = DISCLOSURE_CONTROL_STATES
const producers = PRODUCER_SYNC_STATES
const ingests = REGISTRY_INGEST_STATES
const capabilities = DISCLOSURE_CAPABILITIES
const grantStates = ['active', 'revoked'] as const
const grantTargets = ['member', 'team'] as const

const controlTransitions: Record<DisclosureControlState, readonly DisclosureControlState[]> = {
  active: ['paused', 'revoked', 'expired'],
  paused: ['active', 'revoked', 'expired'],
  revoked: ['deleting'],
  expired: ['deleting'],
  deleting: ['deleted'],
  deleted: [],
}
const requestTransitions: Record<A2aRequestState, readonly A2aRequestState[]> = {
  created: ['queued', 'cancelled', 'expired'],
  queued: ['delivered', 'cancelled', 'expired'],
  delivered: ['running', 'failed'],
  running: ['completed', 'failed'],
  completed: [],
  expired: [],
  cancelled: [],
  failed: [],
}
const producerTransitions: Record<ProducerSyncState, readonly ProducerSyncState[]> = {
  idle: ['backfilling'],
  backfilling: ['live', 'idle', 'offline', 'error_retryable', 'error_conflict'],
  live: ['backfilling', 'idle', 'offline', 'error_retryable', 'error_conflict'],
  offline: ['backfilling', 'idle', 'error_retryable', 'error_conflict'],
  error_retryable: ['backfilling', 'offline', 'idle', 'error_conflict'],
  error_conflict: [],
}

/** Invalid durable state, forbidden transition, or stale conditional update. */
export class RegistryDomainError extends Error {
  /** @param message - Local diagnostic; never return this detail as a public access denial. */
  constructor(message: string) {
    super(message)
    this.name = 'RegistryDomainError'
  }
}

function validVersion(version: number): boolean {
  return Number.isSafeInteger(version) && version >= 0
}

function validAccess(access: DisclosureAccess): boolean {
  return controls.includes(access.control) && producers.includes(access.producer)
    && ingests.includes(access.ingest) && Number.isFinite(access.expiresAt)
    && validVersion(access.authorizationVersion)
    && access.capabilities.every(capability => capabilities.includes(capability))
    && access.grants.every(grant => grantStates.includes(grant.state)
      && grantTargets.includes(grant.target.kind)
      && Number.isFinite(grant.expiresAt)
      && grant.capabilities.every(capability => capabilities.includes(capability)))
    && (access.ingest !== 'ready' || access.checkpointHash !== null)
}

function accessibleControl(access: DisclosureAccess, now: number): boolean {
  return Number.isFinite(now) && now < access.expiresAt
    && (access.control === 'active' || access.control === 'paused')
}

function requiredCapabilities(action: DisclosureAction): readonly DisclosureCapability[] | null {
  switch (action) {
    case 'read':
    case 'subscribe': return ['conversation.read']
    case 'import':
    case 'ask':
    case 'refresh': return ['conversation.read', 'branch.create']
    default: return null
  }
}

/**
 * Evaluate a read or branch action from freshly loaded membership and disclosure facts.
 * @param subject - Current authenticated member, never a grant-time member expansion.
 * @param action - Operation being executed; unknown operations deny access.
 * @param access - Current disclosure or null when absent.
 * @param now - Registry clock in epoch milliseconds.
 * @returns A confirmed prefix and evaluation version, or the uniform public denial.
 */
export function authorizeDisclosure(
  subject: DisclosureSubject, action: DisclosureAction, access: DisclosureAccess | null, now: number,
): DisclosureAuthorization {
  const denied = { allowed: false, code: 'not-found' } as const
  const required = requiredCapabilities(action)
  if (access === null || required === null || !validAccess(access)
    || !subject.authenticated || subject.membership !== 'active'
    || subject.organizationId !== access.organizationId || !accessibleControl(access, now)
    || access.ingest === 'pending' || access.checkpointHash === null) return denied

  const matching = access.grants.filter(grant => grant.state === 'active' && now < grant.expiresAt
    && (grant.target.kind === 'member'
      ? grant.target.memberId === subject.memberId
      : subject.currentTeamIds.includes(grant.target.teamId)))
  if (!required.every(capability => access.capabilities.includes(capability)
    && matching.some(grant => grant.capabilities.includes(capability)))) return denied
  return { allowed: true, authorizationVersion: access.authorizationVersion, checkpointHash: access.checkpointHash }
}

/**
 * Check producer identity and upload eligibility independently of reader grants.
 * @param access - Current disclosure access state.
 * @param organizationId - Organization from authenticated instance credentials.
 * @param instanceId - Instance from authenticated instance credentials.
 * @param now - Registry clock in epoch milliseconds.
 * @returns Whether ingestion may accept a new event or completion checkpoint.
 */
export function canUploadDisclosure(
  access: DisclosureAccess, organizationId: OrganizationId, instanceId: DshInstanceId, now: number,
): boolean {
  return validAccess(access) && Number.isFinite(now) && now < access.expiresAt
    && access.control === 'active' && access.ingest !== 'frozen'
    && access.organizationId === organizationId && access.instanceId === instanceId
}

function assertUpdate(access: DisclosureAccess, expectedVersion: number): void {
  if (!validAccess(access)) throw new RegistryDomainError('disclosure access state is invalid')
  if (access.authorizationVersion !== expectedVersion) throw new RegistryDomainError('authorization version conflict')
}

function nextVersion(version: number): number {
  if (!validVersion(version) || version === Number.MAX_SAFE_INTEGER) {
    throw new RegistryDomainError('authorization version cannot increment')
  }
  return version + 1
}

/**
 * Invalidate decisions after a committed member/team change affecting this disclosure.
 * @param access - Current disclosure state.
 * @param expectedVersion - Version read by the transaction.
 * @returns A detached state with the next authorization version.
 * @throws RegistryDomainError for invalid state, stale version, or version exhaustion.
 */
export function invalidateDisclosureAuthorization(access: DisclosureAccess, expectedVersion: number): DisclosureAccess {
  assertUpdate(access, expectedVersion)
  return { ...access, authorizationVersion: nextVersion(access.authorizationVersion) }
}

/**
 * Replace explicit grants, capabilities, and expiry without reviving an expired disclosure.
 * @param access - Current disclosure state.
 * @param update - Complete new access fields.
 * @param expectedVersion - Version read by the transaction.
 * @param now - Registry clock in epoch milliseconds.
 * @returns Unchanged state for an identical replacement; otherwise the next version.
 * @throws RegistryDomainError for stale, invalid, terminal, or already elapsed state.
 */
export function updateDisclosureAccess(
  access: DisclosureAccess, update: DisclosureAccessUpdate, expectedVersion: number, now: number,
): DisclosureAccess {
  assertUpdate(access, expectedVersion)
  // Typed callers can still carry extra JSON fields; access edits never change identity or control.
  const candidate = {
    ...access, expiresAt: update.expiresAt, capabilities: update.capabilities, grants: update.grants,
  }
  if (!accessibleControl(access, now) || !validAccess(candidate) || update.expiresAt <= now) {
    throw new RegistryDomainError('disclosure access update is not permitted')
  }
  if (access.expiresAt === update.expiresAt
    && JSON.stringify(access.capabilities) === JSON.stringify(update.capabilities)
    && JSON.stringify(access.grants) === JSON.stringify(update.grants)) return access
  return {
    ...candidate,
    capabilities: [...update.capabilities],
    grants: update.grants.map(grant => ({ ...grant, target: { ...grant.target }, capabilities: [...grant.capabilities] })),
    authorizationVersion: nextVersion(access.authorizationVersion),
  }
}

/**
 * Apply one conditional control transition; revoked and expired resources cannot reactivate.
 * @param access - Current state under transaction lock.
 * @param target - Requested control state.
 * @param expectedVersion - Version read by the transaction.
 * @param now - Registry clock in epoch milliseconds.
 * @returns Same state for a repeated transition, otherwise the next authorization version.
 * @throws RegistryDomainError for an invalid, stale, or forbidden transition.
 */
export function transitionDisclosureControl(
  access: DisclosureAccess, target: DisclosureControlState, expectedVersion: number, now: number,
): DisclosureAccess {
  assertUpdate(access, expectedVersion)
  if (!Number.isFinite(now) || !controls.includes(target)) throw new RegistryDomainError('invalid control transition')
  if (target === access.control) return access
  if (!controlTransitions[access.control].includes(target)
    || (target === 'active' && now >= access.expiresAt)
    || (target === 'expired' && now < access.expiresAt)) {
    throw new RegistryDomainError(`disclosure control cannot transition from ${access.control} to ${target}`)
  }
  return { ...access, control: target, authorizationVersion: nextVersion(access.authorizationVersion) }
}

/**
 * Validate an idempotent request transition without changing any other request facts.
 * @param state - Current durable state.
 * @param target - Requested next state.
 * @returns The accepted target state.
 * @throws RegistryDomainError for unknown states or a forbidden transition.
 */
export function transitionA2aRequest(state: A2aRequestState, target: A2aRequestState): A2aRequestState {
  const allowed = requestTransitions[state]
  if (!Object.hasOwn(requestTransitions, state) || !Object.hasOwn(requestTransitions, target)
    || (state !== target && !allowed.includes(target))) {
    throw new RegistryDomainError(`A2A request cannot transition from ${state} to ${target}`)
  }
  return target
}

/**
 * Validate local progress without altering disclosure access or Registry readiness.
 * @param state - Current producer progress.
 * @param target - Requested next progress.
 * @returns Accepted target; integrity conflicts cannot restart the same chain.
 * @throws RegistryDomainError for unknown or forbidden transitions.
 */
export function transitionProducerSync(state: ProducerSyncState, target: ProducerSyncState): ProducerSyncState {
  if (!producers.includes(state) || !producers.includes(target)
    || (state !== target && !producerTransitions[state].includes(target))) {
    throw new RegistryDomainError(`producer cannot transition from ${state} to ${target}`)
  }
  return target
}

/**
 * Validate publication readiness after the ingest owner verifies the complete signed prefix.
 * @param state - Current Registry ingest state.
 * @param target - Requested publication state.
 * @returns Accepted target; a frozen chain cannot publish another prefix.
 * @throws RegistryDomainError for unknown or forbidden transitions.
 */
export function transitionRegistryIngest(state: RegistryIngestState, target: RegistryIngestState): RegistryIngestState {
  if (!ingests.includes(state) || !ingests.includes(target)
    || (state !== target && !(state === 'pending' && target === 'ready') && target !== 'frozen')) {
    throw new RegistryDomainError(`ingest cannot transition from ${state} to ${target}`)
  }
  return target
}

/**
 * Reauthorize a queued question immediately before transaction-owned dispatch.
 * @param request - Durable queue item binding requester, disclosure, checkpoint and prior version.
 * @param subject - Fresh membership facts for that exact requester.
 * @param access - Fresh disclosure state or null.
 * @param now - Registry clock in epoch milliseconds.
 * @param sourceOnline - Authenticated source presence; false retains the queue without execution.
 * @param verifiedCheckpoint - Exact retained prefix verified inside the current lease, or null; never request JSON.
 * @returns Deliver only after the owner atomically commits the state/version fence; retries of advanced states are settled.
 * @throws RegistryDomainError for invalid queue timestamps, versions, or states.
 */
export function evaluateA2aDispatch(
  request: QueuedA2aRequest, subject: DisclosureSubject, access: DisclosureAccess | null,
  now: number, sourceOnline: boolean, verifiedCheckpoint: VerifiedDisclosureCheckpoint | null,
): A2aDispatchDecision {
  transitionA2aRequest(request.state, request.state)
  if (!validVersion(request.authorizationVersion) || !Number.isFinite(request.expiresAt) || !Number.isFinite(now)) {
    throw new RegistryDomainError('A2A queue item has invalid expiry or authorization version')
  }
  if (request.state !== 'queued') return { kind: 'settled', request }
  if (now >= request.expiresAt) return { kind: 'expire', request: { ...request, state: 'expired' } }
  const authorization = authorizeDisclosure(subject, 'ask', access, now)
  if (!authorization.allowed || access === null
    || request.organizationId !== subject.organizationId || request.requesterId !== subject.memberId
    || request.disclosureId !== access.disclosureId || verifiedCheckpoint === null
    || verifiedCheckpoint.authorizationVersion !== authorization.authorizationVersion
    || verifiedCheckpoint.checkpoint.organizationId !== access.organizationId
    || verifiedCheckpoint.checkpoint.instanceId !== access.instanceId
    || verifiedCheckpoint.checkpoint.disclosureId !== access.disclosureId
    || verifiedCheckpoint.checkpoint.checkpointHash !== request.checkpointHash
    || request.authorizationVersion > authorization.authorizationVersion) {
    return { kind: 'cancel', request: { ...request, state: 'cancelled' } }
  }
  return {
    kind: sourceOnline ? 'deliver' : 'wait',
    request: { ...request, authorizationVersion: authorization.authorizationVersion, state: sourceOnline ? 'delivered' : 'queued' },
  }
}
