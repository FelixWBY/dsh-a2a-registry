/** Browser-safe Registry metadata and the package-local same-origin HTTP adapter. */

export type RegistryApiErrorCode =
  | 'identity-not-configured'
  | 'registry-not-configured'
  | 'unauthenticated'
  | 'not-found'
  | 'invalid-input'
  | 'conflict'
  | 'operation-not-configured'
  | 'method-not-allowed'
  | 'rate-limited'
  | 'unavailable'

export type RegistryAuthorizedAction = 'read' | 'import' | 'ask'
export type RegistryControlState = 'active' | 'paused' | 'revoked' | 'expired' | 'deleting' | 'deleted'
export type RegistryProducerState = 'idle' | 'backfilling' | 'live' | 'offline' | 'error_retryable' | 'error_conflict'
export type RegistryIngestState = 'pending' | 'ready' | 'frozen'

export interface RegistryCheckpointMetadata {
  readonly checkpointHash: string
  readonly policyVersion: number
  readonly sourceCursor: number
  readonly eventCount: number
  readonly lastDisclosureSeq: number
  readonly lastEventHash: string | null
}

/** Authorized metadata only; no title, owner, conversation identity or body. */
export interface RegistryDisclosureMetadata {
  readonly disclosureId: string
  readonly instanceId: string
  readonly control: RegistryControlState
  readonly producer: RegistryProducerState
  readonly ingest: RegistryIngestState
  readonly expiresAt: number
  readonly authorizationVersion: number
  /** Registry-confirmed time for the selected signed checkpoint, not a transport heartbeat. */
  readonly checkpointVerifiedAt: number
  readonly checkpoint: RegistryCheckpointMetadata
  /** Host-computed current actions; the browser never derives these from lifecycle fields. */
  readonly authorizedActions: readonly RegistryAuthorizedAction[]
}

/** Detail and list rows share the same freshly authorized metadata contract. */
export type RegistryDisclosureDetail = RegistryDisclosureMetadata

export interface RegistryDisclosurePage {
  readonly items: readonly RegistryDisclosureMetadata[]
  readonly nextCursor: string | null
}

export type RegistryDisclosureContentEvent =
  | {
    readonly disclosureSeq: number
    readonly occurredAt: number
    readonly type: 'conversation.user-message' | 'conversation.assistant-message'
    readonly text: string
  }
  | {
    readonly disclosureSeq: number
    readonly occurredAt: number
    readonly type: 'conversation.tool-result-summary'
    readonly toolName: string
    readonly outcome: 'success' | 'failure'
    readonly text: string
  }
  | {
    readonly disclosureSeq: number
    readonly occurredAt: number
    readonly type: 'conversation.title'
    readonly title: string
  }

/** Authorized plain-text events for one immutable disclosure checkpoint. */
export interface RegistryDisclosureContent {
  readonly checkpointHash: string
  readonly events: readonly RegistryDisclosureContentEvent[]
}

export type RegistryInstancePhase = 'confirmed' | 'revoked'
export type RegistryInstanceScope = 'disclosure.sync' | 'a2a.receive'
export type RegistryInstanceTransport = 'connected' | 'not-observed'
export type RegistryInstanceReportState = 'online' | 'busy' | 'paused' | 'degraded'

/** Authorized account-owned binding plus current, explicitly non-historical transport observation. */
export interface RegistryInstance {
  readonly bindingId: string
  readonly instanceId: string
  readonly instanceName: string
  readonly phase: RegistryInstancePhase
  readonly requestedScopes: readonly RegistryInstanceScope[]
  readonly transport: RegistryInstanceTransport
  readonly lastHeartbeatAt: number | null
  readonly reportState: RegistryInstanceReportState | null
  readonly acceptingA2A: boolean | null
  readonly activeRequests: number | null
}

export interface RegistryInstancePage {
  readonly items: readonly RegistryInstance[]
}

export type RegistryBindingPhase = 'pending' | 'approved' | 'confirmed' | 'rejected' | 'revoked'

/** Code-authorized enrollment metadata; it contains no code, public key, challenge or account identity. */
export interface RegistryBindingReview {
  readonly bindingId: string
  readonly instanceId: string
  readonly keyId: string
  readonly createdAt: number
  readonly expiresAt: number
  readonly phase: RegistryBindingPhase
  readonly instanceName: string
  readonly requestedScopes: readonly RegistryInstanceScope[]
}

export type RegistryDirectoryRole = 'owner' | 'admin' | 'member'
export type RegistryDirectoryMemberState = 'active' | 'suspended' | 'removed'

export interface RegistryDirectoryMember {
  readonly memberId: string
  readonly displayName: string
  readonly role: RegistryDirectoryRole
  readonly state: RegistryDirectoryMemberState
}

export interface RegistryDirectoryTeam {
  readonly teamId: string
  readonly displayName: string
  readonly memberIds: readonly string[]
}

/** Administrator-visible organization directory revision; it contains no account or login credentials. */
export interface RegistryDirectoryPage {
  readonly revision: number
  readonly actorRole: RegistryDirectoryRole
  readonly members: readonly RegistryDirectoryMember[]
  readonly teams: readonly RegistryDirectoryTeam[]
}

export type RegistryDirectoryChange =
  | { readonly kind: 'put-member'; readonly member: RegistryDirectoryMember }
  | { readonly kind: 'put-team'; readonly team: RegistryDirectoryTeam }
  | { readonly kind: 'remove-team'; readonly teamId: string }

export interface RegistryDirectoryChangeReceipt {
  readonly revision: number
  readonly invalidatedDisclosures: number
}

export type RegistryConfigurationState = 'configured' | 'unconfigured'
export type RegistryDeploymentMode = 'standard' | 'test-only'
export type RegistryIdentityProvider = 'oidc' | 'external' | 'local-test' | 'unconfigured'
export type RegistryBillingProvider = 'stripe' | 'alipay' | 'unconfigured'

/** Startup configuration facts; these labels do not claim ongoing worker health. */
export interface RegistryRuntimeStatus {
  /** Server-owned deployment class; `standard` is not itself a production-health claim. */
  readonly deploymentMode: RegistryDeploymentMode
  readonly identity: RegistryConfigurationState
  readonly identityProvider: RegistryIdentityProvider
  readonly registry: RegistryConfigurationState
  readonly disclosureOperations: RegistryConfigurationState
  readonly deviceBinding: RegistryConfigurationState
  readonly audit: RegistryConfigurationState
  readonly rateLimits: RegistryConfigurationState
  readonly disclosureCleanup: RegistryConfigurationState
  readonly mailboxCleanup: RegistryConfigurationState
  readonly billing: RegistryConfigurationState
  readonly billingProvider: RegistryBillingProvider
}

export interface RegistryListRequest {
  readonly cursor?: string
}

export type RegistryAuditActorKind = 'enrollment' | 'producer' | 'member' | 'maintenance' | 'unattributed'
export type RegistryAuditResult = 'pending' | 'succeeded' | 'rejected'
export type RegistryAuditAction = 'register' | 'status' | 'event' | 'checkpoint' | 'read' | 'metadata-read'
  | 'metadata-list' | 'access' | 'control' | 'delete' | 'directory-read' | 'directory-change'
  | 'binding-start' | 'binding-approve' | 'binding-confirm' | 'binding-review' | 'binding-reject'
  | 'binding-revoke' | 'binding-rename' | 'binding-list'

/** Authorized journal projection; it cannot carry request/reply bodies or provider diagnostics. */
export interface RegistryAuditMetadata {
  readonly operationId: string
  readonly occurredAt: number
  readonly actorKind: RegistryAuditActorKind
  readonly actorId: string | null
  readonly instanceId: string | null
  readonly objectId: string | null
  readonly action: RegistryAuditAction
  readonly result: RegistryAuditResult
}

export interface RegistryAuditPage {
  readonly items: readonly RegistryAuditMetadata[]
  readonly nextCursor: string | null
}

/** Select the bound DSH instance that will own the new isolated branch. */
export interface RegistryImportRequest {
  readonly targetInstanceId: string
  readonly idempotencyKey: string
}

export type RegistryImportTransport = 'connected' | 'not-observed'

/** One provider-confirmed target binding; the browser never invents reachability. */
export interface RegistryImportTarget {
  readonly instanceId: string
  readonly transport: RegistryImportTransport
  readonly acceptingA2A: boolean | null
  readonly activeRequests: number | null
}

export interface RegistryImportTargetPage {
  readonly items: readonly RegistryImportTarget[]
}

export type RegistryImportStatus = 'queued' | 'completed' | 'failed'

/** Authoritative import receipt returned by the Registry Host. */
export interface RegistryImportResult {
  readonly operationId: string
  readonly status: RegistryImportStatus
  readonly sessionId?: string
  /** Provider-issued absolute address for the created target session. */
  readonly sessionUrl?: string
}

/** Pure-text question sent to the source DSH. */
export interface RegistryQuestionRequest {
  readonly question: string
  readonly idempotencyKey: string
}

export type RegistryQuestionStatus = 'queued' | 'delivered' | 'running' | 'completed' | 'failed' | 'cancelled' | 'expired'

/** Authoritative question receipt returned by the Registry Host. */
export interface RegistryQuestionResult {
  readonly requestId: string
  readonly status: RegistryQuestionStatus
  /** Immutable disclosure checkpoint selected when the question was enqueued. */
  readonly checkpointHash: string
  /** Present only for a completed request; it is rendered as inert plain text. */
  readonly reply?: string
}

/** Authorized request-list metadata; question/reply text and internal identities are never included. */
export interface RegistryA2aRequestMetadata {
  readonly requestId: string
  readonly disclosureId: string
  readonly sourceInstanceId: string
  readonly checkpointHash: string
  readonly status: RegistryQuestionStatus
  readonly expiresAt: number
  readonly updatedAt: number
}

export interface RegistryA2aRequestPage {
  readonly items: readonly RegistryA2aRequestMetadata[]
  readonly nextCursor: string | null
}

export interface RegistryApi {
  readStatus(signal: AbortSignal): Promise<RegistryRuntimeStatus>
  readDirectory(signal: AbortSignal): Promise<RegistryDirectoryPage>
  changeDirectory(expectedRevision: number, change: RegistryDirectoryChange,
    signal: AbortSignal): Promise<RegistryDirectoryChangeReceipt>
  listInstances(signal: AbortSignal): Promise<RegistryInstancePage>
  renameInstance(bindingId: string, instanceName: string, signal: AbortSignal): Promise<RegistryInstance>
  revokeInstance(bindingId: string, signal: AbortSignal): Promise<RegistryInstance>
  reviewBinding(bindingId: string, code: string, signal: AbortSignal): Promise<RegistryBindingReview>
  approveBinding(bindingId: string, code: string, instanceName: string, signal: AbortSignal): Promise<RegistryBindingReview>
  rejectBinding(bindingId: string, code: string, signal: AbortSignal): Promise<RegistryBindingReview>
  listAudit(request: RegistryListRequest, signal: AbortSignal): Promise<RegistryAuditPage>
  listBranches(request: RegistryListRequest, signal: AbortSignal): Promise<RegistryA2aRequestPage>
  listDisclosures(request: RegistryListRequest, signal: AbortSignal): Promise<RegistryDisclosurePage>
  readDisclosure(disclosureId: string, signal: AbortSignal): Promise<RegistryDisclosureDetail>
  readDisclosureContent(disclosureId: string, checkpointHash: string,
    signal: AbortSignal): Promise<RegistryDisclosureContent>
  listImportTargets(disclosureId: string, signal: AbortSignal): Promise<RegistryImportTargetPage>
  importDisclosure(disclosureId: string, request: RegistryImportRequest, signal: AbortSignal): Promise<RegistryImportResult>
  readImport(disclosureId: string, operationId: string, signal: AbortSignal): Promise<RegistryImportResult>
  askDisclosure(disclosureId: string, request: RegistryQuestionRequest, signal: AbortSignal): Promise<RegistryQuestionResult>
  readQuestion(disclosureId: string, requestId: string, signal: AbortSignal): Promise<RegistryQuestionResult>
  cancelQuestion(disclosureId: string, requestId: string, signal: AbortSignal): Promise<RegistryQuestionResult>
}

/** Content-free application failure; response bodies and server messages never reach components. */
export class RegistryApiError extends Error {
  constructor(readonly code: RegistryApiErrorCode) {
    super('Registry request failed')
    this.name = 'RegistryApiError'
  }
}

const API_BASE = '/registry-api/v1'
const ERROR_CODES: readonly RegistryApiErrorCode[] = [
  'identity-not-configured', 'registry-not-configured', 'unauthenticated', 'not-found',
  'invalid-input', 'conflict', 'operation-not-configured', 'method-not-allowed', 'rate-limited', 'unavailable',
]
const ACTIONS: readonly RegistryAuthorizedAction[] = ['read', 'import', 'ask']
const INSTANCE_PHASES: readonly RegistryInstancePhase[] = ['confirmed', 'revoked']
const BINDING_PHASES: readonly RegistryBindingPhase[] = ['pending', 'approved', 'confirmed', 'rejected', 'revoked']
const INSTANCE_SCOPES: readonly RegistryInstanceScope[] = ['disclosure.sync', 'a2a.receive']
const INSTANCE_TRANSPORTS: readonly RegistryInstanceTransport[] = ['connected', 'not-observed']
const INSTANCE_REPORT_STATES: readonly RegistryInstanceReportState[] = ['online', 'busy', 'paused', 'degraded']
const DIRECTORY_ROLES: readonly RegistryDirectoryRole[] = ['owner', 'admin', 'member']
const DIRECTORY_MEMBER_STATES: readonly RegistryDirectoryMemberState[] = ['active', 'suspended', 'removed']
const CONFIGURATION_STATES: readonly RegistryConfigurationState[] = ['configured', 'unconfigured']
const CONTROLS: readonly RegistryControlState[] = ['active', 'paused', 'revoked', 'expired', 'deleting', 'deleted']
const PRODUCERS: readonly RegistryProducerState[] = ['idle', 'backfilling', 'live', 'offline', 'error_retryable', 'error_conflict']
const INGESTS: readonly RegistryIngestState[] = ['pending', 'ready', 'frozen']
const IMPORT_STATUSES: readonly RegistryImportStatus[] = ['queued', 'completed', 'failed']
const IMPORT_TRANSPORTS: readonly RegistryImportTransport[] = ['connected', 'not-observed']
const QUESTION_STATUSES: readonly RegistryQuestionStatus[] = [
  'queued', 'delivered', 'running', 'completed', 'failed', 'cancelled', 'expired',
]
const CONTENT_EVENT_TYPES: readonly RegistryDisclosureContentEvent['type'][] = [
  'conversation.user-message', 'conversation.assistant-message',
  'conversation.tool-result-summary', 'conversation.title',
]
const TOOL_OUTCOMES = ['success', 'failure'] as const
const AUDIT_ACTOR_KINDS: readonly RegistryAuditActorKind[] = [
  'enrollment', 'producer', 'member', 'maintenance', 'unattributed',
]
const AUDIT_RESULTS: readonly RegistryAuditResult[] = ['pending', 'succeeded', 'rejected']
const AUDIT_ACTIONS: readonly RegistryAuditAction[] = [
  'register', 'status', 'event', 'checkpoint', 'read', 'metadata-read', 'metadata-list', 'access', 'control',
  'delete', 'directory-read', 'directory-change', 'binding-start', 'binding-approve', 'binding-confirm',
  'binding-review', 'binding-reject', 'binding-revoke', 'binding-rename', 'binding-list',
]
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const CHECKPOINT_HASH = /^sha256:[0-9a-f]{64}$/u

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null
}

function safeInteger(value: unknown, minimum: number): number | null {
  return Number.isSafeInteger(value) && (value as number) >= minimum && !Object.is(value, -0)
    ? value as number
    : null
}

function member<T extends string>(value: unknown, values: readonly T[]): T | null {
  return typeof value === 'string' && values.includes(value as T) ? value as T : null
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}

function safeText(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.isWellFormed() && !value.includes('\0')
    ? value
    : null
}

function actions(value: unknown): readonly RegistryAuthorizedAction[] | null {
  if (!Array.isArray(value)) return null
  const decoded: RegistryAuthorizedAction[] = []
  for (const item of value) {
    const action = member(item, ACTIONS)
    if (action === null) return null
    if (!decoded.includes(action)) decoded.push(action)
  }
  return decoded
}

function checkpoint(value: unknown): RegistryCheckpointMetadata | null {
  const source = record(value)
  if (source === null || typeof source.checkpointHash !== 'string' || source.checkpointHash.length === 0
    || !(source.lastEventHash === null || typeof source.lastEventHash === 'string')) return null
  const policyVersion = safeInteger(source.policyVersion, 1)
  const sourceCursor = safeInteger(source.sourceCursor, 0)
  const eventCount = safeInteger(source.eventCount, 0)
  const lastDisclosureSeq = safeInteger(source.lastDisclosureSeq, -1)
  if (policyVersion === null || sourceCursor === null || eventCount === null || lastDisclosureSeq === null) return null
  return {
    checkpointHash: source.checkpointHash,
    policyVersion,
    sourceCursor,
    eventCount,
    lastDisclosureSeq,
    lastEventHash: source.lastEventHash,
  }
}

function metadata(value: unknown): RegistryDisclosureMetadata {
  const source = record(value)
  if (source === null || typeof source.disclosureId !== 'string' || !IDENTIFIER.test(source.disclosureId)
    || typeof source.instanceId !== 'string' || !IDENTIFIER.test(source.instanceId)) throw new RegistryApiError('unavailable')
  const control = member(source.control, CONTROLS)
  const producer = member(source.producer, PRODUCERS)
  const ingest = member(source.ingest, INGESTS)
  const expiresAt = safeInteger(source.expiresAt, 0)
  const authorizationVersion = safeInteger(source.authorizationVersion, 0)
  const checkpointVerifiedAt = safeInteger(source.checkpointVerifiedAt, 0)
  const decodedCheckpoint = checkpoint(source.checkpoint)
  const decodedActions = actions(source.authorizedActions)
  if (control === null || producer === null || ingest === null || expiresAt === null
    || authorizationVersion === null || checkpointVerifiedAt === null
    || decodedCheckpoint === null || decodedActions === null) {
    throw new RegistryApiError('unavailable')
  }
  return {
    disclosureId: source.disclosureId,
    instanceId: source.instanceId,
    control,
    producer,
    ingest,
    expiresAt,
    authorizationVersion,
    checkpointVerifiedAt,
    checkpoint: decodedCheckpoint,
    authorizedActions: decodedActions,
  }
}

function page(value: unknown): RegistryDisclosurePage {
  const source = record(value)
  if (source === null || !Array.isArray(source.items)
    || !(source.nextCursor === null || typeof source.nextCursor === 'string')) throw new RegistryApiError('unavailable')
  return { items: source.items.map(metadata), nextCursor: source.nextCursor }
}

function contentEvent(value: unknown): RegistryDisclosureContentEvent {
  const source = record(value)
  const type = member(source?.type, CONTENT_EVENT_TYPES)
  const disclosureSeq = safeInteger(source?.disclosureSeq, 0)
  const occurredAt = safeInteger(source?.occurredAt, 0)
  if (source === null || type === null || disclosureSeq === null || occurredAt === null) {
    throw new RegistryApiError('unavailable')
  }
  if (type === 'conversation.title') {
    const title = safeText(source.title)
    if (!hasExactKeys(source, ['disclosureSeq', 'occurredAt', 'type', 'title']) || title === null) {
      throw new RegistryApiError('unavailable')
    }
    return { disclosureSeq, occurredAt, type, title }
  }
  const text = safeText(source.text)
  if (type === 'conversation.tool-result-summary') {
    const toolName = safeText(source.toolName)
    const outcome = member(source.outcome, TOOL_OUTCOMES)
    if (!hasExactKeys(source, ['disclosureSeq', 'occurredAt', 'type', 'toolName', 'outcome', 'text'])
      || toolName === null || outcome === null || text === null) throw new RegistryApiError('unavailable')
    return { disclosureSeq, occurredAt, type, toolName, outcome, text }
  }
  if (!hasExactKeys(source, ['disclosureSeq', 'occurredAt', 'type', 'text']) || text === null) {
    throw new RegistryApiError('unavailable')
  }
  return { disclosureSeq, occurredAt, type, text }
}

function disclosureContent(value: unknown, expectedCheckpointHash: string): RegistryDisclosureContent {
  const source = record(value)
  if (source === null || !hasExactKeys(source, ['checkpointHash', 'events'])
    || source.checkpointHash !== expectedCheckpointHash || !CHECKPOINT_HASH.test(expectedCheckpointHash)
    || !Array.isArray(source.events)) throw new RegistryApiError('unavailable')
  const events = source.events.map(contentEvent)
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index]
    if (event === undefined || event.disclosureSeq !== index) throw new RegistryApiError('unavailable')
  }
  return { checkpointHash: expectedCheckpointHash, events }
}

function optionalIdentifier(value: unknown): string | null {
  return value === null ? null : typeof value === 'string' && IDENTIFIER.test(value) ? value : null
}

function auditPage(value: unknown): RegistryAuditPage {
  const source = record(value)
  if (source === null || !Array.isArray(source.items)
    || !(source.nextCursor === null || typeof source.nextCursor === 'string' && IDENTIFIER.test(source.nextCursor))) {
    throw new RegistryApiError('unavailable')
  }
  const seen = new Set<string>()
  const items = source.items.map((value): RegistryAuditMetadata => {
    const item = record(value)
    const occurredAt = safeInteger(item?.occurredAt, 0)
    const actorKind = member(item?.actorKind, AUDIT_ACTOR_KINDS)
    const action = member(item?.action, AUDIT_ACTIONS)
    const result = member(item?.result, AUDIT_RESULTS)
    const actorId = optionalIdentifier(item?.actorId)
    const instanceId = optionalIdentifier(item?.instanceId)
    const objectId = optionalIdentifier(item?.objectId)
    if (item === null || typeof item.operationId !== 'string' || !IDENTIFIER.test(item.operationId)
      || seen.has(item.operationId) || occurredAt === null || actorKind === null || action === null || result === null
      || actorId === null && item.actorId !== null || instanceId === null && item.instanceId !== null
      || objectId === null && item.objectId !== null
      || ((actorKind === 'producer' || actorKind === 'enrollment') && (actorId === null || instanceId !== actorId))
      || (actorKind === 'member' && actorId === null)
      || ((actorKind === 'maintenance' || actorKind === 'unattributed') && actorId !== null)) {
      throw new RegistryApiError('unavailable')
    }
    seen.add(item.operationId)
    return { operationId: item.operationId, occurredAt, actorKind, actorId, instanceId, objectId, action, result }
  })
  return { items, nextCursor: source.nextCursor }
}

function instance(value: unknown): RegistryInstance {
  const item = record(value)
  const phase = member(item?.phase, INSTANCE_PHASES)
  const transport = member(item?.transport, INSTANCE_TRANSPORTS)
  const reportState = item?.reportState === null ? null : member(item?.reportState, INSTANCE_REPORT_STATES)
  const lastHeartbeatAt = item?.lastHeartbeatAt === null ? null : safeInteger(item?.lastHeartbeatAt, 0)
  const activeRequests = item?.activeRequests === null ? null : safeInteger(item?.activeRequests, 0)
  if (item === null || typeof item.bindingId !== 'string' || !IDENTIFIER.test(item.bindingId)
    || typeof item.instanceId !== 'string' || !IDENTIFIER.test(item.instanceId)
    || typeof item.instanceName !== 'string' || item.instanceName.length === 0
    || phase === null || transport === null || !Array.isArray(item.requestedScopes)
    || !(item.acceptingA2A === null || typeof item.acceptingA2A === 'boolean')
    || lastHeartbeatAt === null && item.lastHeartbeatAt !== null
    || reportState === null && item.reportState !== null
    || activeRequests === null && item.activeRequests !== null) throw new RegistryApiError('unavailable')
  const requestedScopes: RegistryInstanceScope[] = []
  for (const raw of item.requestedScopes) {
    const scope = member(raw, INSTANCE_SCOPES)
    if (scope === null) throw new RegistryApiError('unavailable')
    if (!requestedScopes.includes(scope)) requestedScopes.push(scope)
  }
  if (transport === 'not-observed' && (lastHeartbeatAt !== null || reportState !== null
    || item.acceptingA2A !== null || activeRequests !== null)) throw new RegistryApiError('unavailable')
  return {
    bindingId: item.bindingId,
    instanceId: item.instanceId,
    instanceName: item.instanceName,
    phase,
    requestedScopes,
    transport,
    lastHeartbeatAt,
    reportState,
    acceptingA2A: item.acceptingA2A,
    activeRequests,
  }
}

function instances(value: unknown): RegistryInstancePage {
  const source = record(value)
  if (source === null || !Array.isArray(source.items)) throw new RegistryApiError('unavailable')
  const seenBindings = new Set<string>()
  const seenInstances = new Set<string>()
  const items = source.items.map((value) => {
    const decoded = instance(value)
    if (seenBindings.has(decoded.bindingId) || seenInstances.has(decoded.instanceId)) {
      throw new RegistryApiError('unavailable')
    }
    seenBindings.add(decoded.bindingId)
    seenInstances.add(decoded.instanceId)
    return decoded
  })
  return { items }
}

function updatedInstance(value: unknown, expected: {
  readonly bindingId: string
  readonly instanceName?: string
  readonly phase?: RegistryInstancePhase
}): RegistryInstance {
  const decoded = instance(value)
  if (decoded.bindingId !== expected.bindingId
    || expected.instanceName !== undefined && decoded.instanceName !== expected.instanceName
    || expected.phase !== undefined && decoded.phase !== expected.phase) {
    throw new RegistryApiError('unavailable')
  }
  return decoded
}

function bindingReview(value: unknown, expected: {
  readonly bindingId: string
  readonly phase?: RegistryBindingPhase
}): RegistryBindingReview {
  const item = record(value)
  const phase = member(item?.phase, BINDING_PHASES)
  const createdAt = safeInteger(item?.createdAt, 0)
  const expiresAt = safeInteger(item?.expiresAt, 1)
  if (item === null || item.bindingId !== expected.bindingId
    || typeof item.instanceId !== 'string' || !IDENTIFIER.test(item.instanceId)
    || typeof item.keyId !== 'string' || !CHECKPOINT_HASH.test(item.keyId)
    || createdAt === null || expiresAt === null || expiresAt <= createdAt
    || phase === null || expected.phase !== undefined && phase !== expected.phase
    || !validDisplayName(item.instanceName) || !Array.isArray(item.requestedScopes)
    || item.requestedScopes.length === 0 || item.requestedScopes.length > INSTANCE_SCOPES.length) {
    throw new RegistryApiError('unavailable')
  }
  const requestedScopes: RegistryInstanceScope[] = []
  for (const raw of item.requestedScopes) {
    const scope = member(raw, INSTANCE_SCOPES)
    if (scope === null || requestedScopes.includes(scope)) throw new RegistryApiError('unavailable')
    requestedScopes.push(scope)
  }
  return {
    bindingId: expected.bindingId,
    instanceId: item.instanceId,
    keyId: item.keyId,
    createdAt,
    expiresAt,
    phase,
    instanceName: item.instanceName,
    requestedScopes,
  }
}

function validDisplayName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value === value.trim()
    && value.isWellFormed() && !/[\u0000-\u001f\u007f]/u.test(value)
}

function directory(value: unknown): RegistryDirectoryPage {
  const source = record(value)
  const revision = safeInteger(source?.revision, 0)
  const actorRole = member(source?.actorRole, DIRECTORY_ROLES)
  if (source === null || revision === null || actorRole === null
    || !Array.isArray(source.members) || !Array.isArray(source.teams)) {
    throw new RegistryApiError('unavailable')
  }
  const memberIds = new Set<string>()
  const members = source.members.map((value): RegistryDirectoryMember => {
    const item = record(value)
    const role = member(item?.role, DIRECTORY_ROLES)
    const state = member(item?.state, DIRECTORY_MEMBER_STATES)
    if (item === null || typeof item.memberId !== 'string' || !IDENTIFIER.test(item.memberId)
      || memberIds.has(item.memberId) || !validDisplayName(item.displayName) || role === null || state === null) {
      throw new RegistryApiError('unavailable')
    }
    memberIds.add(item.memberId)
    return { memberId: item.memberId, displayName: item.displayName, role, state }
  })
  const teamIds = new Set<string>()
  const teams = source.teams.map((value): RegistryDirectoryTeam => {
    const item = record(value)
    if (item === null || typeof item.teamId !== 'string' || !IDENTIFIER.test(item.teamId)
      || teamIds.has(item.teamId) || !validDisplayName(item.displayName) || !Array.isArray(item.memberIds)) {
      throw new RegistryApiError('unavailable')
    }
    const seenMembers = new Set<string>()
    const memberIdsForTeam = item.memberIds.map((memberId) => {
      if (typeof memberId !== 'string' || !IDENTIFIER.test(memberId) || !memberIds.has(memberId)
        || seenMembers.has(memberId)) throw new RegistryApiError('unavailable')
      seenMembers.add(memberId)
      return memberId
    })
    teamIds.add(item.teamId)
    return { teamId: item.teamId, displayName: item.displayName, memberIds: memberIdsForTeam }
  })
  return { revision, actorRole, members, teams }
}

function directoryReceipt(value: unknown): RegistryDirectoryChangeReceipt {
  const source = record(value)
  const revision = safeInteger(source?.revision, 0)
  const invalidatedDisclosures = safeInteger(source?.invalidatedDisclosures, 0)
  if (revision === null || invalidatedDisclosures === null) throw new RegistryApiError('unavailable')
  return { revision, invalidatedDisclosures }
}

function runtimeStatus(value: unknown): RegistryRuntimeStatus {
  const source = record(value)
  const deploymentMode = member(source?.deploymentMode, ['standard', 'test-only'] as const)
  const identity = member(source?.identity, CONFIGURATION_STATES)
  const identityProvider = member(source?.identityProvider, ['oidc', 'external', 'local-test', 'unconfigured'] as const)
  const registry = member(source?.registry, CONFIGURATION_STATES)
  const disclosureOperations = member(source?.disclosureOperations, CONFIGURATION_STATES)
  const deviceBinding = member(source?.deviceBinding, CONFIGURATION_STATES)
  const audit = member(source?.audit, CONFIGURATION_STATES)
  const rateLimits = member(source?.rateLimits, CONFIGURATION_STATES)
  const disclosureCleanup = member(source?.disclosureCleanup, CONFIGURATION_STATES)
  const mailboxCleanup = member(source?.mailboxCleanup, CONFIGURATION_STATES)
  const billing = member(source?.billing, CONFIGURATION_STATES)
  const billingProvider = member(source?.billingProvider, ['stripe', 'alipay', 'unconfigured'] as const)
  if (source === null || deploymentMode === null || identity === null || identityProvider === null
    || (identity === 'unconfigured' && identityProvider !== 'unconfigured')
    || (identity === 'configured' && identityProvider === 'unconfigured')
    || registry === null || disclosureOperations === null
    || deviceBinding === null || audit === null || rateLimits === null
    || disclosureCleanup === null || mailboxCleanup === null || billing === null || billingProvider === null
    || (billing === 'unconfigured' && billingProvider !== 'unconfigured')
    || (billing === 'configured' && billingProvider === 'unconfigured')) throw new RegistryApiError('unavailable')
  return { deploymentMode, identity, identityProvider, registry, disclosureOperations, deviceBinding, audit, rateLimits,
    disclosureCleanup, mailboxCleanup, billing, billingProvider }
}

function importResult(value: unknown): RegistryImportResult {
  const source = record(value)
  const status = member(source?.status, IMPORT_STATUSES)
  const sessionUrl = typeof source?.sessionUrl === 'string' ? absoluteHttpUrl(source.sessionUrl) : source?.sessionUrl
  if (source === null || typeof source.operationId !== 'string' || !IDENTIFIER.test(source.operationId)
    || status === null || !(source.sessionId === undefined
      || (typeof source.sessionId === 'string' && IDENTIFIER.test(source.sessionId)))
    || !(sessionUrl === undefined || typeof sessionUrl === 'string')
    || (status !== 'completed' && (source.sessionId !== undefined || source.sessionUrl !== undefined))) {
    throw new RegistryApiError('unavailable')
  }
  return {
    operationId: source.operationId,
    status,
    ...(source.sessionId === undefined ? {} : { sessionId: source.sessionId }),
    ...(sessionUrl === undefined ? {} : { sessionUrl }),
  }
}

function absoluteHttpUrl(value: string): string | null {
  if (value.length > 2048) return null
  let url: URL
  try { url = new URL(value) } catch { return null }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username !== '' || url.password !== '') return null
  return url.href
}

function importTargets(value: unknown): RegistryImportTargetPage {
  const source = record(value)
  if (source === null || !Array.isArray(source.items)) throw new RegistryApiError('unavailable')
  const seen = new Set<string>()
  const items = source.items.map((value): RegistryImportTarget => {
    const target = record(value)
    const transport = member(target?.transport, IMPORT_TRANSPORTS)
    const activeRequests = target?.activeRequests === null ? null : safeInteger(target?.activeRequests, 0)
    if (target === null || typeof target.instanceId !== 'string' || !IDENTIFIER.test(target.instanceId)
      || seen.has(target.instanceId) || transport === null
      || !(target.acceptingA2A === null || typeof target.acceptingA2A === 'boolean')
      || activeRequests === null && target.activeRequests !== null) throw new RegistryApiError('unavailable')
    seen.add(target.instanceId)
    return { instanceId: target.instanceId, transport, acceptingA2A: target.acceptingA2A, activeRequests }
  })
  return { items }
}

function questionResult(value: unknown): RegistryQuestionResult {
  const source = record(value)
  const status = member(source?.status, QUESTION_STATUSES)
  if (source === null || typeof source.requestId !== 'string' || !IDENTIFIER.test(source.requestId)
    || typeof source.checkpointHash !== 'string' || !CHECKPOINT_HASH.test(source.checkpointHash)
    || status === null || !(source.reply === undefined || typeof source.reply === 'string')
    || (source.reply !== undefined && (status !== 'completed' || !source.reply.isWellFormed() || source.reply.includes('\0')))) {
    throw new RegistryApiError('unavailable')
  }
  return {
    requestId: source.requestId,
    status,
    checkpointHash: source.checkpointHash,
    ...(source.reply === undefined ? {} : { reply: source.reply }),
  }
}

function branchPage(value: unknown): RegistryA2aRequestPage {
  const source = record(value)
  if (source === null || !Array.isArray(source.items)
    || !(source.nextCursor === null || typeof source.nextCursor === 'string' && IDENTIFIER.test(source.nextCursor))) {
    throw new RegistryApiError('unavailable')
  }
  const seen = new Set<string>()
  const items = source.items.map((value): RegistryA2aRequestMetadata => {
    const item = record(value)
    const status = member(item?.status, QUESTION_STATUSES)
    const expiresAt = safeInteger(item?.expiresAt, 0)
    const updatedAt = safeInteger(item?.updatedAt, 0)
    if (item === null || typeof item.requestId !== 'string' || !IDENTIFIER.test(item.requestId)
      || seen.has(item.requestId)
      || typeof item.disclosureId !== 'string' || !IDENTIFIER.test(item.disclosureId)
      || typeof item.sourceInstanceId !== 'string' || !IDENTIFIER.test(item.sourceInstanceId)
      || typeof item.checkpointHash !== 'string' || !CHECKPOINT_HASH.test(item.checkpointHash)
      || status === null || expiresAt === null || updatedAt === null) throw new RegistryApiError('unavailable')
    seen.add(item.requestId)
    return { requestId: item.requestId, disclosureId: item.disclosureId,
      sourceInstanceId: item.sourceInstanceId, checkpointHash: item.checkpointHash,
      status, expiresAt, updatedAt }
  })
  if (source.nextCursor !== null && source.nextCursor !== items.at(-1)?.requestId) {
    throw new RegistryApiError('unavailable')
  }
  return { items, nextCursor: source.nextCursor }
}

async function request<T>(path: string, init: RequestInit, decode: (value: unknown) => T): Promise<T> {
  let response: Response
  const headers = new Headers(init.headers)
  headers.set('accept', 'application/json')
  try {
    response = await globalThis.fetch(path, {
      ...init,
      cache: 'no-store',
      credentials: 'same-origin',
      headers,
    })
  } catch (error) {
    if (init.signal?.aborted === true) throw error
    throw new RegistryApiError('unavailable')
  }
  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new RegistryApiError('unavailable')
  }
  const envelope = record(body)
  if (envelope?.ok === false) {
    const failure = record(envelope.error)
    throw new RegistryApiError(member(failure?.code, ERROR_CODES) ?? 'unavailable')
  }
  if (!response.ok || envelope?.ok !== true || !Object.hasOwn(envelope, 'value')) {
    throw new RegistryApiError('unavailable')
  }
  return decode(envelope.value)
}

/** Create one stable adapter for the plugin lifetime; React receives only its narrow callbacks. */
export function createRegistryApi(): RegistryApi {
  return {
    readStatus: signal => request(`${API_BASE}/status`, { method: 'GET', signal }, runtimeStatus),
    readDirectory: signal => request(`${API_BASE}/directory`, { method: 'GET', signal }, directory),
    changeDirectory: (expectedRevision, change, signal) => request(
      `${API_BASE}/directory`,
      { method: 'POST', signal, headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ expectedRevision, change }) },
      directoryReceipt,
    ),
    listInstances: signal => request(`${API_BASE}/instances`, { method: 'GET', signal }, instances),
    renameInstance: (bindingId, instanceName, signal) => request(
      `${API_BASE}/instances/${encodeURIComponent(bindingId)}/rename`,
      { method: 'POST', signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ instanceName }) },
      value => updatedInstance(value, { bindingId, instanceName, phase: 'confirmed' }),
    ),
    revokeInstance: (bindingId, signal) => request(
      `${API_BASE}/instances/${encodeURIComponent(bindingId)}/revoke`,
      { method: 'POST', signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ confirmation: 'revoke' }) },
      value => updatedInstance(value, { bindingId, phase: 'revoked' }),
    ),
    reviewBinding: (bindingId, code, signal) => request(
      `${API_BASE}/bindings/${encodeURIComponent(bindingId)}/review`,
      { method: 'POST', signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code }) },
      value => bindingReview(value, { bindingId }),
    ),
    approveBinding: (bindingId, code, instanceName, signal) => request(
      `${API_BASE}/bindings/${encodeURIComponent(bindingId)}/approve`,
      { method: 'POST', signal, headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code, instanceName }) },
      value => bindingReview(value, { bindingId, phase: 'approved' }),
    ),
    rejectBinding: (bindingId, code, signal) => request(
      `${API_BASE}/bindings/${encodeURIComponent(bindingId)}/reject`,
      { method: 'POST', signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code }) },
      value => bindingReview(value, { bindingId, phase: 'rejected' }),
    ),
    listAudit: (input, signal) => {
      const query = input.cursor === undefined ? '' : `?cursor=${encodeURIComponent(input.cursor)}`
      return request(`${API_BASE}/audit${query}`, { method: 'GET', signal }, auditPage)
    },
    listBranches: (input, signal) => {
      const query = input.cursor === undefined ? '' : `?cursor=${encodeURIComponent(input.cursor)}`
      return request(`${API_BASE}/branches${query}`, { method: 'GET', signal }, branchPage)
    },
    listDisclosures: (input, signal) => {
      const query = input.cursor === undefined ? '' : `?cursor=${encodeURIComponent(input.cursor)}`
      return request(`${API_BASE}/disclosures${query}`, { method: 'GET', signal }, page)
    },
    readDisclosure: (disclosureId, signal) => request(
      `${API_BASE}/disclosures/${encodeURIComponent(disclosureId)}`,
      { method: 'GET', signal },
      metadata,
    ),
    readDisclosureContent: (disclosureId, checkpointHash, signal) => request(
      `${API_BASE}/disclosures/${encodeURIComponent(disclosureId)}/content?checkpoint=${encodeURIComponent(checkpointHash)}`,
      { method: 'GET', signal },
      value => disclosureContent(value, checkpointHash),
    ),
    listImportTargets: (disclosureId, signal) => request(
      `${API_BASE}/disclosures/${encodeURIComponent(disclosureId)}/import-targets`,
      { method: 'GET', signal },
      importTargets,
    ),
    importDisclosure: (disclosureId, input, signal) => request(
      `${API_BASE}/disclosures/${encodeURIComponent(disclosureId)}/import`,
      { method: 'POST', signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify(input) },
      importResult,
    ),
    readImport: (disclosureId, operationId, signal) => request(
      `${API_BASE}/disclosures/${encodeURIComponent(disclosureId)}/imports/${encodeURIComponent(operationId)}`,
      { method: 'GET', signal },
      importResult,
    ),
    askDisclosure: (disclosureId, input, signal) => request(
      `${API_BASE}/disclosures/${encodeURIComponent(disclosureId)}/questions`,
      { method: 'POST', signal, headers: { 'content-type': 'application/json' }, body: JSON.stringify(input) },
      questionResult,
    ),
    readQuestion: (disclosureId, requestId, signal) => request(
      `${API_BASE}/disclosures/${encodeURIComponent(disclosureId)}/questions/${encodeURIComponent(requestId)}`,
      { method: 'GET', signal },
      questionResult,
    ),
    cancelQuestion: (disclosureId, requestId, signal) => request(
      `${API_BASE}/disclosures/${encodeURIComponent(disclosureId)}/questions/${encodeURIComponent(requestId)}`,
      { method: 'DELETE', signal },
      questionResult,
    ),
  }
}
