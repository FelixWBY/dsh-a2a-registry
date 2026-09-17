/** Same-origin Registry metadata API; account identity remains deployment-provided. */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import { decodeRegistryChallenge, decodeRegistryProof } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { A2aRequestId, DisclosureSubject, MemberId, TeamId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { RegistryIngestError, type FreshRegistryDirectoryAuthority,
  type FreshRegistryMetadataAuthority, type FreshProducerAuthority,
  type RegistryBindingId, type RegistryBindingRequest, type RegistryBindingReview,
  type RegistryBindingScope, type RegistryDirectoryChange, type RegistryDisclosureMetadata } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type {} from '@deepseek-ai/dsh-host-webserver'
import type { RegistryAccountAuthenticator, RegistryAuthenticatedAccount,
  RegistryAuthenticatedIdentity } from './account-auth.ts'
import type { RegistryEnrollment } from './enrollment.ts'
import type { RegistryDisclosureImportInput, RegistryDisclosureOperations, RegistryDisclosureOperationSelection,
  RegistryDisclosureQuestionInput, RegistryImportOperationId } from './operations.ts'
import type { RegistryDisclosureReader } from './reader.ts'
import type { FreshRegistryAuditAuthority, RegistryAuditReader } from './audit-reader.ts'
import type { RegistryDisclosureControl } from './control.ts'
import type { RegistryDirectory } from './directory.ts'
import { RegistryBrowserAdmission, type RegistryBrowserAdmissionConfig,
  type RegistryBrowserAdmissionDecision } from './browser-admission.ts'
import type { RegistryOperationalRateLimitScope } from './operational-alerts.ts'
import type { RegistryBillingCheckout, RegistryBillingPlan } from './billing.ts'
import type { RegistryAccount, RegistryAccountId, RegistryOrganizationAccess } from './tenancy.ts'
import { RegistryTenancyError } from './tenancy.ts'
import type { RegistryTenantRuntime } from './ingest-runtime.ts'
import type { RegistryTenantRuntimeLease } from './tenant-runtime-router.ts'

const API_BASE = '/registry-api/v1'
const DISCLOSURES_PATH = `${API_BASE}/disclosures`
const BRANCHES_PATH = `${API_BASE}/branches`
const INSTANCES_PATH = `${API_BASE}/instances`
const BINDINGS_PATH = `${API_BASE}/bindings`
const DIRECTORY_PATH = `${API_BASE}/directory`
const AUDIT_PATH = `${API_BASE}/audit`
const STATUS_PATH = `${API_BASE}/status`
const ACCOUNT_PATH = `${API_BASE}/account`
const ORGANIZATIONS_PATH = `${API_BASE}/organizations`
const INVITATIONS_PATH = `${API_BASE}/invitations`
const BILLING_PATH = `${API_BASE}/billing`
const TEST_ONLY_REVOKE_PATH = `${API_BASE}/test-only/revoke-seed`
const TEST_ONLY_CONFIRM_HEADER = 'x-dsh-local-mvp-confirm'
const TEST_ONLY_CONFIRM_VALUE = 'revoke-seed'
const ACCOUNT_ADMISSION_ORGANIZATION = brandString<OrganizationId>('registry-account')
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
const INVITATION_TOKEN = /^[A-Za-z0-9_-]{43}$/u
const AUDIT_ACTORS = ['enrollment', 'producer', 'member', 'maintenance', 'unattributed'] as const
const AUDIT_RESULTS = ['pending', 'succeeded', 'rejected'] as const
const AUDIT_ACTIONS = ['register', 'status', 'event', 'checkpoint', 'read', 'metadata-read', 'metadata-list',
  'access', 'control', 'delete', 'directory-read', 'directory-change', 'binding-start', 'binding-approve',
  'binding-confirm', 'binding-review', 'binding-reject', 'binding-revoke', 'binding-rename', 'binding-list'] as const

/** Explicit bounds for browser metadata responses and opaque cursor input. */
export interface RegistryBrowserApiConfig {
  /** Fixed number of authorized rows requested from storage for each page. */
  pageSize: number
  /** Complete Registry metadata value bound before the small API envelope is added. */
  maxValueBytes: number
  /** Maximum UTF-8 bytes accepted for one opaque pagination cursor. */
  maxCursorBytes: number
  /** Maximum raw UTF-8 JSON bytes accepted by one import or question request. */
  maxOperationInputBytes: number
  /** Optional operation limits; top-level sharedAdmission can coordinate them across same-host processes. */
  admission?: RegistryBrowserAdmissionConfig
}

/** Runtime features that reached startup before the browser API is published. */
export interface RegistryBrowserApiRuntimeConfiguration {
  /** Explicit deployment class; `standard` says only that no test-only overlay was mounted. */
  readonly deploymentMode: 'standard' | 'test-only'
  /** Configured account-login mechanism; runtime status still reports unconfigured when its service is absent. */
  readonly identityProvider: 'oidc' | 'external' | 'local-test'
  /** The shared ingest owner started disclosure retirement scheduling. */
  readonly disclosureCleanup: boolean
  /** The mailbox owner started ciphertext expiry scheduling. */
  readonly mailboxCleanup: boolean
  /** Exact one-shot seed withdrawal enabled only by the explicit local MVP overlay. */
  readonly testOnlyRevoke?: {
    readonly mode: 'test-only'
    readonly disclosureId: DisclosureId
    readonly sourceInstanceId: DshInstanceId
    readonly sourceKeyId: InstanceKeyId
    readonly expectedAuthorizationVersion: number
  }
}

const UNCONFIGURED_RUNTIME: RegistryBrowserApiRuntimeConfiguration = {
  deploymentMode: 'standard',
  identityProvider: 'external',
  disclosureCleanup: false,
  mailboxCleanup: false,
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const admissionBucket = z.object({ capacity: positive(), refillPerSecond: positive(), maxEntries: positive() }).required()
const trustedProxy = z.object({
  cidrs: z.array(z.string().required()).required(),
  maxForwardedBytes: positive(),
  maxForwardedEntries: positive(),
}).required()
/** Loader schema for the optional browser API. */
export const Config: z<RegistryBrowserApiConfig> = z.object({
  pageSize: positive(), maxValueBytes: positive(), maxCursorBytes: positive(), maxOperationInputBytes: positive(),
  admission: z.union([z.object({ directPeer: admissionBucket, account: admissionBucket,
    trustedProxy: z.union([trustedProxy]) })]),
})

type ApiErrorCode = 'identity-not-configured' | 'registry-not-configured' | 'unauthenticated'
  | 'not-found' | 'invalid-input' | 'conflict' | 'unavailable' | 'operation-not-configured' | 'method-not-allowed' | 'rate-limited'

type TenantRoute = { readonly organizationId?: OrganizationId }

type TenantApiRoute = TenantRoute & (
  | { readonly kind: 'instances' }
  | { readonly kind: 'instance-action'; readonly bindingId: RegistryBindingId; readonly action: 'rename' | 'revoke' }
  | { readonly kind: 'binding-start' }
  | { readonly kind: 'binding-confirm'; readonly bindingId: RegistryBindingId }
  | {
    readonly kind: 'binding-account-action'
    readonly bindingId: RegistryBindingId
    readonly action: 'review' | 'approve' | 'reject'
  }
  | { readonly kind: 'directory' }
  | { readonly kind: 'invitations' }
  | { readonly kind: 'invitation-revoke'; readonly invitationId: string }
  | { readonly kind: 'billing-plans' }
  | { readonly kind: 'billing-checkout' }
  | { readonly kind: 'audit'; readonly cursor?: string }
  | { readonly kind: 'branches'; readonly cursor?: string }
  | { readonly kind: 'list'; readonly cursor?: string }
  | { readonly kind: 'detail'; readonly disclosureId: DisclosureId }
  | { readonly kind: 'content'; readonly disclosureId: DisclosureId; readonly checkpointHash: DisclosureHash }
  | { readonly kind: 'operation'; readonly disclosureId: DisclosureId; readonly action: 'import' | 'ask' }
  | { readonly kind: 'import-targets'; readonly disclosureId: DisclosureId }
  | { readonly kind: 'import-status'; readonly disclosureId: DisclosureId; readonly operationId: RegistryImportOperationId }
  | { readonly kind: 'question'; readonly disclosureId: DisclosureId; readonly requestId: A2aRequestId })

type ApiRoute =
  | { readonly kind: 'status' }
  | { readonly kind: 'account' }
  | { readonly kind: 'organization-create' }
  | { readonly kind: 'invitation-preview' | 'invitation-accept' | 'invitation-decline' }
  | { readonly kind: 'test-only-revoke' }
  | TenantApiRoute

type OperationInput =
  | { readonly action: 'import'; readonly value: RegistryDisclosureImportInput }
  | { readonly action: 'ask'; readonly value: RegistryDisclosureQuestionInput }

type InstanceActionInput =
  | { readonly action: 'rename'; readonly instanceName: string }
  | { readonly action: 'revoke' }

type BindingInput =
  | { readonly action: 'start'; readonly value: RegistryBindingRequest }
  | { readonly action: 'confirm'; readonly proof: string }
  | { readonly action: 'review' | 'reject'; readonly code: string }
  | { readonly action: 'approve'; readonly code: string; readonly instanceName: string }

type DirectoryInput = { readonly expectedRevision: number; readonly change: RegistryDirectoryChange }
type BillingInput = { readonly planId: string; readonly idempotencyKey: string; readonly returnPath: string }
type OrganizationInput = { readonly displayName: string; readonly idempotencyKey: string }
type InvitationInput = { readonly role: 'admin' | 'member'; readonly displayName?: string; readonly expiresInSeconds?: number }
type InvitationTokenInput = { readonly token: string }

class ApiFailure extends Error {
  constructor(readonly status: number, readonly code: ApiErrorCode, readonly allow?: string,
    readonly retryAfterSeconds?: number) {
    super(code)
    this.name = 'RegistryApiFailure'
  }
}

function writeJson(res: ServerResponse, status: number, value: unknown, extraHeaders: Record<string, string> = {}): void {
  const body = JSON.stringify(value)
  res.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body, 'utf8')),
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  })
  res.end(body)
}

function succeed(res: ServerResponse, value: unknown): void {
  writeJson(res, 200, { ok: true, value })
}

function fail(res: ServerResponse, failure: ApiFailure): void {
  const headers: Record<string, string> = {}
  if (failure.allow !== undefined) headers.allow = failure.allow
  if (failure.retryAfterSeconds !== undefined) headers['retry-after'] = String(failure.retryAfterSeconds)
  writeJson(res, failure.status, { ok: false, error: { code: failure.code } }, headers)
}

function requireAdmission(ctx: Context, decision: RegistryBrowserAdmissionDecision,
  scope: RegistryOperationalRateLimitScope): void {
  if (decision.admitted) return
  try { ctx.get('registryOperationalAlertReporter', false)?.reportRateLimit(scope) } catch {
    // Alert export is observational and cannot alter the stable admission result.
  }
  throw new ApiFailure(429, 'rate-limited', undefined, decision.retryAfterSeconds)
}

function requireOperationActive(signal: AbortSignal): void {
  if (signal.aborted) throw new RegistryIngestError('not-found')
}

function disclosureId(value: string): DisclosureId {
  let decoded: string
  try { decoded = decodeURIComponent(value) } catch { throw new ApiFailure(400, 'invalid-input') }
  if (!IDENTIFIER.test(decoded)) throw new ApiFailure(400, 'invalid-input')
  return brandString<DisclosureId>(decoded)
}

function bindingId(value: string): RegistryBindingId {
  let decoded: string
  try { decoded = decodeURIComponent(value) } catch { throw new ApiFailure(400, 'invalid-input') }
  if (!IDENTIFIER.test(decoded)) throw new ApiFailure(400, 'invalid-input')
  return brandString<RegistryBindingId>(decoded)
}

function invitationId(value: string): string {
  let decoded: string
  try { decoded = decodeURIComponent(value) } catch { throw new ApiFailure(404, 'not-found') }
  if (!UUID.test(decoded)) throw new ApiFailure(404, 'not-found')
  return decoded
}

function requestId(value: string): A2aRequestId {
  let decoded: string
  try { decoded = decodeURIComponent(value) } catch { throw new ApiFailure(400, 'invalid-input') }
  if (!IDENTIFIER.test(decoded)) throw new ApiFailure(400, 'invalid-input')
  return brandString<A2aRequestId>(decoded)
}

function operationId(value: string): RegistryImportOperationId {
  let decoded: string
  try { decoded = decodeURIComponent(value) } catch { throw new ApiFailure(400, 'invalid-input') }
  if (!IDENTIFIER.test(decoded)) throw new ApiFailure(400, 'invalid-input')
  return brandString<RegistryImportOperationId>(decoded)
}

function noQuery(url: URL): void {
  if ([...url.searchParams].length !== 0) throw new ApiFailure(400, 'invalid-input')
}

function isJsonContentType(value: string | undefined): boolean {
  if (value === undefined) return false
  const parts = value.split(';').map(part => part.trim())
  const [mediaType, parameter, ...extra] = parts
  if (mediaType?.toLowerCase() !== 'application/json') return false
  if (parameter === undefined) return true
  return extra.length === 0 && /^charset=(?:utf-8|"utf-8")$/iu.test(parameter)
}

function declaredLength(request: IncomingMessage): number | undefined {
  const value = request.headers['content-length']
  if (value === undefined) return undefined
  if (!/^(0|[1-9]\d*)$/u.test(value)) throw new ApiFailure(400, 'invalid-input')
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed)) throw new ApiFailure(400, 'invalid-input')
  return parsed
}

async function readJson(request: IncomingMessage, maxBytes: number, signal: AbortSignal): Promise<unknown> {
  if (!isJsonContentType(request.headers['content-type'])) {
    request.resume()
    throw new ApiFailure(400, 'invalid-input')
  }
  const declared = declaredLength(request)
  if (declared !== undefined && declared > maxBytes) {
    request.resume()
    throw new ApiFailure(400, 'invalid-input')
  }
  const chunks: Buffer[] = []
  let size = 0
  const stop = (): void => { request.destroy() }
  signal.addEventListener('abort', stop, { once: true })
  try {
    for await (const raw of request) {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as string)
      size += chunk.byteLength
      if (size > maxBytes) {
        request.resume()
        throw new ApiFailure(400, 'invalid-input')
      }
      chunks.push(chunk)
    }
  } catch (error) {
    if (error instanceof ApiFailure) throw error
    throw new ApiFailure(400, 'invalid-input')
  } finally {
    signal.removeEventListener('abort', stop)
  }
  if (!request.complete || signal.aborted || size === 0) throw new ApiFailure(400, 'invalid-input')
  let text: string
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size)) } catch {
    throw new ApiFailure(400, 'invalid-input')
  }
  try { return JSON.parse(text) as unknown } catch {
    throw new ApiFailure(400, 'invalid-input')
  }
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ApiFailure(400, 'invalid-input')
  const record = value as Record<string, unknown>
  const actual = Object.keys(record)
  if (actual.length !== keys.length || actual.some(key => !keys.includes(key))) {
    throw new ApiFailure(400, 'invalid-input')
  }
  return record
}

function idempotencyKey(value: unknown): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) throw new ApiFailure(400, 'invalid-input')
  return value
}

function operationRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiFailure(503, 'unavailable')
  }
  return value as Record<string, unknown>
}

function providerExactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  const record = operationRecord(value)
  const keys = Object.keys(record)
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) {
    throw new ApiFailure(503, 'unavailable')
  }
  return record
}

function importOperationResult(value: unknown): Record<string, unknown> {
  const record = operationRecord(value)
  if (typeof record.operationId !== 'string' || !IDENTIFIER.test(record.operationId)
    || (record.status !== 'queued' && record.status !== 'completed' && record.status !== 'failed')
    || !(record.sessionId === undefined
      || (typeof record.sessionId === 'string' && IDENTIFIER.test(record.sessionId)))) {
    throw new ApiFailure(503, 'unavailable')
  }
  let sessionUrl: string | undefined
  if (record.sessionUrl !== undefined) {
    if (typeof record.sessionUrl !== 'string' || record.sessionUrl.length > 2048) {
      throw new ApiFailure(503, 'unavailable')
    }
    try {
      const parsed = new URL(record.sessionUrl)
      if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:')
        || parsed.username !== '' || parsed.password !== '') throw new ApiFailure(503, 'unavailable')
    } catch (error) {
      if (error instanceof ApiFailure) throw error
      throw new ApiFailure(503, 'unavailable')
    }
    sessionUrl = record.sessionUrl
  }
  if (record.status !== 'completed' && (record.sessionId !== undefined || sessionUrl !== undefined)) {
    throw new ApiFailure(503, 'unavailable')
  }
  return {
    operationId: record.operationId,
    status: record.status,
    ...(record.sessionId === undefined ? {} : { sessionId: record.sessionId }),
    ...(sessionUrl === undefined ? {} : { sessionUrl }),
  }
}

function importTargetsResult(value: unknown, maxItems: number): Record<string, unknown> {
  if (!Array.isArray(value) || value.length > maxItems) throw new ApiFailure(503, 'unavailable')
  const instanceIds = new Set<string>()
  const items = value.map((item) => {
    const record = operationRecord(item)
    if (typeof record.instanceId !== 'string' || !IDENTIFIER.test(record.instanceId)
      || (record.transport !== 'connected' && record.transport !== 'not-observed')
      || !(record.acceptingA2A === null || typeof record.acceptingA2A === 'boolean')
      || !(record.activeRequests === null || (Number.isSafeInteger(record.activeRequests)
        && (record.activeRequests as number) >= 0 && !Object.is(record.activeRequests, -0)))
      || instanceIds.has(record.instanceId)) {
      throw new ApiFailure(503, 'unavailable')
    }
    instanceIds.add(record.instanceId)
    return { instanceId: record.instanceId, transport: record.transport,
      acceptingA2A: record.acceptingA2A, activeRequests: record.activeRequests }
  })
  return { items }
}

function requestedScopes(value: unknown): readonly ('disclosure.sync' | 'a2a.receive')[] {
  if (!Array.isArray(value) || value.length === 0) throw new ApiFailure(503, 'unavailable')
  const scopes: ('disclosure.sync' | 'a2a.receive')[] = []
  for (const candidate of value as readonly unknown[]) {
    if (candidate !== 'disclosure.sync' && candidate !== 'a2a.receive') throw new ApiFailure(503, 'unavailable')
    const scope: 'disclosure.sync' | 'a2a.receive' = candidate
    if (!scopes.includes(scope)) scopes.push(scope)
  }
  return scopes
}

const BINDING_PHASES = ['pending', 'approved', 'confirmed', 'rejected', 'revoked'] as const

function bindingReviewResult(value: unknown, expected: {
  readonly bindingId: RegistryBindingId
  readonly organizationId: string
}, maxValueBytes: number): Omit<RegistryBindingReview, 'organizationId'> {
  const record = operationRecord(value)
  const createdAt = record.createdAt
  const expiresAt = record.expiresAt
  if (record.bindingId !== expected.bindingId || record.organizationId !== expected.organizationId
    || typeof record.instanceId !== 'string' || !IDENTIFIER.test(record.instanceId)
    || typeof record.keyId !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(record.keyId)
    || !Number.isSafeInteger(createdAt) || (createdAt as number) < 0 || Object.is(createdAt, -0)
    || !Number.isSafeInteger(expiresAt) || (expiresAt as number) <= (createdAt as number)
    || typeof record.phase !== 'string' || !(BINDING_PHASES as readonly string[]).includes(record.phase)
    || typeof record.instanceName !== 'string' || record.instanceName.length === 0
    || record.instanceName !== record.instanceName.trim() || !record.instanceName.isWellFormed()
    || /[\u0000-\u001f\u007f]/u.test(record.instanceName)) {
    throw new ApiFailure(503, 'unavailable')
  }
  const result = {
    bindingId: expected.bindingId,
    instanceId: brandString<DshInstanceId>(record.instanceId),
    keyId: brandString<InstanceKeyId>(record.keyId),
    createdAt: createdAt as number,
    expiresAt: expiresAt as number,
    phase: record.phase as RegistryBindingReview['phase'],
    instanceName: record.instanceName,
    requestedScopes: requestedScopes(record.requestedScopes) as readonly RegistryBindingScope[],
  }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) {
    throw new ApiFailure(503, 'unavailable')
  }
  return result
}

function bindingTicketResult(value: unknown, maxValueBytes: number): Record<string, unknown> {
  const record = operationRecord(value)
  if (typeof record.bindingId !== 'string' || !IDENTIFIER.test(record.bindingId)
    || typeof record.code !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(record.code)) {
    throw new ApiFailure(503, 'unavailable')
  }
  let challenge: ReturnType<typeof decodeRegistryChallenge>
  try { challenge = decodeRegistryChallenge(record.challenge) } catch {
    throw new ApiFailure(503, 'unavailable')
  }
  const result = { bindingId: record.bindingId, code: record.code, challenge: {
    version: challenge.version, audience: challenge.audience, organizationId: challenge.organizationId,
    instanceId: challenge.instanceId, keyId: challenge.keyId, nonce: challenge.nonce, expiresAt: challenge.expiresAt,
  } }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) {
    throw new ApiFailure(503, 'unavailable')
  }
  return result
}

function bindingReceiptResult(value: unknown, expected: {
  readonly bindingId: RegistryBindingId
  readonly phase: 'approved' | 'confirmed' | 'rejected'
}): Record<string, unknown> {
  const record = operationRecord(value)
  const state = operationRecord(record.state)
  if (record.bindingId !== expected.bindingId || state.kind !== expected.phase) {
    throw new ApiFailure(503, 'unavailable')
  }
  return { bindingId: expected.bindingId, phase: expected.phase }
}

function nonnegativeIntegerOrNull(value: unknown): value is number | null {
  return value === null || (Number.isSafeInteger(value) && (value as number) >= 0 && !Object.is(value, -0))
}

function instanceResult(value: unknown): Record<string, unknown> {
  const record = operationRecord(value)
  if (typeof record.bindingId !== 'string' || !IDENTIFIER.test(record.bindingId)
    || typeof record.instanceId !== 'string' || !IDENTIFIER.test(record.instanceId)
    || typeof record.instanceName !== 'string' || !record.instanceName.isWellFormed()
    || record.instanceName.length === 0 || record.instanceName !== record.instanceName.trim()
    || /[\u0000-\u001f\u007f]/u.test(record.instanceName)
    || (record.phase !== 'confirmed' && record.phase !== 'revoked')) {
    throw new ApiFailure(503, 'unavailable')
  }
  const scopes = requestedScopes(record.requestedScopes)
  const observation = operationRecord(record.transport)
  let transport: 'connected' | 'not-observed'
  let lastHeartbeatAt: number | null = null
  let reportState: 'online' | 'busy' | 'paused' | 'degraded' | null = null
  let acceptingA2A: boolean | null = null
  let activeRequests: number | null = null
  if (observation.kind === 'not-observed') {
    if (observation.lastHeartbeatAt !== undefined || observation.report !== undefined) {
      throw new ApiFailure(503, 'unavailable')
    }
    transport = 'not-observed'
  } else if (observation.kind === 'connected') {
    if (!nonnegativeIntegerOrNull(observation.lastHeartbeatAt)) throw new ApiFailure(503, 'unavailable')
    transport = 'connected'
    lastHeartbeatAt = observation.lastHeartbeatAt
    if (observation.report !== undefined) {
      const report = operationRecord(observation.report)
      if (report.state !== 'online' && report.state !== 'busy' && report.state !== 'paused'
        && report.state !== 'degraded') throw new ApiFailure(503, 'unavailable')
      if (typeof report.acceptingA2A !== 'boolean' || !nonnegativeIntegerOrNull(report.activeRequests)
        || report.activeRequests === null) throw new ApiFailure(503, 'unavailable')
      reportState = report.state
      acceptingA2A = report.acceptingA2A
      activeRequests = report.activeRequests
    }
  } else {
    throw new ApiFailure(503, 'unavailable')
  }
  return {
    bindingId: record.bindingId, instanceId: record.instanceId, instanceName: record.instanceName,
    phase: record.phase, requestedScopes: scopes, transport, lastHeartbeatAt, reportState, acceptingA2A, activeRequests,
  }
}

function instancesResult(value: unknown, maxValueBytes: number): Record<string, unknown> {
  if (!Array.isArray(value)) throw new ApiFailure(503, 'unavailable')
  const items = value.map(instanceResult)
  if (Buffer.byteLength(JSON.stringify(items), 'utf8') > maxValueBytes) throw new ApiFailure(503, 'unavailable')
  return { items }
}

function updatedInstanceResult(value: unknown, expected: {
  readonly bindingId: RegistryBindingId
  readonly action: InstanceActionInput
}, maxValueBytes: number): Record<string, unknown> {
  const result = instanceResult(value)
  if (result.bindingId !== expected.bindingId
    || expected.action.action === 'rename'
      && (result.phase !== 'confirmed' || result.instanceName !== expected.action.instanceName)
    || expected.action.action === 'revoke' && result.phase !== 'revoked'
    || Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) {
    throw new ApiFailure(503, 'unavailable')
  }
  return result
}

function directoryResult(value: unknown, actorRole: DisclosureSubject['role'], maxValueBytes: number): Record<string, unknown> {
  const source = operationRecord(value)
  if (!Number.isSafeInteger(source.revision) || (source.revision as number) < 0
    || Object.is(source.revision, -0) || !Array.isArray(source.members) || !Array.isArray(source.teams)) {
    throw new ApiFailure(503, 'unavailable')
  }
  const memberIds = new Set<string>()
  const validName = (candidate: unknown): candidate is string => typeof candidate === 'string'
    && candidate.length > 0 && candidate === candidate.trim() && candidate.isWellFormed()
    && !/[\u0000-\u001f\u007f]/u.test(candidate)
  const members = source.members.map((value) => {
    const item = operationRecord(value)
    if (typeof item.memberId !== 'string' || !IDENTIFIER.test(item.memberId) || memberIds.has(item.memberId)
      || !validName(item.displayName) || (item.role !== 'owner' && item.role !== 'admin' && item.role !== 'member')
      || (item.state !== 'active' && item.state !== 'suspended' && item.state !== 'removed')) {
      throw new ApiFailure(503, 'unavailable')
    }
    memberIds.add(item.memberId)
    return { memberId: item.memberId, displayName: item.displayName, role: item.role, state: item.state }
  })
  const teamIds = new Set<string>()
  const teams = source.teams.map((value) => {
    const item = operationRecord(value)
    if (typeof item.teamId !== 'string' || !IDENTIFIER.test(item.teamId) || teamIds.has(item.teamId)
      || !validName(item.displayName) || !Array.isArray(item.memberIds)) {
      throw new ApiFailure(503, 'unavailable')
    }
    const teamMemberIds = new Set<string>()
    const ids = item.memberIds.map((memberId) => {
      if (typeof memberId !== 'string' || !IDENTIFIER.test(memberId) || !memberIds.has(memberId)
        || teamMemberIds.has(memberId)) throw new ApiFailure(503, 'unavailable')
      teamMemberIds.add(memberId)
      return memberId
    })
    teamIds.add(item.teamId)
    return { teamId: item.teamId, displayName: item.displayName, memberIds: ids }
  })
  const result = { revision: source.revision as number, actorRole, members, teams }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) throw new ApiFailure(503, 'unavailable')
  return result
}

function billingPlansResult(value: readonly RegistryBillingPlan[], maxValueBytes: number): Record<string, unknown> {
  if (!Array.isArray(value) || value.length > 32) throw new ApiFailure(503, 'unavailable')
  const planIds = new Set<string>()
  const items = value.map((item) => {
    if (typeof item.planId !== 'string' || !IDENTIFIER.test(item.planId) || planIds.has(item.planId)
      || typeof item.displayName !== 'string' || item.displayName.length === 0 || item.displayName !== item.displayName.trim()
      || !item.displayName.isWellFormed() || /[\u0000-\u001f\u007f]/u.test(item.displayName)
      || typeof item.currency !== 'string' || !/^[A-Z]{3}$/u.test(item.currency)
      || !Number.isSafeInteger(item.unitAmount) || item.unitAmount < 0 || Object.is(item.unitAmount, -0)
      || (item.interval !== 'month' && item.interval !== 'year')) throw new ApiFailure(503, 'unavailable')
    planIds.add(item.planId)
    return { planId: item.planId, displayName: item.displayName, currency: item.currency,
      unitAmount: item.unitAmount, interval: item.interval }
  })
  const result = { items }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) throw new ApiFailure(503, 'unavailable')
  return result
}

function billingCheckoutResult(value: RegistryBillingCheckout, maxValueBytes: number): Record<string, unknown> {
  if (typeof value.checkoutId !== 'string' || !IDENTIFIER.test(value.checkoutId)
    || typeof value.checkoutUrl !== 'string' || value.checkoutUrl.length > 2048
    || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now() || Object.is(value.expiresAt, -0)) {
    throw new ApiFailure(503, 'unavailable')
  }
  let checkoutUrl: URL
  try { checkoutUrl = new URL(value.checkoutUrl) } catch { throw new ApiFailure(503, 'unavailable') }
  if (checkoutUrl.protocol !== 'https:' || checkoutUrl.username !== '' || checkoutUrl.password !== '') {
    throw new ApiFailure(503, 'unavailable')
  }
  const result = { checkoutId: value.checkoutId, checkoutUrl: checkoutUrl.href, expiresAt: value.expiresAt }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) throw new ApiFailure(503, 'unavailable')
  return result
}

function auditResult(value: unknown, maxItems: number, maxValueBytes: number): Record<string, unknown> {
  const page = operationRecord(value)
  if (!Array.isArray(page.items) || page.items.length > maxItems
    || !(page.nextCursor === null || typeof page.nextCursor === 'string' && IDENTIFIER.test(page.nextCursor))) {
    throw new ApiFailure(503, 'unavailable')
  }
  const operationIds = new Set<string>()
  const items = page.items.map((value) => {
    const item = operationRecord(value)
    const nullableId = (candidate: unknown): candidate is string | null => candidate === null
      || typeof candidate === 'string' && IDENTIFIER.test(candidate)
    if (typeof item.operationId !== 'string' || !IDENTIFIER.test(item.operationId) || operationIds.has(item.operationId)
      || !Number.isSafeInteger(item.occurredAt) || (item.occurredAt as number) < 0 || Object.is(item.occurredAt, -0)
      || typeof item.actorKind !== 'string' || !(AUDIT_ACTORS as readonly string[]).includes(item.actorKind)
      || !nullableId(item.actorId) || !nullableId(item.instanceId) || !nullableId(item.objectId)
      || typeof item.action !== 'string' || !(AUDIT_ACTIONS as readonly string[]).includes(item.action)
      || typeof item.result !== 'string' || !(AUDIT_RESULTS as readonly string[]).includes(item.result)
      || ((item.actorKind === 'producer' || item.actorKind === 'enrollment')
        && (item.actorId === null || item.instanceId !== item.actorId))
      || (item.actorKind === 'member' && item.actorId === null)
      || ((item.actorKind === 'maintenance' || item.actorKind === 'unattributed') && item.actorId !== null)) {
      throw new ApiFailure(503, 'unavailable')
    }
    operationIds.add(item.operationId)
    return { operationId: item.operationId, occurredAt: item.occurredAt, actorKind: item.actorKind,
      actorId: item.actorId, instanceId: item.instanceId, objectId: item.objectId,
      action: item.action, result: item.result }
  })
  const result = { items, nextCursor: page.nextCursor }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) throw new ApiFailure(503, 'unavailable')
  return result
}

function questionOperationResult(value: unknown, maxReplyBytes: number): Record<string, unknown> {
  const record = operationRecord(value)
  if (typeof record.requestId !== 'string' || !IDENTIFIER.test(record.requestId)
    || typeof record.checkpointHash !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(record.checkpointHash)
    || typeof record.status !== 'string'
    || !['queued', 'delivered', 'running', 'completed', 'failed', 'cancelled', 'expired'].includes(record.status)) {
    throw new ApiFailure(503, 'unavailable')
  }
  const reply = record.reply
  if (reply !== undefined && (record.status !== 'completed' || typeof reply !== 'string'
    || !reply.isWellFormed() || reply.includes('\0') || Buffer.byteLength(reply, 'utf8') > maxReplyBytes)) {
    throw new ApiFailure(503, 'unavailable')
  }
  return {
    requestId: record.requestId,
    checkpointHash: record.checkpointHash,
    status: record.status,
    ...(reply === undefined ? {} : { reply }),
  }
}

function questionListResult(value: unknown, maxItems: number, maxValueBytes: number): Record<string, unknown> {
  const page = operationRecord(value)
  if (!Array.isArray(page.items) || page.items.length > maxItems
    || !(page.nextCursor === null || typeof page.nextCursor === 'string' && IDENTIFIER.test(page.nextCursor))) {
    throw new ApiFailure(503, 'unavailable')
  }
  const requestIds = new Set<string>()
  const items = page.items.map((value) => {
    const item = operationRecord(value)
    if (typeof item.requestId !== 'string' || !IDENTIFIER.test(item.requestId) || requestIds.has(item.requestId)
      || typeof item.disclosureId !== 'string' || !IDENTIFIER.test(item.disclosureId)
      || typeof item.sourceInstanceId !== 'string' || !IDENTIFIER.test(item.sourceInstanceId)
      || typeof item.checkpointHash !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(item.checkpointHash)
      || typeof item.status !== 'string'
      || !['queued', 'delivered', 'running', 'completed', 'failed', 'cancelled', 'expired'].includes(item.status)
      || !Number.isSafeInteger(item.expiresAt) || (item.expiresAt as number) < 0 || Object.is(item.expiresAt, -0)
      || !Number.isSafeInteger(item.updatedAt) || (item.updatedAt as number) < 0 || Object.is(item.updatedAt, -0)) {
      throw new ApiFailure(503, 'unavailable')
    }
    requestIds.add(item.requestId)
    return {
      requestId: item.requestId,
      disclosureId: item.disclosureId,
      sourceInstanceId: item.sourceInstanceId,
      checkpointHash: item.checkpointHash,
      status: item.status,
      expiresAt: item.expiresAt,
      updatedAt: item.updatedAt,
    }
  })
  if (page.nextCursor !== null && page.nextCursor !== items.at(-1)?.requestId) {
    throw new ApiFailure(503, 'unavailable')
  }
  const result = { items, nextCursor: page.nextCursor }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) throw new ApiFailure(503, 'unavailable')
  return result
}

function contentResult(value: unknown, expectedCheckpointHash: DisclosureHash,
  maxValueBytes: number): Record<string, unknown> {
  const content = providerExactRecord(value, ['checkpointHash', 'events'])
  if (content.checkpointHash !== expectedCheckpointHash || !Array.isArray(content.events)) {
    throw new ApiFailure(503, 'unavailable')
  }
  const events = content.events.map((value, index) => {
    const row = operationRecord(value)
    const common = typeof row.type === 'string' && Number.isSafeInteger(row.disclosureSeq)
      && row.disclosureSeq === index && Number.isSafeInteger(row.occurredAt)
      && (row.occurredAt as number) >= 0 && !Object.is(row.occurredAt, -0)
    if (!common) throw new ApiFailure(503, 'unavailable')
    if (row.type === 'conversation.user-message' || row.type === 'conversation.assistant-message') {
      providerExactRecord(row, ['disclosureSeq', 'occurredAt', 'type', 'text'])
      if (typeof row.text !== 'string' || !row.text.isWellFormed() || row.text.includes('\0')) {
        throw new ApiFailure(503, 'unavailable')
      }
      return { disclosureSeq: row.disclosureSeq, occurredAt: row.occurredAt, type: row.type, text: row.text }
    }
    if (row.type === 'conversation.tool-result-summary') {
      providerExactRecord(row, ['disclosureSeq', 'occurredAt', 'type', 'toolName', 'outcome', 'text'])
      if (typeof row.toolName !== 'string' || !row.toolName.isWellFormed() || row.toolName.includes('\0')
        || (row.outcome !== 'success' && row.outcome !== 'failure')
        || typeof row.text !== 'string' || !row.text.isWellFormed() || row.text.includes('\0')) {
        throw new ApiFailure(503, 'unavailable')
      }
      return { disclosureSeq: row.disclosureSeq, occurredAt: row.occurredAt, type: row.type,
        toolName: row.toolName, outcome: row.outcome, text: row.text }
    }
    if (row.type === 'conversation.title') {
      providerExactRecord(row, ['disclosureSeq', 'occurredAt', 'type', 'title'])
      if (typeof row.title !== 'string' || !row.title.isWellFormed() || row.title.includes('\0')) {
        throw new ApiFailure(503, 'unavailable')
      }
      return { disclosureSeq: row.disclosureSeq, occurredAt: row.occurredAt, type: row.type, title: row.title }
    }
    throw new ApiFailure(503, 'unavailable')
  })
  const result = { checkpointHash: content.checkpointHash, events }
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxValueBytes) throw new ApiFailure(503, 'unavailable')
  return result
}

async function operationInput(request: IncomingMessage, action: 'import' | 'ask', config: RegistryBrowserApiConfig,
  signal: AbortSignal): Promise<OperationInput> {
  const value = await readJson(request, config.maxOperationInputBytes, signal)
  if (action === 'import') {
    const record = exactRecord(value, ['targetInstanceId', 'idempotencyKey'])
    if (typeof record.targetInstanceId !== 'string' || !IDENTIFIER.test(record.targetInstanceId)) {
      throw new ApiFailure(400, 'invalid-input')
    }
    return { action, value: {
      targetInstanceId: brandString<DshInstanceId>(record.targetInstanceId),
      idempotencyKey: idempotencyKey(record.idempotencyKey),
    } }
  }
  const record = exactRecord(value, ['question', 'idempotencyKey'])
  if (typeof record.question !== 'string' || !record.question.isWellFormed() || record.question.includes('\0')) {
    throw new ApiFailure(400, 'invalid-input')
  }
  const question = record.question.trim()
  if (question.length === 0 || question.length > 2000) throw new ApiFailure(400, 'invalid-input')
  return { action, value: { question, idempotencyKey: idempotencyKey(record.idempotencyKey) } }
}

async function instanceActionInput(request: IncomingMessage, action: 'rename' | 'revoke',
  config: RegistryBrowserApiConfig, signal: AbortSignal): Promise<InstanceActionInput> {
  const value = await readJson(request, config.maxOperationInputBytes, signal)
  if (action === 'revoke') {
    const record = exactRecord(value, ['confirmation'])
    if (record.confirmation !== 'revoke') throw new ApiFailure(400, 'invalid-input')
    return { action }
  }
  const record = exactRecord(value, ['instanceName'])
  if (!validInstanceName(record.instanceName)) throw new ApiFailure(400, 'invalid-input')
  return { action, instanceName: record.instanceName }
}

function validInstanceName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value === value.trim()
    && value.isWellFormed() && !/[\u0000-\u001f\u007f]/u.test(value)
}

function bindingCode(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    throw new ApiFailure(400, 'invalid-input')
  }
  return value
}

async function bindingInput(request: IncomingMessage, action: BindingInput['action'],
  config: RegistryBrowserApiConfig, signal: AbortSignal): Promise<BindingInput> {
  const value = await readJson(request, config.maxOperationInputBytes, signal)
  if (action === 'start') {
    const record = exactRecord(value, ['publicKeySpki', 'instanceName', 'requestedScopes'])
    if (typeof record.publicKeySpki !== 'string' || record.publicKeySpki.length === 0
      || !record.publicKeySpki.isWellFormed() || !validInstanceName(record.instanceName)
      || !Array.isArray(record.requestedScopes) || record.requestedScopes.length === 0
      || record.requestedScopes.length > 2) throw new ApiFailure(400, 'invalid-input')
    const scopes: RegistryBindingScope[] = []
    for (const candidate of record.requestedScopes as readonly unknown[]) {
      if (candidate !== 'disclosure.sync' && candidate !== 'a2a.receive') {
        throw new ApiFailure(400, 'invalid-input')
      }
      const scope: RegistryBindingScope = candidate
      if (scopes.includes(scope)) throw new ApiFailure(400, 'invalid-input')
      scopes.push(scope)
    }
    return { action, value: {
      publicKeySpki: record.publicKeySpki,
      instanceName: record.instanceName,
      requestedScopes: scopes,
    } }
  }
  const keys = action === 'approve' ? ['code', 'instanceName'] : action === 'confirm' ? ['proof'] : ['code']
  const record = exactRecord(value, keys)
  if (action === 'confirm') {
    try { return { action, proof: decodeRegistryProof(record.proof) } } catch {
      throw new ApiFailure(400, 'invalid-input')
    }
  }
  const code = bindingCode(record.code)
  if (action === 'approve') {
    if (!validInstanceName(record.instanceName)) throw new ApiFailure(400, 'invalid-input')
    return { action, code, instanceName: record.instanceName }
  }
  return { action, code }
}

async function directoryInput(request: IncomingMessage, config: RegistryBrowserApiConfig,
  signal: AbortSignal): Promise<DirectoryInput> {
  const value = exactRecord(await readJson(request, config.maxOperationInputBytes, signal), ['expectedRevision', 'change'])
  if (!Number.isSafeInteger(value.expectedRevision) || (value.expectedRevision as number) < 0
    || Object.is(value.expectedRevision, -0)) throw new ApiFailure(400, 'invalid-input')
  if (value.change === null || typeof value.change !== 'object' || Array.isArray(value.change)) {
    throw new ApiFailure(400, 'invalid-input')
  }
  const kind = (value.change as Record<string, unknown>).kind
  const raw = exactRecord(value.change, kind === 'put-member' ? ['kind', 'member']
    : kind === 'put-team' ? ['kind', 'team'] : ['kind', 'teamId'])
  if (raw.kind === 'put-member') {
    const member = exactRecord(raw.member, ['memberId', 'displayName', 'role', 'state'])
    if (typeof member.memberId !== 'string' || !IDENTIFIER.test(member.memberId)
      || !validInstanceName(member.displayName)
      || (member.role !== 'owner' && member.role !== 'admin' && member.role !== 'member')
      || (member.state !== 'active' && member.state !== 'suspended' && member.state !== 'removed')) {
      throw new ApiFailure(400, 'invalid-input')
    }
    return { expectedRevision: value.expectedRevision as number, change: { kind: 'put-member', member: {
      memberId: brandString<MemberId>(member.memberId), displayName: member.displayName,
      role: member.role, state: member.state,
    } } }
  }
  if (raw.kind === 'put-team') {
    const team = exactRecord(raw.team, ['teamId', 'displayName', 'memberIds'])
    if (typeof team.teamId !== 'string' || !IDENTIFIER.test(team.teamId) || !validInstanceName(team.displayName)
      || !Array.isArray(team.memberIds)) throw new ApiFailure(400, 'invalid-input')
    const ids = team.memberIds.map((candidate) => {
      if (typeof candidate !== 'string' || !IDENTIFIER.test(candidate)) throw new ApiFailure(400, 'invalid-input')
      return brandString<MemberId>(candidate)
    })
    if (new Set(ids).size !== ids.length) throw new ApiFailure(400, 'invalid-input')
    return { expectedRevision: value.expectedRevision as number, change: { kind: 'put-team', team: {
      teamId: brandString<TeamId>(team.teamId), displayName: team.displayName, memberIds: ids,
    } } }
  }
  if (raw.kind !== 'remove-team' || typeof raw.teamId !== 'string' || !IDENTIFIER.test(raw.teamId)) {
    throw new ApiFailure(400, 'invalid-input')
  }
  return { expectedRevision: value.expectedRevision as number,
    change: { kind: 'remove-team', teamId: brandString<TeamId>(raw.teamId) } }
}

async function billingInput(request: IncomingMessage, config: RegistryBrowserApiConfig,
  signal: AbortSignal): Promise<BillingInput> {
  const value = exactRecord(await readJson(request, config.maxOperationInputBytes, signal),
    ['planId', 'idempotencyKey', 'returnPath'])
  if (typeof value.planId !== 'string' || !IDENTIFIER.test(value.planId)
    || typeof value.returnPath !== 'string' || value.returnPath.length === 0
    || Buffer.byteLength(value.returnPath, 'utf8') > 1024 || !value.returnPath.startsWith('/')
    || value.returnPath.startsWith('//') || value.returnPath.includes('\\')) {
    throw new ApiFailure(400, 'invalid-input')
  }
  let parsed: URL
  try { parsed = new URL(value.returnPath, 'https://registry.invalid') } catch {
    throw new ApiFailure(400, 'invalid-input')
  }
  if (parsed.origin !== 'https://registry.invalid' || parsed.username !== '' || parsed.password !== '') {
    throw new ApiFailure(400, 'invalid-input')
  }
  return { planId: value.planId, idempotencyKey: idempotencyKey(value.idempotencyKey),
    returnPath: `${parsed.pathname}${parsed.search}${parsed.hash}` }
}

async function organizationInput(request: IncomingMessage, config: RegistryBrowserApiConfig,
  signal: AbortSignal): Promise<OrganizationInput> {
  const value = exactRecord(await readJson(request, config.maxOperationInputBytes, signal),
    ['displayName', 'idempotencyKey'])
  if (typeof value.displayName !== 'string' || !validInstanceName(value.displayName)
    || Buffer.byteLength(value.displayName, 'utf8') > 256) throw new ApiFailure(400, 'invalid-input')
  return { displayName: value.displayName, idempotencyKey: idempotencyKey(value.idempotencyKey) }
}

async function invitationInput(request: IncomingMessage, config: RegistryBrowserApiConfig,
  signal: AbortSignal): Promise<InvitationInput> {
  const raw = await readJson(request, config.maxOperationInputBytes, signal)
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new ApiFailure(400, 'invalid-input')
  const value = raw as Record<string, unknown>
  const keys = Object.keys(value)
  if (!keys.includes('role') || keys.some(key => key !== 'role' && key !== 'displayName'
    && key !== 'expiresInSeconds') || (value.role !== 'admin' && value.role !== 'member')) {
    throw new ApiFailure(400, 'invalid-input')
  }
  if (value.displayName !== undefined && (typeof value.displayName !== 'string'
    || !validInstanceName(value.displayName) || Buffer.byteLength(value.displayName, 'utf8') > 256)) {
    throw new ApiFailure(400, 'invalid-input')
  }
  if (value.expiresInSeconds !== undefined && (!Number.isSafeInteger(value.expiresInSeconds)
    || (value.expiresInSeconds as number) < 300 || (value.expiresInSeconds as number) > 604_800
    || Object.is(value.expiresInSeconds, -0))) throw new ApiFailure(400, 'invalid-input')
  return {
    role: value.role,
    ...(value.displayName === undefined ? {} : { displayName: value.displayName as string }),
    ...(value.expiresInSeconds === undefined ? {} : { expiresInSeconds: value.expiresInSeconds as number }),
  }
}

async function invitationTokenInput(request: IncomingMessage, config: RegistryBrowserApiConfig,
  signal: AbortSignal): Promise<InvitationTokenInput> {
  const value = exactRecord(await readJson(request, config.maxOperationInputBytes, signal), ['token'])
  if (typeof value.token !== 'string' || !INVITATION_TOKEN.test(value.token)) {
    throw new ApiFailure(400, 'invalid-input')
  }
  return { token: value.token }
}

async function emptyJsonInput(request: IncomingMessage, config: RegistryBrowserApiConfig,
  signal: AbortSignal): Promise<void> {
  exactRecord(await readJson(request, config.maxOperationInputBytes, signal), [])
}

function parseRoute(request: IncomingMessage, config: RegistryBrowserApiConfig): ApiRoute {
  const url = new URL(request.url ?? '/', 'http://registry.invalid')
  if (url.pathname === TEST_ONLY_REVOKE_PATH) {
    noQuery(url)
    return { kind: 'test-only-revoke' }
  }
  if (url.pathname === STATUS_PATH) {
    noQuery(url)
    return { kind: 'status' }
  }
  if (url.pathname === ACCOUNT_PATH) {
    noQuery(url)
    return { kind: 'account' }
  }
  if (url.pathname === ORGANIZATIONS_PATH) {
    noQuery(url)
    return { kind: 'organization-create' }
  }
  if (url.pathname === `${INVITATIONS_PATH}/preview`
    || url.pathname === `${INVITATIONS_PATH}/accept`
    || url.pathname === `${INVITATIONS_PATH}/decline`) {
    noQuery(url)
    return { kind: url.pathname.endsWith('/preview') ? 'invitation-preview'
      : url.pathname.endsWith('/accept') ? 'invitation-accept' : 'invitation-decline' }
  }
  let organizationId: OrganizationId | undefined
  if (url.pathname.startsWith(`${ORGANIZATIONS_PATH}/`)) {
    const remainder = url.pathname.slice(ORGANIZATIONS_PATH.length + 1)
    const separator = remainder.indexOf('/')
    const encodedOrganizationId = separator < 0 ? '' : remainder.slice(0, separator)
    const resource = separator < 0 ? '' : remainder.slice(separator + 1)
    let rawOrganizationId: string
    try { rawOrganizationId = decodeURIComponent(encodedOrganizationId) } catch {
      throw new ApiFailure(404, 'not-found')
    }
    if (!IDENTIFIER.test(rawOrganizationId) || resource.length === 0) throw new ApiFailure(404, 'not-found')
    organizationId = brandString<OrganizationId>(rawOrganizationId)
    url.pathname = `${API_BASE}/${resource}`
  }
  const scoped = (route: TenantApiRoute): TenantApiRoute => organizationId === undefined
    ? route : { ...route, organizationId }
  if (url.pathname === INSTANCES_PATH) {
    noQuery(url)
    return scoped({ kind: 'instances' })
  }
  if (url.pathname === `${BINDINGS_PATH}/start`) {
    noQuery(url)
    return scoped({ kind: 'binding-start' })
  }
  if (url.pathname.startsWith(`${BINDINGS_PATH}/`)) {
    noQuery(url)
    const segments = url.pathname.slice(BINDINGS_PATH.length + 1).split('/')
    if (segments.length === 2 && segments[0] !== undefined && segments[1] !== undefined) {
      const selected = bindingId(segments[0])
      if (segments[1] === 'confirm') return scoped({ kind: 'binding-confirm', bindingId: selected })
      if (segments[1] === 'review' || segments[1] === 'approve' || segments[1] === 'reject') {
        return scoped({ kind: 'binding-account-action', bindingId: selected, action: segments[1] })
      }
    }
    throw new ApiFailure(404, 'not-found')
  }
  if (url.pathname.startsWith(`${INSTANCES_PATH}/`)) {
    noQuery(url)
    const segments = url.pathname.slice(INSTANCES_PATH.length + 1).split('/')
    if (segments.length === 2 && segments[0] !== undefined
      && (segments[1] === 'rename' || segments[1] === 'revoke')) {
      return scoped({ kind: 'instance-action', bindingId: bindingId(segments[0]), action: segments[1] })
    }
    throw new ApiFailure(404, 'not-found')
  }
  if (url.pathname === DIRECTORY_PATH) {
    noQuery(url)
    return scoped({ kind: 'directory' })
  }
  if (url.pathname === INVITATIONS_PATH) {
    noQuery(url)
    if (organizationId === undefined) throw new ApiFailure(404, 'not-found')
    return scoped({ kind: 'invitations' })
  }
  if (url.pathname.startsWith(`${INVITATIONS_PATH}/`)) {
    noQuery(url)
    if (organizationId === undefined) throw new ApiFailure(404, 'not-found')
    const segments = url.pathname.slice(INVITATIONS_PATH.length + 1).split('/')
    if (segments.length === 2 && segments[0] !== undefined && segments[1] === 'revoke') {
      return scoped({ kind: 'invitation-revoke', invitationId: invitationId(segments[0]) })
    }
    throw new ApiFailure(404, 'not-found')
  }
  if (url.pathname === `${BILLING_PATH}/plans`) {
    noQuery(url)
    return scoped({ kind: 'billing-plans' })
  }
  if (url.pathname === `${BILLING_PATH}/checkout`) {
    noQuery(url)
    return scoped({ kind: 'billing-checkout' })
  }
  if (url.pathname === AUDIT_PATH) {
    const keys = [...url.searchParams.keys()]
    if (keys.some(key => key !== 'cursor') || url.searchParams.getAll('cursor').length > 1) {
      throw new ApiFailure(400, 'invalid-input')
    }
    const cursor = url.searchParams.get('cursor')
    if (cursor !== null && (cursor === '' || Buffer.byteLength(cursor, 'utf8') > config.maxCursorBytes)) {
      throw new ApiFailure(400, 'invalid-input')
    }
    return cursor === null ? scoped({ kind: 'audit' }) : scoped({ kind: 'audit', cursor })
  }
  if (url.pathname === BRANCHES_PATH) {
    const keys = [...url.searchParams.keys()]
    if (keys.some(key => key !== 'cursor') || url.searchParams.getAll('cursor').length > 1) {
      throw new ApiFailure(400, 'invalid-input')
    }
    const cursor = url.searchParams.get('cursor')
    if (cursor !== null && (cursor === '' || Buffer.byteLength(cursor, 'utf8') > config.maxCursorBytes
      || !IDENTIFIER.test(cursor))) throw new ApiFailure(400, 'invalid-input')
    return cursor === null ? scoped({ kind: 'branches' }) : scoped({ kind: 'branches', cursor })
  }
  if (url.pathname === DISCLOSURES_PATH) {
    const keys = [...url.searchParams.keys()]
    if (keys.some(key => key !== 'cursor') || url.searchParams.getAll('cursor').length > 1) {
      throw new ApiFailure(400, 'invalid-input')
    }
    const cursor = url.searchParams.get('cursor')
    if (cursor !== null && (cursor === '' || Buffer.byteLength(cursor, 'utf8') > config.maxCursorBytes)) {
      throw new ApiFailure(400, 'invalid-input')
    }
    return cursor === null ? scoped({ kind: 'list' }) : scoped({ kind: 'list', cursor })
  }
  if (!url.pathname.startsWith(`${DISCLOSURES_PATH}/`)) throw new ApiFailure(404, 'not-found')
  const segments = url.pathname.slice(DISCLOSURES_PATH.length + 1).split('/')
  const resource = segments[0]
  if (resource === undefined) throw new ApiFailure(404, 'not-found')
  if (segments.length === 2 && segments[1] === 'content') {
    const keys = [...url.searchParams.keys()]
    if (keys.some(key => key !== 'checkpoint') || url.searchParams.getAll('checkpoint').length !== 1) {
      throw new ApiFailure(400, 'invalid-input')
    }
    const checkpoint = url.searchParams.get('checkpoint')
    if (checkpoint === null || !/^sha256:[0-9a-f]{64}$/u.test(checkpoint)) {
      throw new ApiFailure(400, 'invalid-input')
    }
    return scoped({ kind: 'content', disclosureId: disclosureId(resource),
      checkpointHash: brandString<DisclosureHash>(checkpoint) })
  }
  noQuery(url)
  if (segments.length === 1) return scoped({ kind: 'detail', disclosureId: disclosureId(resource) })
  if (segments.length === 2 && (segments[1] === 'import' || segments[1] === 'questions')) {
    return scoped({ kind: 'operation', disclosureId: disclosureId(resource),
      action: segments[1] === 'import' ? 'import' : 'ask' })
  }
  if (segments.length === 2 && segments[1] === 'import-targets') {
    return scoped({ kind: 'import-targets', disclosureId: disclosureId(resource) })
  }
  if (segments.length === 3 && segments[1] === 'imports' && segments[2] !== undefined) {
    return scoped({ kind: 'import-status', disclosureId: disclosureId(resource), operationId: operationId(segments[2]) })
  }
  if (segments.length === 3 && segments[1] === 'questions' && segments[2] !== undefined) {
    return scoped({ kind: 'question', disclosureId: disclosureId(resource), requestId: requestId(segments[2]) })
  }
  throw new ApiFailure(404, 'not-found')
}

function assertMethod(request: IncomingMessage, route: ApiRoute): void {
  if (route.kind === 'account' || route.kind === 'organization-create'
    || route.kind === 'invitation-preview' || route.kind === 'invitation-accept'
    || route.kind === 'invitation-decline') {
    const allowed = route.kind === 'account' ? 'GET' : 'POST'
    if (request.method !== allowed) throw new ApiFailure(405, 'method-not-allowed', allowed)
    return
  }
  if (route.kind === 'question') {
    const allowed = 'GET, DELETE'
    if (request.method !== 'GET' && request.method !== 'DELETE') {
      throw new ApiFailure(405, 'method-not-allowed', allowed)
    }
    return
  }
  if (route.kind === 'directory') {
    const allowed = 'GET, POST'
    if (request.method !== 'GET' && request.method !== 'POST') throw new ApiFailure(405, 'method-not-allowed', allowed)
    return
  }
  if (route.kind === 'invitations') {
    const allowed = 'GET, POST'
    if (request.method !== 'GET' && request.method !== 'POST') throw new ApiFailure(405, 'method-not-allowed', allowed)
    return
  }
  if (route.kind === 'billing-plans' || route.kind === 'billing-checkout') {
    const allowed = route.kind === 'billing-plans' ? 'GET' : 'POST'
    if (request.method !== allowed) throw new ApiFailure(405, 'method-not-allowed', allowed)
    return
  }
  const allowed = route.kind === 'operation' || route.kind === 'instance-action'
    || route.kind === 'binding-start' || route.kind === 'binding-confirm'
    || route.kind === 'binding-account-action' || route.kind === 'invitation-revoke'
    || route.kind === 'test-only-revoke' ? 'POST' : 'GET'
  if (request.method !== allowed) throw new ApiFailure(405, 'method-not-allowed', allowed)
}

/** Direct peer predicate shared by the deliberately narrow test-only route. */
export function isDirectLoopback(address: string | undefined): boolean {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

function assertTestOnlyRequest(request: IncomingMessage): void {
  if (request.headers.origin !== undefined
    || request.headers[TEST_ONLY_CONFIRM_HEADER] !== TEST_ONLY_CONFIRM_VALUE) {
    throw new ApiFailure(404, 'not-found')
  }
  const length = request.headers['content-length']
  if ((length !== undefined && length !== '0') || request.headers['transfer-encoding'] !== undefined) {
    request.resume()
    throw new ApiFailure(400, 'invalid-input')
  }
}

async function revokeTestSeed(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  config: NonNullable<RegistryBrowserApiRuntimeConfiguration['testOnlyRevoke']>): Promise<unknown> {
  const authenticator = ctx.get('registryAccountAuthenticator')
  const control: RegistryDisclosureControl | undefined = ctx.get('registryDisclosureControl')
  if (authenticator === undefined || control === undefined) throw new ApiFailure(404, 'not-found')
  const authority: FreshProducerAuthority = async () => {
    let current: RegistryAuthenticatedAccount | null
    try { current = await authenticator.authenticate(request, signal) } catch {
      throw new RegistryIngestError('not-found')
    }
    if (current === null || !current.subject.authenticated || current.subject.membership !== 'active'
      || current.subject.role !== 'owner') throw new RegistryIngestError('not-found')
    const history = current.historyFor(config.sourceInstanceId)
    if (history === null || history.organizationId !== current.subject.organizationId
      || history.instanceId !== config.sourceInstanceId || history.status !== 'active'
      || !history.keys.some(key => key.keyId === config.sourceKeyId)) throw new RegistryIngestError('not-found')
    return { history: structuredClone(history), connection: {
      organizationId: current.subject.organizationId,
      instanceId: config.sourceInstanceId,
      keyId: config.sourceKeyId,
      now: Date.now(),
    } }
  }
  const receipt = await control.transitionControl(authority, config.disclosureId, 'revoked',
    config.expectedAuthorizationVersion)
  return { disclosureId: receipt.disclosureId, control: receipt.control,
    authorizationVersion: receipt.authorizationVersion }
}

async function tenantRuntime(ctx: Context, organizationId: OrganizationId | undefined):
Promise<RegistryTenantRuntimeLease | undefined> {
  if (organizationId === undefined) return undefined
  const router = ctx.get('registryTenantRouter')
  if (router === undefined) throw new ApiFailure(503, 'registry-not-configured')
  return router.acquireRuntime(organizationId)
}

async function authenticateAccount(authenticator: RegistryAccountAuthenticator, request: IncomingMessage,
  signal: AbortSignal, organizationId: OrganizationId | undefined): Promise<RegistryAuthenticatedAccount | null> {
  return organizationId === undefined
    ? authenticator.authenticate(request, signal)
    : authenticator.authenticateOrganization(request, organizationId, signal)
}

async function requireAuthenticatedAccount(authenticator: RegistryAccountAuthenticator, request: IncomingMessage,
  signal: AbortSignal, organizationId: OrganizationId | undefined): Promise<RegistryAuthenticatedAccount> {
  let account: RegistryAuthenticatedAccount | null
  try { account = await authenticateAccount(authenticator, request, signal, organizationId) } catch {
    throw new ApiFailure(503, 'unavailable')
  }
  if (account !== null && account.subject.authenticated) return account
  if (organizationId !== undefined) {
    let identity: RegistryAuthenticatedIdentity | null
    try { identity = await authenticator.authenticateIdentity(request, signal) } catch {
      throw new ApiFailure(503, 'unavailable')
    }
    if (identity !== null) throw new ApiFailure(404, 'not-found')
  }
  throw new ApiFailure(401, 'unauthenticated')
}

async function requestAuthority(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  reauthorizationFailure: 'not-found' | 'unavailable' = 'not-found',
  organizationId?: OrganizationId, selectedRuntime?: RegistryTenantRuntime):
Promise<{
  readonly reader: RegistryDisclosureReader
  readonly enrollment?: RegistryEnrollment
  readonly authority: FreshRegistryMetadataAuthority
  readonly authenticatedSubject: DisclosureSubject
  readonly authorizedSubject: () => DisclosureSubject
}> {
  const authenticator = ctx.get('registryAccountAuthenticator')
  if (authenticator === undefined) throw new ApiFailure(503, 'identity-not-configured')
  const account = await requireAuthenticatedAccount(authenticator, request, signal, organizationId)
  const runtime = selectedRuntime
  const reader = runtime?.reader ?? ctx.get('registryDisclosureReader')
  if (reader === undefined) throw new ApiFailure(503, 'registry-not-configured')
  const enrollment = runtime?.enrollment ?? ctx.get('registryEnrollment')
  const authenticatedSubject = structuredClone(account.subject)
  let authorizedSubject: DisclosureSubject | undefined
  const authority: FreshRegistryMetadataAuthority = async () => {
    let current: RegistryAuthenticatedAccount | null
    try { current = await authenticateAccount(authenticator, request, signal, organizationId) } catch {
      throw new RegistryIngestError(reauthorizationFailure === 'not-found' ? 'not-found' : 'storage-unavailable')
    }
    if (current === null || !current.subject.authenticated) throw new RegistryIngestError('not-found')
    // Operation admission was charged to this request's first authenticated
    // account. A fresh identity may narrow permissions, but it must not move
    // the authorization onto a different account bucket mid-request.
    if (current.subject.organizationId !== authenticatedSubject.organizationId
      || current.subject.memberId !== authenticatedSubject.memberId) throw new RegistryIngestError('not-found')
    authorizedSubject = structuredClone(current.subject)
    return { subject: authorizedSubject, now: Date.now(), historyFor: current.historyFor }
  }
  return { reader, ...(enrollment === undefined ? {} : { enrollment }), authority, authenticatedSubject,
    authorizedSubject: () => {
    if (authorizedSubject === undefined) throw new ApiFailure(503, 'unavailable')
    return authorizedSubject
  } }
}

function operationSelection(reader: RegistryDisclosureReader, enrollment: RegistryEnrollment | undefined,
  authority: FreshRegistryMetadataAuthority,
  selectedSubject: DisclosureSubject, disclosure: RegistryDisclosureMetadata, selectedDisclosureId: DisclosureId,
  action: 'import' | 'ask', maxResponseBytes: number): RegistryDisclosureOperationSelection {
  return {
    subject: selectedSubject,
    disclosure,
    authorizeTarget: async (targetInstanceId: DshInstanceId, operationSignal: AbortSignal) => {
      requireOperationActive(operationSignal)
      if (enrollment === undefined) throw new RegistryIngestError('closed')
      const pinnedAuthority: FreshRegistryDirectoryAuthority = async () => {
        const current = await authority()
        if (current.subject.organizationId !== selectedSubject.organizationId
          || current.subject.memberId !== selectedSubject.memberId) throw new RegistryIngestError('not-found')
        return { subject: {
          organizationId: current.subject.organizationId,
          memberId: current.subject.memberId,
          authenticated: current.subject.authenticated,
        }, now: current.now }
      }
      const bindings = await enrollment.list(pinnedAuthority, maxResponseBytes)
      requireOperationActive(operationSignal)
      const matches = bindings.filter(binding => binding.organizationId === selectedSubject.organizationId
        && binding.instanceId === targetInstanceId)
      if (matches.length !== 1 || matches[0]?.phase !== 'confirmed'
        || !matches[0].requestedScopes.includes('a2a.receive')) throw new RegistryIngestError('not-found')
      return structuredClone(matches[0].transport)
    },
    readAuthorizedPrefix: async (expected: { readonly sourceInstanceId: DshInstanceId
      readonly checkpointHash: DisclosureHash }, operationSignal: AbortSignal) => {
      requireOperationActive(operationSignal)
      const pinnedAuthority: FreshRegistryMetadataAuthority = async () => {
        const current = await authority()
        if (current.subject.organizationId !== selectedSubject.organizationId
          || current.subject.memberId !== selectedSubject.memberId) throw new RegistryIngestError('not-found')
        return current
      }
      const prefix = await reader.readPrefix(pinnedAuthority, selectedDisclosureId, expected.sourceInstanceId,
        action, expected.checkpointHash)
      requireOperationActive(operationSignal)
      return prefix
    },
  }
}

async function enrollmentAuthority(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  organizationId?: OrganizationId, selectedRuntime?: RegistryTenantRuntime): Promise<{
  readonly enrollment: RegistryEnrollment
  readonly authority: FreshRegistryDirectoryAuthority
  readonly authenticatedSubject: DisclosureSubject
}> {
  const authenticator = ctx.get('registryAccountAuthenticator')
  if (authenticator === undefined) throw new ApiFailure(503, 'identity-not-configured')
  const account = await requireAuthenticatedAccount(authenticator, request, signal, organizationId)
  const authenticatedSubject = structuredClone(account.subject)
  const runtime = selectedRuntime
  const enrollment = runtime?.enrollment ?? ctx.get('registryEnrollment')
  if (enrollment === undefined) throw new ApiFailure(503, 'registry-not-configured')
  const authority: FreshRegistryDirectoryAuthority = async () => {
    let current: RegistryAuthenticatedAccount | null
    try { current = await authenticateAccount(authenticator, request, signal, organizationId) } catch {
      throw new RegistryIngestError('not-found')
    }
    if (current === null || !current.subject.authenticated
      || current.subject.organizationId !== authenticatedSubject.organizationId
      || current.subject.memberId !== authenticatedSubject.memberId) throw new RegistryIngestError('not-found')
    return { subject: {
      organizationId: current.subject.organizationId,
      memberId: current.subject.memberId,
      authenticated: current.subject.authenticated,
    }, now: Date.now() }
  }
  return { enrollment, authority, authenticatedSubject }
}

async function directoryAuthority(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  organizationId?: OrganizationId, selectedRuntime?: RegistryTenantRuntime): Promise<{
  readonly directory: RegistryDirectory
  readonly authority: FreshRegistryDirectoryAuthority
  readonly authenticatedSubject: DisclosureSubject
}> {
  const authenticator = ctx.get('registryAccountAuthenticator')
  if (authenticator === undefined) throw new ApiFailure(503, 'identity-not-configured')
  const account = await requireAuthenticatedAccount(authenticator, request, signal, organizationId)
  const authenticatedSubject = structuredClone(account.subject)
  const runtime = selectedRuntime
  const directory = runtime?.directory ?? ctx.get('registryDirectory')
  if (directory === undefined) throw new ApiFailure(503, 'registry-not-configured')
  const authority: FreshRegistryDirectoryAuthority = async () => {
    let current: RegistryAuthenticatedAccount | null
    try { current = await authenticateAccount(authenticator, request, signal, organizationId) } catch {
      throw new RegistryIngestError('not-found')
    }
    if (current === null || !current.subject.authenticated
      || current.subject.organizationId !== authenticatedSubject.organizationId
      || current.subject.memberId !== authenticatedSubject.memberId) throw new RegistryIngestError('not-found')
    return { subject: {
      organizationId: current.subject.organizationId,
      memberId: current.subject.memberId,
      authenticated: true,
    }, now: Date.now() }
  }
  return { directory, authority, authenticatedSubject }
}

async function billingOwner(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  organizationId?: OrganizationId): Promise<DisclosureSubject> {
  const authenticator = ctx.get('registryAccountAuthenticator')
  if (authenticator === undefined) throw new ApiFailure(503, 'identity-not-configured')
  const account = await requireAuthenticatedAccount(authenticator, request, signal, organizationId)
  if (account.subject.membership !== 'active' || account.subject.role !== 'owner') {
    throw new ApiFailure(404, 'not-found')
  }
  return structuredClone(account.subject)
}

async function auditAuthority(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  organizationId?: OrganizationId, selectedRuntime?: RegistryTenantRuntime): Promise<{
  readonly reader: RegistryAuditReader
  readonly authority: FreshRegistryAuditAuthority
}> {
  const authenticator = ctx.get('registryAccountAuthenticator')
  if (authenticator === undefined) throw new ApiFailure(503, 'identity-not-configured')
  const account = await requireAuthenticatedAccount(authenticator, request, signal, organizationId)
  const runtime = selectedRuntime
  const reader = runtime?.auditReader ?? ctx.get('registryAuditReader')
  if (reader === undefined) throw new ApiFailure(503, 'registry-not-configured')
  const authenticatedSubject = structuredClone(account.subject)
  const authority: FreshRegistryAuditAuthority = async () => {
    let current: RegistryAuthenticatedAccount | null
    try { current = await authenticateAccount(authenticator, request, signal, organizationId) } catch {
      throw new RegistryIngestError('not-found')
    }
    if (current === null || !current.subject.authenticated
      || current.subject.organizationId !== authenticatedSubject.organizationId
      || current.subject.memberId !== authenticatedSubject.memberId) throw new RegistryIngestError('not-found')
    return structuredClone(current.subject)
  }
  return { reader, authority }
}

async function globalIdentity(ctx: Context, request: IncomingMessage,
  signal: AbortSignal): Promise<RegistryAuthenticatedIdentity> {
  const authenticator = ctx.get('registryAccountAuthenticator')
  if (authenticator === undefined) throw new ApiFailure(503, 'identity-not-configured')
  let identity: RegistryAuthenticatedIdentity | null
  try { identity = await authenticator.authenticateIdentity(request, signal) } catch {
    throw new ApiFailure(503, 'unavailable')
  }
  if (identity === null) throw new ApiFailure(401, 'unauthenticated')
  return identity
}

function organizationAccessResult(access: RegistryOrganizationAccess): unknown {
  return {
    organizationId: access.organization.organizationId,
    slug: access.organization.slug,
    displayName: access.organization.displayName,
    state: access.organization.state,
    memberId: access.membership.memberId,
    role: access.membership.role,
    membershipState: access.membership.state,
  }
}

function invitationResult(value: {
  readonly invitationId: string
  readonly organizationId: OrganizationId
  readonly role: 'admin' | 'member'
  readonly displayName: string | null
  readonly status: string
  readonly expiresAt: number
  readonly createdAt: number
  readonly createdByMemberId: MemberId
}): unknown {
  return {
    invitationId: value.invitationId,
    organizationId: value.organizationId,
    role: value.role,
    displayName: value.displayName,
    status: value.status,
    expiresAt: value.expiresAt,
    createdAt: value.createdAt,
    createdByMemberId: value.createdByMemberId,
  }
}

function invitationPreviewResult(value: {
  readonly invitationId: string
  readonly organizationId: OrganizationId
  readonly organizationDisplayName: string
  readonly role: 'admin' | 'member'
  readonly displayName: string | null
  readonly status: string
  readonly expiresAt: number
}): unknown {
  return {
    invitationId: value.invitationId,
    organizationId: value.organizationId,
    organizationDisplayName: value.organizationDisplayName,
    role: value.role,
    displayName: value.displayName,
    status: value.status,
    expiresAt: value.expiresAt,
  }
}

function tenancyAccount(identity: RegistryAuthenticatedIdentity): RegistryAccount {
  return {
    accountId: brandString<RegistryAccountId>(identity.accountId),
    memberId: brandString<MemberId>(identity.memberId),
    displayName: identity.displayName,
    createdAt: 0,
    updatedAt: 0,
  }
}

async function accountResult(ctx: Context, request: IncomingMessage, signal: AbortSignal): Promise<unknown> {
  const identity = await globalIdentity(ctx, request, signal)
  const router = ctx.get('registryTenantRouter')
  if (router !== undefined) {
    const organizations = await router.listOrganizations(brandString<RegistryAccountId>(identity.accountId))
    return { accountId: identity.accountId, memberId: identity.memberId, displayName: identity.displayName,
      organizations: organizations.map(organizationAccessResult) }
  }
  const authenticator = ctx.get('registryAccountAuthenticator')
  let account: RegistryAuthenticatedAccount | null = null
  if (authenticator !== undefined) {
    try { account = await authenticator.authenticate(request, signal) } catch {
      throw new ApiFailure(503, 'unavailable')
    }
  }
  const organizations = account === null ? [] : [{
    organizationId: account.subject.organizationId,
    slug: account.subject.organizationId,
    displayName: account.subject.organizationId,
    state: 'active',
    memberId: account.subject.memberId,
    role: account.subject.role,
    membershipState: account.subject.membership,
  }]
  return { accountId: identity.accountId, memberId: identity.memberId, displayName: identity.displayName,
    organizations }
}

async function createOrganization(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  input: OrganizationInput): Promise<unknown> {
  const identity = await globalIdentity(ctx, request, signal)
  const router = ctx.get('registryTenantRouter')
  if (router === undefined) throw new ApiFailure(503, 'registry-not-configured')
  const account = tenancyAccount(identity)
  const created = await router.tenancy.createOrganization(account, input)
  const lease = created.organization.state === 'active' ? undefined : await router.provision(created, identity.displayName)
  try {
    const current = await router.tenancy.getOrganizationForAccount(account.accountId,
      created.organization.organizationId)
    if (current === null || current.organization.state !== 'active') throw new RegistryTenancyError('unavailable')
    return organizationAccessResult(current)
  } finally { lease?.release() }
}

async function invitationActor(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  organizationId: OrganizationId): Promise<{
  readonly identity: RegistryAuthenticatedIdentity
  readonly account: RegistryAuthenticatedAccount
}> {
  const authenticator = ctx.get('registryAccountAuthenticator')
  if (authenticator === undefined) throw new ApiFailure(503, 'identity-not-configured')
  const [identity, account] = await Promise.all([
    globalIdentity(ctx, request, signal),
    requireAuthenticatedAccount(authenticator, request, signal, organizationId),
  ])
  if (identity.memberId !== account.subject.memberId || account.subject.organizationId !== organizationId
    || account.subject.membership !== 'active'
    || (account.subject.role !== 'owner' && account.subject.role !== 'admin')) {
    throw new ApiFailure(404, 'not-found')
  }
  return { identity, account }
}

async function acceptInvitation(ctx: Context, request: IncomingMessage, signal: AbortSignal,
  token: string, maxValueBytes: number): Promise<unknown> {
  const identity = await globalIdentity(ctx, request, signal)
  const router = ctx.get('registryTenantRouter')
  if (router === undefined) throw new ApiFailure(503, 'registry-not-configured')
  const account = tenancyAccount(identity)
  const claim = await router.tenancy.claimInvitation(account, token)
  if (claim.invitation.status === 'accepted') {
    return organizationAccessResult(await router.tenancy.activateInvitation(account,
      claim.invitation.invitationId))
  }
  const lease = await router.acquireRuntime(claim.invitation.organizationId)
  const directory = lease.runtime.directory
  if (directory === undefined) {
    lease.release()
    throw new ApiFailure(503, 'registry-not-configured')
  }
  const authority: FreshRegistryDirectoryAuthority = async () => ({ subject: {
    organizationId: claim.invitation.organizationId,
    memberId: claim.invitation.createdByMemberId,
    authenticated: true,
  }, now: Date.now() })
  let inserted = false
  try {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const state = await directory.read(authority, 'administration', maxValueBytes)
      const existing = state.members.find(member => member.memberId === account.memberId)
      if (existing !== undefined) {
        if (existing.role !== claim.invitation.role || existing.state !== 'active') {
          throw new RegistryTenancyError('conflict')
        }
        break
      }
      try {
        await directory.change(authority, { kind: 'put-member', member: {
          memberId: account.memberId,
          displayName: account.displayName,
          role: claim.invitation.role,
          state: 'active',
        } }, state.revision)
        inserted = true
        break
      } catch (error) {
        if (!(error instanceof RegistryIngestError) || error.code !== 'version-conflict' || attempt === 2) throw error
      }
    }
    try {
      return organizationAccessResult(await router.tenancy.activateInvitation(account,
        claim.invitation.invitationId))
    } catch (error) {
      // A transient/unknown control-plane failure must remain retryable: the suspended membership
      // keeps an active directory orphan inaccessible. Tombstone only a confirmed terminal invite.
      let terminal = error instanceof RegistryTenancyError && error.code === 'conflict'
      if (!terminal) {
        try {
          const preview = await router.tenancy.previewInvitation(account.accountId, token)
          terminal = preview.status === 'revoked' || preview.status === 'expired' || preview.status === 'declined'
        } catch { /* Unknown availability is not proof that the invitation is terminal. */ }
      }
      if (inserted && terminal) {
        try {
          const state = await directory.read(authority, 'administration', maxValueBytes)
          const existing = state.members.find(member => member.memberId === account.memberId)
          if (existing?.role === claim.invitation.role && existing.state === 'active') {
            await directory.change(authority, { kind: 'put-member', member: {
              ...existing, state: 'removed',
            } }, state.revision)
          }
        } catch { /* Control membership is still suspended/removed and therefore fail-closed. */ }
      }
      throw error
    }
  } finally { lease.release() }
}

function mapFailure(error: unknown): ApiFailure {
  if (error instanceof ApiFailure) return error
  if (error instanceof RegistryTenancyError) {
    if (error.code === 'invalid-input') return new ApiFailure(400, 'invalid-input')
    if (error.code === 'conflict') return new ApiFailure(409, 'conflict')
    if (error.code === 'not-found') return new ApiFailure(404, 'not-found')
    return new ApiFailure(503, 'unavailable')
  }
  if (error instanceof RegistryIngestError) {
    if (error.code === 'not-found') return new ApiFailure(404, 'not-found')
    if (error.code === 'version-conflict') return new ApiFailure(409, 'conflict')
    if (error.code === 'invalid-input' || error.code === 'limit') return new ApiFailure(400, 'invalid-input')
    return new ApiFailure(503, 'unavailable')
  }
  return new ApiFailure(503, 'unavailable')
}

/** Register the bounded browser API and abort admitted authentication when its owner unloads.
 * @param ctx - Registry application context with the public HTTP service.
 * @param config - Explicit page, value and cursor bounds.
 * @param runtime - Startup configuration facts; they do not claim continuing worker health.
 * @returns Idempotent route disposer. */
export function installRegistryBrowserApi(ctx: Context, config: RegistryBrowserApiConfig,
  runtime: RegistryBrowserApiRuntimeConfiguration = UNCONFIGURED_RUNTIME): () => void {
  const disclosureCleanupConfigured = runtime.disclosureCleanup
  const mailboxCleanupConfigured = runtime.mailboxCleanup
  const admission = config.admission === undefined ? undefined : new RegistryBrowserAdmission(
    config.admission, undefined, ctx.get('registrySharedAdmission', false))
  const active = new Set<AbortController>()
  let testOnlyRevokeConsumed = false
  const unregister = ctx.webServer.register({ kind: 'prefix', path: API_BASE, handler: async (request, response) => {
    const controller = new AbortController()
    let tenantLease: RegistryTenantRuntimeLease | undefined
    active.add(controller)
    const cancel = () => { controller.abort() }
    request.once('aborted', cancel)
    response.once('close', cancel)
    try {
      const route = parseRoute(request, config)
      if (route.kind === 'test-only-revoke' && (runtime.testOnlyRevoke?.mode !== 'test-only'
        || !isDirectLoopback(request.socket.remoteAddress) || admission === undefined)) {
        throw new ApiFailure(404, 'not-found')
      }
      assertMethod(request, route)
      if ((route.kind === 'operation' || route.kind === 'instance-action' || route.kind === 'binding-start'
        || route.kind === 'binding-confirm' || route.kind === 'binding-account-action'
        || route.kind === 'directory' && request.method === 'POST' || route.kind === 'billing-checkout'
        || route.kind === 'organization-create' || route.kind === 'invitations' && request.method === 'POST'
        || route.kind === 'invitation-revoke' || route.kind === 'invitation-preview'
        || route.kind === 'invitation-accept' || route.kind === 'invitation-decline')
        && admission !== undefined) {
        const address = request.socket.remoteAddress
        if (address === undefined) throw new ApiFailure(503, 'unavailable')
        requireAdmission(ctx, admission.admitDirectPeer(address, request.headers['x-forwarded-for']), 'client-address')
      }
      const input = route.kind === 'operation'
        ? await operationInput(request, route.action, config, controller.signal) : undefined
      const instanceInput = route.kind === 'instance-action'
        ? await instanceActionInput(request, route.action, config, controller.signal) : undefined
      const enrollmentInput = route.kind === 'binding-start'
        ? await bindingInput(request, 'start', config, controller.signal)
        : route.kind === 'binding-confirm'
          ? await bindingInput(request, 'confirm', config, controller.signal)
          : route.kind === 'binding-account-action'
            ? await bindingInput(request, route.action, config, controller.signal)
            : undefined
      const directoryChangeInput = route.kind === 'directory' && request.method === 'POST'
        ? await directoryInput(request, config, controller.signal) : undefined
      const organizationCreateInput = route.kind === 'organization-create'
        ? await organizationInput(request, config, controller.signal) : undefined
      const invitationCreateInput = route.kind === 'invitations' && request.method === 'POST'
        ? await invitationInput(request, config, controller.signal) : undefined
      const invitationToken = route.kind === 'invitation-preview' || route.kind === 'invitation-accept'
        || route.kind === 'invitation-decline'
        ? await invitationTokenInput(request, config, controller.signal) : undefined
      if (route.kind === 'invitation-revoke') {
        await emptyJsonInput(request, config, controller.signal)
      }
      const checkoutInput = route.kind === 'billing-checkout'
        ? await billingInput(request, config, controller.signal) : undefined
      const organizationId = 'organizationId' in route ? route.organizationId : undefined
      const anonymousTenantRoute = route.kind === 'binding-start' || route.kind === 'binding-confirm'
      if (organizationId !== undefined && !anonymousTenantRoute) {
        const authenticator = ctx.get('registryAccountAuthenticator')
        if (authenticator === undefined) throw new ApiFailure(503, 'identity-not-configured')
        await requireAuthenticatedAccount(authenticator, request, controller.signal, organizationId)
      }
      tenantLease = await tenantRuntime(ctx, organizationId)
      const selectedRuntime = tenantLease?.runtime
      if (route.kind === 'status') {
        const tenantRouterConfigured = ctx.get('registryTenantRouter') !== undefined
        const operations = ctx.get('registryDisclosureOperations')
        const disclosureOperationsConfigured = operations !== undefined
          && ['readContent', 'listQuestions', 'listImportTargets', 'importDisclosure', 'readImport',
            'askDisclosure', 'readQuestion', 'cancelQuestion']
            .every(method => typeof operations[method as keyof RegistryDisclosureOperations] === 'function')
        succeed(response, {
          deploymentMode: runtime.deploymentMode,
          identity: ctx.get('registryAccountAuthenticator') === undefined ? 'unconfigured' : 'configured',
          identityProvider: ctx.get('registryAccountAuthenticator') === undefined
            ? 'unconfigured' : runtime.identityProvider,
          registry: ctx.get('registryDisclosureReader') === undefined && !tenantRouterConfigured
            ? 'unconfigured' : 'configured',
          disclosureOperations: disclosureOperationsConfigured ? 'configured' : 'unconfigured',
          deviceBinding: ctx.get('registryEnrollment') === undefined && !tenantRouterConfigured
            ? 'unconfigured' : 'configured',
          audit: ctx.get('registryAuditReader') === undefined && !tenantRouterConfigured
            ? 'unconfigured' : 'configured',
          rateLimits: admission === undefined ? 'unconfigured' : 'configured',
          disclosureCleanup: disclosureCleanupConfigured ? 'configured' : 'unconfigured',
          mailboxCleanup: mailboxCleanupConfigured ? 'configured' : 'unconfigured',
          billing: ctx.get('registryBillingProvider') === undefined ? 'unconfigured' : 'configured',
          billingProvider: ctx.get('registryBillingProvider')?.provider ?? 'unconfigured',
        })
        return
      }
      if (route.kind === 'account') {
        succeed(response, await accountResult(ctx, request, controller.signal))
        return
      }
      if (route.kind === 'organization-create') {
        if (organizationCreateInput === undefined) throw new ApiFailure(503, 'unavailable')
        if (admission !== undefined) {
          const identity = await globalIdentity(ctx, request, controller.signal)
          requireAdmission(ctx, admission.admitAccount(ACCOUNT_ADMISSION_ORGANIZATION,
            brandString<MemberId>(identity.memberId)), 'account')
        }
        succeed(response, await createOrganization(ctx, request, controller.signal, organizationCreateInput))
        return
      }
      if (route.kind === 'invitation-preview' || route.kind === 'invitation-accept'
        || route.kind === 'invitation-decline') {
        if (invitationToken === undefined) throw new ApiFailure(503, 'unavailable')
        const identity = await globalIdentity(ctx, request, controller.signal)
        if (admission !== undefined) {
          requireAdmission(ctx, admission.admitAccount(ACCOUNT_ADMISSION_ORGANIZATION,
            brandString<MemberId>(identity.memberId)), 'account')
        }
        const router = ctx.get('registryTenantRouter')
        if (router === undefined) throw new ApiFailure(503, 'registry-not-configured')
        if (route.kind === 'invitation-preview') {
          const preview = await router.tenancy.previewInvitation(
            brandString<RegistryAccountId>(identity.accountId), invitationToken.token)
          succeed(response, { invitation: invitationPreviewResult(preview) })
        } else if (route.kind === 'invitation-accept') {
          succeed(response, await acceptInvitation(ctx, request, controller.signal,
            invitationToken.token, config.maxValueBytes))
        } else {
          const declined = await router.tenancy.declineInvitation(tenancyAccount(identity), invitationToken.token)
          succeed(response, { invitation: invitationPreviewResult(declined) })
        }
        return
      }
      if (route.kind === 'test-only-revoke') {
        if (runtime.testOnlyRevoke === undefined) throw new ApiFailure(404, 'not-found')
        const address = request.socket.remoteAddress
        if (admission === undefined || address === undefined || testOnlyRevokeConsumed) {
          throw new ApiFailure(404, 'not-found')
        }
        assertTestOnlyRequest(request)
        requireAdmission(ctx, admission.admitDirectPeer(address, request.headers['x-forwarded-for']), 'client-address')
        // Consume before entering the durable queue so concurrent or repeated acceptance calls cannot add audit pressure.
        testOnlyRevokeConsumed = true
        succeed(response, await revokeTestSeed(ctx, request, controller.signal, runtime.testOnlyRevoke))
        return
      }
      if (route.kind === 'binding-start' || route.kind === 'binding-confirm') {
        const enrollment = selectedRuntime?.enrollment ?? ctx.get('registryEnrollment')
        if (enrollment === undefined) throw new ApiFailure(503, 'registry-not-configured')
        if (route.kind === 'binding-start') {
          if (enrollmentInput?.action !== 'start') throw new ApiFailure(503, 'unavailable')
          const ticket = await enrollment.start(enrollmentInput.value)
          requireOperationActive(controller.signal)
          succeed(response, bindingTicketResult(ticket, config.maxValueBytes))
        } else {
          if (enrollmentInput?.action !== 'confirm') throw new ApiFailure(503, 'unavailable')
          const receipt = await enrollment.confirm(route.bindingId, enrollmentInput.proof)
          requireOperationActive(controller.signal)
          succeed(response, bindingReceiptResult(receipt, { bindingId: route.bindingId, phase: 'confirmed' }))
        }
        return
      }
      if (route.kind === 'invitations' || route.kind === 'invitation-revoke') {
        if (route.organizationId === undefined) throw new ApiFailure(404, 'not-found')
        const { identity, account } = await invitationActor(ctx, request, controller.signal, route.organizationId)
        if (admission !== undefined && (route.kind === 'invitation-revoke' || request.method === 'POST')) {
          requireAdmission(ctx, admission.admitAccount(account.subject.organizationId,
            account.subject.memberId), 'account')
        }
        const router = ctx.get('registryTenantRouter')
        if (router === undefined) throw new ApiFailure(503, 'registry-not-configured')
        const accountId = brandString<RegistryAccountId>(identity.accountId)
        if (route.kind === 'invitation-revoke') {
          const revoked = await router.tenancy.revokeInvitation(accountId, account.subject.memberId,
            account.subject.role, route.organizationId, route.invitationId)
          succeed(response, { invitation: invitationResult(revoked) })
        } else if (request.method === 'POST') {
          if (invitationCreateInput === undefined) throw new ApiFailure(503, 'unavailable')
          const created = await router.tenancy.createInvitation(accountId, account.subject.memberId,
            account.subject.role, route.organizationId, invitationCreateInput)
          succeed(response, { invitation: invitationResult(created.invitation), token: created.token })
        } else {
          const items = await router.tenancy.listInvitations(accountId, account.subject.memberId,
            account.subject.role, route.organizationId)
          succeed(response, { items: items.map(invitationResult) })
        }
        return
      }
      if (route.kind === 'binding-account-action') {
        const { enrollment, authority, authenticatedSubject } = await enrollmentAuthority(ctx, request,
          controller.signal, route.organizationId, selectedRuntime)
        if (admission !== undefined) {
          requireAdmission(ctx, admission.admitAccount(authenticatedSubject.organizationId,
            authenticatedSubject.memberId), 'account')
        }
        if (enrollmentInput?.action !== route.action) throw new ApiFailure(503, 'unavailable')
        if (enrollmentInput.action === 'approve') {
          const receipt = await enrollment.approve(authority, route.bindingId, enrollmentInput.code,
            enrollmentInput.instanceName)
          bindingReceiptResult(receipt, { bindingId: route.bindingId, phase: 'approved' })
          requireOperationActive(controller.signal)
        } else if (enrollmentInput.action === 'reject') {
          const receipt = await enrollment.reject(authority, route.bindingId, enrollmentInput.code)
          bindingReceiptResult(receipt, { bindingId: route.bindingId, phase: 'rejected' })
          requireOperationActive(controller.signal)
        }
        const value = await enrollment.review(authority, route.bindingId, enrollmentInput.code, config.maxValueBytes)
        requireOperationActive(controller.signal)
        succeed(response, bindingReviewResult(value, {
          bindingId: route.bindingId,
          organizationId: authenticatedSubject.organizationId,
        }, config.maxValueBytes))
        return
      }
      if (route.kind === 'instances' || route.kind === 'instance-action') {
        const { enrollment, authority, authenticatedSubject } = await enrollmentAuthority(ctx, request,
          controller.signal, route.organizationId, selectedRuntime)
        if (route.kind === 'instances') {
          const value = await enrollment.list(authority, config.maxValueBytes)
          succeed(response, instancesResult(value, config.maxValueBytes))
          return
        }
        if (admission !== undefined) {
          requireAdmission(ctx, admission.admitAccount(authenticatedSubject.organizationId,
            authenticatedSubject.memberId), 'account')
        }
        if (instanceInput === undefined || instanceInput.action !== route.action) {
          throw new ApiFailure(503, 'unavailable')
        }
        const receipt = instanceInput.action === 'rename'
          ? await enrollment.rename(authority, route.bindingId, instanceInput.instanceName)
          : await enrollment.revoke(authority, route.bindingId)
        if (receipt.bindingId !== route.bindingId
          || receipt.state.kind !== (instanceInput.action === 'rename' ? 'confirmed' : 'revoked')) {
          throw new ApiFailure(503, 'unavailable')
        }
        requireOperationActive(controller.signal)
        const value = await enrollment.inspect(authority, route.bindingId, config.maxValueBytes)
        succeed(response, updatedInstanceResult(value, { bindingId: route.bindingId, action: instanceInput },
          config.maxValueBytes))
        return
      }
      if (route.kind === 'directory') {
        const { directory, authority, authenticatedSubject } = await directoryAuthority(ctx, request,
          controller.signal, route.organizationId, selectedRuntime)
        if (request.method === 'POST') {
          if (admission !== undefined) requireAdmission(ctx, admission.admitAccount(authenticatedSubject.organizationId,
            authenticatedSubject.memberId), 'account')
          if (directoryChangeInput === undefined) throw new ApiFailure(503, 'unavailable')
          const receipt = await directory.change(authority, directoryChangeInput.change,
            directoryChangeInput.expectedRevision)
          requireOperationActive(controller.signal)
          if (directoryChangeInput.change.kind === 'put-member') {
            const router = ctx.get('registryTenantRouter')
            if (router !== undefined) {
              const member = directoryChangeInput.change.member
              await router.tenancy.syncMembershipFromDirectory(authenticatedSubject.organizationId,
                member.memberId, member.role, member.state)
              requireOperationActive(controller.signal)
            }
          }
          succeed(response, { revision: receipt.revision, invalidatedDisclosures: receipt.invalidatedDisclosures })
          return
        }
        const value = await directory.read(authority, 'administration', config.maxValueBytes)
        succeed(response, directoryResult(value, authenticatedSubject.role, config.maxValueBytes))
        return
      }
      if (route.kind === 'billing-plans' || route.kind === 'billing-checkout') {
        const provider = ctx.get('registryBillingProvider')
        if (provider === undefined) throw new ApiFailure(501, 'operation-not-configured')
        const subject = await billingOwner(ctx, request, controller.signal, route.organizationId)
        if (admission !== undefined) requireAdmission(ctx, admission.admitAccount(subject.organizationId,
          subject.memberId), 'account')
        if (route.kind === 'billing-plans') {
          const plans = await provider.listPlans(subject, controller.signal)
          requireOperationActive(controller.signal)
          succeed(response, billingPlansResult(plans, config.maxValueBytes))
          return
        }
        if (checkoutInput === undefined) throw new ApiFailure(503, 'unavailable')
        const checkout = await provider.createCheckout({ subject, ...checkoutInput }, controller.signal)
        requireOperationActive(controller.signal)
        succeed(response, billingCheckoutResult(checkout, config.maxValueBytes))
        return
      }
      if (route.kind === 'audit') {
        const { reader, authority } = await auditAuthority(ctx, request, controller.signal, route.organizationId,
          selectedRuntime)
        const value = await reader.list(authority, {
          pageSize: config.pageSize, maxPageSize: config.pageSize, maxResponseBytes: config.maxValueBytes,
          ...(route.cursor === undefined ? {} : { cursor: route.cursor }),
        })
        succeed(response, auditResult(value, config.pageSize, config.maxValueBytes))
        return
      }
      const { reader, enrollment, authority, authenticatedSubject, authorizedSubject } = await requestAuthority(ctx,
        request, controller.signal, route.kind === 'branches' ? 'unavailable' : 'not-found', route.organizationId,
        selectedRuntime)
      if (route.kind === 'operation' && admission !== undefined) {
        requireAdmission(ctx, admission.admitAccount(authenticatedSubject.organizationId,
          authenticatedSubject.memberId), 'account')
      }
      if (route.kind === 'content') {
        const operations = ctx.get('registryDisclosureOperations')
        if (operations?.readContent === undefined) throw new ApiFailure(501, 'operation-not-configured')
        const metadata = await reader.readMetadata(authority, route.disclosureId, 'read', {
          checkpointHash: route.checkpointHash, maxResponseBytes: config.maxValueBytes,
        })
        const prefix = await reader.readPrefix(authority, route.disclosureId, metadata.instanceId,
          'read', route.checkpointHash)
        requireOperationActive(controller.signal)
        const decrypted = await operations.readContent(prefix, config.maxValueBytes, controller.signal)
        const current = await reader.readPrefix(authority, route.disclosureId, metadata.instanceId,
          'read', route.checkpointHash)
        requireOperationActive(controller.signal)
        if (current.checkpoint.checkpointHash !== prefix.checkpoint.checkpointHash) {
          throw new RegistryIngestError('not-found')
        }
        succeed(response, contentResult(decrypted, route.checkpointHash, config.maxValueBytes))
        return
      }
      if (route.kind === 'branches') {
        const operations = ctx.get('registryDisclosureOperations')
        if (operations?.listQuestions === undefined) throw new ApiFailure(501, 'operation-not-configured')
        const providerResult = await operations.listQuestions({
          subject: authenticatedSubject,
          selectDisclosure: async (selectedDisclosureId, sourceInstanceId, operationSignal) => {
            requireOperationActive(operationSignal)
            const value = await reader.readMetadata(authority, selectedDisclosureId, 'ask', {
              maxResponseBytes: config.maxValueBytes,
            })
            const selectedSubject = authorizedSubject()
            if (value.instanceId !== sourceInstanceId) throw new RegistryIngestError('not-found')
            return operationSelection(reader, enrollment, authority, selectedSubject, value, selectedDisclosureId,
              'ask', config.maxValueBytes)
          },
        }, { pageSize: config.pageSize, ...(route.cursor === undefined ? {} : { cursor: route.cursor }) },
        controller.signal)
        requireOperationActive(controller.signal)
        succeed(response, questionListResult(providerResult, config.pageSize, config.maxValueBytes))
        return
      }
      if (route.kind === 'list') {
        const value = await reader.list(authority, {
          pageSize: config.pageSize, maxPageSize: config.pageSize, maxResponseBytes: config.maxValueBytes,
          ...(route.cursor === undefined ? {} : { cursor: route.cursor }),
        })
        succeed(response, value)
      } else {
        const value = await reader.readMetadata(authority, route.disclosureId,
          route.kind === 'detail' ? 'read' : route.kind === 'operation' ? route.action
            : route.kind === 'question' ? 'ask' : 'import',
          { maxResponseBytes: config.maxValueBytes })
        if (route.kind === 'detail') succeed(response, value)
        else {
          const operations = ctx.get('registryDisclosureOperations')
          if (operations === undefined) throw new ApiFailure(501, 'operation-not-configured')
          const selectedSubject = authorizedSubject()
          const action = route.kind === 'question' ? 'ask' : route.kind === 'operation' ? route.action : 'import'
          const selection = operationSelection(reader, enrollment, authority, selectedSubject, value, route.disclosureId,
            action, config.maxValueBytes)
          if (route.kind === 'import-targets') {
            if (operations.listImportTargets === undefined) throw new ApiFailure(501, 'operation-not-configured')
            const providerResult = await operations.listImportTargets(selection, controller.signal)
            succeed(response, importTargetsResult(providerResult, config.pageSize))
            return
          }
          if (route.kind === 'import-status') {
            if (operations.readImport === undefined) throw new ApiFailure(501, 'operation-not-configured')
            const providerResult = await operations.readImport(selection, route.operationId, controller.signal)
            succeed(response, importOperationResult(providerResult))
            return
          }
          if (route.kind === 'question') {
            let providerResult: unknown
            if (request.method === 'GET') {
              if (operations.readQuestion === undefined) throw new ApiFailure(501, 'operation-not-configured')
              providerResult = await operations.readQuestion(selection, route.requestId, controller.signal)
            } else {
              if (operations.cancelQuestion === undefined) throw new ApiFailure(501, 'operation-not-configured')
              providerResult = await operations.cancelQuestion(selection, route.requestId, controller.signal)
            }
            succeed(response, questionOperationResult(providerResult, config.maxValueBytes))
            return
          }
          if (input === undefined) throw new ApiFailure(503, 'unavailable')
          let providerResult: unknown
          if (input.action === 'import') {
            if (operations.importDisclosure === undefined) throw new ApiFailure(501, 'operation-not-configured')
            providerResult = await operations.importDisclosure(selection, input.value, controller.signal)
          } else {
            if (operations.askDisclosure === undefined) throw new ApiFailure(501, 'operation-not-configured')
            providerResult = await operations.askDisclosure(selection, input.value, controller.signal)
          }
          const result = input.action === 'import'
            ? importOperationResult(providerResult)
            : questionOperationResult(providerResult, config.maxValueBytes)
          succeed(response, result)
        }
      }
    } catch (error) {
      if (!response.headersSent && !response.destroyed) fail(response, mapFailure(error))
    } finally {
      tenantLease?.release()
      request.off('aborted', cancel)
      response.off('close', cancel)
      active.delete(controller)
    }
  } })
  let disposed = false
  return () => {
    if (disposed) return
    disposed = true
    unregister()
    for (const controller of active) controller.abort()
    active.clear()
  }
}
