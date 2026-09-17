/** Enrollment candidate validation and transitions; the shared ingest owner must serialize and persist them. */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import { brandString } from '@deepseek-ai/dsh-brand'
import { decodeInstanceKeyHistory, decodeRegistryDeviceSecretHash,
  type InstanceKeyHistory, type InstanceKeyId, type RegistryDeviceSecretHash } from '@deepseek-ai/dsh-a2a-device-identity'
import { decodeRegistryAudience, decodeRegistryChallenge, verifyRegistryChallenge } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { DisclosureSubject, MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { RegistryDirectoryMember } from './directory-types.ts'
import type { RegistryBindingId, RegistryBindingLimits, RegistryBindingRecord, RegistryBindingRequest,
  RegistryBindingReview, RegistryBindingStart, RegistryBindingRecordV5 } from './binding-types.ts'
import type { RegistryProducerAuthority } from './types.ts'
import { byteLength, RegistryIngestError, requireIngest } from './record.ts'

const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const memberId = z.string().max(128).regex(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]*[A-Za-z0-9])?$/u)
  .transform(value => brandString<MemberId>(value))
const intent = { instanceName: z.string(), requestedScopes: z.array(z.enum(['disclosure.sync', 'a2a.receive']))
  .min(1).max(2).refine(value => new Set(value).size === value.length).readonly() }
const deviceSecretHash = z.string().regex(/^sha256:[0-9a-f]{64}$/u).transform(decodeRegistryDeviceSecretHash)
const requestSchema = z.strictObject({ publicKeySpki: z.string(), deviceSecretHash, ...intent })
const state = z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.literal('pending') }),
    z.strictObject({ kind: z.literal('approved'), memberId, approvedAt: integer }),
    z.strictObject({ kind: z.literal('confirmed'), memberId, approvedAt: integer, confirmedAt: integer }),
    z.strictObject({ kind: z.literal('rejected'), memberId, rejectedAt: integer }),
    z.strictObject({ kind: z.literal('revoked'), memberId, approvedAt: integer, confirmedAt: integer, revokedAt: integer }),
  ]).readonly()
const recordFields = {
  bindingId: z.uuid().transform(value => brandString<RegistryBindingId>(value)), ...intent,
  createdAt: integer, challenge: z.unknown().transform(decodeRegistryChallenge), publicKeySpki: z.string(),
  codeHash: z.string().regex(/^[0-9a-f]{64}$/u), state,
}
const schema = z.discriminatedUnion('version', [
  z.strictObject({ version: z.literal(4), ...recordFields }).readonly(),
  z.strictObject({ version: z.literal(5), ...recordFields, deviceSecretHash }).readonly(),
])

function history(record: RegistryBindingRecord): InstanceKeyHistory {
  const { organizationId, instanceId, keyId } = record.challenge
  return decodeInstanceKeyHistory({ organizationId, instanceId, status: 'active', keys: [{ keyId,
    publicKeySpki: record.publicKeySpki, validFrom: record.createdAt, validUntil: null, revokedAt: null }] })
}

function credentialHistory(record: RegistryBindingRecordV5 & {
  readonly state: Extract<RegistryBindingRecord['state'], { readonly kind: 'confirmed' }>
}): InstanceKeyHistory {
  const { organizationId, instanceId, keyId } = record.challenge
  return decodeInstanceKeyHistory({ organizationId, instanceId, status: 'active', keys: [{ keyId,
    publicKeySpki: record.publicKeySpki, validFrom: record.state.confirmedAt, validUntil: null, revokedAt: null }] })
}

function codeHash(code: string): string {
  return createHash('sha256').update(code, 'utf8').digest('hex')
}

function current(record: RegistryBindingRecord, now: number): void {
  requireIngest(Number.isSafeInteger(now) && now >= record.createdAt && now < record.challenge.expiresAt, 'not-found')
}

function name(value: string, limits: RegistryBindingLimits): void {
  requireIngest(value.length > 0 && value === value.trim() && !/[\u0000-\u001f\u007f]/u.test(value)
    && Buffer.byteLength(value, 'utf8') <= limits.maxNameBytes, 'invalid-input')
}

function account(record: RegistryBindingRecord, subject: DisclosureSubject, code: string, now: number): void {
  requireIngest(Number.isSafeInteger(now) && now >= record.createdAt && subject.authenticated && subject.membership === 'active'
    && subject.organizationId === record.challenge.organizationId && /^[A-Za-z0-9_-]{43}$/u.test(code)
    && codeHash(code) === record.codeHash, 'not-found')
  if (record.state.kind !== 'pending') requireIngest(record.state.memberId === subject.memberId, 'not-found')
  if (record.state.kind === 'approved') requireIngest(now >= record.state.approvedAt, 'not-found')
}

/** Validate the full stored candidate without exposing keys or parser diagnostics on failure.
 * @param input - Untrusted retained JSON.
 * @param limits - Explicit byte bound and enrollment lifetime.
 * @returns Detached candidate; this is not an authenticated instance history. */
export function parseBinding(input: unknown, limits: RegistryBindingLimits): RegistryBindingRecord {
  try {
    requireIngest(byteLength(input) <= limits.maxRecordBytes, 'invalid-storage')
    const record = schema.parse(input)
    name(record.instanceName, limits)
    requireIngest(record.challenge.expiresAt > record.createdAt
      && record.challenge.expiresAt - record.createdAt <= limits.ttlMs, 'invalid-storage')
    history(record)
    if (record.state.kind === 'rejected') {
      requireIngest(record.state.rejectedAt >= record.createdAt && record.state.rejectedAt < record.challenge.expiresAt, 'invalid-storage')
    } else if (record.state.kind !== 'pending') {
      requireIngest(record.state.approvedAt >= record.createdAt && record.state.approvedAt < record.challenge.expiresAt, 'invalid-storage')
      if (record.state.kind === 'confirmed' || record.state.kind === 'revoked') requireIngest(record.state.confirmedAt >= record.state.approvedAt
        && record.state.confirmedAt < record.challenge.expiresAt, 'invalid-storage')
      if (record.state.kind === 'revoked') requireIngest(record.state.revokedAt >= record.state.confirmedAt, 'invalid-storage')
    }
    return Object.freeze({ ...record, challenge: Object.freeze(record.challenge) })
  } catch {
    // Enrollment parser diagnostics must not disclose retained identity or request data.
    throw new RegistryIngestError('invalid-storage')
  }
}

/** Create a server-scoped attempt from an untrusted public key, without approving an account or issuing credentials.
 * @param organizationId - Fixed Registry owner organization.
 * @param audience - Trusted configured WSS destination.
 * @param request - Untrusted public key, instance-name suggestion and requested device functions.
 * @param now - Trusted server time.
 * @param limits - Explicit positive safe-integer limits.
 * @returns A one-time enrollment code and its candidate record; only the record may be persisted. */
export function startBinding(organizationId: OrganizationId, audience: string, request: RegistryBindingRequest,
  now: number, limits: RegistryBindingLimits): RegistryBindingStart {
  for (const value of [limits.ttlMs, limits.maxRecordBytes, limits.maxBindings, limits.maxNameBytes]) {
    requireIngest(Number.isSafeInteger(value) && value > 0, 'limit')
  }
  requireIngest(Number.isSafeInteger(now) && now >= 0 && Number.isSafeInteger(now + limits.ttlMs), 'invalid-input')
  requireIngest(byteLength(request) <= limits.maxRecordBytes, 'limit')
  let parsedRequest: RegistryBindingRequest
  try { parsedRequest = requestSchema.parse(request) } catch { throw new RegistryIngestError('invalid-input') }
  name(parsedRequest.instanceName, limits)
  const { publicKeySpki, deviceSecretHash: secretHash, instanceName, requestedScopes } = parsedRequest
  const code = randomBytes(32).toString('base64url')
  const record: RegistryBindingRecordV5 = { version: 5, bindingId: brandString<RegistryBindingId>(randomUUID()), createdAt: now,
    instanceName, requestedScopes, deviceSecretHash: secretHash,
    challenge: { version: 1, audience: decodeRegistryAudience(audience), organizationId,
      instanceId: brandString<DshInstanceId>(randomUUID()),
      keyId: brandString<InstanceKeyId>(`sha256:${createHash('sha256').update(Buffer.from(publicKeySpki, 'base64url')).digest('hex')}`),
      nonce: randomBytes(32).toString('base64url'), expiresAt: now + limits.ttlMs },
    publicKeySpki, codeHash: codeHash(code), state: { kind: 'pending' } }
  try {
    const parsed = parseBinding(record, limits)
    requireIngest(parsed.version === 5, 'invalid-input')
    const reserved = parseBinding({ ...parsed, state: { kind: 'revoked', memberId: 'x'.repeat(128),
      approvedAt: parsed.challenge.expiresAt - 1, confirmedAt: parsed.challenge.expiresAt - 1,
      revokedAt: Number.MAX_SAFE_INTEGER } }, limits)
    requireIngest(byteLength(reserved) - byteLength(instanceName) + 2 * limits.maxNameBytes + 2 <= limits.maxRecordBytes, 'invalid-input')
    return { code, record: parsed }
  } catch {
    throw new RegistryIngestError('invalid-input')
  }
}

/** Resolve one confirmed v5 binding into current device authority without exposing its stored digest.
 * The serialized owner supplies the current approving member and configured audience. */
export function authenticateBindingCredential(record: RegistryBindingRecord, member: RegistryDirectoryMember,
  presentedHash: RegistryDeviceSecretHash, now: number, audience: string): RegistryProducerAuthority {
  requireIngest(record.version === 5 && record.state.kind === 'confirmed'
    && member.memberId === record.state.memberId && member.state === 'active'
    && Number.isSafeInteger(now) && now >= record.state.confirmedAt
    && record.challenge.audience === audience, 'not-found')
  let selectedHash: RegistryDeviceSecretHash
  try { selectedHash = decodeRegistryDeviceSecretHash(presentedHash) } catch { throw new RegistryIngestError('not-found') }
  const retained = Buffer.from(record.deviceSecretHash.slice('sha256:'.length), 'hex')
  const presented = Buffer.from(selectedHash.slice('sha256:'.length), 'hex')
  requireIngest(retained.length === 32 && presented.length === 32 && timingSafeEqual(retained, presented), 'not-found')
  const currentHistory = credentialHistory(record as RegistryBindingRecordV5 & {
    readonly state: Extract<RegistryBindingRecord['state'], { readonly kind: 'confirmed' }>
  })
  const { organizationId, instanceId, keyId } = record.challenge
  requireIngest(currentHistory.organizationId === organizationId && currentHistory.instanceId === instanceId
    && currentHistory.keys.length === 1 && currentHistory.keys[0]?.keyId === keyId, 'not-found')
  return { connection: { organizationId, instanceId, keyId, now }, history: currentHistory }
}

/** Approve the candidate for the currently authenticated member; no device possession is inferred.
 * @param record - Current validated candidate in the serialized owner.
 * @param subject - Fresh externally authenticated identity with current directory-owned membership.
 * @param code - Untrusted enrollment code supplied by the confirming user.
 * @param instanceName - Account-selected name; a retry must retain the already approved name.
 * @param now - Trusted time after earlier operations settle.
 * @param limits - Explicit name and record bounds.
 * @returns Approved record, or the original record for the same member's exact approved retry.
 * Server time before the retained approval denies the operation. */
export function approveBinding(record: RegistryBindingRecord, subject: DisclosureSubject, code: string,
  instanceName: string, now: number, limits: RegistryBindingLimits): RegistryBindingRecord {
  current(record, now)
  account(record, subject, code, now)
  name(instanceName, limits)
  if (record.state.kind === 'approved') {
    requireIngest(record.instanceName === instanceName, 'conflict')
    return record
  }
  requireIngest(record.state.kind === 'pending', 'invalid-transition')
  return { ...record, instanceName, state: { kind: 'approved', memberId: subject.memberId, approvedAt: now } }
}

/** Read only the metadata a currently authenticated member can use to review an exact enrollment code.
 * @param record - Current owner-validated attempt.
 * @param subject - Fresh account identity with directory-owned membership.
 * @param code - Exact enrollment code; knowledge of an attempt ID alone is insufficient.
 * @param now - Trusted server time.
 * @returns Confirmation metadata; terminal results remain visible only to their original member with the code.
 * Server time before the retained approval or terminal transition denies the read. */
export function reviewBinding(record: RegistryBindingRecord, subject: DisclosureSubject, code: string,
  now: number): RegistryBindingReview {
  account(record, subject, code, now)
  if (record.state.kind === 'pending' || record.state.kind === 'approved') current(record, now)
  else requireIngest(now >= (record.state.kind === 'confirmed' ? record.state.confirmedAt
    : record.state.kind === 'revoked' ? record.state.revokedAt : record.state.rejectedAt), 'not-found')
  return metadata(record)
}

function metadata(record: RegistryBindingRecord): RegistryBindingReview {
  const { organizationId, instanceId, keyId, expiresAt } = record.challenge
  return { bindingId: record.bindingId, organizationId, instanceId, keyId, createdAt: record.createdAt,
    expiresAt, phase: record.state.kind, instanceName: record.instanceName, requestedScopes: record.requestedScopes }
}

/** Persist an account's terminal refusal of a still-pending attempt; approval is not reversible through rejection.
 * @param record - Current owner-validated attempt.
 * @param subject - Fresh account identity with directory-owned membership.
 * @param code - Exact enrollment code.
 * @param now - Trusted server time.
 * @returns Rejected candidate, or the same member's unchanged rejected retry, including after expiry. */
export function rejectBinding(record: RegistryBindingRecord, subject: DisclosureSubject, code: string,
  now: number): RegistryBindingRecord {
  account(record, subject, code, now)
  if (record.state.kind === 'rejected') {
    requireIngest(now >= record.state.rejectedAt, 'not-found')
    return record
  }
  current(record, now)
  requireIngest(record.state.kind === 'pending', 'invalid-transition')
  return { ...record, state: { kind: 'rejected', memberId: subject.memberId, rejectedAt: now } }
}

/** Verify device possession after approval and current member lookup; token issuance remains a separate owner operation.
 * @param record - Current approved candidate from the serialized owner, never a device-supplied record.
 * @param member - Current directory member matching the earlier account approval.
 * @param proof - Untrusted signature of this attempt's challenge.
 * @param now - Trusted server time.
 * @returns Confirmed record, or the unchanged confirmed record after verifying a retry.
 * The caller must persist first confirmation atomically; this operation never issues credentials. */
export function confirmBinding(record: RegistryBindingRecord, member: RegistryDirectoryMember, proof: unknown,
  now: number): RegistryBindingRecord {
  requireIngest((record.state.kind === 'approved' || record.state.kind === 'confirmed')
    && member.memberId === record.state.memberId && member.state === 'active', 'not-found')
  if (record.state.kind === 'approved') current(record, now)
  requireIngest(Number.isSafeInteger(now) && now >= record.state.approvedAt
    && (record.state.kind !== 'confirmed' || now >= record.state.confirmedAt), 'not-found')
  const verifiedAt = record.state.kind === 'confirmed' ? record.state.confirmedAt : now
  try {
    verifyRegistryChallenge(record.challenge, proof, history(record), { ...record.challenge, now: verifiedAt },
      { audience: record.challenge.audience, nonce: record.challenge.nonce })
  } catch { throw new RegistryIngestError('invalid-input') }
  return record.state.kind === 'confirmed' ? record : { ...record, state: { ...record.state, kind: 'confirmed', confirmedAt: now } }
}

/** Revoke a confirmed instance binding using its current owning account, without requiring the enrollment code.
 * @param record - Current owner-validated binding.
 * @param subject - Fresh authenticated account with directory-owned active membership.
 * @param now - Trusted server time, no earlier than the retained confirmation or revocation.
 * @returns Terminal revoked record; an exact owner's retry preserves the original revocation time. */
export function revokeBinding(record: RegistryBindingRecord, subject: DisclosureSubject, now: number): RegistryBindingRecord {
  const state = requireOwner(record, subject, now)
  return state.kind === 'revoked' ? record : { ...record, state: { ...state, kind: 'revoked', revokedAt: now } }
}

function requireOwner(record: RegistryBindingRecord, subject: DisclosureSubject, now: number):
Extract<RegistryBindingRecord['state'], { kind: 'confirmed' | 'revoked' }> {
  const state = record.state
  requireIngest(subject.authenticated && subject.membership === 'active'
    && subject.organizationId === record.challenge.organizationId
    && (state.kind === 'confirmed' || state.kind === 'revoked') && state.memberId === subject.memberId, 'not-found')
  requireIngest(Number.isSafeInteger(now) && now >= (state.kind === 'revoked' ? state.revokedAt : state.confirmedAt), 'not-found')
  return state
}

/** Read a confirmed or revoked instance's metadata using its owning account rather than an enrollment code.
 * @param record - Current owner-validated binding.
 * @param subject - Fresh authenticated owning account with directory-owned active membership.
 * @param now - Trusted server time, no earlier than the retained confirmation or revocation.
 * @returns Binding metadata after enrollment expiry, without code digests, public key bytes or challenge nonces.
 * Pending, approved and rejected attempts remain accessible only through code-authorized review. */
export function inspectBinding(record: RegistryBindingRecord, subject: DisclosureSubject, now: number): RegistryBindingReview {
  requireOwner(record, subject, now)
  return metadata(record)
}

/** Rename a confirmed instance without changing its key, scopes or lifecycle timestamps.
 * @param record - Current owner-validated binding.
 * @param subject - Fresh authenticated owning account with directory-owned active membership.
 * @param instanceName - Exact trimmed name within the configured UTF-8 bound.
 * @param now - Trusted server time, no earlier than confirmation.
 * @param limits - Explicit name and retained record bounds.
 * @returns Updated record, or the original record when the name already matches; no enrollment code is required. */
export function renameBinding(record: RegistryBindingRecord, subject: DisclosureSubject, instanceName: string,
  now: number, limits: RegistryBindingLimits): RegistryBindingRecord {
  requireIngest(record.state.kind === 'confirmed' && subject.authenticated && subject.membership === 'active'
    && subject.organizationId === record.challenge.organizationId && subject.memberId === record.state.memberId
    && Number.isSafeInteger(now) && now >= record.state.confirmedAt, 'not-found')
  name(instanceName, limits)
  return record.instanceName === instanceName ? record : { ...record, instanceName }
}
