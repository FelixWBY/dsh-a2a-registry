/** Browser-safe disclosure authorization and lifecycle records; no runtime imports. */
import type { Branded } from '@deepseek-ai/dsh-brand'
import type { DisclosureCheckpoint, DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'

export type { DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'

/** Organization-scoped member identity. */
export type MemberId = Branded<'A2AMemberId'>
/** Organization-scoped team identity. */
export type TeamId = Branded<'A2ATeamId'>
/** Independent text request identity. */
export type A2aRequestId = Branded<'A2ARequestId'>
/** Access lifecycle, independent from transport and ingest progress. */
export type DisclosureControlState = 'active' | 'paused' | 'revoked' | 'expired' | 'deleting' | 'deleted'
/** Local producer progress; offline does not invalidate a confirmed prefix. */
export type ProducerSyncState = 'idle' | 'backfilling' | 'live' | 'offline' | 'error_retryable' | 'error_conflict'
/** Registry publication eligibility. */
export type RegistryIngestState = 'pending' | 'ready' | 'frozen'
/** Text-only request lifecycle; terminal states never reopen. */
export type A2aRequestState = 'created' | 'queued' | 'delivered' | 'running' | 'completed' | 'expired' | 'cancelled' | 'failed'
/** Only capabilities admitted in the initial disclosure release. */
export type DisclosureCapability = 'conversation.read' | 'branch.create'
/** Read subscriptions and branch operations use the same authorization predicate. */
export type DisclosureAction = 'read' | 'subscribe' | 'import' | 'ask' | 'refresh'

/** Authenticated member facts loaded from the current organization membership. */
export interface DisclosureSubject {
  readonly organizationId: OrganizationId
  readonly memberId: MemberId
  readonly authenticated: boolean
  readonly membership: 'active' | 'suspended' | 'removed'
  readonly role: 'owner' | 'admin' | 'member'
  readonly currentTeamIds: readonly TeamId[]
}

/** Explicit, revocable, time-bounded member or team authorization. */
export interface DisclosureGrant {
  readonly target: { readonly kind: 'member'; readonly memberId: MemberId }
    | { readonly kind: 'team'; readonly teamId: TeamId }
  readonly state: 'active' | 'revoked'
  readonly capabilities: readonly DisclosureCapability[]
  readonly expiresAt: number
}

/** Registry access state read under the caller's storage transaction. */
export interface DisclosureAccess {
  readonly organizationId: OrganizationId
  readonly disclosureId: DisclosureId
  readonly instanceId: DshInstanceId
  readonly control: DisclosureControlState
  readonly producer: ProducerSyncState
  readonly ingest: RegistryIngestState
  readonly expiresAt: number
  readonly authorizationVersion: number
  readonly capabilities: readonly DisclosureCapability[]
  readonly grants: readonly DisclosureGrant[]
  /** Latest verified published checkpoint; selecting an older prefix never changes this field. */
  readonly checkpointHash: DisclosureHash | null
}

/**
 * Trusted checkpoint-verification facts obtained within the current authorization lease.
 * The owner verifies the exact retained prefix, signatures and current key revocation before supplying this value.
 * This typed record is not wire/JSON self-authentication; its version is necessary but is not a cross-await lease.
 */
export interface VerifiedDisclosureCheckpoint {
  readonly authorizationVersion: number
  readonly checkpoint: Pick<DisclosureCheckpoint, 'organizationId' | 'instanceId' | 'disclosureId' | 'checkpointHash'>
}

/** Public denial deliberately does not distinguish absent and unauthorized resources. */
export type DisclosureAuthorization = {
  readonly allowed: false
  readonly code: 'not-found'
} | {
  readonly allowed: true
  readonly authorizationVersion: number
  readonly checkpointHash: DisclosureHash
}

/** Fields whose committed changes invalidate prior authorization decisions. */
export interface DisclosureAccessUpdate {
  readonly expiresAt: number
  readonly capabilities: readonly DisclosureCapability[]
  readonly grants: readonly DisclosureGrant[]
}

/** Durable queue identity fixes the requesting member and imported context. */
export interface QueuedA2aRequest {
  readonly requestId: A2aRequestId
  readonly organizationId: OrganizationId
  readonly disclosureId: DisclosureId
  readonly requesterId: MemberId
  readonly checkpointHash: DisclosureHash
  readonly authorizationVersion: number
  readonly state: A2aRequestState
  readonly expiresAt: number
}

/** Dispatch remains a transaction-owned side effect after this decision is committed. */
export type A2aDispatchDecision = {
  readonly kind: 'deliver' | 'wait' | 'cancel' | 'expire' | 'settled'
  readonly request: QueuedA2aRequest
}
