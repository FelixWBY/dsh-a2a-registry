/** Internal text queue adapters; transport authentication and authorization leases are host-owned. */
import type { A2aRequestState, DisclosureAccess, DisclosureSubject, DshInstanceId, MemberId, OrganizationId, QueuedA2aRequest, VerifiedDisclosureCheckpoint } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { SessionId } from '@deepseek-ai/dsh-session/types'

/** Immutable request identity, including the authorization version selected by its requester. */
export interface MailboxBinding extends Omit<QueuedA2aRequest, 'state'> {
  readonly instanceId: DshInstanceId
}

/** Explicit complete-text, ciphertext, lifetime, materialized-request, and owner-admission bounds. */
export interface MailboxLimits {
  readonly maxTextBytes: number
  readonly maxTextCharacters: number
  readonly maxCiphertextBytes: number
  readonly maxAggregateBytes: number
  /** Active requests plus terminal requests whose reply body is still retained; idempotency tombstones do not consume it. */
  readonly maxRequests: number
  /** Hard bound for every durable request identity, including metadata-only idempotency tombstones. */
  readonly maxRetainedRequests: number
  readonly maxPendingOperations: number
  readonly maxLifetimeMs: number
}

/** A real authorization owner holds membership/disclosure versions stable until commit settles. */
export interface MailboxAuthorizationLease {
  readonly actor: MailboxActor
  readonly subject: DisclosureSubject
  readonly access: DisclosureAccess | null
  /** Exact pinned prefix verified inside this lease; null denies delivery. Never accept request JSON as proof. */
  readonly checkpoint: VerifiedDisclosureCheckpoint | null
  readonly now: number
  readonly sourceOnline: boolean
  readonly signal: AbortSignal
  /** Throw on released scope, invalidated actor/membership/source keys, aborted authority,
   * or a changed authorization version, including null access. */
  assertCurrent(authorizationVersion: number | null): void
}

/** Authenticated active connection identity supplied by the trusted lease owner, never request JSON. */
export type MailboxActor =
  | { readonly kind: 'requester'; readonly organizationId: OrganizationId; readonly memberId: MemberId }
  | { readonly kind: 'source'; readonly organizationId: OrganizationId; readonly instanceId: DshInstanceId }

/** The lease owner must authenticate the actor required by this operation before invoking commit. */
export type MailboxOperation = 'enqueue' | 'dispatch' | 'status' | 'reply' | MailboxTransition['state']

/** Must invoke and await commit exactly once under the current lease, observe abort while acquiring it, and never retain commit. */
export type WithMailboxAuthorization = (
  binding: Readonly<MailboxBinding>, operation: MailboxOperation, commit: (lease: MailboxAuthorizationLease) => Promise<void>,
  signal: AbortSignal,
) => Promise<void>

/** Mandatory trusted authenticated-encryption adapter; no keys or plaintext are persisted by the queue. */
export interface MailboxTextCodec {
  /** Seal UTF-8 text with fresh nonce and the exact AAD; return complete canonical base64url bytes. */
  seal(text: string, aad: string, signal: AbortSignal): Promise<string>
  /** Authenticate the exact AAD before returning complete UTF-8 text; reject malformed plaintext. */
  open(ciphertext: string, aad: string, signal: AbortSignal): Promise<string>
}

/** Opening scope: abort stops all admission and body release; close must still drain the owner. */
export interface MailboxOptions {
  readonly limits: MailboxLimits
  /** Registry-owned running lease. Expiry permits one version-fenced takeover; it does not extend request lifetime. */
  readonly executionLeaseMs: number
  readonly codec: MailboxTextCodec
  readonly withAuthorization: WithMailboxAuthorization
  readonly signal: AbortSignal
}

/** Trusted server selection for bounded expiry cleanup; never decode this from a mailbox request. */
export interface MailboxExpiryBatchOptions {
  /** Only records in this exact organization are eligible. */
  readonly organizationId: OrganizationId
  /** Server clock captured once for the batch. */
  readonly now: number
  /** Maximum individual record commits. */
  readonly maxItems: number
  /** Stops before another record; an admitted physical write still drains. */
  readonly signal?: AbortSignal
}

/** Metadata-only cleanup progress; retained request identities are never removed. */
export interface MailboxExpiryBatchReceipt {
  readonly cleaned: number
  /** Another currently eligible record remains after the bounded or cancelled batch. */
  readonly hasMore: boolean
}

/** Metadata-only durable receipt. Digests identify text; they are not encryption or authorization. */
export interface MailboxReceipt {
  readonly binding: MailboxBinding
  readonly state: A2aRequestState
  readonly version: number
  readonly authorizationVersion: number
  readonly questionHash: string
  readonly replyHash: string | null
  readonly updatedAt: number
}

/** Delivery is at-least-once; the instance must durably claim the request before creating a branch. */
export type MailboxDispatch = { readonly receipt: MailboxReceipt; readonly question: string | null }

/** Authorized completed result; null text means its durable receipt remains but reply retention ended. */
export interface MailboxReply {
  readonly receipt: MailboxReceipt
  readonly text: string | null
}

/** No arbitrary transition or tool execution API is exposed. */
export type MailboxTransition =
  | { readonly state: 'running' | 'failed' | 'cancelled' }
  | { readonly state: 'completed'; readonly reply: string }

/** Local, metadata-only assignment. Repeated delivery returns this exact session ID. */
export interface MailboxConsumerClaim {
  readonly binding: MailboxBinding
  readonly questionHash: string
  readonly sessionId: SessionId
}

/** Stable sanitized categories; no user text, backend diagnostics, or ciphertext are included. */
export type MailboxErrorCode = 'invalid-input' | 'invalid-storage' | 'not-found' | 'conflict' | 'limit' | 'closed' | 'unavailable' | 'storage-failed' | 'authority-failed' | 'codec-failed'
