/** Exact version-one synchronization frames; identities and receipts retain their owning package types. */
import type { DisclosureCheckpoint, DisclosureConversationId, DisclosureEventEnvelope, DisclosureHash, DisclosureId,
  DisclosureSignature, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { RegistryChallenge, RegistryConnectionIdentity } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { RegistryCheckpointReceipt, RegistryIngestErrorCode, RegistryIngestReceipt,
  RegistryConfirmedPrefix, RegistryProducerSyncStatus } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { MemberId, TeamId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { MailboxBinding, MailboxReceipt, MailboxTransition } from '@deepseek-ai/dsh-a2a-mailbox'

export type { RegistryProducerSyncStatus } from '@deepseek-ai/dsh-a2a-registry-ingest'

/** Every request has a positive safe integer ID, strictly increasing within one connection. */
interface Frame {
  readonly protocolVersion: 1
  readonly requestId: number
}

/** Bounded producer report, never a Registry-derived availability state or permission to execute. */
export interface RegistryInstanceReport {
  /** Instance-reported business state; offline is a Registry observation, never a connected producer's claim. */
  readonly state: 'online' | 'busy' | 'paused' | 'degraded'
  /** Reported willingness only; device scopes, reader grants and broker admission still decide execution. */
  readonly acceptingA2A: boolean
  /** Number of currently executing A2A requests, not total local conversations or their identities. */
  readonly activeRequests: number
}

/** Exact authenticated Local instance whose receiver state a report source observes. */
export interface RegistryInstanceReportBinding {
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
}

/** Optional deployment-owned snapshot of this instance's current A2A receiver state. */
export interface RegistryInstanceReportSource {
  /** Immutable identity shared with the one presence connection that may publish this source's reports. */
  readonly binding: RegistryInstanceReportBinding
  /** Return current bounded state, or null when receiver state is intentionally unknown.
   * @param signal - heartbeat-attempt lifetime; abort stops the provider read.
   * @returns Current receiver state, or null when this deployment cannot observe it. */
  read(signal: AbortSignal): Promise<RegistryInstanceReport | null>
}

/** One source-authorized text delivery and its fixed disclosed prefix. */
export interface RegistryQuestionDelivery {
  readonly binding: MailboxBinding
  readonly receipt: MailboxReceipt
  readonly question: string
  readonly prefix: RegistryConfirmedPrefix
  readonly source: {
    readonly instanceName: string
    readonly conversationTitle: string
  }
}

/** One checkpoint-pinned context import released only to its authenticated target instance. */
export interface RegistryImportDelivery {
  readonly operationId: string
  /** Deterministic target Session identity; retries must create or return exactly this Session. */
  readonly expectedSessionId: string
  readonly targetInstanceId: DshInstanceId
  readonly organizationId: OrganizationId
  readonly disclosureId: DisclosureId
  readonly sourceInstanceId: DshInstanceId
  readonly checkpointHash: DisclosureHash
  readonly prefix: RegistryConfirmedPrefix
  readonly source: {
    readonly instanceName: string
    readonly conversationTitle: string
  }
}

/** Target result returned while Registry authorization for one import is still held. */
export type RegistryImportOutcome =
  | { readonly status: 'completed'; readonly sessionId: string }
  | { readonly status: 'retry' }

/** Explicit member or team selected by the source owner for one producer command. */
export type RegistryProducerTarget =
  | { readonly kind: 'member'; readonly memberId: MemberId }
  | { readonly kind: 'team'; readonly teamId: TeamId }

/** Minimal first-registration input; authenticated connection facts supply organization and source instance. */
export interface RegistryProducerRegistration {
  readonly conversationId: DisclosureConversationId
  readonly policyVersion: number
  readonly targets: readonly RegistryProducerTarget[]
  readonly expiresAt: number
}

/** Complete V1 access replacement; capabilities remain the Registry-owned fixed V1 set. */
export interface RegistryProducerAccessUpdate {
  readonly targets: readonly RegistryProducerTarget[]
  readonly expiresAt: number
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    registryInstanceReportSource: RegistryInstanceReportSource
  }
}

/** Only these operations may travel from a Local producer to the Registry. */
export type RegistryClientFrame = Frame & (
  | { readonly type: 'hello'; readonly token: string }
  | { readonly type: 'prove'; readonly signature: DisclosureSignature }
  | { readonly type: 'status'; readonly disclosureId: DisclosureId }
  | { readonly type: 'producer-register'; readonly disclosureId: DisclosureId; readonly registration: RegistryProducerRegistration }
  | {
    readonly type: 'producer-update-access'
    readonly disclosureId: DisclosureId
    readonly expectedAuthorizationVersion: number
    readonly update: RegistryProducerAccessUpdate
  }
  | {
    readonly type: 'producer-transition-control'
    readonly disclosureId: DisclosureId
    readonly expectedAuthorizationVersion: number
    readonly target: 'active' | 'paused' | 'revoked'
  }
  | { readonly type: 'producer-delete'; readonly disclosureId: DisclosureId; readonly expectedAuthorizationVersion: number }
  | { readonly type: 'event'; readonly disclosureId: DisclosureId; readonly envelope: DisclosureEventEnvelope }
  | { readonly type: 'checkpoint'; readonly disclosureId: DisclosureId; readonly checkpoint: DisclosureCheckpoint }
  | { readonly type: 'heartbeat'; readonly report?: RegistryInstanceReport }
  | { readonly type: 'question-dispatch'; readonly excludeRequestIds?: readonly MailboxBinding['requestId'][] }
  | { readonly type: 'question-start'; readonly binding: MailboxBinding; readonly expectedVersion: number }
  | { readonly type: 'question-renew'; readonly binding: MailboxBinding; readonly expectedVersion: number }
  | { readonly type: 'question-status'; readonly binding: MailboxBinding }
  | {
    readonly type: 'question-transition'
    readonly binding: MailboxBinding
    readonly expectedVersion: number
    readonly transition: MailboxTransition
  }
  | { readonly type: 'question-authorize'; readonly binding: MailboxBinding; readonly expectedVersion: number }
  | { readonly type: 'question-authorize-release'; readonly authorizationRequestId: number }
  | { readonly type: 'import-dispatch' }
  | { readonly type: 'import-release'; readonly authorizationRequestId: number; readonly outcome: RegistryImportOutcome }
)

/** Fixed content-free failure categories; provider diagnostics never cross the connection. */
export type RegistrySyncErrorCode = RegistryIngestErrorCode | 'unauthorized' | 'protocol' | 'busy'

/** Every response echoes the outstanding request ID; only one request may be in flight. */
export type RegistryServerFrame = Frame & (
  | { readonly type: 'challenge'; readonly challenge: RegistryChallenge }
  | { readonly type: 'authenticated'; readonly identity: RegistryConnectionIdentity }
  | { readonly type: 'status'; readonly status: RegistryProducerSyncStatus }
  | { readonly type: 'producer-register-ack'; readonly status: RegistryProducerSyncStatus }
  | { readonly type: 'producer-update-access-ack'; readonly status: RegistryProducerSyncStatus }
  | { readonly type: 'producer-transition-control-ack'; readonly status: RegistryProducerSyncStatus }
  | { readonly type: 'producer-delete-ack'; readonly status: RegistryProducerSyncStatus }
  | { readonly type: 'event-ack'; readonly receipt: RegistryIngestReceipt }
  | { readonly type: 'checkpoint-ack'; readonly receipt: RegistryCheckpointReceipt }
  | { readonly type: 'heartbeat-ack'; readonly observedAt: number }
  | { readonly type: 'question-dispatch'; readonly delivery: RegistryQuestionDelivery | null }
  | {
    readonly type: 'question-start'
    readonly receipt: MailboxReceipt
    readonly started: boolean
    readonly renewAfterMs: number
  }
  | { readonly type: 'question-renew'; readonly receipt: MailboxReceipt; readonly renewAfterMs: number }
  | { readonly type: 'question-status'; readonly receipt: MailboxReceipt }
  | { readonly type: 'question-transition'; readonly receipt: MailboxReceipt }
  | { readonly type: 'question-authorized'; readonly delivery: RegistryQuestionDelivery }
  | { readonly type: 'question-authorize-released'; readonly authorizationRequestId: number }
  | { readonly type: 'import-dispatch'; readonly delivery: RegistryImportDelivery | null }
  | { readonly type: 'import-released'; readonly authorizationRequestId: number }
  | { readonly type: 'error'; readonly code: RegistrySyncErrorCode }
)
