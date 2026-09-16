/** Consumer records; runtime signature and storage implementations stay on the Host. */
import type { DisclosureCheckpoint, DisclosureConversationId, DisclosureEventEnvelope, DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { InstanceKeyHistory, InstanceVerificationContext } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DisclosureAccess, DisclosureAction, DisclosureSubject } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { REGISTRY_INGEST_ERROR_CODES } from './record.ts'

/** Trusted adapter output, obtained afresh inside each serialized operation, never decoded from its request body. */
export interface RegistryProducerAuthority {
  readonly connection: InstanceVerificationContext
  readonly history: InstanceKeyHistory
}

/** Fresh account membership and source-instance history, resolved by the authenticated Registry adapter. */
export interface RegistryReaderAuthority {
  readonly subject: DisclosureSubject
  readonly history: InstanceKeyHistory
  readonly now: number
}

/** Authentication callbacks check current session/device revocation and active binding-owner membership.
 * Returned facts are detached and trusted. */
export type FreshProducerAuthority = () => RegistryProducerAuthority | Promise<RegistryProducerAuthority>
/** Membership and device facts must be current at callback completion; no grant-time team expansion. */
export type FreshReaderAuthority = () => RegistryReaderAuthority | Promise<RegistryReaderAuthority>

/** One current organization snapshot. The synchronous resolver uses only Registry-owned key history. */
export interface RegistryMetadataAuthority {
  readonly subject: DisclosureSubject
  readonly now: number
  /** Resolve an instance within subject.organizationId.
   * @param instanceId - Stored source selected after disclosure access is authorized.
   * @returns Current trusted key history, or null to deny that disclosure. */
  historyFor(instanceId: DshInstanceId): InstanceKeyHistory | null
}

/** Obtained once inside the serialized page operation; not a membership transaction across owners. */
export type FreshRegistryMetadataAuthority = () => RegistryMetadataAuthority | Promise<RegistryMetadataAuthority>

/** Reader operations exposed for this authenticated subject without returning grants or stored capability lists. */
export type RegistryAuthorizedAction = Extract<DisclosureAction, 'read' | 'import' | 'ask'>

/** Authorized confirmed-prefix metadata; no title, conversation identity, body, grants or key material. */
export interface RegistryDisclosureMetadata extends Pick<DisclosureAccess,
  'organizationId' | 'disclosureId' | 'instanceId' | 'control' | 'producer' | 'ingest' | 'expiresAt' | 'authorizationVersion'> {
  readonly authorizedActions: readonly RegistryAuthorizedAction[]
  /** Registry clock captured when the selected signed checkpoint became durable. */
  readonly checkpointVerifiedAt: number
  readonly checkpoint: Pick<DisclosureCheckpoint,
    'checkpointHash' | 'policyVersion' | 'sourceCursor' | 'eventCount' | 'lastDisclosureSeq' | 'lastEventHash'>
}

/** Point-read output bound supplied by the trusted consumer; selected checkpoints never fall back. */
export interface RegistryMetadataReadOptions {
  readonly maxResponseBytes: number
  readonly checkpointHash?: DisclosureHash
}

/** The consumer clamps request pageSize against its own maxPageSize and complete JSON byte bound. */
export interface RegistryMetadataListOptions {
  readonly pageSize: number
  readonly maxPageSize: number
  readonly maxResponseBytes: number
  /** Owner-local authenticated anchor, not authorization or a durable snapshot. Reopen restarts pagination. */
  readonly cursor?: string
}

/** No total or scanned count; nextCursor exists only when another currently authorized row exists. */
export interface RegistryMetadataPage {
  readonly items: readonly RegistryDisclosureMetadata[]
  readonly nextCursor: string | null
}

/** Explicit resource limits; no deployment default is selected by this library. */
export interface RegistryIngestLimits {
  readonly maxInputBytes: number
  readonly maxAggregateBytes: number
  readonly maxEvents: number
  /** All accepted checkpoint verification receipts remain retained until deletion; no eviction. */
  readonly maxCheckpoints: number
  readonly maxDisclosures: number
  /** Metadata audit is a bounded recent-history window; deletion retains only its deletion entry. */
  readonly maxAuditEntries: number
}

/** Initial access is owner-selected; the store requires active control, pending ingest and no checkpoint. */
export interface RegistryDisclosureRegistration {
  readonly access: DisclosureAccess
  readonly conversationId: DisclosureConversationId
  readonly policyVersion: number
}

/** Metadata acknowledgement emitted only after the aggregate is durable. */
export interface RegistryIngestReceipt {
  readonly disclosureId: DisclosureId
  readonly lastDisclosureSeq: number
  readonly lastEventHash: DisclosureHash | null
  readonly checkpointHash: DisclosureHash | null
  readonly authorizationVersion: number
  readonly control: DisclosureAccess['control']
  readonly ingest: DisclosureAccess['ingest']
}

/** A confirmed local authorization-version change; neither current authority nor a replayable delivery receipt. */
export interface RegistryDisclosureInvalidation {
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly disclosureId: DisclosureId
  readonly authorizationVersion: number
}

/** A successful checkpoint operation, including retries of an older retained checkpoint. */
export interface RegistryCheckpointReceipt extends RegistryIngestReceipt {
  /** This request's durably accepted checkpoint; checkpointHash remains the latest published selector. */
  readonly acceptedCheckpointHash: DisclosureHash
}

/** Current source-owned synchronization metadata, not an upload grant or an authorization lease. */
export type RegistryProducerSyncStatus =
  | {
    /** A retained disclosure, including paused, retired or frozen states; not permission to upload. */
    readonly kind: 'live'
    /** Stored expiry, even when it has elapsed; reading status does not advance control state. */
    readonly expiresAt: number
    /** Trusted Registry observation time; consumer clocks do not decide whether expiry has already elapsed. */
    readonly observedAt: number
    readonly receipt: RegistryIngestReceipt
  }
  | {
    /** Content and chain receipts were erased; no empty-prefix acknowledgement is implied. */
    readonly kind: 'deleted'
    readonly disclosureId: DisclosureId
    readonly authorizationVersion: number
  }

/** Only a signed, complete, currently authorized prefix leaves the store. */
export interface RegistryConfirmedPrefix {
  readonly authorizationVersion: number
  /** Stored source conversation identity, including for a confirmed empty prefix. */
  readonly conversationId: DisclosureConversationId
  readonly checkpoint: DisclosureCheckpoint
  readonly events: readonly DisclosureEventEnvelope[]
}

/** Trusted server maintenance selection; never decoded from a reader or producer request. */
export interface RegistryDeletionBatchOptions {
  readonly organizationId: OrganizationId
  /** Server clock captured for this batch; active/paused rows retire only at or after expiry. */
  readonly now: number
  /** Maximum atomic disclosure replacements in one batch. */
  readonly maxItems: number
  /** Stops admission of another item; an already-started write still drains to its real outcome. */
  readonly signal?: AbortSignal
}

/** Administrative progress, not a reader-visible count or a cross-organization cursor. */
export interface RegistryDeletionBatchReceipt {
  readonly deleted: number
  /** Another currently eligible row remains, including when cancellation stopped this batch. */
  readonly hasMore: boolean
}

/** Public diagnostics contain categories only, never ciphertext, input values, key material or backend errors. */
export type RegistryIngestErrorCode = (typeof REGISTRY_INGEST_ERROR_CODES)[number]
