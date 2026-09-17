/** Optional Host adapters for authorized Registry disclosure operations. */
import type { Branded } from '@deepseek-ai/dsh-brand'
import type { DisclosureHash, DshInstanceId } from '@deepseek-ai/dsh-a2a-protocol'
import type { A2aRequestId, DisclosureSubject } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { RegistryDisclosureMetadata } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryConfirmedPrefix } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryTransportObservation } from './transport-observation.ts'

/** Opaque identity of one accepted context-import operation. */
export type RegistryImportOperationId = Branded<'A2ARegistryImportOperationId'>

/** Opaque Local Session identity returned only after the target adapter has created it. */
export type RegistryImportedSessionId = Branded<'A2ARegistryImportedSessionId'>

/** Reader-authorized resource selection fixed to one verified checkpoint. */
export interface RegistryDisclosureOperationSelection {
  /** Fresh account subject used by the immediately preceding reader authorization. */
  readonly subject: DisclosureSubject
  /** Body-free metadata whose checkpoint identifies the exact prefix for this operation. */
  readonly disclosure: RegistryDisclosureMetadata
  /** Reauthenticate the browser account and authorize one current receive target.
   * The Registry enrollment owner must confirm that the target belongs to this member,
   * remains confirmed, and retains the `a2a.receive` scope.
   * @param targetInstanceId - Provider-selected target identity; never a client-supplied binding claim.
   * @param signal - Execution lifetime for fresh account and binding authorization.
   * @returns The current authenticated transport observation for the authorized target.
   * @throws RegistryIngestError `not-found` when the target is not currently authorized. */
  readonly authorizeTarget: (targetInstanceId: DshInstanceId,
    signal: AbortSignal) => Promise<RegistryTransportObservation>
  /** Reauthenticate the browser account and list only its currently confirmed receive-capable bindings.
   * Absence of a live transport observation does not remove an otherwise eligible offline target. */
  readonly listAuthorizedTargets: (signal: AbortSignal) => Promise<readonly RegistryDisclosureImportTarget[]>
  /** Reauthenticate the browser account and source keys before reading an explicitly retained checkpoint.
   * @param expected - Provider-owned source and checkpoint recovered from durable operation state.
   * @param signal - Execution lifetime; an aborted operation does not begin another authority lookup.
   * @returns The complete verified prefix selected by expected, even when disclosure names a newer checkpoint. */
  readonly readAuthorizedPrefix: (expected: {
    readonly sourceInstanceId: DshInstanceId
    readonly checkpointHash: DisclosureHash
  }, signal: AbortSignal) => Promise<RegistryConfirmedPrefix>
}

/** Browser-selected Local DSH target for an isolated context import. */
export interface RegistryDisclosureImportInput {
  readonly targetInstanceId: DshInstanceId
  /** Stable browser retry key; the deployment provider persists it before accepting work. */
  readonly idempotencyKey: string
}

/** Browser-safe projection of one currently eligible import target. */
export interface RegistryDisclosureImportTarget {
  readonly instanceId: DshInstanceId
  readonly transport: 'connected' | 'not-observed'
  readonly acceptingA2A: boolean | null
  readonly activeRequests: number | null
}

/** Durable lifecycle state of one context-import operation. */
export type RegistryDisclosureImportStatus = 'queued' | 'completed' | 'failed'

/** Accepted context-import work; adapters never report success before accepting durable work. */
export interface RegistryDisclosureImportResult {
  readonly operationId: RegistryImportOperationId
  readonly status: RegistryDisclosureImportStatus
  readonly sessionId?: RegistryImportedSessionId
  /** Absolute credential-free target URL, present only after the target created the Session. */
  readonly sessionUrl?: string
}

/** Text-only question pinned to the authorized disclosure checkpoint. */
export interface RegistryDisclosureQuestionInput {
  readonly question: string
  /** Stable browser retry key; the deployment provider persists it before accepting work. */
  readonly idempotencyKey: string
}

/** Durable lifecycle state of one text-only A2A request. */
export type RegistryDisclosureQuestionStatus = 'queued' | 'delivered' | 'running' | 'completed'
  | 'failed' | 'cancelled' | 'expired'

/** Current durable A2A request identity and lifecycle state. */
export interface RegistryDisclosureQuestionResult {
  readonly requestId: A2aRequestId
  /** Exact disclosure checkpoint cited by this immutable question. */
  readonly checkpointHash: DisclosureHash
  readonly status: RegistryDisclosureQuestionStatus
  /** Present only for a completed request whose bounded text reply is available. */
  readonly reply?: string
}

/** Browser-safe plaintext event projected from one verified encrypted disclosure envelope. */
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

/** Minimal plaintext projection for one exact confirmed checkpoint. */
export interface RegistryDisclosureContent {
  readonly checkpointHash: DisclosureHash
  readonly events: readonly RegistryDisclosureContentEvent[]
}

/** Browser-safe metadata for one durable question request; it never contains text or internal digests. */
export interface RegistryDisclosureQuestionMetadata {
  readonly requestId: A2aRequestId
  readonly disclosureId: RegistryDisclosureMetadata['disclosureId']
  readonly sourceInstanceId: DshInstanceId
  readonly checkpointHash: DisclosureHash
  readonly status: RegistryDisclosureQuestionStatus
  readonly expiresAt: number
  readonly updatedAt: number
}

/** Bounded provider-owned continuation over currently authorized question metadata. */
export interface RegistryDisclosureQuestionPage {
  readonly items: readonly RegistryDisclosureQuestionMetadata[]
  /** Opaque provider cursor, or null when no further authorized row was observed. */
  readonly nextCursor: string | null
}

/** Current browser account plus the only Host-owned path for selecting each candidate disclosure. */
export interface RegistryDisclosureQuestionListScope {
  readonly subject: DisclosureSubject
  /** Reauthenticate the same account and authorize `ask` before the provider may expose one candidate. */
  readonly selectDisclosure: (disclosureId: RegistryDisclosureMetadata['disclosureId'],
    sourceInstanceId: DshInstanceId, signal: AbortSignal) => Promise<RegistryDisclosureOperationSelection>
}

/** Trusted Host pagination bound and an opaque provider cursor. */
export interface RegistryDisclosureQuestionListOptions {
  readonly pageSize: number
  readonly cursor?: string
}

/** Host-owned operation surface. In SaaS mode the Registry composes this surface and only delegates content projection. */
export interface RegistryDisclosureOperations {
  /** Project one already authorized confirmed prefix into browser-safe plaintext.
   * The browser adapter must freshly authorize the same fixed checkpoint both before and after this call.
   * @param prefix - Complete reader-verified prefix selected by its exact checkpoint.
   * @param maxResponseBytes - Complete plaintext response bound.
   * @param signal - Browser request lifetime.
   * @returns Minimal user-visible plaintext event projection. */
  readContent?(prefix: RegistryConfirmedPrefix, maxResponseBytes: number,
    signal: AbortSignal): Promise<RegistryDisclosureContent>
  /** List only durable question metadata owned by the current browser account.
   * Providers may scan private storage internally, but must prefilter its organization/member and then invoke
   * `selectDisclosure` plus their exact-checkpoint status authorization for every returned row. */
  listQuestions?(scope: RegistryDisclosureQuestionListScope, options: RegistryDisclosureQuestionListOptions,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionPage>
  /** List only this subject's confirmed bindings that retain the a2a.receive scope.
   * @param selection - freshly authorized subject and exact disclosure checkpoint.
   * @param signal - request lifetime for target observation.
   * @returns Current browser-safe targets; an unobserved target is not reported as offline. */
  listImportTargets?(selection: RegistryDisclosureOperationSelection,
    signal: AbortSignal): Promise<readonly RegistryDisclosureImportTarget[]>
  /** Accept an isolated import for an already authorized fixed prefix.
   * @param selection - Fresh account subject and reader-verified checkpoint metadata.
   * @param input - Canonical target instance selected by the browser.
   * @param signal - Request lifetime; the provider releases partial work before settling on abort.
   * @returns Durable operation identity and its current state. */
  importDisclosure?(selection: RegistryDisclosureOperationSelection, input: RegistryDisclosureImportInput,
    signal: AbortSignal): Promise<RegistryDisclosureImportResult>
  /** Read current durable import state after fresh authorization of its disclosure.
   * @param selection - Freshly authorized subject and current disclosure metadata; queued recovery reauthorizes its stored checkpoint.
   * @param operationId - provider-owned import operation to inspect.
   * @param signal - request lifetime for the durable state read.
   * @returns Current state and completed Session fields only when available. */
  readImport?(selection: RegistryDisclosureOperationSelection, operationId: RegistryImportOperationId,
    signal: AbortSignal): Promise<RegistryDisclosureImportResult>
  /** Accept a text-only A2A question for an already authorized fixed prefix.
   * @param selection - Fresh account subject and reader-verified checkpoint metadata.
   * @param input - Complete bounded question text.
   * @param signal - Request lifetime; the provider releases partial work before settling on abort.
   * @returns Durable request identity and its current state. */
  askDisclosure?(selection: RegistryDisclosureOperationSelection, input: RegistryDisclosureQuestionInput,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult>
  /** Read the current state and optional completed reply after fresh Registry authorization.
   * @param selection - freshly authorized subject and exact disclosure checkpoint.
   * @param requestId - provider-owned A2A request to inspect.
   * @param signal - request lifetime for the durable state read.
   * @returns Current request state and a reply only when completed. */
  readQuestion?(selection: RegistryDisclosureOperationSelection, requestId: A2aRequestId,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult>
  /** Cancel queued work after fresh Registry authorization; running work is provider-defined failure.
   * @param selection - freshly authorized subject and exact disclosure checkpoint.
   * @param requestId - provider-owned queued request to cancel.
   * @param signal - request lifetime for the durable transition.
   * @returns Current request state after the cancellation attempt. */
  cancelQuestion?(selection: RegistryDisclosureOperationSelection, requestId: A2aRequestId,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Present only while a complete Registry-owned or standalone operation surface is active. */
    registryDisclosureOperations: RegistryDisclosureOperations
  }
}
