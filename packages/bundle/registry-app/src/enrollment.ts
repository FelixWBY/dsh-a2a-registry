/** Host enrollment operations share Registry directory and storage ownership, without issuing credentials. */
import type { FreshRegistryDirectoryAuthority, RegistryBindingId, RegistryBindingReceipt, RegistryBindingRequest, RegistryBindingReview,
  RegistryBindingTicket } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryTransportObservation } from './transport-observation.ts'

/** Owner-visible binding metadata plus an ephemeral observation, not public discovery or business availability. */
export interface RegistryBindingInspection extends RegistryBindingReview {
  readonly transport: RegistryTransportObservation
}

/** Explicit runtime capability for durable device enrollment candidates, not account login or a network endpoint. */
export interface RegistryEnrollment {
  /** Find the current account's confirmed and revoked instances without retained enrollment codes.
   * @param authority - Fresh identity checked against current persisted membership inside the shared owner queue.
   * @param maxResponseBytes - Positive complete JSON array byte bound; an oversized result is rejected, never truncated.
   * @returns Detached metadata ordered by binding ID with current transport observations after core metadata audit completion.
   * The complete augmented result is bounded separately; observations are not historical presence or business status. */
  list(authority: FreshRegistryDirectoryAuthority, maxResponseBytes: number): Promise<readonly RegistryBindingInspection[]>
  /** Persist an attempt before returning the one-time code.
   * @param request - Public key, suggested name and requested device functions, copied before queuing.
   * @returns Durable attempt ticket, never a connection token. */
  start(request: RegistryBindingRequest): Promise<RegistryBindingTicket>
  /** Read current confirmation metadata without exposing code digests or challenge nonces.
   * @param authority - Trusted current account identity; the directory supplies membership.
   * @param bindingId - Server-generated attempt identifier.
   * @param code - Exact enrollment code.
   * @param maxResponseBytes - Trusted complete JSON response bound.
   * @returns Detached fingerprint, organization, instance and lifecycle fields, not device credentials. */
  review(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId, code: string,
    maxResponseBytes: number): Promise<RegistryBindingReview>
  /** Inspect the current account's confirmed or revoked instance without an enrollment code.
   * @param authority - Fresh account identity, rechecked against persisted membership and binding ownership.
   * @param bindingId - Confirmed or revoked binding selected by its owning account.
   * @param maxResponseBytes - Trusted bound on the complete JSON response.
   * @returns Detached metadata and current transport observation after core review-audit completion; no key bytes, digest or nonce.
   * The complete augmented result is bounded separately; not-observed does not establish device offline status. */
  inspect(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId,
    maxResponseBytes: number): Promise<RegistryBindingInspection>
  /** Reject a still-pending candidate without revoking an already approved device.
   * @param authority - Trusted current account identity, rechecked inside the shared owner.
   * @param bindingId - Server-generated attempt identifier.
   * @param code - Exact enrollment code.
   * @returns Durable terminal rejection; the same member's retry preserves its timestamp. */
  reject(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId, code: string): Promise<RegistryBindingReceipt>
  /** Revoke the authenticated account's confirmed instance binding without an enrollment code.
   * @param authority - Fresh external account identity, rechecked against the stored directory.
   * @param bindingId - Confirmed binding selected by its owning account.
   * @returns Durable terminal receipt; subsequent producer operations deny this binding.
   * The shared runtime closes matching sync sockets after commit; subsequent source reads deny access.
   * Reader leases and content deletion remain separate responsibilities. */
  revoke(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId): Promise<RegistryBindingReceipt>
  /** Rename the current account's confirmed instance without changing its key, scopes or confirmation time.
   * @param authority - Fresh account identity, rechecked against the persisted directory and binding owner.
   * @param bindingId - Confirmed binding selected by its owning account; no enrollment code is required.
   * @param instanceName - Exact trimmed name within the configured UTF-8 bound.
   * @returns Receipt after atomic name and enabled audit commit; matching-name retries preserve the binding. */
  rename(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId,
    instanceName: string): Promise<RegistryBindingReceipt>
  /** Commit approval by a currently authenticated organization member.
   * @param authority - Trusted external account mapping, evaluated after earlier runtime operations settle.
   * @param bindingId - Server-generated attempt identifier.
   * @param code - Exact one-time enrollment code.
   * @param instanceName - Account-selected name; approval accepts the unchanged requested device scopes together.
   * @returns Persisted approval receipt; directory membership is checked inside the shared owner. */
  approve(authority: FreshRegistryDirectoryAuthority, bindingId: RegistryBindingId, code: string,
    instanceName: string): Promise<RegistryBindingReceipt>
  /** Persist exact challenge proof after approval and current membership checks.
   * @param bindingId - Server-generated attempt identifier.
   * @param proof - Untrusted proof, copied before entering the runtime queue.
   * @returns Confirmed receipt, not upload authority; verified retries preserve confirmation time.
   * A failed copy queues an unattributed rejection without retaining the proof. */
  confirm(bindingId: RegistryBindingId, proof: unknown): Promise<RegistryBindingReceipt>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Present only with explicit enrollment configuration; retained handles reject after runtime disposal. */
    registryEnrollment: RegistryEnrollment
  }
}
