/** Trusted Host-only disclosure commands sharing the active Registry storage owner. */
import type { DisclosureId } from '@deepseek-ai/dsh-a2a-protocol'
import type { DisclosureAccessUpdate, DisclosureControlState } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { FreshProducerAuthority, RegistryDisclosureRegistration,
  RegistryIngestReceipt, RegistryProducerSyncStatus } from '@deepseek-ai/dsh-a2a-registry-ingest'

/** Commands require current producer authority; this capability supplies neither identity nor a remote route. */
export interface RegistryDisclosureControl {
  /** Create one source-owned disclosure from a trusted Host adapter. An exact retry may return the existing
   * receipt only while the full registration remains pristine; changed or progressed identities conflict.
   * Remote request decoding and identity authentication remain outside this capability. */
  register(authority: FreshProducerAuthority,
    registration: RegistryDisclosureRegistration): Promise<RegistryIngestReceipt>
  /** Read the current source-owned Registry state through the same serialized storage owner. */
  getSyncStatus(authority: FreshProducerAuthority, id: DisclosureId): Promise<RegistryProducerSyncStatus>
  /** Replace grants, capabilities, and expiration using the same serialized owner as synchronization.
   * @param authority - Trusted provider callback rechecking the current source identity.
   * @param id - Disclosure owned by that source in this runtime's organization.
   * @param update - Complete replacement access settings, synchronously copied before queuing.
   * @param expectedVersion - Required current authorization version.
   * @returns The durable operation receipt. A failed Host-side copy enters the same owner queue without the payload,
   * exception or authority; an enabled journal records fixed unattributed access rejection metadata before invalid-input.
   * Journal capacity, persistence and lifecycle failures retain their existing precedence. */
  updateAccess(authority: FreshProducerAuthority, id: DisclosureId, update: DisclosureAccessUpdate,
    expectedVersion: number): Promise<RegistryIngestReceipt>
  /** Change producer control state without supplying reader access or clearing a Local outbox.
   * @param authority - Trusted provider callback rechecking the current source identity.
   * @param id - Disclosure owned by that source in this runtime's organization.
   * @param target - Domain-defined control state; deletion uses the separate command.
   * @param expectedVersion - Required current authorization version.
   * @returns The durable operation receipt. */
  transitionControl(authority: FreshProducerAuthority, id: DisclosureId,
    target: Exclude<DisclosureControlState, 'deleted'>, expectedVersion: number): Promise<RegistryIngestReceipt>
  /** Persist the domain-defined minimal deletion tombstone.
   * @param authority - Trusted provider callback rechecking the current source identity.
   * @param id - Disclosure owned by that source in this runtime's organization.
   * @param expectedVersion - Required current authorization version.
   * @returns The durable deletion receipt, not a content checkpoint acknowledgment. */
  delete(authority: FreshProducerAuthority, id: DisclosureId, expectedVersion: number): Promise<RegistryIngestReceipt>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Runtime-scoped command capability, not a readiness signal; every command rechecks owner availability. */
    registryDisclosureControl: RegistryDisclosureControl
  }
}
