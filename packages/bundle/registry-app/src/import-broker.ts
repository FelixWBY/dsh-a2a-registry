/** Authenticated target-side delivery of Registry-owned durable context imports. */
import type { RegistryConnectionAuthority } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { RegistryDisclosureRefreshAuthorization, RegistryDisclosureRefreshDelivery,
  RegistryDisclosureRefreshReadiness, RegistryDisclosureRefreshStatus,
  RegistryImportDelivery, RegistryImportOutcome } from '@deepseek-ai/dsh-a2a-registry-sync'

/** Private target-side Broker surface. The caller holds device authority through the delivery callback. */
export interface RegistryImportBroker {
  /** Select one queued import for this exact target and keep its authorization current until release.
   * @param target - Fresh authenticated target authority for this connection.
   * @param receive - Callback kept inside the fixed-checkpoint authorization window.
   * @param signal - Connection lifetime; cancellation releases retained authority.
   * @returns true when one delivery callback ran; false when no authorized queued work remained. */
  dispatch(target: RegistryConnectionAuthority,
    receive: (delivery: RegistryImportDelivery) => Promise<RegistryImportOutcome>,
    signal: AbortSignal): Promise<boolean>
  /** Compare a target's imported prefix with the latest prefix still authorized through its completed import. */
  refreshReadiness(target: RegistryConnectionAuthority, readiness: RegistryDisclosureRefreshReadiness,
    signal: AbortSignal): Promise<RegistryDisclosureRefreshStatus>
  /** Build one bounded refresh, wait for WSS release, then reauthorize the exact prefix before returning. */
  withRefreshAuthorization(target: RegistryConnectionAuthority,
    authorization: RegistryDisclosureRefreshAuthorization, authorizationRequestId: number,
    receive: (delivery: RegistryDisclosureRefreshDelivery, signal: AbortSignal) => Promise<void>,
    signal: AbortSignal): Promise<void>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Present only while an explicitly configured Registry import owner is live. */
    registryImportBroker: RegistryImportBroker
  }
}
