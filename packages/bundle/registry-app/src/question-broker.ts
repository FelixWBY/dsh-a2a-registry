/** Authenticated WSS question operations over the Registry-owned mailbox. */
import type { RegistryConnectionAuthority } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { MailboxBinding, MailboxReceipt, MailboxTransition } from '@deepseek-ai/dsh-a2a-mailbox'
import type { RegistryQuestionDelivery } from '@deepseek-ai/dsh-a2a-registry-sync'

/** Private source-side Broker surface. The caller holds the device authority stable for every method. */
export interface RegistryQuestionBroker {
  /** Select and authorize one delivery for this exact source instance. */
  dispatch(source: RegistryConnectionAuthority, excludeRequestIds: readonly string[],
    signal: AbortSignal): Promise<RegistryQuestionDelivery | null>
  /** Acquire or inspect the current version-fenced execution claim. */
  start(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    signal: AbortSignal): Promise<{ receipt: MailboxReceipt; started: boolean; renewAfterMs: number }>
  /** Renew one current execution fence. */
  renew(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    signal: AbortSignal): Promise<{ receipt: MailboxReceipt; renewAfterMs: number }>
  /** Read current source-authorized metadata without releasing text. */
  status(source: RegistryConnectionAuthority, binding: MailboxBinding,
    signal: AbortSignal): Promise<MailboxReceipt>
  /** Commit one version-fenced terminal transition. */
  transition(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    transition: MailboxTransition, signal: AbortSignal): Promise<MailboxReceipt>
  /** Hold requester, disclosure and source authority while the receiver durably imports the prefix. */
  withAuthorization(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    receive: (delivery: RegistryQuestionDelivery) => Promise<void>, signal: AbortSignal): Promise<void>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Present only while the configured Registry mailbox owner is live. */
    registryQuestionBroker: RegistryQuestionBroker
  }
}
