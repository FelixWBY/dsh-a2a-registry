/** Host-only authorized disclosure reads sharing the active Registry storage owner. */
import type { DisclosureHash, DisclosureId, DshInstanceId } from '@deepseek-ai/dsh-a2a-protocol'
import type { DisclosureAction } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { FreshRegistryDirectoryAuthority, FreshRegistryMetadataAuthority, RegistryConfirmedPrefix, RegistryDisclosureMetadata,
  RegistryMetadataListOptions, RegistryMetadataPage, RegistryMetadataReadOptions } from '@deepseek-ai/dsh-a2a-registry-ingest'

/** One exact authorization snapshot held only for a bounded local Registry-side callback. */
export interface RegistryAuthorizedPrefixSnapshot {
  readonly metadata: RegistryDisclosureMetadata
  readonly prefix: RegistryConfirmedPrefix
}

/** Optional source receive binding checked by the same serialized Registry owner. */
export interface RegistryReceiveBindingRequirement {
  readonly authority: FreshRegistryDirectoryAuthority
  readonly instanceId: DshInstanceId
  readonly maxResponseBytes: number
}

/** Runtime-scoped reader; callers supply authenticated authority, never JSON identity claims. */
export interface RegistryDisclosureReader {
  /** List current readable metadata.
   * @param authority - Fresh authenticated member, server clock and source-key resolver.
   * @param options - Trusted server-selected page and response limits.
   * @returns Authorized metadata and an opaque continuation cursor. */
  list(authority: FreshRegistryMetadataAuthority, options: RegistryMetadataListOptions): Promise<RegistryMetadataPage>
  /** Read one authorized metadata record for the selected operation.
   * @param authority - Fresh authenticated member, server clock and source-key resolver.
   * @param disclosureId - Canonical resource identity selected by the server route.
   * @param action - Current permission required for this observation.
   * @param options - Trusted server-selected response limits.
   * @returns Body-free metadata and effective actions from the same authorization snapshot. */
  readMetadata(authority: FreshRegistryMetadataAuthority, disclosureId: DisclosureId,
    action: Extract<DisclosureAction, 'read' | 'import' | 'ask'>,
    options: RegistryMetadataReadOptions): Promise<RegistryDisclosureMetadata>
  /** Read an exact confirmed prefix after fresh account and source-key resolution.
   * @param authority - Fresh authenticated member, server clock and source-key resolver.
   * @param disclosureId - Canonical resource identity selected by the server route.
   * @param sourceInstanceId - Reader-authorized source used to resolve its current key history.
   * @param action - Current derivation permission required for this exact prefix.
   * @param checkpointHash - Reader-authorized checkpoint; a missing selection never falls back.
   * @returns Detached signed prefix with its stored source conversation identity. */
  readPrefix(authority: FreshRegistryMetadataAuthority, disclosureId: DisclosureId,
    sourceInstanceId: DshInstanceId, action: Extract<DisclosureAction, 'read' | 'import' | 'ask'>,
    checkpointHash: DisclosureHash): Promise<RegistryConfirmedPrefix>
  /** Hold the serialized ingest owner while a bounded local consumer commits against one fresh snapshot.
   * The callback must not perform model work or network I/O. A not-found snapshot is delivered as null so
   * the consumer can atomically stop its own derived record before another Registry mutation overtakes it. */
  withAuthorizedPrefix<T>(authority: FreshRegistryMetadataAuthority, disclosureId: DisclosureId,
    sourceInstanceId: DshInstanceId, action: Extract<DisclosureAction, 'read' | 'import' | 'ask'>,
    checkpointHash: DisclosureHash, maxMetadataBytes: number,
    receive: RegistryReceiveBindingRequirement | undefined,
    callback: (snapshot: RegistryAuthorizedPrefixSnapshot | null) => Promise<T>): Promise<T>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Present only while an explicitly configured ingest owner is active. */
    registryDisclosureReader: RegistryDisclosureReader
  }
}
