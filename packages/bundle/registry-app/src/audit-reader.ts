/** Host-only authorized projection of the retained Registry operation journal. */
import type { DisclosureSubject } from '@deepseek-ai/dsh-a2a-registry-domain'

export type RegistryAuditActorKind = 'enrollment' | 'producer' | 'member' | 'maintenance' | 'unattributed'
export type RegistryAuditResult = 'pending' | 'succeeded' | 'rejected'

/** Browser-safe metadata only; no payload, reply, attachment, prompt, signature or key material. */
export interface RegistryAuditMetadata {
  readonly operationId: string
  readonly occurredAt: number
  readonly actorKind: RegistryAuditActorKind
  readonly actorId: string | null
  readonly instanceId: string | null
  readonly objectId: string | null
  readonly action: string
  readonly result: RegistryAuditResult
}

export interface RegistryAuditPage {
  readonly items: readonly RegistryAuditMetadata[]
  readonly nextCursor: string | null
}

export interface RegistryAuditListOptions {
  readonly pageSize: number
  readonly maxPageSize: number
  readonly maxResponseBytes: number
  readonly cursor?: string
}

/** Fresh deployment-owned account facts; no browser-supplied role or organization is trusted. */
export type FreshRegistryAuditAuthority = () => DisclosureSubject | Promise<DisclosureSubject>

/** Runtime-scoped reader published only when the durable audit journal is explicitly enabled. */
export interface RegistryAuditReader {
  /** Read one authorized, bounded page of metadata-only journal records.
   * @param authority - fresh deployment-owned organization membership and role facts.
   * @param options - fixed page, response and optional cursor bounds.
   * @returns Newest-first audit metadata and an opaque continuation cursor. */
  list(authority: FreshRegistryAuditAuthority, options: RegistryAuditListOptions): Promise<RegistryAuditPage>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    registryAuditReader: RegistryAuditReader
  }
}
