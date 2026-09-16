/** Organization directory data never authenticates a request or grants disclosure access. */
import type { DisclosureSubject, MemberId, TeamId } from '@deepseek-ai/dsh-a2a-registry-domain'

/** Persistent membership; removed identities are retained and cannot be reassigned. */
export interface RegistryDirectoryMember {
  readonly memberId: MemberId
  readonly displayName: string
  readonly role: DisclosureSubject['role']
  readonly state: DisclosureSubject['membership']
}

/** Current team membership, not a grant-time expansion. */
export interface RegistryDirectoryTeam {
  readonly teamId: TeamId
  readonly displayName: string
  readonly memberIds: readonly MemberId[]
}

/** One organization-owned revision, committed with disclosure authorization invalidation. */
export interface RegistryDirectoryState {
  readonly revision: number
  readonly members: readonly RegistryDirectoryMember[]
  readonly teams: readonly RegistryDirectoryTeam[]
}

/** Explicit storage bounds and trusted first-open provisioning; no identity provider is selected. */
export interface RegistryDirectoryConfig {
  readonly maxMembers: number
  readonly maxTeams: number
  readonly maxTeamMembers: number
  readonly maxNameBytes: number
  readonly maxBytes: number
  /** Used only when the domain is empty; changing configuration does not replace an existing owner. */
  readonly bootstrapOwner: { readonly memberId: MemberId; readonly displayName: string }
}

/** Commands enter the serialized owner with an expected directory revision. */
export type RegistryDirectoryChange =
  | { readonly kind: 'put-member'; readonly member: RegistryDirectoryMember }
  | { readonly kind: 'put-team'; readonly team: RegistryDirectoryTeam }
  | { readonly kind: 'remove-team'; readonly teamId: TeamId }

/** Only an external trusted authenticator supplies these facts; roles and teams are read from storage. */
export type FreshRegistryDirectoryAuthority = () => {
  readonly subject: Pick<DisclosureSubject, 'organizationId' | 'memberId' | 'authenticated'>
  readonly now: number
} | Promise<{
  readonly subject: Pick<DisclosureSubject, 'organizationId' | 'memberId' | 'authenticated'>
  readonly now: number
}>

/** A directory commit receipt is not a signed-in session or a disclosure grant. */
export interface RegistryDirectoryReceipt {
  readonly revision: number
  readonly invalidatedDisclosures: number
}
