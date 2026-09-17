/** Persistent SaaS account, organization and membership control-plane contracts. */
import type { Branded } from '@deepseek-ai/dsh-brand'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'

/** Server-issued Registry account identity, independent from any one organization. */
export type RegistryAccountId = Branded<'RegistryAccountId'>

/** Account resolved from one stable external OIDC issuer/subject pair. */
export interface RegistryAccount {
  readonly accountId: RegistryAccountId
  /** Stable Registry member identifier reused when this account joins an organization. */
  readonly memberId: MemberId
  readonly displayName: string
  readonly createdAt: number
  readonly updatedAt: number
}

/** Stable external identity facts captured only after successful OIDC validation. */
export interface RegistryOidcAccountInput {
  readonly issuer: string
  readonly subject: string
  readonly memberId: MemberId
  readonly displayName: string
}

export type RegistryOrganizationState = 'provisioning' | 'active' | 'failed'
export type RegistryOrganizationRole = 'owner' | 'admin' | 'member'
export type RegistryOrganizationMembershipState = 'active' | 'suspended' | 'removed'

/** Public organization metadata; IDs are immutable while names and slugs are presentation fields. */
export interface RegistryOrganization {
  readonly organizationId: OrganizationId
  readonly slug: string
  readonly displayName: string
  readonly state: RegistryOrganizationState
  readonly createdAt: number
  readonly updatedAt: number
}

/** One account's organization-scoped member identity and RBAC role. */
export interface RegistryOrganizationMembership {
  readonly organizationId: OrganizationId
  readonly accountId: RegistryAccountId
  readonly memberId: MemberId
  readonly role: RegistryOrganizationRole
  readonly state: RegistryOrganizationMembershipState
  readonly createdAt: number
  readonly updatedAt: number
}

/** Organization plus the freshly loaded membership that made it visible to this account. */
export interface RegistryOrganizationAccess {
  readonly organization: RegistryOrganization
  readonly membership: RegistryOrganizationMembership
}

export interface RegistryOrganizationCreationInput {
  readonly displayName: string
  /** Stable caller retry key; reuse with a different name is a conflict. */
  readonly idempotencyKey: string
}

export interface RegistryLegacyOrganizationInput {
  /** Existing pre-SaaS organization identifiers are retained even when they are not UUIDs. */
  readonly organizationId: OrganizationId
  readonly displayName: string
}

export type RegistryTenancyErrorCode = 'invalid-input' | 'conflict' | 'not-found' | 'unavailable' | 'closed'

/** Stable, payload-free failure boundary for the HTTP/OIDC adapters. */
export class RegistryTenancyError extends Error {
  constructor(readonly code: RegistryTenancyErrorCode) {
    super(code)
    this.name = 'RegistryTenancyError'
  }
}

/** Minimal control-plane persistence needed for self-service organization provisioning. */
export interface RegistryTenancyStore {
  resolveOrCreateAccount(input: RegistryOidcAccountInput): Promise<RegistryAccount>
  listOrganizations(accountId: RegistryAccountId): Promise<readonly RegistryOrganizationAccess[]>
  createOrganization(account: RegistryAccount,
    input: RegistryOrganizationCreationInput): Promise<RegistryOrganizationAccess>
  getOrganizationForAccount(accountId: RegistryAccountId,
    organizationId: OrganizationId): Promise<RegistryOrganizationAccess | null>
  /** Internal provisioning lookup; callers must not expose its existence as a public authorization result. */
  getOrganizationInternal(organizationId: OrganizationId): Promise<RegistryOrganization | null>
  markOrganizationState(organizationId: OrganizationId,
    state: Extract<RegistryOrganizationState, 'active' | 'failed'>): Promise<RegistryOrganization>
  ensureLegacyOrganization(input: RegistryLegacyOrganizationInput): Promise<RegistryOrganization>
  /** Link a pre-SaaS bootstrap owner after the caller has independently verified that legacy ownership. */
  claimLegacyOwner(account: RegistryAccount,
    organizationId: OrganizationId): Promise<RegistryOrganizationAccess>
  close(): Promise<void>
}
