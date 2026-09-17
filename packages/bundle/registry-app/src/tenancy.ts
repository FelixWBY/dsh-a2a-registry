/** Persistent SaaS account, organization and membership control-plane contracts. */
import type { Branded } from '@deepseek-ai/dsh-brand'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type {
  RegistryBillingCheckoutAttachment,
  RegistryBillingEvent,
  RegistryBillingOrder,
  RegistryBillingOrderReservation,
} from './billing.ts'

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
export type RegistryInvitationState = 'pending' | 'accepted' | 'declined' | 'revoked' | 'expired'
export type RegistryInvitationRole = Exclude<RegistryOrganizationRole, 'owner'>

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

/** One bounded organization invitation. The bearer token is deliberately not retained on this record. */
export interface RegistryInvitation {
  readonly invitationId: string
  readonly organizationId: OrganizationId
  readonly role: RegistryInvitationRole
  readonly displayName: string | null
  readonly status: RegistryInvitationState
  readonly expiresAt: number
  readonly createdAt: number
  readonly createdByMemberId: MemberId
}

/** Invitation metadata visible only to a signed-in account possessing the bearer token. */
export interface RegistryInvitationPreview {
  readonly invitationId: string
  readonly organizationId: OrganizationId
  readonly organizationDisplayName: string
  readonly role: RegistryInvitationRole
  readonly displayName: string | null
  readonly status: RegistryInvitationState
  readonly expiresAt: number
}

export interface RegistryInvitationCreationInput {
  readonly role: RegistryInvitationRole
  readonly displayName?: string
  readonly expiresInSeconds?: number
}

/** Raw token is returned exactly once and is never persisted. */
export interface RegistryInvitationCreation {
  readonly invitation: RegistryInvitation
  readonly token: string
}

/** Short-lived claim used while the directory and control plane converge. */
export interface RegistryInvitationClaim {
  readonly invitation: RegistryInvitation
  readonly account: RegistryAccount
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
  listInvitations(accountId: RegistryAccountId, memberId: MemberId, actorRole: RegistryOrganizationRole,
    organizationId: OrganizationId): Promise<readonly RegistryInvitation[]>
  createInvitation(accountId: RegistryAccountId, memberId: MemberId, actorRole: RegistryOrganizationRole,
    organizationId: OrganizationId, input: RegistryInvitationCreationInput): Promise<RegistryInvitationCreation>
  revokeInvitation(accountId: RegistryAccountId, memberId: MemberId, actorRole: RegistryOrganizationRole,
    organizationId: OrganizationId, invitationId: string): Promise<RegistryInvitation>
  previewInvitation(accountId: RegistryAccountId, token: string): Promise<RegistryInvitationPreview>
  claimInvitation(account: RegistryAccount, token: string): Promise<RegistryInvitationClaim>
  activateInvitation(account: RegistryAccount, invitationId: string): Promise<RegistryOrganizationAccess>
  declineInvitation(account: RegistryAccount, token: string): Promise<RegistryInvitationPreview>
  /** Mirror an already committed directory member change when that member is linked to an account. */
  syncMembershipFromDirectory(organizationId: OrganizationId, memberId: MemberId,
    role: RegistryOrganizationRole, state: RegistryOrganizationMembershipState): Promise<void>
  /** Reserve one organization-scoped commercial intent before contacting its provider. */
  reserveBillingOrder(accountId: RegistryAccountId, memberId: MemberId,
    input: RegistryBillingOrderReservation): Promise<RegistryBillingOrder>
  /** Attach provider checkout metadata without persisting its bearer-like redirect URL. */
  attachBillingCheckout(input: RegistryBillingCheckoutAttachment): Promise<RegistryBillingOrder>
  /** List newest orders only after reloading a current active Owner membership. */
  listBillingOrders(accountId: RegistryAccountId, memberId: MemberId,
    organizationId: OrganizationId): Promise<readonly RegistryBillingOrder[]>
  /** Apply one signature-verified provider event through the core transition table. */
  applyVerifiedBillingEvent(input: RegistryBillingEvent): Promise<RegistryBillingOrder>
  close(): Promise<void>
}
