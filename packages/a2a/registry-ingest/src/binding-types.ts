/** Binding candidates are not connection credentials or account authentication. */
import type { Branded } from '@deepseek-ai/dsh-brand'
import type { RegistryChallenge } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import type { InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'

/** Server-generated identity of one bounded enrollment attempt. */
export type RegistryBindingId = Branded<'A2ARegistryBindingId'>

/** Body-free, post-commit invalidation of one binding or its approving membership; not an authorization snapshot. */
export interface RegistryBindingInvalidation {
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
}

/** Explicit enrollment limits; the owner bounds retained attempts and request admission separately. */
export interface RegistryBindingLimits {
  readonly ttlMs: number
  readonly maxRecordBytes: number
  readonly maxBindings: number
  readonly maxNameBytes: number
}

/** Device-level requested functions, never disclosure-reader grants; enforcement belongs to credential consumers. */
export type RegistryBindingScope = 'disclosure.sync' | 'a2a.receive'

/** Device-supplied enrollment intent; the owner fixes identity, destination and challenge. */
export interface RegistryBindingRequest {
  readonly publicKeySpki: string
  readonly instanceName: string
  readonly requestedScopes: readonly RegistryBindingScope[]
}

/** Explicit enrollment destination and storage bounds; current directory membership is required. */
export interface RegistryBindingConfig extends RegistryBindingLimits {
  readonly audience: string
}

/** Device response after durable creation; no private record or code digest crosses this API. */
export interface RegistryBindingTicket {
  readonly bindingId: RegistryBindingId
  readonly code: string
  readonly challenge: RegistryChallenge
}

/** Persisted enrollment phase, not a token or permission to upload. */
export interface RegistryBindingReceipt {
  readonly bindingId: RegistryBindingId
  readonly state: RegistryBindingState
}

/** Account-visible binding metadata, excluding the code digest, public key bytes and challenge nonce. */
export interface RegistryBindingReview {
  readonly bindingId: RegistryBindingId
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly keyId: InstanceKeyId
  readonly createdAt: number
  readonly expiresAt: number
  readonly phase: RegistryBindingState['kind']
  readonly instanceName: string
  readonly requestedScopes: readonly RegistryBindingScope[]
}

/** Account approval and device possession are separate facts of one attempt. */
export type RegistryBindingState =
  | { readonly kind: 'pending' }
  | { readonly kind: 'approved'; readonly memberId: MemberId; readonly approvedAt: number }
  | { readonly kind: 'confirmed'; readonly memberId: MemberId; readonly approvedAt: number; readonly confirmedAt: number }
  | { readonly kind: 'rejected'; readonly memberId: MemberId; readonly rejectedAt: number }
  | {
    readonly kind: 'revoked'
    readonly memberId: MemberId
    readonly approvedAt: number
    readonly confirmedAt: number
    readonly revokedAt: number
  }

/** Owner-private durable candidate; no raw enrollment code, private key or bearer token is retained. */
export interface RegistryBindingRecord {
  readonly version: 4
  readonly bindingId: RegistryBindingId
  readonly createdAt: number
  readonly challenge: RegistryChallenge
  readonly publicKeySpki: string
  readonly instanceName: string
  readonly requestedScopes: readonly RegistryBindingScope[]
  readonly codeHash: string
  readonly state: RegistryBindingState
}

/** Return the code once to the initiating device; persist only the record. */
export interface RegistryBindingStart {
  readonly code: string
  readonly record: RegistryBindingRecord
}
