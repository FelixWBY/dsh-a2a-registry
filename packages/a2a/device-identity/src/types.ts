/** Public identity records; the registry authenticates their ownership before decoding. */
import type { KeyObject } from 'node:crypto'
import type { Branded } from '@deepseek-ai/dsh-brand'
import type { DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'

/** SHA-256 fingerprint of the canonical Ed25519 SPKI DER public key. */
export type InstanceKeyId = Branded<'A2AInstanceKeyId'>

/** In-memory key material; no private-key serialization or persistence is performed. */
export interface InstanceKeyPair {
  readonly keyId: InstanceKeyId
  readonly publicKeySpki: string
  readonly privateKey: KeyObject
}

/** One authenticated public key with an inclusive start and exclusive expiry. */
export interface InstancePublicKey {
  readonly keyId: InstanceKeyId
  readonly publicKeySpki: string
  readonly validFrom: number
  readonly validUntil: number | null
  readonly revokedAt: number | null
}

/** Registry-owned history for exactly one organization and instance. */
export interface InstanceKeyHistory {
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly status: 'active' | 'revoked'
  readonly keys: readonly InstancePublicKey[]
}

/** Authenticated connection identity and trusted receive time, never payload-selected. */
export interface InstanceVerificationContext {
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly keyId: InstanceKeyId
  readonly now: number
}
