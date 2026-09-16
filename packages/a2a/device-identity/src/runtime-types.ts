/** External identity-provider obligations for the Local and Registry synchronization consumers. */
import type { DisclosureSignature, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { InstanceKeyHistory, InstanceKeyId, InstanceVerificationContext } from './types.ts'

/** One domain-separated, expiring device challenge issued for one connection attempt. */
export interface RegistryChallenge {
  readonly version: 1
  readonly audience: string
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly keyId: InstanceKeyId
  /** Exactly 32 random bytes, encoded as canonical unpadded base64url. */
  readonly nonce: string
  readonly expiresAt: number
}

/** Authenticated identity fixed for the lifetime of one transport connection. */
export type RegistryConnectionIdentity = Pick<InstanceVerificationContext, 'organizationId' | 'instanceId' | 'keyId'>

/** Fresh facts compatible with Registry ingestion, without depending on the ingest package. */
export interface RegistryConnectionAuthority {
  readonly connection: InstanceVerificationContext
  readonly history: InstanceKeyHistory
}

/** Each call rechecks current token expiry, membership, device and key validity inside its active lease. */
export type FreshRegistryConnectionAuthority = () => RegistryConnectionAuthority | Promise<RegistryConnectionAuthority>

/** Local credentials belong to one explicit destination and pre-existing organization/instance binding. */
export interface LocalRegistryConnection {
  readonly token: string
  readonly invalidated: AbortSignal
  /** Sign only a matching, unexpired challenge; never expose the private key to the transport.
   * @param challenge - Bounded decoded server challenge.
   * @param signal - Attempt cancellation.
   * @returns Domain-separated Ed25519 proof. */
  prove(challenge: RegistryChallenge, signal: AbortSignal): Promise<DisclosureSignature>
  /** Stop new proofs and await every outstanding provider operation. @returns Quiescent release. */
  close(): Promise<void>
}

/** One authenticated connection. No callback or fresh resolver may remain usable after its lease ends. */
export interface AuthenticatedRegistryConnection {
  readonly identity: RegistryConnectionIdentity
  /** Abort immediately when the token, membership, binding or key becomes invalid. */
  readonly invalidated: AbortSignal
  /** Hold current authorization stable until the single callback and its storage work settle.
   * The provider must reject late/repeated callback use and resolver use outside this lease.
   * @param perform - Trusted consumer operation, invoked exactly once with fresh checked facts.
   * @param signal - Request and connection cancellation; admitted I/O must still drain.
   * @returns The operation result after its lease ends; never an authorization snapshot. */
  withAuthority<T>(perform: (fresh: FreshRegistryConnectionAuthority) => Promise<T>, signal: AbortSignal): Promise<T>
  /** Stop new leases, invalidate the connection and drain admitted operations. @returns Quiescent release. */
  close(): Promise<void>
}

/** The provider owns nonce uniqueness, one-shot consumption, expiry and cleanup for this attempt. */
export interface RegistryChallengeAttempt {
  readonly challenge: RegistryChallenge
  /** Consume this challenge once; authenticate the proof and all current token/binding/member facts.
   * @param signature - Decoded Ed25519 proof, not an event signature.
   * @param signal - Attempt cancellation.
   * @returns A connection with fixed authenticated identity and current-authority leases. */
  complete(signature: DisclosureSignature, signal: AbortSignal): Promise<AuthenticatedRegistryConnection>
  /** Withdraw the challenge and drain in-flight completion. @returns Quiescent release. */
  close(): Promise<void>
}
