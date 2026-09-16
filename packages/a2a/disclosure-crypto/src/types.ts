/** Scoped keys and explicit limits for the disclosure payload encryption library. */
import type { KeyObject } from 'node:crypto'
import type { Branded } from '@deepseek-ai/dsh-brand'
import type { CredentialKey, CredentialRecord } from '@deepseek-ai/dsh-credentials'
import type {
  DisclosureConversationId, DisclosureEventId, DisclosureId, DisclosureSemanticEventType, DshInstanceId, OrganizationId,
} from '@deepseek-ai/dsh-a2a-protocol'

/** Opaque provider-owned data key selector; it contains no secret key material. */
export type DisclosureDataKeyId = Branded<'A2ADisclosureDataKeyId'>

/** One source conversation; sharing a data key across these scopes is forbidden. */
export interface DisclosureKeyScope {
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly conversationId: DisclosureConversationId
}

/** Trusted provider key; KeyObject is in-memory but remains exportable by its owner. */
export interface DisclosureDataKey {
  readonly keyId: DisclosureDataKeyId
  readonly scope: DisclosureKeyScope
  readonly key: KeyObject
}

/** Disclosure-specific scope persisted by the two explicit local-test credential owners. */
export interface DisclosureDataKeyGrantScope extends DisclosureKeyScope {
  readonly disclosureId: DisclosureId
}

/** The only credential stores allowed to retain local-test disclosure data-key grants. */
export type DisclosureDataKeyGrantOwner = 'web-app' | 'registry-app'

/** Exact AAD coordinates for the local-test source-to-Registry wrapped-key transfer. */
export interface DisclosureDataKeyWrapContext {
  readonly version: 1
  readonly organizationId: OrganizationId
  readonly sourceInstanceId: DshInstanceId
  readonly conversationId: DisclosureConversationId
  readonly disclosureId: DisclosureId
  readonly keyId: DisclosureDataKeyId
}

/** Fixed-size AES-256-GCM envelope carrying one wrapped 32-byte disclosure data key. */
export interface WrappedDisclosureDataKey {
  readonly version: 1
  readonly nonce: string
  readonly ciphertext: string
  readonly tag: string
}

/** Credentials address and record returned together so callers cannot select mismatched scopes. */
export interface DisclosureDataKeyGrant {
  readonly key: CredentialKey
  readonly record: CredentialRecord
}

/** Exact metadata authenticated as AAD; callers derive it from the authenticated event envelope. */
export interface DisclosureEncryptionMetadata extends DisclosureKeyScope {
  readonly disclosureId: DisclosureId
  readonly eventId: DisclosureEventId
  readonly eventType: DisclosureSemanticEventType
  readonly policyVersion: number
}

/** Deployment-selected complete-record byte bounds and maximum retained decryption key candidates. */
export interface DisclosureCryptoLimits {
  /** Complete serialized UTF-8 semantic JSON, not only its visible text. */
  readonly maxPlaintextBytes: number
  /** Complete ASCII base64url payload, including version, key selector, nonce, and authentication tag. */
  readonly maxCiphertextBytes: number
  /** Maximum explicit historical keys supplied by the trusted provider for one decrypt operation. */
  readonly maxTrustedKeys: number
}

/** Payload-free diagnostics safe to record without copying input content. */
export type DisclosureCryptoErrorCode =
  | 'invalid-limits'
  | 'invalid-metadata'
  | 'invalid-semantic-event'
  | 'limit-exceeded'
  | 'invalid-key'
  | 'ambiguous-key'
  | 'key-not-found'
  | 'key-scope-mismatch'
  | 'invalid-payload'
  | 'unsupported-version'
  | 'authentication-failed'
