/** Public contracts for the deliberately software-only Registry envelope-key store. */
import type { KeyObject } from 'node:crypto'
import type {
  DisclosureDataKeyGrantScope, DisclosureDataKeyId,
} from '@deepseek-ai/dsh-a2a-disclosure-crypto'

/** Honest capability statement: this implementation is neither an HSM nor end-to-end encryption. */
export interface SoftwareLocalKeyProtection {
  readonly assurance: 'software-local'
  readonly hsmBacked: false
  readonly hardwareAttested: false
  readonly endToEnd: false
  readonly rootKeyPersistence: 'external-runtime-secret'
  readonly keysExportableInProcess: true
  readonly singleWriterRequired: true
}

/** Stable, non-secret protection metadata suitable for readiness and operator status. */
export const SOFTWARE_LOCAL_KEY_PROTECTION: SoftwareLocalKeyProtection = Object.freeze({
  assurance: 'software-local',
  hsmBacked: false,
  hardwareAttested: false,
  endToEnd: false,
  rootKeyPersistence: 'external-runtime-secret',
  keysExportableInProcess: true,
  singleWriterRequired: true,
})

/** Versioned 256-bit root key supplied by a deployment-owned secret boundary, never persisted here. */
export interface SoftwareLocalRootKey {
  readonly keyId: string
  readonly key: KeyObject
}

/** Explicit storage and admission bounds; the PostgreSQL backend enforces tenantId through RLS. */
export interface SoftwareLocalDisclosureKeyStoreOptions {
  readonly organizationId: DisclosureDataKeyGrantScope['organizationId']
  readonly rootKey: SoftwareLocalRootKey
  readonly storage: {
    /** Stable base name; the provider appends an organization hash so active tenants never share a physical domain. */
    readonly domainNamePrefix: string
    readonly tenantId: string
  }
  readonly limits: {
    readonly maxDataKeys: number
    readonly maxPendingOperations: number
  }
  readonly signal: AbortSignal
}

/** Metadata-only acknowledgement emitted only after the wrapped key is durable. */
export interface SoftwareLocalDisclosureKeyReceipt {
  readonly scope: DisclosureDataKeyGrantScope
  readonly keyId: DisclosureDataKeyId
  readonly assurance: 'software-local'
}

/** Content-free failures safe to return across an authenticated adapter boundary. */
export type SoftwareLocalKmsErrorCode =
  | 'invalid-input'
  | 'invalid-root-key'
  | 'root-key-unavailable'
  | 'invalid-storage'
  | 'authentication-failed'
  | 'scope-mismatch'
  | 'conflict'
  | 'not-found'
  | 'limit'
  | 'storage-failed'
  | 'closed'
  | 'unavailable'

/** Sanitized store error; messages and causes never include key bytes or durable records. */
export class SoftwareLocalKmsError extends Error {
  /** @param code - Stable content-free failure category. */
  constructor(readonly code: SoftwareLocalKmsErrorCode) {
    super(`software-local disclosure KMS: ${code}`)
    this.name = 'SoftwareLocalKmsError'
  }
}

/** Fixed AES-256-GCM envelope stored in the tenant-scoped domain. */
export interface SoftwareLocalWrappedKey {
  readonly version: 1
  readonly algorithm: 'A256GCM'
  readonly nonce: string
  readonly ciphertext: string
  readonly tag: string
}
