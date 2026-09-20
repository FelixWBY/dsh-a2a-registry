/** Deployment-owned disclosure-key persistence seam; network authentication remains Registry-owned. */
import { Context, Service } from '@deepseek-ai/cordis'
import type {
  DisclosureDataKey, DisclosureDataKeyGrantScope, DisclosureDataKeyId,
} from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import type { RegistryImportKeyGrant } from '@deepseek-ai/dsh-a2a-registry-sync'

export type { RegistryImportKeyGrant } from '@deepseek-ai/dsh-a2a-registry-sync'
export { decodeRegistryImportKeyGrant } from '@deepseek-ai/dsh-a2a-registry-sync'

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Optional narrow adapter for publishing and reading already-generated disclosure keys. */
    registryDisclosureKeyProvider: RegistryDisclosureKeyProvider
  }
}

/** Honest operator-visible boundary; the discriminant forbids a software provider from claiming HSM properties. */
export type RegistryDisclosureKeyProtection = {
  readonly assurance: 'software-local'
  readonly hsmBacked: false
  readonly hardwareAttested: false
  readonly endToEnd: false
  readonly rootKeyPersistence: 'external-runtime-secret'
  readonly keysExportableInProcess: true
  readonly singleWriterRequired: true
} | {
  readonly assurance: 'hardware-backed'
  readonly hsmBacked: true
  readonly hardwareAttested: boolean
  readonly endToEnd: false
  readonly rootKeyPersistence: 'external-kms'
  readonly keysExportableInProcess: boolean
  readonly singleWriterRequired: boolean
}

/** Metadata-only durable acknowledgement. */
export interface RegistryDisclosureKeyReceipt {
  readonly scope: DisclosureDataKeyGrantScope
  readonly keyId: DisclosureDataKeyId
  readonly assurance: RegistryDisclosureKeyProtection['assurance']
}

/**
 * Optional key provider. It receives organization/instance scope only after Registry authentication.
 * Implementations must persist before acknowledging and treat same-scope/key-id material conflicts as failures.
 */
export abstract class RegistryDisclosureKeyProvider extends Service {
  constructor(ctx: Context) { super(ctx, 'registryDisclosureKeyProvider') }

  /** Non-secret capability metadata; callers must not infer HSM or E2E guarantees from mere availability. */
  abstract readonly protection: RegistryDisclosureKeyProtection

  /** Persist a source-generated key. Exact material retries must be idempotent. */
  abstract publishDataKey(scope: DisclosureDataKeyGrantScope, dataKey: DisclosureDataKey,
    signal: AbortSignal): Promise<RegistryDisclosureKeyReceipt>

  /** Release at most `maxKeys` authenticated keys only to Registry-owned content projection. */
  abstract readDataKeys(scope: DisclosureDataKeyGrantScope,
    maxKeys: number, signal: AbortSignal): Promise<readonly DisclosureDataKey[]>

  /** Explicitly export one bounded raw-key grant after the caller has held exact import authorization. */
  abstract issueAuthorizedGrant(scope: DisclosureDataKeyGrantScope,
    maxKeys: number, maxBytes: number, signal: AbortSignal): Promise<RegistryImportKeyGrant>

  /** Verify one authenticated organization's retained hierarchy without exposing material. */
  abstract checkReadiness(organizationId: DisclosureDataKeyGrantScope['organizationId'],
    signal: AbortSignal): Promise<boolean>
}
