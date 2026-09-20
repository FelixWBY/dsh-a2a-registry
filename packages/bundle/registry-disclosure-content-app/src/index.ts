/** Official bounded Registry disclosure-content projection over one injected key provider. */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { DisclosureCryptoLimits } from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import type { RegistryConfirmedPrefix } from '@deepseek-ai/dsh-a2a-registry-ingest'
import {
  RegistryDisclosureContentProvider,
  projectRegistryDisclosureContent,
  type RegistryDisclosureContent,
  type RegistryDisclosureContentProjectionLimits,
  type RegistryDisclosureKeyProvider,
} from '@deepseek-ai/dsh-registry-app'

/** Explicit event, plaintext, ciphertext, and historical-key ceilings. */
export interface Config {
  readonly maxContentEvents: number
  readonly crypto: DisclosureCryptoLimits
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()

/** Loader schema. No limit is inferred from untrusted disclosure data. */
export const Config: z<Config> = z.object({
  maxContentEvents: positive(),
  crypto: z.object({
    maxPlaintextBytes: positive(),
    maxCiphertextBytes: positive(),
    maxTrustedKeys: positive(),
  }).required(),
})

/** Stable Cordis plugin identity. */
export const name = 'registry-disclosure-content-app'
/** The key provider owns key persistence and must outlive every admitted projection. */
export const inject = ['registryDisclosureKeyProvider']

/** Stateless projector. It holds neither keys nor plaintext after a request settles. */
export class KmsRegistryDisclosureContentProvider extends RegistryDisclosureContentProvider {
  private readonly limits: RegistryDisclosureContentProjectionLimits

  constructor(ctx: Context, private readonly keyProvider: RegistryDisclosureKeyProvider, config: Config) {
    super(ctx)
    // Copy only the schema-owned fields. Schemastery intentionally preserves unknown
    // object members, so spreading deployment input here would let an untrusted
    // `crypto.maxEvents` shadow the separately validated event ceiling.
    this.limits = Object.freeze({
      maxEvents: config.maxContentEvents,
      maxPlaintextBytes: config.crypto.maxPlaintextBytes,
      maxCiphertextBytes: config.crypto.maxCiphertextBytes,
      maxTrustedKeys: config.crypto.maxTrustedKeys,
    })
  }

  readContent(prefix: RegistryConfirmedPrefix, maxResponseBytes: number,
    signal: AbortSignal): Promise<RegistryDisclosureContent> {
    return projectRegistryDisclosureContent(
      (scope, maxKeys, operationSignal) => this.keyProvider.readDataKeys(scope, maxKeys, operationSignal),
      prefix, this.limits, maxResponseBytes, signal,
    )
  }
}

/** Mount exactly one official projector over the injected deployment-selected key provider. */
export function apply(ctx: Context, config: Config): void {
  const keyProvider = ctx.get('registryDisclosureKeyProvider')
  if (keyProvider === undefined) {
    throw new Error('Registry disclosure content projection requires registryDisclosureKeyProvider')
  }
  new KmsRegistryDisclosureContentProvider(ctx, keyProvider, Config(config))
}
