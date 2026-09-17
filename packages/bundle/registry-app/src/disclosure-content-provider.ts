/** Deployment-owned plaintext projection for one already authorized disclosure prefix. */
import { Context, Service } from '@deepseek-ai/cordis'
import type { RegistryConfirmedPrefix } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryDisclosureContent } from './operations.ts'

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Optional narrow adapter used by the SaaS-owned disclosure operation surface. */
    registryDisclosureContentProvider: RegistryDisclosureContentProvider
  }
}

/** Optional content adapter. It cannot replace the SaaS-owned import and question operations. */
export abstract class RegistryDisclosureContentProvider extends Service {
  constructor(ctx: Context) { super(ctx, 'registryDisclosureContentProvider') }

  /** Project one exact reader-authorized checkpoint into bounded browser-safe plaintext.
   * Implementations must honor the supplied request lifetime and response-byte bound. */
  abstract readContent(prefix: RegistryConfirmedPrefix, maxResponseBytes: number,
    signal: AbortSignal): Promise<RegistryDisclosureContent>
}
