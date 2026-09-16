/** Optional browser-account authentication supplied by a deployment identity adapter. */
import type { IncomingMessage } from 'node:http'
import { Context, Service } from '@deepseek-ai/cordis'
import type { InstanceKeyHistory } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DshInstanceId } from '@deepseek-ai/dsh-a2a-protocol'
import type { DisclosureSubject } from '@deepseek-ai/dsh-a2a-registry-domain'

/** Current account and Registry-owned source-key snapshot for one authenticated HTTP request. */
export interface RegistryAuthenticatedAccount {
  /** Complete current membership, role and team facts; the API never fills authorization fields itself. */
  readonly subject: DisclosureSubject
  /** Resolve current key history only inside this account's organization. */
  readonly historyFor: (instanceId: DshInstanceId) => InstanceKeyHistory | null
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    registryAccountAuthenticator: RegistryAccountAuthenticator
  }
}

/** Deployment-owned browser session verifier; this package supplies no implementation or credential. */
export abstract class RegistryAccountAuthenticator extends Service {
  /** @param ctx - Provider-owned lifecycle context. */
  constructor(ctx: Context) { super(ctx, 'registryAccountAuthenticator') }

  /** Authenticate one browser request and load current source-key histories.
   * @param request - Incoming request whose cookie or authorization metadata belongs to the provider.
   * @param signal - Request cancellation signal; providers release partial authentication work before settling.
   * @returns Current account facts, or null when the request has no valid signed-in session. */
  abstract authenticate(request: IncomingMessage, signal: AbortSignal):
  Promise<RegistryAuthenticatedAccount | null>
}
