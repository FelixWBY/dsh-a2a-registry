/** Optional browser-account authentication supplied by a deployment identity adapter. */
import type { IncomingMessage } from 'node:http'
import { Context, Service } from '@deepseek-ai/cordis'
import type { InstanceKeyHistory } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { DisclosureSubject } from '@deepseek-ai/dsh-a2a-registry-domain'

/** Current account and Registry-owned source-key snapshot for one authenticated HTTP request. */
export interface RegistryAuthenticatedAccount {
  /** Complete current membership, role and team facts; the API never fills authorization fields itself. */
  readonly subject: DisclosureSubject
  /** Resolve current key history only inside this account's organization. */
  readonly historyFor: (instanceId: DshInstanceId) => InstanceKeyHistory | null
}

/** Global signed-in identity, valid even before the user belongs to an organization. */
export interface RegistryAuthenticatedIdentity {
  readonly accountId: string
  readonly issuer: string
  readonly subject: string
  readonly memberId: string
  readonly displayName: string
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

  /** Authenticate the global account used by self-service organization onboarding.
   * Legacy providers derive a compatibility identity from their one organization account. */
  async authenticateIdentity(request: IncomingMessage, signal: AbortSignal):
  Promise<RegistryAuthenticatedIdentity | null> {
    const account = await this.authenticate(request, signal)
    if (account === null) return null
    return {
      accountId: account.subject.memberId,
      issuer: 'legacy',
      subject: account.subject.memberId,
      memberId: account.subject.memberId,
      displayName: account.subject.memberId,
    }
  }

  /** Resolve one explicit URL organization; a mismatch is indistinguishable from no membership. */
  async authenticateOrganization(request: IncomingMessage, organizationId: OrganizationId,
    signal: AbortSignal): Promise<RegistryAuthenticatedAccount | null> {
    const account = await this.authenticate(request, signal)
    return account?.subject.organizationId === organizationId ? account : null
  }
}
