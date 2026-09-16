/** Deployment-owned billing boundary. Registry ships disabled and never stores merchant secrets. */
import { Context, Service } from '@deepseek-ai/cordis'
import type { DisclosureSubject } from '@deepseek-ai/dsh-a2a-registry-domain'

export type RegistryBillingProviderName = 'stripe' | 'alipay'

/** Browser-safe commercial offer. Provider price identifiers remain server-side. */
export interface RegistryBillingPlan {
  readonly planId: string
  readonly displayName: string
  readonly currency: string
  readonly unitAmount: number
  readonly interval: 'month' | 'year'
}

/** Checkout request authorized to the current organization owner. */
export interface RegistryBillingCheckoutInput {
  readonly subject: DisclosureSubject
  readonly planId: string
  readonly idempotencyKey: string
  /** Same-origin route to return to; the provider owns the absolute public origin. */
  readonly returnPath: string
}

/** Redirect-only checkout result. Paid state must come from a verified provider webhook, never this redirect. */
export interface RegistryBillingCheckout {
  readonly checkoutId: string
  readonly checkoutUrl: string
  readonly expiresAt: number
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    registryBillingProvider: RegistryBillingProvider
  }
}

/** Optional production adapter for provider-hosted checkout and webhook-backed order state. */
export abstract class RegistryBillingProvider extends Service {
  abstract readonly provider: RegistryBillingProviderName

  constructor(ctx: Context) { super(ctx, 'registryBillingProvider') }

  abstract listPlans(subject: DisclosureSubject, signal: AbortSignal): Promise<readonly RegistryBillingPlan[]>
  abstract createCheckout(input: RegistryBillingCheckoutInput, signal: AbortSignal): Promise<RegistryBillingCheckout>
}
