/** Deployment-owned billing boundary. Registry ships disabled and never stores merchant secrets. */
import { Context, Service } from '@deepseek-ai/cordis'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { DisclosureSubject } from '@deepseek-ai/dsh-a2a-registry-domain'

export type RegistryBillingProviderName = 'stripe' | 'alipay'
export type RegistryBillingOrderState = 'creating' | 'checkout-pending' | 'paid' | 'refunded' | 'disputed'
  | 'failed' | 'expired'
export type RegistryBillingEventType = 'checkout-paid' | 'checkout-expired' | 'checkout-failed' | 'refunded'
  | 'disputed'

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
  /** Registry order identifier copied into provider metadata for verified webhook correlation. */
  readonly orderId: string
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

/** Server-priced order reservation; no browser-supplied amount reaches this contract. */
export interface RegistryBillingOrderReservation {
  readonly organizationId: OrganizationId
  readonly provider: RegistryBillingProviderName
  readonly planId: string
  readonly idempotencyKey: string
  readonly currency: string
  readonly unitAmount: number
  readonly interval: RegistryBillingPlan['interval']
}

/** Provider checkout identity persisted after a hosted checkout has been created. */
export interface RegistryBillingCheckoutAttachment {
  readonly organizationId: OrganizationId
  readonly orderId: string
  readonly provider: RegistryBillingProviderName
  readonly providerCheckoutId: string
  readonly expiresAt: number
}

/** Signature-verified provider event. Raw webhook bodies and secrets never enter the order store. */
export interface RegistryBillingEvent {
  readonly organizationId: OrganizationId
  readonly orderId: string
  readonly provider: RegistryBillingProviderName
  readonly eventId: string
  readonly eventType: RegistryBillingEventType
  readonly payloadHash: string
  readonly occurredAt: number
}

/** Lower-cased request headers with every wire value retained in arrival order. */
export type RegistryBillingWebhookHeaders = Readonly<Record<string, readonly string[]>>

/** Exact bounded request bytes and normalized headers supplied only to the deployment adapter. */
export interface RegistryBillingWebhookInput {
  readonly rawBody: Uint8Array
  readonly headers: RegistryBillingWebhookHeaders
}

/** Provider result after signature, merchant and timestamp validation. Registry adds provider and payload hash. */
export interface RegistryBillingVerifiedEvent {
  readonly organizationId: OrganizationId
  readonly orderId: string
  readonly eventId: string
  readonly eventType: RegistryBillingEventType
  readonly occurredAt: number
}

/** Browser-safe provider-neutral order snapshot. */
export interface RegistryBillingOrder {
  readonly orderId: string
  readonly organizationId: OrganizationId
  readonly provider: RegistryBillingProviderName
  readonly planId: string
  readonly currency: string
  readonly unitAmount: number
  readonly interval: RegistryBillingPlan['interval']
  readonly state: RegistryBillingOrderState
  readonly providerCheckoutId: string | null
  readonly checkoutExpiresAt: number | null
  readonly paidAt: number | null
  readonly refundedAt: number | null
  readonly disputedAt: number | null
  readonly lastEventAt: number | null
  readonly createdAt: number
  readonly updatedAt: number
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
  /** Return null only when signature, merchant identity or event freshness validation fails. */
  abstract verifyWebhook(input: RegistryBillingWebhookInput, signal: AbortSignal):
    Promise<RegistryBillingVerifiedEvent | null>
}
