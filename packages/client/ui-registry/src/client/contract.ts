import type { InjectFace, PropsLocale, PropsRenderSlots, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type { LocaleSnapshot } from '@deepseek-ai/dsh-client-locale/client'
import type { ThemePreference, ThemeSnapshot } from '@deepseek-ai/dsh-client-ui-theme/client'
import type { HostObservable } from '@deepseek-ai/dsh-client-ui-slots'
import type { RegistryPage } from './navigation.ts'
import type { RegistryKey } from './locales.ts'
import type {
  RegistryAccountContext,
  RegistryAuditPage,
  RegistryA2aRequestPage,
  RegistryBindingReview,
  RegistryBillingCheckout,
  RegistryBillingCheckoutRequest,
  RegistryBillingOrderPage,
  RegistryBillingPlanPage,
  RegistryDisclosureContent,
  RegistryDisclosureDetail,
  RegistryDisclosurePage,
  RegistryImportRequest,
  RegistryImportResult,
  RegistryImportTargetPage,
  RegistryDirectoryPage,
  RegistryDirectoryChange,
  RegistryDirectoryChangeReceipt,
  RegistryInvitation,
  RegistryInvitationCreateRequest,
  RegistryInvitationCreated,
  RegistryInvitationPage,
  RegistryInvitationPreview,
  RegistryInstance,
  RegistryInstancePage,
  RegistryListRequest,
  RegistryQuestionRequest,
  RegistryQuestionResult,
  RegistryRuntimeStatus,
  RegistryOrganizationCreateRequest,
  RegistryOrganizationSummary,
} from './registry-api.ts'

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Registry shell, empty pages and setup requirements. */
    registry: RegistryKey
  }
  interface SlotMap {
    /** Independent Registry page; no Local session scope or authority. */
    'registry.page': { kind: 'single'; scope: 'root'; owner: { page: RegistryPage } }
  }
}

/** Registry-private observable values and actions bound by the renderer. */
export interface RegistryInjected {
  /** Route and preference sources stay outside React. */
  hooks: { page: HostObservable<RegistryPage>; locale: HostObservable<LocaleSnapshot> }
  /** Select a built-in locale for the current browser session. */
  setLocale: (id: 'zh' | 'en') => void
  /** Explicit browser configuration; true only for a locally composed non-production identity. */
  localTestIdentityBanner: boolean
  /** Read the signed-in account and every organization currently visible to it. */
  readAccount: (signal: AbortSignal) => Promise<RegistryAccountContext>
}

/** Root inputs derive from the registered child, locale and injection declarations. */
export type RegistryRootProps = PropsRuntime<'root'> & PropsRenderSlots<'registry.page'> & PropsLocale<'registry'> & InjectFace<RegistryInjected>

/** Page-local access to the same theme owner used by the Registry root. */
export interface RegistryPageInjected {
  /** The renderer binds the existing theme source without a second subscription owner. */
  hooks: { theme: HostObservable<ThemeSnapshot> }
  /** Select a built-in preference through the session-scoped ThemeRuntime. */
  setTheme: (preference: ThemePreference) => void
  /** True only for the explicitly composed loopback environment, never production readiness. */
  localTestIdentityBanner: boolean
  /** Read explicit Registry startup configuration facts without inferring liveness. */
  readStatus: (signal: AbortSignal) => Promise<RegistryRuntimeStatus>
  /** Read the signed-in account without selecting an organization. */
  readAccount: (signal: AbortSignal) => Promise<RegistryAccountContext>
  /** Create one organization and its owner membership as an idempotent server transaction. */
  createOrganization: (request: RegistryOrganizationCreateRequest,
    signal: AbortSignal) => Promise<RegistryOrganizationSummary>
  /** Read the current administrator-visible organization member and team directory. */
  readDirectory: (organizationId: string, signal: AbortSignal) => Promise<RegistryDirectoryPage>
  /** Apply one optimistic owner/admin directory mutation. */
  changeDirectory: (organizationId: string, expectedRevision: number, change: RegistryDirectoryChange,
    signal: AbortSignal) => Promise<RegistryDirectoryChangeReceipt>
  /** List invitation metadata; raw join tokens never appear in this response. */
  listInvitations: (organizationId: string, signal: AbortSignal) => Promise<RegistryInvitationPage>
  /** Create an invitation and return its raw token exactly once. */
  createInvitation: (organizationId: string, request: RegistryInvitationCreateRequest,
    signal: AbortSignal) => Promise<RegistryInvitationCreated>
  revokeInvitation: (organizationId: string, invitationId: string,
    signal: AbortSignal) => Promise<RegistryInvitation>
  /** Preview and resolve one invitation directly from its URL token. */
  readInvitation: (token: string, signal: AbortSignal) => Promise<RegistryInvitationPreview>
  acceptInvitation: (token: string, signal: AbortSignal) => Promise<RegistryOrganizationSummary>
  declineInvitation: (token: string, signal: AbortSignal) => Promise<RegistryInvitationPreview>
  /** List deployment-owned fixed-price plans for an active organization Owner. */
  listBillingPlans: (organizationId: string, signal: AbortSignal) => Promise<RegistryBillingPlanPage>
  /** List the newest persistent organization orders for an active organization Owner. */
  listBillingOrders: (organizationId: string, signal: AbortSignal) => Promise<RegistryBillingOrderPage>
  /** Reserve an order and create one provider-hosted checkout. */
  createBillingCheckout: (organizationId: string, request: RegistryBillingCheckoutRequest,
    signal: AbortSignal) => Promise<RegistryBillingCheckout>
  /** Read current account-owned instance bindings and ephemeral observations. */
  listInstances: (organizationId: string, signal: AbortSignal) => Promise<RegistryInstancePage>
  /** Rename one currently confirmed binding owned by the authenticated account. */
  renameInstance: (organizationId: string, bindingId: string, instanceName: string,
    signal: AbortSignal) => Promise<RegistryInstance>
  /** Revoke one currently confirmed binding owned by the authenticated account. */
  revokeInstance: (organizationId: string, bindingId: string, signal: AbortSignal) => Promise<RegistryInstance>
  /** Review one device-started binding with the signed-in member's one-time code. */
  reviewBinding: (organizationId: string, bindingId: string, code: string,
    signal: AbortSignal) => Promise<RegistryBindingReview>
  /** Approve one reviewed binding after fresh account authorization. */
  approveBinding: (organizationId: string, bindingId: string, code: string, instanceName: string,
    signal: AbortSignal) => Promise<RegistryBindingReview>
  /** Reject one reviewed binding after fresh account authorization. */
  rejectBinding: (organizationId: string, bindingId: string, code: string,
    signal: AbortSignal) => Promise<RegistryBindingReview>
  /** Read one authorized page of structured Registry audit metadata. */
  listAudit: (organizationId: string, request: RegistryListRequest,
    signal: AbortSignal) => Promise<RegistryAuditPage>
  /** Read one authorized page of durable A2A question metadata without question or reply text. */
  listBranches: (organizationId: string, request: RegistryListRequest,
    signal: AbortSignal) => Promise<RegistryA2aRequestPage>
  /** Read only the current caller's authorized Registry metadata page. */
  listDisclosures: (organizationId: string, request: RegistryListRequest,
    signal: AbortSignal) => Promise<RegistryDisclosurePage>
  /** Read one authorized metadata record; nonexistent and unauthorized resources share one failure. */
  readDisclosure: (organizationId: string, disclosureId: string,
    signal: AbortSignal) => Promise<RegistryDisclosureDetail>
  /** Read one immutable checkpoint's authorized plain-text events without retaining a browser cache. */
  readDisclosureContent: (organizationId: string, disclosureId: string, checkpointHash: string,
    signal: AbortSignal) => Promise<RegistryDisclosureContent>
  /** List provider-confirmed target bindings for the currently authorized import. */
  listImportTargets: (organizationId: string, disclosureId: string,
    signal: AbortSignal) => Promise<RegistryImportTargetPage>
  /** Ask the Host to import the currently authorized checkpoint into one selected bound DSH. */
  importDisclosure: (organizationId: string, disclosureId: string, request: RegistryImportRequest,
    signal: AbortSignal) => Promise<RegistryImportResult>
  /** Reauthorize and read one durable context-import operation. */
  readImport: (organizationId: string, disclosureId: string, operationId: string,
    signal: AbortSignal) => Promise<RegistryImportResult>
  /** Ask the Host to deliver one pure-text question to the source DSH. */
  askDisclosure: (organizationId: string, disclosureId: string, request: RegistryQuestionRequest,
    signal: AbortSignal) => Promise<RegistryQuestionResult>
  /** Reauthorize and read one durable question status and completed plain-text reply. */
  readQuestion: (organizationId: string, disclosureId: string, requestId: string,
    signal: AbortSignal) => Promise<RegistryQuestionResult>
  /** Reauthorize and cancel one question while it remains queued. */
  cancelQuestion: (organizationId: string, disclosureId: string, requestId: string,
    signal: AbortSignal) => Promise<RegistryQuestionResult>
}

/** Page inputs derive from the public route, locale and theme injection declarations. */
export type RegistryPageProps = PropsRuntime<'registry.page'> & PropsLocale<'registry'> & InjectFace<RegistryPageInjected>

/** Stable organization-bound callbacks passed from the route owner to existing page components. */
export interface RegistryOrganizationPageActions {
  readDirectory: (signal: AbortSignal) => Promise<RegistryDirectoryPage>
  changeDirectory: (expectedRevision: number, change: RegistryDirectoryChange,
    signal: AbortSignal) => Promise<RegistryDirectoryChangeReceipt>
  listInvitations: (signal: AbortSignal) => Promise<RegistryInvitationPage>
  createInvitation: (request: RegistryInvitationCreateRequest,
    signal: AbortSignal) => Promise<RegistryInvitationCreated>
  revokeInvitation: (invitationId: string, signal: AbortSignal) => Promise<RegistryInvitation>
  listBillingPlans: (signal: AbortSignal) => Promise<RegistryBillingPlanPage>
  listBillingOrders: (signal: AbortSignal) => Promise<RegistryBillingOrderPage>
  createBillingCheckout: (request: RegistryBillingCheckoutRequest,
    signal: AbortSignal) => Promise<RegistryBillingCheckout>
  listInstances: (signal: AbortSignal) => Promise<RegistryInstancePage>
  renameInstance: (bindingId: string, instanceName: string, signal: AbortSignal) => Promise<RegistryInstance>
  revokeInstance: (bindingId: string, signal: AbortSignal) => Promise<RegistryInstance>
  reviewBinding: (bindingId: string, code: string, signal: AbortSignal) => Promise<RegistryBindingReview>
  approveBinding: (bindingId: string, code: string, instanceName: string,
    signal: AbortSignal) => Promise<RegistryBindingReview>
  rejectBinding: (bindingId: string, code: string, signal: AbortSignal) => Promise<RegistryBindingReview>
  listAudit: (request: RegistryListRequest, signal: AbortSignal) => Promise<RegistryAuditPage>
  listBranches: (request: RegistryListRequest, signal: AbortSignal) => Promise<RegistryA2aRequestPage>
  listDisclosures: (request: RegistryListRequest, signal: AbortSignal) => Promise<RegistryDisclosurePage>
  readDisclosure: (disclosureId: string, signal: AbortSignal) => Promise<RegistryDisclosureDetail>
  readDisclosureContent: (disclosureId: string, checkpointHash: string,
    signal: AbortSignal) => Promise<RegistryDisclosureContent>
  listImportTargets: (disclosureId: string, signal: AbortSignal) => Promise<RegistryImportTargetPage>
  importDisclosure: (disclosureId: string, request: RegistryImportRequest,
    signal: AbortSignal) => Promise<RegistryImportResult>
  readImport: (disclosureId: string, operationId: string, signal: AbortSignal) => Promise<RegistryImportResult>
  askDisclosure: (disclosureId: string, request: RegistryQuestionRequest,
    signal: AbortSignal) => Promise<RegistryQuestionResult>
  readQuestion: (disclosureId: string, requestId: string, signal: AbortSignal) => Promise<RegistryQuestionResult>
  cancelQuestion: (disclosureId: string, requestId: string, signal: AbortSignal) => Promise<RegistryQuestionResult>
}

export type RegistryOrganizationPageProps = Pick<RegistryPageProps,
  't' | 'useTheme' | 'setTheme' | 'localTestIdentityBanner' | 'readStatus'> & RegistryOrganizationPageActions
