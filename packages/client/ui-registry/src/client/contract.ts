import type { InjectFace, PropsLocale, PropsRenderSlots, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type { LocaleSnapshot } from '@deepseek-ai/dsh-client-locale/client'
import type { ThemePreference, ThemeSnapshot } from '@deepseek-ai/dsh-client-ui-theme/client'
import type { HostObservable } from '@deepseek-ai/dsh-client-ui-slots'
import type { RegistryPage } from './navigation.ts'
import type { RegistryKey } from './locales.ts'
import type {
  RegistryAuditPage,
  RegistryA2aRequestPage,
  RegistryBindingReview,
  RegistryDisclosureContent,
  RegistryDisclosureDetail,
  RegistryDisclosurePage,
  RegistryImportRequest,
  RegistryImportResult,
  RegistryImportTargetPage,
  RegistryDirectoryPage,
  RegistryInstance,
  RegistryInstancePage,
  RegistryListRequest,
  RegistryQuestionRequest,
  RegistryQuestionResult,
  RegistryRuntimeStatus,
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
  /** Read the current administrator-visible organization member and team directory. */
  readDirectory: (signal: AbortSignal) => Promise<RegistryDirectoryPage>
  /** Read current account-owned instance bindings and ephemeral observations. */
  listInstances: (signal: AbortSignal) => Promise<RegistryInstancePage>
  /** Rename one currently confirmed binding owned by the authenticated account. */
  renameInstance: (bindingId: string, instanceName: string, signal: AbortSignal) => Promise<RegistryInstance>
  /** Revoke one currently confirmed binding owned by the authenticated account. */
  revokeInstance: (bindingId: string, signal: AbortSignal) => Promise<RegistryInstance>
  /** Review one device-started binding with the signed-in member's one-time code. */
  reviewBinding: (bindingId: string, code: string, signal: AbortSignal) => Promise<RegistryBindingReview>
  /** Approve one reviewed binding after fresh account authorization. */
  approveBinding: (bindingId: string, code: string, instanceName: string,
    signal: AbortSignal) => Promise<RegistryBindingReview>
  /** Reject one reviewed binding after fresh account authorization. */
  rejectBinding: (bindingId: string, code: string, signal: AbortSignal) => Promise<RegistryBindingReview>
  /** Read one authorized page of structured Registry audit metadata. */
  listAudit: (request: RegistryListRequest, signal: AbortSignal) => Promise<RegistryAuditPage>
  /** Read one authorized page of durable A2A question metadata without question or reply text. */
  listBranches: (request: RegistryListRequest, signal: AbortSignal) => Promise<RegistryA2aRequestPage>
  /** Read only the current caller's authorized Registry metadata page. */
  listDisclosures: (request: RegistryListRequest, signal: AbortSignal) => Promise<RegistryDisclosurePage>
  /** Read one authorized metadata record; nonexistent and unauthorized resources share one failure. */
  readDisclosure: (disclosureId: string, signal: AbortSignal) => Promise<RegistryDisclosureDetail>
  /** Read one immutable checkpoint's authorized plain-text events without retaining a browser cache. */
  readDisclosureContent: (disclosureId: string, checkpointHash: string,
    signal: AbortSignal) => Promise<RegistryDisclosureContent>
  /** List provider-confirmed target bindings for the currently authorized import. */
  listImportTargets: (disclosureId: string, signal: AbortSignal) => Promise<RegistryImportTargetPage>
  /** Ask the Host to import the currently authorized checkpoint into one selected bound DSH. */
  importDisclosure: (disclosureId: string, request: RegistryImportRequest, signal: AbortSignal) => Promise<RegistryImportResult>
  /** Reauthorize and read one durable context-import operation. */
  readImport: (disclosureId: string, operationId: string, signal: AbortSignal) => Promise<RegistryImportResult>
  /** Ask the Host to deliver one pure-text question to the source DSH. */
  askDisclosure: (disclosureId: string, request: RegistryQuestionRequest, signal: AbortSignal) => Promise<RegistryQuestionResult>
  /** Reauthorize and read one durable question status and completed plain-text reply. */
  readQuestion: (disclosureId: string, requestId: string, signal: AbortSignal) => Promise<RegistryQuestionResult>
  /** Reauthorize and cancel one question while it remains queued. */
  cancelQuestion: (disclosureId: string, requestId: string, signal: AbortSignal) => Promise<RegistryQuestionResult>
}

/** Page inputs derive from the public route, locale and theme injection declarations. */
export type RegistryPageProps = PropsRuntime<'registry.page'> & PropsLocale<'registry'> & InjectFace<RegistryPageInjected>
