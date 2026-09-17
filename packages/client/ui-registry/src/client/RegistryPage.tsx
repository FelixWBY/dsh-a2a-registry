import { useMemo } from 'react'
import type { RegistryOrganizationPageActions, RegistryPageProps } from './contract.ts'
import type { RegistryOrganizationPage as OrganizationPageRoute } from './navigation.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { AuthPage } from './AuthPage.tsx'
import { AuditPage } from './AuditPage.tsx'
import { BindingPage } from './BindingPage.tsx'
import { BranchesPage } from './BranchesPage.tsx'
import { DisclosureDetailPage } from './DisclosureDetailPage.tsx'
import { DisclosureListPage } from './DisclosureListPage.tsx'
import { OrganizationPage } from './OrganizationPage.tsx'
import { QuestionDetailPage } from './QuestionDetailPage.tsx'
import { NodesPage } from './NodesPage.tsx'
import { MembersPage } from './MembersPage.tsx'
import { NodeDetailPage } from './NodeDetailPage.tsx'
import { OverviewPage } from './OverviewPage.tsx'
import { SettingsPage } from './SettingsPage.tsx'

function OrganizationRegistryPage({ organizationId, page, props }:
  { organizationId: string; page: OrganizationPageRoute; props: RegistryPageProps }) {
  const api = useMemo<RegistryOrganizationPageActions>(() => ({
    readDirectory: signal => props.readDirectory(organizationId, signal),
    changeDirectory: (expectedRevision, change, signal) =>
      props.changeDirectory(organizationId, expectedRevision, change, signal),
    listInstances: signal => props.listInstances(organizationId, signal),
    renameInstance: (bindingId, instanceName, signal) =>
      props.renameInstance(organizationId, bindingId, instanceName, signal),
    revokeInstance: (bindingId, signal) => props.revokeInstance(organizationId, bindingId, signal),
    reviewBinding: (bindingId, code, signal) => props.reviewBinding(organizationId, bindingId, code, signal),
    approveBinding: (bindingId, code, instanceName, signal) =>
      props.approveBinding(organizationId, bindingId, code, instanceName, signal),
    rejectBinding: (bindingId, code, signal) => props.rejectBinding(organizationId, bindingId, code, signal),
    listAudit: (request, signal) => props.listAudit(organizationId, request, signal),
    listBranches: (request, signal) => props.listBranches(organizationId, request, signal),
    listDisclosures: (request, signal) => props.listDisclosures(organizationId, request, signal),
    readDisclosure: (disclosureId, signal) => props.readDisclosure(organizationId, disclosureId, signal),
    readDisclosureContent: (disclosureId, checkpointHash, signal) =>
      props.readDisclosureContent(organizationId, disclosureId, checkpointHash, signal),
    listImportTargets: (disclosureId, signal) => props.listImportTargets(organizationId, disclosureId, signal),
    importDisclosure: (disclosureId, request, signal) =>
      props.importDisclosure(organizationId, disclosureId, request, signal),
    readImport: (disclosureId, operationId, signal) =>
      props.readImport(organizationId, disclosureId, operationId, signal),
    askDisclosure: (disclosureId, request, signal) =>
      props.askDisclosure(organizationId, disclosureId, request, signal),
    readQuestion: (disclosureId, requestId, signal) =>
      props.readQuestion(organizationId, disclosureId, requestId, signal),
    cancelQuestion: (disclosureId, requestId, signal) =>
      props.cancelQuestion(organizationId, disclosureId, requestId, signal),
  }), [organizationId, props.approveBinding, props.askDisclosure, props.cancelQuestion, props.changeDirectory,
    props.importDisclosure, props.listAudit, props.listBranches, props.listDisclosures, props.listImportTargets,
    props.listInstances, props.readDirectory, props.readDisclosure, props.readDisclosureContent, props.readImport,
    props.readQuestion, props.rejectBinding, props.renameInstance, props.reviewBinding, props.revokeInstance])

  const { t, useTheme, setTheme } = props
  if (typeof page !== 'string') {
    if (page.kind === 'nodeDetail') return <NodeDetailPage
      key={page.instanceId}
      organizationId={organizationId}
      instanceId={page.instanceId}
      t={t}
      listInstances={api.listInstances}
      listDisclosures={api.listDisclosures}
    />
    if (page.kind === 'questionDetail') return <QuestionDetailPage
      key={`${page.disclosureId}:${page.requestId}`}
      organizationId={organizationId}
      disclosureId={page.disclosureId}
      requestId={page.requestId}
      t={t}
      readQuestion={api.readQuestion}
      cancelQuestion={api.cancelQuestion}
    />
    return <DisclosureDetailPage
      key={page.disclosureId}
      organizationId={organizationId}
      disclosureId={page.disclosureId}
      t={t}
      readDisclosure={api.readDisclosure}
      readDisclosureContent={api.readDisclosureContent}
      listImportTargets={api.listImportTargets}
      importDisclosure={api.importDisclosure}
      readImport={api.readImport}
      askDisclosure={api.askDisclosure}
    />
  }
  if (page === 'audit') return <AuditPage t={t} listAudit={api.listAudit} />
  if (page === 'settings') return <SettingsPage organizationId={organizationId} t={t} useTheme={useTheme} setTheme={setTheme}
    localTestIdentityBanner={props.localTestIdentityBanner} readStatus={props.readStatus} />
  if (page === 'overview') return <OverviewPage organizationId={organizationId} t={t} localTestIdentityBanner={props.localTestIdentityBanner}
    readStatus={props.readStatus} />
  if (page === 'members') return <MembersPage t={t} readDirectory={api.readDirectory}
    changeDirectory={api.changeDirectory} />
  if (page === 'nodes') return <NodesPage organizationId={organizationId} t={t} listInstances={api.listInstances}
    renameInstance={api.renameInstance} revokeInstance={api.revokeInstance} />
  if (page === 'binding') return <BindingPage organizationId={organizationId} t={t} listInstances={api.listInstances}
    reviewBinding={api.reviewBinding} approveBinding={api.approveBinding} rejectBinding={api.rejectBinding} />
  if (page === 'disclosures') return <DisclosureListPage organizationId={organizationId} t={t} listDisclosures={api.listDisclosures} />
  return <BranchesPage organizationId={organizationId} t={t} listBranches={api.listBranches} />
}

/** Route public account entry and explicitly organization-scoped data pages. */
export function RegistryPage(props: RegistryPageProps) {
  const { page, t } = props
  if (page === 'signIn' || page === 'signUp') return <AuthPage mode={page} t={t} readStatus={props.readStatus} />
  if (page === 'newOrganization') return <OrganizationPage t={t} createOrganization={props.createOrganization} />
  if (typeof page !== 'object') return <AccessLossPage t={t} />
  return <OrganizationRegistryPage organizationId={page.organizationId} page={page.page} props={props} />
}
