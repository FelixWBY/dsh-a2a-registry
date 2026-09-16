import type { RegistryPageProps } from './contract.ts'
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

/** Route public setup pages and authorized Registry metadata through injected callbacks. */
export function RegistryPage(props: RegistryPageProps) {
  const { page, t, useTheme, setTheme } = props
  if (typeof page !== 'string') {
    if (page.kind === 'nodeDetail') return <NodeDetailPage
      key={page.instanceId}
      instanceId={page.instanceId}
      t={t}
      listInstances={props.listInstances}
      listDisclosures={props.listDisclosures}
    />
    if (page.kind === 'questionDetail') return <QuestionDetailPage
      key={`${page.disclosureId}:${page.requestId}`}
      disclosureId={page.disclosureId}
      requestId={page.requestId}
      t={t}
      readQuestion={props.readQuestion}
      cancelQuestion={props.cancelQuestion}
    />
    return <DisclosureDetailPage
      key={page.disclosureId}
      disclosureId={page.disclosureId}
      t={t}
      readDisclosure={props.readDisclosure}
      readDisclosureContent={props.readDisclosureContent}
      listImportTargets={props.listImportTargets}
      importDisclosure={props.importDisclosure}
      readImport={props.readImport}
      askDisclosure={props.askDisclosure}
    />
  }
  if (page === 'signIn' || page === 'signUp') return <AuthPage mode={page} t={t} readStatus={props.readStatus} />
  if (page === 'newOrganization') return <OrganizationPage t={t} />
  if (page === 'notFound') return <AccessLossPage t={t} />
  if (page === 'audit') return <AuditPage t={t} listAudit={props.listAudit} />
  if (page === 'settings') return <SettingsPage t={t} useTheme={useTheme} setTheme={setTheme}
    localTestIdentityBanner={props.localTestIdentityBanner} readStatus={props.readStatus} />
  if (page === 'overview') return <OverviewPage t={t} localTestIdentityBanner={props.localTestIdentityBanner}
    readStatus={props.readStatus} />
  if (page === 'members') return <MembersPage t={t} readDirectory={props.readDirectory} />
  if (page === 'nodes') return <NodesPage t={t} listInstances={props.listInstances}
    renameInstance={props.renameInstance} revokeInstance={props.revokeInstance} />
  if (page === 'binding') return <BindingPage t={t} listInstances={props.listInstances}
    reviewBinding={props.reviewBinding} approveBinding={props.approveBinding} rejectBinding={props.rejectBinding} />
  if (page === 'disclosures') return <DisclosureListPage t={t} listDisclosures={props.listDisclosures} />
  return <BranchesPage t={t} listBranches={props.listBranches} />
}
