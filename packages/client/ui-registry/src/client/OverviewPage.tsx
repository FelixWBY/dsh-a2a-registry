import { useEffect, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import type { RegistryConfigurationState, RegistryRuntimeStatus } from './registry-api.ts'
import css from './Registry.module.css'

type OverviewProps = Pick<RegistryPageProps, 't' | 'localTestIdentityBanner' | 'readStatus'>
type OverviewState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly status: RegistryRuntimeStatus }

const STATUS_ROWS: readonly {
  readonly field: Exclude<keyof RegistryRuntimeStatus, 'deploymentMode' | 'identityProvider'>
  readonly icon: 'members' | 'disclosures' | 'branches' | 'nodes' | 'audit' | 'settings'
  readonly labelKey: 'overviewIdentity' | 'overviewRegistry' | 'overviewDisclosureOperations' | 'overviewDeviceBinding'
    | 'overviewAudit' | 'overviewRateLimits' | 'overviewDisclosureCleanup' | 'overviewMailboxCleanup'
  readonly descriptionKey: 'overviewIdentityDescription' | 'overviewRegistryDescription'
    | 'overviewDisclosureOperationsDescription' | 'overviewDeviceBindingDescription' | 'overviewAuditDescription'
    | 'overviewRateLimitsDescription' | 'overviewDisclosureCleanupDescription' | 'overviewMailboxCleanupDescription'
}[] = [
  { field: 'identity', icon: 'members', labelKey: 'overviewIdentity', descriptionKey: 'overviewIdentityDescription' },
  { field: 'registry', icon: 'disclosures', labelKey: 'overviewRegistry', descriptionKey: 'overviewRegistryDescription' },
  { field: 'disclosureOperations', icon: 'branches', labelKey: 'overviewDisclosureOperations',
    descriptionKey: 'overviewDisclosureOperationsDescription' },
  { field: 'deviceBinding', icon: 'nodes', labelKey: 'overviewDeviceBinding', descriptionKey: 'overviewDeviceBindingDescription' },
  { field: 'audit', icon: 'audit', labelKey: 'overviewAudit', descriptionKey: 'overviewAuditDescription' },
  { field: 'rateLimits', icon: 'settings', labelKey: 'overviewRateLimits', descriptionKey: 'overviewRateLimitsDescription' },
  { field: 'disclosureCleanup', icon: 'disclosures', labelKey: 'overviewDisclosureCleanup', descriptionKey: 'overviewDisclosureCleanupDescription' },
  { field: 'mailboxCleanup', icon: 'branches', labelKey: 'overviewMailboxCleanup', descriptionKey: 'overviewMailboxCleanupDescription' },
]

const QUICK_LINKS = [
  { page: 'members', descriptionKey: 'overviewMembersLinkDescription' },
  { page: 'nodes', descriptionKey: 'overviewNodesLinkDescription' },
  { page: 'disclosures', descriptionKey: 'overviewDisclosuresLinkDescription' },
  { page: 'audit', descriptionKey: 'overviewAuditLinkDescription' },
] as const

function statusKey(state: RegistryConfigurationState, localTest: boolean): 'statusConfigured' | 'statusLocalTest' | 'statusUnconfigured' {
  if (state !== 'configured') return 'statusUnconfigured'
  return localTest ? 'statusLocalTest' : 'statusConfigured'
}

/** Truthful startup configuration overview; it never turns configuration into a health claim. */
export function OverviewPage({ t, localTestIdentityBanner, readStatus }: OverviewProps) {
  const [requestRevision, setRequestRevision] = useState(0)
  const [state, setState] = useState<OverviewState>({ kind: 'loading' })

  useEffect(() => {
    const controller = new AbortController()
    setState({ kind: 'loading' })
    void readStatus(controller.signal).then((status) => {
      if (!controller.signal.aborted) setState({ kind: 'ready', status })
    }, () => {
      if (!controller.signal.aborted) setState({ kind: 'retry' })
    })
    return () => { controller.abort() }
  }, [readStatus, requestRevision])

  const localTest = localTestIdentityBanner || (state.kind === 'ready' && state.status.deploymentMode === 'test-only')

  return <section className={css.overviewPage}>
    <div className={css.pageHeading}><h1>{t('overview')}</h1><p>{t('overviewDescription')}</p></div>
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingOverview')}</p></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRequestRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'ready' && <>
      {localTest && <div className={css.overviewBanner} role="status">
        <RegistryIcon name="warning" />
        <div><strong>{t('overviewLocalBannerTitle')}</strong><p>{t('overviewLocalBannerDescription')}</p></div>
      </div>}
      <article className={css.overviewHero}>
        <div className={css.overviewHeroSummary}>
          <span className={css.overviewHeroIcon}><RegistryIcon name="environment" size={30} /></span>
          <div>
            <h2>{t(localTest ? 'overviewLocalEnvironmentTitle' : 'overviewDeploymentTitle')}</h2>
            <strong>{t(localTest ? 'overviewLocalEnvironmentStatus' : 'overviewDeploymentStatus')}</strong>
            <p>{t(localTest ? 'overviewLocalEnvironmentDescription' : 'overviewDeploymentDescription')}</p>
          </div>
        </div>
        <dl className={css.overviewFacts}>
          <div><dt>{t('overviewEnvironmentLabel')}</dt><dd>{t(localTest ? 'localTestIdentityBanner' : 'overviewProductionEnvironment')}</dd></div>
          <div><dt>{t('overviewIdentitySourceLabel')}</dt><dd>{t(localTest ? 'overviewLocalIdentitySource' : 'overviewProductionIdentitySource')}</dd></div>
          <div><dt>{t('overviewReadinessLabel')}</dt><dd>{t(localTest ? 'overviewProductionPending' : 'overviewConfigurationLoaded')}</dd></div>
        </dl>
      </article>

      <div className={css.overviewSectionHeading}>
        <h2>{t('overviewQuickLinks')}</h2><p>{t('overviewQuickLinksDescription')}</p>
      </div>
      <nav className={css.overviewLinks} aria-label={t('overviewQuickLinks')}>
        {QUICK_LINKS.map(item => <a key={item.page} href={`#/${item.page}`}>
          <RegistryIcon name={item.page} />
          <span><strong>{t(item.page)}</strong><small>{t(item.descriptionKey)}</small></span>
          <RegistryIcon name="arrowRight" />
        </a>)}
      </nav>

      <div className={css.overviewSectionHeading}>
        <h2>{t('overviewCapabilities')}</h2><p>{t('overviewCapabilitiesDescription')}</p>
      </div>
      <div className={css.overviewTableFrame}>
        <div className={css.tableScroll} tabIndex={0} role="region" aria-label={t('overviewCapabilities')}>
          <table className={css.overviewTable}>
            <thead><tr><th scope="col">{t('overviewCapabilityName')}</th><th scope="col">{t('overviewCapabilityDescription')}</th>
              <th scope="col">{t('overviewCapabilityStatus')}</th><th scope="col">{t('overviewCapabilityLimit')}</th></tr></thead>
            <tbody>{STATUS_ROWS.map((row) => {
              const configured = state.status[row.field] === 'configured'
              const className = configured
                ? localTest ? css.overviewLocal : css.overviewConfigured
                : css.overviewUnconfigured
              return <tr key={row.field}>
                <td data-label={t('overviewCapabilityName')}><span className={css.overviewCapability}><RegistryIcon name={row.icon} /><h2>{t(row.labelKey)}</h2></span></td>
                <td data-label={t('overviewCapabilityDescription')}>{t(row.descriptionKey)}</td>
                <td data-label={t('overviewCapabilityStatus')}><span className={className}>{t(statusKey(state.status[row.field], localTest))}</span></td>
                <td data-label={t('overviewCapabilityLimit')}>{t(localTest ? 'overviewLocalLimit' : configured ? 'overviewProductionLimit' : 'overviewNotApplicable')}</td>
              </tr>
            })}</tbody>
          </table>
        </div>
      </div>
      <div className={css.notice}><RegistryIcon name="info" />
        <p>{t(localTest ? 'overviewLocalTestNote' : 'overviewConfigurationNote')}</p>
      </div>
    </>}
  </section>
}
