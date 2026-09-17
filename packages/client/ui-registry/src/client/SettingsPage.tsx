import { useEffect, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { organizationHref } from './navigation.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import type { RegistryConfigurationState, RegistryRuntimeStatus } from './registry-api.ts'
import css from './Registry.module.css'

type SettingsPageProps = Pick<RegistryPageProps, 't' | 'useTheme' | 'setTheme' | 'localTestIdentityBanner' | 'readStatus'> & {
  readonly organizationId: string
}
type SettingsState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly status: RegistryRuntimeStatus }

const requirements = [
  { fields: ['identity'], titleKey: 'identityTitle', bodyKey: 'identityRequirement' },
  { fields: ['registry', 'disclosureOperations'], titleKey: 'apiTitle', bodyKey: 'apiRequirement' },
  { fields: ['deviceBinding'], titleKey: 'deviceTitle', bodyKey: 'deviceRequirement' },
  { fields: ['audit'], titleKey: 'overviewAudit', bodyKey: 'overviewAuditDescription' },
  { fields: ['rateLimits'], titleKey: 'overviewRateLimits', bodyKey: 'overviewRateLimitsDescription' },
  { fields: ['disclosureCleanup'], titleKey: 'overviewDisclosureCleanup', bodyKey: 'overviewDisclosureCleanupDescription' },
  { fields: ['mailboxCleanup'], titleKey: 'overviewMailboxCleanup', bodyKey: 'overviewMailboxCleanupDescription' },
  { fields: ['billing'], titleKey: 'overviewBilling', bodyKey: 'overviewBillingDescription' },
] as const

function statusKey(state: RegistryConfigurationState, localTest: boolean): 'statusConfigured' | 'statusLocalTest' | 'statusUnconfigured' {
  if (state !== 'configured') return 'statusUnconfigured'
  return localTest ? 'statusLocalTest' : 'statusConfigured'
}

/** Render runtime-confirmed setup facts without treating local test identity as production sign-in. */
export function SettingsPage({ organizationId, t, useTheme, setTheme, localTestIdentityBanner, readStatus }: SettingsPageProps) {
  const preference = useTheme(snapshot => snapshot.preference)
  const [requestRevision, setRequestRevision] = useState(0)
  const [state, setState] = useState<SettingsState>({ kind: 'loading' })

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
  const ready = !localTest && state.kind === 'ready'
    && requirements.every(({ fields }) => fields[0] === 'billing'
      || fields.every(field => state.status[field] === 'configured'))
  const statusTitle = localTest
    ? t('settingsLocalTest')
    : ready ? t('settingsReady') : t('settingsIncomplete')
  return (
    <section>
      <div className={css.pageHeading}><h1>{t('settings')}</h1><p>{t('settingsDescription')}</p></div>
      {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingOverview')}</p></div>}
      {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRequestRevision(value => value + 1) }}>{t('retry')}</button></div>}
      {state.kind === 'ready' && <>
        <section className={css.settingsStatus} aria-labelledby="registry-settings-status-title">
          <RegistryIcon name={ready ? 'audit' : 'info'} />
          <div>
            <h2 id="registry-settings-status-title">{statusTitle}</h2>
            <p>{t(localTest ? 'settingsLocalTestNote' : 'settingsStatusNote')}</p>
            <p>{t('noLocalData')}</p>
          </div>
        </section>
      </>}
      <section className={css.requirements} aria-labelledby="registry-settings-requirements-title">
        <h2 id="registry-settings-requirements-title">{t('requirementsHeading')}</h2>
        <dl>{requirements.map(({ fields, titleKey, bodyKey }) => {
          const status = state.kind === 'ready'
            ? fields.every(field => state.status[field] === 'configured') ? 'configured' : 'unconfigured'
            : null
          const configured = status === 'configured' && !localTest
          return <div className={css.requirement} key={titleKey}><dt>{t(titleKey)}</dt><dd>{t(bodyKey)}{fields[0] === 'deviceBinding' ? <p><a href={organizationHref(organizationId, 'binding')}>{t('bindingScopeLink')}</a></p> : null}</dd><dd className={configured ? css.overviewConfigured : css.overviewUnconfigured}>{t(status === null ? 'statusUnknown' : statusKey(status, localTest))}</dd></div>
        })}</dl>
      </section>
      <div className={css.notice}><RegistryIcon name="info" /><p>{t('securityNote')}</p></div>
      {state.kind === 'ready' && state.status.identityProvider === 'oidc' && <section className={css.preference} aria-labelledby="registry-settings-account-title">
        <h2 id="registry-settings-account-title">{t('accountSessionHeading')}</h2>
        <p>{t('accountSessionDescription')}</p>
        <form method="post" action="/registry-auth/v1/logout"><button type="submit" className={css.secondaryButton}>{t('signOutAction')}</button></form>
      </section>}
      <section className={css.preference} aria-labelledby="registry-settings-preferences-title">
        <h2 id="registry-settings-preferences-title">{t('preferencesHeading')}</h2><p id="registry-session-preference">{t('sessionPreference')}</p>
        <label htmlFor="registry-theme">{t('theme')}</label>
        <select id="registry-theme" className={css.themeSelect} aria-describedby="registry-session-preference" value={preference} onChange={(event) => {
          const next = event.currentTarget.value
          if (next === 'system' || next === 'light' || next === 'dark') setTheme(next)
        }}>
          <option value="system">{t('themeSystem')}</option>
          <option value="light">{t('themeLight')}</option>
          <option value="dark">{t('themeDark')}</option>
        </select>
      </section>
    </section>
  )
}
