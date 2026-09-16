import { useId, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import css from './Registry.module.css'

type Translate = RegistryPageProps['t']

/** Render organization setup as a local form preview until production identity is connected. */
export function OrganizationPage({ t }: { t: Translate }) {
  const [name, setName] = useState('')
  const [status, setStatus] = useState<string | null>(null)
  const titleId = useId()
  const statusId = useId()

  return (
    <section className={css.organizationPage} aria-labelledby={titleId}>
      <header className={css.organizationHeader}>
        <a className={css.organizationBrand} href="#/sign-up"><RegistryIcon name="brand" size={26} /><span aria-hidden="true">/</span><strong>{t('newOrganization')}</strong></a>
        <a className={css.organizationHelp} href="#/settings"><RegistryIcon name="info" size={18} /><span>{t('authSetupGuide')}</span></a>
      </header>
      <div className={css.organizationCanvas}>
        <form className={css.organizationCard} aria-describedby={statusId} onSubmit={(event) => { event.preventDefault(); setStatus(t('organizationUnavailable')) }}>
          <div className={css.organizationIntro}><h1 id={titleId}>{t('organizationCreateTitle')}</h1><p>{t('organizationCreateDescription')}</p></div>
          <div className={css.organizationRow}>
            <label htmlFor="registry-organization-name">{t('organizationName')}</label>
            <div><input id="registry-organization-name" value={name} autoComplete="organization" placeholder={t('organizationNamePlaceholder')} onChange={(event) => { setName(event.currentTarget.value); setStatus(null) }} /><p>{t('organizationNameHelp')}</p></div>
          </div>
          <div className={css.organizationRow}>
            <label htmlFor="registry-organization-type">{t('organizationType')}</label>
            <div><select id="registry-organization-type" defaultValue="team"><option value="personal">{t('organizationTypePersonal')}</option><option value="team">{t('organizationTypeTeam')}</option><option value="company">{t('organizationTypeCompany')}</option></select><p>{t('organizationTypeHelp')}</p></div>
          </div>
          <div className={css.organizationRow}>
            <label htmlFor="registry-identity-method">{t('organizationIdentityMethod')}</label>
            <div><select id="registry-identity-method" value="unconfigured" disabled><option value="unconfigured">{t('organizationIdentityUnconfigured')}</option></select><p>{t('organizationIdentityHelp')}</p></div>
          </div>
          <p id={statusId} className={css.organizationStatus} role="status">{status ?? t('identityMissing')}</p>
          <footer className={css.organizationActions}><a href="#/sign-up">{t('cancel')}</a><button type="submit" disabled={name.trim().length === 0}>{t('createOrganization')}</button></footer>
        </form>
      </div>
    </section>
  )
}
