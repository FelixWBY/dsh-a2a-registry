import { useId, useRef, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { organizationHref } from './navigation.ts'
import { RegistryApiError } from './registry-api.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import css from './Registry.module.css'

type Translate = RegistryPageProps['t']

/** Create the first or an additional organization through the authenticated SaaS control plane. */
export function OrganizationPage({ t, createOrganization }:
  { t: Translate; createOrganization: RegistryPageProps['createOrganization'] }) {
  const [name, setName] = useState('')
  const [status, setStatus] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const idempotencyKey = useRef(globalThis.crypto.randomUUID())
  const titleId = useId()
  const statusId = useId()

  return (
    <section className={css.organizationPage} aria-labelledby={titleId}>
      <header className={css.organizationHeader}>
        <a className={css.organizationBrand} href="#/"><RegistryIcon name="brand" size={26} /><span aria-hidden="true">/</span><strong>{t('newOrganization')}</strong></a>
        <span className={css.organizationHelp}><RegistryIcon name="info" size={18} /><span>{t('organizationAccountRequired')}</span></span>
      </header>
      <div className={css.organizationCanvas}>
        <form className={css.organizationCard} aria-describedby={statusId} onSubmit={(event) => {
          event.preventDefault()
          const displayName = name.trim()
          if (displayName === '' || submitting) return
          const controller = new AbortController()
          setSubmitting(true)
          setStatus(t('organizationCreating'))
          void createOrganization({ displayName, idempotencyKey: idempotencyKey.current }, controller.signal).then((organization) => {
            window.location.hash = organizationHref(organization.organizationId, 'overview')
          }, (error: unknown) => {
            setSubmitting(false)
            setStatus(t(error instanceof RegistryApiError && error.code === 'conflict'
              ? 'organizationCreateConflict' : 'organizationCreateFailed'))
          })
        }}>
          <div className={css.organizationIntro}><h1 id={titleId}>{t('organizationCreateTitle')}</h1><p>{t('organizationCreateDescription')}</p></div>
          <div className={css.organizationRow}>
            <label htmlFor="registry-organization-name">{t('organizationName')}</label>
            <div><input id="registry-organization-name" value={name} autoComplete="organization" maxLength={80} disabled={submitting} placeholder={t('organizationNamePlaceholder')} onChange={(event) => { setName(event.currentTarget.value); setStatus(null) }} /><p>{t('organizationNameHelp')}</p></div>
          </div>
          <p id={statusId} className={css.organizationStatus} role="status">{status ?? t('organizationCreateReady')}</p>
          <footer className={css.organizationActions}><a href="#/">{t('cancel')}</a><button type="submit" disabled={name.trim().length === 0 || submitting}>{t(submitting ? 'organizationCreating' : 'createOrganization')}</button></footer>
        </form>
      </div>
    </section>
  )
}
