import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import clsx from 'clsx'
import { Button, IconCloseOutline16, IconGlobeOutline14, IconPanelLeftOutline16 } from '@deepseek-ai/dsh-client-ui-primitives'
import type { RegistryRootProps } from './contract.ts'
import { organizationHref, PRIMARY_PAGES, registryOrganizationId, registryPageKey } from './navigation.ts'
import { RegistryApiError, type RegistryAccountContext, type RegistryOrganizationSummary } from './registry-api.ts'
import { OrganizationSwitcher } from './OrganizationSwitcher.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import css from './Registry.module.css'

type AccountState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unauthenticated' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly loadedForOrganizationId: string | null; readonly account: RegistryAccountContext }

function activeOrganizations(account: RegistryAccountContext): readonly RegistryOrganizationSummary[] {
  return account.organizations.filter(organization =>
    organization.state === 'active' && organization.membershipState === 'active')
}

function replaceHash(hash: string): void {
  if (window.location.hash !== hash) window.location.replace(hash)
}

/** Compose the Registry shell around an account whose selected organization exists only in the URL. */
export function RegistryRoot(props: RegistryRootProps) {
  const { t } = props
  const page = props.usePage(value => value)
  const pageKey = registryPageKey(page)
  const organizationId = registryOrganizationId(page)
  const organizationPage = typeof page === 'object' ? page.page : null
  const primaryPage = typeof organizationPage === 'string'
    ? organizationPage
    : organizationPage?.kind === 'nodeDetail' ? 'nodes' : 'disclosures'
  const activeLocale = props.useLocale(value => value.active)
  const [navigationOpen, setNavigationOpen] = useState(false)
  const [accountRevision, setAccountRevision] = useState(0)
  const [accountState, setAccountState] = useState<AccountState>({ kind: 'loading' })
  const navigationId = useId()
  const navigationRef = useRef<HTMLElement>(null)
  const contentRef = useRef<HTMLDivElement>(null)
  const openerRef = useRef<HTMLButtonElement | null>(null)
  const identityBanner = props.localTestIdentityBanner
    ? <div className={css.localTestIdentityBanner} role="status">{t('localTestIdentityBanner')}</div>
    : null

  useEffect(() => {
    const controller = new AbortController()
    setAccountState({ kind: 'loading' })
    const loadedForOrganizationId = organizationId
    void props.readAccount(controller.signal).then((account) => {
      if (!controller.signal.aborted) setAccountState({ kind: 'ready', loadedForOrganizationId, account })
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      setAccountState({ kind: error instanceof RegistryApiError && error.code === 'unauthenticated'
        ? 'unauthenticated' : 'retry' })
    })
    return () => { controller.abort() }
  }, [props.readAccount, accountRevision, organizationId])

  useEffect(() => {
    if (accountState.kind === 'unauthenticated') {
      if (page !== 'signIn' && page !== 'signUp') replaceHash('#/sign-in')
      return
    }
    if (accountState.kind !== 'ready' || accountState.loadedForOrganizationId !== organizationId
      || page === 'newOrganization') return
    const organizations = activeOrganizations(accountState.account)
    if (typeof page === 'object' && organizations.some(item => item.organizationId === page.organizationId)) return
    if (organizations[0] === undefined) replaceHash('#/new-organization')
    else replaceHash(organizationHref(organizations[0].organizationId, 'overview'))
  }, [accountState, page])

  useLayoutEffect(() => {
    if (!navigationOpen) {
      openerRef.current?.focus()
      return
    }
    const panel = navigationRef.current
    const content = contentRef.current
    const opener = openerRef.current
    /* v8 ignore next -- both DOM refs are committed before this effect; only the mounted opener can open navigation. */
    if (!panel || !content || !opener) return
    const previousInert = content.inert
    const candidates = () => Array.from(panel.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], summary')).filter(element => element.tabIndex >= 0)
    const focusFirst = () => { (candidates()[0] ?? panel).focus() }
    content.inert = true
    focusFirst()

    const keepFocus = () => {
      if (!panel.contains(document.activeElement)) focusFirst()
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        setNavigationOpen(false)
      } else if (event.key === 'Tab') {
        const elements = candidates()
        const index = elements.findIndex(element => element === document.activeElement)
        if (event.shiftKey) {
          if (index <= 0) {
            event.preventDefault()
            ;(elements.at(-1) ?? panel).focus()
          }
        } else if (index === -1 || index === elements.length - 1) {
          event.preventDefault()
          focusFirst()
        }
      }
    }
    document.addEventListener('focusin', keepFocus)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('focusin', keepFocus)
      document.removeEventListener('keydown', onKeyDown)
      content.inert = previousInert
    }
  }, [navigationOpen, page])

  if (page === 'signIn' || page === 'signUp') {
    return <div className={css.standaloneShell}>{identityBanner}<main className={css.standaloneMain}>{props.renderSlot('registry.page', { page })}</main></div>
  }

  if (page === 'newOrganization' && accountState.kind === 'ready') {
    return <div className={css.standaloneShell}>{identityBanner}<main className={css.standaloneMain}>{props.renderSlot('registry.page', { page })}</main></div>
  }

  if (typeof page !== 'object') {
    return <div className={css.standaloneShell}>{identityBanner}<main className={css.accountBootstrap}>
      {accountState.kind === 'retry' ? <><RegistryIcon name="warning" size={34} /><h1>{t('accountUnavailable')}</h1><p>{t('accountUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setAccountRevision(value => value + 1) }}>{t('retry')}</button></>
        : <><span className={css.spinner} aria-hidden="true" /><p>{t('loadingAccount')}</p></>}
    </main></div>
  }

  const organizations = accountState.kind === 'ready' ? activeOrganizations(accountState.account) : []
  const currentOrganization = organizations.find(item => item.organizationId === page.organizationId)

  return (
    <div className={css.shell}>
      <aside ref={navigationRef} id={navigationId} tabIndex={-1} role={navigationOpen ? 'dialog' : undefined} aria-modal={navigationOpen ? true : undefined} aria-label={navigationOpen ? t('navigation') : undefined} className={clsx(css.sidebar, navigationOpen && css.sidebarOpen)}>
        <div className={css.brand}><RegistryIcon name="brand" size={30} /><span>{t('brand')}</span><Button className={css.closeNavigation} aria-label={t('closeNavigation')} onClick={() => { setNavigationOpen(false) }}><IconCloseOutline16 /></Button></div>
        <nav className={css.navigation} aria-label={t('navigation')}>
          {PRIMARY_PAGES.map(item => <a key={item} href={organizationHref(page.organizationId, item)} className={clsx(css.navLink, primaryPage === item && css.selected)} aria-current={primaryPage === item ? 'page' : undefined} onClick={() => { setNavigationOpen(false) }}><RegistryIcon name={item} /><span>{t(item)}</span></a>)}
        </nav>
        <div className={css.sidebarFooter}>
          {currentOrganization === undefined
            ? <div className={css.organizationLoading}><span className={css.spinner} aria-hidden="true" /><span>{t('loadingAccount')}</span></div>
            : <OrganizationSwitcher current={currentOrganization} organizations={organizations} t={t} />}
        </div>
      </aside>
      <div ref={contentRef} className={css.content}>
        <header className={css.header}>
          <Button className={css.openNavigation} aria-label={t('openNavigation')} aria-controls={navigationId} aria-expanded={navigationOpen} onClick={(event) => { openerRef.current = event.currentTarget; setNavigationOpen(true) }}><IconPanelLeftOutline16 /></Button>
          <div className={css.breadcrumb}>
            <span>{currentOrganization?.displayName ?? t('loadingOrganization')}</span>
            <span aria-hidden="true">/</span>
            <span>{t(pageKey)}</span>
          </div>
          <div className={css.headerActions}>
            {identityBanner}
            <Button variant="outline" className={css.language} icon={<IconGlobeOutline14 />} onClick={() => { props.setLocale(activeLocale === 'zh' ? 'en' : 'zh') }}>{t('switchLanguage')}</Button>
          </div>
        </header>
        <main className={css.main}>{props.renderSlot('registry.page', { page })}</main>
      </div>
    </div>
  )
}
