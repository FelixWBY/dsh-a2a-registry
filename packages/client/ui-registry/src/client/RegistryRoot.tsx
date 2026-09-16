import { useId, useLayoutEffect, useRef, useState } from 'react'
import clsx from 'clsx'
import { Button, IconCloseOutline16, IconGlobeOutline14, IconPanelLeftOutline16 } from '@deepseek-ai/dsh-client-ui-primitives'
import type { RegistryRootProps } from './contract.ts'
import { PRIMARY_PAGES, registryPageKey } from './navigation.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import css from './Registry.module.css'

/** Compose the Registry shell without mounting Local Chat or any local data source. */
export function RegistryRoot(props: RegistryRootProps) {
  const { t } = props
  const page = props.usePage(value => value)
  const pageKey = registryPageKey(page)
  const primaryPage = typeof page === 'string' ? page : page.kind === 'nodeDetail' ? 'nodes' : 'disclosures'
  const activeLocale = props.useLocale(value => value.active)
  const [navigationOpen, setNavigationOpen] = useState(false)
  const navigationId = useId()
  const navigationRef = useRef<HTMLElement>(null)
  const contentRef = useRef<HTMLDivElement>(null)
  const openerRef = useRef<HTMLButtonElement | null>(null)
  const identityBanner = props.localTestIdentityBanner
    ? <div className={css.localTestIdentityBanner} role="status">{t('localTestIdentityBanner')}</div>
    : null

  useLayoutEffect(() => {
    if (!navigationOpen) {
      // Return focus after React has committed the closed overlay, not during
      // layout-effect cleanup where React can still restore the old selection.
      openerRef.current?.focus()
      return
    }
    const panel = navigationRef.current
    const content = contentRef.current
    const opener = openerRef.current
    /* v8 ignore next -- both DOM refs are committed before this effect; only the mounted opener can open navigation. */
    if (!panel || !content || !opener) return
    const previousInert = content.inert
    const candidates = () => Array.from(panel.querySelectorAll<HTMLElement>('button:not(:disabled), a[href]')).filter(element => element.tabIndex >= 0)
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
    // Inert excludes the page from native keyboard navigation; the guard also
    // keeps explicit focus changes inside this component-owned overlay.
    document.addEventListener('focusin', keepFocus)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('focusin', keepFocus)
      document.removeEventListener('keydown', onKeyDown)
      content.inert = previousInert
    }
  }, [navigationOpen, page])

  if (page === 'signIn' || page === 'signUp' || page === 'newOrganization') {
    return <div className={css.standaloneShell}>{identityBanner}<main className={css.standaloneMain}>{props.renderSlot('registry.page', { page })}</main></div>
  }

  return (
    <div className={css.shell}>
      <aside ref={navigationRef} id={navigationId} tabIndex={-1} role={navigationOpen ? 'dialog' : undefined} aria-modal={navigationOpen ? true : undefined} aria-label={navigationOpen ? t('navigation') : undefined} className={clsx(css.sidebar, navigationOpen && css.sidebarOpen)}>
        <div className={css.brand}><RegistryIcon name="brand" size={30} /><span>{t('brand')}</span><Button className={css.closeNavigation} aria-label={t('closeNavigation')} onClick={() => { setNavigationOpen(false) }}><IconCloseOutline16 /></Button></div>
        <nav className={css.navigation} aria-label={t('navigation')}>
          {PRIMARY_PAGES.map(item => <a key={item} href={`#/${item}`} className={clsx(css.navLink, primaryPage === item && css.selected)} aria-current={primaryPage === item ? 'page' : undefined} onClick={() => { setNavigationOpen(false) }}><RegistryIcon name={item} /><span>{t(item)}</span></a>)}
        </nav>
        <div className={css.sidebarFooter}>
          <RegistryIcon name="members" />
          <div className={css.sidebarMeta}>
            <strong>{t(props.localTestIdentityBanner ? 'localTestOrganization' : 'organization')}</strong>
            <span>{t('collaboration')}</span>
          </div>
        </div>
      </aside>
      <div ref={contentRef} className={css.content}>
        <header className={css.header}>
          <Button className={css.openNavigation} aria-label={t('openNavigation')} aria-controls={navigationId} aria-expanded={navigationOpen} onClick={(event) => { openerRef.current = event.currentTarget; setNavigationOpen(true) }}><IconPanelLeftOutline16 /></Button>
          <div className={css.breadcrumb}>
            <span>{t(props.localTestIdentityBanner ? 'localTestOrganization' : 'registry')}</span>
            <span aria-hidden="true">/</span>
            <span>{t(pageKey)}</span>
          </div>
          <div className={css.headerActions}>
            {identityBanner}
            {!props.localTestIdentityBanner && <a className={css.organization} href="#/sign-in">{t('organization')}</a>}
            <Button variant="outline" className={css.language} icon={<IconGlobeOutline14 />} onClick={() => { props.setLocale(activeLocale === 'zh' ? 'en' : 'zh') }}>{t('switchLanguage')}</Button>
          </div>
        </header>
        <main className={css.main}>{props.renderSlot('registry.page', { page })}</main>
      </div>
    </div>
  )
}
