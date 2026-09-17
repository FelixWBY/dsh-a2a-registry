import type { RegistryRootProps } from './contract.ts'
import { organizationHref } from './navigation.ts'
import type { RegistryOrganizationSummary } from './registry-api.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import css from './Registry.module.css'

type Translate = RegistryRootProps['t']
const ROLE_KEYS = {
  owner: 'organizationRoleOwner', admin: 'organizationRoleAdmin', member: 'organizationRoleMember',
} as const

/** URL-owned organization switcher; selecting an item never mutates a shared session tenant. */
export function OrganizationSwitcher({ current, organizations, t }:
  { current: RegistryOrganizationSummary; organizations: readonly RegistryOrganizationSummary[]; t: Translate }) {
  return <details className={css.organizationSwitcher}>
    <summary aria-label={t('switchOrganization')}>
      <RegistryIcon name="newOrganization" />
      <span className={css.sidebarMeta}><strong>{current.displayName}</strong><span>{t(ROLE_KEYS[current.role])}</span></span>
      <span className={css.organizationChevron} aria-hidden="true">⌃</span>
    </summary>
    <div className={css.organizationMenu}>
      <div className={css.organizationMenuHeading}>{t('yourOrganizations')}</div>
      {organizations.map(organization => <a
        key={organization.organizationId}
        href={organizationHref(organization.organizationId, 'overview')}
        aria-current={organization.organizationId === current.organizationId ? 'true' : undefined}
      >
        <span className={css.organizationMonogram} aria-hidden="true">{organization.displayName.slice(0, 1).toLocaleUpperCase()}</span>
        <span><strong>{organization.displayName}</strong><small>{organization.slug}</small></span>
        {organization.organizationId === current.organizationId ? <span aria-hidden="true">✓</span> : null}
      </a>)}
      <a className={css.organizationCreateLink} href="#/new-organization"><span aria-hidden="true">＋</span><strong>{t('createAnotherOrganization')}</strong></a>
    </div>
  </details>
}
