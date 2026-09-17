import type { RegistryPageProps } from './contract.ts'
import { RegistryIcon, type RegistryIconName } from './RegistryIcon.tsx'
import css from './Registry.module.css'

interface UnconfiguredPanelProps extends Pick<RegistryPageProps, 't'> {
  icon?: RegistryIconName
  headingLevel?: 2 | 3
}

/** Explain an unavailable Registry surface without implying an empty authorized result. */
export function UnconfiguredPanel({ t, icon = 'emptyNodes', headingLevel = 2 }: UnconfiguredPanelProps) {
  return (
    <div className={css.empty}>
      <RegistryIcon name={icon} size={96} />
      {headingLevel === 3 ? <h3>{t('unconfigured')}</h3> : <h2>{t('unconfigured')}</h2>}
      <div><p>{t('identityMissing')}</p><p>{t('noLocalData')}</p></div>
      <a className={css.primaryAction} href="#/">{t('requirements')}</a>
    </div>
  )
}
