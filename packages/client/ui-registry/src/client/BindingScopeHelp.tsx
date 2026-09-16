import type { RegistryPageProps } from './contract.ts'
import css from './Registry.module.css'

const sections = [
  ['bindingSyncTitle', 'bindingSyncBody'], ['bindingReceiveTitle', 'bindingReceiveBody'],
  ['bindingReadTitle', 'bindingReadBody'], ['bindingRevokeTitle', 'bindingRevokeBody'],
] as const

/** Explain enrollment scope without accepting a code, reading identity or granting a device permission. */
export function BindingScopeHelp({ t }: Pick<RegistryPageProps, 't'>) {
  return (
    <details className={css.bindingHelp}>
      <summary>{t('bindingScopeLink')}</summary>
      <div className={css.bindingHelpContent}>
        <p>{t('bindingScopeIntro')}</p>
        <dl>{sections.map(([title, body]) => <div key={title}><dt>{t(title)}</dt><dd>{t(body)}</dd></div>)}</dl>
        <p>{t('bindingScopeUnconfigured')}</p>
      </div>
    </details>
  )
}
