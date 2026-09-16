import type { RegistryPageProps } from './contract.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import css from './Registry.module.css'

/** Render the shared nonexistent-or-unauthorized state without accepting resource metadata. */
export function AccessLossPage({ t }: Pick<RegistryPageProps, 't'>) {
  return (
    <section className={css.access} aria-labelledby="registry-access-loss-title">
      <RegistryIcon name="notFound" size={48} />
      <h1 id="registry-access-loss-title">{t('accessDenied')}</h1>
      <p>{t('accessDescription')}</p>
      <div className={css.accessActions}>
        <a className={css.primaryAction} href="#/disclosures">{t('backToDisclosures')}</a>
        <a className={css.secondaryAction} href="#/overview">{t('backToOverview')}</a>
      </div>
    </section>
  )
}
