import { useEffect, useId, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import css from './Registry.module.css'

type AuthenticationMode = 'signIn' | 'signUp'
type Translate = RegistryPageProps['t']
type ProviderState = 'loading' | 'oidc' | 'unavailable'

/** Render account entry from runtime-confirmed identity configuration without offering a fake password flow. */
export function AuthPage({ mode, t, readStatus }:
  { mode: AuthenticationMode; t: Translate; readStatus: RegistryPageProps['readStatus'] }) {
  const [status, setStatus] = useState<string | null>(null)
  const [provider, setProvider] = useState<ProviderState>('loading')
  const headingId = useId()
  const statusId = useId()
  const isSignIn = mode === 'signIn'
  const showUnavailable = (): void => { setStatus(t('authProviderUnavailable')) }

  useEffect(() => {
    const controller = new AbortController()
    void readStatus(controller.signal).then((runtime) => {
      if (!controller.signal.aborted) setProvider(runtime.identityProvider === 'oidc' ? 'oidc' : 'unavailable')
    }, () => {
      if (!controller.signal.aborted) setProvider('unavailable')
    })
    return () => { controller.abort() }
  }, [readStatus])

  return (
    <section className={css.authPage} aria-labelledby={headingId}>
      <div className={css.authPanel}>
        <a className={css.authBrand} href="#/disclosures"><RegistryIcon name="brand" size={30} /><span>{t('brand')}</span></a>
        <div className={css.authFormWrap}>
          <header className={css.authHeading}>
            <h1 id={headingId}>{t(isSignIn ? 'authWelcomeBack' : 'authGetStarted')}</h1>
            <p>{t(isSignIn ? 'authSignInSubtitle' : 'authSignUpSubtitle')}</p>
          </header>

          <div className={css.authProviders} aria-describedby={statusId}>
            {provider === 'oidc'
              ? <a className={css.providerButton} href="/registry-auth/v1/start?returnTo=%2F%23%2Foverview">
                <RegistryIcon name="members" size={20} /><span>{t('continueSso')}</span><span aria-hidden="true">→</span>
              </a>
              : <button type="button" className={css.providerButton} disabled={provider === 'loading'} onClick={showUnavailable}>
                <RegistryIcon name="members" size={20} /><span>{t(provider === 'loading' ? 'authCheckingProvider' : 'continueSso')}</span><span aria-hidden="true">→</span>
              </button>}
          </div>

          <p className={css.authSwitch}>{t(isSignIn ? 'noAccount' : 'haveAccount')} <a href={isSignIn ? '#/sign-up' : '#/sign-in'}>{t(isSignIn ? 'signUpAction' : 'signInAction')}</a></p>
          <div id={statusId} className={css.authStatus} role="status">
            <RegistryIcon name="info" size={18} />
            <div><strong>{t(provider === 'oidc' ? 'authProviderReadyTitle' : 'authUnconfiguredTitle')}</strong><p>{status ?? t(provider === 'oidc' ? 'authProviderReadyDescription' : provider === 'loading' ? 'authCheckingProviderDescription' : 'authProviderUnavailable')}</p></div>
            {provider === 'oidc' ? null : <a href="#/settings">{t('authSetupGuide')} →</a>}
          </div>
        </div>
        <p className={css.authLegal}><RegistryIcon name="info" size={16} />{t('authLegal')}</p>
      </div>

      <aside className={css.authStory} aria-label={t('authStoryLabel')}>
        <a className={css.authDocs} href="#/settings"><RegistryIcon name="documentation" size={18} /><span>{t('documentation')}</span></a>
        <div className={css.authStoryCopy}>
          <h2>{t('authStoryTitle')}</h2>
          <p>{t(isSignIn ? 'authStorySignIn' : 'authStorySignUp')}</p>
          <ol className={css.authTimeline}>
            <li><RegistryIcon name="nodes" /><span>{t('authFlowConnected')}</span></li>
            <li><RegistryIcon name="disclosures" /><span>{t('authFlowConfirmed')}</span></li>
            <li><RegistryIcon name="audit" /><span>{t('authFlowAudited')}</span></li>
          </ol>
          <div className={css.authLog} aria-hidden="true">
            <div><span /><span /><span /><b>{t('authLogPreview')}</b></div>
            <p><span>{t('authLogStep')} 01</span><strong>{t('authLogInfo')}</strong>{t('authFlowConnected')}</p>
            <p><span>{t('authLogStep')} 02</span><strong>{t('authLogInfo')}</strong>{t('authFlowConfirmed')}</p>
            <p><span>{t('authLogStep')} 03</span><strong>{t('authLogInfo')}</strong>{t('authFlowAudited')}</p>
          </div>
        </div>
      </aside>
    </section>
  )
}
