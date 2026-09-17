import { useEffect, useId, useRef, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { organizationHref } from './navigation.ts'
import { RegistryApiError, type RegistryAccountContext, type RegistryInvitationPreview,
  type RegistryInvitationRole, type RegistryInvitationStatus } from './registry-api.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import css from './Registry.module.css'

type JoinProps = Pick<RegistryPageProps,
't' | 'readAccount' | 'readInvitation' | 'acceptInvitation' | 'declineInvitation'> & { readonly token: string | null }
type PreviewState = { readonly kind: 'loading' | 'retry' | 'unavailable' }
  | { readonly kind: 'ready'; readonly invitation: RegistryInvitationPreview }
type IdentityState = { readonly kind: 'loading' | 'signedOut' | 'retry' }
  | { readonly kind: 'signedIn'; readonly account: RegistryAccountContext }
type JoinAction = 'idle' | 'accepting' | 'declining'

const CONTINUATION_KEY = 'dsh-registry:invitation-continuation'
const INVITATION_TOKEN = /^[A-Za-z0-9_-]{43}$/u

const ROLE_KEYS: Record<RegistryInvitationRole, 'directoryRoleAdmin' | 'directoryRoleMember'> = {
  admin: 'directoryRoleAdmin', member: 'directoryRoleMember',
}
const STATUS_KEYS: Record<RegistryInvitationStatus,
'invitationStatusPending' | 'invitationStatusAccepted' | 'invitationStatusDeclined' | 'invitationStatusRevoked' | 'invitationStatusExpired'> = {
  pending: 'invitationStatusPending', accepted: 'invitationStatusAccepted', declined: 'invitationStatusDeclined',
  revoked: 'invitationStatusRevoked', expired: 'invitationStatusExpired',
}

function invitationIsAvailable(invitation: RegistryInvitationPreview): boolean {
  return invitation.status === 'pending' && invitation.expiresAt > Date.now()
}

function clearInvitationAddress(): void {
  if (window.location.hash.startsWith('#/join/')) window.history.replaceState(null, '', '#/join')
}

/** The invitation is previewed only after sign-in and consumed only by an explicit member action. */
export function JoinOrganizationPage({ token, t, readAccount, readInvitation, acceptInvitation,
  declineInvitation }: JoinProps) {
  const invalidToken = token !== null && !INVITATION_TOKEN.test(token)
  const [revision, setRevision] = useState(0)
  const [preview, setPreview] = useState<PreviewState>({ kind: 'loading' })
  const [identity, setIdentity] = useState<IdentityState>({ kind: 'loading' })
  const [resolvedToken, setResolvedToken] = useState<string | null>(token !== null && INVITATION_TOKEN.test(token) ? token : null)
  const [continuationLoaded, setContinuationLoaded] = useState(token !== null)
  const [action, setAction] = useState<JoinAction>('idle')
  const [message, setMessage] = useState<string | null>(null)
  const actionController = useRef<AbortController | null>(null)
  const titleId = useId()

  useEffect(() => {
    if (invalidToken) clearInvitationAddress()
  }, [invalidToken])

  useEffect(() => {
    if (token !== null) {
      setResolvedToken(INVITATION_TOKEN.test(token) ? token : null)
      setContinuationLoaded(true)
      clearInvitationAddress()
      return
    }
    let continued: string | null = null
    try {
      continued = window.sessionStorage.getItem(CONTINUATION_KEY)
    } catch { /* A blocked session store produces the same unavailable state as a missing continuation. */ }
    setResolvedToken(continued !== null && INVITATION_TOKEN.test(continued) ? continued : null)
    setContinuationLoaded(true)
  }, [token])

  useEffect(() => {
    if (token !== null || resolvedToken === null) return
    try { window.sessionStorage.removeItem(CONTINUATION_KEY) } catch { /* The token is already retained only in component memory. */ }
  }, [resolvedToken, token])

  useEffect(() => {
    const controller = new AbortController()
    setIdentity({ kind: 'loading' })
    setMessage(null)
    void readAccount(controller.signal).then((account) => {
      if (!controller.signal.aborted) setIdentity({ kind: 'signedIn', account })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setIdentity({ kind: error instanceof RegistryApiError
        && error.code === 'unauthenticated' ? 'signedOut' : 'retry' })
    })
    return () => { controller.abort() }
  }, [readAccount, revision])

  useEffect(() => {
    if (identity.kind !== 'signedIn' || !continuationLoaded) return
    if (resolvedToken === null) {
      setPreview({ kind: 'unavailable' })
      return
    }
    const controller = new AbortController()
    setPreview({ kind: 'loading' })
    void readInvitation(resolvedToken, controller.signal).then((invitation) => {
      if (!controller.signal.aborted) {
        if (invitationIsAvailable(invitation)) setPreview({ kind: 'ready', invitation })
        else {
          clearInvitationAddress()
          setResolvedToken(null)
          setPreview({ kind: 'unavailable' })
        }
      }
    }, (error: unknown) => {
      if (!controller.signal.aborted) {
        const unavailable = error instanceof RegistryApiError
          && (error.code === 'not-found' || error.code === 'invalid-input' || error.code === 'conflict'
            || error.code === 'unauthenticated')
        if (unavailable) {
          clearInvitationAddress()
          setResolvedToken(null)
        }
        setPreview({ kind: unavailable ? 'unavailable' : 'retry' })
      }
    })
    return () => { controller.abort() }
  }, [continuationLoaded, identity.kind, readInvitation, resolvedToken, revision])

  useEffect(() => () => { actionController.current?.abort() }, [])

  const failResolution = (error: unknown): void => {
    if (error instanceof RegistryApiError && error.code === 'unauthenticated') {
      setIdentity({ kind: 'signedOut' })
    } else if (error instanceof RegistryApiError
      && (error.code === 'unavailable' || error.code === 'rate-limited')) {
      setPreview({ kind: 'retry' })
    } else {
      clearInvitationAddress()
      setResolvedToken(null)
      setPreview({ kind: 'unavailable' })
      setMessage(t('invitationUnavailableDescription'))
    }
    setAction('idle')
  }

  const resolveInvitation = (decision: 'accept' | 'decline'): void => {
    if (preview.kind !== 'ready' || identity.kind !== 'signedIn' || resolvedToken === null || action !== 'idle') return
    actionController.current?.abort()
    const controller = new AbortController()
    actionController.current = controller
    setAction(decision === 'accept' ? 'accepting' : 'declining')
    setMessage(null)
    if (decision === 'accept') {
      void acceptInvitation(resolvedToken, controller.signal).then(async organization => {
        try { await readAccount(controller.signal) } catch { /* Root refreshes once the organization URL replaces this token. */ }
        if (!controller.signal.aborted) window.location.replace(organizationHref(organization.organizationId, 'overview'))
      }, (error: unknown) => {
        if (controller.signal.aborted) return
        failResolution(error)
      })
      return
    }
    void declineInvitation(resolvedToken, controller.signal).then(() => {
      if (!controller.signal.aborted) {
        clearInvitationAddress()
        setResolvedToken(null)
        setAction('idle')
        setPreview({ kind: 'unavailable' })
        setMessage(t('invitationDeclined'))
      }
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      failResolution(error)
    })
  }

  const homeOrganization = identity.kind === 'signedIn'
    ? identity.account.organizations.find(item => item.state === 'active' && item.membershipState === 'active')
    : undefined
  const startLogin = (): void => {
    if (resolvedToken === null) return
    try {
      window.sessionStorage.setItem(CONTINUATION_KEY, resolvedToken)
    } catch {
      setPreview({ kind: 'unavailable' })
      setResolvedToken(null)
      setMessage(t('invitationContinuationFailed'))
      return
    }
    clearInvitationAddress()
    window.location.assign(`/registry-auth/v1/start?returnTo=${encodeURIComponent('/#/join')}`)
  }

  return <section className={css.organizationPage} aria-labelledby={titleId}>
    <header className={css.organizationHeader}>
      <a className={css.organizationBrand} href="#/"><RegistryIcon name="brand" size={26} /><span aria-hidden="true">/</span><strong>{t('joinOrganization')}</strong></a>
      <span className={css.organizationHelp}><RegistryIcon name="info" size={18} /><span>{t('invitationSecurityNote')}</span></span>
    </header>
    <div className={css.invitationCanvas}>
      <article className={css.invitationCard}>
        {invalidToken || continuationLoaded && resolvedToken === null
          ? <div className={css.invitationState} role="status"><RegistryIcon name="notFound" size={44} /><h1 id={titleId}>{t('invitationUnavailable')}</h1><p>{message ?? t('invitationUnavailableDescription')}</p></div>
          : identity.kind === 'loading' || !continuationLoaded
          ? <div className={css.invitationState} role="status"><span className={css.spinner} aria-hidden="true" /><h1 id={titleId}>{t('invitationCheckingAccount')}</h1><p>{t('loadingAccount')}</p></div>
          : identity.kind === 'retry'
            ? <div className={css.invitationState} role="alert"><RegistryIcon name="warning" size={40} /><h1 id={titleId}>{t('accountUnavailable')}</h1><p>{t('accountUnavailableDescription')}</p><button className={css.primaryAction} type="button" onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div>
            : identity.kind === 'signedOut'
              ? <div className={css.invitationState}><RegistryIcon name="members" size={44} /><h1 id={titleId}>{t('invitationSignInTitle')}</h1><p>{t('invitationSignInRequired')}</p><button className={css.primaryAction} type="button" disabled={resolvedToken === null} onClick={startLogin}>{t('signInAction')}</button></div>
              : preview.kind === 'loading'
                ? <div className={css.invitationState} role="status"><span className={css.spinner} aria-hidden="true" /><h1 id={titleId}>{t('invitationLoading')}</h1><p>{t('invitationLoadingDescription')}</p></div>
                : preview.kind === 'retry'
                  ? <div className={css.invitationState} role="alert"><RegistryIcon name="warning" size={40} /><h1 id={titleId}>{t('requestUnavailable')}</h1><p>{t('requestUnavailableDescription')}</p><button className={css.primaryAction} type="button" onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div>
                  : preview.kind === 'unavailable'
                    ? <div className={css.invitationState} role="status"><RegistryIcon name="notFound" size={44} /><h1 id={titleId}>{t('invitationUnavailable')}</h1><p>{message ?? t('invitationUnavailableDescription')}</p>{homeOrganization === undefined
                      ? <a className={css.secondaryAction} href="#/new-organization">{t('createOrganization')}</a>
                      : <a className={css.secondaryAction} href={organizationHref(homeOrganization.organizationId, 'overview')}>{t('returnToRegistry')}</a>}</div>
                    : <>
                      <div className={css.invitationIntro}><span className={css.invitationEyebrow}>{t('organizationInvitation')}</span><h1 id={titleId}>{t('invitationJoinTitle').replace('{organization}', preview.invitation.organizationDisplayName)}</h1><p>{t('invitationJoinDescription')}</p></div>
                      <dl className={css.invitationDetails}>
                        <div><dt>{t('invitationOrganization')}</dt><dd>{preview.invitation.organizationDisplayName}</dd></div>
                        <div><dt>{t('directoryMemberRole')}</dt><dd>{t(ROLE_KEYS[preview.invitation.role])}</dd></div>
                        <div><dt>{t('expiry')}</dt><dd><time dateTime={new Date(preview.invitation.expiresAt).toISOString()}>{new Date(preview.invitation.expiresAt).toLocaleString()}</time></dd></div>
                        <div><dt>{t('directoryMemberState')}</dt><dd>{t(STATUS_KEYS[preview.invitation.status])}</dd></div>
                      </dl>
                      <div className={css.invitationDecision}><p>{t('invitationConfirmAccount').replace('{account}', identity.account.displayName)}</p><div><button className={css.secondaryAction} type="button" disabled={action !== 'idle'} onClick={() => { resolveInvitation('decline') }}>{t(action === 'declining' ? 'invitationDeclining' : 'invitationDecline')}</button><button className={css.primaryAction} type="button" disabled={action !== 'idle'} onClick={() => { resolveInvitation('accept') }}>{t(action === 'accepting' ? 'invitationAccepting' : 'invitationAccept')}</button></div></div>
                    </>}
      </article>
    </div>
  </section>
}
