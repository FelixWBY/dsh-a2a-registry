import { useEffect, useId, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { BindingScopeHelp } from './BindingScopeHelp.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import {
  RegistryApiError,
  type RegistryBindingPhase,
  type RegistryBindingReview,
  type RegistryInstanceScope,
} from './registry-api.ts'
import css from './Registry.module.css'

type BindingProps = Pick<RegistryPageProps,
  't' | 'listInstances' | 'reviewBinding' | 'approveBinding' | 'rejectBinding'>
type Readiness = 'loading' | 'identityMissing' | 'runtimeMissing' | 'accessLoss' | 'retry' | 'ready'
type PendingAction = 'idle' | 'review' | 'approve' | 'reject'
type ActionFailure = 'invalid' | 'unavailable' | null

const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const BINDING_CODE = /^[A-Za-z0-9_-]{43}$/u
const PHASE_KEYS: Record<RegistryBindingPhase,
  'bindingPhasePending' | 'bindingPhaseApproved' | 'bindingPhaseConfirmed'
  | 'bindingPhaseRejected' | 'bindingPhaseRevoked'> = {
  pending: 'bindingPhasePending', approved: 'bindingPhaseApproved', confirmed: 'bindingPhaseConfirmed',
  rejected: 'bindingPhaseRejected', revoked: 'bindingPhaseRevoked',
}
const SCOPE_KEYS: Record<RegistryInstanceScope, 'nodeScopeSync' | 'nodeScopeReceive'> = {
  'disclosure.sync': 'nodeScopeSync', 'a2a.receive': 'nodeScopeReceive',
}

function readinessFailure(error: unknown): Exclude<Readiness, 'loading' | 'ready'> {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured') return 'identityMissing'
  if (error.code === 'registry-not-configured') return 'runtimeMissing'
  if (error.code === 'unauthenticated' || error.code === 'not-found') return 'accessLoss'
  return 'retry'
}

function displayTime(value: number, fallback: string): string {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? fallback : date.toISOString()
}

/** Signed-in member review surface for a device-started binding; device keys and proofs never enter React. */
export function BindingPage({ t, listInstances, reviewBinding, approveBinding, rejectBinding }: BindingProps) {
  const [readinessRevision, setReadinessRevision] = useState(0)
  const [readiness, setReadiness] = useState<Readiness>('loading')
  const [bindingId, setBindingId] = useState('')
  const [code, setCode] = useState('')
  const [instanceName, setInstanceName] = useState('')
  const [review, setReview] = useState<RegistryBindingReview | null>(null)
  const [pending, setPending] = useState<PendingAction>('idle')
  const [failure, setFailure] = useState<ActionFailure>(null)
  const actionController = useRef<AbortController | null>(null)
  const bindingIdInput = useId()
  const codeInput = useId()
  const codeHelp = useId()
  const nameInput = useId()
  const nameHelp = useId()

  useEffect(() => {
    const controller = new AbortController()
    setReadiness('loading')
    void listInstances(controller.signal).then(() => {
      if (!controller.signal.aborted) setReadiness('ready')
    }, (error: unknown) => {
      if (!controller.signal.aborted) setReadiness(readinessFailure(error))
    })
    return () => { controller.abort() }
  }, [listInstances, readinessRevision])
  useEffect(() => () => { actionController.current?.abort() }, [])

  const clearCandidate = () => {
    actionController.current?.abort()
    setReview(null)
    setPending('idle')
    setFailure(null)
  }
  const applyFailure = (error: unknown) => {
    if (error instanceof RegistryApiError && error.code === 'invalid-input') {
      setFailure('invalid')
    } else {
      const boundary = readinessFailure(error)
      if (boundary === 'retry') setFailure('unavailable')
      else {
        setCode('')
        setReview(null)
        setReadiness(boundary)
      }
    }
    setPending('idle')
  }
  const run = (action: Exclude<PendingAction, 'idle'>) => {
    if (pending !== 'idle') return
    const selectedBindingId = bindingId.trim()
    const selectedCode = code.trim()
    const selectedName = instanceName.trim()
    if (!IDENTIFIER.test(selectedBindingId) || !BINDING_CODE.test(selectedCode)
      || action === 'approve' && selectedName.length === 0) {
      setFailure('invalid')
      return
    }
    const controller = new AbortController()
    actionController.current?.abort()
    actionController.current = controller
    setPending(action)
    setFailure(null)
    const operation = action === 'approve'
      ? approveBinding(selectedBindingId, selectedCode, selectedName, controller.signal)
      : action === 'reject'
        ? rejectBinding(selectedBindingId, selectedCode, controller.signal)
        : reviewBinding(selectedBindingId, selectedCode, controller.signal)
    void operation.then((value) => {
      if (controller.signal.aborted) return
      setReview(value)
      setInstanceName(value.instanceName)
      setPending('idle')
      if (value.phase === 'confirmed' || value.phase === 'rejected' || value.phase === 'revoked') setCode('')
    }, (error: unknown) => {
      if (!controller.signal.aborted) applyFailure(error)
    })
  }
  const submitReview = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    run('review')
  }
  const canReview = IDENTIFIER.test(bindingId.trim()) && BINDING_CODE.test(code.trim())
  const busy = pending !== 'idle'

  if (readiness === 'accessLoss') return <AccessLossPage t={t} />
  return <section>
    <div className={css.pageHeading}><h1>{t('binding')}</h1><p>{t('bindingDescription')}</p></div>
    <BindingScopeHelp t={t} />
    {readiness === 'loading' && <div className={css.statePanel} role="status">
      <span className={css.spinner} aria-hidden="true" /><p>{t('bindingReadinessLoading')}</p>
    </div>}
    {(readiness === 'identityMissing' || readiness === 'runtimeMissing') && <div className={css.statePanel} role="alert">
      <RegistryIcon name="binding" size={64} />
      <h2>{t('unconfigured')}</h2>
      <p>{t(readiness === 'identityMissing' ? 'bindingIdentityMissing' : 'bindingRuntimeMissing')}</p>
      <a className={css.primaryAction} href="#/settings">{t('requirements')}</a>
    </div>}
    {readiness === 'retry' && <div className={css.statePanel} role="alert">
      <RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2>
      <p>{t('requestUnavailableDescription')}</p>
      <button className={css.primaryButton} onClick={() => { setReadinessRevision(value => value + 1) }}>
        {t('retry')}
      </button>
    </div>}
    {readiness === 'ready' && <div className={css.detailLayout}>
      <div className={css.notice} role="note"><RegistryIcon name="info" /><p>{t('bindingDeviceOwnedNote')}</p></div>
      <section className={css.detailCard} aria-labelledby="binding-review-heading">
        <div className={css.cardHeading}><div>
          <h2 id="binding-review-heading">{t('bindingReviewTitle')}</h2>
          <p>{t('bindingReadyIntro')}</p>
        </div></div>
        <form className={css.bindingForm} onSubmit={submitReview}>
          <div className={css.dialogField}>
            <label htmlFor={bindingIdInput}>{t('bindingIdLabel')}</label>
            <input id={bindingIdInput} value={bindingId} disabled={busy} autoComplete="off" spellCheck={false}
              maxLength={128} placeholder={t('bindingIdPlaceholder')}
              onChange={(event) => { setBindingId(event.currentTarget.value); clearCandidate() }} />
          </div>
          <div className={css.dialogField}>
            <label htmlFor={codeInput}>{t('bindingCodeLabel')}</label>
            <input id={codeInput} type="password" value={code} disabled={busy} autoComplete="off" spellCheck={false}
              minLength={43} maxLength={43} pattern="[A-Za-z0-9_-]{43}" aria-describedby={codeHelp}
              placeholder={t('bindingCodePlaceholder')}
              onChange={(event) => { setCode(event.currentTarget.value); clearCandidate() }} />
            <small id={codeHelp} className={css.fieldHelp}>{t('bindingCodeHelp')}</small>
          </div>
          {failure !== null && <p className={css.inlineAlert} role="alert">
            {t(failure === 'invalid' ? 'bindingInvalidInput' : 'bindingActionUnavailable')}
          </p>}
          <div className={css.bindingActions}>
            <button type="submit" className={css.primaryButton} disabled={!canReview || busy}>
              {t(pending === 'review' ? 'bindingReviewing' : 'bindingReviewAction')}
            </button>
          </div>
        </form>
      </section>
      {review !== null && <section className={css.detailCard} aria-labelledby="binding-candidate-heading">
        <div className={css.cardHeading}><div>
          <h2 id="binding-candidate-heading">{t('bindingCandidateTitle')}</h2>
          <p>{t('bindingCandidateDescription')}</p>
        </div></div>
        <dl className={css.metadataGrid}>
          <div><dt>{t('bindingIdLabel')}</dt><dd><bdi>{review.bindingId}</bdi></dd></div>
          <div><dt>{t('nodeInstanceId')}</dt><dd><bdi>{review.instanceId}</bdi></dd></div>
          <div><dt>{t('bindingFingerprint')}</dt><dd><code><bdi>{review.keyId}</bdi></code></dd></div>
          <div><dt>{t('bindingExpiresAt')}</dt><dd><time>{displayTime(review.expiresAt, t('unknownValue'))}</time></dd></div>
          <div><dt>{t('bindingRequestedScopes')}</dt>
            <dd>{review.requestedScopes.map(scope => t(SCOPE_KEYS[scope])).join(' · ')}</dd></div>
          <div><dt>{t('bindingPhase')}</dt><dd><code>{t(PHASE_KEYS[review.phase])}</code></dd></div>
        </dl>
        <div className={css.dialogField}>
          <label htmlFor={nameInput}>{t('bindingNameLabel')}</label>
          <input id={nameInput} value={instanceName} required readOnly={review.phase !== 'pending'} disabled={busy}
            aria-describedby={nameHelp} onChange={(event) => { setInstanceName(event.currentTarget.value) }} />
          <small id={nameHelp} className={css.fieldHelp}>{t('bindingNameHelp')}</small>
        </div>
        {review.phase === 'pending' && <div className={css.bindingActions}>
          <button type="button" className={css.secondaryButton} disabled={busy} onClick={() => { run('reject') }}>
            {t(pending === 'reject' ? 'bindingRejecting' : 'bindingRejectAction')}
          </button>
          <button type="button" className={css.primaryButton} disabled={busy || instanceName.trim().length === 0}
            onClick={() => { run('approve') }}>
            {t(pending === 'approve' ? 'bindingApproving' : 'bindingApproveAction')}
          </button>
        </div>}
        {review.phase === 'approved' && <div className={css.bindingStatus} role="status">
          <p>{t('bindingAwaitingDevice')}</p>
          <button type="button" className={css.secondaryButton} disabled={busy} onClick={() => { run('review') }}>
            {t(pending === 'review' ? 'bindingReviewing' : 'bindingRefreshAction')}
          </button>
        </div>}
        {review.phase === 'confirmed' && <div className={css.bindingStatus} role="status">
          <p>{t('bindingConfirmedMessage')}</p>
          <a className={css.primaryButton} href="#/nodes">{t('bindingOpenNodes')}</a>
        </div>}
        {(review.phase === 'rejected' || review.phase === 'revoked') && <div className={css.terminalNotice} role="status">
          <RegistryIcon name="info" />
          <p>{t(review.phase === 'rejected' ? 'bindingRejectedMessage' : 'bindingRevokedMessage')}</p>
        </div>}
      </section>}
    </div>}
  </section>
}
