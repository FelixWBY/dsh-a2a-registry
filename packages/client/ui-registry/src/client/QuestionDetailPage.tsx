import { useEffect, useRef, useState } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { disclosureHref } from './navigation.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import { RegistryApiError, type RegistryQuestionResult, type RegistryQuestionStatus } from './registry-api.ts'
import css from './Registry.module.css'

type QuestionDetailProps = Pick<RegistryOrganizationPageProps, 't' | 'readQuestion' | 'cancelQuestion'> & {
  readonly organizationId: string
  readonly disclosureId: string
  readonly requestId: string
}

type QuestionState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly result: RegistryQuestionResult }

const STATUS_KEYS: Record<RegistryQuestionStatus,
'operationQueued' | 'operationDelivered' | 'operationRunning' | 'operationCompleted' | 'operationFailed' | 'operationCancelled' | 'operationExpired'> = {
  queued: 'operationQueued',
  delivered: 'operationDelivered',
  running: 'operationRunning',
  completed: 'operationCompleted',
  failed: 'operationFailed',
  cancelled: 'operationCancelled',
  expired: 'operationExpired',
}

function failureState(error: unknown): 'unconfigured' | 'accessLoss' | 'retry' {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured'
    || error.code === 'operation-not-configured') return 'unconfigured'
  if (error.code === 'unauthenticated' || error.code === 'not-found' || error.code === 'invalid-input') return 'accessLoss'
  return 'retry'
}

/** Durable question deep-link; every refresh and cancellation is reauthorized by the Host. */
export function QuestionDetailPage({ organizationId, disclosureId, requestId, t, readQuestion, cancelQuestion }: QuestionDetailProps) {
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<QuestionState>({ kind: 'loading' })
  const [cancelling, setCancelling] = useState(false)
  const mutationController = useRef<AbortController | null>(null)

  useEffect(() => () => { mutationController.current?.abort() }, [])

  useEffect(() => {
    const controller = new AbortController()
    setCancelling(false)
    setState({ kind: 'loading' })
    void readQuestion(disclosureId, requestId, controller.signal).then((result) => {
      if (!controller.signal.aborted) setState({ kind: 'ready', result })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setState({ kind: failureState(error) })
    })
    return () => { controller.abort() }
  }, [disclosureId, readQuestion, requestId, revision])

  const cancelQueued = () => {
    if (state.kind !== 'ready' || state.result.status !== 'queued' || cancelling) return
    const controller = new AbortController()
    mutationController.current?.abort()
    mutationController.current = controller
    setCancelling(true)
    void cancelQuestion(disclosureId, requestId, controller.signal).then((result) => {
      if (controller.signal.aborted) return
      setCancelling(false)
      setState({ kind: 'ready', result })
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      setCancelling(false)
      setState({ kind: failureState(error) })
    })
  }

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  const disclosureLink = disclosureHref(organizationId, disclosureId)
  return <section>
    <div className={css.pageHeading}>
      <a className={css.backLink} href={disclosureLink}>← {t('backToDisclosure')}</a>
      <h1>{t('questionDetail')}</h1>
      <p>{t('questionDetailDescription')}</p>
    </div>
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingQuestion')}</p></div>}
    {state.kind === 'unconfigured' && <div className={css.tableFrame}><UnconfiguredPanel t={t} /></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'ready' && <div className={css.detailLayout}>
      <section className={css.detailCard} aria-labelledby="registry-question-status">
        <div className={css.cardHeading}>
          <div><h2 id="registry-question-status">{t('questionStatus')}</h2><p>{t('questionStatusDescription')}</p></div>
          <button className={css.secondaryButton} disabled={cancelling} onClick={() => { setRevision(value => value + 1) }}>{t('refreshStatus')}</button>
        </div>
        <dl className={css.metadataGrid}>
          <div><dt>{t('requestId')}</dt><dd><bdi>{state.result.requestId}</bdi></dd></div>
          <div><dt>{t('operationStatus')}</dt><dd><code>{t(STATUS_KEYS[state.result.status])}</code></dd></div>
          <div className={css.wideMetadata}><dt>{t('checkpointHash')}</dt><dd><bdi>{state.result.checkpointHash}</bdi></dd></div>
        </dl>
        {state.result.status === 'queued' && <div className={css.questionActions}>
          <p>{t('cancelQueuedDescription')}</p>
          <button className={css.secondaryButton} disabled={cancelling} onClick={cancelQueued}>{cancelling ? t('cancellingQuestion') : t('cancelQuestion')}</button>
        </div>}
      </section>
      {state.result.status === 'completed' && <section className={css.detailCard} aria-labelledby="registry-question-reply">
        <h2 id="registry-question-reply">{t('questionReply')}</h2>
        <pre className={css.plainReply}>{state.result.reply ?? t('questionReplyUnavailable')}</pre>
      </section>}
      {(state.result.status === 'failed' || state.result.status === 'cancelled' || state.result.status === 'expired')
        && <div className={css.terminalNotice} role="status"><RegistryIcon name="audit" /><p>{t(state.result.status === 'failed' ? 'questionFailedDescription' : state.result.status === 'cancelled' ? 'questionCancelledDescription' : 'questionExpiredDescription')}</p></div>}
    </div>}
  </section>
}
