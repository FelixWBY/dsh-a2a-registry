import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent, MouseEvent } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { questionHref } from './navigation.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import { RegistryApiError, type RegistryDisclosureDetail, type RegistryQuestionResult, type RegistryQuestionStatus } from './registry-api.ts'
import css from './Registry.module.css'

type AskSourceDialogProps = Pick<RegistryOrganizationPageProps, 't' | 'askDisclosure'> & {
  readonly organizationId: string
  readonly detail: RegistryDisclosureDetail
  readonly onBoundaryFailure: (error: unknown) => boolean
  readonly onClose: () => void
}

type QuestionState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'pending' }
  | { readonly kind: 'success'; readonly result: RegistryQuestionResult }
  | { readonly kind: 'notConfigured' }
  | { readonly kind: 'error' }

const QUESTION_STATUS_KEYS: Record<RegistryQuestionStatus,
'operationQueued' | 'operationDelivered' | 'operationRunning' | 'operationCompleted' | 'operationFailed' | 'operationCancelled' | 'operationExpired'> = {
  queued: 'operationQueued',
  delivered: 'operationDelivered',
  running: 'operationRunning',
  completed: 'operationCompleted',
  failed: 'operationFailed',
  cancelled: 'operationCancelled',
  expired: 'operationExpired',
}

/** Collect and submit one pure-text question without attaching local context or capabilities. */
export function AskSourceDialog({ organizationId, detail, t, askDisclosure, onBoundaryFailure, onClose }: AskSourceDialogProps) {
  const [question, setQuestion] = useState('')
  const [state, setState] = useState<QuestionState>({ kind: 'idle' })
  const controller = useRef<AbortController | null>(null)
  const questionField = useRef<HTMLTextAreaElement>(null)
  const idempotencyKey = useRef(globalThis.crypto.randomUUID())
  const titleId = useId()
  const descriptionId = useId()
  const questionHelpId = useId()

  useEffect(() => () => { controller.current?.abort() }, [])
  useLayoutEffect(() => { questionField.current?.focus() }, [])

  const close = () => {
    controller.current?.abort()
    onClose()
  }
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const text = question.trim()
    if (text.length === 0 || state.kind === 'pending' || state.kind === 'success') return
    const requestController = new AbortController()
    controller.current?.abort()
    controller.current = requestController
    setState({ kind: 'pending' })
    void askDisclosure(detail.disclosureId, {
      question: text,
      idempotencyKey: idempotencyKey.current,
    }, requestController.signal).then((result) => {
      if (!requestController.signal.aborted) setState({ kind: 'success', result })
    }, (error: unknown) => {
      if (requestController.signal.aborted || onBoundaryFailure(error)) return
      setState(error instanceof RegistryApiError && error.code === 'operation-not-configured'
        ? { kind: 'notConfigured' }
        : { kind: 'error' })
    })
  }
  const dismissBackdrop = (event: MouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget) close()
  }
  const handleDialogKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault()
      close()
      return
    }
    if (event.key !== 'Tab') return
    const elements = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('*')).filter(element =>
      element.matches('a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled)')
      && element.tabIndex >= 0)
    const index = elements.findIndex(element => element === document.activeElement)
    if (event.shiftKey && index <= 0) {
      event.preventDefault()
      ;(elements.at(-1) ?? event.currentTarget).focus()
    } else if (!event.shiftKey && (index === -1 || index === elements.length - 1)) {
      event.preventDefault()
      ;(elements[0] ?? event.currentTarget).focus()
    }
  }

  return <div className={css.dialogBackdrop} onMouseDown={dismissBackdrop}>
    <section className={css.actionDialog} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={descriptionId} onKeyDown={handleDialogKeyDown}>
      <header className={css.dialogHeader}>
        <div><h2 id={titleId}>{t('askSourceTitle')}</h2><p id={descriptionId}>{t('askSourceDescription')}</p></div>
        <button type="button" className={css.dialogClose} aria-label={t('close')} onClick={close}>×</button>
      </header>
      <div className={css.dialogSource}>
        <RegistryIcon name="disclosures" />
        <div><bdi>{detail.instanceId}</bdi><p>{t('checkpointBasis', { checkpointHash: detail.checkpoint.checkpointHash })}</p></div>
      </div>
      <form className={css.dialogForm} onSubmit={submit}>
        <label className={css.dialogField}>
          <span>{t('pureTextQuestion')}</span>
          <textarea ref={questionField} required maxLength={2000} aria-describedby={questionHelpId} placeholder={t('questionPlaceholder')} value={question} disabled={state.kind === 'pending' || state.kind === 'success'} onChange={(event) => { setQuestion(event.currentTarget.value) }} />
        </label>
        <div id={questionHelpId} className={css.questionHelp}><span>{t('pureTextOnly')}</span><span>{t('questionLimit')}</span></div>
        <section className={css.boundaryCard} aria-labelledby={`${titleId}-boundary`}>
          <RegistryIcon name="audit" />
          <div><h3 id={`${titleId}-boundary`}>{t('securityBoundary')}</h3><p>{t('questionBoundaryDescription')}</p></div>
        </section>
        {state.kind !== 'idle' && <div className={css.dialogStatus} role={state.kind === 'error' || state.kind === 'notConfigured' ? 'alert' : 'status'}>
          {state.kind === 'pending' && <p>{t('actionPending')}</p>}
          {state.kind === 'notConfigured' && <p>{t('actionNotConfigured')}</p>}
          {state.kind === 'error' && <p>{t('actionUnavailable')}</p>}
          {state.kind === 'success' && <><p>{t('questionSubmitted')}</p><dl>
            <div><dt>{t('operationStatus')}</dt><dd>{t(QUESTION_STATUS_KEYS[state.result.status])}</dd></div>
            <div><dt>{t('requestId')}</dt><dd><bdi>{state.result.requestId}</bdi></dd></div>
          </dl><a className={css.inlineAction} href={questionHref(organizationId, detail.disclosureId, state.result.requestId)}>{t('viewQuestion')}</a></>}
        </div>}
        <footer className={css.dialogActions}>
          <button type="button" className={css.secondaryButton} onClick={close}>{state.kind === 'success' ? t('close') : t('cancel')}</button>
          {state.kind !== 'success' && <button type="submit" className={css.primaryButton} disabled={question.trim().length === 0 || state.kind === 'pending'}>{state.kind === 'pending' ? t('actionPending') : t('sendQuestion')}</button>}
        </footer>
      </form>
    </section>
  </div>
}
