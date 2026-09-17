import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent, MouseEvent } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import { RegistryApiError, type RegistryDisclosureDetail, type RegistryImportResult, type RegistryImportStatus, type RegistryImportTarget } from './registry-api.ts'
import css from './Registry.module.css'

type UseContextDialogProps = Pick<RegistryOrganizationPageProps, 't' | 'listImportTargets' | 'importDisclosure' | 'readImport'> & {
  readonly detail: RegistryDisclosureDetail
  readonly onBoundaryFailure: (error: unknown) => boolean
  readonly onClose: () => void
}

type TargetState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly items: readonly RegistryImportTarget[] }
  | { readonly kind: 'notConfigured' }
  | { readonly kind: 'error' }

type ImportState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'pending' }
  | { readonly kind: 'success'; readonly result: RegistryImportResult }
  | { readonly kind: 'notConfigured' }
  | { readonly kind: 'error' }

const IMPORT_STATUS_KEYS: Record<RegistryImportStatus, 'operationQueued' | 'operationCompleted' | 'operationFailed'> = {
  queued: 'operationQueued',
  completed: 'operationCompleted',
  failed: 'operationFailed',
}

function targetAvailable(target: RegistryImportTarget): boolean {
  return target.transport === 'connected' && target.acceptingA2A === true
}

/** Select one provider-confirmed target before requesting a fixed-policy context import. */
export function UseContextDialog({
  detail, t, listImportTargets, importDisclosure, readImport, onBoundaryFailure, onClose,
}: UseContextDialogProps) {
  const [targetInstanceId, setTargetInstanceId] = useState('')
  const [targets, setTargets] = useState<TargetState>({ kind: 'loading' })
  const [state, setState] = useState<ImportState>({ kind: 'idle' })
  const [refreshing, setRefreshing] = useState(false)
  const controller = useRef<AbortController | null>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  const idempotencyKey = useRef(globalThis.crypto.randomUUID())
  const titleId = useId()
  const descriptionId = useId()
  const targetHelpId = useId()

  useEffect(() => {
    const requestController = new AbortController()
    controller.current = requestController
    void listImportTargets(detail.disclosureId, requestController.signal).then((page) => {
      if (requestController.signal.aborted) return
      setTargets({ kind: 'ready', items: page.items })
      setTargetInstanceId(page.items.find(targetAvailable)?.instanceId ?? '')
    }, (error: unknown) => {
      if (requestController.signal.aborted || onBoundaryFailure(error)) return
      setTargets(error instanceof RegistryApiError && error.code === 'operation-not-configured'
        ? { kind: 'notConfigured' }
        : { kind: 'error' })
    })
    return () => { requestController.abort() }
  }, [detail.disclosureId, listImportTargets, onBoundaryFailure])
  useLayoutEffect(() => { closeButton.current?.focus() }, [])

  const close = () => {
    controller.current?.abort()
    onClose()
  }
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (targetInstanceId === '' || state.kind === 'pending' || state.kind === 'success') return
    const selected = targets.kind === 'ready' ? targets.items.find(target => target.instanceId === targetInstanceId) : undefined
    if (selected === undefined || !targetAvailable(selected)) return
    const requestController = new AbortController()
    controller.current?.abort()
    controller.current = requestController
    setState({ kind: 'pending' })
    void importDisclosure(detail.disclosureId, {
      targetInstanceId,
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
  const refreshImport = () => {
    if (state.kind !== 'success' || state.result.status !== 'queued' || refreshing) return
    const requestController = new AbortController()
    controller.current?.abort()
    controller.current = requestController
    setRefreshing(true)
    void readImport(detail.disclosureId, state.result.operationId, requestController.signal).then((result) => {
      if (requestController.signal.aborted) return
      setRefreshing(false)
      setState({ kind: 'success', result })
    }, (error: unknown) => {
      if (requestController.signal.aborted || onBoundaryFailure(error)) return
      setRefreshing(false)
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
  const targetLabel = (target: RegistryImportTarget): string => {
    const availability = target.transport === 'not-observed'
      ? t('targetNotObserved')
      : target.acceptingA2A === true ? t('targetConnectedReady') : t('targetConnectedPaused')
    return target.activeRequests === null
      ? `${target.instanceId} · ${availability}`
      : `${target.instanceId} · ${availability} · ${t('activeRequestCount', { count: target.activeRequests })}`
  }

  const canSubmit = targetInstanceId !== '' && targets.kind === 'ready'
    && targets.items.some(target => target.instanceId === targetInstanceId && targetAvailable(target))
  return <div className={css.dialogBackdrop} onMouseDown={dismissBackdrop}>
    <section className={css.actionDialog} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={titleId} aria-describedby={descriptionId} onKeyDown={handleDialogKeyDown}>
      <header className={css.dialogHeader}>
        <div><h2 id={titleId}>{t('useContextTitle')}</h2><p id={descriptionId}>{t('useContextDescription')}</p></div>
        <button ref={closeButton} type="button" className={css.dialogClose} aria-label={t('close')} onClick={close}>×</button>
      </header>
      <div className={css.dialogSource}>
        <RegistryIcon name="disclosures" />
        <div><bdi>{detail.disclosureId}</bdi><p>{t('checkpointBasis', { checkpointHash: detail.checkpoint.checkpointHash })}</p></div>
      </div>
      <form className={css.dialogForm} onSubmit={submit}>
        <label className={css.dialogField}>
          <span>{t('targetDsh')}</span>
          <select required aria-describedby={targetHelpId} value={targetInstanceId} disabled={targets.kind !== 'ready' || state.kind === 'pending' || state.kind === 'success'} onChange={(event) => { setTargetInstanceId(event.currentTarget.value) }}>
            <option value="">{targets.kind === 'loading' ? t('loadingTargets') : t('selectTargetDsh')}</option>
            {targets.kind === 'ready' && targets.items.map(target => <option key={target.instanceId} value={target.instanceId} disabled={!targetAvailable(target)}>{targetLabel(target)}</option>)}
          </select>
        </label>
        <p id={targetHelpId} className={css.fieldHelp}>{t('targetDshHelp')}</p>
        {targets.kind === 'ready' && targets.items.length === 0 && <p className={css.inlineAlert} role="status">{t('noImportTargets')}</p>}
        {targets.kind === 'notConfigured' && <p className={css.inlineAlert} role="alert">{t('actionNotConfigured')}</p>}
        {targets.kind === 'error' && <p className={css.inlineAlert} role="alert">{t('actionUnavailable')}</p>}
        <section className={css.boundaryCard} aria-labelledby={`${titleId}-boundary`}>
          <RegistryIcon name="audit" />
          <div>
            <h3 id={`${titleId}-boundary`}>{t('securityBoundary')}</h3>
            <p>{t('securityBoundaryDescription')}</p>
            <ul><li>{t('isolatedBranch')}</li><li>{t('untrustedContext')}</li><li>{t('noTools')}</li><li>{t('noSourceWrite')}</li></ul>
          </div>
        </section>
        {state.kind !== 'idle' && <div className={css.dialogStatus} role={state.kind === 'error' || state.kind === 'notConfigured' ? 'alert' : 'status'}>
          {state.kind === 'pending' && <p>{t('actionPending')}</p>}
          {state.kind === 'notConfigured' && <p>{t('actionNotConfigured')}</p>}
          {state.kind === 'error' && <p>{t('actionUnavailable')}</p>}
          {state.kind === 'success' && <><p>{state.result.status === 'failed' ? t('importFailed') : t('importSubmitted')}</p><dl>
            <div><dt>{t('operationStatus')}</dt><dd>{t(IMPORT_STATUS_KEYS[state.result.status])}</dd></div>
            <div><dt>{t('operationId')}</dt><dd><bdi>{state.result.operationId}</bdi></dd></div>
            {state.result.sessionId !== undefined && <div><dt>{t('createdSessionId')}</dt><dd><bdi>{state.result.sessionId}</bdi></dd></div>}
          </dl>
          {state.result.status === 'queued' && <button type="button" className={css.inlineButton} disabled={refreshing} onClick={refreshImport}>{refreshing ? t('refreshingStatus') : t('refreshStatus')}</button>}
          {state.result.status === 'completed' && <>
            <p className={css.inlineNote}>{t('importUpdateHandoff')}</p>
            {state.result.sessionUrl === undefined
              ? <p className={css.inlineNote}>{t('sessionOpenUnavailable')}</p>
              : <a className={css.inlineAction} href={state.result.sessionUrl} target="_blank" rel="noreferrer">{t('openCreatedSession')}</a>}
          </>}
          </>}
        </div>}
        <footer className={css.dialogActions}>
          <button type="button" className={css.secondaryButton} onClick={close}>{state.kind === 'success' ? t('close') : t('cancel')}</button>
          {state.kind !== 'success' && <button type="submit" className={css.primaryButton} disabled={!canSubmit || state.kind === 'pending'}>{state.kind === 'pending' ? t('actionPending') : t('createBranch')}</button>}
        </footer>
      </form>
    </section>
  </div>
}
