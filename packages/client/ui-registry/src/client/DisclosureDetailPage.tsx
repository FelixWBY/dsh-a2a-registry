import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { AskSourceDialog } from './AskSourceDialog.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import {
  RegistryApiError,
  type RegistryDisclosureContent,
  type RegistryDisclosureContentEvent,
  type RegistryDisclosureDetail,
} from './registry-api.ts'
import { UseContextDialog } from './UseContextDialog.tsx'
import css from './Registry.module.css'

type DetailProps = Pick<RegistryPageProps, 't' | 'readDisclosure' | 'readDisclosureContent'
  | 'listImportTargets' | 'importDisclosure' | 'readImport' | 'askDisclosure'> & {
    readonly disclosureId: string
  }
type DetailState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly detail: RegistryDisclosureDetail }
type OpenDialog = 'import' | 'ask' | null
type ContentState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'operationUnconfigured' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly content: RegistryDisclosureContent }

function failureState(error: unknown): 'unconfigured' | 'accessLoss' | 'retry' {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured') return 'unconfigured'
  if (error.code === 'unauthenticated' || error.code === 'not-found' || error.code === 'invalid-input') return 'accessLoss'
  return 'retry'
}

function expiresAt(value: number): string {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? String(value) : date.toISOString()
}

function contentFailureState(error: unknown): 'unconfigured' | 'operationUnconfigured' | 'retry' | 'accessLoss' {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured') return 'unconfigured'
  if (error.code === 'operation-not-configured') return 'operationUnconfigured'
  if (error.code === 'unauthenticated' || error.code === 'not-found') return 'accessLoss'
  return 'retry'
}

function assertNever(value: never): never {
  void value
  throw new Error('Unsupported disclosure content event')
}

function contentEventLabel(event: RegistryDisclosureContentEvent, t: DetailProps['t']): string {
  switch (event.type) {
    case 'conversation.user-message': return t('contentUserMessage')
    case 'conversation.assistant-message': return t('contentAssistantMessage')
    case 'conversation.tool-result-summary': return t('contentToolSummary')
    case 'conversation.title': return t('contentTitleChange')
    default: return assertNever(event)
  }
}

function DisclosureContentEventItem({ event, t }: {
  readonly event: RegistryDisclosureContentEvent
  readonly t: DetailProps['t']
}) {
  const timestamp = expiresAt(event.occurredAt)
  return <li className={css.contentEvent}>
    <header className={css.contentEventHeader}>
      <strong>{contentEventLabel(event, t)}</strong>
      <span>{t('contentSequence', { sequence: event.disclosureSeq })}</span>
      <time dateTime={timestamp}>{timestamp}</time>
    </header>
    {event.type === 'conversation.title'
      ? <h3 className={css.contentTitle}>{event.title}</h3>
      : <>
        {event.type === 'conversation.tool-result-summary' && <div className={css.contentToolMeta}>
          <bdi>{event.toolName}</bdi>
          <span>{event.outcome === 'success' ? t('contentToolSuccess') : t('contentToolFailure')}</span>
        </div>}
        <p className={css.contentText}>{event.text}</p>
      </>}
  </li>
}

/** One authorized detail projection with Host-rechecked import and question actions. */
export function DisclosureDetailPage({
  disclosureId, t, readDisclosure, readDisclosureContent,
  listImportTargets, importDisclosure, readImport, askDisclosure,
}: DetailProps) {
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<DetailState>({ kind: 'loading' })
  const [contentRevision, setContentRevision] = useState(0)
  const [contentState, setContentState] = useState<ContentState>({ kind: 'loading' })
  const [openDialog, setOpenDialog] = useState<OpenDialog>(null)
  const dialogOpener = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setOpenDialog(null)
    setState({ kind: 'loading' })
    setContentState({ kind: 'loading' })
    void readDisclosure(disclosureId, controller.signal).then((detail) => {
      if (!controller.signal.aborted) setState({ kind: 'ready', detail })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setState({ kind: failureState(error) })
    })
    return () => { controller.abort() }
  }, [disclosureId, readDisclosure, revision])

  const checkpointHash = state.kind === 'ready' ? state.detail.checkpoint.checkpointHash : null
  useEffect(() => {
    if (checkpointHash === null) return
    const controller = new AbortController()
    setContentState({ kind: 'loading' })
    void readDisclosureContent(disclosureId, checkpointHash, controller.signal).then((content) => {
      if (!controller.signal.aborted) setContentState({ kind: 'ready', content })
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      const failure = contentFailureState(error)
      if (failure === 'accessLoss') {
        setContentState({ kind: 'loading' })
        setOpenDialog(null)
        setState({ kind: 'accessLoss' })
      } else {
        setContentState({ kind: failure })
      }
    })
    return () => { controller.abort() }
  }, [checkpointHash, contentRevision, disclosureId, readDisclosureContent])

  useLayoutEffect(() => {
    if (openDialog !== null) return
    const opener = dialogOpener.current
    dialogOpener.current = null
    if (opener?.isConnected) opener.focus()
  }, [openDialog])

  const handleBoundaryFailure = useCallback((error: unknown): boolean => {
    if (!(error instanceof RegistryApiError)) return false
    if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured') {
      setState({ kind: 'unconfigured' })
      setContentState({ kind: 'loading' })
      setOpenDialog(null)
      return true
    }
    if (error.code === 'unauthenticated' || error.code === 'not-found') {
      setState({ kind: 'accessLoss' })
      setContentState({ kind: 'loading' })
      setOpenDialog(null)
      return true
    }
    return false
  }, [])

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  return <section>
    <div className={css.pageHeading}>
      <a className={css.backLink} href="#/disclosures">← {t('backToList')}</a>
      <h1>{t('disclosureDetail')}</h1>
      <p>{t('disclosureDetailDescription')}</p>
    </div>
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingDisclosure')}</p></div>}
    {state.kind === 'unconfigured' && <div className={css.tableFrame}><UnconfiguredPanel t={t} /></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'ready' && <div className={css.detailLayout}>
      <section className={css.detailCard} aria-labelledby="registry-disclosure-metadata">
        <h2 id="registry-disclosure-metadata">{t('disclosureMetadata')}</h2>
        <dl className={css.metadataGrid}>
          <div><dt>{t('disclosureId')}</dt><dd><bdi>{state.detail.disclosureId}</bdi></dd></div>
          <div><dt>{t('sourceInstance')}</dt><dd><bdi>{state.detail.instanceId}</bdi></dd></div>
          <div><dt>{t('controlState')}</dt><dd><code>{state.detail.control}</code></dd></div>
          <div><dt>{t('producerState')}</dt><dd><code>{state.detail.producer}</code></dd></div>
          <div><dt>{t('ingestState')}</dt><dd><code>{state.detail.ingest}</code></dd></div>
          <div><dt>{t('expiry')}</dt><dd><time dateTime={expiresAt(state.detail.expiresAt)}>{expiresAt(state.detail.expiresAt)}</time></dd></div>
          <div><dt>{t('authorizationVersion')}</dt><dd>{state.detail.authorizationVersion}</dd></div>
          <div><dt>{t('checkpointVerifiedAt')}</dt><dd><time dateTime={expiresAt(state.detail.checkpointVerifiedAt)}>{expiresAt(state.detail.checkpointVerifiedAt)}</time></dd></div>
          <div><dt>{t('policyVersion')}</dt><dd>{state.detail.checkpoint.policyVersion}</dd></div>
          <div><dt>{t('sourceCursor')}</dt><dd>{state.detail.checkpoint.sourceCursor}</dd></div>
          <div><dt>{t('eventCount')}</dt><dd>{state.detail.checkpoint.eventCount}</dd></div>
          <div><dt>{t('lastDisclosureSeq')}</dt><dd>{state.detail.checkpoint.lastDisclosureSeq}</dd></div>
          <div className={css.wideMetadata}><dt>{t('checkpointHash')}</dt><dd><bdi>{state.detail.checkpoint.checkpointHash}</bdi></dd></div>
          <div className={css.wideMetadata}><dt>{t('lastEventHash')}</dt><dd><bdi>{state.detail.checkpoint.lastEventHash ?? t('noHash')}</bdi></dd></div>
        </dl>
      </section>
      <section className={css.detailCard} aria-labelledby="registry-disclosure-content">
        <div className={css.cardHeading}>
          <div><h2 id="registry-disclosure-content">{t('disclosureContent')}</h2><p>{t('disclosureContentDescription')}</p></div>
        </div>
        {contentState.kind === 'loading' && <div className={`${css.statePanel} ${css.contentState}`} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingDisclosureContent')}</p></div>}
        {contentState.kind === 'unconfigured' && <UnconfiguredPanel t={t} headingLevel={3} />}
        {contentState.kind === 'operationUnconfigured' && <div className={`${css.statePanel} ${css.contentState}`} role="status"><RegistryIcon name="notFound" size={40} /><h3>{t('contentNotConfigured')}</h3><p>{t('contentNotConfiguredDescription')}</p></div>}
        {contentState.kind === 'retry' && <div className={`${css.statePanel} ${css.contentState}`} role="alert"><RegistryIcon name="notFound" size={40} /><h3>{t('contentUnavailable')}</h3><p>{t('contentUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setContentRevision(value => value + 1) }}>{t('retry')}</button></div>}
        {contentState.kind === 'ready' && contentState.content.events.length === 0 && <div className={`${css.statePanel} ${css.contentState}`} role="status"><RegistryIcon name="disclosures" size={40} /><h3>{t('emptyDisclosureContent')}</h3><p>{t('emptyDisclosureContentDescription')}</p></div>}
        {contentState.kind === 'ready' && contentState.content.events.length > 0 && <ol className={css.contentEvents}>
          {contentState.content.events.map(event => <DisclosureContentEventItem key={event.disclosureSeq} event={event} t={t} />)}
        </ol>}
      </section>
      <section className={css.detailCard} aria-labelledby="registry-disclosure-actions">
        <h2 id="registry-disclosure-actions">{t('disclosureActions')}</h2>
        <div className={css.authorizedActionSummary}>
          <span>{t('currentCapabilities')}</span>
          <div className={css.authorizedActionList}>
            {state.detail.authorizedActions.map(action => <span key={action}>{t(action === 'read'
              ? 'capabilityRead' : action === 'import' ? 'capabilityImport' : 'capabilityAsk')}</span>)}
          </div>
        </div>
        <div className={css.operationGrid}>
          {(['import', 'ask'] as const).map((action) => {
            const allowed = state.detail.authorizedActions.includes(action)
            const label = action === 'import' ? t('importAction') : t('askAction')
            return <div className={css.operation} key={action}>
              <button className={action === 'import' ? css.primaryButton : css.secondaryButton} disabled={!allowed} onClick={(event) => { dialogOpener.current = event.currentTarget; setOpenDialog(action) }}>{label}</button>
              {!allowed && <p>{t('actionNotAuthorized')}</p>}
            </div>
          })}
          <div className={css.operation}>
            <a className={css.secondaryButton} href="#/branches">{t('viewExistingBranches')}</a>
            <p>{t('existingBranchesDescription')}</p>
          </div>
        </div>
      </section>
      {openDialog === 'import' && <UseContextDialog detail={state.detail} t={t} listImportTargets={listImportTargets} importDisclosure={importDisclosure} readImport={readImport} onBoundaryFailure={handleBoundaryFailure} onClose={() => { setOpenDialog(null) }} />}
      {openDialog === 'ask' && <AskSourceDialog detail={state.detail} t={t} askDisclosure={askDisclosure} onBoundaryFailure={handleBoundaryFailure} onClose={() => { setOpenDialog(null) }} />}
    </div>}
  </section>
}
