import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import type { FormEvent, KeyboardEvent, MouseEvent } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { nodeHref, organizationHref } from './navigation.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import { RegistryApiError, type RegistryInstance, type RegistryInstanceReportState } from './registry-api.ts'
import css from './Registry.module.css'

type NodesProps = Pick<RegistryOrganizationPageProps, 't' | 'listInstances' | 'renameInstance' | 'revokeInstance'> & {
  readonly organizationId: string
}
type NodesState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly items: readonly RegistryInstance[]; readonly refreshing: boolean }

type NodeAction = {
  readonly kind: 'rename' | 'revoke'
  readonly node: RegistryInstance
}

type NodeActionDialogProps = Pick<NodesProps, 't' | 'renameInstance' | 'revokeInstance'> & {
  readonly action: NodeAction
  readonly onBoundaryFailure: (error: unknown) => boolean
  readonly onClose: () => void
  readonly onUpdated: (node: RegistryInstance, kind: NodeAction['kind']) => void
}

const REPORT_KEYS: Record<RegistryInstanceReportState,
'nodeReportOnline' | 'nodeReportBusy' | 'nodeReportPaused' | 'nodeReportDegraded'> = {
  online: 'nodeReportOnline',
  busy: 'nodeReportBusy',
  paused: 'nodeReportPaused',
  degraded: 'nodeReportDegraded',
}

function failureState(error: unknown): 'unconfigured' | 'accessLoss' | 'retry' {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured') return 'unconfigured'
  if (error.code === 'unauthenticated' || error.code === 'not-found') return 'accessLoss'
  return 'retry'
}

function timestamp(value: number | null, unknown: string): string {
  if (value === null) return unknown
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? unknown : date.toISOString().slice(0, 16).replace('T', ' ')
}

/** Focused confirmation surface for one account-owned node mutation. */
function NodeActionDialog({
  action, t, renameInstance, revokeInstance, onBoundaryFailure, onClose, onUpdated,
}: NodeActionDialogProps) {
  const [instanceName, setInstanceName] = useState(action.node.instanceName)
  const [status, setStatus] = useState<'idle' | 'pending' | 'error'>('idle')
  const controller = useRef<AbortController | null>(null)
  const renameField = useRef<HTMLInputElement>(null)
  const safeButton = useRef<HTMLButtonElement>(null)
  const titleId = useId()
  const descriptionId = useId()
  const renameFieldId = useId()
  const renameHelpId = useId()

  useEffect(() => () => { controller.current?.abort() }, [])
  useLayoutEffect(() => {
    if (action.kind === 'rename') renameField.current?.focus()
    else safeButton.current?.focus()
  }, [action.kind])

  const close = () => {
    controller.current?.abort()
    onClose()
  }
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const nextName = instanceName.trim()
    if (status === 'pending' || action.kind === 'rename'
      && (nextName.length === 0 || nextName === action.node.instanceName)) return
    const requestController = new AbortController()
    controller.current?.abort()
    controller.current = requestController
    setStatus('pending')
    const operation = action.kind === 'rename'
      ? renameInstance(action.node.bindingId, nextName, requestController.signal)
      : revokeInstance(action.node.bindingId, requestController.signal)
    void operation.then((updated) => {
      if (!requestController.signal.aborted) onUpdated(updated, action.kind)
    }, (error: unknown) => {
      if (requestController.signal.aborted || onBoundaryFailure(error)) return
      setStatus('error')
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
      element.matches('button:not(:disabled), input:not(:disabled)') && element.tabIndex >= 0)
    const index = elements.findIndex(element => element === document.activeElement)
    if (event.shiftKey && index <= 0) {
      event.preventDefault()
      ;(elements.at(-1) ?? event.currentTarget).focus()
    } else if (!event.shiftKey && (index === -1 || index === elements.length - 1)) {
      event.preventDefault()
      ;(elements[0] ?? event.currentTarget).focus()
    }
  }
  const canRename = instanceName.trim().length > 0 && instanceName.trim() !== action.node.instanceName

  return <div className={css.dialogBackdrop} onMouseDown={dismissBackdrop}>
    <section className={css.actionDialog} tabIndex={-1} role="dialog" aria-modal="true"
      aria-labelledby={titleId} aria-describedby={descriptionId} onKeyDown={handleDialogKeyDown}>
      <header className={css.dialogHeader}>
        <div>
          <h2 id={titleId}>{t(action.kind === 'rename' ? 'nodeRenameTitle' : 'nodeRevokeTitle')}</h2>
          <p id={descriptionId}>{t(action.kind === 'rename' ? 'nodeRenameDescription' : 'nodeRevokeDescription')}</p>
        </div>
        <button type="button" className={css.dialogClose} aria-label={t('close')} onClick={close}>×</button>
      </header>
      <div className={css.dialogSource}>
        <RegistryIcon name="nodes" />
        <div><strong>{action.node.instanceName}</strong><p><bdi>{action.node.instanceId}</bdi></p></div>
      </div>
      <form className={css.dialogForm} onSubmit={submit}>
        {action.kind === 'rename' ? <div className={css.dialogField}>
          <label htmlFor={renameFieldId}>{t('nodeName')}</label>
          <input id={renameFieldId} aria-describedby={renameHelpId} ref={renameField} required
            value={instanceName} disabled={status === 'pending'}
            onChange={(event) => { setInstanceName(event.currentTarget.value); setStatus('idle') }} />
          <small id={renameHelpId} className={css.fieldHelp}>{t('nodeRenameHelp')}</small>
        </div> : <div className={css.nodeRevokeWarning} role="note">
          <RegistryIcon name="info" /><p>{t('nodeRevokeWarning')}</p>
        </div>}
        {status === 'error' && <p className={css.inlineAlert} role="alert">{t('nodeActionUnavailable')}</p>}
        <footer className={css.dialogActions}>
          <button ref={safeButton} type="button" className={css.secondaryButton} onClick={close}>{t('cancel')}</button>
          <button type="submit" className={action.kind === 'revoke' ? css.dangerButton : css.primaryButton}
            disabled={status === 'pending' || action.kind === 'rename' && !canRename}>
            {status === 'pending'
              ? t(action.kind === 'rename' ? 'nodeRenaming' : 'nodeRevoking')
              : t(action.kind === 'rename' ? 'nodeRenameConfirm' : 'nodeRevokeConfirm')}
          </button>
        </footer>
      </form>
    </section>
  </div>
}

/** Account-owned bindings with current transport observations and explicit owner actions. */
export function NodesPage({ organizationId, t, listInstances, renameInstance, revokeInstance }: NodesProps) {
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<NodesState>({ kind: 'loading' })
  const [action, setAction] = useState<NodeAction | null>(null)
  const [feedback, setFeedback] = useState<NodeAction['kind'] | null>(null)
  const [query, setQuery] = useState('')
  const refreshController = useRef<AbortController | null>(null)

  useEffect(() => {
    refreshController.current?.abort()
    refreshController.current = null
    const controller = new AbortController()
    setState({ kind: 'loading' })
    setAction(null)
    setFeedback(null)
    void listInstances(controller.signal).then((page) => {
      if (!controller.signal.aborted) setState({ kind: 'ready', items: page.items, refreshing: false })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setState({ kind: failureState(error) })
    })
    return () => { controller.abort() }
  }, [listInstances, revision])
  useEffect(() => () => { refreshController.current?.abort() }, [])

  const refreshInstances = () => {
    if (refreshController.current !== null) return
    const controller = new AbortController()
    refreshController.current = controller
    setAction(null)
    setFeedback(null)
    setState(current => current.kind === 'ready' ? { ...current, refreshing: true } : current)
    void listInstances(controller.signal).then((page) => {
      if (controller.signal.aborted) return
      refreshController.current = null
      setState({ kind: 'ready', items: page.items, refreshing: false })
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      refreshController.current = null
      setState({ kind: failureState(error) })
    })
  }

  const boundaryFailure = (error: unknown): boolean => {
    const failure = failureState(error)
    if (failure === 'retry') return false
    setAction(null)
    setFeedback(null)
    setState({ kind: failure })
    return true
  }
  const updateNode = (updated: RegistryInstance, kind: NodeAction['kind']) => {
    setState(current => current.kind === 'ready' ? {
      kind: 'ready',
      items: current.items.map(item => item.bindingId === updated.bindingId ? updated : item),
      refreshing: current.refreshing,
    } : current)
    setAction(null)
    setFeedback(kind)
  }

  const normalizedQuery = query.trim().toLocaleLowerCase()
  const items = state.kind === 'ready' ? state.items : []
  const visibleItems = normalizedQuery.length === 0 ? items : items.filter(item =>
    `${item.instanceName} ${item.instanceId} ${item.requestedScopes.join(' ')}`.toLocaleLowerCase().includes(normalizedQuery))
  const summary = items.reduce((value, item) => ({
    connected: value.connected + Number(item.transport === 'connected'),
    online: value.online + Number(item.reportState === 'online'),
    unknown: value.unknown + Number(item.reportState === null),
  }), { connected: 0, online: 0, unknown: 0 })

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  return <section>
    <div className={css.pageHeading}>
      <div><h1>{t('nodes')}</h1><p>{t('nodesDescription')}</p></div>
    </div>
    {state.kind === 'ready' && <>
      <p className={css.nodeSummary}>{t('nodesSummary', { count: items.length, connected: summary.connected, online: summary.online, unknown: summary.unknown })}</p>
      <div className={css.nodeToolbar}>
        <label className={css.nodeSearch}>
          <span className={css.visuallyHidden}>{t('nodeSearch')}</span>
          <RegistryIcon name="nodes" size={18} />
          <input type="search" value={query} placeholder={t('nodeSearchPlaceholder')} onChange={(event) => { setQuery(event.currentTarget.value) }} />
        </label>
        <button type="button" className={css.secondaryButton} disabled={state.refreshing} onClick={refreshInstances}>
          {t(state.refreshing ? 'refreshingStatus' : 'refreshStatus')}
        </button>
        <a className={css.primaryButton} href={organizationHref(organizationId, 'binding')}>{t('addNode')}</a>
      </div>
    </>}
    {feedback !== null && <p className={css.nodeActionStatus} role="status">
      {t(feedback === 'rename' ? 'nodeRenameSuccess' : 'nodeRevokeSuccess')}
    </p>}
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingInstances')}</p></div>}
    {state.kind === 'unconfigured' && <div className={css.tableFrame}><UnconfiguredPanel t={t} /></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'ready' && state.items.length === 0 && <div className={css.statePanel}><RegistryIcon name="emptyNodes" size={72} /><h2>{t('emptyInstances')}</h2><p>{t('emptyInstancesDescription')}</p></div>}
    {state.kind === 'ready' && state.items.length > 0 && <>
      <div className={css.tableFrame}>
        <div className={css.tableScroll} tabIndex={0} role="region" aria-label={t('nodes')}>
          <table className={`${css.table} ${css.nodeTable}`}>
            <thead><tr>{(['nodeName', 'nodeConnection', 'nodeScopes', 'nodeActiveRequests', 'nodeHeartbeat', 'actions'] as const).map(key => <th scope="col" key={key}>{t(key)}</th>)}</tr></thead>
            <tbody>{visibleItems.map(item => <tr key={item.bindingId}>
              <td data-label={t('nodeName')}><div className={css.nodeIdentity}><RegistryIcon name="nodes" size={20} /><div><a className={css.nodeNameLink} href={nodeHref(organizationId, item.instanceId)}><strong>{item.instanceName}</strong></a><span><bdi>{item.instanceId}</bdi> · {t(item.phase === 'confirmed' ? 'nodeConfirmed' : 'nodeRevoked')}</span></div></div></td>
              <td data-label={t('nodeConnection')}><div className={css.nodeStatus}><span className={`${css.statusDot} ${item.transport === 'connected' ? css.statusHealthy : css.statusMuted}`} aria-hidden="true" /><div><strong>{t(item.transport === 'connected' ? 'nodeConnected' : 'nodeNotObserved')}</strong><span>{item.reportState === null ? t('unknownValue') : t(REPORT_KEYS[item.reportState])}</span></div></div></td>
              <td data-label={t('nodeScopes')}><div className={css.nodePolicy}><strong>{item.requestedScopes.length === 0 ? t('unknownValue') : item.requestedScopes.map(scope => t(scope === 'a2a.receive' ? 'nodeScopeReceive' : 'nodeScopeSync')).join(' · ')}</strong><span>{t('nodePolicyAccepting', { value: item.acceptingA2A === null ? t('unknownValue') : t(item.acceptingA2A ? 'yes' : 'no') })}</span></div></td>
              <td data-label={t('nodeActiveRequests')}>{item.activeRequests ?? t('unknownValue')}</td>
              <td data-label={t('nodeHeartbeat')}><time dateTime={item.lastHeartbeatAt === null ? undefined : new Date(item.lastHeartbeatAt).toISOString()}>{timestamp(item.lastHeartbeatAt, t('unknownValue'))}</time></td>
              <td data-label={t('actions')}>{item.phase === 'confirmed' ? <div className={css.nodeRowActions}>
                <button type="button" className={css.nodeActionButton} disabled={action !== null}
                  onClick={() => { setFeedback(null); setAction({ kind: 'rename', node: item }) }}>{t('nodeRename')}</button>
                <button type="button" className={`${css.nodeActionButton} ${css.nodeRevokeButton}`} disabled={action !== null}
                  onClick={() => { setFeedback(null); setAction({ kind: 'revoke', node: item }) }}>{t('nodeRevoke')}</button>
              </div> : <span className={css.nodeNoActions}>{t('nodeActionsUnavailable')}</span>}</td>
            </tr>)}{visibleItems.length === 0 && <tr><td className={css.disclosureFilterEmpty} colSpan={6}>{t('nodeSearchEmpty')}</td></tr>}</tbody>
          </table>
        </div>
      </div>
      <div className={css.notice}><RegistryIcon name="info" /><p>{t('nodeObservationNote')}</p></div>
    </>}
    {action !== null && <NodeActionDialog key={`${action.kind}:${action.node.bindingId}`} action={action} t={t}
      renameInstance={renameInstance} revokeInstance={revokeInstance} onBoundaryFailure={boundaryFailure}
      onClose={() => { setAction(null) }} onUpdated={updateNode} />}
  </section>
}
