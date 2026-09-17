import { useEffect, useRef, useState } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { disclosureHref, organizationHref } from './navigation.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import {
  RegistryApiError,
  type RegistryDisclosureMetadata,
  type RegistryInstance,
  type RegistryInstanceReportState,
} from './registry-api.ts'
import css from './Registry.module.css'

type NodeDetailProps = Pick<RegistryOrganizationPageProps, 't' | 'listInstances' | 'listDisclosures'> & {
  readonly organizationId: string
  readonly instanceId: string
}

type NodeDetailState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | {
    readonly kind: 'ready'
    readonly node: RegistryInstance
    readonly disclosures: readonly RegistryDisclosureMetadata[]
    readonly nextCursor: string | null
    readonly more: 'idle' | 'loading' | 'error'
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

function disclosureTime(value: number): string {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? String(value) : date.toISOString().slice(0, 16).replace('T', ' ')
}

function isoTimestamp(value: number): string | undefined {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? undefined : date.toISOString()
}

/** Account-authorized node facts and only the currently loaded disclosures from that node. */
export function NodeDetailPage({ organizationId, instanceId, t, listInstances, listDisclosures }: NodeDetailProps) {
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<NodeDetailState>({ kind: 'loading' })
  const moreController = useRef<AbortController | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    moreController.current?.abort()
    setState({ kind: 'loading' })
    void Promise.all([
      listInstances(controller.signal),
      listDisclosures({}, controller.signal),
    ]).then(([instances, disclosures]) => {
      if (controller.signal.aborted) return
      const node = instances.items.find(item => item.instanceId === instanceId)
      if (node === undefined) {
        setState({ kind: 'accessLoss' })
        return
      }
      setState({
        kind: 'ready',
        node,
        disclosures: disclosures.items.filter(item => item.instanceId === instanceId),
        nextCursor: disclosures.nextCursor,
        more: 'idle',
      })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setState({ kind: failureState(error) })
    })
    return () => { controller.abort() }
  }, [instanceId, listDisclosures, listInstances, revision])

  useEffect(() => () => { moreController.current?.abort() }, [])

  const loadMore = () => {
    if (state.kind !== 'ready' || state.nextCursor === null || state.more === 'loading') return
    const cursor = state.nextCursor
    const controller = new AbortController()
    moreController.current?.abort()
    moreController.current = controller
    setState(current => current.kind === 'ready' ? { ...current, more: 'loading' } : current)
    void listDisclosures({ cursor }, controller.signal).then((page) => {
      if (controller.signal.aborted) return
      setState(current => current.kind === 'ready' ? {
        ...current,
        disclosures: [...current.disclosures, ...page.items.filter(item => item.instanceId === instanceId)],
        nextCursor: page.nextCursor,
        more: 'idle',
      } : current)
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      const failure = failureState(error)
      setState(current => failure === 'retry' && current.kind === 'ready'
        ? { ...current, more: 'error' }
        : { kind: failure })
    })
  }

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  return <section>
    <div className={css.pageHeading}>
      <a className={css.backLink} href={organizationHref(organizationId, 'nodes')}>← {t('backToNodes')}</a>
      <h1>{t('nodeDetail')}</h1>
      <p>{t('nodeDetailDescription')}</p>
    </div>
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingNodeDetail')}</p></div>}
    {state.kind === 'unconfigured' && <div className={css.tableFrame}><UnconfiguredPanel t={t} /></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'ready' && <div className={css.detailLayout}>
      <article className={css.nodeDetailHero}>
        <div className={css.nodeDetailHeroIcon}><RegistryIcon name="nodes" size={28} /></div>
        <div className={css.nodeDetailHeroCopy}>
          <span>{t('nodeDetailIdentity')}</span>
          <h2>{state.node.instanceName}</h2>
          <bdi title={state.node.instanceId}>{state.node.instanceId}</bdi>
        </div>
        <div className={css.nodeDetailHeroActions}>
          <span className={state.node.phase === 'confirmed' ? css.nodePhaseActive : css.nodePhaseRevoked}>
            {t(state.node.phase === 'confirmed' ? 'nodeConfirmed' : 'nodeRevoked')}
          </span>
          <a className={css.secondaryButton} href={organizationHref(organizationId, 'nodes')}>{t('manageNodeBindings')}</a>
        </div>
      </article>

      <section className={css.detailCard} aria-labelledby="registry-node-status">
        <div className={css.cardHeading}>
          <div><h2 id="registry-node-status">{t('nodeRuntimeStatus')}</h2><p>{t('nodeRuntimeStatusDescription')}</p></div>
        </div>
        <dl className={css.metadataGrid}>
          <div><dt>{t('nodeConnection')}</dt><dd><span className={css.nodeDetailStatus}><i className={`${css.statusDot} ${state.node.transport === 'connected' ? css.statusHealthy : css.statusMuted}`} aria-hidden="true" />{t(state.node.transport === 'connected' ? 'nodeConnected' : 'nodeNotObserved')}</span></dd></div>
          <div><dt>{t('nodeReportState')}</dt><dd>{state.node.reportState === null ? t('unknownValue') : t(REPORT_KEYS[state.node.reportState])}</dd></div>
          <div><dt>{t('nodeAccepting')}</dt><dd>{state.node.acceptingA2A === null ? t('unknownValue') : t(state.node.acceptingA2A ? 'yes' : 'no')}</dd></div>
          <div><dt>{t('nodeActiveRequests')}</dt><dd>{state.node.activeRequests ?? t('unknownValue')}</dd></div>
          <div><dt>{t('nodeHeartbeat')}</dt><dd>{state.node.lastHeartbeatAt === null
            ? t('unknownValue')
            : <time dateTime={isoTimestamp(state.node.lastHeartbeatAt)}>{timestamp(state.node.lastHeartbeatAt, t('unknownValue'))}</time>}</dd></div>
          <div><dt>{t('nodeBindingState')}</dt><dd>{t(state.node.phase === 'confirmed' ? 'nodeConfirmed' : 'nodeRevoked')}</dd></div>
          <div className={css.wideMetadata}><dt>{t('nodeScopes')}</dt><dd>{state.node.requestedScopes.length === 0
            ? t('unknownValue')
            : state.node.requestedScopes.map(scope => t(scope === 'a2a.receive' ? 'nodeScopeReceive' : 'nodeScopeSync')).join(' · ')}</dd></div>
        </dl>
      </section>

      <section className={css.detailCard} aria-labelledby="registry-node-disclosures">
        <div className={css.cardHeading}>
          <div><h2 id="registry-node-disclosures">{t('nodeAccessibleDisclosures')}</h2><p>{t('nodeAccessibleDisclosuresDescription')}</p></div>
          <span className={css.nodeDisclosureCount}>{t('nodeDisclosuresLoaded', { count: state.disclosures.length })}</span>
        </div>
        {state.disclosures.length === 0
          ? <div className={css.nodeDetailEmpty}><RegistryIcon name="disclosures" size={32} /><p>{t('nodeDisclosuresEmpty')}</p></div>
          : <div className={css.tableFrame}>
            <div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region" aria-label={t('nodeAccessibleDisclosures')}>
              <table className={`${css.table} ${css.responsiveTable}`}>
                <thead><tr>{(['disclosureId', 'controlState', 'producerState', 'checkpoint', 'expiry', 'actions'] as const).map(key => <th scope="col" key={key}>{t(key)}</th>)}</tr></thead>
                <tbody>{state.disclosures.map(item => <tr key={item.disclosureId}>
                  <td data-label={t('disclosureId')}><a className={css.metadataLink} href={disclosureHref(organizationId, item.disclosureId)}><bdi className={css.tableIdentifier} title={item.disclosureId}>{item.disclosureId}</bdi></a></td>
                  <td data-label={t('controlState')}><code>{item.control}</code></td>
                  <td data-label={t('producerState')}><code>{item.producer}</code></td>
                  <td data-label={t('checkpoint')}>{t('checkpointSummary', { policyVersion: item.checkpoint.policyVersion, eventCount: item.checkpoint.eventCount })}</td>
                  <td data-label={t('expiry')}><time dateTime={isoTimestamp(item.expiresAt)}>{disclosureTime(item.expiresAt)}</time></td>
                  <td data-label={t('actions')}><a className={css.rowAction} href={disclosureHref(organizationId, item.disclosureId)}>{t('viewDetails')}</a></td>
                </tr>)}</tbody>
              </table>
            </div>
          </div>}
        {state.nextCursor !== null && <div className={css.pagination}>
          {state.more === 'error' && <p role="alert">{t('requestUnavailableDescription')}</p>}
          <button className={css.secondaryButton} disabled={state.more === 'loading'} onClick={loadMore}>{state.more === 'loading' ? t('loadingMore') : state.more === 'error' ? t('retry') : t('loadMore')}</button>
        </div>}
        <p className={css.nodeDisclosuresNote}>{t('nodeDisclosuresLoadedNote')}</p>
      </section>
      <div className={css.notice}><RegistryIcon name="info" /><p>{t('nodeObservationNote')}</p></div>
    </div>}
  </section>
}
