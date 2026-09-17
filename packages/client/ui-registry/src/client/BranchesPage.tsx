import { useEffect, useRef, useState } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { questionHref } from './navigation.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import { RegistryApiError, type RegistryA2aRequestMetadata, type RegistryQuestionStatus } from './registry-api.ts'
import css from './Registry.module.css'

type BranchesProps = Pick<RegistryOrganizationPageProps, 't' | 'listBranches'> & { readonly organizationId: string }
type BranchesState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'empty' }
  | {
    readonly kind: 'ready'
    readonly items: readonly RegistryA2aRequestMetadata[]
    readonly nextCursor: string | null
    readonly more: 'idle' | 'loading' | 'error'
  }

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
  if (error.code === 'unauthenticated' || error.code === 'not-found') return 'accessLoss'
  return 'retry'
}

function timestamp(value: number): string {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? String(value) : date.toISOString()
}

function displayTime(value: number): string {
  const date = new Date(value)
  if (Number.isNaN(date.valueOf())) return String(value)
  const pad = (part: number): string => String(part).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function RequestRows({ organizationId, items, t }:
  { readonly organizationId: string; readonly items: readonly RegistryA2aRequestMetadata[]; readonly t: BranchesProps['t'] }) {
  return <>{items.map((item) => {
    const href = questionHref(organizationId, item.disclosureId, item.requestId)
    return <tr key={item.requestId}>
      <td data-label={t('requestId')}><a className={css.metadataLink} href={href}><bdi className={css.tableIdentifier} title={item.requestId}>{item.requestId}</bdi></a></td>
      <td data-label={t('disclosureId')}><bdi className={css.tableIdentifier} title={item.disclosureId}>{item.disclosureId}</bdi></td>
      <td data-label={t('sourceInstance')}><bdi className={css.tableIdentifier} title={item.sourceInstanceId}>{item.sourceInstanceId}</bdi></td>
      <td data-label={t('checkpointHash')}><bdi className={css.tableIdentifier} title={item.checkpointHash}>{item.checkpointHash}</bdi></td>
      <td data-label={t('operationStatus')}><code>{t(STATUS_KEYS[item.status])}</code></td>
      <td data-label={t('lastActivity')}><time dateTime={timestamp(item.updatedAt)}>{displayTime(item.updatedAt)}</time></td>
      <td data-label={t('expiry')}><time dateTime={timestamp(item.expiresAt)}>{displayTime(item.expiresAt)}</time></td>
      <td data-label={t('actions')}><a className={css.rowAction} href={href}>{t('viewQuestion')}</a></td>
    </tr>
  })}</>
}

/** Authorized, body-free question discovery; each detail click crosses the Host authorization boundary again. */
export function BranchesPage({ organizationId, t, listBranches }: BranchesProps) {
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<BranchesState>({ kind: 'loading' })
  const moreController = useRef<AbortController | null>(null)
  const loadingMore = useRef(false)

  useEffect(() => {
    const controller = new AbortController()
    moreController.current?.abort()
    loadingMore.current = false
    setState({ kind: 'loading' })
    void listBranches({}, controller.signal).then((value) => {
      if (controller.signal.aborted) return
      setState(value.items.length === 0
        ? { kind: 'empty' }
        : { kind: 'ready', items: value.items, nextCursor: value.nextCursor, more: 'idle' })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setState({ kind: failureState(error) })
    })
    return () => { controller.abort() }
  }, [listBranches, revision])

  useEffect(() => () => { moreController.current?.abort() }, [])

  const loadMore = () => {
    if (state.kind !== 'ready' || state.nextCursor === null || loadingMore.current) return
    const cursor = state.nextCursor
    const controller = new AbortController()
    loadingMore.current = true
    moreController.current?.abort()
    moreController.current = controller
    setState(current => current.kind === 'ready' ? { ...current, more: 'loading' } : current)
    void listBranches({ cursor }, controller.signal).then((value) => {
      if (controller.signal.aborted) return
      loadingMore.current = false
      setState(current => current.kind === 'ready'
        ? { kind: 'ready', items: [...current.items, ...value.items], nextCursor: value.nextCursor, more: 'idle' }
        : current)
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      loadingMore.current = false
      const failure = failureState(error)
      setState(current => failure === 'retry' && current.kind === 'ready'
        ? { ...current, more: 'error' }
        : { kind: failure })
    })
  }

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  return <section>
    <div className={css.pageHeading}><h1>{t('branches')}</h1><p>{t('branchesDescription')}</p></div>
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingBranches')}</p></div>}
    {state.kind === 'unconfigured' && <div className={css.tableFrame}><UnconfiguredPanel t={t} /></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'empty' && <div className={css.statePanel}><RegistryIcon name="branches" size={72} /><h2>{t('emptyBranches')}</h2><p>{t('emptyBranchesDescription')}</p></div>}
    {state.kind === 'ready' && <>
      <div className={css.tableFrame}>
        <div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region" aria-label={t('branchRequests')}>
          <table className={`${css.table} ${css.responsiveTable} ${css.branchTable}`}>
            <thead><tr>{(['requestId', 'disclosureId', 'sourceInstance', 'checkpointHash', 'operationStatus', 'lastActivity', 'expiry', 'actions'] as const).map(column => <th scope="col" key={column}>{t(column)}</th>)}</tr></thead>
            <tbody><RequestRows organizationId={organizationId} items={state.items} t={t} /></tbody>
          </table>
        </div>
      </div>
      {state.nextCursor !== null && <div className={css.pagination}>
        {state.more === 'error' && <p role="alert">{t('requestUnavailableDescription')}</p>}
        <button className={css.secondaryButton} disabled={state.more === 'loading'} onClick={loadMore}>{state.more === 'loading' ? t('loadingMore') : state.more === 'error' ? t('retry') : t('loadMore')}</button>
      </div>}
      <div className={css.notice}><RegistryIcon name="info" /><p>{t('branchMetadataOnly')}</p></div>
    </>}
  </section>
}
