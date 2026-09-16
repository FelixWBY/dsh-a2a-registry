import { useEffect, useRef, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import { RegistryApiError, type RegistryDisclosureMetadata } from './registry-api.ts'
import css from './Registry.module.css'

type ListProps = Pick<RegistryPageProps, 't' | 'listDisclosures'>
type ListState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'empty' }
  | {
    readonly kind: 'ready'
    readonly items: readonly RegistryDisclosureMetadata[]
    readonly nextCursor: string | null
    readonly more: 'idle' | 'loading' | 'error'
  }

function failureState(error: unknown): 'unconfigured' | 'accessLoss' | 'retry' {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured') return 'unconfigured'
  if (error.code === 'unauthenticated' || error.code === 'not-found') return 'accessLoss'
  return 'retry'
}

function expiresAt(value: number): string {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? String(value) : date.toISOString()
}

function displayTime(value: number): string {
  const date = new Date(value)
  if (Number.isNaN(date.valueOf())) return String(value)
  const pad = (part: number): string => String(part).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function DisclosureRows({ items, t }: { readonly items: readonly RegistryDisclosureMetadata[]; readonly t: ListProps['t'] }) {
  return <>{items.map(item => <tr key={item.disclosureId}>
    <td data-label={t('disclosureId')}><a className={css.metadataLink} href={`#/disclosures/${encodeURIComponent(item.disclosureId)}`}><bdi className={css.tableIdentifier} title={item.disclosureId}>{item.disclosureId}</bdi></a></td>
    <td data-label={t('sourceInstance')}><bdi className={css.tableIdentifier} title={item.instanceId}>{item.instanceId}</bdi></td>
    <td data-label={t('controlState')}><code>{item.control}</code></td>
    <td data-label={t('producerState')}><code>{item.producer}</code></td>
    <td data-label={t('ingestState')}><code>{item.ingest}</code></td>
    <td data-label={t('checkpoint')}><span>{t('checkpointSummary', { policyVersion: item.checkpoint.policyVersion, eventCount: item.checkpoint.eventCount })}</span></td>
    <td data-label={t('lastSync')}><time dateTime={expiresAt(item.checkpointVerifiedAt)}>{displayTime(item.checkpointVerifiedAt)}</time></td>
    <td data-label={t('expiry')}><time dateTime={expiresAt(item.expiresAt)}>{displayTime(item.expiresAt)}</time></td>
    <td data-label={t('authorizationVersion')}>{item.authorizationVersion}</td>
    <td data-label={t('actions')}><a className={css.rowAction} href={`#/disclosures/${encodeURIComponent(item.disclosureId)}`}>{t('viewDetails')}</a></td>
  </tr>)}</>
}

/** Authorized paged disclosure metadata; it never synthesizes title, owner or body fields. */
export function DisclosureListPage({ t, listDisclosures }: ListProps) {
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<ListState>({ kind: 'loading' })
  const [search, setSearch] = useState('')
  const [source, setSource] = useState('')
  const [control, setControl] = useState('')
  const moreController = useRef<AbortController | null>(null)
  const loadingMore = useRef(false)

  useEffect(() => {
    const controller = new AbortController()
    moreController.current?.abort()
    loadingMore.current = false
    setState({ kind: 'loading' })
    void listDisclosures({}, controller.signal).then((value) => {
      if (controller.signal.aborted) return
      setState(value.items.length === 0
        ? { kind: 'empty' }
        : { kind: 'ready', items: value.items, nextCursor: value.nextCursor, more: 'idle' })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setState({ kind: failureState(error) })
    })
    return () => { controller.abort() }
  }, [listDisclosures, revision])

  useEffect(() => () => { moreController.current?.abort() }, [])

  const loadMore = () => {
    if (state.kind !== 'ready' || state.nextCursor === null || loadingMore.current) return
    const cursor = state.nextCursor
    const controller = new AbortController()
    loadingMore.current = true
    moreController.current?.abort()
    moreController.current = controller
    setState(current => current.kind === 'ready' ? { ...current, more: 'loading' } : current)
    void listDisclosures({ cursor }, controller.signal).then((value) => {
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

  const normalizedSearch = search.trim().toLocaleLowerCase()
  const sourceOptions = state.kind === 'ready'
    ? [...new Set(state.items.map(item => item.instanceId))].sort((left, right) => left.localeCompare(right))
    : []
  const controlOptions = state.kind === 'ready'
    ? [...new Set(state.items.map(item => item.control))].sort((left, right) => left.localeCompare(right))
    : []
  const visibleItems = state.kind === 'ready' ? state.items.filter((item) => {
    const matchesSearch = normalizedSearch.length === 0
      || item.disclosureId.toLocaleLowerCase().includes(normalizedSearch)
      || item.instanceId.toLocaleLowerCase().includes(normalizedSearch)
    return matchesSearch
      && (source.length === 0 || item.instanceId === source)
      && (control.length === 0 || item.control === control)
  }) : []

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  return <section>
    <div className={css.pageHeading}><h1>{t('disclosures')}</h1><p>{t('disclosureDescription')}</p></div>
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingDisclosures')}</p></div>}
    {state.kind === 'unconfigured' && <div className={css.tableFrame}><UnconfiguredPanel t={t} /></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'empty' && <div className={css.statePanel}><RegistryIcon name="emptyNodes" size={72} /><h2>{t('emptyDisclosures')}</h2><p>{t('emptyDisclosuresDescription')}</p></div>}
    {state.kind === 'ready' && <>
      <fieldset className={css.disclosureFilters}>
        <legend className={css.visuallyHidden}>{t('disclosureFilters')}</legend>
        <div className={css.disclosureFilterControls}>
          <label className={css.disclosureFilter}>
            <span>{t('disclosureFilterSearch')}</span>
            <input
              type="search"
              value={search}
              placeholder={t('disclosureFilterSearchPlaceholder')}
              aria-describedby="registry-disclosure-filter-note"
              onChange={(event) => { setSearch(event.currentTarget.value) }}
            />
          </label>
          <label className={css.disclosureFilter}>
            <span>{t('disclosureFilterSource')}</span>
            <select value={source} aria-describedby="registry-disclosure-filter-note" onChange={(event) => { setSource(event.currentTarget.value) }}>
              <option value="">{t('disclosureFilterSourceAll')}</option>
              {sourceOptions.map(value => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
          <label className={css.disclosureFilter}>
            <span>{t('disclosureFilterControl')}</span>
            <select value={control} aria-describedby="registry-disclosure-filter-note" onChange={(event) => { setControl(event.currentTarget.value) }}>
              <option value="">{t('disclosureFilterControlAll')}</option>
              {controlOptions.map(value => <option key={value} value={value}>{value}</option>)}
            </select>
          </label>
        </div>
        <p id="registry-disclosure-filter-note" className={css.disclosureFilterNote}>{t('disclosureFilterLoadedNote')}</p>
      </fieldset>
      <div className={css.tableFrame}>
        <div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region" aria-label={t('disclosures')}>
          <table className={`${css.table} ${css.responsiveTable}`}>
            <thead><tr>{(['disclosureId', 'sourceInstance', 'controlState', 'producerState', 'ingestState', 'checkpoint', 'lastSync', 'expiry', 'authorizationVersion', 'actions'] as const).map(column => <th scope="col" key={column}>{t(column)}</th>)}</tr></thead>
            <tbody>{visibleItems.length === 0
              ? <tr><td className={css.disclosureFilterEmpty} colSpan={10}>{t('disclosureFilterNoMatches')}</td></tr>
              : <DisclosureRows items={visibleItems} t={t} />}</tbody>
          </table>
        </div>
      </div>
      {state.nextCursor !== null && <div className={css.pagination}>
        {state.more === 'error' && <p role="alert">{t('requestUnavailableDescription')}</p>}
        <button className={css.secondaryButton} disabled={state.more === 'loading'} onClick={loadMore}>{state.more === 'loading' ? t('loadingMore') : state.more === 'error' ? t('retry') : t('loadMore')}</button>
      </div>}
      <div className={css.notice}><RegistryIcon name="info" /><p>{t('offlineNote')}</p></div>
    </>}
  </section>
}
