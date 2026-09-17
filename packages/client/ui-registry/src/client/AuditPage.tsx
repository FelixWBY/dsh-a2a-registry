import { useEffect, useRef, useState } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import { RegistryApiError, type RegistryAuditActorKind, type RegistryAuditMetadata } from './registry-api.ts'
import css from './Registry.module.css'

type AuditProps = Pick<RegistryOrganizationPageProps, 't' | 'listAudit'>
type AuditState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | {
    readonly kind: 'ready'
    readonly items: readonly RegistryAuditMetadata[]
    readonly nextCursor: string | null
    readonly more: 'idle' | 'loading' | 'error'
  }

const actorKeys: Record<RegistryAuditActorKind,
'auditActorEnrollment' | 'auditActorProducer' | 'auditActorMember' | 'auditActorMaintenance' | 'auditActorUnattributed'> = {
  enrollment: 'auditActorEnrollment', producer: 'auditActorProducer', member: 'auditActorMember',
  maintenance: 'auditActorMaintenance', unattributed: 'auditActorUnattributed',
}

function failureState(error: unknown): 'unconfigured' | 'accessLoss' | 'retry' {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured') return 'unconfigured'
  if (error.code === 'unauthenticated' || error.code === 'not-found') return 'accessLoss'
  return 'retry'
}

function isStaleCursor(error: unknown): boolean {
  return error instanceof RegistryApiError && error.code === 'invalid-input'
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

function subjectKey(item: RegistryAuditMetadata): string {
  return `${item.actorKind}:${item.actorId ?? ''}`
}

/** Authorized, paged operation metadata. Filters apply only to rows already returned by the Host. */
export function AuditPage({ t, listAudit }: AuditProps) {
  const [revision, setRevision] = useState(0)
  const [state, setState] = useState<AuditState>({ kind: 'loading' })
  const [subject, setSubject] = useState('')
  const [action, setAction] = useState('')
  const [result, setResult] = useState('')
  const [timeRange, setTimeRange] = useState('')
  const moreController = useRef<AbortController | null>(null)
  const loadingMore = useRef(false)

  useEffect(() => {
    const controller = new AbortController()
    moreController.current?.abort()
    loadingMore.current = false
    setState({ kind: 'loading' })
    void listAudit({}, controller.signal).then((page) => {
      if (!controller.signal.aborted) setState({ kind: 'ready', items: page.items,
        nextCursor: page.nextCursor, more: 'idle' })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setState({ kind: failureState(error) })
    })
    return () => { controller.abort() }
  }, [listAudit, revision])

  useEffect(() => () => { moreController.current?.abort() }, [])

  const loadMore = () => {
    if (state.kind !== 'ready' || state.nextCursor === null || loadingMore.current) return
    const controller = new AbortController()
    const cursor = state.nextCursor
    loadingMore.current = true
    moreController.current?.abort()
    moreController.current = controller
    setState(current => current.kind === 'ready' ? { ...current, more: 'loading' } : current)
    void listAudit({ cursor }, controller.signal).then((page) => {
      if (controller.signal.aborted) return
      loadingMore.current = false
      setState(current => current.kind === 'ready' ? { kind: 'ready', items: [...current.items, ...page.items],
        nextCursor: page.nextCursor, more: 'idle' } : current)
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      loadingMore.current = false
      if (isStaleCursor(error)) {
        setRevision(value => value + 1)
        return
      }
      const failure = failureState(error)
      setState(current => failure === 'retry' && current.kind === 'ready'
        ? { ...current, more: 'error' } : { kind: failure })
    })
  }

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  if (state.kind === 'loading') return <section><div className={css.pageHeading}><h1>{t('audit')}</h1>
    <p>{t('auditDescription')}</p></div><div className={css.statePanel} role="status">
    <span className={css.spinner} aria-hidden="true" /><p>{t('auditLoading')}</p></div></section>
  if (state.kind === 'retry') return <section><div className={css.pageHeading}><h1>{t('audit')}</h1>
    <p>{t('auditDescription')}</p></div><div className={css.statePanel} role="alert">
    <RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2>
    <p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton}
      onClick={() => { setRevision(value => value + 1) }}>{t('retry')}</button></div></section>

  const configured = state.kind === 'ready'
  const items = configured ? state.items : []
  const subjects = [...new Map(items.map(item => [subjectKey(item), item])).entries()]
  const actions = [...new Set(items.map(item => item.action))].sort((left, right) => left.localeCompare(right))
  const results = [...new Set(items.map(item => item.result))].sort((left, right) => left.localeCompare(right))
  const cutoff = timeRange === 'day' ? Date.now() - 86_400_000
    : timeRange === 'week' ? Date.now() - 604_800_000
      : timeRange === 'month' ? Date.now() - 2_592_000_000 : 0
  const visibleItems = items.filter(item => (subject === '' || subjectKey(item) === subject)
    && (action === '' || item.action === action) && (result === '' || item.result === result)
    && item.occurredAt >= cutoff)
  const filtered = subject !== '' || action !== '' || result !== '' || timeRange !== ''
  const actorLabel = (item: RegistryAuditMetadata): string => item.actorId ?? t(actorKeys[item.actorKind])
  const resultLabel = (value: RegistryAuditMetadata['result']): string => t(value === 'pending'
    ? 'auditResultPending' : value === 'succeeded' ? 'auditResultSucceeded' : 'auditResultRejected')

  return (
    <section aria-labelledby="registry-audit-title">
      <div className={css.pageHeading}>
        <h1 id="registry-audit-title">{t('audit')}</h1><p>{t('auditDescription')}</p>
      </div>
      <section className={css.auditFilterCard} aria-labelledby="registry-audit-filters-title">
        <div className={css.auditFilterHeader}>
          <h2 id="registry-audit-filters-title">{t('auditFiltersHeading')}</h2>
          <button className={css.auditClear} type="button" disabled={!configured || !filtered}
            aria-describedby="registry-audit-filter-reason" onClick={() => {
              setSubject(''); setAction(''); setResult(''); setTimeRange('')
            }}>{t('auditClearFilters')}</button>
        </div>
        <fieldset className={css.auditFilterFieldset} aria-describedby="registry-audit-filter-reason" disabled={!configured}>
          <legend className={css.visuallyHidden}>{t('auditFiltersHeading')}</legend>
          <div className={css.auditFilters}>
            <div className={css.auditFilter}><label htmlFor="registry-audit-subject">{t('auditSubject')}</label>
              <select id="registry-audit-subject" disabled={!configured} value={subject}
                aria-describedby="registry-audit-filter-reason" onChange={(event) => { setSubject(event.currentTarget.value) }}>
                <option value="">{t('auditSubjectAll')}</option>{subjects.map(([key, item]) => <option key={key} value={key}>{actorLabel(item)}</option>)}
              </select></div>
            <div className={css.auditFilter}><label htmlFor="registry-audit-action">{t('auditActionFilter')}</label>
              <select id="registry-audit-action" disabled={!configured} value={action}
                aria-describedby="registry-audit-filter-reason" onChange={(event) => { setAction(event.currentTarget.value) }}>
                <option value="">{t('auditActionAll')}</option>{actions.map(value => <option key={value} value={value}>{value}</option>)}
              </select></div>
            <div className={css.auditFilter}><label htmlFor="registry-audit-result">{t('auditResultFilter')}</label>
              <select id="registry-audit-result" disabled={!configured} value={result}
                aria-describedby="registry-audit-filter-reason" onChange={(event) => { setResult(event.currentTarget.value) }}>
                <option value="">{t('auditResultAll')}</option>{results.map(value => <option key={value} value={value}>{resultLabel(value)}</option>)}
              </select></div>
            <div className={css.auditFilter}><label htmlFor="registry-audit-time">{t('auditTimeRange')}</label>
              <select id="registry-audit-time" disabled={!configured} value={timeRange}
                aria-describedby="registry-audit-filter-reason" onChange={(event) => { setTimeRange(event.currentTarget.value) }}>
                <option value="">{t('auditTimeRangeAll')}</option><option value="day">{t('auditTimeDay')}</option>
                <option value="week">{t('auditTimeWeek')}</option><option value="month">{t('auditTimeMonth')}</option>
              </select></div>
          </div>
        </fieldset>
        <p id="registry-audit-filter-reason" className={css.filterReason}>{t(configured
          ? 'auditFiltersLoaded' : 'auditFiltersUnavailable')}</p>
      </section>
      <div className={css.tableFrame}>
        <div className={css.auditTableHeader}>
          <h2 id="registry-audit-records-title">{t('auditRecords')}</h2>
          <p id="registry-audit-metadata-note">{t('auditMetadataOnly')}</p>
        </div>
        <div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region"
          aria-labelledby="registry-audit-records-title" aria-describedby="registry-audit-metadata-note">
          <table className={`${css.table} ${css.auditTable} ${css.responsiveTable}`} aria-labelledby="registry-audit-records-title">
            <thead><tr>{(['auditTime', 'auditActor', 'auditInstance', 'auditObject',
              'auditActionColumn', 'auditResultColumn'] as const).map(column => <th scope="col" key={column}>{t(column)}</th>)}</tr></thead>
            <tbody>{visibleItems.map(item => <tr key={item.operationId}>
              <td data-label={t('auditTime')}><time dateTime={timestamp(item.occurredAt)}>{displayTime(item.occurredAt)}</time></td>
              <td data-label={t('auditActor')}><bdi className={css.tableIdentifier} title={actorLabel(item)}>{actorLabel(item)}</bdi></td>
              <td data-label={t('auditInstance')}><bdi className={css.tableIdentifier} title={item.instanceId ?? undefined}>{item.instanceId ?? t('unknownValue')}</bdi></td>
              <td data-label={t('auditObject')}><bdi className={css.tableIdentifier} title={item.objectId ?? undefined}>{item.objectId ?? t('unknownValue')}</bdi></td>
              <td data-label={t('auditActionColumn')}><code>{item.action}</code></td>
              <td data-label={t('auditResultColumn')}>{resultLabel(item.result)}</td>
            </tr>)}{configured && visibleItems.length === 0 ? <tr><td className={css.disclosureFilterEmpty} colSpan={6}>
              {t(filtered ? 'auditNoMatches' : 'auditEmpty')}</td></tr> : null}</tbody>
          </table>
        </div>
        {!configured ? <UnconfiguredPanel t={t} icon="audit" headingLevel={3} /> : null}
      </div>
      {configured && state.nextCursor !== null ? <div className={css.pagination}>
        {state.more === 'error' ? <p role="alert">{t('requestUnavailableDescription')}</p> : null}
        <button className={css.secondaryButton} disabled={state.more === 'loading'} onClick={loadMore}>
          {state.more === 'loading' ? t('loadingMore') : state.more === 'error' ? t('retry') : t('loadMore')}</button>
      </div> : null}
    </section>
  )
}
