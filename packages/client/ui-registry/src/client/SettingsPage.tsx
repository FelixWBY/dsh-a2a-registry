import { useEffect, useRef, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { organizationHref } from './navigation.ts'
import { RegistryIcon } from './RegistryIcon.tsx'
import { RegistryApiError } from './registry-api.ts'
import type { RegistryBillingOrder, RegistryBillingOrderState, RegistryBillingPlan,
  RegistryConfigurationState, RegistryRuntimeStatus } from './registry-api.ts'
import css from './Registry.module.css'

type SettingsPageProps = Pick<RegistryPageProps, 't' | 'useTheme' | 'setTheme' | 'localTestIdentityBanner'
  | 'readStatus' | 'listBillingPlans' | 'listBillingOrders' | 'createBillingCheckout'> & {
  readonly organizationId: string
}
type BillingState =
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'owner-only' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly plans: readonly RegistryBillingPlan[];
    readonly orders: readonly RegistryBillingOrder[] }
type SettingsState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly status: RegistryRuntimeStatus; readonly billing: BillingState }

const requirements = [
  { fields: ['identity'], titleKey: 'identityTitle', bodyKey: 'identityRequirement' },
  { fields: ['registry', 'disclosureOperations'], titleKey: 'apiTitle', bodyKey: 'apiRequirement' },
  { fields: ['deviceBinding'], titleKey: 'deviceTitle', bodyKey: 'deviceRequirement' },
  { fields: ['audit'], titleKey: 'overviewAudit', bodyKey: 'overviewAuditDescription' },
  { fields: ['rateLimits'], titleKey: 'overviewRateLimits', bodyKey: 'overviewRateLimitsDescription' },
  { fields: ['disclosureCleanup'], titleKey: 'overviewDisclosureCleanup', bodyKey: 'overviewDisclosureCleanupDescription' },
  { fields: ['mailboxCleanup'], titleKey: 'overviewMailboxCleanup', bodyKey: 'overviewMailboxCleanupDescription' },
  { fields: ['billing'], titleKey: 'overviewBilling', bodyKey: 'overviewBillingDescription' },
] as const

function statusKey(state: RegistryConfigurationState, localTest: boolean): 'statusConfigured' | 'statusLocalTest' | 'statusUnconfigured' {
  if (state !== 'configured') return 'statusUnconfigured'
  return localTest ? 'statusLocalTest' : 'statusConfigured'
}

function billingError(error: unknown): BillingState['kind'] {
  if (error instanceof RegistryApiError && error.code === 'not-found') return 'owner-only'
  if (error instanceof RegistryApiError && error.code === 'operation-not-configured') return 'unconfigured'
  return 'retry'
}

function price(plan: Pick<RegistryBillingPlan, 'currency' | 'unitAmount'>): string {
  try {
    const formatter = new Intl.NumberFormat(undefined, { style: 'currency', currency: plan.currency })
    const digits = formatter.resolvedOptions().maximumFractionDigits
    return formatter.format(plan.unitAmount / 10 ** digits)
  } catch { return `${plan.currency} ${plan.unitAmount}` }
}

const orderStateKeys: Record<RegistryBillingOrderState, 'billingStateCreating' | 'billingStatePending'
  | 'billingStatePaid' | 'billingStateRefunded' | 'billingStateDisputed' | 'billingStateFailed'
  | 'billingStateExpired'> = {
    creating: 'billingStateCreating',
    'checkout-pending': 'billingStatePending',
    paid: 'billingStatePaid',
    refunded: 'billingStateRefunded',
    disputed: 'billingStateDisputed',
    failed: 'billingStateFailed',
    expired: 'billingStateExpired',
  }

/** Render runtime-confirmed setup facts without treating local test identity as production sign-in. */
export function SettingsPage({ organizationId, t, useTheme, setTheme, localTestIdentityBanner, readStatus,
  listBillingPlans, listBillingOrders, createBillingCheckout }: SettingsPageProps) {
  const preference = useTheme(snapshot => snapshot.preference)
  const [requestRevision, setRequestRevision] = useState(0)
  const [state, setState] = useState<SettingsState>({ kind: 'loading' })
  const [checkoutPlanId, setCheckoutPlanId] = useState<string | null>(null)
  const [checkoutFailed, setCheckoutFailed] = useState(false)
  const idempotencyKeys = useRef(new Map<string, string>())

  useEffect(() => {
    const controller = new AbortController()
    setState({ kind: 'loading' })
    void readStatus(controller.signal).then(async (status) => {
      if (controller.signal.aborted) return
      if (status.billing === 'unconfigured') {
        setState({ kind: 'ready', status, billing: { kind: 'unconfigured' } })
        return
      }
      const [plansResult, ordersResult] = await Promise.allSettled([
        listBillingPlans(controller.signal),
        listBillingOrders(controller.signal),
      ])
      if (controller.signal.aborted) return
      if (plansResult.status === 'fulfilled' && ordersResult.status === 'fulfilled') {
        setState({ kind: 'ready', status, billing: {
          kind: 'ready', plans: plansResult.value.items, orders: ordersResult.value.items,
        } })
        return
      }
      const error = plansResult.status === 'rejected' ? plansResult.reason
        : ordersResult.status === 'rejected' ? ordersResult.reason : undefined
      setState({ kind: 'ready', status, billing: { kind: billingError(error) } })
    }, () => {
      if (!controller.signal.aborted) setState({ kind: 'retry' })
    })
    return () => { controller.abort() }
  }, [listBillingOrders, listBillingPlans, readStatus, requestRevision])

  const beginCheckout = async (planId: string): Promise<void> => {
    setCheckoutPlanId(planId)
    setCheckoutFailed(false)
    let key = idempotencyKeys.current.get(planId)
    if (key === undefined) {
      key = globalThis.crypto.randomUUID()
      idempotencyKeys.current.set(planId, key)
    }
    const controller = new AbortController()
    try {
      const checkout = await createBillingCheckout({
        planId,
        idempotencyKey: key,
        returnPath: `/${organizationHref(organizationId, 'settings')}`,
      }, controller.signal)
      idempotencyKeys.current.delete(planId)
      globalThis.location.assign(checkout.checkoutUrl)
    } catch {
      setCheckoutFailed(true)
      setCheckoutPlanId(null)
    }
  }

  const localTest = localTestIdentityBanner || (state.kind === 'ready' && state.status.deploymentMode === 'test-only')
  const ready = !localTest && state.kind === 'ready'
    && requirements.every(({ fields }) => fields[0] === 'billing'
      || fields.every(field => state.status[field] === 'configured'))
  const statusTitle = localTest
    ? t('settingsLocalTest')
    : ready ? t('settingsReady') : t('settingsIncomplete')
  return (
    <section>
      <div className={css.pageHeading}><h1>{t('settings')}</h1><p>{t('settingsDescription')}</p></div>
      {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingOverview')}</p></div>}
      {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRequestRevision(value => value + 1) }}>{t('retry')}</button></div>}
      {state.kind === 'ready' && <>
        <section className={css.settingsStatus} aria-labelledby="registry-settings-status-title">
          <RegistryIcon name={ready ? 'audit' : 'info'} />
          <div>
            <h2 id="registry-settings-status-title">{statusTitle}</h2>
            <p>{t(localTest ? 'settingsLocalTestNote' : 'settingsStatusNote')}</p>
            <p>{t('noLocalData')}</p>
          </div>
        </section>
      </>}
      <section className={css.requirements} aria-labelledby="registry-settings-requirements-title">
        <h2 id="registry-settings-requirements-title">{t('requirementsHeading')}</h2>
        <dl>{requirements.map(({ fields, titleKey, bodyKey }) => {
          const status = state.kind === 'ready'
            ? fields.every(field => state.status[field] === 'configured') ? 'configured' : 'unconfigured'
            : null
          const configured = status === 'configured' && !localTest
          return <div className={css.requirement} key={titleKey}><dt>{t(titleKey)}</dt><dd>{t(bodyKey)}{fields[0] === 'deviceBinding' ? <p><a href={organizationHref(organizationId, 'binding')}>{t('bindingScopeLink')}</a></p> : null}</dd><dd className={configured ? css.overviewConfigured : css.overviewUnconfigured}>{t(status === null ? 'statusUnknown' : statusKey(status, localTest))}</dd></div>
        })}</dl>
      </section>
      {state.kind === 'ready' && <section className={css.billing} aria-labelledby="registry-settings-billing-title">
        <div className={css.billingHeading}>
          <div><h2 id="registry-settings-billing-title">{t('billingHeading')}</h2><p>{t('billingDescription')}</p></div>
          {state.billing.kind === 'retry' && <button className={css.secondaryButton}
            onClick={() => { setRequestRevision(value => value + 1) }}>{t('retry')}</button>}
        </div>
        {state.billing.kind === 'unconfigured' && <div className={css.billingNotice} role="status">
          <RegistryIcon name="info" /><div><strong>{t('billingUnconfigured')}</strong><p>{t('billingUnconfiguredDescription')}</p></div>
        </div>}
        {state.billing.kind === 'owner-only' && <div className={css.billingNotice} role="status">
          <RegistryIcon name="info" /><div><strong>{t('billingOwnerOnly')}</strong><p>{t('billingOwnerOnlyDescription')}</p></div>
        </div>}
        {state.billing.kind === 'retry' && <p className={css.billingError} role="alert">{t('billingUnavailable')}</p>}
        {state.billing.kind === 'ready' && <>
          <div className={css.billingPlans}>{state.billing.plans.map(plan => <article className={css.billingPlan} key={plan.planId}>
            <div><h3>{plan.displayName}</h3><p><strong>{price(plan)}</strong> / {t(plan.interval === 'month' ? 'billingMonth' : 'billingYear')}</p></div>
            <button className={css.primaryButton} disabled={checkoutPlanId !== null}
              onClick={() => { void beginCheckout(plan.planId) }}>
              {checkoutPlanId === plan.planId ? t('billingOpeningCheckout') : t('billingCheckout')}
            </button>
          </article>)}</div>
          {state.billing.plans.length === 0 && <p className={css.billingEmpty}>{t('billingNoPlans')}</p>}
          {checkoutFailed && <p className={css.billingError} role="alert">{t('billingCheckoutFailed')}</p>}
          <div className={css.billingOrdersHeading}><h3>{t('billingOrders')}</h3><p>{t('billingOrdersDescription')}</p></div>
          {state.billing.orders.length === 0 ? <p className={css.billingEmpty}>{t('billingNoOrders')}</p>
            : <div className={css.tableFrame}><div className={css.tableScroll} tabIndex={0}>
              <table className={css.table}><thead><tr><th>{t('billingPlan')}</th><th>{t('operationStatus')}</th>
                <th>{t('billingAmount')}</th><th>{t('billingCreated')}</th></tr></thead><tbody>
                {state.billing.orders.map(order => <tr key={order.orderId}>
                  <td data-label={t('billingPlan')}><code>{order.planId}</code></td>
                  <td data-label={t('operationStatus')}><span className={css.billingState} data-state={order.state}>{t(orderStateKeys[order.state])}</span></td>
                  <td data-label={t('billingAmount')}>{price(order)}</td>
                  <td data-label={t('billingCreated')}><time dateTime={new Date(order.createdAt).toISOString()}>{new Date(order.createdAt).toLocaleString()}</time></td>
                </tr>)}</tbody></table>
            </div></div>}
        </>}
      </section>}
      <div className={css.notice}><RegistryIcon name="info" /><p>{t('securityNote')}</p></div>
      {state.kind === 'ready' && state.status.identityProvider === 'oidc' && <section className={css.preference} aria-labelledby="registry-settings-account-title">
        <h2 id="registry-settings-account-title">{t('accountSessionHeading')}</h2>
        <p>{t('accountSessionDescription')}</p>
        <form method="post" action="/registry-auth/v1/logout"><button type="submit" className={css.secondaryButton}>{t('signOutAction')}</button></form>
      </section>}
      <section className={css.preference} aria-labelledby="registry-settings-preferences-title">
        <h2 id="registry-settings-preferences-title">{t('preferencesHeading')}</h2><p id="registry-session-preference">{t('sessionPreference')}</p>
        <label htmlFor="registry-theme">{t('theme')}</label>
        <select id="registry-theme" className={css.themeSelect} aria-describedby="registry-session-preference" value={preference} onChange={(event) => {
          const next = event.currentTarget.value
          if (next === 'system' || next === 'light' || next === 'dark') setTheme(next)
        }}>
          <option value="system">{t('themeSystem')}</option>
          <option value="light">{t('themeLight')}</option>
          <option value="dark">{t('themeDark')}</option>
        </select>
      </section>
    </section>
  )
}
