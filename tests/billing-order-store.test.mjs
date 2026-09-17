import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'

import { PostgresRegistryTenancy } from '../packages/bundle/registry-app/src/tenancy-postgres.ts'

const organizationId = 'organization-a'
const accountId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const memberId = 'owner-a'
const orderId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const createdAt = new Date('2026-09-18T00:00:00.000Z')

function order(overrides = {}) {
  return {
    order_id: orderId,
    organization_id: organizationId,
    provider: 'stripe',
    plan_id: 'pro-monthly',
    currency: 'USD',
    unit_amount: '1200',
    interval: 'month',
    state: 'creating',
    provider_checkout_id: null,
    checkout_expires_at: null,
    paid_at: null,
    refunded_at: null,
    disputed_at: null,
    last_event_at: null,
    created_at: createdAt,
    updated_at: createdAt,
    ...overrides,
  }
}

function store(client) {
  const value = Object.create(PostgresRegistryTenancy.prototype)
  value.schema = '"registry"'
  value.transaction = async (_account, _organization, operation) => operation(client)
  value.requireActiveMembership = async () => ({ role: 'owner', state: 'active' })
  value.advisoryLock = async () => undefined
  return value
}

function billingEventHarness(initial) {
  let current = order(initial)
  let updates = 0
  const events = new Map()
  const statements = []
  const client = {
    async query(statement, values) {
      statements.push(statement)
      if (/from "registry"\.billing_provider_events/u.test(statement)) {
        const retained = events.get(`${values[0]}\0${values[1]}`)
        return { rows: retained === undefined ? [] : [retained] }
      }
      if (/from "registry"\.billing_orders/u.test(statement)) return { rows: [current] }
      if (/insert into "registry"\.billing_provider_events/u.test(statement)) {
        const key = `${values[0]}\0${values[1]}`
        if (events.has(key)) return { rows: [] }
        events.set(key, {
          provider: values[0],
          event_id: values[1],
          organization_id: values[2],
          order_id: values[3],
          event_type: values[4],
          payload_hash: values[5],
          occurred_at: values[6],
        })
        return { rows: [{ provider: values[0] }] }
      }
      if (/update "registry"\.billing_orders set state/u.test(statement)) {
        assert.equal(values.length, 5)
        const projectedState = values[2]
        const occurredAt = values[3]
        const eventType = values[4]
        const paidAt = eventType === 'checkout-paid'
          ? current.paid_at === null || current.paid_at > occurredAt ? occurredAt : current.paid_at
          : projectedState === 'paid' || projectedState === 'disputed' || projectedState === 'refunded'
            ? current.paid_at ?? occurredAt : current.paid_at
        const lastEventAt = current.last_event_at === null || current.last_event_at < occurredAt
          ? occurredAt : current.last_event_at
        current = order({
          ...current,
          state: projectedState,
          paid_at: paidAt,
          refunded_at: eventType === 'refunded'
            && (current.refunded_at === null || current.refunded_at > occurredAt)
            ? occurredAt : current.refunded_at,
          disputed_at: eventType === 'disputed'
            && (current.disputed_at === null || current.disputed_at > occurredAt)
            ? occurredAt : current.disputed_at,
          last_event_at: lastEventAt,
          updated_at: occurredAt,
        })
        updates += 1
        return { rows: [current] }
      }
      throw new Error(`unexpected statement: ${statement}`)
    },
  }
  return {
    store: store(client),
    events,
    statements,
    current: () => current,
    updates: () => updates,
  }
}

function providerEvent(eventId, eventType, occurredAt) {
  return {
    organizationId,
    orderId,
    provider: 'stripe',
    eventId,
    eventType,
    payloadHash: createHash('sha256').update(eventId).digest('hex'),
    occurredAt,
  }
}

const reservation = {
  organizationId,
  provider: 'stripe',
  planId: 'pro-monthly',
  idempotencyKey: 'checkout-1',
  currency: 'USD',
  unitAmount: 1200,
  interval: 'month',
}

test('billing reservation binds one organization idempotency key to canonical priced terms', async () => {
  const requestHash = createHash('sha256').update('registry-billing-order-v1\0', 'utf8')
    .update(JSON.stringify(['stripe', 'pro-monthly', 'USD', 1200, 'month']), 'utf8').digest('hex')
  const matching = store({
    async query(statement, values) {
      assert.match(statement, /from "registry"\.billing_orders/u)
      assert.deepEqual(values, [organizationId, reservation.idempotencyKey])
      return { rows: [{ ...order(), request_hash: requestHash }] }
    },
  })
  assert.equal((await matching.reserveBillingOrder(accountId, memberId, reservation)).orderId, orderId)

  const conflicting = store({ query: async () => ({ rows: [{ ...order(), request_hash: '0'.repeat(64) }] }) })
  await assert.rejects(conflicting.reserveBillingOrder(accountId, memberId, reservation),
    error => error?.code === 'conflict')
})

test('checkout attachment never regresses a webhook-confirmed order', async () => {
  const paidAt = new Date('2026-09-18T00:01:00.000Z')
  const checkoutExpiresAt = new Date('2026-09-18T01:00:00.000Z')
  const statements = []
  const value = store({
    async query(statement) {
      statements.push(statement)
      if (statements.length === 1) return { rows: [order({ state: 'paid', paid_at: paidAt })] }
      assert.match(statement, /case when state = 'creating' then 'checkout-pending' else state end/u)
      return { rows: [order({ state: 'paid', paid_at: paidAt, provider_checkout_id: 'cs_test_1',
        checkout_expires_at: checkoutExpiresAt })] }
    },
  })
  const result = await value.attachBillingCheckout({
    organizationId, orderId, provider: 'stripe', providerCheckoutId: 'cs_test_1',
    expiresAt: checkoutExpiresAt.getTime(),
  })
  assert.equal(result.state, 'paid')
  assert.equal(result.providerCheckoutId, 'cs_test_1')
})

test('checkout-paid never clears a dispute and the ignored verified event remains durable', async () => {
  const harness = billingEventHarness({
    state: 'disputed',
    paid_at: new Date('2026-09-18T00:03:00.000Z'),
    disputed_at: new Date('2026-09-18T00:03:00.000Z'),
    last_event_at: new Date('2026-09-18T00:03:00.000Z'),
  })
  const result = await harness.store.applyVerifiedBillingEvent(providerEvent(
    'evt_ignored_paid', 'checkout-paid', new Date('2026-09-18T00:01:00.000Z').getTime()))
  assert.equal(result.state, 'disputed')
  assert.equal(result.paidAt, new Date('2026-09-18T00:01:00.000Z').getTime())
  assert.equal(result.lastEventAt, new Date('2026-09-18T00:03:00.000Z').getTime())
  assert.equal(harness.events.size, 1)
  assert.equal(harness.updates(), 1)
  assert.equal(harness.statements.some(statement => /insert into "registry"\.billing_provider_events/u.test(statement)), true)
})

test('same-time refund and dispute events converge to refunded in either delivery order', async () => {
  const occurredAt = new Date('2026-09-18T00:05:00.000Z').getTime()
  const project = async (eventTypes) => {
    const harness = billingEventHarness({
      state: 'paid',
      paid_at: new Date('2026-09-18T00:01:00.000Z'),
      last_event_at: new Date('2026-09-18T00:01:00.000Z'),
    })
    let result
    for (const [index, eventType] of eventTypes.entries()) {
      result = await harness.store.applyVerifiedBillingEvent(
        providerEvent(`evt_${eventType}_${index}`, eventType, occurredAt))
    }
    return { harness, result }
  }

  const disputeThenRefund = await project(['disputed', 'refunded'])
  const refundThenDispute = await project(['refunded', 'disputed'])
  const projection = result => ({
    state: result.state,
    paidAt: result.paidAt,
    disputedAt: result.disputedAt,
    refundedAt: result.refundedAt,
    lastEventAt: result.lastEventAt,
  })
  assert.deepEqual(projection(disputeThenRefund.result), projection(refundThenDispute.result))
  assert.deepEqual(projection(disputeThenRefund.result), {
    state: 'refunded',
    paidAt: new Date('2026-09-18T00:01:00.000Z').getTime(),
    disputedAt: occurredAt,
    refundedAt: occurredAt,
    lastEventAt: occurredAt,
  })
  assert.equal(disputeThenRefund.harness.events.size, 2)
  assert.equal(refundThenDispute.harness.events.size, 2)
  assert.equal(disputeThenRefund.harness.updates(), 2)
  assert.equal(refundThenDispute.harness.updates(), 2)
})

test('billing order listing rechecks Owner membership and stays hard bounded', async () => {
  let orderQuery
  const value = store({
    async query(statement, values) {
      orderQuery = { statement, values }
      return { rows: [order()] }
    },
  })
  assert.equal((await value.listBillingOrders(accountId, memberId, organizationId)).length, 1)
  assert.match(orderQuery.statement, /order by created_at desc, order_id desc limit \$2/u)
  assert.deepEqual(orderQuery.values, [organizationId, 100])

  value.requireActiveMembership = async () => ({ role: 'member', state: 'active' })
  await assert.rejects(value.listBillingOrders(accountId, memberId, organizationId),
    error => error?.code === 'not-found')
})
