import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { request } from 'node:http'
import test from 'node:test'

import { Context } from '@deepseek-ai/cordis'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import { RegistryBillingProvider } from '@deepseek-ai/dsh-registry-app'
import { installRegistryBrowserApi } from '@deepseek-ai/dsh-registry-app/src/browser-api.ts'

const organizationId = 'webhook-tenant'
const orderId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const occurredAt = Date.parse('2026-09-18T08:00:00.000Z')
const event = { organizationId, orderId, eventId: 'evt_webhook_1', eventType: 'checkout-paid', occurredAt }

class MemoryBillingProvider extends RegistryBillingProvider {
  calls = []

  constructor(ctx, provider, verify) {
    super(ctx)
    this.provider = provider
    this.verify = verify
  }

  listPlans() { return Promise.resolve([]) }
  createCheckout() { return Promise.reject(new Error('not used')) }

  verifyWebhook(input, signal) {
    this.calls.push({ input, signal })
    return Promise.resolve(this.verify(input, signal))
  }
}

function verifiedEvent(selectedEvent = event) {
  return selectedEvent
}

async function call(url, { method = 'POST', body = Buffer.alloc(0), headers = {} } = {}) {
  const target = new URL(url)
  return new Promise((resolve, reject) => {
    const selectedHeaders = { ...headers }
    if (body.byteLength > 0 && !Object.keys(selectedHeaders).some(name => name.toLowerCase() === 'content-length')) {
      selectedHeaders['content-length'] = String(body.byteLength)
    }
    const outgoing = request({
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method,
      headers: selectedHeaders,
    }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(Buffer.from(chunk)))
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }))
    })
    outgoing.once('error', reject)
    outgoing.end(body)
  })
}

async function openWebhook({ verify = () => verifiedEvent(), apply, enabled = true, maxBytes = 64,
  providerName = 'stripe', directCapacity = 100 } = {}) {
  const ctx = new Context()
  let stopApi
  try {
    await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0, compression: 'none' })
    const provider = new MemoryBillingProvider(ctx, providerName, verify)
    const applied = []
    ctx.provide('registryTenantRouter', {
      tenancy: {
        async applyVerifiedBillingEvent(selected) {
          applied.push(structuredClone(selected))
          if (apply !== undefined) return apply(selected)
          return { orderId: selected.orderId }
        },
      },
    })
    stopApi = installRegistryBrowserApi(ctx, {
      pageSize: 20,
      maxValueBytes: 4096,
      maxCursorBytes: 256,
      maxOperationInputBytes: 4096,
      maxBillingWebhookBytes: maxBytes,
      admission: {
        directPeer: { capacity: directCapacity, refillPerSecond: 1, maxEntries: 8 },
        account: { capacity: 100, refillPerSecond: 100, maxEntries: 8 },
      },
    }, {
      deploymentMode: 'standard',
      identityProvider: 'external',
      disclosureCleanup: false,
      mailboxCleanup: false,
      billingProvider: enabled,
    })
    const base = `http://127.0.0.1:${ctx.webServer.port}/registry-api/v1`
    return {
      applied,
      base,
      provider,
      stop: async () => {
        stopApi?.()
        await ctx.fiber.dispose()
      },
    }
  } catch (error) {
    stopApi?.()
    await ctx.fiber.dispose()
    throw error
  }
}

test('verified webhook preserves raw bytes and duplicate headers, commits before a retry-safe acknowledgement', async () => {
  const rawBody = Buffer.from([0, 255, 12, 34, 128, 10])
  const durable = new Map()
  const runtime = await openWebhook({
    verify(input, signal) {
      assert.deepEqual(Buffer.from(input.rawBody), rawBody)
      assert.deepEqual(input.headers['x-provider-signature'], ['first', 'second'])
      assert.ok(Object.isFrozen(input.headers))
      assert.ok(Object.isFrozen(input.headers['x-provider-signature']))
      assert.ok(signal instanceof AbortSignal)
      assert.equal(signal.aborted, false)
      return verifiedEvent()
    },
    apply(selected) {
      const key = `${selected.provider}\0${selected.eventId}`
      const retained = durable.get(key)
      if (retained === undefined) durable.set(key, structuredClone(selected))
      else assert.deepEqual(selected, retained)
      return { orderId: selected.orderId }
    },
  })
  try {
    const options = { body: rawBody, headers: { 'X-Provider-Signature': ['first', 'second'] } }
    const first = await call(`${runtime.base}/billing/webhooks/stripe`, options)
    const retried = await call(`${runtime.base}/billing/webhooks/stripe`, options)
    assert.equal(first.status, 204)
    assert.equal(first.body.byteLength, 0)
    assert.equal(first.headers['content-type'], undefined)
    assert.equal(retried.status, 204)
    assert.equal(runtime.provider.calls.length, 2)
    assert.equal(runtime.applied.length, 2)
    assert.equal(durable.size, 1)
    const stored = runtime.applied[0]
    assert.equal(stored.provider, 'stripe')
    assert.equal(stored.payloadHash, createHash('sha256').update(rawBody).digest('hex'))

    assert.equal((await call(`${runtime.base}/billing/webhooks/stripe`, { method: 'GET' })).status, 405)
    assert.equal((await call(`${runtime.base}/billing/webhooks/stripe?unexpected=1`, { body: rawBody })).status, 400)
    assert.equal(runtime.provider.calls.length, 2)
  } finally { await runtime.stop() }
})

test('failed provider verification never reaches tenancy', async () => {
  const runtime = await openWebhook({ verify: () => null })
  try {
    const response = await call(`${runtime.base}/billing/webhooks/stripe`, { body: Buffer.from('bad-signature') })
    assert.equal(response.status, 400)
    assert.equal(runtime.provider.calls.length, 1)
    assert.equal(runtime.applied.length, 0)
  } finally { await runtime.stop() }
})

test('oversized webhook bodies are rejected before provider verification', async () => {
  const runtime = await openWebhook({ maxBytes: 8 })
  try {
    const response = await call(`${runtime.base}/billing/webhooks/stripe`, { body: Buffer.alloc(9, 1) })
    assert.equal(response.status, 400)
    assert.equal(runtime.provider.calls.length, 0)
    assert.equal(runtime.applied.length, 0)
  } finally { await runtime.stop() }
})

test('Registry acknowledgement is withheld when the billing transaction fails', async () => {
  const runtime = await openWebhook({ apply: () => { throw new Error('database unavailable') } })
  try {
    const response = await call(`${runtime.base}/billing/webhooks/stripe`, { body: Buffer.from('signed') })
    assert.equal(response.status, 503)
    assert.notEqual(response.body.toString('utf8'), 'success')
    assert.equal(runtime.applied.length, 1)
  } finally { await runtime.stop() }
})

test('explicit SaaS enablement controls status and rejects a mismatched provider path', async () => {
  const disabled = await openWebhook({ enabled: false })
  try {
    const status = await call(`${disabled.base}/status`, { method: 'GET' })
    assert.equal(status.status, 200)
    assert.equal(JSON.parse(status.body.toString('utf8')).value.billing, 'unconfigured')
    assert.equal((await call(`${disabled.base}/billing/webhooks/stripe`, { body: Buffer.from('signed') })).status, 501)
    assert.equal(disabled.provider.calls.length, 0)
  } finally { await disabled.stop() }

  const enabled = await openWebhook()
  try {
    assert.equal((await call(`${enabled.base}/billing/webhooks/alipay`, { body: Buffer.from('signed') })).status, 404)
    assert.equal(enabled.provider.calls.length, 0)
  } finally { await enabled.stop() }

  const limited = await openWebhook({ directCapacity: 2 })
  try {
    assert.equal((await call(`${limited.base}/billing/webhooks/stripe?bad=1`, { body: Buffer.from('signed') })).status,
      400)
    assert.equal((await call(`${limited.base}/billing/webhooks/stripe`, { method: 'GET' })).status, 405)
    assert.equal((await call(`${limited.base}/billing/webhooks/stripe`, { body: Buffer.from('signed') })).status, 429)
    assert.equal(limited.provider.calls.length, 0)
  } finally { await limited.stop() }

  const alipay = await openWebhook({ providerName: 'alipay' })
  try {
    const response = await call(`${alipay.base}/billing/webhooks/alipay`, { body: Buffer.from('signed') })
    assert.equal(response.status, 200)
    assert.equal(response.headers['content-type'], 'text/plain; charset=utf-8')
    assert.equal(response.body.toString('utf8'), 'success')
  } finally { await alipay.stop() }

  const context = new Context()
  try {
    assert.throws(() => installRegistryBrowserApi(context, {
      pageSize: 20,
      maxValueBytes: 4096,
      maxCursorBytes: 256,
      maxOperationInputBytes: 4096,
      maxBillingWebhookBytes: 64,
    }, {
      deploymentMode: 'standard',
      identityProvider: 'external',
      disclosureCleanup: false,
      mailboxCleanup: false,
      billingProvider: true,
    }), /billing webhook requires direct-peer admission/u)
  } finally { await context.fiber.dispose() }
})
