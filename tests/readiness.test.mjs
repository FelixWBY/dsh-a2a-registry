import test from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { RegistryReadinessProbe } from '../packages/bundle/registry-app/src/readiness.ts'
import { installRegistryStatic } from '../packages/bundle/registry-app/src/static.ts'
import { PostgresRegistryTenancy } from '../packages/bundle/registry-app/src/tenancy-postgres.ts'
import { DomainFacility } from '../packages/storage/storage-domain/src/index.ts'
import { PostgresStorageBackend, STORAGE_POSTGRES_SCHEMA_VERSION } from '../packages/storage/storage-postgres/src/index.ts'

test('readiness probe coalesces callers, caches briefly, and observes recovery', async () => {
  let now = 0
  let calls = 0
  let available = true
  let release
  let hold = true
  const probe = new RegistryReadinessProbe(() => {
    calls += 1
    if (!hold) return available
    return new Promise(resolve => { release = resolve })
  }, { cacheTtlMs: 100, timeoutMs: 1_000, now: () => now })

  const initial = Array.from({ length: 100 }, () => probe.ready())
  await Promise.resolve()
  assert.equal(calls, 1)
  hold = false
  release(true)
  assert.deepEqual(await Promise.all(initial), Array(100).fill(true))
  assert.equal(await probe.ready(), true)
  assert.equal(calls, 1)

  now += 100
  available = false
  assert.equal(await probe.ready(), false)
  assert.equal(calls, 2)
  available = true
  assert.equal(await probe.ready(), false)
  assert.equal(calls, 2)

  now += 100
  assert.equal(await probe.ready(), true)
  assert.equal(calls, 3)
})

test('timed-out readiness keeps one dependency probe in flight', async () => {
  let now = 0
  let calls = 0
  let release
  const probe = new RegistryReadinessProbe(() => {
    calls += 1
    return new Promise(resolve => { release = resolve })
  }, { cacheTtlMs: 10, timeoutMs: 20, now: () => now })

  assert.deepEqual(await Promise.all(Array.from({ length: 50 }, () => probe.ready())), Array(50).fill(false))
  assert.equal(calls, 1)
  now += 10
  assert.deepEqual(await Promise.all(Array.from({ length: 50 }, () => probe.ready())), Array(50).fill(false))
  assert.equal(calls, 1)

  release(true)
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(await probe.ready(), true)
  assert.equal(calls, 1)
})

test('PostgreSQL tenancy readiness requires both authoritative schema markers', async () => {
  const store = Object.create(PostgresRegistryTenancy.prototype)
  store.closed = false
  store.schema = '"registry"'
  let rows = [{ storage_version: 2, tenancy_version: 2 }]
  let queries = 0
  store.pool = { query: async (query) => {
    queries += 1
    assert.match(query.text, /storage_meta/u)
    assert.match(query.text, /tenancy_meta/u)
    assert.equal(query.query_timeout, 1_500)
    return { rows }
  } }

  assert.equal(await store.checkReadiness(), true)
  rows = [{ storage_version: 1, tenancy_version: 2 }]
  assert.equal(await store.checkReadiness(), false)
  store.pool.query = async () => { throw new Error('database unavailable') }
  assert.equal(await store.checkReadiness(), false)
  store.closed = true
  assert.equal(await store.checkReadiness(), false)
  assert.equal(queries, 2)
})

test('SaaS domain readiness probes the selected PostgreSQL storage pool', async () => {
  const backend = Object.create(PostgresStorageBackend.prototype)
  backend.closing = undefined
  backend.ready = Promise.resolve()
  backend.schema = '"registry"'
  backend.pool = { query: async (query) => {
    assert.match(query.text, /storage_meta/u)
    assert.equal(query.query_timeout, 1_500)
    return { rows: [{ schema_version: STORAGE_POSTGRES_SCHEMA_VERSION }] }
  } }
  assert.equal(await backend.checkReadiness(), true)

  const facility = new DomainFacility({ storage: { backend: { get: name => {
    assert.equal(name, 'postgres')
    return backend
  } } } }, { backend: 'postgres', routes: {} })
  assert.equal(await facility.checkReadiness('postgres'), true)

  const misrouted = new DomainFacility({ storage: { backend: { get: () => backend } } },
    { backend: 'postgres', routes: { unsafe: 'sqlite' } })
  assert.equal(await misrouted.checkReadiness('postgres'), false)
})

test('health remains live while readiness follows the bounded runtime check', async () => {
  const routes = new Map()
  const ctx = {
    webServer: {
      register: (route) => { routes.set(route.path, route.handler); return () => {} },
      registerFallback: () => () => {},
      renderIndex: value => value,
    },
    effect: register => register(),
  }
  let runtimeReady = false
  installRegistryStatic(ctx, fileURLToPath(new URL('../package.json', import.meta.url)),
    () => true, () => runtimeReady)

  const request = { method: 'GET' }
  const invoke = async (path) => {
    const response = {
      status: 0,
      body: '',
      setHeader: () => {},
      writeHead(status) { this.status = status },
      end(value = '') { this.body = value },
    }
    await routes.get(path)(request, response)
    return response
  }

  assert.equal((await invoke('/healthz')).status, 200)
  assert.equal((await invoke('/readyz')).status, 503)
  runtimeReady = true
  assert.equal((await invoke('/readyz')).status, 200)
  runtimeReady = false
  assert.equal((await invoke('/healthz')).status, 200)
  assert.equal((await invoke('/readyz')).status, 503)
})
