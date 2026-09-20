import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createConnection } from 'node:net'
import { Context } from '@deepseek-ai/cordis'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import { encodeRegistryBridgeToken, encodeRegistryDeviceToken, generateRegistryBridgeSecret,
  generateRegistryDeviceSecret, hashRegistryBridgeSecret,
  hashRegistryDeviceSecret } from '@deepseek-ai/dsh-a2a-device-identity'
import { RegistryIngestError } from '@deepseek-ai/dsh-a2a-registry-ingest'
import { RegistryDisclosureKeyProvider } from '@deepseek-ai/dsh-registry-app/src/disclosure-key-provider.ts'
import { Config as RegistryAppConfig } from '@deepseek-ai/dsh-registry-app/src/index.ts'
import { REGISTRY_PRODUCTION_DISCLOSURE_BRIDGE_PATH,
  RegistryProductionDisclosureBridge } from '@deepseek-ai/dsh-registry-app/src/production-disclosure-bridge.ts'
import { RegistryTenancyError } from '@deepseek-ai/dsh-registry-app/src/tenancy.ts'

const organizationId = 'bridge-organization'
const instanceId = 'bridge-instance'
const memberId = 'bridge-member'
const bindingId = randomUUID()
const keyId = 'bridge-key'
const tokenSecret = generateRegistryBridgeSecret()
const token = encodeRegistryBridgeToken({ organizationId, bindingId, secret: tokenSecret })
const expectedHash = hashRegistryBridgeSecret(tokenSecret)
const expectedSameRawDeviceHash = hashRegistryDeviceSecret(tokenSecret)

const baseConfig = Object.freeze({
  requestTimeoutMs: 5_000,
  maxConcurrentRequests: 8,
  maxRequestBytes: 4_096,
  maxResponseBytes: 8_192,
  maxDirectoryBytes: 8_192,
  maxAudienceEntries: 10,
  maxDisplayNameCharacters: 100,
  maxActivePublications: 5,
  maxPreviewBytes: 1_024,
  maxTargets: 5,
  maxPublicationLifetimeMs: 60_000,
})

class MemoryKeyProvider extends RegistryDisclosureKeyProvider {
  protection = Object.freeze({ assurance: 'software-local', hsmBacked: false, hardwareAttested: false,
    endToEnd: false, rootKeyPersistence: 'external-runtime-secret', keysExportableInProcess: true,
    singleWriterRequired: true })
  readiness = []
  publications = []

  constructor(ctx, options) {
    super(ctx)
    this.options = options
  }

  async checkReadiness(selectedOrganizationId, signal) {
    assert.equal(signal.aborted, false)
    this.readiness.push(selectedOrganizationId)
    this.options.onReadiness?.()
    if (this.options.readinessGate !== undefined) await this.options.readinessGate
    return selectedOrganizationId === organizationId
  }

  async publishDataKey(scope, dataKey, signal) {
    assert.equal(signal.aborted, false)
    this.options.onPublication?.()
    if (this.options.publicationGate !== undefined) await this.options.publicationGate
    const exported = dataKey.key.export()
    this.publications.push({ scope: structuredClone(scope), keyId: dataKey.keyId,
      material: Buffer.from(exported) })
    return { scope: structuredClone(scope), keyId: dataKey.keyId, assurance: 'software-local' }
  }

  readDataKeys() { return Promise.reject(new Error('bridge never reads keys')) }
}

function producer() {
  const instanceKeyId = `sha256:${'a'.repeat(64)}`
  return {
    connection: { organizationId, instanceId, keyId: instanceKeyId, now: Date.now() },
    history: { organizationId, instanceId, status: 'active', keys: [{ keyId: instanceKeyId,
      publicKeySpki: Buffer.alloc(44).toString('base64url'), validFrom: 0, validUntil: null, revokedAt: null }] },
  }
}

async function openBridge(options = {}) {
  const ctx = new Context()
  const controller = new AbortController()
  let releases = 0
  let authentications = 0
  let acquisitions = 0
  const authenticationGate = options.authenticationGate
  const acquisitionGate = options.acquisitionGate
  const directoryGate = options.directoryGate
  try {
    await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0, compression: 'none' })
    const store = {
      subscribeInvalidation() { return () => {} },
      async authenticateBridgeCredential(selectedBindingId, presentedHash, sameRawDeviceHash) {
        authentications += 1
        options.onAuthentication?.()
        const selectedGate = typeof authenticationGate === 'function'
          ? authenticationGate(authentications) : authenticationGate
        if (selectedGate !== undefined) await selectedGate
        if (selectedBindingId !== bindingId || presentedHash !== expectedHash
          || sameRawDeviceHash !== expectedSameRawDeviceHash) throw new RegistryIngestError('not-found')
        return { bindingId, organizationId, instanceId, memberId, producer: producer() }
      },
    }
    const directory = {
      async read(authority, scope, maxBytes) {
        options.onDirectory?.()
        if (directoryGate !== undefined) await directoryGate
        assert.equal(scope, 'audience')
        assert.equal(maxBytes, (options.config ?? baseConfig).maxDirectoryBytes)
        const current = await authority()
        assert.deepEqual(current.subject, { authenticated: true, organizationId, memberId })
        return { revision: 1, members: [{ memberId, displayName: '成员一', role: 'member', state: 'active' }],
          teams: [{ teamId: 'team-one', displayName: '研发组', memberIds: [memberId] }] }
      },
    }
    const runtime = { organizationId, store, directory, signal: controller.signal }
    const router = {
      async acquireRuntime(selectedOrganizationId) {
        acquisitions += 1
        options.onAcquisition?.()
        if (selectedOrganizationId !== organizationId) throw new RegistryTenancyError('not-found')
        if (options.acquisitionError !== undefined) throw options.acquisitionError
        const selectedGate = typeof acquisitionGate === 'function'
          ? acquisitionGate(acquisitions) : acquisitionGate
        if (selectedGate !== undefined) await selectedGate
        return { runtime, release() { releases += 1 } }
      },
    }
    const provider = new MemoryKeyProvider(ctx, options)
    const bridge = new RegistryProductionDisclosureBridge(router, provider, options.config ?? baseConfig,
      route => ctx.webServer.register(route))
    let bridgeClosed = false
    const closeBridge = async () => {
      if (bridgeClosed) return
      bridgeClosed = true
      await bridge.close()
    }
    return {
      provider,
      url: `http://127.0.0.1:${ctx.webServer.port}${REGISTRY_PRODUCTION_DISCLOSURE_BRIDGE_PATH}`,
      acquisitions: () => acquisitions,
      authentications: () => authentications,
      releases: () => releases,
      closeBridge,
      stop: async () => {
        await closeBridge()
        controller.abort()
        await ctx.fiber.dispose()
      },
    }
  } catch (error) {
    controller.abort()
    await ctx.fiber.dispose()
    throw error
  }
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((settle, fail) => { resolve = settle; reject = fail })
  return { promise, resolve, reject }
}

async function rawIncompleteRequest(runtime, request) {
  const target = new URL(runtime.url)
  return await new Promise((resolve, reject) => {
    const socket = createConnection({ host: target.hostname, port: Number(target.port) })
    const chunks = []
    let settled = false
    const timeout = setTimeout(() => {
      socket.destroy()
      reject(new Error('server did not close rejected incomplete request'))
    }, 2_000)
    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      resolve(Buffer.concat(chunks).toString('utf8'))
    }
    socket.once('connect', () => { socket.write(request) })
    socket.on('data', chunk => { chunks.push(Buffer.from(chunk)) })
    socket.once('end', finish)
    socket.once('close', finish)
    socket.once('error', reject)
  })
}

function incompleteRequest(runtime, { method = 'POST', path, authorization = token,
  contentType = 'application/json', framing = 'Transfer-Encoding: chunked', body = '8\r\n{"versio\r\n' } = {}) {
  const target = new URL(runtime.url)
  return `${method} ${path ?? target.pathname} HTTP/1.1\r\nHost: ${target.host}\r\n`
    + (authorization === null ? '' : `Authorization: Bearer ${authorization}\r\n`)
    + (contentType === null ? '' : `Content-Type: ${contentType}\r\n`)
    + `${framing}\r\nConnection: keep-alive\r\n\r\n${body}`
}

test('Registry config requires the explicit tenant key-provider gate before enabling the bridge', () => {
  assert.throws(() => RegistryAppConfig({
    printUrl: false,
    api: { pageSize: 10, maxValueBytes: 4_096, maxCursorBytes: 1_024,
      maxOperationInputBytes: 4_096, maxBillingWebhookBytes: 4_096 },
    oidc: { mode: 'production', issuer: 'https://identity.example.test/', clientId: 'registry',
      clientSecretEnv: 'OIDC_SECRET', sessionSecretEnv: 'SESSION_SECRET',
      publicOrigin: 'https://registry.example.test/', organizationId, memberIdClaim: 'member_id',
      scopes: 'openid', sessionValidation: 'introspection', maxActiveSessions: 10,
      maxSessionsPerSubject: 2, sessionTtlMs: 60_000, transactionTtlMs: 30_000,
      maxAuthenticationAgeSeconds: 60, clockToleranceSeconds: 5, requestTimeoutMs: 1_000,
      maxCookieBytes: 4_096, maxDirectoryBytes: 8_192 },
    saas: { databaseUrlEnv: 'POSTGRES_URL', disclosureContentProvider: false,
      disclosureKeyProvider: false, billingProvider: false, schema: 'registry', schemaMode: 'validate',
      allowUnsafeSharedDatabase: false, legacyOrganizationName: 'Legacy organization', maxConnections: 2,
      maxOrganizationsPerAccount: 5, maxActiveOrganizations: 10, idleTimeoutMs: 5_000,
      statementTimeoutMs: 5_000 },
    productionDisclosureBridge: baseConfig,
    ingest: { organizationId, limits: { maxInputBytes: 4_096, maxAggregateBytes: 65_536,
      maxEvents: 10, maxCheckpoints: 10, maxDisclosures: 10, maxAuditEntries: 100 },
    directory: { maxMembers: 10, maxTeams: 10, maxTeamMembers: 10, maxNameBytes: 256,
      maxBytes: 65_536, bootstrapOwner: { memberId, displayName: 'Owner' } },
    bindings: { audience: 'wss://registry.example.test/a2a/v1/sync', ttlMs: 60_000,
      maxRecordBytes: 8_192, maxBindings: 10, maxNameBytes: 256 } },
  }), /requires SaaS directory, bindings and disclosure key provider/u)
})

function envelope(operation, extra = {}) {
  return { version: 1, operation, organizationId, instanceId, ...extra }
}

async function post(runtime, body, selectedToken = token) {
  return fetch(runtime.url, { method: 'POST', redirect: 'error', headers: {
    authorization: `Bearer ${selectedToken}`,
    'content-type': 'application/json; charset=utf-8',
  }, body: typeof body === 'string' ? body : JSON.stringify(body) })
}

test('production disclosure bridge matches all four Harness operations with fresh V6 binding authority', async () => {
  const runtime = await openBridge()
  try {
    const authority = await post(runtime, envelope('authority.read'))
    assert.equal(authority.status, 200)
    assert.equal(authority.headers.get('cache-control'), 'no-store')
    assert.equal(authority.headers.get('content-type'), 'application/json; charset=utf-8')
    assert.deepEqual(await authority.json(), { version: 1, status: 'ready', audience: [
      { target: { kind: 'member', memberId }, displayName: '成员一' },
      { target: { kind: 'team', teamId: 'team-one' }, displayName: '研发组' },
    ] })

    const capacity = await post(runtime, envelope('authority.capacity', { request: {
      phase: 'commit', activePublications: 1, previewBytes: 128, targetCount: 2,
      expiresAt: Date.now() + 30_000,
    } }))
    assert.deepEqual(await capacity.json(), { version: 1, status: 'available' })

    const fullCommit = await post(runtime, envelope('authority.capacity', { request: {
      phase: 'commit', activePublications: baseConfig.maxActivePublications,
      previewBytes: 128, targetCount: 2, expiresAt: Date.now() + 30_000,
    } }))
    assert.deepEqual(await fullCommit.json(), { version: 1, status: 'available' })

    const fullPrepare = await post(runtime, envelope('authority.capacity', { request: {
      phase: 'prepare', activePublications: baseConfig.maxActivePublications,
      previewBytes: 128, targetCount: 2, expiresAt: Date.now() + 30_000,
    } }))
    assert.deepEqual(await fullPrepare.json(), { version: 1, status: 'exhausted' })

    const readiness = await post(runtime, envelope('keys.readiness'))
    assert.deepEqual(await readiness.json(), { version: 1, status: 'ready' })
    assert.deepEqual(runtime.provider.readiness, [organizationId])

    const material = Buffer.alloc(32, 0x5a)
    const scope = { organizationId, instanceId, conversationId: 'conversation-one', disclosureId: 'disclosure-one' }
    const provision = await post(runtime, envelope('keys.provision', { scope,
      key: { keyId, material: material.toString('base64url') } }))
    assert.deepEqual(await provision.json(), { version: 1, status: 'provisioned', scope, keyId })
    assert.equal(runtime.provider.publications.length, 1)
    assert.deepEqual(runtime.provider.publications[0].scope, scope)
    assert.equal(runtime.provider.publications[0].keyId, keyId)
    assert.equal(runtime.provider.publications[0].material.equals(material), true)
    assert.equal(runtime.acquisitions(), 6)
    assert.equal(runtime.authentications(), 6)
    assert.equal(runtime.releases(), 6)
  } finally { await runtime.stop() }
})

test('bridge rejects cross-tenant, duplicate-member, oversized and invalid bearer requests without provider access', async () => {
  const runtime = await openBridge()
  try {
    const queryTarget = await fetch(`${runtime.url}?operation=keys.readiness`, { method: 'POST',
      redirect: 'error', headers: { authorization: `Bearer ${token}`,
        'content-type': 'application/json' }, body: JSON.stringify(envelope('keys.readiness')) })
    assert.equal(queryTarget.status, 400)
    assert.equal(runtime.acquisitions(), 0)

    const deviceToken = encodeRegistryDeviceToken({ organizationId, bindingId,
      secret: generateRegistryDeviceSecret() })
    const wrongCredentialClass = await post(runtime, envelope('keys.readiness'), deviceToken)
    assert.equal(wrongCredentialClass.status, 401)
    assert.equal(runtime.acquisitions(), 0)

    const otherSecret = generateRegistryBridgeSecret()
    const wrongToken = encodeRegistryBridgeToken({ organizationId, bindingId, secret: otherSecret })
    const unauthorized = await post(runtime, envelope('keys.readiness'), wrongToken)
    assert.equal(unauthorized.status, 403)

    const foreignSelector = encodeRegistryBridgeToken({ organizationId: 'other-tenant', bindingId,
      secret: tokenSecret })
    const wrongTenant = await post(runtime, { ...envelope('keys.readiness'), organizationId: 'other-tenant' },
      foreignSelector)
    assert.equal(wrongTenant.status, 403)

    const crossTenant = await post(runtime, { ...envelope('keys.readiness'), organizationId: 'other-tenant' })
    assert.equal(crossTenant.status, 403)

    const duplicate = `{"version":1,"operation":"authority.capacity","organizationId":"${organizationId}",`
      + `"instanceId":"${instanceId}","request":{"phase":"prepare","phase":"commit",`
      + '"activePublications":0,"previewBytes":1,"targetCount":1,"expiresAt":9999999999999}}'
    const ambiguous = await post(runtime, duplicate)
    assert.equal(ambiguous.status, 400)

    const surplus = await post(runtime, { ...envelope('keys.readiness'), extra: true })
    assert.equal(surplus.status, 400)

    const oversized = await post(runtime, `${JSON.stringify(envelope('keys.readiness')).slice(0, -1)},`
      + `"padding":"${'x'.repeat(baseConfig.maxRequestBytes)}"}`)
    assert.equal(oversized.status, 413)
    assert.deepEqual(runtime.provider.readiness, [])
    assert.equal(runtime.releases(), 5)
  } finally { await runtime.stop() }
})

test('bridge closes sockets after rejecting request bodies it did not completely consume', async (t) => {
  const runtime = await openBridge()
  try {
    const cases = [
      { name: 'path', status: 400, request: incompleteRequest(runtime,
        { path: `${new URL(runtime.url).pathname}?unexpected=1` }) },
      { name: 'method', status: 405, request: incompleteRequest(runtime, { method: 'PUT' }) },
      { name: 'authorization', status: 401, request: incompleteRequest(runtime, { authorization: null }) },
      { name: 'content type', status: 400, request: incompleteRequest(runtime, { contentType: 'text/plain' }) },
      { name: 'declared length', status: 413, request: incompleteRequest(runtime,
        { framing: `Content-Length: ${baseConfig.maxRequestBytes + 1}`, body: '' }) },
      { name: 'streamed overflow', status: 413, request: incompleteRequest(runtime, {
        body: `${(baseConfig.maxRequestBytes + 1).toString(16)}\r\n`
          + `${'x'.repeat(baseConfig.maxRequestBytes + 1)}\r\n`,
      }) },
    ]
    for (const selected of cases) {
      await t.test(selected.name, async () => {
        const response = await rawIncompleteRequest(runtime, selected.request)
        assert.match(response, new RegExp(`^HTTP/1\\.1 ${selected.status} `, 'u'))
        assert.match(response, /\r\nconnection: close\r\n/iu)
      })
    }
  } finally { await runtime.stop() }
})

test('tenant acquisition maps only an explicit tenancy not-found error to forbidden', async (t) => {
  const cases = [
    { name: 'not found', error: new RegistryTenancyError('not-found'), status: 403 },
    { name: 'tenant unavailable', error: new RegistryTenancyError('unavailable'), status: 503 },
    { name: 'unexpected router failure', error: new Error('router failed'), status: 503 },
  ]
  for (const selected of cases) {
    await t.test(selected.name, async () => {
      const runtime = await openBridge({ acquisitionError: selected.error })
      try {
        const response = await post(runtime, envelope('keys.readiness'))
        assert.equal(response.status, selected.status)
      } finally { await runtime.stop() }
    })
  }
})

test('bridge enforces the global in-flight request bound before tenant work', async () => {
  let releaseAuthentication
  const authenticationGate = new Promise(resolve => { releaseAuthentication = resolve })
  let started
  const authenticationStarted = new Promise(resolve => { started = resolve })
  const runtime = await openBridge({ config: { ...baseConfig, maxConcurrentRequests: 1 }, authenticationGate,
    onAuthentication: () => { started() } })
  try {
    const first = post(runtime, envelope('keys.readiness'))
    await authenticationStarted
    const refused = await post(runtime, envelope('keys.readiness'))
    assert.equal(refused.status, 503)
    assert.deepEqual(await refused.json(), { version: 1, status: 'unavailable' })
    const incomplete = await rawIncompleteRequest(runtime, incompleteRequest(runtime))
    assert.match(incomplete, /^HTTP\/1\.1 503 /u)
    assert.match(incomplete, /\r\nconnection: close\r\n/iu)
    assert.equal(runtime.authentications(), 1)
    assert.equal(runtime.acquisitions(), 1)
    releaseAuthentication()
    assert.equal((await first).status, 200)
  } finally {
    releaseAuthentication?.()
    await runtime.stop()
  }
})

test('timed-out dependencies retain admission until late settlement without blocking close', async () => {
  const lateAuthentication = deferred()
  const runtime = await openBridge({ config: { ...baseConfig, requestTimeoutMs: 50,
    maxConcurrentRequests: 1 },
  authenticationGate: call => call === 1 ? lateAuthentication.promise : undefined })
  try {
    const first = await post(runtime, envelope('keys.readiness'))
    assert.equal(first.status, 503)
    assert.equal(runtime.authentications(), 1)

    const quarantined = await post(runtime, envelope('keys.readiness'))
    assert.equal(quarantined.status, 503)
    assert.equal(runtime.authentications(), 1)

    lateAuthentication.reject(new Error('late authentication failure'))
    await new Promise(resolve => setImmediate(resolve))
    const recovered = await post(runtime, envelope('keys.readiness'))
    assert.equal(recovered.status, 200)
    assert.equal(runtime.authentications(), 2)
  } finally {
    lateAuthentication.resolve()
    await runtime.stop()
  }

  const began = deferred()
  const never = new Promise(() => {})
  const closing = await openBridge({ config: { ...baseConfig, requestTimeoutMs: 50,
    maxConcurrentRequests: 1 }, authenticationGate: never, onAuthentication: began.resolve })
  try {
    const request = post(closing, envelope('keys.readiness'))
    await began.promise
    assert.equal((await request).status, 503)
    let timeout
    await Promise.race([
      closing.closeBridge(),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(
        new Error('bridge close waited for a quarantined dependency')), 500) }),
    ]).finally(() => { clearTimeout(timeout) })
  } finally { await closing.stop() }
})

test('bridge deadline bounds every non-cooperative dependency and releases each acquired lease', async (t) => {
  const cases = [
    { name: 'binding authentication', gate: 'authenticationGate', started: 'onAuthentication' },
    { name: 'directory read', gate: 'directoryGate', started: 'onDirectory', operation: 'authority.read' },
    { name: 'key-provider readiness', gate: 'readinessGate', started: 'onReadiness' },
    { name: 'key-provider publication', gate: 'publicationGate', started: 'onPublication',
      operation: 'keys.provision' },
  ]
  for (const selected of cases) {
    await t.test(selected.name, async () => {
      const began = deferred()
      const never = new Promise(() => {})
      const runtime = await openBridge({ config: { ...baseConfig, requestTimeoutMs: 50 },
        [selected.gate]: never, [selected.started]: began.resolve })
      try {
        const scope = { organizationId, instanceId, conversationId: 'conversation-one',
          disclosureId: 'disclosure-one' }
        const body = selected.operation === 'authority.read' ? envelope('authority.read')
          : selected.operation === 'keys.provision' ? envelope('keys.provision', { scope,
            key: { keyId, material: Buffer.alloc(32, 0x5a).toString('base64url') } })
            : envelope('keys.readiness')
        const pending = post(runtime, body)
        await began.promise
        const response = await pending
        assert.equal(response.status, 503)
        assert.deepEqual(await response.json(), { version: 1, status: 'unavailable' })
        assert.equal(runtime.releases(), 1)
      } finally { await runtime.stop() }
    })
  }
})

test('bridge releases a tenant lease that resolves after timeout and close drains a hung handler', async () => {
  const beganAcquisition = deferred()
  const acquisition = deferred()
  const late = await openBridge({ config: { ...baseConfig, requestTimeoutMs: 50 },
    acquisitionGate: acquisition.promise, onAcquisition: beganAcquisition.resolve })
  try {
    const pending = post(late, envelope('keys.readiness'))
    await beganAcquisition.promise
    const response = await pending
    assert.equal(response.status, 503)
    assert.equal(late.releases(), 0)
    acquisition.resolve()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(late.releases(), 1)
  } finally {
    acquisition.resolve()
    await late.stop()
  }

  const beganDirectory = deferred()
  const never = new Promise(() => {})
  const closing = await openBridge({ config: { ...baseConfig, requestTimeoutMs: 5_000 },
    directoryGate: never, onDirectory: beganDirectory.resolve })
  try {
    const pending = post(closing, envelope('authority.read'))
    await beganDirectory.promise
    await closing.closeBridge()
    const response = await pending
    assert.equal(response.status, 503)
    assert.equal(closing.releases(), 1)
  } finally { await closing.stop() }
})
