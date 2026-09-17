import test from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execute = promisify(execFile)
const root = dirname(dirname(fileURLToPath(import.meta.url)))
const script = join(root, 'deploy', 'registry', 'verify-registry-restore.mjs')
const organizationId = 'tenant:restore'
const encodedOrganizationId = encodeURIComponent(organizationId)
const checkpointHash = `sha256:${'a'.repeat(64)}`
const cookie = 'registry_session=fixture'

function response(value) {
  return JSON.stringify({ ok: true, value })
}

function run(origin, command, selectedOrganizationId, expectation) {
  return execute(process.execPath, [script, command, origin, selectedOrganizationId, expectation], {
    env: { ...process.env, DSH_REGISTRY_RESTORE_COOKIE: cookie },
    windowsHide: true,
  })
}

test('restore verification fixes every SaaS probe to the captured organization', { timeout: 20_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'registry-restore-verification-'))
  const expectation = join(directory, 'expectation.json')
  const requests = []
  let auditRootRequests = 0
  const tenantBase = `/registry-api/v1/organizations/${encodedOrganizationId}`
  const disclosure = {
    disclosureId: 'disclosure-1', instanceId: 'instance-1', control: 'active', producer: 'offline',
    ingest: 'ready', expiresAt: 4_000_000_000_000, authorizationVersion: 3,
    checkpointVerifiedAt: 1_700_000_000_000, authorizedActions: ['read'],
    checkpoint: { checkpointHash, policyVersion: 1, sourceCursor: 0, eventCount: 0,
      lastDisclosureSeq: -1, lastEventHash: null },
  }
  const server = createServer((request, serverResponse) => {
    const url = new URL(request.url ?? '/', 'http://fixture.invalid')
    requests.push({ url: request.url, cookie: request.headers.cookie })
    let value
    if (url.pathname === '/registry-api/v1/status') value = { deploymentMode: 'saas' }
    else if (url.pathname === `${tenantBase}/directory`) value = { revision: 4, members: [], teams: [] }
    else if (url.pathname === `${tenantBase}/instances`) value = { items: [{ bindingId: 'binding-1',
      instanceId: 'instance-1', instanceName: 'Fixture', phase: 'confirmed', requestedScopes: ['disclosure.sync'] }] }
    else if (url.pathname === `${tenantBase}/disclosures`) value = { items: [disclosure], nextCursor: null }
    else if (url.pathname === `${tenantBase}/disclosures/disclosure-1/content`) {
      assert.equal(url.searchParams.get('checkpoint'), checkpointHash)
      value = { checkpointHash, events: [] }
    } else if (url.pathname === `${tenantBase}/audit`) {
      const cursor = url.searchParams.get('cursor')
      if (cursor === 'captured-page') value = { items: [{ operationId: 'operation-1' }], nextCursor: null }
      else if (cursor === null) {
        auditRootRequests += 1
        value = auditRootRequests === 1
          ? { items: [{ operationId: 'operation-1' }], nextCursor: null }
          : { items: [{ operationId: `new-operation-${auditRootRequests}` }], nextCursor: 'captured-page' }
      } else {
        serverResponse.writeHead(404, { 'content-type': 'application/json' })
        serverResponse.end(JSON.stringify({ ok: false, error: 'not-found' }))
        return
      }
    } else {
      serverResponse.writeHead(404, { 'content-type': 'application/json' })
      serverResponse.end(JSON.stringify({ ok: false, error: 'not-found' }))
      return
    }
    serverResponse.writeHead(200, { 'content-type': 'application/json' })
    serverResponse.end(response(value))
  })
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', resolve)
    })
    const address = server.address()
    assert.ok(address && typeof address === 'object')
    const origin = `http://127.0.0.1:${address.port}`

    const captured = await run(origin, 'capture', organizationId, expectation)
    assert.equal(JSON.parse(captured.stdout).organizationId, organizationId)
    const document = JSON.parse(await readFile(expectation, 'utf8'))
    assert.equal(document.version, 2)
    assert.equal(document.organizationId, organizationId)
    assert.equal(JSON.stringify(document).includes(cookie), false)

    requests.length = 0
    const verified = await run(origin, 'verify', organizationId, expectation)
    assert.equal(JSON.parse(verified.stdout).organizationId, organizationId)
    assert.ok(requests.some(item => item.url?.includes('/disclosures/disclosure-1/content?checkpoint=')))
    assert.ok(requests.some(item => item.url === `${tenantBase}/audit?cursor=captured-page`))
    assert.ok(requests.every(item => item.cookie === cookie))
    assert.ok(requests.every(item => item.url === '/registry-api/v1/status'
      || item.url?.startsWith(`${tenantBase}/`)))

    const requestCount = requests.length
    await assert.rejects(run(origin, 'verify', 'another-tenant', expectation), error =>
      typeof error?.stderr === 'string' && error.stderr.includes('organizationId differs from the captured Registry tenant'))
    assert.equal(requests.length, requestCount)
    await assert.rejects(run(origin, 'capture', 'invalid/tenant', join(directory, 'invalid.json')), error =>
      typeof error?.stderr === 'string' && error.stderr.includes('organizationId must be a canonical opaque identifier'))
    assert.equal(requests.length, requestCount)
  } finally {
    await new Promise(resolve => server.close(resolve))
    await rm(directory, { recursive: true, force: true })
  }
})
