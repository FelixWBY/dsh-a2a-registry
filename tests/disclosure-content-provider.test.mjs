import test from 'node:test'
import assert from 'node:assert/strict'
import { Context } from '@deepseek-ai/cordis'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import { RegistryAccountAuthenticator, RegistryDisclosureContentProvider } from '@deepseek-ai/dsh-registry-app'
import { installRegistryBrowserApi } from '@deepseek-ai/dsh-registry-app/src/browser-api.ts'
import { createRegistrySaasDisclosureOperations } from '@deepseek-ai/dsh-registry-app/src/saas-disclosure-operations.ts'

const organizationId = 'content-tenant'
const memberId = 'content-member'
const disclosureId = 'content-disclosure'
const instanceId = 'content-source'
const checkpointHash = `sha256:${'a'.repeat(64)}`
const maxValueBytes = 4096

class TestAuthenticator extends RegistryAccountAuthenticator {
  calls = 0

  authenticate(_request, signal) {
    assert.equal(signal.aborted, false)
    this.calls += 1
    return Promise.resolve({
      subject: { authenticated: true, organizationId, memberId, membership: 'active', role: 'member', teamIds: [] },
      historyFor: () => null,
    })
  }
}

class MemoryContentProvider extends RegistryDisclosureContentProvider {
  constructor(ctx, content, sequence) {
    super(ctx)
    this.content = content
    this.sequence = sequence
    this.calls = []
  }

  readContent(prefix, responseBytes, signal) {
    this.sequence.push('provider')
    this.calls.push({ prefix, responseBytes, signal })
    return Promise.resolve(structuredClone(this.content))
  }
}

function operationRouters() {
  const unavailable = () => Promise.reject(new Error('not used'))
  return {
    imports: { listImportTargets: unavailable, importDisclosure: unavailable, readImport: unavailable },
    questions: {
      listQuestions: unavailable,
      askDisclosure: unavailable,
      readQuestion: unavailable,
      cancelQuestion: unavailable,
    },
  }
}

async function openBrowserApi(content) {
  const ctx = new Context()
  const sequence = []
  let stopApi
  try {
    await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0, compression: 'none' })
    const authenticator = new TestAuthenticator(ctx)
    const prefix = { checkpoint: { checkpointHash } }
    let prefixReads = 0
    const reader = {
      list: () => Promise.reject(new Error('not used')),
      async readMetadata(authority, selectedDisclosureId, action, options) {
        sequence.push('metadata')
        await authority()
        assert.equal(selectedDisclosureId, disclosureId)
        assert.equal(action, 'read')
        assert.equal(options.checkpointHash, checkpointHash)
        assert.equal(options.maxResponseBytes, maxValueBytes)
        return { disclosureId, instanceId, checkpoint: { checkpointHash } }
      },
      async readPrefix(authority, selectedDisclosureId, sourceInstanceId, action, selectedCheckpointHash) {
        sequence.push('prefix')
        await authority()
        assert.equal(selectedDisclosureId, disclosureId)
        assert.equal(sourceInstanceId, instanceId)
        assert.equal(action, 'read')
        assert.equal(selectedCheckpointHash, checkpointHash)
        prefixReads += 1
        return prefix
      },
      withAuthorizedPrefix: () => Promise.reject(new Error('not used')),
    }
    let releases = 0
    ctx.provide('registryTenantRouter', {
      acquireRuntime(selectedOrganizationId) {
        assert.equal(selectedOrganizationId, organizationId)
        return Promise.resolve({ runtime: { reader }, release() { releases += 1 } })
      },
    })
    const routers = operationRouters()
    const provider = content === undefined ? undefined : new MemoryContentProvider(ctx, content, sequence)
    const operations = createRegistrySaasDisclosureOperations(routers.imports, routers.questions, provider)
    ctx.provide('registryDisclosureOperations', operations)
    stopApi = installRegistryBrowserApi(ctx, {
      pageSize: 20,
      maxValueBytes,
      maxCursorBytes: 256,
      maxOperationInputBytes: 4096,
    })
    return {
      ctx,
      authenticator,
      operations,
      prefix,
      prefixReads: () => prefixReads,
      provider,
      releases: () => releases,
      sequence,
      stop: async () => {
        stopApi?.()
        await ctx.fiber.dispose()
      },
      url: `http://127.0.0.1:${ctx.webServer.port}/registry-api/v1/organizations/${organizationId}`
        + `/disclosures/${disclosureId}/content?checkpoint=${encodeURIComponent(checkpointHash)}`,
    }
  } catch (error) {
    stopApi?.()
    await ctx.fiber.dispose()
    throw error
  }
}

test('SaaS content remains unconfigured when the narrow provider is absent', async () => {
  const runtime = await openBrowserApi(undefined)
  try {
    assert.equal(runtime.operations.readContent, undefined)
    const response = await fetch(runtime.url)
    assert.equal(response.status, 501)
    assert.deepEqual(await response.json(), { ok: false, error: { code: 'operation-not-configured' } })
    assert.equal(runtime.prefixReads(), 0)
    assert.equal(runtime.releases(), 1)
  } finally { await runtime.stop() }
})

test('SaaS content provider receives the fixed authorized prefix, bound and request signal', async () => {
  const content = { checkpointHash, events: [{
    disclosureSeq: 0,
    occurredAt: 1,
    type: 'conversation.user-message',
    text: '固定检查点正文',
  }] }
  const runtime = await openBrowserApi(content)
  try {
    const response = await fetch(runtime.url)
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), { ok: true, value: content })
    assert.deepEqual(runtime.sequence, ['metadata', 'prefix', 'provider', 'prefix'])
    assert.equal(runtime.prefixReads(), 2)
    assert.ok(runtime.authenticator.calls >= 4)
    assert.equal(runtime.provider.calls.length, 1)
    assert.equal(runtime.provider.calls[0].prefix, runtime.prefix)
    assert.equal(runtime.provider.calls[0].responseBytes, maxValueBytes)
    assert.ok(runtime.provider.calls[0].signal instanceof AbortSignal)
    assert.equal(runtime.provider.calls[0].signal.aborted, false)
    assert.equal(runtime.releases(), 1)
  } finally { await runtime.stop() }
})

test('browser API rejects content that exceeds its bound even when a provider returns it', async () => {
  const runtime = await openBrowserApi({ checkpointHash, events: [{
    disclosureSeq: 0,
    occurredAt: 1,
    type: 'conversation.assistant-message',
    text: 'x'.repeat(maxValueBytes),
  }] })
  try {
    const response = await fetch(runtime.url)
    assert.equal(response.status, 503)
    assert.deepEqual(await response.json(), { ok: false, error: { code: 'unavailable' } })
    assert.equal(runtime.provider.calls[0].responseBytes, maxValueBytes)
    assert.deepEqual(runtime.sequence, ['metadata', 'prefix', 'provider', 'prefix'])
  } finally { await runtime.stop() }
})

test('multiple content providers and whole-operation conflicts fail closed', async () => {
  const ctx = new Context()
  try {
    new MemoryContentProvider(ctx, { checkpointHash, events: [] }, [])
    assert.throws(() => new MemoryContentProvider(ctx, { checkpointHash, events: [] }, []),
      /service "registryDisclosureContentProvider" has been registered/u)

    ctx.provide('registryDisclosureOperations', Object.freeze({}))
    assert.notEqual(ctx.get('registryDisclosureOperations'), undefined)
    assert.throws(() => ctx.provide('registryDisclosureOperations', Object.freeze({})),
      /service "registryDisclosureOperations" has been registered/u)
  } finally { await ctx.fiber.dispose() }
})
