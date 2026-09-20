import test from 'node:test'
import assert from 'node:assert/strict'
import { createSecretKey } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import Storage from '@deepseek-ai/dsh-storage'
import * as jsonStorage from '@deepseek-ai/dsh-storage-json'
import * as storageDomain from '@deepseek-ai/dsh-storage-domain'
import {
  encryptDisclosurePayload,
  generateDisclosureDataKey,
} from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import {
  generateInstanceKeyPair,
  signDisclosureCheckpoint,
  signDisclosureEvent,
} from '@deepseek-ai/dsh-a2a-device-identity'
import { computeDisclosureCiphertextHash } from '@deepseek-ai/dsh-a2a-protocol'
import { SoftwareLocalRegistryDisclosureKeyProvider } from '@deepseek-ai/dsh-registry-kms-software-app'
import {
  Config as ContentConfig,
  KmsRegistryDisclosureContentProvider,
  apply as applyContentProvider,
} from '@deepseek-ai/dsh-registry-disclosure-content-app'
import { RegistryDisclosureContentProjectionError } from '@deepseek-ai/dsh-registry-app'

const organizationId = 'content-provider-organization'
const instanceId = 'content-provider-instance'
const conversationId = 'content-provider-conversation'
const disclosureId = 'content-provider-disclosure'
const cryptoLimits = Object.freeze({
  maxPlaintextBytes: 4_096,
  maxCiphertextBytes: 16_384,
  maxTrustedKeys: 4,
})
const providerConfig = ContentConfig({ maxContentEvents: 8, crypto: cryptoLimits })

function signal() { return new AbortController().signal }

function scope(selectedDisclosureId = disclosureId) {
  return Object.freeze({ organizationId, instanceId, conversationId, disclosureId: selectedDisclosureId })
}

function keyScope() {
  return Object.freeze({ organizationId, instanceId, conversationId })
}

function signedPrefix(dataKey, semanticEvents, selectedDisclosureId = disclosureId) {
  const signingKey = generateInstanceKeyPair()
  const envelopes = []
  for (const [index, semanticEvent] of semanticEvents.entries()) {
    const eventId = `content-provider-event-${String(index)}`
    const metadata = {
      organizationId,
      instanceId,
      conversationId,
      disclosureId: selectedDisclosureId,
      eventId,
      eventType: semanticEvent.type,
      policyVersion: 1,
    }
    const ciphertext = encryptDisclosurePayload(semanticEvent, metadata, dataKey, cryptoLimits)
    const previous = envelopes.at(-1)
    envelopes.push(signDisclosureEvent({
      protocolVersion: 1,
      ...metadata,
      disclosureSeq: index,
      sourceCursor: index + 1,
      occurredAt: index + 10,
      previousEventHash: previous?.eventHash ?? null,
      ciphertext,
      ciphertextHash: computeDisclosureCiphertextHash(ciphertext),
    }, signingKey.privateKey))
  }
  const last = envelopes.at(-1)
  const checkpoint = signDisclosureCheckpoint({
    protocolVersion: 1,
    organizationId,
    instanceId,
    disclosureId: selectedDisclosureId,
    policyVersion: 1,
    sourceCursor: semanticEvents.length,
    eventCount: semanticEvents.length,
    lastDisclosureSeq: semanticEvents.length - 1,
    lastEventHash: last?.eventHash ?? null,
  }, signingKey.privateKey)
  return Object.freeze({ authorizationVersion: 1, conversationId, checkpoint,
    events: Object.freeze(envelopes) })
}

async function openRuntime() {
  const home = await mkdtemp(join(tmpdir(), 'registry-content-provider-'))
  const ctx = new Context()
  try {
    await ctx.plugin(Storage).await()
    await ctx.plugin(jsonStorage, { root: home }).await()
    await ctx.plugin(storageDomain, { backend: 'json' }).await()
    const keyProvider = new SoftwareLocalRegistryDisclosureKeyProvider(ctx, ctx.storageDomain, {
      singleInstance: true,
      rootKeyId: 'content-provider-root:v1',
      domainNamePrefix: 'content_provider_keys',
      maxDataKeysPerOrganization: 16,
      maxPendingOperationsPerOrganization: 8,
      maxActiveOrganizations: 2,
    }, createSecretKey(Buffer.alloc(32, 0x61)))
    applyContentProvider(ctx, providerConfig)
    const contentProvider = ctx.get('registryDisclosureContentProvider')
    assert.ok(contentProvider instanceof KmsRegistryDisclosureContentProvider)
    return { ctx, home, keyProvider, contentProvider, stop: async () => {
      await keyProvider.close()
      await ctx.fiber.dispose()
      await rm(home, { recursive: true, force: true })
    } }
  } catch (error) {
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
    throw error
  }
}

async function rejectsProjection(action, code) {
  await assert.rejects(action,
    error => error instanceof RegistryDisclosureContentProjectionError && error.code === code)
}

test('software-local content provider decrypts every signed semantic event with historical scoped keys', async () => {
  const runtime = await openRuntime()
  const grantScope = scope()
  const oldKey = generateDisclosureDataKey(keyScope())
  const currentKey = generateDisclosureDataKey(keyScope())
  const prefix = signedPrefix(oldKey, [
    { version: 1, type: 'conversation.title', title: 'Bounded history' },
    { version: 1, type: 'conversation.user-message', text: 'First question' },
    { version: 1, type: 'conversation.assistant-message', text: 'First answer' },
    { version: 1, type: 'conversation.tool-result-summary', toolName: 'search', outcome: 'success', text: 'One result' },
  ])
  try {
    await runtime.keyProvider.publishDataKey(grantScope, oldKey, signal())
    await runtime.keyProvider.publishDataKey(grantScope, currentKey, signal())
    const content = await runtime.contentProvider.readContent(prefix, 16_384, signal())
    assert.deepEqual(content, {
      checkpointHash: prefix.checkpoint.checkpointHash,
      events: [
        { disclosureSeq: 0, occurredAt: 10, type: 'conversation.title', title: 'Bounded history' },
        { disclosureSeq: 1, occurredAt: 11, type: 'conversation.user-message', text: 'First question' },
        { disclosureSeq: 2, occurredAt: 12, type: 'conversation.assistant-message', text: 'First answer' },
        { disclosureSeq: 3, occurredAt: 13, type: 'conversation.tool-result-summary', toolName: 'search',
          outcome: 'success', text: 'One result' },
      ],
    })
  } finally { await runtime.stop() }
})

test('content provider derives the disclosure grant scope and fails closed without that exact key grant', async () => {
  const runtime = await openRuntime()
  const retainedScope = scope()
  const dataKey = generateDisclosureDataKey(keyScope())
  try {
    await runtime.keyProvider.publishDataKey(retainedScope, dataKey, signal())
    const foreignPrefix = signedPrefix(dataKey,
      [{ version: 1, type: 'conversation.user-message', text: 'not authorized by another grant' }],
      'content-provider-other-disclosure')
    await rejectsProjection(() => runtime.contentProvider.readContent(foreignPrefix, 16_384, signal()), 'unavailable')
  } finally { await runtime.stop() }
})

test('content provider forwards the historical-key bound and returns no oversized or tampered projection', async () => {
  const ctx = new Context()
  const dataKey = generateDisclosureDataKey(keyScope())
  const prefix = signedPrefix(dataKey,
    [{ version: 1, type: 'conversation.assistant-message', text: 'bounded response' }])
  const calls = []
  const keyProvider = {
    readDataKeys(selectedScope, maxKeys, operationSignal) {
      calls.push({ selectedScope, maxKeys, operationSignal })
      return Promise.resolve([dataKey])
    },
  }
  const provider = new KmsRegistryDisclosureContentProvider(ctx, keyProvider, providerConfig)
  try {
    assert.equal((await provider.readContent(prefix, 16_384, signal())).events.length, 1)
    assert.equal(calls.length, 1)
    assert.deepEqual(calls[0].selectedScope, scope())
    assert.equal(calls[0].maxKeys, cryptoLimits.maxTrustedKeys)
    assert.ok(calls[0].operationSignal instanceof AbortSignal)

    await rejectsProjection(() => provider.readContent(prefix, 16, signal()), 'limit')
    const tampered = structuredClone(prefix)
    const last = tampered.events[0].ciphertext.at(-1)
    tampered.events[0].ciphertext = `${tampered.events[0].ciphertext.slice(0, -1)}${last === 'A' ? 'B' : 'A'}`
    await rejectsProjection(() => provider.readContent(tampered, 16_384, signal()), 'unavailable')

    const overBudgetThenTampered = structuredClone(signedPrefix(dataKey, [
      { version: 1, type: 'conversation.user-message', text: 'x'.repeat(768) },
      { version: 1, type: 'conversation.assistant-message', text: 'must not be decrypted' },
    ]))
    const tail = overBudgetThenTampered.events[1].ciphertext.at(-1)
    overBudgetThenTampered.events[1].ciphertext = `${overBudgetThenTampered.events[1].ciphertext.slice(0, -1)}${tail === 'A' ? 'B' : 'A'}`
    await rejectsProjection(() => provider.readContent(overBudgetThenTampered, 256, signal()), 'limit')

    const controller = new AbortController()
    controller.abort()
    await assert.rejects(() => provider.readContent(prefix, 16_384, controller.signal),
      error => error?.name === 'AbortError')
  } finally { await ctx.fiber.dispose() }
})

test('content provider configuration and plugin dependency fail closed', async () => {
  assert.throws(() => ContentConfig({ maxContentEvents: 0, crypto: cryptoLimits }))
  assert.throws(() => ContentConfig({ maxContentEvents: 1, crypto: { ...cryptoLimits, maxTrustedKeys: 0 } }))
  const boundedContext = new Context()
  const dataKey = generateDisclosureDataKey(keyScope())
  const shadowedConfig = ContentConfig({
    maxContentEvents: 1,
    crypto: { ...cryptoLimits, maxEvents: Number.MAX_SAFE_INTEGER },
  })
  const boundedProvider = new KmsRegistryDisclosureContentProvider(boundedContext, {
    readDataKeys() { return Promise.resolve([dataKey]) },
  }, shadowedConfig)
  try {
    await rejectsProjection(() => boundedProvider.readContent(signedPrefix(dataKey, [
      { version: 1, type: 'conversation.user-message', text: 'first' },
      { version: 1, type: 'conversation.assistant-message', text: 'second' },
    ]), 16_384, signal()), 'limit')
  } finally { await boundedContext.fiber.dispose() }

  const ctx = new Context()
  try {
    assert.throws(() => applyContentProvider(ctx, providerConfig), /requires registryDisclosureKeyProvider/u)
    assert.equal(ctx.get('registryDisclosureContentProvider'), undefined)
  } finally { await ctx.fiber.dispose() }
})
