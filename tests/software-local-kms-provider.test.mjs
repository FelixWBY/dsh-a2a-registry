import test from 'node:test'
import assert from 'node:assert/strict'
import { createSecretKey } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { Context } from '@deepseek-ai/cordis'
import Storage from '@deepseek-ai/dsh-storage'
import * as jsonStorage from '@deepseek-ai/dsh-storage-json'
import * as storageDomain from '@deepseek-ai/dsh-storage-domain'
import { SoftwareLocalKmsError } from '@deepseek-ai/dsh-a2a-registry-kms-software'
import * as providerPlugin from '@deepseek-ai/dsh-registry-kms-software-app'

const signal = () => new AbortController().signal

function scope(organizationId, suffix = '') {
  return Object.freeze({
    organizationId,
    instanceId: `source${suffix}`,
    conversationId: `conversation${suffix}`,
    disclosureId: `disclosure${suffix}`,
  })
}

function dataKey(grantScope, keyId, byte, keyScope = grantScope) {
  return Object.freeze({
    keyId,
    scope: Object.freeze({
      organizationId: keyScope.organizationId,
      instanceId: keyScope.instanceId,
      conversationId: keyScope.conversationId,
    }),
    key: createSecretKey(Buffer.alloc(32, byte)),
  })
}

function config(overrides = {}) {
  return providerPlugin.Config({
    singleInstance: true,
    rootKeyId: 'root-key:v1',
    domainNamePrefix: 'provider_test_keys',
    maxDataKeysPerOrganization: 16,
    maxPendingOperationsPerOrganization: 8,
    maxActiveOrganizations: 2,
    ...overrides,
  })
}

function key(byte = 0x71) {
  return createSecretKey(Buffer.alloc(32, byte))
}

function exported(secret) {
  const value = secret.export()
  return Buffer.isBuffer(value) ? value : Buffer.from(value)
}

async function runtime(root) {
  const ctx = new Context()
  try {
    await ctx.plugin(Storage).await()
    await ctx.plugin(jsonStorage, { root }).await()
    await ctx.plugin(storageDomain, { backend: 'json' }).await()
    return ctx
  } catch (error) {
    await ctx.fiber.dispose()
    throw error
  }
}

function provideCredential(ctx, resolved, previousResolved) {
  ctx.provide('credentials', Object.freeze({
    async resolve(ref) {
      if (ref === providerPlugin.DISCLOSURE_ROOT_KEY_ENV) return resolved
      assert.equal(ref, providerPlugin.DISCLOSURE_PREVIOUS_ROOT_KEY_ENV)
      return previousResolved
    },
  }))
}

async function rejectsCode(action, code) {
  await assert.rejects(async () => action(),
    error => error instanceof SoftwareLocalKmsError && error.code === code)
}

test('loader configuration and the fixed root-key environment fail closed', () => {
  assert.throws(() => providerPlugin.Config({ singleInstance: false, rootKeyId: 'root-key:v1' }))
  assert.throws(() => providerPlugin.Config({ singleInstance: true, rootKeyId: 'has spaces' }))
  assert.throws(() => providerPlugin.Config({ singleInstance: true, rootKeyId: 'root-key:v1',
    previousRootKeyId: 'root-key:v1' }))
  assert.throws(() => providerPlugin.parseDisclosureRootKey(''))
  assert.throws(() => providerPlugin.parseDisclosureRootKey(Buffer.alloc(32, 0x72).toString('base64')))

  const material = Buffer.alloc(32, 0x73)
  const imported = providerPlugin.parseDisclosureRootKey(material.toString('base64url'))
  const retained = exported(imported)
  try { assert.deepEqual(retained, material) } finally { retained.fill(0); material.fill(0) }
})

test('the loader admits at most one distinct environment-only previous root', async (t) => {
  const active = { value: Buffer.alloc(32, 0x78).toString('base64url'), source: 'env' }
  const previous = { value: Buffer.alloc(32, 0x79).toString('base64url'), source: 'env' }
  await t.test('legacy single-root tolerates a missing optional credential error', async () => {
    const home = await mkdtemp(join(tmpdir(), 'registry-kms-provider-legacy-single-root-'))
    const ctx = await runtime(home)
    try {
      ctx.provide('credentials', Object.freeze({
        async resolve(ref) {
          if (ref === providerPlugin.DISCLOSURE_ROOT_KEY_ENV) return active
          assert.equal(ref, providerPlugin.DISCLOSURE_PREVIOUS_ROOT_KEY_ENV)
          throw new Error('credential is absent')
        },
      }))
      await ctx.plugin(providerPlugin, config()).await()
      assert.equal(await ctx.registryDisclosureKeyProvider.checkReadiness(
        'organization-legacy-single-root', signal()), true)
    } finally {
      await ctx.fiber.dispose()
      await rm(home, { recursive: true, force: true })
    }
  })

  for (const [label, selectedConfig, selectedPrevious, expected] of [
    ['missing material', config({ previousRootKeyId: 'root-key:previous' }), undefined,
      /must resolve from the inherited process environment/u],
    ['non-environment material', config({ previousRootKeyId: 'root-key:previous' }),
      { ...previous, source: 'file' }, /must resolve from the inherited process environment/u],
    ['orphan material', config(), previous, /requires DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID/u],
    ['reused material', config({ previousRootKeyId: 'root-key:previous' }), active,
      /must be independent/u],
  ]) await t.test(label, async () => {
    const home = await mkdtemp(join(tmpdir(), `registry-kms-provider-previous-${label.replaceAll(' ', '-')}-`))
    const ctx = await runtime(home)
    try {
      provideCredential(ctx, active, selectedPrevious)
      await assert.rejects(ctx.plugin(providerPlugin, selectedConfig).await(), expected)
      assert.equal(ctx.get('registryDisclosureKeyProvider'), undefined)
    } finally {
      await ctx.fiber.dispose()
      await rm(home, { recursive: true, force: true })
    }
  })

  await t.test('valid previous slot', async () => {
    const home = await mkdtemp(join(tmpdir(), 'registry-kms-provider-previous-valid-'))
    const ctx = await runtime(home)
    try {
      provideCredential(ctx, active, previous)
      await ctx.plugin(providerPlugin, config({ previousRootKeyId: 'root-key:previous' })).await()
      const verified = await ctx.registryDisclosureKeyProvider.verifyRetainedKeys('organization-previous', signal())
      assert.equal(verified.rootKeyId, 'root-key:v1')
      assert.equal(verified.dataKeyCount, 0)
    } finally {
      await ctx.fiber.dispose()
      await rm(home, { recursive: true, force: true })
    }
  })
})

test('the loader rejects missing and file-layer root keys', async (t) => {
  for (const [label, resolved] of [
    ['missing', undefined],
    ['file', { value: Buffer.alloc(32, 0x74).toString('base64url'), source: 'file' }],
    ['project-env', { value: Buffer.alloc(32, 0x75).toString('base64url'), source: 'project-env' }],
  ]) await t.test(label, async () => {
    const home = await mkdtemp(join(tmpdir(), `registry-kms-provider-${label}-`))
    const ctx = await runtime(home)
    try {
      provideCredential(ctx, resolved)
      await assert.rejects(ctx.plugin(providerPlugin, config()).await(),
        /must resolve from the inherited process environment/)
      assert.equal(ctx.get('registryDisclosureKeyProvider'), undefined)
    } finally {
      await ctx.fiber.dispose()
      await rm(home, { recursive: true, force: true })
    }
  })
})

test('the loader mounts one inherited-environment provider and disposes it with the plugin', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-kms-provider-loader-'))
  let ctx
  try {
    ctx = await runtime(home)
    provideCredential(ctx, {
      value: Buffer.alloc(32, 0x76).toString('base64url'),
      source: 'env',
    })
    await ctx.plugin(providerPlugin, config()).await()
    assert.equal(ctx.registryDisclosureKeyProvider.protection.assurance, 'software-local')
    assert.equal(ctx.registryDisclosureKeyProvider.protection.singleWriterRequired, true)
    assert.equal(await ctx.registryDisclosureKeyProvider.checkReadiness('organization-loader', signal()), true)
  } finally {
    if (ctx !== undefined) await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})

test('tenant routing stays isolated and an idle LRU tenant reopens from durable storage', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-kms-provider-lru-'))
  const ctx = await runtime(home)
  const provider = new providerPlugin.SoftwareLocalRegistryDisclosureKeyProvider(
    ctx, ctx.storageDomain, config({ maxActiveOrganizations: 1 }), key(),
  )
  const firstScope = scope('organization-a', '-a')
  const secondScope = scope('organization-b', '-b')
  const firstKey = dataKey(firstScope, 'data-key:first', 0x75)
  const firstHistoricalKey = dataKey(firstScope, 'data-key:historical', 0x77)
  const secondKey = dataKey(secondScope, 'data-key:second', 0x76)
  try {
    await provider.publishDataKey(firstScope, firstKey, signal())
    await provider.publishDataKey(firstScope, firstHistoricalKey, signal())
    await provider.publishDataKey(secondScope, secondKey, signal())

    await rejectsCode(() => provider.readDataKeys(firstScope, 1, signal()), 'limit')
    const restored = await provider.readDataKeys(firstScope, 2, signal())
    assert.deepEqual(restored.map(item => item.keyId), [firstKey.keyId, firstHistoricalKey.keyId])
    const retained = exported(restored.find(item => item.keyId === firstKey.keyId).key)
    try { assert.deepEqual(retained, Buffer.alloc(32, 0x75)) } finally { retained.fill(0) }

    const grant = await provider.issueAuthorizedGrant(firstScope, 2, 4 * 1024, signal())
    assert.deepEqual(grant.scope, firstScope)
    assert.deepEqual(grant.keys.map(item => item.keyId), [firstKey.keyId, firstHistoricalKey.keyId])
    assert.deepEqual(grant.keys.map(item => Buffer.from(item.material, 'base64url').byteLength), [32, 32])
    await rejectsCode(() => provider.issueAuthorizedGrant(firstScope, 1, 4 * 1024, signal()), 'limit')
    await rejectsCode(() => provider.issueAuthorizedGrant(firstScope, 2, 1, signal()), 'limit')

    const verification = await provider.verifyRetainedKeys(firstScope.organizationId, signal())
    assert.equal(verification.organizationId, firstScope.organizationId)
    assert.equal(verification.rootKeyId, 'root-key:v1')
    assert.equal(verification.dataKeyCount, 2)
    assert.match(verification.metadataSha256, /^sha256:[0-9a-f]{64}$/u)

    await rejectsCode(() => provider.publishDataKey(firstScope,
      dataKey(firstScope, 'data-key:foreign-scope', 0x77, secondScope), signal()), 'scope-mismatch')
    const second = await provider.readDataKeys(secondScope, 1, signal())
    assert.equal(second.length, 1)
    assert.equal(second[0].keyId, secondKey.keyId)
  } finally {
    await provider.close()
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})

test('close stops admission, waits for an in-flight tenant open, and releases every store', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-kms-provider-close-'))
  const ctx = await runtime(home)
  let releaseOpen
  let markStarted
  const started = new Promise(resolve => { markStarted = resolve })
  const gate = new Promise(resolve => { releaseOpen = resolve })
  const delayedFacility = {
    async open(specification) {
      markStarted()
      await gate
      return ctx.storageDomain.open(specification)
    },
  }
  const provider = new providerPlugin.SoftwareLocalRegistryDisclosureKeyProvider(
    ctx, delayedFacility, config({ maxActiveOrganizations: 1 }), key(0x78),
  )
  try {
    const readiness = provider.checkReadiness('organization-drain', signal())
    await started
    const sharedReadiness = provider.checkReadiness('organization-drain', signal())
    await rejectsCode(() => provider.checkReadiness('organization-at-capacity', signal()), 'limit')
    const closing = provider.close()
    assert.equal(await Promise.race([closing.then(() => 'closed'), delay(25, 'waiting')]), 'waiting')
    await rejectsCode(() => provider.checkReadiness('organization-after-close', signal()), 'closed')
    releaseOpen()
    assert.equal(await readiness, true)
    assert.equal(await sharedReadiness, true)
    await closing
    await rejectsCode(() => provider.checkReadiness('organization-after-drain', signal()), 'closed')
  } finally {
    releaseOpen()
    await provider.close().catch(() => undefined)
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})
