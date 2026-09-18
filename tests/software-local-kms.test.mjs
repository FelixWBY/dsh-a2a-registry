import test from 'node:test'
import assert from 'node:assert/strict'
import { createSecretKey } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import Storage from '@deepseek-ai/dsh-storage'
import * as jsonStorage from '@deepseek-ai/dsh-storage-json'
import * as storageDomain from '@deepseek-ai/dsh-storage-domain'
import {
  openSoftwareLocalDisclosureKeyStore, softwareLocalDisclosureKeyDomainName,
  SOFTWARE_LOCAL_KEY_PROTECTION, SoftwareLocalKmsError,
} from '@deepseek-ai/dsh-a2a-registry-kms-software'
import { RegistryDisclosureKeyProvider } from '@deepseek-ai/dsh-registry-app'

const operationSignal = () => new AbortController().signal
const limits = Object.freeze({ maxDataKeys: 16, maxPendingOperations: 8 })

function scope(organizationId, suffix = '') {
  return Object.freeze({
    organizationId,
    instanceId: `source${suffix}`,
    conversationId: `conversation${suffix}`,
    disclosureId: `disclosure${suffix}`,
  })
}

function dataKey(grantScope, keyId, byte) {
  return Object.freeze({
    keyId,
    scope: Object.freeze({
      organizationId: grantScope.organizationId,
      instanceId: grantScope.instanceId,
      conversationId: grantScope.conversationId,
    }),
    key: createSecretKey(Buffer.alloc(32, byte)),
  })
}

function rootKey(byte, keyId = 'root-key:v1') {
  return Object.freeze({ keyId, key: createSecretKey(Buffer.alloc(32, byte)) })
}

async function runtime(root) {
  const ctx = new Context()
  try {
    await ctx.plugin(Storage)
    await ctx.plugin(jsonStorage, { root })
    await ctx.plugin(storageDomain, { backend: 'json' })
    return ctx
  } catch (error) {
    await ctx.fiber.dispose()
    throw error
  }
}

async function openStore(ctx, organizationId, key, lifecycle, domainNamePrefix = 'software_local_kms') {
  return openSoftwareLocalDisclosureKeyStore(ctx.storageDomain, {
    organizationId,
    rootKey: key,
    storage: { domainNamePrefix, tenantId: organizationId },
    limits,
    signal: lifecycle.signal,
  })
}

function domainPath(root, prefix, organizationId) {
  return join(root, `${softwareLocalDisclosureKeyDomainName(prefix, organizationId)}.json`)
}

function exported(key) {
  const value = key.export()
  return Buffer.isBuffer(value) ? value : Buffer.from(value)
}

async function rejectsCode(action, code) {
  await assert.rejects(async () => action(),
    error => error instanceof SoftwareLocalKmsError && error.code === code)
}

test('software-local hierarchy persists only wrapped keys and survives a clean restart', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-software-kms-restart-'))
  const organizationId = 'organization-a'
  const grantScope = scope(organizationId)
  const master = rootKey(0x11)
  const published = dataKey(grantScope, 'data-key:restart', 0x22)
  let ctx
  try {
    ctx = await runtime(home)
    const lifecycle = new AbortController()
    const store = await openStore(ctx, organizationId, master, lifecycle)
    assert.deepEqual(store.protection, SOFTWARE_LOCAL_KEY_PROTECTION)
    assert.deepEqual(store.protection, {
      assurance: 'software-local', hsmBacked: false, hardwareAttested: false, endToEnd: false,
      rootKeyPersistence: 'external-runtime-secret', keysExportableInProcess: true, singleWriterRequired: true,
    })
    const first = await store.publishDataKey(grantScope, published, operationSignal())
    const retry = await store.publishDataKey(grantScope, published, operationSignal())
    assert.deepEqual(retry, first)
    assert.equal(await store.checkReadiness(operationSignal()), true)
    await store.close()
    await ctx.fiber.dispose()
    ctx = undefined

    const durable = await readFile(domainPath(home, 'software_local_kms', organizationId), 'utf8')
    assert.equal(durable.includes(Buffer.alloc(32, 0x11).toString('base64url')), false)
    assert.equal(durable.includes(Buffer.alloc(32, 0x22).toString('base64url')), false)

    ctx = await runtime(home)
    const restarted = await openStore(ctx, organizationId, master, new AbortController())
    const retained = await restarted.readDataKeys(grantScope, operationSignal())
    assert.equal(retained.length, 1)
    assert.equal(retained[0].keyId, published.keyId)
    assert.deepEqual(exported(retained[0].key), Buffer.alloc(32, 0x22))
    await restarted.close()
  } finally {
    if (ctx !== undefined) await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})

test('one domain prefix derives distinct physical stores for concurrently active organizations', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-software-kms-domains-'))
  const firstOrganization = 'organization-a'
  const secondOrganization = 'organization-b'
  const prefix = 'software_local_kms'
  const ctx = await runtime(home)
  try {
    assert.notEqual(softwareLocalDisclosureKeyDomainName(prefix, firstOrganization),
      softwareLocalDisclosureKeyDomainName(prefix, secondOrganization))
    const first = await openStore(ctx, firstOrganization, rootKey(0x23), new AbortController(), prefix)
    const second = await openStore(ctx, secondOrganization, rootKey(0x24), new AbortController(), prefix)
    const firstScope = scope(firstOrganization)
    const secondScope = scope(secondOrganization)
    await first.publishDataKey(firstScope, dataKey(firstScope, 'data-key:first', 0x25), operationSignal())
    await second.publishDataKey(secondScope, dataKey(secondScope, 'data-key:second', 0x26), operationSignal())
    await first.close()
    await second.close()
    await readFile(domainPath(home, prefix, firstOrganization), 'utf8')
    await readFile(domainPath(home, prefix, secondOrganization), 'utf8')
  } finally {
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})

test('publish rejects cross-tenant scope and conflicting material without replacing the durable key', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-software-kms-conflict-'))
  const organizationId = 'organization-a'
  const grantScope = scope(organizationId)
  const retained = dataKey(grantScope, 'data-key:conflict', 0x31)
  const conflicting = dataKey(grantScope, retained.keyId, 0x32)
  const ctx = await runtime(home)
  try {
    const lifecycle = new AbortController()
    const store = await openStore(ctx, organizationId, rootKey(0x30), lifecycle)
    await store.publishDataKey(grantScope, retained, operationSignal())
    await rejectsCode(() => store.publishDataKey(grantScope, conflicting, operationSignal()), 'conflict')
    const foreignScope = scope('organization-b')
    await rejectsCode(() => store.publishDataKey(foreignScope,
      dataKey(foreignScope, 'data-key:foreign', 0x33), operationSignal()), 'scope-mismatch')
    const result = await store.readDataKeys(grantScope, operationSignal())
    assert.deepEqual(exported(result[0].key), Buffer.alloc(32, 0x31))
    lifecycle.abort()
    await rejectsCode(() => store.checkReadiness(operationSignal()), 'closed')
    await store.close()
  } finally {
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})

test('an ambiguous committed write quarantines the handle and an idempotent restart recovers it', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-software-kms-ambiguous-'))
  const organizationId = 'organization-ambiguous'
  const grantScope = scope(organizationId)
  const master = rootKey(0x38)
  const published = dataKey(grantScope, 'data-key:ambiguous', 0x39)
  const ctx = new Context()
  const backend = new jsonStorage.JsonStorageBackend(home)
  let failDataKeyWrite = true
  let openedDescriptor
  const ambiguousBackend = {
    kv: {
      async open(descriptor) {
        openedDescriptor = structuredClone(descriptor)
        const unit = await backend.kv.open(descriptor)
        return {
          loadAll: unit.loadAll.bind(unit),
          async putRecord(table, key, value) {
            await unit.putRecord(table, key, value)
            if (table === 'data_keys' && failDataKeyWrite) {
              failDataKeyWrite = false
              throw new Error('simulated post-commit transport failure')
            }
          },
          putRecords: unit.putRecords?.bind(unit),
          deleteRecord: unit.deleteRecord.bind(unit),
          setGlobal: unit.setGlobal.bind(unit),
          close: unit.close.bind(unit),
        }
      },
    },
    close: backend.close.bind(backend),
  }
  let unregister
  let store
  const facility = new storageDomain.DomainFacility(ctx, { backend: 'ambiguous' })
  try {
    await ctx.plugin(Storage)
    unregister = ctx.storage.backend.register('ambiguous', ambiguousBackend)
    store = await openSoftwareLocalDisclosureKeyStore(facility, {
      organizationId,
      rootKey: master,
      storage: { domainNamePrefix: 'software_local_kms', tenantId: organizationId },
      limits,
      signal: new AbortController().signal,
    })
    assert.equal(openedDescriptor.tenantId, organizationId)
    assert.equal(openedDescriptor.name,
      softwareLocalDisclosureKeyDomainName('software_local_kms', organizationId))
    await rejectsCode(() => store.publishDataKey(grantScope, published, operationSignal()), 'storage-failed')
    await rejectsCode(() => store.readDataKeys(grantScope, operationSignal()), 'unavailable')
    await store.close()
    store = undefined
  } finally {
    if (store !== undefined) await store.close()
    await facility.closeAll()
    unregister?.()
    await ambiguousBackend.close()
    await ctx.fiber.dispose()
  }

  try {
    const restarted = await runtime(home)
    try {
      const recovered = await openStore(restarted, organizationId, master, new AbortController())
      const retained = await recovered.readDataKeys(grantScope, operationSignal())
      assert.deepEqual(exported(retained[0].key), Buffer.alloc(32, 0x39))
      assert.deepEqual(await recovered.publishDataKey(grantScope, published, operationSignal()), {
        scope: grantScope, keyId: published.keyId, assurance: 'software-local',
      })
      await recovered.close()
    } finally { await restarted.fiber.dispose() }
  } finally { await rm(home, { recursive: true, force: true }) }
})

test('cleanup failures cannot replace sanitized KMS errors or escape from public close', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-software-kms-close-'))
  const organizationId = 'organization-close'
  const master = rootKey(0x3a)
  const ctx = await runtime(home)
  const closeFailingFacility = (beforeReturn = () => {}) => ({
    async open(specification) {
      const domain = await ctx.storageDomain.open(specification)
      beforeReturn()
      return {
        table: domain.table.bind(domain),
        async close() {
          await domain.close()
          throw new Error('raw backend cleanup diagnostic')
        },
      }
    },
  })
  try {
    const store = await openSoftwareLocalDisclosureKeyStore(closeFailingFacility(), {
      organizationId,
      rootKey: master,
      storage: { domainNamePrefix: 'kms_close_public', tenantId: organizationId },
      limits,
      signal: new AbortController().signal,
    })
    await rejectsCode(() => store.close(), 'storage-failed')

    const lifecycle = new AbortController()
    await rejectsCode(() => openSoftwareLocalDisclosureKeyStore(
      closeFailingFacility(() => lifecycle.abort()), {
        organizationId,
        rootKey: master,
        storage: { domainNamePrefix: 'kms_close_primary', tenantId: organizationId },
        limits,
        signal: lifecycle.signal,
      },
    ), 'closed')
  } finally {
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})

test('cross-tenant wrapped-row substitution fails authentication even under the same root key', async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-software-kms-tenant-'))
  const master = rootKey(0x41)
  const sourceScope = scope('organization-a', '-shared')
  const targetScope = scope('organization-b', '-shared')
  const ctx = await runtime(home)
  try {
    const source = await openStore(ctx, sourceScope.organizationId, master, new AbortController(), 'kms_source')
    const target = await openStore(ctx, targetScope.organizationId, master, new AbortController(), 'kms_target')
    await source.publishDataKey(sourceScope, dataKey(sourceScope, 'data-key:shared', 0x42), operationSignal())
    await target.publishDataKey(targetScope, dataKey(targetScope, 'data-key:shared', 0x43), operationSignal())
    await source.close()
    await target.close()
  } finally { await ctx.fiber.dispose() }

  try {
    const sourcePath = domainPath(home, 'kms_source', sourceScope.organizationId)
    const targetPath = domainPath(home, 'kms_target', targetScope.organizationId)
    const sourceDocument = JSON.parse(await readFile(sourcePath, 'utf8'))
    const targetDocument = JSON.parse(await readFile(targetPath, 'utf8'))
    const sourceRecord = Object.values(sourceDocument.tables.data_keys)[0]
    const targetRecord = Object.values(targetDocument.tables.data_keys)[0]
    targetRecord.wrappedDataKey = sourceRecord.wrappedDataKey
    await writeFile(targetPath, `${JSON.stringify(targetDocument, null, 2)}\n`, 'utf8')

    const restarted = await runtime(home)
    try {
      await rejectsCode(() => openStore(restarted, targetScope.organizationId, master,
        new AbortController(), 'kms_target'), 'authentication-failed')
    } finally { await restarted.fiber.dispose() }
  } finally { await rm(home, { recursive: true, force: true }) }
})

test('tampered wrapped DEK and wrong same-id root key both fail closed on restart', async (t) => {
  await t.test('tampered DEK', async () => {
    const home = await mkdtemp(join(tmpdir(), 'registry-software-kms-tamper-'))
    const organizationId = 'organization-tamper'
    const grantScope = scope(organizationId)
    const master = rootKey(0x51)
    const ctx = await runtime(home)
    try {
      const store = await openStore(ctx, organizationId, master, new AbortController())
      await store.publishDataKey(grantScope, dataKey(grantScope, 'data-key:tamper', 0x52), operationSignal())
      await store.close()
    } finally { await ctx.fiber.dispose() }
    try {
      const path = domainPath(home, 'software_local_kms', organizationId)
      const document = JSON.parse(await readFile(path, 'utf8'))
      const record = Object.values(document.tables.data_keys)[0]
      const first = record.wrappedDataKey.ciphertext.at(0)
      record.wrappedDataKey.ciphertext = `${first === 'A' ? 'B' : 'A'}${record.wrappedDataKey.ciphertext.slice(1)}`
      await writeFile(path, `${JSON.stringify(document, null, 2)}\n`, 'utf8')
      const restarted = await runtime(home)
      try {
        await rejectsCode(() => openStore(restarted, organizationId, master, new AbortController()),
          'authentication-failed')
      } finally { await restarted.fiber.dispose() }
    } finally { await rm(home, { recursive: true, force: true }) }
  })

  await t.test('wrong RMK', async () => {
    const home = await mkdtemp(join(tmpdir(), 'registry-software-kms-root-'))
    const organizationId = 'organization-root'
    const master = rootKey(0x61)
    const ctx = await runtime(home)
    try {
      const store = await openStore(ctx, organizationId, master, new AbortController())
      await store.close()
    } finally { await ctx.fiber.dispose() }
    try {
      const restarted = await runtime(home)
      try {
        await rejectsCode(() => openStore(restarted, organizationId, rootKey(0x62), new AbortController()),
          'authentication-failed')
      } finally { await restarted.fiber.dispose() }
    } finally { await rm(home, { recursive: true, force: true }) }
  })
})

test('RegistryDisclosureKeyProvider is a unique narrow service with explicit software-local assurance', async () => {
  class MemoryProvider extends RegistryDisclosureKeyProvider {
    protection = SOFTWARE_LOCAL_KEY_PROTECTION
    publishDataKey(scopeValue, key) {
      return Promise.resolve({ scope: scopeValue, keyId: key.keyId, assurance: this.protection.assurance })
    }
    readDataKeys() { return Promise.resolve([]) }
    checkReadiness() { return Promise.resolve(true) }
  }
  const ctx = new Context()
  try {
    const provider = new MemoryProvider(ctx)
    assert.equal(provider.protection.assurance, 'software-local')
    assert.equal(provider.protection.hsmBacked, false)
    assert.throws(() => new MemoryProvider(ctx), /service "registryDisclosureKeyProvider" has been registered/u)
  } finally { await ctx.fiber.dispose() }
})
