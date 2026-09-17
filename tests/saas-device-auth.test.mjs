import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import WebSocket from 'ws'
import { Context } from '@deepseek-ai/cordis'
import Storage from '@deepseek-ai/dsh-storage'
import * as jsonStorage from '@deepseek-ai/dsh-storage-json'
import * as storageDomain from '@deepseek-ai/dsh-storage-domain'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import {
  encodeRegistryDeviceToken,
  generateInstanceKeyPair,
  generateRegistryDeviceSecret,
  hashRegistryDeviceSecret,
  signDisclosureCheckpoint,
} from '@deepseek-ai/dsh-a2a-device-identity'
import { signRegistryChallenge } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import {
  REGISTRY_SYNC_PATH,
  decodeRegistryServerFrame,
  encodeRegistryClientFrame,
} from '@deepseek-ai/dsh-a2a-registry-sync'
import { RegistryBindingProducerAuthenticator } from '@deepseek-ai/dsh-registry-app'
import { openRegistryTenantRuntime } from '@deepseek-ai/dsh-registry-app/src/ingest-runtime.ts'
import { installRegistrySync } from '@deepseek-ai/dsh-registry-app/src/sync.ts'

const MAX_FRAME_BYTES = 64 * 1024
const TIMEOUT_MS = 5_000
const AUDIENCE = `wss://registry.example${REGISTRY_SYNC_PATH}`

function waitForOpen(socket) {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('open', opened)
      socket.off('error', errored)
      if (error === undefined) resolve()
      else reject(error)
    }
    const timer = setTimeout(() => finish(new Error('WebSocket open timed out')), TIMEOUT_MS)
    const opened = () => finish()
    const errored = () => finish(new Error('WebSocket open failed'))
    socket.once('open', opened)
    socket.once('error', errored)
  })
}

function exchange(socket, requestId, request) {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (error, frame) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('message', received)
      socket.off('close', closed)
      socket.off('error', errored)
      if (error === undefined) resolve(frame)
      else reject(error)
    }
    const timer = setTimeout(() => finish(new Error(`${request.type} timed out`)), TIMEOUT_MS)
    const closed = () => finish(new Error(`WebSocket closed during ${request.type}`))
    const errored = () => finish(new Error(`WebSocket failed during ${request.type}`))
    const received = (data, binary) => {
      try {
        if (binary || !Buffer.isBuffer(data)) throw new Error('Registry returned a non-text frame')
        const frame = decodeRegistryServerFrame(data.toString('utf8'), MAX_FRAME_BYTES)
        assert.equal(frame.requestId, requestId)
        finish(undefined, frame)
      } catch (error) {
        finish(error instanceof Error ? error : new Error('Registry returned an invalid frame'))
      }
    }
    socket.once('message', received)
    socket.once('close', closed)
    socket.once('error', errored)
    const encoded = encodeRegistryClientFrame({ protocolVersion: 1, requestId, ...request }, MAX_FRAME_BYTES)
    socket.send(encoded, { binary: false }, (error) => {
      if (error != null) finish(new Error(`could not send ${request.type}: ${error.message}`))
    })
  })
}

async function closeSocket(socket) {
  if (socket.readyState === WebSocket.CLOSED) return
  await new Promise((resolve) => {
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('close', finish)
      socket.off('error', finish)
      resolve()
    }
    const timer = setTimeout(() => {
      socket.terminate()
      finish()
    }, 1_000)
    socket.once('close', finish)
    socket.once('error', finish)
    if (socket.readyState === WebSocket.CONNECTING) socket.terminate()
    else socket.close(1000, 'test complete')
  })
}

function runtimeConfig(organizationId, memberId) {
  return {
    organizationId,
    limits: {
      maxInputBytes: MAX_FRAME_BYTES,
      maxAggregateBytes: 256 * 1024,
      maxEvents: 32,
      maxCheckpoints: 8,
      maxDisclosures: 8,
      maxAuditEntries: 32,
    },
    directory: {
      maxMembers: 8,
      maxTeams: 8,
      maxTeamMembers: 8,
      maxNameBytes: 128,
      maxBytes: MAX_FRAME_BYTES,
      bootstrapOwner: { memberId, displayName: `${organizationId} owner` },
    },
    bindings: {
      audience: AUDIENCE,
      ttlMs: 60_000,
      maxRecordBytes: 16 * 1024,
      maxBindings: 8,
      maxNameBytes: 128,
    },
  }
}

function syncConfig() {
  const requests = { capacity: 100, refillPerSecond: 100 }
  const bytes = { capacity: MAX_FRAME_BYTES * 100, refillPerSecond: MAX_FRAME_BYTES * 100 }
  const frames = { requests, bytes }
  const scoped = { maxEntries: 32, requests, bytes }
  return {
    audience: AUDIENCE,
    tlsTermination: 'loopback-proxy',
    maxConnections: 8,
    maxFrameBytes: MAX_FRAME_BYTES,
    maxSendBufferBytes: MAX_FRAME_BYTES * 2,
    handshakeTimeoutMs: TIMEOUT_MS,
    idleTimeoutMs: TIMEOUT_MS * 2,
    admission: {
      upgrades: { capacity: 20, refillPerSecond: 20 },
      frames,
      handshakes: { capacity: 20, refillPerSecond: 20 },
      organizations: scoped,
      instances: scoped,
      disclosures: scoped,
    },
  }
}

function accountAuthority(organizationId, memberId) {
  return () => ({ subject: { authenticated: true, organizationId, memberId }, now: Date.now() })
}

async function authenticate(url, token, keyPair, expectedIdentity) {
  const socket = new WebSocket(url)
  socket.on('error', () => {})
  await waitForOpen(socket)
  try {
    const challengeFrame = await exchange(socket, 1, { type: 'hello', token })
    assert.equal(challengeFrame.type, 'challenge')
    assert.equal(challengeFrame.challenge.audience, AUDIENCE)
    assert.equal(challengeFrame.challenge.organizationId, expectedIdentity.organizationId)
    assert.equal(challengeFrame.challenge.instanceId, expectedIdentity.instanceId)
    assert.equal(challengeFrame.challenge.keyId, expectedIdentity.keyId)

    const authenticated = await exchange(socket, 2, {
      type: 'prove',
      signature: signRegistryChallenge(challengeFrame.challenge, keyPair.privateKey),
    })
    assert.equal(authenticated.type, 'authenticated')
    assert.deepEqual(authenticated.identity, expectedIdentity)

    const heartbeat = await exchange(socket, 3, { type: 'heartbeat' })
    assert.equal(heartbeat.type, 'heartbeat-ack')
    assert.ok(Number.isSafeInteger(heartbeat.observedAt) && heartbeat.observedAt >= 0)
  } finally {
    await closeSocket(socket)
  }
}

test('SaaS device authentication is bound to the selected tenant runtime', { timeout: 30_000 }, async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-saas-device-auth-'))
  const ctx = new Context()
  const syncAbort = new AbortController()
  const runtimes = []
  let authenticator
  let stopSync
  try {
    await ctx.plugin(Storage)
    await ctx.plugin(jsonStorage, { root: join(home, 'storage') })
    await ctx.plugin(storageDomain, { backend: 'json' })
    await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0, compression: 'none' })

    const organizationA = 'tenant-a'
    const organizationB = 'tenant-b'
    const memberA = 'owner-a'
    const runtimeA = await openRegistryTenantRuntime(ctx, runtimeConfig(organizationA, memberA), {
      storage: { domainName: 'saas_device_auth_a', tenantId: organizationA },
    })
    const runtimeB = await openRegistryTenantRuntime(ctx, runtimeConfig(organizationB, 'owner-b'), {
      storage: { domainName: 'saas_device_auth_b', tenantId: organizationB },
    })
    runtimes.push(runtimeA, runtimeB)
    assert.ok(runtimeA.enrollment)

    const keyPair = generateInstanceKeyPair()
    const secret = generateRegistryDeviceSecret()
    const ticket = await runtimeA.enrollment.start({
      publicKeySpki: keyPair.publicKeySpki,
      deviceSecretHash: hashRegistryDeviceSecret(secret),
      instanceName: 'Tenant A producer',
      requestedScopes: ['disclosure.sync'],
    })
    const authority = accountAuthority(organizationA, memberA)
    assert.equal((await runtimeA.enrollment.approve(authority, ticket.bindingId, ticket.code,
      'Tenant A producer')).state.kind, 'approved')
    const confirmed = await runtimeA.enrollment.confirm(ticket.bindingId,
      signRegistryChallenge(ticket.challenge, keyPair.privateKey))
    assert.equal(confirmed.state.kind, 'confirmed')

    const byOrganization = new Map([
      [organizationA, runtimeA],
      [organizationB, runtimeB],
    ])
    const resolveRuntime = async (organizationId) => {
      const runtime = byOrganization.get(organizationId)
      if (runtime === undefined) throw new Error('tenant unavailable')
      return { store: runtime.store, release() {} }
    }
    const config = syncConfig()
    authenticator = new RegistryBindingProducerAuthenticator(ctx, {
      audience: config.audience,
      handshakeTimeoutMs: config.handshakeTimeoutMs,
      maxFrameBytes: config.maxFrameBytes,
    }, resolveRuntime)
    stopSync = installRegistrySync(ctx, config, authenticator, resolveRuntime, syncAbort.signal)

    const url = `ws://127.0.0.1:${ctx.webServer.port}${REGISTRY_SYNC_PATH}`
    const token = encodeRegistryDeviceToken({ organizationId: organizationA, bindingId: ticket.bindingId, secret })
    const expectedIdentity = {
      organizationId: organizationA,
      instanceId: ticket.challenge.instanceId,
      keyId: keyPair.keyId,
    }
    await authenticate(url, token, keyPair, expectedIdentity)
    await authenticate(url, token, keyPair, expectedIdentity)

    const wrongTenantToken = encodeRegistryDeviceToken({
      organizationId: organizationB,
      bindingId: ticket.bindingId,
      secret,
    })
    const socket = new WebSocket(url)
    socket.on('error', () => {})
    await waitForOpen(socket)
    try {
      const response = await exchange(socket, 1, { type: 'hello', token: wrongTenantToken })
      assert.equal(response.type, 'error')
      assert.equal(response.code, 'unauthorized')
    } finally {
      await closeSocket(socket)
    }

    const now = Date.now()
    const disclosureId = 'tenant-a-disclosure'
    const history = {
      organizationId: organizationA,
      instanceId: ticket.challenge.instanceId,
      status: 'active',
      keys: [{
        keyId: keyPair.keyId,
        publicKeySpki: keyPair.publicKeySpki,
        validFrom: confirmed.state.confirmedAt,
        validUntil: null,
        revokedAt: null,
      }],
    }
    const producerAuthority = () => ({
      connection: {
        organizationId: organizationA,
        instanceId: ticket.challenge.instanceId,
        keyId: keyPair.keyId,
        now: Date.now(),
      },
      history,
    })
    await runtimeA.control.register(producerAuthority, {
      conversationId: 'tenant-a-conversation',
      policyVersion: 1,
      access: {
        organizationId: organizationA,
        instanceId: ticket.challenge.instanceId,
        disclosureId,
        control: 'active',
        producer: 'idle',
        ingest: 'pending',
        expiresAt: now + 60_000,
        authorizationVersion: 0,
        capabilities: ['conversation.read'],
        checkpointHash: null,
        grants: [{
          target: { kind: 'member', memberId: memberA },
          state: 'active',
          capabilities: ['conversation.read'],
          expiresAt: now + 60_000,
        }],
      },
    })
    const checkpoint = signDisclosureCheckpoint({
      protocolVersion: 1,
      organizationId: organizationA,
      instanceId: ticket.challenge.instanceId,
      disclosureId,
      policyVersion: 1,
      sourceCursor: 0,
      eventCount: 0,
      lastDisclosureSeq: -1,
      lastEventHash: null,
    }, keyPair.privateKey)
    await runtimeA.store.run(ingest => ingest.ingestCheckpoint(producerAuthority, disclosureId, checkpoint))

    let externalHistoryCalls = 0
    const readerAuthority = () => ({
      subject: {
        authenticated: true,
        organizationId: organizationA,
        memberId: memberA,
        membership: 'active',
        role: 'owner',
        currentTeamIds: [],
      },
      now: Date.now(),
      historyFor() {
        externalHistoryCalls += 1
        throw new Error('SaaS reads must not trust external key history')
      },
    })
    const metadata = await runtimeA.reader.readMetadata(readerAuthority, disclosureId, 'read',
      { checkpointHash: checkpoint.checkpointHash, maxResponseBytes: MAX_FRAME_BYTES })
    assert.equal(metadata.checkpoint.checkpointHash, checkpoint.checkpointHash)
    const page = await runtimeA.reader.list(readerAuthority,
      { pageSize: 8, maxPageSize: 8, maxResponseBytes: MAX_FRAME_BYTES })
    assert.deepEqual(page.items.map(item => item.disclosureId), [disclosureId])
    const prefix = await runtimeA.reader.readPrefix(readerAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash)
    assert.equal(prefix.checkpoint.checkpointHash, checkpoint.checkpointHash)
    assert.deepEqual(prefix.events, [])
    assert.equal(externalHistoryCalls, 0)
    await assert.rejects(runtimeA.reader.readPrefix(readerAuthority, disclosureId,
      'different-source-instance', 'read', checkpoint.checkpointHash), error => error?.code === 'not-found')
    assert.equal(externalHistoryCalls, 0)

    const duplicateBindingId = '00000000-0000-4000-8000-000000000001'
    await runtimeA.store.run(async (ingest) => {
      const domain = ingest.domain
      const original = domain.table('bindings').get(ticket.bindingId)
      assert.ok(original)
      assert.equal(typeof domain.putMany, 'function')
      await domain.putMany([{ table: 'bindings', key: duplicateBindingId,
        value: { ...original, bindingId: duplicateBindingId } }])
    })
    await assert.rejects(runtimeA.reader.readPrefix(readerAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash), error => error?.code === 'not-found')
    assert.equal(externalHistoryCalls, 0)
    await runtimeA.store.run(async (ingest) => {
      assert.equal(await ingest.domain.table('bindings').delete(duplicateBindingId), true)
    })

    await runtimeA.store.run(async (ingest) => {
      const domain = ingest.domain
      const original = domain.table('bindings').get(ticket.bindingId)
      assert.equal(original?.version, 5)
      const { deviceSecretHash: _deviceSecretHash, ...legacy } = original
      await domain.putMany([{ table: 'bindings', key: ticket.bindingId, value: { ...legacy, version: 4 } }])
    })
    let legacyHistoryCalls = 0
    const legacyReaderAuthority = () => ({
      ...readerAuthority(),
      historyFor(instanceId) {
        legacyHistoryCalls += 1
        return instanceId === history.instanceId ? history : null
      },
    })
    assert.equal((await runtimeA.reader.readPrefix(legacyReaderAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash)).checkpoint.checkpointHash,
    checkpoint.checkpointHash)
    assert.equal(legacyHistoryCalls, 1)
    const mismatchedLegacyAuthority = () => ({
      ...readerAuthority(),
      historyFor() {
        legacyHistoryCalls += 1
        return { ...history, instanceId: 'different-source-instance' }
      },
    })
    await assert.rejects(runtimeA.reader.readPrefix(mismatchedLegacyAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash), error => error?.code === 'not-found')
    assert.equal(legacyHistoryCalls, 2)

    assert.ok(runtimeA.directory)
    const backupOwner = 'owner-backup'
    assert.equal((await runtimeA.directory.change(authority, { kind: 'put-member', member: {
      memberId: backupOwner, displayName: 'Backup owner', role: 'owner', state: 'active',
    } }, 0)).revision, 1)
    const backupAuthority = accountAuthority(organizationA, backupOwner)
    assert.equal((await runtimeA.directory.change(backupAuthority, { kind: 'put-member', member: {
      memberId: memberA, displayName: `${organizationA} owner`, role: 'owner', state: 'suspended',
    } }, 1)).revision, 2)
    await assert.rejects(runtimeA.reader.readPrefix(legacyReaderAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash), error => error?.code === 'not-found')
    assert.equal(legacyHistoryCalls, 2)
    assert.equal((await runtimeA.directory.change(backupAuthority, { kind: 'put-member', member: {
      memberId: memberA, displayName: `${organizationA} owner`, role: 'owner', state: 'active',
    } }, 2)).revision, 3)

    assert.equal((await runtimeA.enrollment.revoke(authority, ticket.bindingId)).state.kind, 'revoked')
    await assert.rejects(runtimeA.reader.readPrefix(legacyReaderAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash), error => error?.code === 'not-found')
    assert.equal(legacyHistoryCalls, 2)
  } finally {
    syncAbort.abort()
    await Promise.allSettled([stopSync?.()])
    await Promise.allSettled([authenticator?.close()])
    await Promise.allSettled(runtimes.map(runtime => runtime.close()))
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})
