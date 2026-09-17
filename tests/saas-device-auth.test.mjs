import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import WebSocket from 'ws'
import { Context } from '@deepseek-ai/cordis'
import Storage from '@deepseek-ai/dsh-storage'
import * as jsonStorage from '@deepseek-ai/dsh-storage-json'
import * as storageDomain from '@deepseek-ai/dsh-storage-domain'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import {
  encodeRegistryDeviceToken,
  generateInstanceKeyPair,
  generateRegistryDeviceSecret,
  hashRegistryDeviceSecret,
  signDisclosureCheckpoint,
  signDisclosureEvent,
} from '@deepseek-ai/dsh-a2a-device-identity'
import { signRegistryChallenge } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import { computeDisclosureCiphertextHash } from '@deepseek-ai/dsh-a2a-protocol'
import {
  REGISTRY_SYNC_PATH,
  decodeRegistryServerFrame,
  encodeRegistryClientFrame,
} from '@deepseek-ai/dsh-a2a-registry-sync'
import { RegistryBindingProducerAuthenticator } from '@deepseek-ai/dsh-registry-app'
import { RegistrySaasImportRouter } from '@deepseek-ai/dsh-registry-app/src/saas-import-queue.ts'
import { RegistrySaasQuestionRouter } from '@deepseek-ai/dsh-registry-app/src/saas-question-mailbox.ts'
import { openRegistryTenantRuntime } from '@deepseek-ai/dsh-registry-app/src/ingest-runtime.ts'
import { installRegistrySync } from '@deepseek-ai/dsh-registry-app/src/sync.ts'

const MAX_FRAME_BYTES = 64 * 1024
const TIMEOUT_MS = 5_000
const AUDIENCE = `wss://registry.example${REGISTRY_SYNC_PATH}`
const MAILBOX_KEY = Buffer.alloc(32, 0x5a).toString('base64url')

class TestCredentials extends CredentialProvider {
  resolve(ref) {
    return Promise.resolve(ref === 'TEST_REGISTRY_MAILBOX_KEY'
      ? { value: MAILBOX_KEY, source: 'test' } : undefined)
  }
  describe(ref) { return Promise.resolve({ configured: ref === 'TEST_REGISTRY_MAILBOX_KEY', source: 'test', writable: false }) }
  set() { return Promise.reject(new Error('read only')) }
  unset() { return Promise.reject(new Error('read only')) }
  readRecord() { return Promise.resolve(undefined) }
  describeRecord() { return Promise.resolve({ configured: false, writable: false }) }
  listRecords() { return Promise.resolve([]) }
  modifyRecord() { return Promise.reject(new Error('read only')) }
}

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
    imports: {
      maxOperations: 8,
      maxRecordBytes: 4 * 1024,
      maxAuthorizationResponseBytes: MAX_FRAME_BYTES,
      maxDeliveryBytes: 8 * 1024,
      deliveryTimeoutMs: TIMEOUT_MS,
    },
    questions: {
      mailboxKeyEnv: 'TEST_REGISTRY_MAILBOX_KEY',
      maxAuthorizationResponseBytes: MAX_FRAME_BYTES,
      maxDeliveryBytes: 8 * 1024,
      operationTimeoutMs: TIMEOUT_MS,
      executionLeaseMs: TIMEOUT_MS,
      limits: {
        maxTextBytes: 4 * 1024,
        maxTextCharacters: 2 * 1024,
        maxCiphertextBytes: 8 * 1024,
        maxAggregateBytes: 16 * 1024,
        maxRequests: 16,
        maxRetainedRequests: 32,
        maxPendingOperations: 16,
        maxLifetimeMs: 60_000,
      },
      expiryMaintenance: { intervalMs: 10_000, maxItems: 8 },
    },
    sync: syncConfig(),
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

async function openAuthenticatedSocket(url, token, keyPair, expectedIdentity) {
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
    return socket
  } catch (error) {
    await closeSocket(socket)
    throw error
  }
}

test('SaaS device authentication is bound to the selected tenant runtime', { timeout: 30_000 }, async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-saas-device-auth-'))
  const ctx = new Context()
  const syncAbort = new AbortController()
  const runtimes = []
  let authenticator
  let stopSync
  let withdrawImportBroker
  let withdrawQuestionBroker
  try {
    await ctx.plugin(Storage)
    await ctx.plugin(jsonStorage, { root: join(home, 'storage') })
    await ctx.plugin(storageDomain, { backend: 'json' })
    await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0, compression: 'none' })
    new TestCredentials(ctx)

    const organizationA = 'tenant-a'
    const organizationB = 'tenant-b'
    const memberA = 'owner-a'
    const memberB = 'requester-b'
    let runtimeA = await openRegistryTenantRuntime(ctx, runtimeConfig(organizationA, memberA), {
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
      requestedScopes: ['disclosure.sync', 'a2a.receive'],
    })
    const authority = accountAuthority(organizationA, memberA)
    assert.ok(runtimeA.directory)
    assert.equal((await runtimeA.directory.change(authority, { kind: 'put-member', member: {
      memberId: memberB, displayName: 'Requester B', role: 'member', state: 'active',
    } }, 0)).revision, 1)
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
    const importRouter = new RegistrySaasImportRouter({
      acquireRuntime: async (organizationId) => {
        const runtime = byOrganization.get(organizationId)
        if (runtime === undefined) throw new Error('tenant unavailable')
        return { runtime, release() {} }
      },
    })
    const questionRouter = new RegistrySaasQuestionRouter({
      acquireRuntime: async (organizationId) => {
        const runtime = byOrganization.get(organizationId)
        if (runtime === undefined) throw new Error('tenant unavailable')
        return { runtime, release() {} }
      },
    })
    withdrawImportBroker = ctx.provide('registryImportBroker', importRouter)
    withdrawQuestionBroker = ctx.provide('registryQuestionBroker', questionRouter)
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

    const disclosureId = 'tenant-a-disclosure'
    const conversationId = 'tenant-a-conversation'
    const sourceCursor = 17
    const expiresAt = Date.now() + 60_000
    const ciphertext = Buffer.from('tenant-a-event-ciphertext', 'utf8').toString('base64url')
    const event = signDisclosureEvent({
      protocolVersion: 1,
      organizationId: organizationA,
      instanceId: ticket.challenge.instanceId,
      conversationId,
      disclosureId,
      eventId: 'tenant-a-event-1',
      disclosureSeq: 0,
      sourceCursor,
      eventType: 'conversation.user-message',
      policyVersion: 1,
      occurredAt: confirmed.state.confirmedAt,
      previousEventHash: null,
      ciphertext,
      ciphertextHash: computeDisclosureCiphertextHash(ciphertext),
    }, keyPair.privateKey)
    const checkpoint = signDisclosureCheckpoint({
      protocolVersion: 1,
      organizationId: organizationA,
      instanceId: ticket.challenge.instanceId,
      disclosureId,
      policyVersion: 1,
      sourceCursor,
      eventCount: 1,
      lastDisclosureSeq: 0,
      lastEventHash: event.eventHash,
    }, keyPair.privateKey)
    const oversizedDisclosureId = 'tenant-a-oversized-disclosure'
    const oversizedConversationId = 'tenant-a-oversized-conversation'
    const oversizedCiphertext = Buffer.alloc(12 * 1024, 0x61).toString('base64url')
    const oversizedEvent = signDisclosureEvent({
      protocolVersion: 1,
      organizationId: organizationA,
      instanceId: ticket.challenge.instanceId,
      conversationId: oversizedConversationId,
      disclosureId: oversizedDisclosureId,
      eventId: 'tenant-a-oversized-event-1',
      disclosureSeq: 0,
      sourceCursor,
      eventType: 'conversation.user-message',
      policyVersion: 1,
      occurredAt: confirmed.state.confirmedAt,
      previousEventHash: null,
      ciphertext: oversizedCiphertext,
      ciphertextHash: computeDisclosureCiphertextHash(oversizedCiphertext),
    }, keyPair.privateKey)
    const oversizedCheckpoint = signDisclosureCheckpoint({
      protocolVersion: 1,
      organizationId: organizationA,
      instanceId: ticket.challenge.instanceId,
      disclosureId: oversizedDisclosureId,
      policyVersion: 1,
      sourceCursor,
      eventCount: 1,
      lastDisclosureSeq: 0,
      lastEventHash: oversizedEvent.eventHash,
    }, keyPair.privateKey)

    const producerSocket = await openAuthenticatedSocket(url, token, keyPair, expectedIdentity)
    let publishedReceipt
    try {
      const registered = await exchange(producerSocket, 4, {
        type: 'producer-register',
        disclosureId,
        registration: {
          conversationId,
          policyVersion: 1,
          targets: [{ kind: 'member', memberId: memberA }, { kind: 'member', memberId: memberB }],
          expiresAt,
        },
      })
      assert.equal(registered.type, 'producer-register-ack')
      assert.equal(registered.status.kind, 'live')
      assert.deepEqual(registered.status.receipt, {
        disclosureId,
        lastDisclosureSeq: -1,
        lastEventHash: null,
        checkpointHash: null,
        authorizationVersion: 0,
        control: 'active',
        ingest: 'pending',
      })

      const acceptedEvent = await exchange(producerSocket, 5,
        { type: 'event', disclosureId, envelope: event })
      assert.equal(acceptedEvent.type, 'event-ack')
      assert.deepEqual(acceptedEvent.receipt, {
        disclosureId,
        lastDisclosureSeq: 0,
        lastEventHash: event.eventHash,
        checkpointHash: null,
        authorizationVersion: 0,
        control: 'active',
        ingest: 'pending',
      })

      const acceptedCheckpoint = await exchange(producerSocket, 6,
        { type: 'checkpoint', disclosureId, checkpoint })
      assert.equal(acceptedCheckpoint.type, 'checkpoint-ack')
      publishedReceipt = acceptedCheckpoint.receipt
      assert.deepEqual(publishedReceipt, {
        disclosureId,
        lastDisclosureSeq: 0,
        lastEventHash: event.eventHash,
        checkpointHash: checkpoint.checkpointHash,
        authorizationVersion: 0,
        control: 'active',
        ingest: 'ready',
        acceptedCheckpointHash: checkpoint.checkpointHash,
      })

      assert.equal((await exchange(producerSocket, 7, {
        type: 'producer-register',
        disclosureId: oversizedDisclosureId,
        registration: {
          conversationId: oversizedConversationId,
          policyVersion: 1,
          targets: [{ kind: 'member', memberId: memberA }, { kind: 'member', memberId: memberB }],
          expiresAt,
        },
      })).type, 'producer-register-ack')
      assert.equal((await exchange(producerSocket, 8,
        { type: 'event', disclosureId: oversizedDisclosureId, envelope: oversizedEvent })).type, 'event-ack')
      assert.equal((await exchange(producerSocket, 9,
        { type: 'checkpoint', disclosureId: oversizedDisclosureId,
          checkpoint: oversizedCheckpoint })).type, 'checkpoint-ack')
    } finally {
      await closeSocket(producerSocket)
    }

    const resumedSocket = await openAuthenticatedSocket(url, token, keyPair, expectedIdentity)
    try {
      const resumed = await exchange(resumedSocket, 4, { type: 'status', disclosureId })
      assert.equal(resumed.type, 'status')
      assert.equal(resumed.status.kind, 'live')
      assert.deepEqual(resumed.status.receipt, {
        disclosureId,
        lastDisclosureSeq: 0,
        lastEventHash: event.eventHash,
        checkpointHash: checkpoint.checkpointHash,
        authorizationVersion: 0,
        control: 'active',
        ingest: 'ready',
      })

      const replayedEvent = await exchange(resumedSocket, 5,
        { type: 'event', disclosureId, envelope: event })
      assert.equal(replayedEvent.type, 'event-ack')
      assert.deepEqual(replayedEvent.receipt, resumed.status.receipt)

      const replayedCheckpoint = await exchange(resumedSocket, 6,
        { type: 'checkpoint', disclosureId, checkpoint })
      assert.equal(replayedCheckpoint.type, 'checkpoint-ack')
      assert.deepEqual(replayedCheckpoint.receipt, publishedReceipt)
    } finally {
      await closeSocket(resumedSocket)
    }

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

    let externalHistoryCalls = 0
    const readerAuthorityFor = (memberId) => ({
      subject: {
        authenticated: true,
        organizationId: organizationA,
        memberId,
        membership: 'active',
        role: memberId === memberA ? 'owner' : 'member',
        currentTeamIds: [],
      },
      now: Date.now(),
      historyFor() {
        externalHistoryCalls += 1
        throw new Error('SaaS reads must not trust external key history')
      },
    })
    const readerAuthority = () => readerAuthorityFor(memberA)
    const metadata = await runtimeA.reader.readMetadata(readerAuthority, disclosureId, 'read',
      { checkpointHash: checkpoint.checkpointHash, maxResponseBytes: MAX_FRAME_BYTES })
    assert.equal(metadata.checkpoint.checkpointHash, checkpoint.checkpointHash)
    const page = await runtimeA.reader.list(readerAuthority,
      { pageSize: 8, maxPageSize: 8, maxResponseBytes: MAX_FRAME_BYTES })
    assert.deepEqual(page.items.map(item => item.disclosureId), [disclosureId, oversizedDisclosureId])
    const prefix = await runtimeA.reader.readPrefix(readerAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash)
    assert.equal(prefix.checkpoint.checkpointHash, checkpoint.checkpointHash)
    assert.equal(prefix.checkpoint.sourceCursor, sourceCursor)
    assert.deepEqual(prefix.events, [event])
    assert.equal(externalHistoryCalls, 0)

    const oversizedMetadata = await runtimeA.reader.readMetadata(readerAuthority, oversizedDisclosureId, 'read',
      { checkpointHash: oversizedCheckpoint.checkpointHash, maxResponseBytes: MAX_FRAME_BYTES })
    const selection = (selectedMetadata = metadata, selectedDisclosureId = disclosureId,
      selectedMemberId = memberA, selectedAction = 'import') => ({
      subject: readerAuthorityFor(selectedMemberId).subject,
      disclosure: selectedMetadata,
      listAuthorizedTargets: async (signal) => {
        signal.throwIfAborted()
        const bindings = await runtimeA.enrollment.list(authority, MAX_FRAME_BYTES)
        return bindings.filter(binding => binding.phase === 'confirmed'
          && binding.requestedScopes.includes('a2a.receive')).map(binding => ({
          instanceId: binding.instanceId,
          transport: binding.transport.kind,
          acceptingA2A: binding.transport.kind === 'connected' && binding.transport.report !== undefined
            ? binding.transport.report.acceptingA2A : null,
          activeRequests: binding.transport.kind === 'connected' && binding.transport.report !== undefined
            ? binding.transport.report.activeRequests : null,
        }))
      },
      authorizeTarget: async (targetInstanceId, signal) => {
        signal.throwIfAborted()
        const bindings = await runtimeA.enrollment.list(authority, MAX_FRAME_BYTES)
        const matches = bindings.filter(binding => binding.phase === 'confirmed'
          && binding.instanceId === targetInstanceId && binding.requestedScopes.includes('a2a.receive'))
        if (matches.length !== 1) throw new Error('target unavailable')
        return matches[0].transport
      },
      readAuthorizedPrefix: ({ sourceInstanceId, checkpointHash }, signal) => {
        signal.throwIfAborted()
        return runtimeA.reader.readPrefix(() => readerAuthorityFor(selectedMemberId), selectedDisclosureId,
          sourceInstanceId, selectedAction, checkpointHash)
      },
    })
    assert.ok(runtimeA.imports)
    assert.ok(runtimeA.questions)
    const importSignal = new AbortController().signal
    const targets = await runtimeA.imports.listImportTargets(selection(), importSignal)
    assert.deepEqual(targets, [{ instanceId: ticket.challenge.instanceId, transport: 'not-observed',
      acceptingA2A: null, activeRequests: null }])
    const oversizedImportInput = {
      targetInstanceId: ticket.challenge.instanceId, idempotencyKey: 'tenant-a-oversized-import-1',
    }
    const queuedOversizedImport = await runtimeA.imports.importDisclosure(
      selection(oversizedMetadata, oversizedDisclosureId), oversizedImportInput, importSignal)
    assert.equal(queuedOversizedImport.status, 'queued')
    assert.deepEqual(await runtimeA.imports.importDisclosure(
      selection(oversizedMetadata, oversizedDisclosureId), oversizedImportInput, importSignal), queuedOversizedImport)
    await assert.rejects(runtimeA.imports.importDisclosure({
      ...selection(oversizedMetadata, oversizedDisclosureId),
      disclosure: { ...oversizedMetadata, authorizationVersion: oversizedMetadata.authorizationVersion + 1 },
    }, oversizedImportInput, importSignal), error => error?.code === 'conflict')
    let misroutedDelivery = false
    const rejectMisroute = async () => {
      misroutedDelivery = true
      return { status: 'retry' }
    }
    const receiverAuthority = (organizationId, instanceId) => ({
      connection: { organizationId, instanceId, keyId: keyPair.keyId, now: Date.now() },
      history: { organizationId, instanceId, status: 'active', keys: [] },
    })
    assert.equal(await importRouter.dispatch(receiverAuthority(organizationB, ticket.challenge.instanceId),
      rejectMisroute, importSignal), false)
    assert.equal(await importRouter.dispatch(receiverAuthority(organizationA, 'different-target-instance'),
      rejectMisroute, importSignal), false)
    assert.equal(misroutedDelivery, false)

    const questionSelection = (selectedMetadata = metadata, selectedDisclosureId = disclosureId) =>
      selection(selectedMetadata, selectedDisclosureId, memberB, 'ask')
    const oversizedQuestionInput = {
      idempotencyKey: 'tenant-a-oversized-question-1', question: 'Summarize the large prefix.',
    }
    const queuedOversizedQuestion = await runtimeA.questions.askDisclosure(
      questionSelection(oversizedMetadata, oversizedDisclosureId), oversizedQuestionInput, importSignal)
    await new Promise(resolve => setTimeout(resolve, 2))
    const questionInput = { idempotencyKey: 'tenant-a-question-1', question: 'What changed?' }
    const abortedQuestion = new AbortController()
    const abortingSelection = questionSelection()
    await assert.rejects(runtimeA.questions.askDisclosure({ ...abortingSelection,
      readAuthorizedPrefix: async (_expected, operationSignal) => {
        abortedQuestion.abort()
        operationSignal.throwIfAborted()
      },
    }, { idempotencyKey: 'tenant-a-aborted-question', question: 'Do not persist this.' },
    abortedQuestion.signal), error => error?.code === 'closed')
    const [queuedQuestion, concurrentRetry] = await Promise.all([
      runtimeA.questions.askDisclosure(questionSelection(), questionInput, importSignal),
      runtimeA.questions.askDisclosure(questionSelection(), questionInput, importSignal),
    ])
    assert.equal(queuedQuestion.status, 'queued')
    assert.deepEqual(concurrentRetry, queuedQuestion)
    assert.deepEqual(await runtimeA.questions.askDisclosure(questionSelection(), questionInput, importSignal), queuedQuestion)
    await assert.rejects(runtimeA.questions.askDisclosure(questionSelection(), {
      ...questionInput, question: 'A different request under the same key',
    }, importSignal), error => error?.code === 'conflict')
    await assert.rejects(runtimeA.questions.askDisclosure({
      ...questionSelection(), disclosure: { ...metadata, authorizationVersion: metadata.authorizationVersion + 1 },
    }, questionInput, importSignal), error => error?.code === 'conflict')
    const cancelledQuestion = await runtimeA.questions.askDisclosure(questionSelection(), {
      idempotencyKey: 'tenant-a-question-cancel', question: 'Cancel this queued request.',
    }, importSignal)
    const questionScope = {
      subject: readerAuthorityFor(memberB).subject,
      selectDisclosure: async (selectedDisclosureId, sourceInstanceId, signal) => {
        signal.throwIfAborted()
        if (sourceInstanceId !== ticket.challenge.instanceId) throw new Error('unexpected source')
        return selectedDisclosureId === oversizedDisclosureId
          ? questionSelection(oversizedMetadata, oversizedDisclosureId) : questionSelection()
      },
    }
    const questionPage = await runtimeA.questions.listQuestions(questionScope,
      { pageSize: 8 }, importSignal)
    assert.deepEqual(new Set(questionPage.items.map(item => item.requestId)),
      new Set([queuedOversizedQuestion.requestId, queuedQuestion.requestId, cancelledQuestion.requestId]))
    assert.equal((await runtimeA.questions.cancelQuestion(questionSelection(),
      cancelledQuestion.requestId, importSignal)).status, 'cancelled')

    await runtimeA.close()
    runtimeA = await openRegistryTenantRuntime(ctx, runtimeConfig(organizationA, memberA), {
      storage: { domainName: 'saas_device_auth_a', tenantId: organizationA },
    })
    runtimes.push(runtimeA)
    byOrganization.set(organizationA, runtimeA)
    assert.ok(runtimeA.imports)
    assert.ok(runtimeA.questions)
    const restoredMetadata = await runtimeA.reader.readMetadata(readerAuthority, disclosureId, 'import',
      { checkpointHash: checkpoint.checkpointHash, maxResponseBytes: MAX_FRAME_BYTES })
    const restoredSelection = () => ({ ...selection(), disclosure: restoredMetadata })
    const restoredQuestionMetadata = await runtimeA.reader.readMetadata(() => readerAuthorityFor(memberB),
      disclosureId, 'ask', { checkpointHash: checkpoint.checkpointHash, maxResponseBytes: MAX_FRAME_BYTES })
    const restoredQuestionSelection = () => questionSelection(restoredQuestionMetadata)
    const restoredOversizedMetadata = await runtimeA.reader.readMetadata(readerAuthority,
      oversizedDisclosureId, 'import',
      { checkpointHash: oversizedCheckpoint.checkpointHash, maxResponseBytes: MAX_FRAME_BYTES })
    const restoredOversizedSelection = () => selection(restoredOversizedMetadata, oversizedDisclosureId)
    const restoredOversizedQuestionMetadata = await runtimeA.reader.readMetadata(
      () => readerAuthorityFor(memberB), oversizedDisclosureId, 'ask',
      { checkpointHash: oversizedCheckpoint.checkpointHash, maxResponseBytes: MAX_FRAME_BYTES })
    const restoredOversizedQuestionSelection = () =>
      questionSelection(restoredOversizedQuestionMetadata, oversizedDisclosureId)
    assert.deepEqual(await runtimeA.imports.readImport(restoredOversizedSelection(),
      queuedOversizedImport.operationId, importSignal), queuedOversizedImport)
    assert.deepEqual(await runtimeA.questions.readQuestion(restoredQuestionSelection(),
      queuedQuestion.requestId, importSignal), queuedQuestion)

    const receiverSocket = await openAuthenticatedSocket(url, token, keyPair, expectedIdentity)
    let queuedImport
    let sessionId
    try {
      const questionDispatch = await exchange(receiverSocket, 4, { type: 'question-dispatch' })
      assert.equal(questionDispatch.type, 'question-dispatch')
      assert.equal(questionDispatch.delivery.binding.requestId, queuedQuestion.requestId)
      assert.equal(questionDispatch.delivery.binding.organizationId, organizationA)
      assert.equal(questionDispatch.delivery.binding.requesterId, memberB)
      assert.equal(questionDispatch.delivery.binding.instanceId, ticket.challenge.instanceId)
      assert.equal(questionDispatch.delivery.question, questionInput.question)
      assert.equal(questionDispatch.delivery.receipt.questionHash,
        `sha256:${createHash('sha256').update(questionDispatch.delivery.question, 'utf8').digest('hex')}`)
      assert.equal(questionDispatch.delivery.receipt.replyHash, null)
      assert.equal(questionDispatch.delivery.prefix.checkpoint.checkpointHash, checkpoint.checkpointHash)
      const questionStarted = await exchange(receiverSocket, 5, {
        type: 'question-start', binding: questionDispatch.delivery.binding,
        expectedVersion: questionDispatch.delivery.receipt.version,
      })
      assert.equal(questionStarted.type, 'question-start')
      assert.equal(questionStarted.started, true)
      const questionAuthorized = await exchange(receiverSocket, 6, {
        type: 'question-authorize', binding: questionDispatch.delivery.binding,
        expectedVersion: questionDispatch.delivery.receipt.version,
      })
      assert.equal(questionAuthorized.type, 'question-authorized')
      assert.equal(questionAuthorized.delivery.question, questionInput.question)
      const questionReleased = await exchange(receiverSocket, 7, {
        type: 'question-authorize-release', authorizationRequestId: 6,
      })
      assert.equal(questionReleased.type, 'question-authorize-released')
      assert.equal(questionReleased.authorizationRequestId, 6)
      const questionCompleted = await exchange(receiverSocket, 8, {
        type: 'question-transition', binding: questionDispatch.delivery.binding,
        expectedVersion: questionStarted.receipt.version,
        transition: { state: 'completed', reply: 'Only the authorized prefix.' },
      })
      assert.equal(questionCompleted.type, 'question-transition')
      assert.equal(questionCompleted.receipt.state, 'completed')
      assert.equal((await runtimeA.questions.readQuestion(restoredOversizedQuestionSelection(),
        queuedOversizedQuestion.requestId, importSignal)).status, 'failed')

      const oversizedDispatch = await exchange(receiverSocket, 9, { type: 'import-dispatch' })
      assert.deepEqual(oversizedDispatch, {
        protocolVersion: 1, requestId: 9, type: 'import-dispatch', delivery: null,
      })
      assert.deepEqual(await runtimeA.imports.readImport(restoredOversizedSelection(),
        queuedOversizedImport.operationId, importSignal), {
        operationId: queuedOversizedImport.operationId, status: 'failed',
      })

      const importInput = { targetInstanceId: ticket.challenge.instanceId, idempotencyKey: 'tenant-a-import-1' }
      queuedImport = await runtimeA.imports.importDisclosure(restoredSelection(), importInput, importSignal)
      sessionId = `a2a-import-${createHash('sha256')
        .update(`${ticket.challenge.instanceId}\0${queuedImport.operationId}`, 'utf8').digest('hex')}`
      const dispatched = await exchange(receiverSocket, 10, { type: 'import-dispatch' })
      assert.equal(dispatched.type, 'import-dispatch')
      assert.equal(dispatched.delivery.operationId, queuedImport.operationId)
      assert.equal(dispatched.delivery.expectedSessionId, sessionId)
      assert.equal(dispatched.delivery.organizationId, organizationA)
      assert.equal(dispatched.delivery.targetInstanceId, ticket.challenge.instanceId)
      assert.equal(dispatched.delivery.checkpointHash, checkpoint.checkpointHash)
      assert.deepEqual(dispatched.delivery.prefix, prefix)
      const released = await exchange(receiverSocket, 11, {
        type: 'import-release',
        authorizationRequestId: 10,
        outcome: { status: 'completed', sessionId },
      })
      assert.equal(released.type, 'import-released')
      assert.equal(released.authorizationRequestId, 10)
    } finally {
      await closeSocket(receiverSocket)
    }
    const completedImport = await runtimeA.imports.readImport(restoredSelection(), queuedImport.operationId,
      importSignal)
    assert.deepEqual(completedImport, { operationId: queuedImport.operationId, status: 'completed', sessionId })
    assert.deepEqual(await runtimeA.imports.importDisclosure(restoredSelection(), {
      targetInstanceId: ticket.challenge.instanceId, idempotencyKey: 'tenant-a-import-1',
    }, importSignal),
      completedImport)
    assert.deepEqual(await runtimeA.questions.readQuestion(restoredQuestionSelection(), queuedQuestion.requestId,
      importSignal), {
      requestId: queuedQuestion.requestId,
      checkpointHash: checkpoint.checkpointHash,
      status: 'completed',
      reply: 'Only the authorized prefix.',
    })
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
    } }, 1)).revision, 2)
    const backupAuthority = accountAuthority(organizationA, backupOwner)
    assert.equal((await runtimeA.directory.change(backupAuthority, { kind: 'put-member', member: {
      memberId: memberA, displayName: `${organizationA} owner`, role: 'owner', state: 'suspended',
    } }, 2)).revision, 3)
    await assert.rejects(runtimeA.reader.readPrefix(legacyReaderAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash), error => error?.code === 'not-found')
    assert.equal(legacyHistoryCalls, 2)
    assert.equal((await runtimeA.directory.change(backupAuthority, { kind: 'put-member', member: {
      memberId: memberA, displayName: `${organizationA} owner`, role: 'owner', state: 'active',
    } }, 3)).revision, 4)

    assert.equal((await runtimeA.enrollment.revoke(authority, ticket.bindingId)).state.kind, 'revoked')
    await assert.rejects(runtimeA.reader.readPrefix(legacyReaderAuthority, disclosureId,
      ticket.challenge.instanceId, 'read', checkpoint.checkpointHash), error => error?.code === 'not-found')
    assert.equal(legacyHistoryCalls, 2)
  } finally {
    syncAbort.abort()
    await Promise.allSettled([stopSync?.()])
    await Promise.allSettled([authenticator?.close()])
    await Promise.allSettled([Promise.resolve().then(() => withdrawImportBroker?.())])
    await Promise.allSettled([Promise.resolve().then(() => withdrawQuestionBroker?.())])
    await Promise.allSettled(runtimes.map(runtime => runtime.close()))
    await ctx.fiber.dispose()
    await rm(home, { recursive: true, force: true })
  }
})
