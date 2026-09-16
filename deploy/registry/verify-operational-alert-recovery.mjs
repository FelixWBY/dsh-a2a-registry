#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:https'
import { isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DatabaseSync } from 'node:sqlite'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { createServer as createPortProbe } from 'node:net'

const FORMAT = 'dsh-registry-operational-alert-recovery-drill'
const VERSION = 1
const NAMESPACE = 'local-recovery-drill-v1'
const ORGANIZATION_ID = 'registry-alert-recovery-drill'
const MAX_BODY_BYTES = 8_192
const TIMEOUT_MS = 1_000
const LEASE_MS = 2_000
const RETRY_DELAY_MS = 200
const PROCESS_TIMEOUT_MS = 10_000
const SCRIPT_PATH = fileURLToPath(import.meta.url)
const REPOSITORY_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const TLS_FIXTURES = process.env.REGISTRY_DRILL_TLS_DIR

function fail(message) {
  throw new Error(`registry-alert-recovery-drill: ${message}`)
}

function absolutePath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`)
  }
  return value
}

function localEndpoint(value) {
  let endpoint
  try { endpoint = new URL(value) } catch { fail('worker endpoint must be an absolute URL') }
  if (endpoint.protocol !== 'https:' || endpoint.hostname !== '127.0.0.1'
    || endpoint.pathname !== '/registry' || endpoint.search !== '' || endpoint.hash !== '') {
    fail('worker endpoint must be an isolated loopback HTTPS Registry receiver')
  }
  return endpoint.href
}

function workerConfig(outboxPath, endpoint) {
  return {
    endpoint,
    maxPendingAlerts: 4,
    deliveryAttempts: 3,
    timeoutMs: TIMEOUT_MS,
    retryDelayMs: RETRY_DELAY_MS,
    outbox: {
      path: outboxPath,
      namespace: NAMESPACE,
      leaseMs: LEASE_MS,
      failedRetentionMs: 60_000,
      busyTimeoutMs: 1_000,
      journalMode: 'wal',
    },
  }
}

async function workerMain(mode, outboxInput, endpointInput) {
  const outboxPath = absolutePath(outboxInput, 'worker outbox path')
  const endpoint = localEndpoint(endpointInput)
  const [{ Context }, alerts] = await Promise.all([
    import('@deepseek-ai/cordis'),
    import('../../packages/bundle/registry-app/src/operational-alerts.ts'),
  ])
  const config = alerts.RegistryOperationalAlertsConfigSchema(workerConfig(outboxPath, endpoint))
  const exporter = new alerts.RegistryOperationalAlertExporter(new Context(), config)

  if (mode === 'accept') {
    exporter.reportStorageUnavailable(ORGANIZATION_ID)
    process.exit(0)
  }
  if (mode !== 'deliver') fail('unknown worker mode')

  const observer = new DatabaseSync(outboxPath, { readOnly: true })
  try {
    const deadline = Date.now() + PROCESS_TIMEOUT_MS
    while (Date.now() < deadline) {
      const row = observer.prepare(`SELECT COUNT(*) AS count FROM operational_alert_outbox
        WHERE namespace = ?`).get(NAMESPACE)
      if (row?.count === 0) {
        observer.close()
        await exporter.close()
        return
      }
      await new Promise(resolveWait => setTimeout(resolveWait, 20))
    }
    fail('delivery worker timed out')
  } finally {
    try { observer.close() } catch {
      // The worker result remains authoritative after an already closed observer.
    }
  }
}

function scrubbedEnvironment(extra) {
  const environment = {}
  for (const [name, value] of Object.entries(process.env)) {
    if (value !== undefined && !/(?:KEY|SECRET|TOKEN|PASSWORD)/iu.test(name)) environment[name] = value
  }
  return { ...environment, ...extra }
}

function startWorker(mode, outboxPath, endpoint, caPath) {
  const child = spawn(process.execPath,
    ['--import', 'tsx/esm', SCRIPT_PATH, '--worker', mode, outboxPath, endpoint], {
      cwd: REPOSITORY_ROOT,
      env: scrubbedEnvironment({ NODE_EXTRA_CA_CERTS: caPath }),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })
  let stdout = ''
  let stderr = ''
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', chunk => { if (stdout.length < MAX_BODY_BYTES) stdout += chunk })
  child.stderr.on('data', chunk => { if (stderr.length < MAX_BODY_BYTES) stderr += chunk })
  const done = new Promise((resolveDone, rejectDone) => {
    child.once('error', rejectDone)
    child.once('exit', (exitCode, signal) => resolveDone({ exitCode, signal, timedOut: false }))
  })
  return { child, done, output: () => ({ stdout, stderr }) }
}

async function timed(promise, milliseconds, label) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds) }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function stopWorker(worker) {
  if (worker.child.exitCode === null && worker.child.signalCode === null) worker.child.kill()
  return timed(worker.done, PROCESS_TIMEOUT_MS, 'worker termination')
}

async function reservePort() {
  const server = createPortProbe()
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') fail('could not reserve a loopback port')
  const port = address.port
  server.close()
  await once(server, 'close')
  return port
}

function outboxRow(path) {
  const database = new DatabaseSync(path, { readOnly: true })
  try {
    const check = database.prepare('PRAGMA quick_check').get()?.quick_check
    if (check !== 'ok') fail('outbox SQLite quick_check failed')
    const rows = database.prepare(`SELECT id, attempts, next_attempt_at, lease_token, lease_until, state
      FROM operational_alert_outbox WHERE namespace = ? ORDER BY created_at, id`).all(NAMESPACE)
    return { check, rows }
  } finally {
    database.close()
  }
}

function validatePayload(body) {
  let payload
  try { payload = JSON.parse(body) } catch { fail('receiver got invalid JSON') }
  const fields = Object.keys(payload).sort()
  const expectedFields = [
    'action', 'actorKind', 'category', 'disclosureId', 'occurredAt', 'operationId',
    'organizationId', 'severity', 'version',
  ].sort()
  if (JSON.stringify(fields) !== JSON.stringify(expectedFields)
    || payload.version !== 1 || payload.category !== 'storage-unavailable'
    || payload.severity !== 'critical' || payload.organizationId !== ORGANIZATION_ID
    || !Number.isSafeInteger(payload.occurredAt) || payload.occurredAt < 0
    || payload.operationId !== null || payload.action !== 'storage'
    || payload.disclosureId !== null || payload.actorKind !== 'unattributed') {
    fail('receiver got an unexpected metadata envelope')
  }
  return payload
}

function createReceiver(keyPath, certificatePath) {
  const observations = []
  const acceptedKeys = new Set()
  let firstResolve
  let firstReject
  let secondResolve
  let secondReject
  const first = new Promise((resolveFirst, rejectFirst) => {
    firstResolve = resolveFirst
    firstReject = rejectFirst
  })
  const second = new Promise((resolveSecond, rejectSecond) => {
    secondResolve = resolveSecond
    secondReject = rejectSecond
  })
  const sockets = new Set()
  const server = createServer({ key: readFileSync(keyPath), cert: readFileSync(certificatePath) },
    (request, response) => {
      const chunks = []
      let size = 0
      request.on('data', chunk => {
        size += chunk.length
        if (size > MAX_BODY_BYTES) request.destroy()
        else chunks.push(chunk)
      })
      request.on('end', () => {
        try {
          const body = Buffer.concat(chunks).toString('utf8')
          if (request.method !== 'POST' || request.url !== '/registry'
            || request.headers['content-type'] !== 'application/json; charset=utf-8'
            || request.headers.authorization !== undefined) {
            fail('receiver got unexpected request metadata')
          }
          validatePayload(body)
          const idempotencyKey = request.headers['idempotency-key']
          if (typeof idempotencyKey !== 'string'
            || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
              .test(idempotencyKey)) {
            fail('receiver got an invalid idempotency key')
          }
          const duplicate = acceptedKeys.has(idempotencyKey)
          acceptedKeys.add(idempotencyKey)
          const observation = Object.freeze({ idempotencyKey,
            bodySha256: createHash('sha256').update(body).digest('hex'), duplicate })
          observations.push(observation)
          if (observations.length === 1) {
            firstResolve(observation)
            return
          }
          if (observations.length === 2) {
            response.writeHead(204)
            response.end()
            secondResolve(observation)
            return
          }
          response.writeHead(409)
          response.end()
        } catch (error) {
          response.writeHead(400)
          response.end()
          firstReject(error)
          secondReject(error)
        }
      })
    })
  server.on('connection', socket => {
    sockets.add(socket)
    socket.once('close', () => sockets.delete(socket))
  })
  return { server, first, second, observations, acceptedKeys, sockets }
}

async function closeReceiver(receiver) {
  for (const socket of receiver.sockets) socket.destroy()
  if (!receiver.server.listening) return
  receiver.server.close()
  await once(receiver.server, 'close')
}

function assertCleanWorker(outcome, worker, label) {
  const output = worker.output()
  if (outcome.exitCode !== 0 || outcome.signal !== null || output.stdout.length !== 0
    || output.stderr.length !== 0) {
    fail(`${label} failed without a clean, silent exit`)
  }
}

async function main(destinationInput) {
  if (!TLS_FIXTURES || !isAbsolute(TLS_FIXTURES)) {
    fail('set REGISTRY_DRILL_TLS_DIR to an absolute directory containing isolated test ca.pem, server.pem and server-key.pem; server certificate must include IP SAN 127.0.0.1')
  }
  for (const name of ['ca.pem', 'server.pem', 'server-key.pem']) {
    if (!existsSync(join(TLS_FIXTURES, name))) fail(`missing isolated test TLS file: ${name}`)
  }
  const destination = absolutePath(destinationInput, 'artifact directory')
  if (existsSync(destination)) fail('artifact directory already exists')
  mkdirSync(destination, { recursive: true, mode: 0o700 })
  const outboxPath = join(destination, 'alert-outbox.sqlite')
  const resultPath = join(destination, 'result.json')
  const caPath = join(TLS_FIXTURES, 'ca.pem')
  const keyPath = join(TLS_FIXTURES, 'server-key.pem')
  const certificatePath = join(TLS_FIXTURES, 'server.pem')
  const port = await reservePort()
  const endpoint = `https://127.0.0.1:${port}/registry`
  let acceptanceWorker
  let interruptedWorker
  let recoveryWorker
  let receiver

  try {
    acceptanceWorker = startWorker('accept', outboxPath, endpoint, caPath)
    const acceptanceOutcome = await timed(acceptanceWorker.done, PROCESS_TIMEOUT_MS, 'acceptance worker')
    assertCleanWorker(acceptanceOutcome, acceptanceWorker, 'acceptance worker')
    const acceptedState = outboxRow(outboxPath)
    if (acceptedState.rows.length !== 1 || acceptedState.rows[0].state !== 'pending'
      || acceptedState.rows[0].attempts !== 0 || acceptedState.rows[0].lease_token !== null) {
      fail('alert was not durably accepted before process exit')
    }
    const acceptedId = acceptedState.rows[0].id

    receiver = createReceiver(keyPath, certificatePath)
    receiver.server.listen(port, '127.0.0.1')
    await once(receiver.server, 'listening')
    interruptedWorker = startWorker('deliver', outboxPath, endpoint, caPath)
    const firstDelivery = await timed(receiver.first, PROCESS_TIMEOUT_MS, 'first delivery')
    if (firstDelivery.idempotencyKey !== acceptedId || firstDelivery.duplicate) {
      fail('first delivery did not use the accepted outbox identity')
    }

    const interruptionOutcome = await stopWorker(interruptedWorker)
    const interruptedState = outboxRow(outboxPath)
    if (interruptedState.rows.length !== 1 || interruptedState.rows[0].id !== acceptedId
      || interruptedState.rows[0].state !== 'pending' || interruptedState.rows[0].attempts !== 0
      || typeof interruptedState.rows[0].lease_token !== 'string'
      || !Number.isSafeInteger(interruptedState.rows[0].lease_until)) {
      fail('interrupted delivery did not retain its leased durable row')
    }

    const waitMs = Math.max(0, interruptedState.rows[0].lease_until - Date.now() + 20)
    if (waitMs > LEASE_MS + 100) fail('persisted lease exceeds the configured recovery bound')
    await new Promise(resolveWait => setTimeout(resolveWait, waitMs))

    recoveryWorker = startWorker('deliver', outboxPath, endpoint, caPath)
    const secondDelivery = await timed(receiver.second, PROCESS_TIMEOUT_MS, 'recovered delivery')
    const recoveryOutcome = await timed(recoveryWorker.done, PROCESS_TIMEOUT_MS, 'recovery worker')
    assertCleanWorker(recoveryOutcome, recoveryWorker, 'recovery worker')
    if (secondDelivery.idempotencyKey !== acceptedId || !secondDelivery.duplicate
      || secondDelivery.bodySha256 !== firstDelivery.bodySha256
      || receiver.acceptedKeys.size !== 1 || receiver.observations.length !== 2) {
      fail('recovered delivery did not preserve receiver deduplication identity')
    }
    const finalState = outboxRow(outboxPath)
    if (finalState.rows.length !== 0) fail('recovered delivery did not acknowledge the durable row')

    const result = Object.freeze({
      format: FORMAT,
      version: VERSION,
      mode: 'test-only-loopback',
      completedAt: new Date().toISOString(),
      endpoint: { protocol: 'https:', host: '127.0.0.1', path: '/registry' },
      acceptance: { processExitCode: acceptanceOutcome.exitCode, durableRows: 1,
        idempotencyKeySha256: createHash('sha256').update(acceptedId).digest('hex') },
      interruption: { ...interruptionOutcome, inFlightLeaseRetained: true, attemptsPersisted: 0 },
      recovery: { processExitCode: recoveryOutcome.exitCode, deliveryAttemptsObserved: 2,
        uniqueIdempotencyKeysObserved: receiver.acceptedKeys.size, duplicateObserved: true,
        sameEnvelopeObserved: true, remainingOutboxRows: 0, sqliteQuickCheck: finalState.check },
    })
    writeFileSync(resultPath, `${JSON.stringify(result, undefined, 2)}\n`, { flag: 'wx', mode: 0o600 })
    process.stdout.write(`${JSON.stringify({ ...result, artifact: relative(REPOSITORY_ROOT, resultPath) })}\n`)
  } finally {
    if (acceptanceWorker !== undefined && acceptanceWorker.child.exitCode === null
      && acceptanceWorker.child.signalCode === null) await stopWorker(acceptanceWorker)
    if (recoveryWorker !== undefined && recoveryWorker.child.exitCode === null
      && recoveryWorker.child.signalCode === null) await stopWorker(recoveryWorker)
    if (interruptedWorker !== undefined && interruptedWorker.child.exitCode === null
      && interruptedWorker.child.signalCode === null) await stopWorker(interruptedWorker)
    if (receiver !== undefined) await closeReceiver(receiver)
  }
}

const arguments_ = process.argv.slice(2)
if (arguments_[0] === '--worker') {
  if (arguments_.length !== 4) fail('worker usage: --worker <accept|deliver> <absolute-outbox> <endpoint>')
  await workerMain(arguments_[1], arguments_[2], arguments_[3])
} else {
  if (arguments_.length !== 1) {
    fail('usage: node --import tsx/esm deploy/registry/verify-operational-alert-recovery.mjs '
      + '<absolute-artifact-directory>')
  }
  await main(arguments_[0])
}
