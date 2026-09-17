#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { accessSync, constants, mkdtempSync, realpathSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { brandString } from '@deepseek-ai/dsh-brand'
import { generateInstanceKeyPair, signDisclosureCheckpoint,
  signDisclosureEvent } from '@deepseek-ai/dsh-a2a-device-identity'
import {
  decodeRegistryClientFrame,
  encodeRegistryServerFrame,
} from '@deepseek-ai/dsh-a2a-registry-sync'

const MAX_FRAME_BYTES = 1_048_576
const CHILD_TIMEOUT_MS = 30_000
const CHILD_MAX_BUFFER_BYTES = 16 * 1024 * 1024
const USAGE = 'usage: node --import tsx/esm deploy/registry/verify-harness-compatibility.mjs'
  + ' --harness-root <path> --node-path <path> --overlay <path> --publication-overlay <path>'

class CompatibilityUsageError extends Error {}
class CompatibilityFailure extends Error {}

function fail(message) {
  throw new CompatibilityFailure(message)
}

/** Parse the four explicit trust-boundary inputs without accepting ambient defaults. */
export function parseCompatibilityArguments(args) {
  const allowed = new Set(['--harness-root', '--node-path', '--overlay', '--publication-overlay'])
  const values = new Map()
  if (args.length % 2 !== 0) throw new CompatibilityUsageError(USAGE)
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]
    const value = args[index + 1]
    if (!allowed.has(name) || typeof value !== 'string' || value.trim().length === 0 || values.has(name)) {
      throw new CompatibilityUsageError(USAGE)
    }
    values.set(name, value)
  }
  if (values.size !== allowed.size || [...allowed].some(name => !values.has(name))) {
    throw new CompatibilityUsageError(USAGE)
  }
  return {
    harnessRoot: resolve(values.get('--harness-root')),
    nodePath: resolve(values.get('--node-path')),
    overlayPath: resolve(values.get('--overlay')),
    publicationOverlayPath: resolve(values.get('--publication-overlay')),
  }
}

function requireDirectory(path, label) {
  try {
    accessSync(path, constants.R_OK)
    if (!statSync(path).isDirectory()) throw new Error()
  } catch { throw new CompatibilityUsageError(`${label} is not a readable directory: ${path}`) }
}

function requireFile(path, label, executable = false) {
  try {
    accessSync(path, constants.R_OK | (executable ? constants.X_OK : 0))
    if (!statSync(path).isFile()) throw new Error()
  } catch { throw new CompatibilityUsageError(`${label} is not a readable file: ${path}`) }
}

function systemEnvironment(extra = {}) {
  const names = process.platform === 'win32'
    ? ['Path', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP']
    : ['PATH', 'TMPDIR', 'TEMP', 'TMP']
  const environment = Object.fromEntries(names.flatMap((name) => {
    const value = process.env[name]
    return value === undefined ? [] : [[name, value]]
  }))
  return { ...environment, ...extra }
}

function firstDiagnostic(result) {
  const line = String(result.stderr ?? '').trim().split(/\r?\n/u)[0]
  return line === undefined || line === '' ? '' : `: ${line.slice(0, 500)}`
}

function runTargetNode(nodePath, args, options, label) {
  const result = spawnSync(nodePath, args, {
    cwd: options.cwd,
    env: options.env ?? systemEnvironment(),
    input: options.input,
    encoding: 'utf8',
    timeout: CHILD_TIMEOUT_MS,
    maxBuffer: CHILD_MAX_BUFFER_BYTES,
  })
  if (result.error !== undefined) fail(`${label} could not run: ${result.error.message}`)
  if (result.status !== 0) fail(`${label} failed${firstDiagnostic(result)}`)
  return result.stdout
}

function requireTargetNode(nodePath, harnessRoot) {
  const output = runTargetNode(nodePath, ['-p', 'process.versions.node'], {
    cwd: harnessRoot,
    env: systemEnvironment(),
  }, 'target Node.js version check').trim()
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(output)
  if (match === null || Number(match[1]) < 24) fail('target Node.js must be version 24 or newer')
}

/** Build one internally consistent disclosure, mailbox and import fixture set. */
function operationFixtures() {
  const key = generateInstanceKeyPair()
  const organizationId = brandString('compatibility-organization')
  const sourceInstanceId = brandString('compatibility-source')
  const targetInstanceId = brandString('compatibility-target')
  const disclosureId = brandString('compatibility-disclosure')
  const conversationId = brandString('compatibility-conversation')
  const plaintext = 'registry-harness-wire-compatibility'
  const ciphertext = Buffer.from(plaintext, 'utf8').toString('base64url')
  const envelope = signDisclosureEvent({
    protocolVersion: 1,
    organizationId,
    instanceId: sourceInstanceId,
    conversationId,
    disclosureId,
    eventId: brandString('compatibility-event'),
    disclosureSeq: 0,
    sourceCursor: 1,
    eventType: 'conversation.user-message',
    policyVersion: 1,
    occurredAt: 1,
    previousEventHash: null,
    ciphertext,
    ciphertextHash: brandString(`sha256:${createHash('sha256').update(plaintext, 'utf8').digest('hex')}`),
  }, key.privateKey)
  const checkpoint = signDisclosureCheckpoint({
    protocolVersion: 1,
    organizationId,
    instanceId: sourceInstanceId,
    disclosureId,
    policyVersion: 1,
    sourceCursor: 1,
    eventCount: 1,
    lastDisclosureSeq: 0,
    lastEventHash: envelope.eventHash,
  }, key.privateKey)
  const pendingReceipt = {
    disclosureId,
    lastDisclosureSeq: -1,
    lastEventHash: null,
    checkpointHash: null,
    authorizationVersion: 0,
    control: 'active',
    ingest: 'pending',
  }
  const eventReceipt = {
    ...pendingReceipt,
    lastDisclosureSeq: 0,
    lastEventHash: envelope.eventHash,
  }
  const readyReceipt = {
    disclosureId,
    lastDisclosureSeq: 0,
    lastEventHash: envelope.eventHash,
    checkpointHash: checkpoint.checkpointHash,
    authorizationVersion: 0,
    control: 'active',
    ingest: 'ready',
  }
  const prefix = { authorizationVersion: 0, conversationId, checkpoint, events: [envelope] }
  const source = { instanceName: 'Compatibility Harness', conversationTitle: 'Compatibility conversation' }
  const binding = {
    requestId: 'compatibility-question',
    organizationId,
    disclosureId,
    requesterId: 'compatibility-member',
    instanceId: sourceInstanceId,
    checkpointHash: checkpoint.checkpointHash,
    authorizationVersion: 0,
    expiresAt: 4_102_444_800_000,
  }
  const question = 'What is the disclosed compatibility context?'
  const questionHash = `sha256:${createHash('sha256').update(question, 'utf8').digest('hex')}`
  const reply = 'Only the authorized plaintext prefix.'
  const replyHash = `sha256:${createHash('sha256').update(reply, 'utf8').digest('hex')}`
  const mailboxReceipt = (state, version, selectedReplyHash = null) => ({
    binding,
    state,
    version,
    authorizationVersion: 0,
    questionHash,
    replyHash: selectedReplyHash,
    updatedAt: 100 + version,
  })
  const deliveredReceipt = mailboxReceipt('delivered', 2)
  const questionDelivery = { binding, receipt: deliveredReceipt, question, prefix, source }
  const importDelivery = {
    operationId: 'compatibility-operation',
    targetInstanceId,
    organizationId,
    disclosureId,
    sourceInstanceId,
    checkpointHash: checkpoint.checkpointHash,
    prefix,
    source,
  }
  return {
    organizationId,
    sourceInstanceId,
    targetInstanceId,
    disclosureId,
    conversationId,
    envelope,
    checkpoint,
    pendingReceipt,
    eventReceipt,
    readyReceipt,
    registration: {
      conversationId,
      policyVersion: 1,
      targets: [{ kind: 'member', memberId: 'compatibility-member' }],
      expiresAt: 4_102_444_800_000,
    },
    binding,
    questionDelivery,
    runningReceipt: mailboxReceipt('running', 3),
    completedReceipt: mailboxReceipt('completed', 4, replyHash),
    failedReceipt: mailboxReceipt('failed', 4),
    reply,
    importDelivery,
  }
}

/** Build Registry-encoded server frames and unencoded Harness client frames for both codec directions. */
export function wireFixtures() {
  const operations = operationFixtures()
  const organizationId = 'compatibility-organization'
  const instanceId = 'compatibility-target'
  const keyId = `sha256:${'1'.repeat(64)}`
  const challenge = {
    version: 1,
    audience: 'wss://registry.invalid/a2a/v1/sync',
    organizationId,
    instanceId,
    keyId,
    nonce: Buffer.alloc(32, 2).toString('base64url'),
    expiresAt: 4_102_444_800_000,
  }
  const frame = (requestId, value) => ({ protocolVersion: 1, requestId, ...value })
  const live = {
    kind: 'live',
    observedAt: 100,
    expiresAt: 4_102_444_800_000,
    receipt: operations.pendingReceipt,
  }
  const serverFrameValues = [
    frame(1, { type: 'challenge', challenge }),
    frame(2, { type: 'authenticated', identity: { organizationId, instanceId, keyId } }),
    frame(3, { type: 'heartbeat-ack', observedAt: 1 }),
    frame(4, { type: 'producer-register-ack', status: live }),
    frame(5, { type: 'event-ack', receipt: operations.eventReceipt }),
    frame(6, { type: 'checkpoint-ack',
      receipt: { ...operations.readyReceipt, acceptedCheckpointHash: operations.checkpoint.checkpointHash } }),
    frame(7, { type: 'import-dispatch', delivery: operations.importDelivery }),
    frame(8, { type: 'import-released', authorizationRequestId: 7 }),
    frame(9, { type: 'question-dispatch', delivery: operations.questionDelivery }),
    frame(10, { type: 'question-start', receipt: operations.runningReceipt,
      started: true, renewAfterMs: 1_000 }),
    frame(11, { type: 'question-transition', receipt: operations.runningReceipt }),
    frame(12, { type: 'question-transition', receipt: operations.completedReceipt }),
    frame(13, { type: 'question-transition', receipt: operations.failedReceipt }),
    frame(14, { type: 'question-authorized', delivery: operations.questionDelivery }),
    frame(15, { type: 'question-authorize-released', authorizationRequestId: 14 }),
  ]
  const serverFrames = serverFrameValues.map(value => {
    try {
      return encodeRegistryServerFrame(value, MAX_FRAME_BYTES)
    } catch {
      fail(`Registry could not encode the representative ${value.type} server frame`)
    }
  })
  const clientFrames = [
    frame(1, { type: 'hello', token: 'compatibility-noncredential-token' }),
    frame(2, { type: 'prove', signature: Buffer.alloc(64, 3).toString('base64url') }),
    frame(3, { type: 'heartbeat', report: { state: 'online', acceptingA2A: false, activeRequests: 0 } }),
    frame(4, { type: 'producer-register', disclosureId: operations.disclosureId,
      registration: operations.registration }),
    frame(5, { type: 'event', disclosureId: operations.disclosureId, envelope: operations.envelope }),
    frame(6, { type: 'checkpoint', disclosureId: operations.disclosureId, checkpoint: operations.checkpoint }),
    frame(7, { type: 'import-dispatch' }),
    frame(8, { type: 'import-release', authorizationRequestId: 7,
      outcome: { status: 'completed', sessionId: 'compatibility-import-session' } }),
    frame(9, { type: 'import-release', authorizationRequestId: 7, outcome: { status: 'retry' } }),
    frame(10, { type: 'question-dispatch' }),
    frame(11, { type: 'question-start', binding: operations.binding, expectedVersion: 2 }),
    frame(12, { type: 'question-transition', binding: operations.binding, expectedVersion: 3,
      transition: { state: 'running' } }),
    frame(13, { type: 'question-transition', binding: operations.binding, expectedVersion: 3,
      transition: { state: 'completed', reply: operations.reply } }),
    frame(14, { type: 'question-transition', binding: operations.binding, expectedVersion: 3,
      transition: { state: 'failed' } }),
    frame(15, { type: 'question-authorize', binding: operations.binding, expectedVersion: 2 }),
    frame(16, { type: 'question-authorize-release', authorizationRequestId: 15 }),
  ]
  return { serverFrames, clientFrames }
}

const codecProbe = specifier => String.raw`
  import { decodeRegistryServerFrame, encodeRegistryClientFrame } from ${JSON.stringify(specifier)}
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  const decoded = input.serverFrames.map(frame => decodeRegistryServerFrame(frame, ${MAX_FRAME_BYTES}))
  if (decoded.length !== 15
    || decoded[0].type !== 'challenge'
    || decoded[0].challenge.organizationId !== 'compatibility-organization'
    || decoded[0].challenge.instanceId !== 'compatibility-target'
    || decoded[1].type !== 'authenticated'
    || decoded[1].identity.instanceId !== 'compatibility-target'
    || decoded[2].type !== 'heartbeat-ack'
    || decoded[2].observedAt !== 1
    || decoded[3].type !== 'producer-register-ack'
    || decoded[3].status.kind !== 'live'
    || decoded[3].status.receipt.disclosureId !== 'compatibility-disclosure'
    || decoded[4].type !== 'event-ack'
    || decoded[4].receipt.lastDisclosureSeq !== 0
    || decoded[5].type !== 'checkpoint-ack'
    || decoded[5].receipt.acceptedCheckpointHash !== decoded[5].receipt.checkpointHash
    || decoded[6].type !== 'import-dispatch'
    || decoded[6].delivery === null
    || decoded[6].delivery.operationId !== 'compatibility-operation'
    || decoded[6].delivery.targetInstanceId !== 'compatibility-target'
    || decoded[7].type !== 'import-released'
    || decoded[7].authorizationRequestId !== 7
    || decoded[8].type !== 'question-dispatch'
    || decoded[8].delivery === null
    || decoded[8].delivery.binding.requestId !== 'compatibility-question'
    || decoded[8].delivery.question !== 'What is the disclosed compatibility context?'
    || decoded[9].type !== 'question-start'
    || decoded[9].receipt.state !== 'running'
    || decoded[10].type !== 'question-transition'
    || decoded[10].receipt.state !== 'running'
    || decoded[11].type !== 'question-transition'
    || decoded[11].receipt.state !== 'completed'
    || decoded[11].receipt.replyHash === null
    || decoded[12].type !== 'question-transition'
    || decoded[12].receipt.state !== 'failed'
    || decoded[13].type !== 'question-authorized'
    || decoded[13].delivery.binding.requestId !== 'compatibility-question'
    || decoded[14].type !== 'question-authorize-released'
    || decoded[14].authorizationRequestId !== 14) process.exit(3)
  process.stdout.write(JSON.stringify(input.clientFrames.map(frame =>
    encodeRegistryClientFrame(frame, ${MAX_FRAME_BYTES}))))
`

function assertClientFrames(encoded) {
  let frames
  try {
    const parsed = JSON.parse(encoded)
    if (!Array.isArray(parsed)) fail('target codec returned an invalid client fixture set')
    frames = parsed.map(frame => decodeRegistryClientFrame(frame, MAX_FRAME_BYTES))
  } catch (error) {
    if (error instanceof CompatibilityFailure) throw error
    fail('target codec returned client frames rejected by Registry')
  }
  if (frames.length !== 16
    || frames[0]?.type !== 'hello' || frames[0].token !== 'compatibility-noncredential-token'
    || frames[1]?.type !== 'prove'
    || frames[2]?.type !== 'heartbeat' || frames[2].report?.state !== 'online'
    || frames[2].report.acceptingA2A !== false || frames[2].report.activeRequests !== 0
    || frames[3]?.type !== 'producer-register'
    || frames[3].disclosureId !== 'compatibility-disclosure'
    || frames[3].registration.conversationId !== 'compatibility-conversation'
    || frames[4]?.type !== 'event' || frames[4].envelope.eventId !== 'compatibility-event'
    || frames[5]?.type !== 'checkpoint' || frames[5].checkpoint.eventCount !== 1
    || frames[6]?.type !== 'import-dispatch'
    || frames[7]?.type !== 'import-release' || frames[7].outcome.status !== 'completed'
    || frames[7].outcome.sessionId !== 'compatibility-import-session'
    || frames[8]?.type !== 'import-release' || frames[8].outcome.status !== 'retry'
    || frames[9]?.type !== 'question-dispatch'
    || frames[10]?.type !== 'question-start'
    || frames[10].binding.requestId !== 'compatibility-question'
    || frames[11]?.type !== 'question-transition' || frames[11].transition.state !== 'running'
    || frames[12]?.type !== 'question-transition' || frames[12].transition.state !== 'completed'
    || frames[12].transition.reply !== 'Only the authorized plaintext prefix.'
    || frames[13]?.type !== 'question-transition' || frames[13].transition.state !== 'failed'
    || frames[14]?.type !== 'question-authorize'
    || frames[15]?.type !== 'question-authorize-release'
    || frames[15].authorizationRequestId !== 15) {
    fail('target codec changed the complete Registry client frame semantics')
  }
}

const connectionOverlaySchemaProbe = (webAppSpecifier, appBootSpecifier) => String.raw`
  import { ProductionRegistryConnectionConfigSchema } from ${JSON.stringify(webAppSpecifier)}
  import { loadOverlayPatches } from ${JSON.stringify(appBootSpecifier)}
  const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
  const expression = (value, source) => exactKeys(value, ['__jsExpr']) && value.__jsExpr === source
  const patches = loadOverlayPatches('registry-harness-compatibility', process.argv[1])
  if (!Array.isArray(patches) || patches.length !== 1) process.exit(3)
  const row = patches[0]
  if (!exactKeys(row, ['id', 'inject', 'config']) || row.id !== 'web-runtime'
    || !Array.isArray(row.inject) || row.inject.length !== 2
    || row.inject[0] !== 'webStartup' || row.inject[1] !== 'credentials') process.exit(3)
  const config = row.config
  if (!exactKeys(config, ['openBrowser', 'printUrl', 'surfaceContext', 'trustedHosts', 'productionRegistryConnection'])
    || !expression(config.openBrowser, 'ctx.webStartup.openBrowser') || config.printUrl !== true
    || config.surfaceContext !== true || !expression(config.trustedHosts, 'ctx.webStartup.trustedHosts')) process.exit(3)
  const connection = config.productionRegistryConnection
  if (!exactKeys(connection, ['mode', 'organizationId', 'instanceId', 'tokenEnv', 'privateKeyEnv', 'transport'])
    || connection.mode !== 'production'
    || !expression(connection.organizationId, 'process.env.DSH_REGISTRY_ORGANIZATION_ID')
    || !expression(connection.instanceId, 'process.env.DSH_INSTANCE_ID')
    || connection.tokenEnv !== 'DSH_REGISTRY_DEVICE_TOKEN'
    || connection.privateKeyEnv !== 'DSH_REGISTRY_DEVICE_PRIVATE_KEY') process.exit(3)
  const transport = connection.transport
  const transportKeys = ['url', 'handshakeTimeoutMs', 'requestTimeoutMs', 'heartbeatIntervalMs', 'pollIntervalMs',
    'maxFrameBytes', 'maxSendBufferBytes', 'maxConnections', 'maxPendingQuestionOperations', 'retryBaseMs',
    'retryCapMs', 'retryJitterMin', 'retryJitterMax']
  if (!exactKeys(transport, transportKeys)
    || !expression(transport.url, 'process.env.DSH_REGISTRY_SYNC_URL')) process.exit(3)
  const resolved = ProductionRegistryConnectionConfigSchema({
    ...connection,
    organizationId: 'compatibility-organization',
    instanceId: 'compatibility-target',
    transport: { ...transport, url: 'wss://registry.invalid/a2a/v1/sync' },
  })
  if (resolved.mode !== 'production' || resolved.organizationId !== 'compatibility-organization'
    || resolved.instanceId !== 'compatibility-target'
    || resolved.transport.url !== 'wss://registry.invalid/a2a/v1/sync') process.exit(3)
  process.stdout.write('overlay-schema-compatible\n')
`

const publicationOverlaySchemaProbe = (webAppSpecifier, sessionControllerSpecifier,
  appBootSpecifier) => String.raw`
  import { resolve } from 'node:path'
  import { Config as WebConfigSchema } from ${JSON.stringify(webAppSpecifier)}
  import { SessionController } from ${JSON.stringify(sessionControllerSpecifier)}
  import { loadOverlayPatches } from ${JSON.stringify(appBootSpecifier)}
  const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
  const expression = (value, source) => exactKeys(value, ['__jsExpr']) && value.__jsExpr === source
  const patches = loadOverlayPatches('registry-harness-publication-compatibility', process.argv[1])
  if (!Array.isArray(patches) || patches.length !== 2) process.exit(3)
  const web = patches.find(row => row?.id === 'web-runtime')
  const session = patches.find(row => row?.id === 'session-controller')
  if (!exactKeys(web, ['id', 'inject', 'config'])
    || !Array.isArray(web.inject) || web.inject.length !== 4
    || web.inject[0] !== 'webStartup' || web.inject[1] !== 'credentials'
    || web.inject[2] !== 'productionDisclosureAuthority'
    || web.inject[3] !== 'registryDisclosureKeyPublisher'
    || !exactKeys(session, ['id', 'config'])) process.exit(3)
  const webConfig = web.config
  if (!exactKeys(webConfig, ['openBrowser', 'printUrl', 'surfaceContext', 'trustedHosts',
    'a2aDisclosureDecryption', 'productionRegistryConnection', 'productionDisclosurePublication'])
    || !expression(webConfig.openBrowser, 'ctx.webStartup.openBrowser')
    || webConfig.printUrl !== true || webConfig.surfaceContext !== true
    || !expression(webConfig.trustedHosts, 'ctx.webStartup.trustedHosts')) process.exit(3)
  const connection = webConfig.productionRegistryConnection
  if (!exactKeys(connection, ['mode', 'organizationId', 'instanceId', 'tokenEnv', 'privateKeyEnv', 'transport'])
    || connection.mode !== 'production'
    || !expression(connection.organizationId, 'process.env.DSH_REGISTRY_ORGANIZATION_ID')
    || !expression(connection.instanceId, 'process.env.DSH_INSTANCE_ID')
    || connection.tokenEnv !== 'DSH_REGISTRY_DEVICE_TOKEN'
    || connection.privateKeyEnv !== 'DSH_REGISTRY_DEVICE_PRIVATE_KEY'
    || !expression(connection.transport?.url, 'process.env.DSH_REGISTRY_SYNC_URL')) process.exit(3)
  const publication = webConfig.productionDisclosurePublication
  if (!exactKeys(publication, ['mode', 'storageRoot', 'producer', 'crypto'])
    || publication.mode !== 'production'
    || !expression(publication.storageRoot, 'process.env.DSH_DISCLOSURE_STATE_PATH')) process.exit(3)
  const resolvedWeb = WebConfigSchema({
    ...webConfig,
    openBrowser: false,
    trustedHosts: [],
    productionRegistryConnection: {
      ...connection,
      organizationId: 'compatibility-organization',
      instanceId: 'compatibility-target',
      transport: { ...connection.transport, url: 'wss://registry.invalid/a2a/v1/sync' },
    },
    productionDisclosurePublication: {
      ...publication,
      storageRoot: resolve('compatibility-disclosure-state'),
    },
  })
  if (resolvedWeb.productionRegistryConnection?.mode !== 'production'
    || resolvedWeb.productionDisclosurePublication?.mode !== 'production'
    || resolvedWeb.productionDisclosurePublication.storageRoot !== resolve('compatibility-disclosure-state')) {
    process.exit(3)
  }
  const sessionConfig = session.config
  if (!exactKeys(sessionConfig, ['disclosurePreview', 'registryDisclosureImport', 'registryA2aConsumer'])) {
    process.exit(3)
  }
  const selectedImport = sessionConfig.registryDisclosureImport
  const selectedQuestion = sessionConfig.registryA2aConsumer
  if (!expression(selectedImport?.organizationId, 'process.env.DSH_REGISTRY_ORGANIZATION_ID')
    || !expression(selectedImport?.targetInstanceId, 'process.env.DSH_INSTANCE_ID')
    || !expression(selectedQuestion?.organizationId, 'process.env.DSH_REGISTRY_ORGANIZATION_ID')
    || !expression(selectedQuestion?.sourceInstanceId, 'process.env.DSH_INSTANCE_ID')
    || selectedQuestion?.handling !== 'manual') process.exit(3)
  const resolvedSession = SessionController.Config({
    ...sessionConfig,
    registryDisclosureImport: {
      ...selectedImport,
      organizationId: 'compatibility-organization',
      targetInstanceId: 'compatibility-target',
    },
    registryA2aConsumer: {
      ...selectedQuestion,
      organizationId: 'compatibility-organization',
      sourceInstanceId: 'compatibility-target',
    },
  })
  if (resolvedSession.registryDisclosureImport?.organizationId !== 'compatibility-organization'
    || resolvedSession.registryDisclosureImport?.targetInstanceId !== 'compatibility-target'
    || resolvedSession.registryA2aConsumer?.organizationId !== 'compatibility-organization'
    || resolvedSession.registryA2aConsumer?.sourceInstanceId !== 'compatibility-target'
    || resolvedSession.registryA2aConsumer?.handling !== 'manual') process.exit(3)
  process.stdout.write('publication-overlay-schema-compatible\n')
`

/** Extract exactly one top-level row from the built CLI config dump. */
function compositionSection(output, id) {
  if (typeof output !== 'string') fail('built Harness CLI returned a non-text config dump')
  const lines = output.split(/\r?\n/u)
  const starts = lines.flatMap((line, index) => line === `- id: ${id}` ? [index] : [])
  if (starts.length !== 1) fail(`built Harness CLI did not compose exactly one ${id} row`)
  const start = starts[0]
  let end = lines.length
  for (let index = start + 1; index < lines.length; index += 1) {
    if (lines[index].startsWith('- id: ')) { end = index; break }
  }
  return lines.slice(start, end).join('\n')
}

function requireCompositionFields(section, fields, label) {
  for (const field of fields) {
    if (!section.includes(field)) fail(`built Harness CLI omitted ${label} field ${field}`)
  }
}

/** Assert the built CLI composed one enabled Web runtime carrying only the connection bridge. */
export function assertConnectionOnlyComposition(output) {
  const section = compositionSection(output, 'web-runtime')
  requireCompositionFields(section, [
    "name: '@deepseek-ai/dsh-web-app'",
    '- credentials',
    'productionRegistryConnection:',
    'mode: production',
    'organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID',
    'instanceId: !!js process.env.DSH_INSTANCE_ID',
    'tokenEnv: DSH_REGISTRY_DEVICE_TOKEN',
    'privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY',
    'url: !!js process.env.DSH_REGISTRY_SYNC_URL',
  ], 'connection-only')
  for (const forbidden of [
    'testOnlyDisclosurePublication:',
    'productionDisclosurePublication:',
    'registryDisclosureImport:',
    'registryA2aConsumer:',
    'productionDisclosureAuthority',
    'registryDisclosureKeyPublisher',
    'a2aDisclosureDecryption:',
  ]) {
    if (output.includes(forbidden)) fail(`connection-only overlay unexpectedly enabled ${forbidden}`)
  }
}

/** Assert the full production template composes connection, publication, import and question consumers. */
export function assertPublicationComposition(output) {
  const web = compositionSection(output, 'web-runtime')
  const session = compositionSection(output, 'session-controller')
  requireCompositionFields(web, [
    "name: '@deepseek-ai/dsh-web-app'",
    '- credentials',
    '- productionDisclosureAuthority',
    '- registryDisclosureKeyPublisher',
    'a2aDisclosureDecryption:',
    'productionRegistryConnection:',
    'productionDisclosurePublication:',
    'storageRoot: !!js process.env.DSH_DISCLOSURE_STATE_PATH',
    'tokenEnv: DSH_REGISTRY_DEVICE_TOKEN',
    'privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY',
    'url: !!js process.env.DSH_REGISTRY_SYNC_URL',
  ], 'publication web-runtime')
  requireCompositionFields(session, [
    "name: '@deepseek-ai/dsh-api-session-controller'",
    'disclosurePreview:',
    'registryDisclosureImport:',
    'organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID',
    'targetInstanceId: !!js process.env.DSH_INSTANCE_ID',
    'registryA2aConsumer:',
    'handling: manual',
    'sourceInstanceId: !!js process.env.DSH_INSTANCE_ID',
  ], 'publication session-controller')
  for (const forbidden of [
    'testOnlyDisclosurePublication:',
    'loopbackDisclosureImport:',
    'loopbackA2aConsumer:',
    'loopbackDisclosureRefresh:',
    'registryUrl:',
    'sharedSecretEnv:',
  ]) {
    if (web.includes(forbidden) || session.includes(forbidden)) {
      fail(`publication overlay unexpectedly enabled ${forbidden}`)
    }
  }
}

function verifyCliComposition(nodePath, harnessRoot, overlayPath, kind) {
  const sandbox = mkdtempSync(join(tmpdir(), 'dsh-harness-compatibility-'))
  const cliPath = join(harnessRoot, 'apps/cli/lib/bin.js')
  try {
    const output = runTargetNode(nodePath, [
      cliPath,
      '--profile', 'web',
      '--patch', overlayPath,
      '--dump-config',
    ], {
      cwd: sandbox,
      env: systemEnvironment({
        DSH_HOME: sandbox,
        DSH_REGISTRY_ORGANIZATION_ID: 'compatibility-organization',
        DSH_INSTANCE_ID: 'compatibility-target',
        DSH_REGISTRY_SYNC_URL: 'wss://registry.invalid/a2a/v1/sync',
        DSH_DISCLOSURE_STATE_PATH: join(sandbox, 'disclosure-state'),
      }),
    }, `built Harness CLI ${kind} composition`)
    if (kind === 'connection-only') assertConnectionOnlyComposition(output)
    else assertPublicationComposition(output)
  } finally {
    rmSync(sandbox, { recursive: true, force: true, maxRetries: 3 })
  }
}

async function main(args) {
  const { harnessRoot, nodePath, overlayPath, publicationOverlayPath } = parseCompatibilityArguments(args)
  requireDirectory(harnessRoot, 'Harness root')
  requireFile(nodePath, 'Target Node.js', true)
  requireFile(overlayPath, 'Connection-only overlay')
  requireFile(publicationOverlayPath, 'Publication overlay')
  if (realpathSync.native(overlayPath) === realpathSync.native(publicationOverlayPath)) {
    throw new CompatibilityUsageError('connection-only and publication overlays must be different files')
  }
  for (const relative of [
    'package.json',
    'apps/cli/package.json',
    'apps/cli/lib/bin.js',
    'packages/a2a/registry-sync/package.json',
    'packages/a2a/registry-sync/src/index.ts',
    'packages/a2a/registry-sync/lib/index.js',
    'packages/boot/app-boot/package.json',
    'packages/boot/app-boot/src/index.ts',
    'packages/boot/app-boot/lib/index.js',
    'packages/bundle/web-app/package.json',
    'packages/bundle/web-app/src/index.ts',
    'packages/bundle/web-app/lib/index.js',
    'packages/api/session-controller/package.json',
    'packages/api/session-controller/src/index.ts',
    'packages/api/session-controller/lib/index.js',
  ]) requireFile(join(harnessRoot, relative), `Harness ${relative}`)

  requireTargetNode(nodePath, harnessRoot)
  const fixtures = JSON.stringify(wireFixtures())
  const targets = [
    {
      label: 'source',
      codecCwd: harnessRoot,
      codecSpecifier: './packages/a2a/registry-sync/src/index.ts',
      webCwd: harnessRoot,
      webSpecifier: './packages/bundle/web-app/src/index.ts',
      sessionSpecifier: './packages/api/session-controller/src/index.ts',
      appBootSpecifier: './packages/boot/app-boot/src/index.ts',
      preload: ['--import', 'tsx/esm'],
    },
    {
      label: 'built runtime',
      codecCwd: join(harnessRoot, 'packages/a2a/registry-sync'),
      codecSpecifier: '@deepseek-ai/dsh-a2a-registry-sync',
      webCwd: join(harnessRoot, 'packages/bundle/web-app'),
      webSpecifier: '@deepseek-ai/dsh-web-app',
      sessionSpecifier: '@deepseek-ai/dsh-api-session-controller',
      appBootSpecifier: '@deepseek-ai/dsh-app-boot',
      preload: [],
    },
  ]
  for (const target of targets) {
    const encoded = runTargetNode(nodePath,
      [...target.preload, '--input-type=module', '--eval', codecProbe(target.codecSpecifier)], {
        cwd: target.codecCwd,
        env: systemEnvironment(),
        input: fixtures,
      }, `Harness ${target.label} bidirectional Registry codec`)
    assertClientFrames(encoded)

    const schema = runTargetNode(nodePath,
      [...target.preload, '--input-type=module', '--eval',
        connectionOverlaySchemaProbe(target.webSpecifier, target.appBootSpecifier), overlayPath], {
        cwd: target.webCwd,
        env: systemEnvironment(),
      }, `Harness ${target.label} connection-only overlay schema`)
    if (schema.trim() !== 'overlay-schema-compatible') {
      fail(`Harness ${target.label} returned an invalid overlay schema result`)
    }

    const publicationSchema = runTargetNode(nodePath,
      [...target.preload, '--input-type=module', '--eval',
        publicationOverlaySchemaProbe(target.webSpecifier, target.sessionSpecifier,
          target.appBootSpecifier), publicationOverlayPath], {
        cwd: target.webCwd,
        env: systemEnvironment(),
      }, `Harness ${target.label} publication overlay schema`)
    if (publicationSchema.trim() !== 'publication-overlay-schema-compatible') {
      fail(`Harness ${target.label} returned an invalid publication overlay schema result`)
    }
  }
  verifyCliComposition(nodePath, harnessRoot, overlayPath, 'connection-only')
  verifyCliComposition(nodePath, harnessRoot, publicationOverlayPath, 'publication')

  process.stdout.write([
    'registry-harness-compatibility: passed',
    '- the explicit target Node.js runtime is version 24 or newer',
    '- Harness source and built codecs accept Registry connection, publication, import and question lifecycle frames',
    '- Registry accepts Harness source and built connection, publication, import release and question transition frames',
    '- Harness source and built web/session schemas accept the actual connection-only and publication overlays',
    '- the built Harness CLI composes both overlays inside separate isolated temporary DSH_HOME directories',
    '- this static gate does not prove real device authentication, KMS delivery or model execution',
    '',
  ].join('\n'))
}

const invoked = process.argv[1]
if (invoked !== undefined
  && realpathSync.native(resolve(invoked)) === realpathSync.native(fileURLToPath(import.meta.url))) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    if (error instanceof CompatibilityUsageError) {
      process.stderr.write(`${error.message}\n${error.message === USAGE ? '' : `${USAGE}\n`}`)
      process.exitCode = 2
    } else {
      const message = error instanceof CompatibilityFailure ? error.message : 'internal compatibility check failed'
      process.stderr.write(`registry-harness-compatibility: ${message}\n`)
      process.exitCode = 1
    }
  }
}
