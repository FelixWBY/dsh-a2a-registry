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
  + ' --harness-root <path> --node-path <path> --overlay <path>'

class CompatibilityUsageError extends Error {}
class CompatibilityFailure extends Error {}

function fail(message) {
  throw new CompatibilityFailure(message)
}

/** Parse the three explicit trust-boundary inputs without accepting ambient defaults. */
export function parseCompatibilityArguments(args) {
  const allowed = new Set(['--harness-root', '--node-path', '--overlay'])
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

function disclosureImportFrame() {
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
  return {
    protocolVersion: 1,
    requestId: 4,
    type: 'import-dispatch',
    delivery: {
      operationId: 'compatibility-operation',
      targetInstanceId,
      organizationId,
      disclosureId,
      sourceInstanceId,
      checkpointHash: checkpoint.checkpointHash,
      prefix: { authorizationVersion: 0, conversationId, checkpoint, events: [envelope] },
      source: { instanceName: 'Compatibility Harness', conversationTitle: 'Compatibility conversation' },
    },
  }
}

function wireFixtures() {
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
  const serverFrames = [
    { protocolVersion: 1, requestId: 1, type: 'challenge', challenge },
    { protocolVersion: 1, requestId: 2, type: 'authenticated',
      identity: { organizationId, instanceId, keyId } },
    { protocolVersion: 1, requestId: 3, type: 'heartbeat-ack', observedAt: 1 },
    disclosureImportFrame(),
  ].map(frame => encodeRegistryServerFrame(frame, MAX_FRAME_BYTES))
  const clientFrames = [
    { protocolVersion: 1, requestId: 1, type: 'hello', token: 'compatibility-noncredential-token' },
    { protocolVersion: 1, requestId: 2, type: 'prove',
      signature: Buffer.alloc(64, 3).toString('base64url') },
    { protocolVersion: 1, requestId: 3, type: 'heartbeat',
      report: { state: 'online', acceptingA2A: false, activeRequests: 0 } },
  ]
  return { serverFrames, clientFrames }
}

const codecProbe = specifier => String.raw`
  import { decodeRegistryServerFrame, encodeRegistryClientFrame } from ${JSON.stringify(specifier)}
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  const decoded = input.serverFrames.map(frame => decodeRegistryServerFrame(frame, ${MAX_FRAME_BYTES}))
  if (decoded.length !== 4
    || decoded[0].type !== 'challenge'
    || decoded[0].challenge.organizationId !== 'compatibility-organization'
    || decoded[0].challenge.instanceId !== 'compatibility-target'
    || decoded[1].type !== 'authenticated'
    || decoded[1].identity.instanceId !== 'compatibility-target'
    || decoded[2].type !== 'heartbeat-ack'
    || decoded[2].observedAt !== 1
    || decoded[3].type !== 'import-dispatch'
    || decoded[3].delivery === null
    || decoded[3].delivery.operationId !== 'compatibility-operation'
    || decoded[3].delivery.targetInstanceId !== 'compatibility-target') process.exit(3)
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
  if (frames.length !== 3
    || frames[0]?.type !== 'hello' || frames[0].token !== 'compatibility-noncredential-token'
    || frames[1]?.type !== 'prove'
    || frames[2]?.type !== 'heartbeat' || frames[2].report?.state !== 'online'
    || frames[2].report.acceptingA2A !== false || frames[2].report.activeRequests !== 0) {
    fail('target codec changed the connection-only client frame semantics')
  }
}

const overlaySchemaProbe = (webAppSpecifier, appBootSpecifier) => String.raw`
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

/** Assert the built CLI composed one enabled Web runtime carrying only the connection bridge. */
export function assertConnectionOnlyComposition(output) {
  if (typeof output !== 'string') fail('built Harness CLI returned a non-text config dump')
  const lines = output.split(/\r?\n/u)
  const starts = lines.flatMap((line, index) => line === '- id: web-runtime' ? [index] : [])
  if (starts.length !== 1) fail('built Harness CLI did not compose exactly one web-runtime row')
  const start = starts[0]
  let end = lines.length
  for (let index = start + 1; index < lines.length; index += 1) {
    if (lines[index].startsWith('- id: ')) { end = index; break }
  }
  const section = lines.slice(start, end).join('\n')
  for (const required of [
    "name: '@deepseek-ai/dsh-web-app'",
    '- credentials',
    'productionRegistryConnection:',
    'mode: production',
    'organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID',
    'instanceId: !!js process.env.DSH_INSTANCE_ID',
    'tokenEnv: DSH_REGISTRY_DEVICE_TOKEN',
    'privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY',
    'url: !!js process.env.DSH_REGISTRY_SYNC_URL',
  ]) {
    if (!section.includes(required)) fail(`built Harness CLI omitted connection-only field ${required}`)
  }
  for (const forbidden of [
    'testOnlyDisclosurePublication:',
    'productionDisclosurePublication:',
    'registryDisclosureImport:',
    'registryA2aConsumer:',
  ]) {
    if (section.includes(forbidden)) fail(`connection-only overlay unexpectedly enabled ${forbidden}`)
  }
}

function verifyCliComposition(nodePath, harnessRoot, overlayPath) {
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
      }),
    }, 'built Harness CLI connection-only composition')
    assertConnectionOnlyComposition(output)
  } finally {
    rmSync(sandbox, { recursive: true, force: true, maxRetries: 3 })
  }
}

async function main(args) {
  const { harnessRoot, nodePath, overlayPath } = parseCompatibilityArguments(args)
  requireDirectory(harnessRoot, 'Harness root')
  requireFile(nodePath, 'Target Node.js', true)
  requireFile(overlayPath, 'Connection-only overlay')
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
      appBootSpecifier: './packages/boot/app-boot/src/index.ts',
      preload: ['--import', 'tsx/esm'],
    },
    {
      label: 'built runtime',
      codecCwd: join(harnessRoot, 'packages/a2a/registry-sync'),
      codecSpecifier: '@deepseek-ai/dsh-a2a-registry-sync',
      webCwd: join(harnessRoot, 'packages/bundle/web-app'),
      webSpecifier: '@deepseek-ai/dsh-web-app',
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
        overlaySchemaProbe(target.webSpecifier, target.appBootSpecifier), overlayPath], {
        cwd: target.webCwd,
        env: systemEnvironment(),
      }, `Harness ${target.label} connection-only overlay schema`)
    if (schema.trim() !== 'overlay-schema-compatible') {
      fail(`Harness ${target.label} returned an invalid overlay schema result`)
    }
  }
  verifyCliComposition(nodePath, harnessRoot, overlayPath)

  process.stdout.write([
    'registry-harness-compatibility: passed',
    '- the explicit target Node.js runtime is version 24 or newer',
    '- Harness source and built codecs accept Registry challenge, authentication, heartbeat and import frames',
    '- Registry accepts Harness source and built hello, proof and heartbeat frames',
    '- Harness source and built web-app schemas accept the actual connection-only overlay',
    '- the built Harness CLI composes that overlay inside an isolated temporary DSH_HOME',
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
