import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { decodeRegistryClientFrame, decodeRegistryServerFrame } from '@deepseek-ai/dsh-a2a-registry-sync'
import {
  assertConnectionOnlyComposition,
  assertPublicationCompositionValidator,
  assertPublicationComposition,
  parseCompatibilityArguments,
  prepareBuiltWorkspaceFallback,
  publicationOverlaySchemaProbe,
  wireFixtures,
} from '../deploy/registry/verify-harness-compatibility.mjs'

const MAX_FRAME_BYTES = 1_048_576

test('Harness compatibility checker requires explicit runtime, checkout and overlay inputs', () => {
  const parsed = parseCompatibilityArguments([
    '--overlay', 'connection.patch.yml',
    '--publication-overlay', 'publication.patch.yml',
    '--harness-root', 'harness',
    '--node-path', 'runtime/node',
  ])
  assert.match(parsed.harnessRoot, /harness$/u)
  assert.match(parsed.nodePath, /runtime[\\/]node$/u)
  assert.match(parsed.overlayPath, /connection\.patch\.yml$/u)
  assert.match(parsed.publicationOverlayPath, /publication\.patch\.yml$/u)
  assert.throws(() => parseCompatibilityArguments(['--harness-root', 'harness']), /usage:/u)
  assert.throws(() => parseCompatibilityArguments([
    '--harness-root', 'harness', '--node-path', 'node', '--overlay', 'one',
    '--publication-overlay', 'publication', '--overlay', 'two',
  ]), /usage:/u)
})

test('built Harness fallback resolves only declared workspace package build entries', () => {
  const root = mkdtempSync(join(tmpdir(), 'registry-harness-fallback-test-'))
  const consumerRoot = join(root, 'packages/bundle/web-app')
  const packages = [
    ['@deepseek-ai/dsh-a2a-disclosure-outbox', 'packages/a2a/disclosure-outbox'],
    ['@deepseek-ai/dsh-a2a-disclosure-policy', 'packages/a2a/disclosure-policy'],
    ['@deepseek-ai/dsh-a2a-disclosure-producer', 'packages/a2a/disclosure-producer'],
    ['@deepseek-ai/dsh-storage-json', 'packages/storage/storage-json'],
  ]
  const dependencies = Object.fromEntries(packages.map(([name]) => [name, 'workspace:^']))
  let fallback
  try {
    mkdirSync(consumerRoot, { recursive: true })
    writeFileSync(join(consumerRoot, 'package.json'), JSON.stringify({ dependencies }))
    for (const [name, relativeRoot] of packages) {
      const packageRoot = join(root, relativeRoot)
      mkdirSync(join(packageRoot, 'lib'), { recursive: true })
      writeFileSync(join(packageRoot, 'package.json'), JSON.stringify({
        name,
        type: 'module',
        main: 'lib/index.js',
        exports: { '.': { default: './lib/index.js' } },
      }))
      writeFileSync(join(packageRoot, 'lib/index.js'), `export const marker = ${JSON.stringify(name)}\n`)
    }

    fallback = prepareBuiltWorkspaceFallback(root)
    const result = spawnSync(process.execPath, [
      ...fallback.preload,
      '--input-type=module',
      '--eval',
      "const value = await import('@deepseek-ai/dsh-a2a-disclosure-policy'); process.stdout.write(value.marker)",
    ], { cwd: consumerRoot, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, '@deepseek-ai/dsh-a2a-disclosure-policy')

    delete dependencies['@deepseek-ai/dsh-a2a-disclosure-policy']
    writeFileSync(join(consumerRoot, 'package.json'), JSON.stringify({ dependencies }))
    assert.throws(() => prepareBuiltWorkspaceFallback(root), /does not declare required workspace dependency/u)
  } finally {
    if (fallback !== undefined) rmSync(fallback.directory, { recursive: true, force: true })
    rmSync(root, { recursive: true, force: true })
  }
})

test('Harness compatibility fixtures cover publication, import release and question terminal alternatives', () => {
  const fixtures = wireFixtures()
  const server = fixtures.serverFrames.map(frame => decodeRegistryServerFrame(frame, MAX_FRAME_BYTES))
  const client = fixtures.clientFrames.map(frame => decodeRegistryClientFrame(
    JSON.stringify(frame), MAX_FRAME_BYTES))
  assert.deepEqual(server.map(frame => frame.type), [
    'challenge', 'authenticated', 'heartbeat-ack',
    'producer-register-ack', 'event-ack', 'checkpoint-ack',
    'import-dispatch', 'import-released',
    'question-dispatch', 'question-start',
    'question-transition', 'question-transition', 'question-transition',
    'question-authorized', 'question-authorize-released',
    'disclosure-refresh-current', 'disclosure-refresh-available',
    'disclosure-refresh-authorized', 'disclosure-refresh-released',
  ])
  assert.deepEqual([
    server[3].status.receipt.ingest,
    server[4].receipt.ingest,
    server[5].receipt.ingest,
  ], ['pending', 'pending', 'ready'])
  assert.deepEqual([
    server[3].status.receipt.lastDisclosureSeq,
    server[4].receipt.lastDisclosureSeq,
    server[5].receipt.lastDisclosureSeq,
  ], [-1, 0, 0])
  assert.deepEqual(server.filter(frame => frame.type === 'question-transition')
    .map(frame => frame.receipt.state), ['running', 'completed', 'failed'])
  assert.deepEqual(client.map(frame => frame.type), [
    'hello', 'prove', 'heartbeat',
    'producer-register', 'event', 'checkpoint',
    'import-dispatch', 'import-release', 'import-release',
    'question-dispatch', 'question-start',
    'question-transition', 'question-transition', 'question-transition',
    'question-authorize', 'question-authorize-release',
    'disclosure-refresh-readiness', 'disclosure-refresh-readiness',
    'disclosure-refresh-authorize', 'disclosure-refresh-release',
  ])
  assert.deepEqual(client.filter(frame => frame.type === 'question-transition')
    .map(frame => frame.transition.state), ['running', 'completed', 'failed'])
  assert.deepEqual(client.filter(frame => frame.type === 'import-release')
    .map(frame => frame.outcome.status), ['completed', 'retry'])
})

test('Registry Sync import key grants are canonical, unique and fixed-prefix scoped', () => {
  const encoded = wireFixtures().serverFrames[6]
  const accepted = decodeRegistryServerFrame(encoded, MAX_FRAME_BYTES)
  assert.equal(accepted.type, 'import-dispatch')
  assert.equal(accepted.delivery.keyGrant.version, 1)
  assert.equal(Buffer.from(accepted.delivery.keyGrant.keys[0].material, 'base64url').byteLength, 32)

  const baseline = JSON.parse(encoded)
  const rejected = [
    value => { delete value.delivery.keyGrant },
    value => { value.delivery.keyGrant.scope.conversationId = 'other-conversation' },
    value => { value.delivery.keyGrant.keys = [] },
    value => { value.delivery.keyGrant.keys[0].material += '=' },
    value => { value.delivery.keyGrant.keys[0].material = Buffer.alloc(31, 4).toString('base64url') },
    value => { value.delivery.keyGrant.keys.push(structuredClone(value.delivery.keyGrant.keys[0])) },
    value => { value.delivery.keyGrant.extra = true },
  ]
  for (const mutate of rejected) {
    const candidate = structuredClone(baseline)
    mutate(candidate)
    assert.throws(() => decodeRegistryServerFrame(JSON.stringify(candidate), MAX_FRAME_BYTES),
      /invalid Registry synchronization frame/u)
  }
})

test('Registry Sync refresh frames are exact and retain real checkpoint cursor metadata', () => {
  const fixtures = wireFixtures()
  const available = fixtures.serverFrames.map(frame => decodeRegistryServerFrame(frame, MAX_FRAME_BYTES))
    .find(frame => frame.type === 'disclosure-refresh-available')
  assert.ok(available)
  assert.equal(available.policyVersion, 1)
  assert.equal(available.sourceCursor, 1)
  assert.equal(available.eventCount, 1)

  const availableWire = JSON.parse(fixtures.serverFrames.find(frame =>
    JSON.parse(frame).type === 'disclosure-refresh-available'))
  for (const mutate of [
    value => { delete value.policyVersion },
    value => { value.sourceCursor = '0' },
    value => { value.eventCount = -1 },
    value => { value.extra = true },
  ]) {
    const candidate = structuredClone(availableWire)
    mutate(candidate)
    assert.throws(() => decodeRegistryServerFrame(JSON.stringify(candidate), MAX_FRAME_BYTES),
      /invalid Registry synchronization frame/u)
  }

  const readiness = fixtures.clientFrames.find(frame => frame.type === 'disclosure-refresh-readiness')
  assert.ok(readiness)
  assert.throws(() => decodeRegistryClientFrame(JSON.stringify({ ...readiness, memberId: 'untrusted' }),
    MAX_FRAME_BYTES), /invalid Registry synchronization frame/u)
})

test('Harness compatibility checker accepts only the connection-only composed Web row', () => {
  const connectionOnly = `
- id: web-runtime
  name: '@deepseek-ai/dsh-web-app'
  inject:
    - webStartup
    - credentials
  config:
    productionRegistryConnection:
      mode: production
      organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID
      instanceId: !!js process.env.DSH_INSTANCE_ID
      tokenEnv: DSH_REGISTRY_DEVICE_TOKEN
      privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY
      transport:
        url: !!js process.env.DSH_REGISTRY_SYNC_URL
- id: next-row
  disabled: true
`
  assert.doesNotThrow(() => { assertConnectionOnlyComposition(connectionOnly) })
  assert.throws(() => assertConnectionOnlyComposition(connectionOnly.replace(
    'productionRegistryConnection:',
    'productionDisclosurePublication:\n      mode: production\n    productionRegistryConnection:',
  )), /unexpectedly enabled productionDisclosurePublication/u)
  assert.throws(() => assertConnectionOnlyComposition(connectionOnly.replace(
    'productionRegistryConnection:',
    'productionDisclosureHttpsBridge:\n      mode: https-bridge\n    productionRegistryConnection:',
  )), /unexpectedly enabled productionDisclosureHttpsBridge/u)
  assert.throws(() => assertConnectionOnlyComposition(connectionOnly.replace(
    'tokenEnv: DSH_REGISTRY_DEVICE_TOKEN',
    'tokenEnv: WRONG_TOKEN',
  )), /omitted connection-only field tokenEnv/u)
  for (const forbidden of [
    'testOnlyDisclosurePublication:',
    'productionDisclosureHttpsBridge:',
    'productionDisclosurePublication:',
    'registryDisclosureImport:',
    'productionRegistryDisclosureImport:',
    'productionRegistryQuestionConsumer:',
    'registryA2aConsumer:',
    'productionDisclosureAuthority',
    'registryDisclosureKeyPublisher',
    'a2aDisclosureDecryption:',
    'loopbackDisclosureImport:',
    'loopbackA2aConsumer:',
    'loopbackDisclosureRefresh:',
    'registryUrl:',
    'sharedSecretEnv:',
  ]) {
    assert.throws(() => assertConnectionOnlyComposition(`${connectionOnly}\n${forbidden}`),
      /connection-only overlay unexpectedly enabled/u)
  }
})

test('publication schema probe enforces the target Harness cross-field composition contract', () => {
  const resolvedWeb = {
    productionRegistryConnection: {
      transport: { url: 'wss://registry.invalid/a2a/v1/sync', maxConnections: 110 },
    },
    productionDisclosureHttpsBridge: {
      url: 'https://registry.invalid/a2a/v1/disclosure-publication',
    },
    productionDisclosurePublication: { producer: { maxPublications: 100 } },
    productionRegistryDisclosureImport: {},
    productionRegistryQuestionConsumer: {},
  }
  const capacityOnly = (connection, _bridge, publication, disclosureImport, questionConsumer) => {
    const reserved = 2 + (disclosureImport === undefined ? 0 : 1)
      + (questionConsumer === undefined ? 0 : 1)
    if (connection.transport.maxConnections - publication.producer.maxPublications < reserved) {
      throw new Error('insufficient capacity')
    }
  }
  const strict = (connection, bridge, publication, disclosureImport, questionConsumer) => {
    capacityOnly(connection, bridge, publication, disclosureImport, questionConsumer)
    const registry = new URL(connection.transport.url)
    registry.protocol = 'https:'
    if (new URL(bridge.url).origin !== registry.origin) throw new Error('foreign authority')
  }
  assert.doesNotThrow(() => { assertPublicationCompositionValidator(strict, resolvedWeb) })
  assert.throws(() => assertPublicationCompositionValidator(() => {}, resolvedWeb),
    /accepted insufficient transport capacity/u)
  assert.throws(() => assertPublicationCompositionValidator(capacityOnly, resolvedWeb),
    /accepted a foreign bridge authority/u)

  const probe = publicationOverlaySchemaProbe('web-app', 'session-controller', 'app-boot')
  assert.match(probe, /validateProductionRegistryComposition/u)
  assert.match(probe,
    /assertPublicationCompositionValidator\(validateProductionRegistryComposition, resolvedWeb\)/u)
})

test('Harness compatibility checker requires the full production publication composition', () => {
  const publication = `
- id: session-controller
  name: '@deepseek-ai/dsh-api-session-controller'
  config:
    disclosurePreview: {}
- id: web-runtime
  name: '@deepseek-ai/dsh-web-app'
  inject:
    - webStartup
    - credentials
  config:
    productionRegistryConnection:
      tokenEnv: DSH_REGISTRY_DEVICE_TOKEN
      privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY
      transport:
        url: !!js process.env.DSH_REGISTRY_SYNC_URL
    productionDisclosureHttpsBridge:
      mode: https-bridge
      url: !!js process.env.DSH_REGISTRY_DISCLOSURE_BRIDGE_URL
      tokenEnv: DSH_REGISTRY_DISCLOSURE_TOKEN
      requestTimeoutMs: 10000
      maxResponseBytes: 1048576
      maxAudienceEntries: 10000
      maxDisplayNameCharacters: 256
    productionDisclosurePublication:
      storageRoot: !!js process.env.DSH_DISCLOSURE_STATE_PATH
    productionRegistryDisclosureImport:
      pollIntervalMs: 1000
      limits:
        maxEvents: 100
        maxEncryptedBytes: 8388608
        maxTextBytes: 1048576
        maxDisplayCharacters: 2000
      cryptoLimits:
        maxPlaintextBytes: 65536
        maxCiphertextBytes: 262144
        maxTrustedKeys: 4
      maxRetainedBytes: 16777216
    productionRegistryQuestionConsumer:
      handling: automatic
      localModel:
        provider: deepseek-official
        model: deepseek-flash
      modelCredentialEnv: DEEPSEEK_API_KEY
      pollIntervalMs: 1000
      maxClaims: 10000
      mailboxLimits:
        maxTextBytes: 16384
        maxTextCharacters: 8192
        maxCiphertextBytes: 32768
        maxAggregateBytes: 16777216
        maxRequests: 10000
        maxRetainedRequests: 100000
        maxPendingOperations: 256
        maxLifetimeMs: 604800000
      contextLimits:
        maxEvents: 100
        maxEncryptedBytes: 8388608
        maxTextBytes: 1048576
        maxDisplayCharacters: 2000
      cryptoLimits:
        maxPlaintextBytes: 65536
        maxCiphertextBytes: 262144
        maxTrustedKeys: 4
      maxQuestionBytes: 16384
      maxQuestionCharacters: 8192
      maxMessageBytes: 8388608
`
  assert.doesNotThrow(() => { assertPublicationComposition(publication) })
  assert.throws(() => assertPublicationComposition(publication.replace(
    'productionRegistryDisclosureImport:', 'registryDisclosureImport:',
  )), /omitted publication web-runtime field productionRegistryDisclosureImport/u)
  assert.throws(() => assertPublicationComposition(publication.replace(
    'productionRegistryQuestionConsumer:', 'registryA2aConsumer:',
  )), /omitted publication web-runtime field productionRegistryQuestionConsumer/u)
  assert.throws(() => assertPublicationComposition(publication.replace(
    '    productionRegistryConnection:',
    '    a2aDisclosureDecryption: {}\n    productionRegistryConnection:',
  )), /unexpectedly enabled a2aDisclosureDecryption/u)
  assert.throws(() => assertPublicationComposition(publication.replace(
    '    - credentials',
    '    - credentials\n    - productionDisclosureAuthority',
  )), /unexpectedly enabled productionDisclosureAuthority/u)
  assert.throws(() => assertPublicationComposition(publication.replace(
    'productionDisclosureHttpsBridge:', 'missingDisclosureHttpsBridge:',
  )), /omitted publication web-runtime field productionDisclosureHttpsBridge/u)
  assert.throws(() => assertPublicationComposition(publication.replace(
    'tokenEnv: DSH_REGISTRY_DISCLOSURE_TOKEN', 'tokenEnv: WRONG_DISCLOSURE_TOKEN',
  )), /omitted publication web-runtime field tokenEnv: DSH_REGISTRY_DISCLOSURE_TOKEN/u)
  assert.throws(() => assertPublicationComposition(publication.replace(
    'url: !!js process.env.DSH_REGISTRY_DISCLOSURE_BRIDGE_URL',
    'url: !!js process.env.DSH_REGISTRY_SYNC_URL',
  )), /omitted publication web-runtime field url: !!js process.env.DSH_REGISTRY_DISCLOSURE_BRIDGE_URL/u)
  for (const [field, replacement] of [
    ['mode: https-bridge', 'mode: production'],
    ['requestTimeoutMs: 10000', 'requestTimeoutMs: 9999'],
    ['maxResponseBytes: 1048576', 'maxResponseBytes: 1048575'],
    ['maxAudienceEntries: 10000', 'maxAudienceEntries: 9999'],
    ['maxDisplayNameCharacters: 256', 'maxDisplayNameCharacters: 255'],
  ]) {
    assert.throws(() => assertPublicationComposition(publication.replace(field, replacement)),
      /omitted publication disclosure bridge field/u)
  }
  const prefixedDecoys = publication.replace(
    /^(      )(mode|url|tokenEnv|requestTimeoutMs|maxResponseBytes|maxAudienceEntries|maxDisplayNameCharacters):/gmu,
    '$1wrong$2:',
  )
  assert.throws(() => assertPublicationComposition(prefixedDecoys),
    /omitted publication disclosure bridge field/u)
})
