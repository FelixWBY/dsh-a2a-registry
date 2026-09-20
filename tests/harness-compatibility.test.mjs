import test from 'node:test'
import assert from 'node:assert/strict'
import { decodeRegistryClientFrame, decodeRegistryServerFrame } from '@deepseek-ai/dsh-a2a-registry-sync'
import {
  assertConnectionOnlyComposition,
  assertPublicationComposition,
  parseCompatibilityArguments,
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
  assert.throws(() => assertConnectionOnlyComposition(`${connectionOnly}
- id: session-controller
  config:
    registryDisclosureImport: {}
    registryA2aConsumer: {}
`), /unexpectedly enabled registryDisclosureImport/u)
})

test('Harness compatibility checker requires the full production publication composition', () => {
  const publication = `
- id: session-controller
  name: '@deepseek-ai/dsh-api-session-controller'
  config:
    disclosurePreview: {}
    registryDisclosureImport:
      organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID
      targetInstanceId: !!js process.env.DSH_INSTANCE_ID
      maxRetainedBytes: 16777216
    registryA2aConsumer:
      handling: manual
      organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID
      sourceInstanceId: !!js process.env.DSH_INSTANCE_ID
- id: web-runtime
  name: '@deepseek-ai/dsh-web-app'
  inject:
    - webStartup
    - credentials
    - productionDisclosureAuthority
    - registryDisclosureKeyPublisher
  config:
    a2aDisclosureDecryption: {}
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
`
  assert.doesNotThrow(() => { assertPublicationComposition(publication) })
  assert.throws(() => assertPublicationComposition(publication.replace(
    'registryA2aConsumer:', 'loopbackA2aConsumer:',
  )), /omitted publication session-controller field registryA2aConsumer/u)
  assert.throws(() => assertPublicationComposition(publication.replace(
    'handling: manual', 'handling: automatic\n      sharedSecretEnv: forbidden',
  )), /omitted publication session-controller field handling: manual/u)
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
