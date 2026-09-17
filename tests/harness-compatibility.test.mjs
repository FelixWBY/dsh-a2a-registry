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
  ])
  assert.deepEqual(client.filter(frame => frame.type === 'question-transition')
    .map(frame => frame.transition.state), ['running', 'completed', 'failed'])
  assert.deepEqual(client.filter(frame => frame.type === 'import-release')
    .map(frame => frame.outcome.status), ['completed', 'retry'])
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
    'tokenEnv: DSH_REGISTRY_DEVICE_TOKEN',
    'tokenEnv: WRONG_TOKEN',
  )), /omitted connection-only field tokenEnv/u)
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
})
