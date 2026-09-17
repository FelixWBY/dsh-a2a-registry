import test from 'node:test'
import assert from 'node:assert/strict'
import {
  assertConnectionOnlyComposition,
  parseCompatibilityArguments,
} from '../deploy/registry/verify-harness-compatibility.mjs'

test('Harness compatibility checker requires explicit runtime, checkout and overlay inputs', () => {
  const parsed = parseCompatibilityArguments([
    '--overlay', 'connection.patch.yml',
    '--harness-root', 'harness',
    '--node-path', 'runtime/node',
  ])
  assert.match(parsed.harnessRoot, /harness$/u)
  assert.match(parsed.nodePath, /runtime[\\/]node$/u)
  assert.match(parsed.overlayPath, /connection\.patch\.yml$/u)
  assert.throws(() => parseCompatibilityArguments(['--harness-root', 'harness']), /usage:/u)
  assert.throws(() => parseCompatibilityArguments([
    '--harness-root', 'harness', '--node-path', 'node', '--overlay', 'one', '--overlay', 'two',
  ]), /usage:/u)
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
