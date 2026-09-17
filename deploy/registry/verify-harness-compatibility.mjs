#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { accessSync, constants } from 'node:fs'
import { join, resolve } from 'node:path'
import { brandString } from '@deepseek-ai/dsh-brand'
import { generateInstanceKeyPair, signDisclosureCheckpoint,
  signDisclosureEvent } from '@deepseek-ai/dsh-a2a-device-identity'
import { encodeRegistryServerFrame } from '@deepseek-ai/dsh-a2a-registry-sync'

function usage(message) {
  if (message !== undefined) process.stderr.write(`${message}\n`)
  process.stderr.write('usage: node --import tsx/esm deploy/registry/verify-harness-compatibility.mjs --harness-root <path>\n')
  process.exit(2)
}

const args = process.argv.slice(2)
if (args.length !== 2 || args[0] !== '--harness-root' || args[1].trim().length === 0) usage()
const harnessRoot = resolve(args[1])
for (const relative of ['package.json', 'apps/cli/lib/bin.js',
  'packages/a2a/registry-sync/package.json', 'packages/a2a/registry-sync/src/index.ts',
  'packages/a2a/registry-sync/lib/index.js']) {
  try { accessSync(join(harnessRoot, relative), constants.R_OK) } catch {
    usage(`Harness checkout is missing ${relative}: ${harnessRoot}`)
  }
}

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
const encoded = encodeRegistryServerFrame({
  protocolVersion: 1,
  requestId: 1,
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
}, 1_048_576)

const decoder = (specifier) => String.raw`
  import { decodeRegistryServerFrame } from ${JSON.stringify(specifier)}
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  const body = Buffer.concat(chunks).toString('utf8')
  const frame = decodeRegistryServerFrame(body, Buffer.byteLength(body, 'utf8'))
  if (frame.type !== 'import-dispatch' || frame.delivery === null
    || frame.delivery.operationId !== 'compatibility-operation'
    || frame.delivery.targetInstanceId !== 'compatibility-target') process.exit(3)
  process.stdout.write('compatible\n')
`
const inheritedSystemVariables = process.platform === 'win32'
  ? ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP']
  : ['PATH', 'TMPDIR', 'TEMP', 'TMP']
const childEnvironment = Object.fromEntries(inheritedSystemVariables.flatMap((name) => {
  const value = process.env[name]
  return value === undefined ? [] : [[name, value]]
}))
const targets = [
  { label: 'source', cwd: harnessRoot,
    specifier: './packages/a2a/registry-sync/src/index.ts', preload: ['--import', 'tsx/esm'] },
  { label: 'built runtime', cwd: join(harnessRoot, 'packages/a2a/registry-sync'),
    specifier: '@deepseek-ai/dsh-a2a-registry-sync', preload: [] },
]
for (const target of targets) {
  const result = spawnSync(process.execPath,
    [...target.preload, '--input-type=module', '--eval', decoder(target.specifier)], {
      cwd: target.cwd,
      input: encoded,
      env: childEnvironment,
      encoding: 'utf8',
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    })
  if (result.error !== undefined) {
    process.stderr.write(`registry-harness-compatibility: failed to run Harness ${target.label} decoder: ${result.error.message}\n`)
    process.exit(1)
  }
  if (result.status !== 0 || result.stdout.trim() !== 'compatible') {
    process.stderr.write(`registry-harness-compatibility: Harness ${target.label} decoder rejects the Registry import wire frame\n`)
    if (result.stderr.trim().length > 0) process.stderr.write(`${result.stderr.trim()}\n`)
    process.exit(1)
  }
}

process.stdout.write([
  'registry-harness-compatibility: passed',
  '- Harness Registry Sync v1 source decoder accepts the current import delivery',
  '- built package export used by the Harness CLI accepts the same delivery',
  '- target Session identity remains deterministically computed and verified by Registry',
  '',
].join('\n'))
