import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto'
import { createServer } from 'node:http'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { assertPrivateWindowsSecretPath } from '../deploy/registry/enroll-registry-device.mjs'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const enrollment = join(repository, 'deploy', 'registry', 'enroll-registry-device.mjs')
const windowsGate = join(repository, 'deploy', 'registry', 'windows-private-path-gate.ps1')

function run(command, arguments_, options) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, arguments_, { ...options, shell: false, windowsHide: true })
    const output = { stdout: [], stderr: [] }
    let timer
    child.stdout.on('data', chunk => output.stdout.push(chunk))
    child.stderr.on('data', chunk => output.stderr.push(chunk))
    child.once('error', rejectPromise)
    child.once('close', code => {
      clearTimeout(timer)
      resolvePromise({
        code,
        stdout: Buffer.concat(output.stdout).toString('utf8'),
        stderr: Buffer.concat(output.stderr).toString('utf8'),
      })
    })
    timer = setTimeout(() => {
      child.kill()
      rejectPromise(new Error('enrollment path-gate test timed out'))
    }, 10_000)
    timer.unref()
  })
}

function windowsCommand(command, arguments_) {
  const result = spawnSync(command, arguments_, { encoding: 'utf8', windowsHide: true })
  assert.equal(result.status, 0, result.stderr || result.stdout)
  return result.stdout.trim()
}

function protectDirectory(path) {
  const sid = windowsCommand('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
  ])
  windowsCommand('icacls.exe', [path, '/inheritance:r', '/grant:r',
    `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'])
}

test('Windows private-path gate is injectable and skipped on non-Windows hosts', async () => {
  const calls = []
  const runGate = async (...arguments_) => calls.push(arguments_)
  await assertPrivateWindowsSecretPath('C:\\private\\device.json', 'NewFile', {
    platform: 'win32', environment: {
      OS: 'Windows_NT', SystemRoot: 'C:\\Windows', DSH_REGISTRY_DEVICE_TOKEN: 'must-not-pass',
    }, runGate,
  })
  await assertPrivateWindowsSecretPath('/private/device.json', 'ReadFile', {
    platform: 'linux', environment: {}, runGate,
  })
  assert.deepEqual(calls, [[
    'C:\\private\\device.json', 'NewFile', { OS: 'Windows_NT', SystemRoot: 'C:\\Windows' },
  ]])
})

test('Windows executable trust gate accepts protected system tools and ignores read-only localized principals', {
  skip: process.platform !== 'win32' ? 'Windows ACL integration test' : false,
}, () => {
  const quotedGate = windowsGate.replaceAll("'", "''")
  windowsCommand('pwsh.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    `$ErrorActionPreference='Stop'; . '${quotedGate}'; `
      + '$system=[Environment]::GetFolderPath([Environment+SpecialFolder]::System); '
      + "Assert-NoUntrustedNamespaceReplacement $system 'system'; "
      + "foreach($name in 'icacls.exe','tar.exe','cmd.exe'){"
      + "$path=Resolve-ExistingFile (Join-Path $system $name) $name;"
      + 'Assert-NoUnauthorizedWriteAcl $path $name $false}',
  ])
})

test('Windows enrollment rejects an inherited parent ACL before network or state-file creation', {
  skip: process.platform !== 'win32' ? 'Windows ACL integration test' : false,
}, async t => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-enrollment-inherited-acl-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const state = join(root, 'registry-device.json')
  let requests = 0
  const server = createServer((_request, response) => {
    requests += 1
    response.writeHead(500, { 'content-type': 'application/json; charset=utf-8' })
    response.end('{"ok":false}')
  })
  await new Promise((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise)
    server.listen(0, '127.0.0.1', resolvePromise)
  })
  t.after(() => new Promise(resolvePromise => server.close(resolvePromise)))
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  const result = await run(process.execPath, [
    enrollment,
    'start',
    '--registry-origin', `http://127.0.0.1:${address.port}/`,
    '--organization-id', 'path-gate-test',
    '--instance-name', 'Path gate test',
    '--state', state,
  ], { cwd: repository, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] })
  assert.notEqual(result.code, 0)
  assert.match(result.stderr, /Windows 长期凭据路径或 ACL 检查失败/u)
  assert.equal(result.stdout, '')
  assert.equal(requests, 0)
  assert.equal(existsSync(state), false)
})

test('Windows private-path gate rejects Deny ACEs and replaceable ancestor namespaces', {
  skip: process.platform !== 'win32' ? 'Windows ACL integration test' : false,
}, async t => {
  const root = mkdtempSync(join(homedir(), 'dsh-enrollment-private-acl-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  protectDirectory(root)
  const privateDirectory = join(root, 'device')
  mkdirSync(privateDirectory)
  protectDirectory(privateDirectory)
  const state = join(privateDirectory, 'registry-device.json')

  await assertPrivateWindowsSecretPath(state, 'NewFile')

  windowsCommand('icacls.exe', [privateDirectory, '/deny', '*S-1-1-0:(D)'])
  await assert.rejects(assertPrivateWindowsSecretPath(state, 'NewFile'), /路径或 ACL 检查失败/u)
  windowsCommand('icacls.exe', [privateDirectory, '/remove:d', '*S-1-1-0'])
  await assertPrivateWindowsSecretPath(state, 'NewFile')

  windowsCommand('icacls.exe', [root, '/grant', '*S-1-1-0:(DC)'])
  await assert.rejects(assertPrivateWindowsSecretPath(state, 'NewFile'), /路径或 ACL 检查失败/u)
})

test('legacy V1 enrollment confirms and exports five connection-only values without inventing dshb1', {
  timeout: 30_000,
}, async t => {
  const root = mkdtempSync(join(homedir(), 'dsh-enrollment-v1-'))
  if (process.platform === 'win32') protectDirectory(root)
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 3 }))
  const statePath = join(root, 'registry-device.json')
  const outputPath = join(root, 'harness.env')
  const bindingId = '00000000-0000-4000-8000-000000000004'
  const instanceId = '00000000-0000-4000-8000-000000000005'
  const pairingCode = Buffer.alloc(32, 0x21).toString('base64url')
  const deviceSecret = Buffer.alloc(32, 0x22).toString('base64url')
  const nonce = Buffer.alloc(32, 0x23).toString('base64url')
  const pair = generateKeyPairSync('ed25519')
  const publicKeySpki = createPublicKey(pair.privateKey).export({ format: 'der', type: 'spki' })
  const keyId = `sha256:${createHash('sha256').update(publicKeySpki).digest('hex')}`
  const privateKeyPkcs8 = pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url')
  let confirmations = 0
  const server = createServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    assert.deepEqual(Object.keys(body), ['proof'])
    assert.match(body.proof, /^[A-Za-z0-9_-]+$/u)
    confirmations += 1
    response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
    response.end(JSON.stringify({ ok: true, value: { bindingId, phase: 'confirmed' } }))
  })
  await new Promise((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise)
    server.listen(0, '127.0.0.1', resolvePromise)
  })
  t.after(() => new Promise(resolvePromise => server.close(resolvePromise)))
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  const expiresAt = Date.now() + 60_000
  const challenge = {
    version: 1,
    audience: 'wss://registry.example/a2a/v1/sync',
    organizationId: 'v1-enrollment',
    instanceId,
    keyId,
    nonce,
    expiresAt,
  }
  writeFileSync(statePath, `${JSON.stringify({
    version: 1,
    phase: 'pending',
    registryOrigin: `http://127.0.0.1:${address.port}/`,
    organizationId: 'v1-enrollment',
    bindingId,
    instanceId,
    keyId,
    instanceName: 'V1 enrollment',
    requestedScopes: ['disclosure.sync'],
    expiresAt,
    challenge,
    pairingCode,
    deviceSecret,
    privateKeyPkcs8,
  }, null, 2)}\n`, { flag: 'wx', mode: 0o600 })
  const environment = Object.fromEntries(Object.entries(process.env)
    .filter(([name]) => name !== 'NODE_OPTIONS' && name !== 'NODE_PATH'))

  const confirmedResult = await run(process.execPath, [enrollment, 'confirm', '--state', statePath], {
    cwd: repository, env: environment, stdio: ['ignore', 'pipe', 'pipe'],
  })
  assert.equal(confirmedResult.code, 0, confirmedResult.stderr)
  assert.equal(confirmations, 1)
  assert.match(confirmedResult.stdout, /仅支持 WSS 连接/u)
  assert.doesNotMatch(confirmedResult.stdout, /dshb?1\./u)
  assert.doesNotMatch(confirmedResult.stdout, new RegExp(deviceSecret, 'u'))
  const confirmed = JSON.parse(readFileSync(statePath, 'utf8'))
  assert.equal(confirmed.version, 1)
  assert.equal(confirmed.phase, 'confirmed')
  assert.match(confirmed.deviceToken, /^dsh1\./u)
  assert.equal(Object.hasOwn(confirmed, 'bridgeToken'), false)
  assert.equal(Object.hasOwn(confirmed, 'bridgeSecretHash'), false)

  const exported = await run(process.execPath, [
    enrollment, 'export-env', '--state', statePath, '--output', outputPath,
  ], { cwd: repository, env: environment, stdio: ['ignore', 'pipe', 'pipe'] })
  assert.equal(exported.code, 0, exported.stderr)
  assert.match(exported.stdout, /旧版五项环境文件仅支持 WSS 连接/u)
  assert.doesNotMatch(exported.stdout, /dshb?1\./u)
  assert.doesNotMatch(exported.stdout, new RegExp(deviceSecret, 'u'))
  const entries = new Map(readFileSync(outputPath, 'utf8').trim().split('\n').map(line => {
    const separator = line.indexOf('=')
    return [line.slice(0, separator), line.slice(separator + 1)]
  }))
  assert.equal(entries.size, 5)
  assert.equal(entries.get('DSH_REGISTRY_DEVICE_TOKEN'), confirmed.deviceToken)
  assert.equal(entries.has('DSH_REGISTRY_DISCLOSURE_TOKEN'), false)
})

test('enrollment exports independent dsh1 and dshb1 credentials without printing either secret', {
  timeout: 30_000,
}, async t => {
  const root = mkdtempSync(join(homedir(), 'dsh-enrollment-v6-'))
  if (process.platform === 'win32') protectDirectory(root)
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 3 }))
  const statePath = join(root, 'registry-device.json')
  const outputPath = join(root, 'harness.env')
  const bindingId = '00000000-0000-4000-8000-000000000006'
  const pairingCode = Buffer.alloc(32, 0x31).toString('base64url')
  const nonce = Buffer.alloc(32, 0x32).toString('base64url')
  const requests = []
  const server = createServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    requests.push({ url: request.url, body })
    let value
    if (request.url?.endsWith('/bindings/start')) {
      const keyId = `sha256:${createHash('sha256').update(Buffer.from(body.publicKeySpki, 'base64url')).digest('hex')}`
      value = { bindingId, code: pairingCode, challenge: {
        version: 1,
        audience: 'wss://registry.example/a2a/v1/sync',
        organizationId: 'v6-enrollment',
        instanceId: '00000000-0000-4000-8000-000000000007',
        keyId,
        nonce,
        expiresAt: Date.now() + 60_000,
      } }
    } else value = { bindingId, phase: 'confirmed' }
    response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
    response.end(JSON.stringify({ ok: true, value }))
  })
  await new Promise((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise)
    server.listen(0, '127.0.0.1', resolvePromise)
  })
  t.after(() => new Promise(resolvePromise => server.close(resolvePromise)))
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  const environment = Object.fromEntries(Object.entries(process.env)
    .filter(([name]) => name !== 'NODE_OPTIONS' && name !== 'NODE_PATH'))

  const started = await run(process.execPath, [
    enrollment, 'start',
    '--registry-origin', `http://127.0.0.1:${address.port}/`,
    '--organization-id', 'v6-enrollment',
    '--instance-name', 'V6 enrollment',
    '--state', statePath,
  ], { cwd: repository, env: environment, stdio: ['ignore', 'pipe', 'pipe'] })
  assert.equal(started.code, 0, started.stderr)
  assert.doesNotMatch(started.stdout, /dshb?1\./u)
  const pending = JSON.parse(readFileSync(statePath, 'utf8'))
  assert.equal(pending.version, 2)
  assert.equal(pending.phase, 'pending')
  assert.notEqual(pending.deviceSecret, pending.bridgeSecret)
  assert.equal(requests[0]?.body.deviceSecretHash.startsWith('sha256:'), true)
  assert.equal(requests[0]?.body.bridgeSecretHash.startsWith('sha256:'), true)
  assert.notEqual(requests[0]?.body.deviceSecretHash, requests[0]?.body.bridgeSecretHash)
  assert.doesNotMatch(started.stdout, new RegExp(`${pending.deviceSecret}|${pending.bridgeSecret}`, 'u'))

  const confirmedResult = await run(process.execPath, [enrollment, 'confirm', '--state', statePath], {
    cwd: repository, env: environment, stdio: ['ignore', 'pipe', 'pipe'],
  })
  assert.equal(confirmedResult.code, 0, confirmedResult.stderr)
  const confirmed = JSON.parse(readFileSync(statePath, 'utf8'))
  assert.equal(confirmed.phase, 'confirmed')
  assert.equal(Object.hasOwn(confirmed, 'deviceSecret'), false)
  assert.equal(Object.hasOwn(confirmed, 'bridgeSecret'), false)
  assert.match(confirmed.deviceToken, /^dsh1\./u)
  assert.match(confirmed.bridgeToken, /^dshb1\./u)
  assert.notEqual(confirmed.deviceToken.split('.')[3], confirmed.bridgeToken.split('.')[3])
  assert.doesNotMatch(confirmedResult.stdout, /dshb?1\./u)

  const exported = await run(process.execPath, [
    enrollment, 'export-env', '--state', statePath, '--output', outputPath,
  ], { cwd: repository, env: environment, stdio: ['ignore', 'pipe', 'pipe'] })
  assert.equal(exported.code, 0, exported.stderr)
  const entries = new Map(readFileSync(outputPath, 'utf8').trim().split('\n').map(line => {
    const separator = line.indexOf('=')
    return [line.slice(0, separator), line.slice(separator + 1)]
  }))
  assert.equal(entries.size, 6)
  assert.equal(entries.get('DSH_REGISTRY_DEVICE_TOKEN'), confirmed.deviceToken)
  assert.equal(entries.get('DSH_REGISTRY_DISCLOSURE_TOKEN'), confirmed.bridgeToken)
  assert.doesNotMatch(exported.stdout, /dshb?1\./u)
})
