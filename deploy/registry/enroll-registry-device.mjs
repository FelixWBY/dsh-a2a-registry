#!/usr/bin/env node
import { constants as fsConstants, realpathSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { lstat, open, rename, rm } from 'node:fs/promises'
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const LEGACY_STATE_VERSION = 1
const STATE_VERSION = 2
const MAX_RESPONSE_BYTES = 32 * 1024
const MAX_STATE_BYTES = 64 * 1024
const REQUEST_TIMEOUT_MS = 15_000
const WINDOWS_PATH_GATE_TIMEOUT_MS = 15_000
const MAX_WINDOWS_PATH_GATE_OUTPUT_BYTES = 4 * 1024
const WINDOWS_PATH_GATE = fileURLToPath(new URL('./windows-private-path-gate.ps1', import.meta.url))
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/u
const KEY_ID = /^sha256:[0-9a-f]{64}$/u
const ALLOWED_SCOPES = new Set(['disclosure.sync', 'a2a.receive'])
const DEVICE_SECRET_HASH_DOMAIN = Buffer.from('dsh:a2a:registry-device-secret:v1\0', 'utf8')
const BRIDGE_SECRET_HASH_DOMAIN = Buffer.from('dsh:a2a:registry-disclosure-bridge-secret:v1\0', 'utf8')

class CliFailure extends Error {
  constructor(message, exitCode = 1) {
    super(message)
    this.name = 'RegistryEnrollmentCliFailure'
    this.exitCode = exitCode
  }
}

function fail(message, exitCode = 1) {
  throw new CliFailure(message, exitCode)
}

function usage() {
  return [
    '用法：',
    '  node deploy/registry/enroll-registry-device.mjs start --registry-origin <URL> --organization-id <ID> --instance-name <名称> --state <绝对路径> [--scope disclosure.sync] [--scope a2a.receive]',
    '  node deploy/registry/enroll-registry-device.mjs confirm --state <绝对路径>',
    '  node deploy/registry/enroll-registry-device.mjs export-env --state <绝对路径> --output <绝对路径>',
  ].join('\n')
}

function checkNodeRuntime() {
  const [major = 0] = process.versions.node.split('.').map(Number)
  if (major < 24) fail('需要 Node.js 24 或更高版本。', 2)
}

function exactRecord(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  const actual = Object.keys(value)
  if (actual.length !== keys.length || actual.some(key => !keys.includes(key))) return null
  return value
}

function canonicalBase64Url(value, byteLength) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) return false
  const bytes = Buffer.from(value, 'base64url')
  return bytes.length === byteLength && bytes.toString('base64url') === value
}

function generateInstanceKeyPair() {
  const pair = generateKeyPairSync('ed25519')
  const publicKeySpki = pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url')
  const keyId = `sha256:${createHash('sha256').update(Buffer.from(publicKeySpki, 'base64url')).digest('hex')}`
  return { privateKey: pair.privateKey, publicKeySpki, keyId }
}

function generateRegistryDeviceSecret() {
  return randomBytes(32).toString('base64url')
}

function generateRegistryBridgeSecret() {
  return randomBytes(32).toString('base64url')
}

function hashRegistryDeviceSecret(secret) {
  if (!canonicalBase64Url(secret, 32)) fail('设备状态文件无效。')
  const bytes = Buffer.from(secret, 'base64url')
  try { return `sha256:${createHash('sha256').update(DEVICE_SECRET_HASH_DOMAIN).update(bytes).digest('hex')}` }
  finally { bytes.fill(0) }
}

function hashRegistryBridgeSecret(secret) {
  if (!canonicalBase64Url(secret, 32)) fail('设备状态文件无效。')
  const bytes = Buffer.from(secret, 'base64url')
  try { return `sha256:${createHash('sha256').update(BRIDGE_SECRET_HASH_DOMAIN).update(bytes).digest('hex')}` }
  finally { bytes.fill(0) }
}

function encodeRegistryDeviceToken({ organizationId, bindingId, secret }) {
  if (!IDENTIFIER.test(organizationId) || !UUID.test(bindingId) || !canonicalBase64Url(secret, 32)) {
    fail('设备状态文件无效。')
  }
  const encodedOrganization = Buffer.from(organizationId, 'utf8').toString('base64url')
  const token = `dsh1.${encodedOrganization}.${bindingId}.${secret}`
  if (Buffer.byteLength(token, 'utf8') > 512) fail('设备状态文件无效。')
  return token
}

function decodeRegistryDeviceToken(token) {
  if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > 512) fail('设备状态文件无效。')
  const parts = token.split('.')
  if (parts.length !== 4 || parts[0] !== 'dsh1' || !UUID.test(parts[2] ?? '')
    || !canonicalBase64Url(parts[3], 32) || !/^[A-Za-z0-9_-]+$/u.test(parts[1] ?? '')) {
    fail('设备状态文件无效。')
  }
  const organizationBytes = Buffer.from(parts[1], 'base64url')
  if (organizationBytes.length === 0 || organizationBytes.toString('base64url') !== parts[1]) {
    fail('设备状态文件无效。')
  }
  const organizationId = organizationBytes.toString('utf8')
  if (!IDENTIFIER.test(organizationId)
    || Buffer.from(organizationId, 'utf8').toString('base64url') !== parts[1]) fail('设备状态文件无效。')
  const result = { organizationId, bindingId: parts[2], secret: parts[3] }
  if (encodeRegistryDeviceToken(result) !== token) fail('设备状态文件无效。')
  return result
}

function encodeRegistryBridgeToken({ organizationId, bindingId, secret }) {
  if (!IDENTIFIER.test(organizationId) || !UUID.test(bindingId) || !canonicalBase64Url(secret, 32)) {
    fail('设备状态文件无效。')
  }
  const encodedOrganization = Buffer.from(organizationId, 'utf8').toString('base64url')
  const token = `dshb1.${encodedOrganization}.${bindingId}.${secret}`
  if (Buffer.byteLength(token, 'utf8') > 512) fail('设备状态文件无效。')
  return token
}

function decodeRegistryBridgeToken(token) {
  if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > 512) fail('设备状态文件无效。')
  const parts = token.split('.')
  if (parts.length !== 4 || parts[0] !== 'dshb1' || !UUID.test(parts[2] ?? '')
    || !canonicalBase64Url(parts[3], 32) || !/^[A-Za-z0-9_-]+$/u.test(parts[1] ?? '')) {
    fail('设备状态文件无效。')
  }
  const organizationBytes = Buffer.from(parts[1], 'base64url')
  if (organizationBytes.length === 0 || organizationBytes.toString('base64url') !== parts[1]) {
    fail('设备状态文件无效。')
  }
  const organizationId = organizationBytes.toString('utf8')
  if (!IDENTIFIER.test(organizationId)
    || Buffer.from(organizationId, 'utf8').toString('base64url') !== parts[1]) fail('设备状态文件无效。')
  const result = { organizationId, bindingId: parts[2], secret: parts[3] }
  if (encodeRegistryBridgeToken(result) !== token) fail('设备状态文件无效。')
  return result
}

function decodeRegistryChallenge(input) {
  const value = exactRecord(input, ['version', 'audience', 'organizationId', 'instanceId', 'keyId', 'nonce', 'expiresAt'])
  if (value === null || value.version !== 1
    || typeof value.organizationId !== 'string' || !IDENTIFIER.test(value.organizationId)
    || typeof value.instanceId !== 'string' || !IDENTIFIER.test(value.instanceId)
    || typeof value.keyId !== 'string' || !KEY_ID.test(value.keyId)
    || !canonicalBase64Url(value.nonce, 32)
    || !Number.isSafeInteger(value.expiresAt) || value.expiresAt < 0 || Object.is(value.expiresAt, -0)
    || typeof value.audience !== 'string') fail('Registry 返回了无效响应。')
  let audience
  try { audience = new URL(value.audience) } catch { fail('Registry 返回了无效响应。') }
  if (audience.protocol !== 'wss:' || audience.href !== value.audience || audience.username !== ''
    || audience.password !== '' || audience.search !== '' || audience.hash !== '') {
    fail('Registry 返回了无效响应。')
  }
  return Object.freeze({ ...value })
}

function signRegistryChallenge(challenge, privateKey) {
  const value = decodeRegistryChallenge(challenge)
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') fail('设备状态文件无效。')
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  if (value.keyId !== `sha256:${createHash('sha256').update(spki).digest('hex')}`) fail('设备状态文件无效。')
  const message = Buffer.from(JSON.stringify(['dsh:a2a:registry-device-proof', value.version, value.audience,
    value.organizationId, value.instanceId, value.keyId, value.nonce, value.expiresAt]), 'utf8')
  return sign(null, message, privateKey).toString('base64url')
}

function absolutePath(value, argument) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || !isAbsolute(value)) {
    fail(`${argument} 必须是绝对路径。`, 2)
  }
  return value
}

function windowsGateEnvironment(environment) {
  const allowed = new Set(['COMSPEC', 'OS', 'PATHEXT', 'SYSTEMROOT', 'TEMP', 'TMP', 'WINDIR'])
  const selected = {}
  for (const [name, value] of Object.entries(environment)) {
    if (typeof value === 'string' && allowed.has(name.toUpperCase())) selected[name] = value
  }
  return selected
}

function windowsPowerShell(environment) {
  const entries = Object.entries(environment)
  const root = entries.find(([name]) => name.toUpperCase() === 'SYSTEMROOT')?.[1]
    ?? entries.find(([name]) => name.toUpperCase() === 'WINDIR')?.[1]
  if (typeof root !== 'string' || !/^[A-Za-z]:[\\/]/u.test(root) || root.includes('\0')) {
    fail('无法定位 Windows 路径权限检查器。')
  }
  return join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
}

async function defaultWindowsPathGate(path, mode, environment) {
  const executable = windowsPowerShell(environment)
  await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(executable, [
      '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', WINDOWS_PATH_GATE, '-Mode', mode,
    ], {
      env: environment,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
    let outputBytes = 0
    let settled = false
    let timer
    const finish = error => {
      if (settled) return
      settled = true
      if (timer !== undefined) clearTimeout(timer)
      if (error === undefined) resolvePromise()
      else rejectPromise(error)
    }
    const receive = chunk => {
      outputBytes += chunk.length
      if (outputBytes > MAX_WINDOWS_PATH_GATE_OUTPUT_BYTES) child.kill()
    }
    child.stdout.on('data', receive)
    child.stderr.on('data', receive)
    child.once('error', () => finish(new CliFailure('Windows 长期凭据路径或 ACL 检查失败。')))
    child.stdin.once('error', () => finish(new CliFailure('Windows 长期凭据路径或 ACL 检查失败。')))
    child.once('close', code => finish(code === 0 && outputBytes <= MAX_WINDOWS_PATH_GATE_OUTPUT_BYTES
      ? undefined : new CliFailure('Windows 长期凭据路径或 ACL 检查失败。')))
    timer = setTimeout(() => {
      child.kill()
      finish(new CliFailure('Windows 长期凭据路径或 ACL 检查失败。'))
    }, WINDOWS_PATH_GATE_TIMEOUT_MS)
    timer.unref()
    child.stdin.end(path, 'utf8')
  })
}

export async function assertPrivateWindowsSecretPath(path, mode, {
  platform = process.platform,
  environment = process.env,
  runGate = defaultWindowsPathGate,
} = {}) {
  if (platform !== 'win32') return
  if (!['NewFile', 'ReadFile', 'ReplaceFile'].includes(mode)) fail('Windows 路径权限检查模式无效。')
  await runGate(path, mode, windowsGateEnvironment(environment))
}

function identifier(value, argument) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) fail(`${argument} 不是有效标识符。`, 2)
  return value
}

function instanceName(value) {
  if (typeof value !== 'string' || value.length === 0 || value !== value.trim()
    || !value.isWellFormed() || /[\u0000-\u001f\u007f]/u.test(value)
    || Buffer.byteLength(value, 'utf8') > 256) {
    fail('--instance-name 必须是 1 至 256 字节的单行名称。', 2)
  }
  return value
}

function registryOrigin(value) {
  let parsed
  try { parsed = new URL(value) } catch { fail('--registry-origin 必须是绝对 URL。', 2) }
  const loopback = parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]' || parsed.hostname === 'localhost'
  if ((parsed.protocol !== 'https:' && !(loopback && parsed.protocol === 'http:'))
    || parsed.username !== '' || parsed.password !== '' || parsed.search !== '' || parsed.hash !== ''
    || parsed.pathname !== '/' || parsed.href !== `${parsed.origin}/`) {
    fail('--registry-origin 必须是 HTTPS 根地址；只有回环地址可使用 HTTP。', 2)
  }
  return parsed.href
}

function parseArguments(argv) {
  const [command, ...rest] = argv
  if (!['start', 'confirm', 'export-env'].includes(command)) fail(usage(), 2)
  const values = new Map()
  const scopes = []
  for (let index = 0; index < rest.length; index += 2) {
    const name = rest[index]
    const value = rest[index + 1]
    if (typeof name !== 'string' || !name.startsWith('--') || value === undefined) fail(usage(), 2)
    if (name === '--scope') {
      scopes.push(value)
      continue
    }
    if (values.has(name)) fail(`参数 ${name} 不能重复。`, 2)
    values.set(name, value)
  }
  const allowed = command === 'start'
    ? new Set(['--registry-origin', '--organization-id', '--instance-name', '--state'])
    : command === 'confirm' ? new Set(['--state']) : new Set(['--state', '--output'])
  if ([...values.keys()].some(name => !allowed.has(name)) || command !== 'start' && scopes.length > 0) fail(usage(), 2)
  for (const name of allowed) if (!values.has(name)) fail(`缺少参数 ${name}。`, 2)
  if (command === 'start') {
    const selectedScopes = scopes.length === 0 ? ['disclosure.sync', 'a2a.receive'] : scopes
    if (selectedScopes.some(scope => !ALLOWED_SCOPES.has(scope))
      || new Set(selectedScopes).size !== selectedScopes.length) {
      fail('--scope 只允许不重复的 disclosure.sync 或 a2a.receive。', 2)
    }
    return {
      command,
      registryOrigin: registryOrigin(values.get('--registry-origin')),
      organizationId: identifier(values.get('--organization-id'), '--organization-id'),
      instanceName: instanceName(values.get('--instance-name')),
      statePath: absolutePath(values.get('--state'), '--state'),
      scopes: selectedScopes,
    }
  }
  return {
    command,
    statePath: absolutePath(values.get('--state'), '--state'),
    ...(command === 'export-env' ? { outputPath: absolutePath(values.get('--output'), '--output') } : {}),
  }
}

async function syncParent(path) {
  if (process.platform === 'win32') return
  let directory
  try {
    directory = await open(dirname(path), 'r')
    await directory.sync()
  } catch {
    // The file itself was fsynced. Some filesystems do not permit directory fsync.
  } finally {
    await directory?.close().catch(() => {})
  }
}

async function reserveExclusive(path, diagnostic) {
  let handle
  let created = false
  try {
    await assertPrivateWindowsSecretPath(path, 'NewFile')
    const parent = await lstat(dirname(path))
    if (!parent.isDirectory() || parent.isSymbolicLink()) fail('输出目录不可用。')
    handle = await open(path, 'wx', 0o600)
    created = true
    await handle.chmod(0o600)
    return handle
  } catch (error) {
    await handle?.close().catch(() => {})
    if (created) await rm(path, { force: true }).catch(() => {})
    if (error instanceof CliFailure) throw error
    if (error?.code === 'EEXIST') fail(diagnostic)
    fail('无法安全写入文件。')
  }
}

async function discardReservation(path, handle) {
  await handle?.close().catch(() => {})
  await rm(path, { force: true }).catch(() => {})
  await syncParent(path)
}

async function commitReservation(path, handle, content) {
  try {
    await assertPrivateWindowsSecretPath(path, 'ReplaceFile')
    await handle.writeFile(content, { encoding: 'utf8' })
    await handle.sync()
    await handle.close()
    await syncParent(path)
  } catch (error) {
    await discardReservation(path, handle)
    if (error instanceof CliFailure) throw error
    fail('无法安全写入文件。')
  }
}

async function writeExclusive(path, content, diagnostic) {
  const handle = await reserveExclusive(path, diagnostic)
  await commitReservation(path, handle, content)
}

async function readPrivateJson(path) {
  let handle
  try {
    await assertPrivateWindowsSecretPath(path, 'ReadFile')
    const entry = await lstat(path)
    if (!entry.isFile() || entry.isSymbolicLink() || entry.size <= 0 || entry.size > MAX_STATE_BYTES) {
      fail('设备状态文件无效。')
    }
    if (process.platform !== 'win32' && (entry.mode & 0o077) !== 0) fail('设备状态文件权限必须为 0600。')
    const noFollow = fsConstants.O_NOFOLLOW ?? 0
    handle = await open(path, fsConstants.O_RDONLY | noFollow)
    const current = await handle.stat()
    if (!current.isFile() || current.size !== entry.size || current.size > MAX_STATE_BYTES
      || current.dev !== entry.dev || current.ino !== entry.ino) fail('设备状态文件无效。')
    const text = await handle.readFile({ encoding: 'utf8' })
    await handle.close()
    handle = undefined
    return JSON.parse(text)
  } catch (error) {
    await handle?.close().catch(() => {})
    if (error instanceof CliFailure) throw error
    fail('无法读取设备状态文件。')
  }
}

async function replaceAtomically(path, content) {
  await assertPrivateWindowsSecretPath(path, 'ReplaceFile')
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  let handle
  try {
    handle = await open(temporary, 'wx', 0o600)
    await handle.chmod(0o600)
    await handle.writeFile(content, { encoding: 'utf8' })
    await handle.sync()
    await handle.close()
    handle = undefined
    await rename(temporary, path)
    await syncParent(path)
  } catch (error) {
    await handle?.close().catch(() => {})
    await rm(temporary, { force: true }).catch(() => {})
    fail('无法原子更新设备状态文件。')
  }
}

async function readBoundedJson(response) {
  const length = response.headers.get('content-length')
  if (length !== null && (!/^(0|[1-9]\d*)$/u.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
    fail('Registry 返回了无效响应。')
  }
  const reader = response.body?.getReader()
  if (reader === undefined) fail('Registry 返回了无效响应。')
  const chunks = []
  let size = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {})
      fail('Registry 返回了无效响应。')
    }
    chunks.push(value)
  }
  let text
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size)) } catch {
    fail('Registry 返回了无效响应。')
  }
  try { return JSON.parse(text) } catch { fail('Registry 返回了无效响应。') }
}

async function postJson(url, body, action) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  let response
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8', 'accept': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: controller.signal,
    })
    const contentType = response.headers.get('content-type') ?? ''
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) {
      fail('Registry 返回了无效响应。')
    }
    const parsed = await readBoundedJson(response)
    if (response.status !== 200) fail(`Registry 拒绝请求，${action}未完成。`)
    const envelope = exactRecord(parsed, ['ok', 'value'])
    if (envelope === null || envelope.ok !== true) fail('Registry 返回了无效响应。')
    return envelope.value
  } catch (error) {
    if (error instanceof CliFailure) throw error
    fail(`无法连接 Registry，${action}未完成。`)
  } finally {
    clearTimeout(timer)
  }
}

function privateKeyFromPkcs8(encoded) {
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(encoded)) fail('设备状态文件无效。')
  const bytes = Buffer.from(encoded, 'base64url')
  try {
    if (bytes.length < 48 || bytes.toString('base64url') !== encoded) fail('设备状态文件无效。')
    const key = createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' })
    const canonical = key.export({ format: 'der', type: 'pkcs8' })
    if (key.asymmetricKeyType !== 'ed25519' || !Buffer.isBuffer(canonical) || !canonical.equals(bytes)) {
      fail('设备状态文件无效。')
    }
    return key
  } catch (error) {
    if (error instanceof CliFailure) throw error
    fail('设备状态文件无效。')
  } finally {
    bytes.fill(0)
  }
}

function canonicalChallenge(value) {
  try { return decodeRegistryChallenge(value) } catch { fail('设备状态文件无效。') }
}

function pendingState(input) {
  const legacy = input?.version === LEGACY_STATE_VERSION
  const keys = ['version', 'phase', 'registryOrigin', 'organizationId', 'bindingId', 'instanceId', 'keyId',
    'instanceName', 'requestedScopes', 'expiresAt', 'challenge', 'pairingCode', 'deviceSecret',
    ...(legacy ? [] : ['bridgeSecret']), 'privateKeyPkcs8']
  const state = exactRecord(input, keys)
  if (state === null || ![LEGACY_STATE_VERSION, STATE_VERSION].includes(state.version)
    || state.phase !== 'pending'
    || typeof state.bindingId !== 'string' || !UUID.test(state.bindingId)
    || typeof state.organizationId !== 'string' || !IDENTIFIER.test(state.organizationId)
    || typeof state.instanceId !== 'string' || !IDENTIFIER.test(state.instanceId)
    || typeof state.keyId !== 'string' || !KEY_ID.test(state.keyId)
    || typeof state.pairingCode !== 'string' || !BASE64URL_32.test(state.pairingCode)
    || typeof state.deviceSecret !== 'string' || !BASE64URL_32.test(state.deviceSecret)
    || (!legacy && (typeof state.bridgeSecret !== 'string' || !BASE64URL_32.test(state.bridgeSecret)
      || state.bridgeSecret === state.deviceSecret))
    || !Array.isArray(state.requestedScopes) || state.requestedScopes.length === 0
    || state.requestedScopes.some(scope => !ALLOWED_SCOPES.has(scope))
    || new Set(state.requestedScopes).size !== state.requestedScopes.length
    || !Number.isSafeInteger(state.expiresAt) || state.expiresAt < 0) fail('设备状态文件无效。')
  registryOrigin(state.registryOrigin)
  instanceName(state.instanceName)
  const challenge = canonicalChallenge(state.challenge)
  if (challenge.organizationId !== state.organizationId || challenge.instanceId !== state.instanceId
    || challenge.keyId !== state.keyId || challenge.expiresAt !== state.expiresAt) fail('设备状态文件无效。')
  const key = privateKeyFromPkcs8(state.privateKeyPkcs8)
  const spki = createPublicKey(key).export({ format: 'der', type: 'spki' })
  const keyId = `sha256:${createHash('sha256').update(spki).digest('hex')}`
  if (keyId !== state.keyId) fail('设备状态文件无效。')
  try { hashRegistryDeviceSecret(state.deviceSecret) } catch { fail('设备状态文件无效。') }
  if (!legacy) {
    try { hashRegistryBridgeSecret(state.bridgeSecret) } catch { fail('设备状态文件无效。') }
  }
  return { state, challenge, key }
}

function confirmedState(input) {
  const legacy = input?.version === LEGACY_STATE_VERSION
  const keys = ['version', 'phase', 'registryOrigin', 'organizationId', 'bindingId', 'instanceId', 'keyId',
    'instanceName', 'requestedScopes', 'syncUrl', 'deviceSecretHash',
    ...(legacy ? [] : ['bridgeSecretHash']), 'deviceToken', ...(legacy ? [] : ['bridgeToken']),
    'privateKeyPkcs8']
  const state = exactRecord(input, keys)
  if (state === null || ![LEGACY_STATE_VERSION, STATE_VERSION].includes(state.version)
    || state.phase !== 'confirmed'
    || typeof state.bindingId !== 'string' || !UUID.test(state.bindingId)
    || typeof state.organizationId !== 'string' || !IDENTIFIER.test(state.organizationId)
    || typeof state.instanceId !== 'string' || !IDENTIFIER.test(state.instanceId)
    || typeof state.keyId !== 'string' || !KEY_ID.test(state.keyId) || typeof state.syncUrl !== 'string'
    || typeof state.deviceSecretHash !== 'string' || !KEY_ID.test(state.deviceSecretHash)
    || (!legacy && (typeof state.bridgeSecretHash !== 'string' || !KEY_ID.test(state.bridgeSecretHash)))
    || !Array.isArray(state.requestedScopes) || state.requestedScopes.length === 0
    || state.requestedScopes.some(scope => !ALLOWED_SCOPES.has(scope))
    || new Set(state.requestedScopes).size !== state.requestedScopes.length) fail('设备状态文件无效。')
  registryOrigin(state.registryOrigin)
  instanceName(state.instanceName)
  let audience
  try { audience = new URL(state.syncUrl) } catch { fail('设备状态文件无效。') }
  if (audience.protocol !== 'wss:' || audience.href !== state.syncUrl || audience.username !== ''
    || audience.password !== '' || audience.search !== '' || audience.hash !== '') fail('设备状态文件无效。')
  const key = privateKeyFromPkcs8(state.privateKeyPkcs8)
  const spki = createPublicKey(key).export({ format: 'der', type: 'spki' })
  if (`sha256:${createHash('sha256').update(spki).digest('hex')}` !== state.keyId) fail('设备状态文件无效。')
  if (typeof state.deviceToken !== 'string') fail('设备状态文件无效。')
  let decoded
  try {
    decoded = decodeRegistryDeviceToken(state.deviceToken)
  } catch { fail('设备状态文件无效。') }
  if (decoded.organizationId !== state.organizationId || decoded.bindingId !== state.bindingId) {
    fail('设备状态文件无效。')
  }
  if (hashRegistryDeviceSecret(decoded.secret) !== state.deviceSecretHash) fail('设备状态文件无效。')
  if (!legacy) {
    if (typeof state.bridgeToken !== 'string') fail('设备状态文件无效。')
    let decodedBridge
    try {
      decodedBridge = decodeRegistryBridgeToken(state.bridgeToken)
    } catch { fail('设备状态文件无效。') }
    if (decodedBridge.organizationId !== state.organizationId || decodedBridge.bindingId !== state.bindingId
      || hashRegistryBridgeSecret(decodedBridge.secret) !== state.bridgeSecretHash
      || decodedBridge.secret === decoded.secret) fail('设备状态文件无效。')
  }
  return state
}

async function start(options) {
  const reservation = await reserveExclusive(options.statePath, '设备状态文件已存在，未覆盖。')
  let committed = false
  try {
    const keyPair = generateInstanceKeyPair()
    const deviceSecret = generateRegistryDeviceSecret()
    const bridgeSecret = generateRegistryBridgeSecret()
    const url = new URL(`/registry-api/v1/organizations/${encodeURIComponent(options.organizationId)}/bindings/start`,
      options.registryOrigin)
    const value = await postJson(url, {
      publicKeySpki: keyPair.publicKeySpki,
      deviceSecretHash: hashRegistryDeviceSecret(deviceSecret),
      bridgeSecretHash: hashRegistryBridgeSecret(bridgeSecret),
      instanceName: options.instanceName,
      requestedScopes: options.scopes,
    }, '设备绑定启动')
    const ticket = exactRecord(value, ['bindingId', 'code', 'challenge'])
    let challenge
    try { challenge = decodeRegistryChallenge(ticket?.challenge) } catch { fail('Registry 返回了无效响应。') }
    if (ticket === null || typeof ticket.bindingId !== 'string' || !UUID.test(ticket.bindingId)
      || typeof ticket.code !== 'string' || !BASE64URL_32.test(ticket.code)
      || challenge.organizationId !== options.organizationId || challenge.keyId !== keyPair.keyId
      || challenge.expiresAt <= Date.now()) fail('Registry 返回了无效响应。')
    const exported = keyPair.privateKey.export({ format: 'der', type: 'pkcs8' })
    if (!Buffer.isBuffer(exported)) fail('无法生成设备密钥。')
    const state = {
      version: STATE_VERSION,
      phase: 'pending',
      registryOrigin: options.registryOrigin,
      organizationId: options.organizationId,
      bindingId: ticket.bindingId,
      instanceId: challenge.instanceId,
      keyId: challenge.keyId,
      instanceName: options.instanceName,
      requestedScopes: options.scopes,
      expiresAt: challenge.expiresAt,
      challenge,
      pairingCode: ticket.code,
      deviceSecret,
      bridgeSecret,
      privateKeyPkcs8: exported.toString('base64url'),
    }
    exported.fill(0)
    await commitReservation(options.statePath, reservation, `${JSON.stringify(state, null, 2)}\n`)
    committed = true
    const approvalUrl = `${options.registryOrigin}#/organizations/${encodeURIComponent(options.organizationId)}/binding`
    process.stdout.write([
      'registry-device-enrollment: 已创建待审批绑定。',
      `approvalUrl: ${approvalUrl}`,
      `bindingId: ${ticket.bindingId}`,
      `pairingCode: ${ticket.code}`,
      `expiresAt: ${challenge.expiresAt}`,
      '请在登录后的 Registry 页面输入 bindingId 和 pairingCode 完成审批，然后运行 confirm。',
      'pairingCode 是短期一次性审批凭据，只发送给本次审批人员。',
      '状态文件包含设备私钥和一次性材料，不要上传、发送或提交到 Git。',
      '',
    ].join('\n'))
  } catch (error) {
    if (!committed) await discardReservation(options.statePath, reservation)
    throw error
  }
}

async function confirm(options) {
  await assertPrivateWindowsSecretPath(options.statePath, 'ReplaceFile')
  const { state, challenge, key } = pendingState(await readPrivateJson(options.statePath))
  const proof = signRegistryChallenge(challenge, key)
  const url = new URL(`/registry-api/v1/organizations/${encodeURIComponent(state.organizationId)}/bindings/${encodeURIComponent(state.bindingId)}/confirm`,
    state.registryOrigin)
  const value = await postJson(url, { proof }, '设备绑定确认')
  const receipt = exactRecord(value, ['bindingId', 'phase'])
  if (receipt === null || receipt.bindingId !== state.bindingId || receipt.phase !== 'confirmed') {
    fail('Registry 返回了无效响应。')
  }
  let deviceToken
  let bridgeToken
  const legacy = state.version === LEGACY_STATE_VERSION
  try {
    deviceToken = encodeRegistryDeviceToken({
      organizationId: state.organizationId,
      bindingId: state.bindingId,
      secret: state.deviceSecret,
    })
    if (!legacy) {
      bridgeToken = encodeRegistryBridgeToken({
        organizationId: state.organizationId,
        bindingId: state.bindingId,
        secret: state.bridgeSecret,
      })
    }
  } catch { fail('设备状态文件无效。') }
  const confirmed = {
    version: state.version,
    phase: 'confirmed',
    registryOrigin: state.registryOrigin,
    organizationId: state.organizationId,
    bindingId: state.bindingId,
    instanceId: state.instanceId,
    keyId: state.keyId,
    instanceName: state.instanceName,
    requestedScopes: state.requestedScopes,
    syncUrl: challenge.audience,
    deviceSecretHash: hashRegistryDeviceSecret(state.deviceSecret),
    ...(!legacy ? { bridgeSecretHash: hashRegistryBridgeSecret(state.bridgeSecret) } : {}),
    deviceToken,
    ...(!legacy ? { bridgeToken } : {}),
    privateKeyPkcs8: state.privateKeyPkcs8,
  }
  await replaceAtomically(options.statePath, `${JSON.stringify(confirmed, null, 2)}\n`)
  process.stdout.write([
    'registry-device-enrollment: 设备绑定已确认。',
    ...(legacy ? [
      '旧版待审批状态已确认；设备 secret 已封装进 dsh1 token。',
      '该凭据仅支持 WSS 连接；如需 disclosure publication，请撤销旧设备并重新绑定。',
    ] : [
      '待审批状态已原子替换；配对码和两个独立 raw secret 字段已移除。',
      'WSS 设备 secret 与 disclosure bridge secret 分别封装进 dsh1、dshb1 token。',
      '两个 token 和私钥仍是长期敏感凭据，不能互换或复用。',
    ]),
    '下一步运行 export-env，为 Harness 生成独占环境文件。',
    '',
  ].join('\n'))
}

async function exportEnvironment(options) {
  await assertPrivateWindowsSecretPath(options.outputPath, 'NewFile')
  const state = confirmedState(await readPrivateJson(options.statePath))
  const content = [
    `DSH_REGISTRY_ORGANIZATION_ID=${state.organizationId}`,
    `DSH_INSTANCE_ID=${state.instanceId}`,
    `DSH_REGISTRY_SYNC_URL=${state.syncUrl}`,
    `DSH_REGISTRY_DEVICE_TOKEN=${state.deviceToken}`,
    ...(state.version === STATE_VERSION ? [`DSH_REGISTRY_DISCLOSURE_TOKEN=${state.bridgeToken}`] : []),
    `DSH_REGISTRY_DEVICE_PRIVATE_KEY=${state.privateKeyPkcs8}`,
    '',
  ].join('\n')
  await writeExclusive(options.outputPath, content, '输出环境文件已存在，未覆盖。')
  process.stdout.write([
    'registry-device-enrollment: Harness 环境文件已生成。',
    '文件包含设备凭据，不要上传、发送或提交到 Git。',
    ...(state.version === LEGACY_STATE_VERSION
      ? ['旧版五项环境文件仅支持 WSS 连接；启用 disclosure publication 必须撤销旧设备并重新绑定。']
      : []),
    '',
  ].join('\n'))
}

async function main() {
  try {
    checkNodeRuntime()
    const options = parseArguments(process.argv.slice(2))
    if (options.command === 'start') await start(options)
    else if (options.command === 'confirm') await confirm(options)
    else await exportEnvironment(options)
  } catch (error) {
    const failure = error instanceof CliFailure ? error : new CliFailure('设备绑定工具发生内部错误。')
    process.stderr.write(`registry-device-enrollment: ${failure.message}\n`)
    process.exitCode = failure.exitCode
  }
}

const invoked = process.argv[1]
if (invoked !== undefined
  && realpathSync.native(resolve(invoked)) === realpathSync.native(fileURLToPath(import.meta.url))) await main()
