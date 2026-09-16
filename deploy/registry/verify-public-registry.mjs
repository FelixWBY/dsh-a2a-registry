#!/usr/bin/env node
import { randomBytes } from 'node:crypto'
import { createRequire } from 'node:module'
import { isIP } from 'node:net'

const TIMEOUT_MS = 10_000
const MAX_FRAME_BYTES = 1_048_576
const MAX_STATUS_BYTES = 8_192
const REQUIRED_RUNTIME_CAPABILITIES = [
  'identity', 'registry', 'disclosureOperations', 'deviceBinding',
  'audit', 'rateLimits', 'disclosureCleanup', 'mailboxCleanup',
]
const rawOrigin = process.argv[2]
  ?? (process.env.REGISTRY_DOMAIN === undefined ? '' : `https://${process.env.REGISTRY_DOMAIN}`)
let origin

function fail(message) {
  throw new Error(`registry-public-verification: ${message}`)
}

function checkNodeRuntime() {
  const [major = 0, minor = 0] = process.versions.node.split('.').map(Number)
  if (!(major === 22 && minor >= 19) && major < 24) fail('Node ^22.19.0 or >=24.0.0 is required')
}

function publicOrigin(value) {
  if (value.length === 0 || process.argv.length > 3) {
    process.stderr.write('usage: node deploy/registry/verify-public-registry.mjs https://registry.example.com\n')
    process.exit(2)
  }
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    fail('expected an absolute HTTPS origin')
  }
  if (parsed.protocol !== 'https:' || parsed.port.length > 0
    || parsed.username.length > 0 || parsed.password.length > 0
    || parsed.pathname !== '/' || parsed.search.length > 0 || parsed.hash.length > 0) {
    fail('expected a credential-free HTTPS origin on port 443 without a path, query or fragment')
  }
  const domain = parsed.hostname.toLowerCase()
  const labels = domain.split('.')
  const documentationDomain = ['example.com', 'example.org', 'example.net']
    .some(value => domain === value || domain.endsWith(`.${value}`))
  if (domain.length > 253 || isIP(domain) !== 0 || labels.length < 2
    || labels.some(label => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/u.test(label))
    || domain === 'localhost' || domain.endsWith('.localhost') || domain.endsWith('.local')
    || domain === 'example' || domain.endsWith('.example') || domain.endsWith('.test')
    || domain.endsWith('.invalid') || documentationDomain) {
    fail('expected a public DNS hostname rather than a loopback or reserved test hostname')
  }
  return parsed
}

function requireHeader(response, name, expected) {
  const value = response.headers.get(name)
  if (value === null || !expected(value)) fail(`${name} response header is missing or invalid`)
  return value
}

function verifySecurityHeaders(response) {
  requireHeader(response, 'content-security-policy', value => [
    "default-src 'none'",
    "frame-ancestors 'none'",
    "connect-src 'self'",
    "object-src 'none'",
  ].every(directive => value.includes(directive)))
  requireHeader(response, 'strict-transport-security', (value) => {
    const match = /(?:^|;)\s*max-age=(\d+)/iu.exec(value)
    return match?.[1] !== undefined && Number(match[1]) >= 31_536_000
  })
  requireHeader(response, 'x-content-type-options', value => value.toLowerCase() === 'nosniff')
  requireHeader(response, 'x-frame-options', value => value.toUpperCase() === 'DENY')
  requireHeader(response, 'referrer-policy', value => value.toLowerCase() === 'no-referrer')
  requireHeader(response, 'cross-origin-opener-policy', value => value.toLowerCase() === 'same-origin')
  requireHeader(response, 'cross-origin-resource-policy', value => value.toLowerCase() === 'same-origin')
  requireHeader(response, 'permissions-policy', value => value.includes('camera=()') && value.includes('microphone=()'))
  if (response.headers.has('server')) fail('the public edge still exposes a Server response header')
}

async function read(path) {
  let response
  try {
    response = await fetch(new URL(path, origin), {
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  } catch {
    fail(`${path} could not be reached over HTTPS`)
  }
  if (response.status !== 200) fail(`${path} returned HTTP ${String(response.status)}`)
  verifySecurityHeaders(response)
  return response
}

async function verifyProbe(path) {
  const response = await read(path)
  requireHeader(response, 'cache-control', value => value.toLowerCase().includes('no-store'))
  if (await response.text() !== 'ok\n') fail(`${path} returned an unexpected body`)
}

async function verifyRuntimeConfiguration() {
  const response = await read('/registry-api/v1/status')
  requireHeader(response, 'cache-control', value => value.toLowerCase().includes('no-store'))
  requireHeader(response, 'content-type', value => value.toLowerCase().startsWith('application/json'))
  const declaredLength = response.headers.get('content-length')
  if (declaredLength !== null && (!/^\d+$/u.test(declaredLength) || Number(declaredLength) > MAX_STATUS_BYTES)) {
    fail('the runtime-configuration response length is invalid')
  }
  const body = await response.text()
  if (Buffer.byteLength(body, 'utf8') > MAX_STATUS_BYTES) fail('the runtime-configuration response is too large')
  let envelope
  try {
    envelope = JSON.parse(body)
  } catch {
    fail('the runtime-configuration response is not JSON')
  }
  if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)
    || envelope.ok !== true || envelope.value === null || typeof envelope.value !== 'object'
    || Array.isArray(envelope.value)) fail('the runtime-configuration response has an invalid envelope')
  const status = envelope.value
  if (status.deploymentMode !== 'standard') {
    fail('the public Registry reports a test-only deployment mode')
  }
  const invalid = REQUIRED_RUNTIME_CAPABILITIES.filter(name => status[name] !== 'configured'
    && status[name] !== 'unconfigured')
  if (invalid.length > 0) fail(`the runtime-configuration response has invalid fields: ${invalid.join(', ')}`)
  const missing = REQUIRED_RUNTIME_CAPABILITIES.filter(name => status[name] !== 'configured')
  if (missing.length > 0) fail(`required runtime capabilities are unconfigured: ${missing.join(', ')}`)
}

async function verifyShell() {
  const response = await read('/')
  requireHeader(response, 'cache-control', value => value.toLowerCase().includes('no-store'))
  requireHeader(response, 'content-type', value => value.toLowerCase().startsWith('text/html'))
  const body = await response.text()
  if (!/<title>DSH Registry<\/title>/iu.test(body) || !/<div\s+id=["']root["']><\/div>/iu.test(body)) {
    fail('the public origin did not return the Registry browser shell')
  }
  if (/[?&]token=/iu.test(body)) fail('the public shell contains a launch-token parameter')
}

async function verifyUnauthenticatedWss() {
  let codec
  let WebSocket
  try {
    codec = await import('@deepseek-ai/dsh-a2a-registry-sync')
    const requireFromClient = createRequire(new URL('../../packages/bundle/registry-app/package.json', import.meta.url))
    WebSocket = requireFromClient('ws')
  } catch { fail('Registry dependencies unavailable; run npm ci and invoke this script with node --import tsx/esm') }
  const endpoint = new URL('/a2a/v1/sync', origin)
  endpoint.protocol = 'wss:'
  await new Promise((resolve, reject) => {
    let settled = false
    const socket = new WebSocket(endpoint, {
      rejectUnauthorized: true,
      followRedirects: false,
      perMessageDeflate: false,
      maxPayload: MAX_FRAME_BYTES,
      handshakeTimeout: TIMEOUT_MS,
    })
    const timer = setTimeout(() => finish(new Error('the WSS authentication check timed out')), TIMEOUT_MS)
    const finish = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.terminate()
      if (error === undefined) resolve()
      else reject(error)
    }
    socket.once('open', () => {
      const token = `uncredentialed-${randomBytes(32).toString('base64url')}`
      let frame
      try {
        frame = codec.encodeRegistryClientFrame({ protocolVersion: 1, requestId: 1, type: 'hello', token }, MAX_FRAME_BYTES)
      } catch { finish(new Error('the uncredentialed hello frame could not be encoded')); return }
      socket.send(frame, { binary: false }, (error) => {
        if (error !== undefined) finish(new Error('the uncredentialed hello frame could not be sent'))
      })
    })
    socket.once('message', (data, binary) => {
      try {
        if (binary || !Buffer.isBuffer(data) || data.byteLength > MAX_FRAME_BYTES) {
          throw new Error('the Registry returned an invalid authentication frame')
        }
        const frame = codec.decodeRegistryServerFrame(data.toString('utf8'), MAX_FRAME_BYTES)
        if (frame.requestId !== 1 || frame.type !== 'error' || frame.code !== 'unauthorized') {
          throw new Error(frame.type === 'challenge'
            ? 'the Registry accepted an uncredentialed device token'
            : 'the Registry returned an unexpected authentication decision')
        }
        finish()
      } catch (error) { finish(error instanceof Error ? error : new Error('invalid WSS authentication decision')) }
    })
    socket.once('unexpected-response', (_request, response) => {
      response.destroy()
      finish(new Error(`the WSS upgrade returned HTTP ${String(response.statusCode ?? 'unknown')} before device authentication`))
    })
    socket.once('error', () => { finish(new Error('the WSS authentication boundary could not be verified')) })
    socket.once('close', () => { finish(new Error('the WSS endpoint closed before returning an authentication decision')) })
  }).catch((error) => { fail(error instanceof Error ? error.message : 'the WSS authentication boundary failed') })
}

try {
  origin = publicOrigin(rawOrigin)
  checkNodeRuntime()
  await verifyProbe('/healthz')
  await verifyProbe('/readyz')
  await verifyRuntimeConfiguration()
  await verifyShell()
  await verifyUnauthenticatedWss()
  process.stdout.write([
    'registry-public-verification: passed',
    `- origin: ${origin.origin}`,
    '- HTTPS shell, HSTS and browser security headers: valid',
    '- liveness and shell readiness: ready',
    '- deployment mode: standard; required runtime capabilities: configured',
    '- WSS upgrade: available; uncredentialed hello: unauthorized',
    '- identity, KMS, alert delivery, restore and SLO evidence require separate authenticated drills',
    '',
  ].join('\n'))
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : 'registry-public-verification: failed'}\n`)
  process.exitCode = 1
}
