#!/usr/bin/env node
import { createPrivateKey } from 'node:crypto'
import { createRequire } from 'node:module'
import { isIP } from 'node:net'

const MAX_FRAME_BYTES = 1_048_576
const TIMEOUT_MS = 10_000

function fail(message, code = 1) {
  process.stderr.write(`registry-device-verification: ${message}\n`)
  process.exitCode = code
}

function checkNodeRuntime() {
  const [major = 0, minor = 0] = process.versions.node.split('.').map(Number)
  if (!(major === 22 && minor >= 19) && major < 24) {
    throw new Error('Node ^22.19.0 or >=24.0.0 is required')
  }
}

function required(name, minimumBytes = 1) {
  const value = process.env[name]
  if (value === undefined || Buffer.byteLength(value, 'utf8') < minimumBytes) {
    throw new Error(`${name} is missing or too short`)
  }
  if (value !== value.trim() || /[\r\n]/u.test(value)) {
    throw new Error(`${name} must be one trimmed line`)
  }
  return value
}

function dshIdentifier(name, value) {
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u.test(value)) {
    throw new Error(`${name} is not a valid DSH identifier`)
  }
  return value
}

function endpoint(input, expectedDomain) {
  let value
  try { value = new URL(input) } catch { throw new Error('DSH_REGISTRY_SYNC_URL is not an absolute URL') }
  const domain = expectedDomain.toLowerCase()
  const labels = domain.split('.')
  const documentationDomain = ['example.com', 'example.org', 'example.net']
    .some(value => domain === value || domain.endsWith(`.${value}`))
  if (domain.length > 253 || isIP(domain) !== 0 || labels.length < 2
    || labels.some(label => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/u.test(label))
    || domain === 'localhost' || domain.endsWith('.localhost') || domain.endsWith('.local')
    || domain === 'example' || domain.endsWith('.example') || domain.endsWith('.test')
    || domain.endsWith('.invalid') || documentationDomain) {
    throw new Error('REGISTRY_DOMAIN is not a public DNS hostname')
  }
  if (value.protocol !== 'wss:' || value.hostname.toLowerCase() !== domain
    || value.pathname !== '/a2a/v1/sync' || value.port !== ''
    || value.username !== '' || value.password !== '' || value.search !== '' || value.hash !== ''
    || value.href !== `wss://${domain}/a2a/v1/sync`) {
    throw new Error('DSH_REGISTRY_SYNC_URL must be the canonical public WSS endpoint on port 443')
  }
  return value.href
}

function signingKey(encoded) {
  if (!/^[A-Za-z0-9_-]+$/u.test(encoded)) throw new Error('device private key is not canonical base64url')
  const bytes = Buffer.from(encoded, 'base64url')
  try {
    if (bytes.byteLength < 48 || bytes.toString('base64url') !== encoded) {
      throw new Error('device private key is not canonical PKCS8')
    }
    const key = createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' })
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('device private key is not Ed25519')
    const canonical = key.export({ format: 'der', type: 'pkcs8' })
    if (!Buffer.isBuffer(canonical) || !canonical.equals(bytes)) {
      throw new Error('device private key is not canonical PKCS8')
    }
    return key
  } catch {
    throw new Error('device private key is not canonical Ed25519 PKCS8')
  } finally { bytes.fill(0) }
}

function waitForOpen(socket) {
  return new Promise((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => finish(new Error('WSS open timed out')), TIMEOUT_MS)
    const finish = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('open', opened)
      socket.off('error', errored)
      socket.off('unexpected-response', unexpected)
      if (error === undefined) resolve()
      else reject(error)
    }
    const opened = () => finish()
    const errored = () => finish(new Error('TLS or WSS connection failed'))
    const unexpected = (_request, response) => {
      const status = response.statusCode
      response.destroy()
      finish(new Error(status === 401 || status === 403
        ? 'WSS upgrade rejected the device connection'
        : 'WSS upgrade returned an unexpected response'))
    }
    socket.once('open', opened)
    socket.once('error', errored)
    socket.once('unexpected-response', unexpected)
  })
}

function exchange(socket, codec, serial, request, expectedType) {
  return new Promise((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => finish(new Error(`${expectedType} timed out`)), TIMEOUT_MS)
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('message', received)
      socket.off('close', closed)
      socket.off('error', errored)
      if (error === undefined) resolve(value)
      else reject(error)
    }
    const closed = () => finish(new Error('WSS closed before the expected response'))
    const errored = () => finish(new Error('WSS failed during authenticated exchange'))
    const received = (data, binary) => {
      try {
        if (binary || !Buffer.isBuffer(data) || data.byteLength > MAX_FRAME_BYTES) {
          throw new Error('Registry returned an invalid text frame')
        }
        const frame = codec.decodeRegistryServerFrame(data.toString('utf8'), MAX_FRAME_BYTES)
        if (frame.requestId !== serial) throw new Error('Registry returned a mismatched request ID')
        if (frame.type === 'error') throw new Error(`Registry rejected ${expectedType}: ${frame.code}`)
        if (frame.type !== expectedType) throw new Error(`Registry returned an unexpected ${frame.type} frame`)
        finish(undefined, frame)
      } catch (error) { finish(error instanceof Error ? error : new Error('Registry returned an invalid response')) }
    }
    socket.once('message', received)
    socket.once('close', closed)
    socket.once('error', errored)
    let encoded
    try {
      encoded = codec.encodeRegistryClientFrame({ protocolVersion: 1, requestId: serial, ...request }, MAX_FRAME_BYTES)
    } catch { finish(new Error(`could not encode ${request.type}`)); return }
    try {
      socket.send(encoded, { binary: false }, (error) => {
        if (error !== undefined) finish(new Error(`could not send ${request.type}`))
      })
    } catch { finish(new Error(`could not send ${request.type}`)) }
  })
}

async function close(socket) {
  if (socket.readyState === 3) return
  await new Promise((resolve) => {
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('close', finish)
      socket.off('error', finish)
      resolve()
    }
    const timer = setTimeout(() => {
      try { socket.terminate() } catch { /* The socket is already tearing down. */ }
      finish()
    }, 1_000)
    socket.once('close', finish)
    socket.once('error', finish)
    try {
      if (socket.readyState === 0) socket.terminate()
      else socket.close(1000, 'verification complete')
    } catch { finish() }
  })
}

async function main() {
  if (process.argv.length !== 2) {
    fail('usage: node --env-file=<harness.env> deploy/registry/verify-registry-device.mjs', 2)
    return
  }
  let token
  let encodedPrivateKey
  let socket
  try {
    checkNodeRuntime()
    const domain = required('REGISTRY_DOMAIN')
    const url = endpoint(required('DSH_REGISTRY_SYNC_URL'), domain)
    const organizationId = dshIdentifier('DSH_REGISTRY_ORGANIZATION_ID', required('DSH_REGISTRY_ORGANIZATION_ID'))
    const instanceId = dshIdentifier('DSH_INSTANCE_ID', required('DSH_INSTANCE_ID'))
    token = required('DSH_REGISTRY_DEVICE_TOKEN', 16)
    encodedPrivateKey = required('DSH_REGISTRY_DEVICE_PRIVATE_KEY', 32)
    delete process.env.DSH_REGISTRY_DEVICE_TOKEN
    delete process.env.DSH_REGISTRY_DEVICE_PRIVATE_KEY

    let codec
    let identity
    try {
      [codec, identity] = await Promise.all([
        import('@deepseek-ai/dsh-a2a-registry-sync'),
        import('@deepseek-ai/dsh-a2a-device-identity/runtime'),
      ])
    } catch {
      throw new Error('Registry dependencies unavailable; run npm ci and invoke this script with node --import tsx/esm')
    }
    const key = signingKey(encodedPrivateKey)
    const requireFromClient = createRequire(new URL('../../packages/bundle/registry-app/package.json', import.meta.url))
    const WebSocket = requireFromClient('ws')
    socket = new WebSocket(url, {
      rejectUnauthorized: true,
      followRedirects: false,
      perMessageDeflate: false,
      maxPayload: MAX_FRAME_BYTES,
      handshakeTimeout: TIMEOUT_MS,
    })
    socket.on('error', () => { /* The active open, exchange, or close owner reports a bounded failure. */ })
    await waitForOpen(socket)
    const challengeFrame = await exchange(socket, codec, 1, { type: 'hello', token }, 'challenge')
    const challenge = challengeFrame.challenge
    if (challenge.audience !== url || challenge.organizationId !== organizationId
      || challenge.instanceId !== instanceId || challenge.expiresAt <= Date.now()) {
      throw new Error('Registry challenge does not match the configured device identity')
    }
    const signature = identity.signRegistryChallenge(challenge, key)
    const authenticated = await exchange(socket, codec, 2, { type: 'prove', signature }, 'authenticated')
    if (authenticated.identity.organizationId !== organizationId
      || authenticated.identity.instanceId !== instanceId
      || authenticated.identity.keyId !== challenge.keyId) {
      throw new Error('Registry authenticated a different device identity')
    }
    const heartbeat = await exchange(socket, codec, 3, { type: 'heartbeat' }, 'heartbeat-ack')
    if (!Number.isSafeInteger(heartbeat.observedAt) || heartbeat.observedAt < 0) {
      throw new Error('Registry returned an invalid heartbeat acknowledgement')
    }
    process.stdout.write([
      'registry-device-verification: authenticated WSS succeeded',
      `- endpoint: ${url}`,
      `- organization: ${organizationId}`,
      `- instance: ${instanceId}`,
      `- key: ${challenge.keyId}`,
      '- TLS trust, device challenge, identity match and heartbeat: valid',
      '- disclosure scopes, publication, import, questions, KMS and IdP still require separate verification',
      '',
    ].join('\n'))
  } catch (error) {
    fail(error instanceof Error ? error.message : 'verification failed')
  } finally {
    token = undefined
    encodedPrivateKey = undefined
    if (socket !== undefined) await close(socket)
  }
}

await main()
