import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import {
  parseProductionOidcArguments,
  validateProductionOidcDiscovery,
  verifyProductionOidc,
} from '../deploy/registry/verify-production-oidc.mjs'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const verifier = join(repository, 'deploy', 'registry', 'verify-production-oidc.mjs')
const secretName = 'DSH_TEST_OIDC_CLIENT_SECRET'
const testSecret = 'synthetic-oidc-secret-32-bytes-only'
const clientId = 'registry-production-test'

function metadata(issuer, endpointOrigin, introspectionPath = '/introspect') {
  return {
    issuer,
    authorization_endpoint: `${endpointOrigin}/authorize`,
    token_endpoint: `${endpointOrigin}/token`,
    introspection_endpoint: `${endpointOrigin}${introspectionPath}`,
    jwks_uri: `${endpointOrigin}/jwks`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    scopes_supported: ['openid'],
    code_challenge_methods_supported: ['S256'],
  }
}

async function listen(handler) {
  const server = createServer(handler)
  await new Promise((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise)
    server.listen(0, '127.0.0.1', resolvePromise)
  })
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  return { server, origin: `http://127.0.0.1:${address.port}` }
}

async function close(server) {
  server.closeAllConnections?.()
  await new Promise(resolvePromise => server.close(resolvePromise))
}

function readBody(request) {
  return new Promise((resolvePromise, rejectPromise) => {
    const chunks = []
    let size = 0
    request.on('data', chunk => {
      size += chunk.length
      if (size > 16 * 1024) {
        request.destroy()
        rejectPromise(new Error('mock request body exceeded test bound'))
      } else chunks.push(chunk)
    })
    request.once('error', rejectPromise)
    request.once('end', () => resolvePromise(Buffer.concat(chunks, size).toString('utf8')))
  })
}

function childEnvironment(extra) {
  const environment = {}
  for (const name of ['COMSPEC', 'OS', 'PATHEXT', 'SYSTEMROOT', 'TEMP', 'TMP', 'WINDIR']) {
    if (typeof process.env[name] === 'string') environment[name] = process.env[name]
  }
  return { ...environment, ...extra }
}

function runCli(arguments_, environment) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [verifier, ...arguments_], {
      cwd: repository,
      env: environment,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const stdout = []
    const stderr = []
    let timer
    child.stdout.on('data', chunk => stdout.push(chunk))
    child.stderr.on('data', chunk => stderr.push(chunk))
    child.once('error', rejectPromise)
    child.once('close', code => {
      clearTimeout(timer)
      resolvePromise({
        code,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      })
    })
    timer = setTimeout(() => {
      child.kill()
      rejectPromise(new Error('production OIDC CLI test timed out'))
    }, 5_000)
    timer.unref()
  })
}

test('production OIDC CLI accepts different endpoint origins without putting the client secret in argv or output', async t => {
  let discoveryRequests = 0
  let introspectionRequests = 0
  let clientAuthenticationValid = false
  let bodyValid = false
  let probeToken = ''

  const endpoints = await listen(async (request, response) => {
    if (request.url !== '/introspect' || request.method !== 'POST') {
      response.writeHead(404).end()
      return
    }
    introspectionRequests += 1
    const body = new URLSearchParams(await readBody(request))
    probeToken = body.get('token') ?? ''
    clientAuthenticationValid = request.headers.authorization === undefined
      && body.get('client_id') === clientId && body.get('client_secret') === testSecret
    bodyValid = body.get('token_type_hint') === 'access_token'
      && /^dsh-oidc-conformance-[A-Za-z0-9_-]{43}$/u.test(probeToken)
      && ![...body.keys()].some(name => !['token', 'token_type_hint', 'client_id', 'client_secret'].includes(name))
      && request.headers['content-type'] === 'application/x-www-form-urlencoded; charset=utf-8'
    response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
    response.end('{"active":false}')
  })
  t.after(() => close(endpoints.server))

  let issuer
  const discovery = await listen((request, response) => {
    if (request.url !== '/.well-known/openid-configuration' || request.method !== 'GET') {
      response.writeHead(404).end()
      return
    }
    discoveryRequests += 1
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(JSON.stringify(metadata(issuer, endpoints.origin)))
  })
  t.after(() => close(discovery.server))
  issuer = discovery.origin

  const result = await runCli([
    '--issuer', issuer,
    '--client-id', clientId,
    '--client-secret-env', secretName,
    '--allow-loopback-http',
  ], childEnvironment({ [secretName]: testSecret }))

  assert.equal(result.code, 0, result.stderr)
  assert.equal(result.stderr, '')
  assert.match(result.stdout, /registry-production-oidc: 验收通过/u)
  assert.equal(result.stdout.includes(testSecret), false)
  assert.equal(result.stdout.includes(probeToken), false)
  assert.equal(discoveryRequests, 1)
  assert.equal(introspectionRequests, 1)
  assert.equal(clientAuthenticationValid, true,
    'client authentication must match the Registry runtime client_secret_post method')
  assert.equal(bodyValid, true, 'introspection must use one fresh opaque probe token')
})

test('discovery issuer mismatch fails before introspection and does not expose the secret', async t => {
  let introspectionRequests = 0
  let issuer
  const mock = await listen((request, response) => {
    if (request.url === '/.well-known/openid-configuration') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify(metadata(`${issuer}/wrong`, issuer)))
      return
    }
    if (request.url === '/introspect') introspectionRequests += 1
    response.writeHead(500, { 'content-type': 'text/plain' })
    response.end(testSecret)
  })
  t.after(() => close(mock.server))
  issuer = mock.origin

  const result = await runCli([
    '--issuer', issuer,
    '--client-id', clientId,
    '--client-secret-env', secretName,
    '--allow-loopback-http',
  ], childEnvironment({ [secretName]: testSecret }))

  assert.equal(result.code, 1)
  assert.equal(result.stdout, '')
  assert.match(result.stderr, /issuer 与命令行 issuer 不精确匹配/u)
  assert.equal(result.stderr.includes(testSecret), false)
  assert.equal(introspectionRequests, 0)
})

test('discovery capability and endpoint validation is fail-closed', () => {
  const issuer = 'https://identity.example.invalid/tenant'
  const valid = metadata(issuer, 'https://login.example.invalid')
  const options = { issuer, allowLoopbackHttp: false }
  assert.doesNotThrow(() => validateProductionOidcDiscovery(valid, options))

  const invalid = [
    { ...valid, authorization_endpoint: 'http://example.com/authorize' },
    { ...valid, token_endpoint: 'https://user@example.com/token' },
    { ...valid, introspection_endpoint: 'https://login.example.invalid/introspect#status' },
    { ...valid, response_types_supported: ['id_token'] },
    { ...valid, grant_types_supported: ['client_credentials'] },
    { ...valid, scopes_supported: ['profile'] },
    { ...valid, code_challenge_methods_supported: ['plain'] },
  ]
  for (const candidate of invalid) {
    assert.throws(() => validateProductionOidcDiscovery(candidate, options))
  }
})

test('introspection redirects, errors, oversized bodies, extra status and timeouts all fail closed', async t => {
  let mode = 'extra'
  let redirected = 0
  let issuer
  const mock = await listen((request, response) => {
    if (request.url === '/.well-known/openid-configuration') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify(metadata(issuer, issuer, `/introspect-${mode}`)))
      return
    }
    if (request.url === '/redirect-target') {
      redirected += 1
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end('{"active":false}')
      return
    }
    if (request.url === '/introspect-extra') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end('{"active":false,"sub":"must-not-appear"}')
    } else if (request.url === '/introspect-redirect') {
      response.writeHead(302, { location: '/redirect-target' })
      response.end()
    } else if (request.url === '/introspect-error') {
      response.writeHead(503, { 'content-type': 'application/json' })
      response.end(`{"error":"${testSecret}"}`)
    } else if (request.url === '/introspect-oversized') {
      response.writeHead(200, { 'content-type': 'application/json', 'content-length': '9000' })
      response.end('{"active":false}')
    } else if (request.url === '/introspect-timeout') {
      request.once('close', () => response.destroy())
    } else {
      response.writeHead(404).end()
    }
  })
  t.after(() => close(mock.server))
  issuer = mock.origin

  for (const selected of ['extra', 'redirect', 'error', 'oversized', 'timeout']) {
    mode = selected
    await assert.rejects(verifyProductionOidc({
      issuer,
      clientId,
      clientSecretEnv: secretName,
      allowLoopbackHttp: true,
      environment: { [secretName]: testSecret },
      timeoutMs: selected === 'timeout' ? 50 : 1_000,
    }), error => {
      assert.equal(String(error).includes(testSecret), false)
      return true
    })
  }
  assert.equal(redirected, 0, 'redirect target must never be followed')
})

test('CLI exposes no client-secret argument and loopback HTTP requires the explicit test flag', async () => {
  assert.throws(() => parseProductionOidcArguments([
    '--issuer', 'https://identity.example.invalid',
    '--client-id', clientId,
    '--client-secret', testSecret,
  ]))
  let requests = 0
  await assert.rejects(verifyProductionOidc({
    issuer: 'http://127.0.0.1:9',
    clientId,
    clientSecretEnv: secretName,
    environment: { [secretName]: testSecret },
    fetchImpl: async () => { requests += 1 },
  }))
  assert.equal(requests, 0)
})
