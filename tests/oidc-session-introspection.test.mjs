import test from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { RegistryOidcAccountAuthenticator } from '../packages/bundle/registry-app/src/oidc-account-auth.ts'

function sealedCookie(secret, value) {
  const body = Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  const signature = createHmac('sha256', secret).update(body, 'ascii').digest('base64url')
  return `${body}.${signature}`
}

test('an opaque OIDC session is rejected on the first request after introspection becomes inactive', async (t) => {
  let active = true
  let introspections = 0
  const provider = createServer((request, response) => {
    const origin = `http://127.0.0.1:${provider.address().port}`
    if (request.url === '/.well-known/openid-configuration') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify({
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        introspection_endpoint: `${origin}/introspect`,
        jwks_uri: `${origin}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
      }))
      return
    }
    if (request.url === '/introspect' && request.method === 'POST') {
      request.resume()
      request.once('end', () => {
        introspections += 1
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(JSON.stringify(active
          ? { active: true, sub: 'subject-1', client_id: 'registry-client', exp: Math.floor(Date.now() / 1000) + 60 }
          : { active: false }))
      })
      return
    }
    response.writeHead(404)
    response.end()
  })
  provider.listen(0, '127.0.0.1')
  await once(provider, 'listening')
  t.after(async () => {
    provider.close()
    await once(provider, 'close')
  })

  const issuer = `http://127.0.0.1:${provider.address().port}`
  const now = Date.now()
  const sessionId = 'A'.repeat(43)
  const secret = 'session-secret-that-is-at-least-thirty-two-bytes'
  const cookie = sealedCookie(secret, { version: 3, sessionId, issuedAt: now, expiresAt: now + 60_000 })
  const authenticator = Object.create(RegistryOidcAccountAuthenticator.prototype)
  Object.assign(authenticator, {
    config: {
      mode: 'loopback-development', issuer, clientId: 'registry-client',
      clientSecretEnv: 'OIDC_CLIENT_SECRET', sessionSecretEnv: 'SESSION_SECRET',
      publicOrigin: 'http://127.0.0.1:3181', organizationId: 'test-organization',
      memberIdClaim: 'sub', scopes: 'openid', sessionValidation: 'introspection',
      maxActiveSessions: 2, maxSessionsPerSubject: 2,
      sessionTtlMs: 60_000, transactionTtlMs: 60_000,
      maxAuthenticationAgeSeconds: 60, clockToleranceSeconds: 0,
      requestTimeoutMs: 2_000, maxCookieBytes: 4_096, maxDirectoryBytes: 4_096,
    },
    runtimeCtx: {
      credentials: { resolve: async () => ({ value: secret }) },
      get: () => undefined,
    },
    sessionName: 'dsh_registry_session',
    sessions: new Map([[sessionId, {
      version: 2, issuer, oidcSubject: 'subject-1', accessToken: 'access-token-1',
      subject: 'subject-1', accountId: '00000000-0000-4000-8000-000000000001',
      memberId: 'member-1', displayName: 'Member 1', issuedAt: now, expiresAt: now + 60_000,
    }]]),
    requestSessions: new WeakMap(),
    requestIdentities: new WeakMap(),
  })

  const request = () => ({ headers: { cookie: `dsh_registry_session=${cookie}` } })
  assert.equal((await authenticator.authenticateIdentity(request(), new AbortController().signal))?.subject, 'subject-1')
  active = false
  assert.equal(await authenticator.authenticateIdentity(request(), new AbortController().signal), null)
  assert.equal(introspections, 2)
  assert.equal(authenticator.sessions.size, 0)
})

function accountSession(subject, issuedAt, expiresAt) {
  return {
    version: 2, issuer: 'https://identity.example', oidcSubject: subject,
    accessToken: `access-token-${subject}-${issuedAt}`, subject,
    accountId: '00000000-0000-4000-8000-000000000001', memberId: `member-${subject}`,
    displayName: `Member ${subject}`, issuedAt, expiresAt,
  }
}

test('retaining a session deterministically evicts only the oldest session for that subject', () => {
  const now = Date.now()
  const authenticator = Object.create(RegistryOidcAccountAuthenticator.prototype)
  Object.assign(authenticator, {
    config: { maxActiveSessions: 3, maxSessionsPerSubject: 2 },
    sessions: new Map([
      ['oldest', accountSession('subject-1', now - 2, now + 60_000)],
      ['newer', accountSession('subject-1', now - 1, now + 60_000)],
      ['other', accountSession('subject-2', now, now + 60_000)],
    ]),
  })

  authenticator.retainSession('newest', accountSession('subject-1', now, now + 60_000))

  assert.deepEqual([...authenticator.sessions.keys()], ['newer', 'other', 'newest'])
})

test('the global session bound fails closed for a new subject', () => {
  const now = Date.now()
  const authenticator = Object.create(RegistryOidcAccountAuthenticator.prototype)
  Object.assign(authenticator, {
    config: { maxActiveSessions: 2, maxSessionsPerSubject: 2 },
    sessions: new Map([
      ['first', accountSession('subject-1', now, now + 60_000)],
      ['second', accountSession('subject-2', now, now + 60_000)],
    ]),
  })

  assert.throws(() => authenticator.retainSession(
    'rejected', accountSession('subject-3', now, now + 60_000)), /active session limit/u)
  assert.deepEqual([...authenticator.sessions.keys()], ['first', 'second'])
})

test('a response failure after retention removes the newly created session', () => {
  const now = Date.now()
  const authenticator = Object.create(RegistryOidcAccountAuthenticator.prototype)
  Object.assign(authenticator, {
    config: { maxActiveSessions: 2, maxSessionsPerSubject: 2 },
    sessions: new Map(), transactionName: 'oidc-transaction', sessionName: 'oidc-session',
    secureCookies: true,
  })
  const response = {
    setHeader() {},
    appendHeader() { throw new Error('response unavailable') },
  }

  assert.throws(() => authenticator.publishSession(response, 'created',
    accountSession('subject-1', now, now + 60_000), 'signed-cookie', 60, '/#/overview'),
  /response unavailable/u)
  assert.equal(authenticator.sessions.size, 0)
})
