/** OIDC Authorization Code + PKCE account authentication for the standalone Registry. */
import { createHmac, timingSafeEqual } from 'node:crypto'
import { isIP } from 'node:net'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { brandString } from '@deepseek-ai/dsh-brand'
import { credentialRef, type CredentialProvider } from '@deepseek-ai/dsh-credentials'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { RegistryIngestError } from '@deepseek-ai/dsh-a2a-registry-ingest'
import z from '@deepseek-ai/schemastery'
import {
  allowInsecureRequests,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  clockTolerance,
  customFetch,
  discovery,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
  type CustomFetch,
  type Configuration,
} from 'openid-client'
import { RegistryAccountAuthenticator, type RegistryAuthenticatedAccount } from './account-auth.ts'
import type { RegistryDirectory } from './directory.ts'

const AUTH_BASE = '/registry-auth/v1'
const START_PATH = `${AUTH_BASE}/start`
const CALLBACK_PATH = `${AUTH_BASE}/callback`
const LOGOUT_PATH = `${AUTH_BASE}/logout`
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const CLAIM_NAME = /^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$/u
const RETURN_PATH = /^\/#\/(?:[A-Za-z0-9._~!$&'()*+,;=:@/?%-]{0,240})$/u

/** Explicit OIDC relying-party and bounded Registry session configuration. */
export interface RegistryOidcAccountAuthConfig {
  /** Production requires HTTPS; loopback-development accepts only a loopback issuer and origin. */
  readonly mode: 'production' | 'loopback-development'
  /** Exact OpenID Provider issuer identifier used for discovery and token validation. */
  readonly issuer: string
  /** Registered confidential client identifier. */
  readonly clientId: string
  /** Credential reference for the confidential client secret. */
  readonly clientSecretEnv: string
  /** Credential reference for HMAC-signing short-lived transaction and account cookies. */
  readonly sessionSecretEnv: string
  /** Canonical Registry origin used for redirect_uri; request Host and forwarding headers are never trusted. */
  readonly publicOrigin: string
  /** Single Registry organization assigned after the provider authenticates the external subject. */
  readonly organizationId: OrganizationId
  /** Immutable ID-token claim whose string value equals one Registry directory member ID. */
  readonly memberIdClaim: string
  /** Space-delimited OIDC scopes; `openid` is mandatory. */
  readonly scopes: string
  /** Maximum browser session lifetime after a successful callback. */
  readonly sessionTtlMs: number
  /** Maximum lifetime of one state, nonce and PKCE transaction cookie. */
  readonly transactionTtlMs: number
  /** Maximum age requested and verified for the upstream authentication event. */
  readonly maxAuthenticationAgeSeconds: number
  /** Permitted ID-token timestamp skew during protocol validation. */
  readonly clockToleranceSeconds: number
  /** Deadline for discovery and token endpoint requests. */
  readonly requestTimeoutMs: number
  /** Maximum accepted Cookie header and generated sealed-cookie size. */
  readonly maxCookieBytes: number
  /** Maximum complete Registry directory snapshot used for fresh membership mapping. */
  readonly maxDirectoryBytes: number
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const rawSchema: z<RegistryOidcAccountAuthConfig> = z.object({
  mode: z.union(['production', 'loopback-development']).required(),
  issuer: z.string().required(),
  clientId: z.string().required(),
  clientSecretEnv: z.string().role('credential-ref').required(),
  sessionSecretEnv: z.string().role('credential-ref').required(),
  publicOrigin: z.string().required(),
  organizationId: z.transform(z.string().pattern(IDENTIFIER).required(),
    value => brandString<OrganizationId>(value)).required(),
  memberIdClaim: z.string().pattern(CLAIM_NAME).required(),
  scopes: z.string().required(),
  sessionTtlMs: positive(),
  transactionTtlMs: positive(),
  maxAuthenticationAgeSeconds: positive(),
  clockToleranceSeconds: z.natural().max(300).required(),
  requestTimeoutMs: positive(),
  maxCookieBytes: positive(),
  maxDirectoryBytes: positive(),
})

function parsedUrl(value: string, field: string): URL {
  try { return new URL(value) } catch { throw new z.ValidationError(`${field} must be an absolute URL`, {}) }
}

function loopbackHostname(hostname: string): boolean {
  if (hostname === 'localhost') return true
  const family = isIP(hostname)
  if (family === 4) return hostname.startsWith('127.')
  return family === 6 && (hostname === '::1' || hostname === '[::1]')
}

/** Loader schema rejects mixed development/production origins before any route or service is published. */
export const RegistryOidcAccountAuthConfigSchema: z<RegistryOidcAccountAuthConfig> = z.transform(rawSchema, (value) => {
  const issuer = parsedUrl(value.issuer, 'OIDC issuer')
  const origin = parsedUrl(value.publicOrigin, 'Registry publicOrigin')
  if (issuer.username !== '' || issuer.password !== '' || issuer.search !== '' || issuer.hash !== '') {
    throw new z.ValidationError('OIDC issuer must not contain credentials, query or fragment', {})
  }
  if (origin.username !== '' || origin.password !== '' || origin.search !== '' || origin.hash !== ''
    || origin.pathname !== '/' || origin.href !== origin.origin + '/') {
    throw new z.ValidationError('Registry publicOrigin must be an origin without credentials, path, query or fragment', {})
  }
  if (value.mode === 'production') {
    if (issuer.protocol !== 'https:' || origin.protocol !== 'https:') {
      throw new z.ValidationError('Production OIDC issuer and Registry publicOrigin must use HTTPS', {})
    }
  } else if (!loopbackHostname(issuer.hostname) || !loopbackHostname(origin.hostname)
    || !['http:', 'https:'].includes(issuer.protocol) || !['http:', 'https:'].includes(origin.protocol)) {
    throw new z.ValidationError('Loopback-development OIDC accepts only HTTP(S) loopback URLs', {})
  }
  const scopes = value.scopes.split(/\s+/u).filter(Boolean)
  if (!scopes.includes('openid') || scopes.length !== new Set(scopes).size || scopes.join(' ') !== value.scopes) {
    throw new z.ValidationError('OIDC scopes must be unique single-space tokens including openid', {})
  }
  if (Buffer.byteLength(value.clientId, 'utf8') > 256 || value.clientId.trim() !== value.clientId
    || value.clientId.length === 0) throw new z.ValidationError('OIDC clientId is invalid', {})
  if (value.transactionTtlMs > 10 * 60_000 || value.sessionTtlMs > 24 * 60 * 60_000
    || value.requestTimeoutMs > 60_000 || value.maxAuthenticationAgeSeconds > 24 * 60 * 60
    || value.maxCookieBytes > 65_536 || value.maxDirectoryBytes > 256 * 1024 * 1024) {
    throw new z.ValidationError('OIDC duration or response bound exceeds the supported maximum', {})
  }
  return value
})

interface TransactionCookie {
  readonly version: 1
  readonly state: string
  readonly nonce: string
  readonly codeVerifier: string
  readonly returnTo: string
  readonly expiresAt: number
}

interface SessionCookie {
  readonly version: 1
  readonly issuer: string
  readonly memberId: string
  readonly issuedAt: number
  readonly expiresAt: number
}

class OidcUnavailable extends Error {}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  const record = value as Record<string, unknown>
  const actual = Object.keys(record)
  return actual.length === keys.length && actual.every(key => keys.includes(key)) ? record : null
}

function finiteTime(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && !Object.is(value, -0)
}

function transactionCookie(value: unknown): TransactionCookie | null {
  const record = exactRecord(value, ['version', 'state', 'nonce', 'codeVerifier', 'returnTo', 'expiresAt'])
  if (record === null || record.version !== 1 || typeof record.state !== 'string' || record.state.length < 32
    || typeof record.nonce !== 'string' || record.nonce.length < 32
    || typeof record.codeVerifier !== 'string' || record.codeVerifier.length < 43
    || typeof record.returnTo !== 'string' || !RETURN_PATH.test(record.returnTo)
    || !finiteTime(record.expiresAt)) return null
  return record as unknown as TransactionCookie
}

function sessionCookie(value: unknown): SessionCookie | null {
  const record = exactRecord(value, ['version', 'issuer', 'memberId', 'issuedAt', 'expiresAt'])
  if (record === null || record.version !== 1 || typeof record.issuer !== 'string'
    || typeof record.memberId !== 'string' || !IDENTIFIER.test(record.memberId)
    || !finiteTime(record.issuedAt) || !finiteTime(record.expiresAt)
    || record.expiresAt <= record.issuedAt) return null
  return record as unknown as SessionCookie
}

function cookieValue(request: IncomingMessage, name: string, maxCookieBytes: number): string | null {
  const header = request.headers.cookie
  if (header === undefined || Buffer.byteLength(header, 'utf8') > maxCookieBytes) return null
  const matches: string[] = []
  for (const segment of header.split(';')) {
    const index = segment.indexOf('=')
    if (index < 1 || segment.slice(0, index).trim() !== name) continue
    matches.push(segment.slice(index + 1).trim())
  }
  return matches.length === 1 ? matches[0]! : null
}

function seal(secret: Buffer, value: object, maxCookieBytes: number): string {
  const body = Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  const signature = createHmac('sha256', secret).update(body, 'ascii').digest('base64url')
  const result = `${body}.${signature}`
  if (Buffer.byteLength(result, 'ascii') > maxCookieBytes) throw new OidcUnavailable('OIDC cookie unavailable')
  return result
}

function open(secret: Buffer, value: string, maxCookieBytes: number): unknown {
  if (Buffer.byteLength(value, 'ascii') > maxCookieBytes) return null
  const parts = value.split('.')
  if (parts.length !== 2) return null
  const [body, signature] = parts as [string, string]
  let supplied: Buffer
  try { supplied = Buffer.from(signature, 'base64url') } catch { return null }
  const expected = createHmac('sha256', secret).update(body, 'ascii').digest()
  try {
    if (supplied.byteLength !== expected.byteLength || !timingSafeEqual(supplied, expected)) return null
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as unknown
  } catch { return null } finally {
    supplied.fill(0)
    expected.fill(0)
  }
}

function setCookie(response: ServerResponse, name: string, value: string, maxAgeSeconds: number,
  secure: boolean): void {
  response.setHeader('set-cookie', `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${String(maxAgeSeconds)}${secure ? '; Secure' : ''}`)
}

function clearCookies(response: ServerResponse, names: readonly string[], secure: boolean): void {
  response.setHeader('set-cookie', names.map(name => `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? '; Secure' : ''}`))
}

function redirect(response: ServerResponse, location: string): void {
  response.writeHead(303, {
    'cache-control': 'no-store',
    location,
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  })
  response.end()
}

function unavailable(response: ServerResponse): void {
  const body = 'identity unavailable\n'
  response.writeHead(503, {
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
    'x-content-type-options': 'nosniff',
  })
  response.end(body)
}

function routeUrl(request: IncomingMessage): URL {
  return new URL(request.url ?? '/', 'http://registry.invalid')
}

function returnPath(url: URL): string {
  if ([...url.searchParams.keys()].some(key => key !== 'returnTo')) return '/#/overview'
  const values = url.searchParams.getAll('returnTo')
  return values.length === 1 && RETURN_PATH.test(values[0]!) ? values[0]! : '/#/overview'
}

/** Real OIDC browser authenticator; Registry storage remains authoritative for membership, roles and teams. */
export class RegistryOidcAccountAuthenticator extends RegistryAccountAuthenticator {
  private readonly secureCookies: boolean
  private readonly sessionName: string
  private readonly transactionName: string
  private readonly requestAccounts = new WeakMap<IncomingMessage,
    Promise<RegistryAuthenticatedAccount | null>>()

  /** @param ctx - Registry runtime with Credentials, WebServer and the persisted directory.
   * @param config - Validated relying-party, session and response bounds. */
  constructor(private readonly runtimeCtx: Context, private readonly config: RegistryOidcAccountAuthConfig) {
    super(runtimeCtx)
    this.secureCookies = new URL(config.publicOrigin).protocol === 'https:'
    this.sessionName = this.secureCookies ? '__Host-dsh_registry_session' : 'dsh_registry_session'
    this.transactionName = this.secureCookies ? '__Host-dsh_registry_oidc' : 'dsh_registry_oidc'
    this.installRoutes()
  }

  /** Verify the signed short session and remap the immutable external member ID through the current Registry directory.
   * @param request - Same-origin browser request carrying the HttpOnly account cookie.
   * @param signal - Request cancellation and directory-read cancellation observation.
   * @returns Fresh Registry role/team facts, or null for a missing, invalid, expired or removed session. */
  async authenticate(request: IncomingMessage, signal: AbortSignal): Promise<RegistryAuthenticatedAccount | null> {
    signal.throwIfAborted()
    const cached = this.requestAccounts.get(request)
    if (cached !== undefined) return cached
    const pending = this.authenticateFresh(request, signal)
    this.requestAccounts.set(request, pending)
    try { return await pending } catch (error) {
      this.requestAccounts.delete(request)
      throw error
    }
  }

  /** Resolve one signed session and one current directory snapshot per HTTP request.
   * Re-entrant authorization callbacks share this request-local result so a directory read cannot lock itself. */
  private async authenticateFresh(request: IncomingMessage,
    signal: AbortSignal): Promise<RegistryAuthenticatedAccount | null> {
    const encoded = cookieValue(request, this.sessionName, this.config.maxCookieBytes)
    if (encoded === null) return null
    const secret = await this.secret(this.config.sessionSecretEnv)
    let value: unknown
    try { value = open(secret, encoded, this.config.maxCookieBytes) } finally { secret.fill(0) }
    const session = sessionCookie(value)
    const now = Date.now()
    if (session === null || session.issuer !== this.config.issuer || session.issuedAt > now
      || session.expiresAt <= now || session.expiresAt - session.issuedAt > this.config.sessionTtlMs) return null
    try { return await this.currentAccount(session.memberId, signal) } catch (error) {
      if (error instanceof RegistryIngestError && error.code === 'not-found') return null
      throw error
    }
  }

  private installRoutes(): void {
    const active = new Set<AbortController>()
    const unregister = this.runtimeCtx.webServer.register({ kind: 'prefix', path: AUTH_BASE,
      handler: async (request, response) => {
        const controller = new AbortController()
        active.add(controller)
        const cancel = () => { controller.abort() }
        request.once('aborted', cancel)
        response.once('close', cancel)
        try { await this.handleRoute(request, response, controller.signal) } finally {
          request.off('aborted', cancel)
          response.off('close', cancel)
          active.delete(controller)
        }
      } })
    this.runtimeCtx.effect(() => async () => {
      unregister()
      for (const controller of active) controller.abort()
      active.clear()
    }, 'registry-app: OIDC account routes')
  }

  private async handleRoute(request: IncomingMessage, response: ServerResponse, signal: AbortSignal): Promise<void> {
    const url = routeUrl(request)
    try {
      if (url.pathname === START_PATH && request.method === 'GET') return await this.start(url, response, signal)
      if (url.pathname === CALLBACK_PATH && request.method === 'GET') return await this.callback(url, request, response, signal)
      if (url.pathname === LOGOUT_PATH && request.method === 'POST') {
        clearCookies(response, [this.sessionName, this.transactionName], this.secureCookies)
        redirect(response, '/#/sign-in')
        return
      }
      response.writeHead(404, { 'cache-control': 'no-store' })
      response.end()
    } catch {
      if (url.pathname === CALLBACK_PATH) {
        clearCookies(response, [this.transactionName], this.secureCookies)
        redirect(response, '/?auth=failed#/sign-in')
      } else unavailable(response)
    }
  }

  private async start(url: URL, response: ServerResponse, signal: AbortSignal): Promise<void> {
    const oidc = await this.client(signal)
    const codeVerifier = randomPKCECodeVerifier()
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier)
    const state = randomState()
    const nonce = randomNonce()
    const redirectTo = buildAuthorizationUrl(oidc, {
      redirect_uri: `${this.config.publicOrigin}${CALLBACK_PATH}`,
      scope: this.config.scopes,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      nonce,
      max_age: String(this.config.maxAuthenticationAgeSeconds),
    })
    const secret = await this.secret(this.config.sessionSecretEnv)
    let cookie: string
    try {
      cookie = seal(secret, { version: 1, state, nonce, codeVerifier, returnTo: returnPath(url),
        expiresAt: Date.now() + this.config.transactionTtlMs } satisfies TransactionCookie, this.config.maxCookieBytes)
    } finally { secret.fill(0) }
    setCookie(response, this.transactionName, cookie, Math.ceil(this.config.transactionTtlMs / 1000), this.secureCookies)
    redirect(response, redirectTo.href)
  }

  private async callback(url: URL, request: IncomingMessage, response: ServerResponse,
    signal: AbortSignal): Promise<void> {
    const encoded = cookieValue(request, this.transactionName, this.config.maxCookieBytes)
    if (encoded === null) throw new OidcUnavailable('OIDC transaction unavailable')
    const sessionSecret = await this.secret(this.config.sessionSecretEnv)
    let transaction: TransactionCookie | null
    try { transaction = transactionCookie(open(sessionSecret, encoded, this.config.maxCookieBytes)) } finally {
      sessionSecret.fill(0)
    }
    if (transaction === null || transaction.expiresAt <= Date.now()) throw new OidcUnavailable('OIDC transaction expired')
    const oidc = await this.client(signal)
    const callback = new URL(`${CALLBACK_PATH}${url.search}`, this.config.publicOrigin)
    const tokens = await authorizationCodeGrant(oidc, callback, {
      pkceCodeVerifier: transaction.codeVerifier,
      expectedState: transaction.state,
      expectedNonce: transaction.nonce,
      idTokenExpected: true,
      maxAge: this.config.maxAuthenticationAgeSeconds,
    })
    const claims = tokens.claims()
    const externalMemberId = claims?.[this.config.memberIdClaim]
    if (typeof externalMemberId !== 'string' || !IDENTIFIER.test(externalMemberId)) {
      throw new OidcUnavailable('OIDC member mapping unavailable')
    }
    await this.currentAccount(externalMemberId, signal)
    const now = Date.now()
    const tokenExpiry = typeof claims?.exp === 'number' && Number.isSafeInteger(claims.exp)
      ? claims.exp * 1000 : now + this.config.sessionTtlMs
    const expiresAt = Math.min(now + this.config.sessionTtlMs, tokenExpiry)
    if (expiresAt <= now) throw new OidcUnavailable('OIDC token expired')
    const secret = await this.secret(this.config.sessionSecretEnv)
    let session: string
    try {
      session = seal(secret, { version: 1, issuer: this.config.issuer, memberId: externalMemberId,
        issuedAt: now, expiresAt } satisfies SessionCookie, this.config.maxCookieBytes)
    } finally { secret.fill(0) }
    clearCookies(response, [this.transactionName], this.secureCookies)
    response.appendHeader('set-cookie', `${this.sessionName}=${session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${String(Math.ceil((expiresAt - now) / 1000))}${this.secureCookies ? '; Secure' : ''}`)
    redirect(response, transaction.returnTo)
  }

  private async client(signal: AbortSignal): Promise<Configuration> {
    const credential = await this.runtimeCtx.credentials.resolve(credentialRef(this.config.clientSecretEnv))
    if (credential === undefined || Buffer.byteLength(credential.value, 'utf8') < 16) {
      throw new OidcUnavailable('OIDC client secret unavailable')
    }
    const timeout = AbortSignal.timeout(this.config.requestTimeoutMs)
    const fetchWithSignal: CustomFetch = (input, init) => {
      const signals = [signal, timeout]
      if (init?.signal !== undefined && init.signal !== null) signals.push(init.signal)
      return globalThis.fetch(input, { ...init, signal: AbortSignal.any(signals) } as RequestInit)
    }
    const options = {
      [customFetch]: fetchWithSignal,
      ...(this.config.mode === 'loopback-development' ? { execute: [allowInsecureRequests] } : {}),
    }
    return discovery(new URL(this.config.issuer), this.config.clientId,
      { client_secret: credential.value, [clockTolerance]: this.config.clockToleranceSeconds }, undefined, options)
  }

  private async secret(reference: string): Promise<Buffer> {
    const credential = await (this.runtimeCtx.credentials as CredentialProvider).resolve(credentialRef(reference))
    if (credential === undefined || Buffer.byteLength(credential.value, 'utf8') < 32) {
      throw new OidcUnavailable('OIDC session secret unavailable')
    }
    return Buffer.from(credential.value, 'utf8')
  }

  private async currentAccount(memberId: string, signal: AbortSignal): Promise<RegistryAuthenticatedAccount> {
    signal.throwIfAborted()
    const directory: RegistryDirectory | undefined = this.runtimeCtx.get('registryDirectory')
    if (directory === undefined) throw new OidcUnavailable('Registry directory unavailable')
    const brandedMemberId = brandString<MemberId>(memberId)
    const value = await directory.read(() => {
      signal.throwIfAborted()
      return { subject: { organizationId: this.config.organizationId,
        memberId: brandedMemberId, authenticated: true }, now: Date.now() }
    }, 'audience', this.config.maxDirectoryBytes)
    signal.throwIfAborted()
    const member = value.members.find(candidate => candidate.memberId === brandedMemberId)
    if (member === undefined || member.state !== 'active') throw new RegistryIngestError('not-found')
    return {
      subject: {
        organizationId: this.config.organizationId,
        memberId: brandedMemberId,
        authenticated: true,
        membership: member.state,
        role: member.role,
        currentTeamIds: value.teams.filter(team => team.memberIds.includes(brandedMemberId)).map(team => team.teamId),
      },
      // Account login proves a member, not a source device. A production device-key resolver remains a separate provider.
      historyFor: () => null,
    }
  }
}
