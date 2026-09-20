/** Authenticated HTTPS boundary matching the Harness production disclosure bridge protocol.
 * The independent dshb1 bearer is revalidated on every HTTPS request. Unlike the WSS device path,
 * this transport has no Ed25519 request proof, so it exposes only directory/capacity reads and
 * write-only key provisioning; it never returns disclosure keys or content. */
import { createSecretKey } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { DisclosureDataKey, DisclosureDataKeyGrantScope,
  DisclosureDataKeyId } from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import { decodeRegistryBridgeToken, hashRegistryBridgeSecret, hashRegistryDeviceSecret,
  REGISTRY_BRIDGE_TOKEN_MAX_BYTES } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import { RegistryIngestError, type RegistryBindingId } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import type { RegistryDisclosureKeyProvider } from './disclosure-key-provider.ts'
import type { RegistryTenantRuntimeLease, RegistryTenantRuntimeRouter } from './tenant-runtime-router.ts'
import { RegistryTenancyError } from './tenancy.ts'

/** Exact route consumed by `ProductionDisclosureHttpsBridge` through an HTTPS reverse proxy. */
export const REGISTRY_PRODUCTION_DISCLOSURE_BRIDGE_PATH = '/a2a/v1/disclosure-publication'

const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const KEY_MATERIAL = /^[A-Za-z0-9_-]{43}$/u

/** Explicit request, response, authority and publication limits for the private bridge. */
export interface RegistryProductionDisclosureBridgeConfig {
  readonly requestTimeoutMs: number
  readonly maxConcurrentRequests: number
  readonly maxRequestBytes: number
  readonly maxResponseBytes: number
  readonly maxDirectoryBytes: number
  readonly maxAudienceEntries: number
  readonly maxDisplayNameCharacters: number
  readonly maxActivePublications: number
  readonly maxPreviewBytes: number
  readonly maxTargets: number
  readonly maxPublicationLifetimeMs: number
}

const positive = () => z.number().step(1).min(1).max(Number.MAX_SAFE_INTEGER).required()
const timer = () => z.number().step(1).min(1).max(2_147_483_647).required()
const rawConfig: z<RegistryProductionDisclosureBridgeConfig> = z.object({
  requestTimeoutMs: timer(),
  maxConcurrentRequests: positive(),
  maxRequestBytes: positive(),
  maxResponseBytes: positive(),
  maxDirectoryBytes: positive(),
  maxAudienceEntries: positive(),
  maxDisplayNameCharacters: positive(),
  maxActivePublications: positive(),
  maxPreviewBytes: positive(),
  maxTargets: positive(),
  maxPublicationLifetimeMs: timer(),
})

/** Strict Loader schema. Authentication reuses each self-enrolled Harness dshb1 credential. */
export const RegistryProductionDisclosureBridgeConfigSchema: z<RegistryProductionDisclosureBridgeConfig> = z.transform(
  rawConfig,
  (config) => {
    if (config.maxRequestBytes < 128 || config.maxResponseBytes < 128) {
      throw new z.ValidationError('Registry disclosure bridge envelope bounds are too small', {})
    }
    return config
  },
)

type BridgeOperation =
  | { readonly kind: 'authority.read' }
  | { readonly kind: 'authority.capacity'; readonly request: {
    readonly phase: 'prepare' | 'commit'
    readonly activePublications: number
    readonly previewBytes: number
    readonly targetCount: number
    readonly expiresAt: number
  } }
  | { readonly kind: 'keys.readiness' }
  | { readonly kind: 'keys.provision'; readonly scope: DisclosureDataKeyGrantScope; readonly key: {
    readonly keyId: DisclosureDataKeyId
    readonly material: string
  } }

interface AuthenticatedBinding {
  readonly organizationId: OrganizationId
  readonly instanceId: DshInstanceId
  readonly memberId: MemberId
  readonly bindingId: RegistryBindingId
}

interface RequestAdmission {
  pendingOperations: number
  handlerFinished: boolean
}

class EndpointFailure extends Error {
  constructor(readonly status: 400 | 401 | 403 | 405 | 413 | 503, readonly allow?: string) {
    super('Registry disclosure bridge request failed')
    this.name = 'RegistryProductionDisclosureBridgeFailure'
  }
}

function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new EndpointFailure(400)
  const value = input as Record<string, unknown>
  if (Object.keys(value).length !== keys.length || !keys.every(key => Object.hasOwn(value, key))) {
    throw new EndpointFailure(400)
  }
  return value
}

function selectedIdentifier(input: unknown): string {
  if (typeof input !== 'string' || !IDENTIFIER.test(input)) throw new EndpointFailure(400)
  return input
}

function coordinate(input: unknown): number {
  if (!Number.isSafeInteger(input) || (input as number) < 0 || Object.is(input, -0)) throw new EndpointFailure(400)
  return input as number
}

function canonicalKeyMaterial(input: unknown): string {
  if (typeof input !== 'string' || !KEY_MATERIAL.test(input)) throw new EndpointFailure(400)
  const material = Buffer.from(input, 'base64url')
  try {
    if (material.byteLength !== 32 || material.toString('base64url') !== input) throw new EndpointFailure(400)
    return input
  } finally { material.fill(0) }
}

function decodeOperation(input: unknown, binding: AuthenticatedBinding): BridgeOperation {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new EndpointFailure(400)
  const operation = (input as Record<string, unknown>).operation
  if (operation !== 'authority.read' && operation !== 'authority.capacity'
    && operation !== 'keys.readiness' && operation !== 'keys.provision') throw new EndpointFailure(400)
  const head = exact(input, operation === 'authority.capacity'
    ? ['version', 'operation', 'organizationId', 'instanceId', 'request']
    : operation === 'keys.provision'
      ? ['version', 'operation', 'organizationId', 'instanceId', 'scope', 'key']
      : operation === 'authority.read' || operation === 'keys.readiness'
        ? ['version', 'operation', 'organizationId', 'instanceId']
        : [])
  if (head.version !== 1) throw new EndpointFailure(400)
  if (head.organizationId !== binding.organizationId || head.instanceId !== binding.instanceId) throw new EndpointFailure(403)
  if (operation === 'authority.read') return { kind: 'authority.read' }
  if (operation === 'keys.readiness') return { kind: 'keys.readiness' }
  if (operation === 'authority.capacity') {
    const request = exact(head.request,
      ['phase', 'activePublications', 'previewBytes', 'targetCount', 'expiresAt'])
    if (request.phase !== 'prepare' && request.phase !== 'commit') throw new EndpointFailure(400)
    return { kind: 'authority.capacity', request: {
      phase: request.phase,
      activePublications: coordinate(request.activePublications),
      previewBytes: coordinate(request.previewBytes),
      targetCount: coordinate(request.targetCount),
      expiresAt: coordinate(request.expiresAt),
    } }
  }
  if (operation === 'keys.provision') {
    const scope = exact(head.scope, ['organizationId', 'instanceId', 'conversationId', 'disclosureId'])
    const key = exact(head.key, ['keyId', 'material'])
    if (scope.organizationId !== binding.organizationId || scope.instanceId !== binding.instanceId) {
      throw new EndpointFailure(403)
    }
    return { kind: 'keys.provision', scope: Object.freeze({
      organizationId: brandString<OrganizationId>(selectedIdentifier(scope.organizationId)),
      instanceId: brandString<DshInstanceId>(selectedIdentifier(scope.instanceId)),
      conversationId: brandString<DisclosureDataKeyGrantScope['conversationId']>(selectedIdentifier(scope.conversationId)),
      disclosureId: brandString<DisclosureDataKeyGrantScope['disclosureId']>(selectedIdentifier(scope.disclosureId)),
    }), key: Object.freeze({
      keyId: brandString<DisclosureDataKeyId>(selectedIdentifier(key.keyId)),
      material: canonicalKeyMaterial(key.material),
    }) }
  }
  throw new EndpointFailure(400)
}

/** Parse bounded JSON only after rejecting duplicate object members at every depth. */
function parseUnambiguousJson(text: string): unknown {
  let offset = 0
  const whitespace = (): void => {
    while (offset < text.length && /[\t\n\r ]/u.test(text[offset] ?? '')) offset++
  }
  const string = (): string => {
    const start = offset
    if (text[offset] !== '"') throw new EndpointFailure(400)
    offset++
    while (offset < text.length) {
      const code = text.charCodeAt(offset)
      if (code === 0x22) {
        offset++
        try { return JSON.parse(text.slice(start, offset)) as string } catch { throw new EndpointFailure(400) }
      }
      if (code <= 0x1f) throw new EndpointFailure(400)
      if (code === 0x5c) {
        offset++
        const escape = text[offset]
        if (escape === 'u') {
          if (!/^[0-9A-Fa-f]{4}$/u.test(text.slice(offset + 1, offset + 5))) throw new EndpointFailure(400)
          offset += 5
        } else if (escape !== undefined && /^["\\/bfnrt]$/u.test(escape)) offset++
        else throw new EndpointFailure(400)
      } else offset++
    }
    throw new EndpointFailure(400)
  }
  const value = (depth: number): void => {
    if (depth > 64) throw new EndpointFailure(400)
    whitespace()
    const token = text[offset]
    if (token === '"') { string(); return }
    if (token === '{') {
      offset++
      whitespace()
      const members = new Set<string>()
      if (text[offset] === '}') { offset++; return }
      while (true) {
        whitespace()
        const member = string()
        if (members.has(member)) throw new EndpointFailure(400)
        members.add(member)
        whitespace()
        if (text[offset] !== ':') throw new EndpointFailure(400)
        offset++
        value(depth + 1)
        whitespace()
        if (text[offset] === '}') { offset++; return }
        if (text[offset] !== ',') throw new EndpointFailure(400)
        offset++
      }
    }
    if (token === '[') {
      offset++
      whitespace()
      if (text[offset] === ']') { offset++; return }
      while (true) {
        value(depth + 1)
        whitespace()
        if (text[offset] === ']') { offset++; return }
        if (text[offset] !== ',') throw new EndpointFailure(400)
        offset++
      }
    }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, offset)) { offset += literal.length; return }
    }
    const number = text.slice(offset).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u)?.[0]
    if (number === undefined) throw new EndpointFailure(400)
    offset += number.length
  }
  value(0)
  whitespace()
  if (offset !== text.length) throw new EndpointFailure(400)
  try { return JSON.parse(text) as unknown } catch { throw new EndpointFailure(400) }
}

function isJsonContentType(value: string | undefined): boolean {
  if (value === undefined) return false
  const parts = value.split(';').map(part => part.trim())
  const [mediaType, parameter, ...extra] = parts
  return mediaType?.toLowerCase() === 'application/json'
    && (parameter === undefined || extra.length === 0 && /^charset=(?:utf-8|"utf-8")$/iu.test(parameter))
}

function declaredLength(request: IncomingMessage): number | undefined {
  const value = request.headers['content-length']
  if (value === undefined) return undefined
  if (!/^(0|[1-9]\d*)$/u.test(value)) throw new EndpointFailure(400)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed)) throw new EndpointFailure(400)
  return parsed
}

async function readJson(request: IncomingMessage, maximum: number, signal: AbortSignal): Promise<unknown> {
  if (!isJsonContentType(request.headers['content-type'])) {
    throw new EndpointFailure(400)
  }
  const declared = declaredLength(request)
  if (declared !== undefined && request.headers['transfer-encoding'] !== undefined) {
    throw new EndpointFailure(400)
  }
  if (declared !== undefined && (declared === 0 || declared > maximum)) {
    throw new EndpointFailure(413)
  }
  const chunks: Buffer[] = []
  let size = 0
  let bytes: Buffer | undefined
  const stop = (): void => { request.destroy() }
  signal.addEventListener('abort', stop, { once: true })
  try {
    for await (const raw of request.iterator({ destroyOnReturn: false })) {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as string)
      size += chunk.byteLength
      chunks.push(chunk)
      if (size > maximum) {
        throw new EndpointFailure(413)
      }
    }
    if (!request.complete || signal.aborted || size === 0 || declared !== undefined && declared !== size) {
      throw new EndpointFailure(400)
    }
    bytes = Buffer.concat(chunks, size)
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    return parseUnambiguousJson(text)
  } catch (error) {
    if (error instanceof EndpointFailure) throw error
    throw new EndpointFailure(400)
  } finally {
    signal.removeEventListener('abort', stop)
    bytes?.fill(0)
    for (const chunk of chunks) chunk.fill(0)
  }
}

function singleAuthorization(request: IncomingMessage): string {
  const values: string[] = []
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === 'authorization') {
      const value = request.rawHeaders[index + 1]
      if (value !== undefined) values.push(value)
    }
  }
  if (values.length !== 1 || !values[0]?.startsWith('Bearer ')) throw new EndpointFailure(401)
  const token = values[0].slice('Bearer '.length)
  if (Buffer.byteLength(token, 'utf8') > REGISTRY_BRIDGE_TOKEN_MAX_BYTES) throw new EndpointFailure(401)
  return token
}

/** Race a possibly non-cooperative dependency while continuing to observe any late rejection. */
function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false
    const finish = (complete: () => void): void => {
      if (settled) return
      settled = true
      signal.removeEventListener('abort', onAbort)
      complete()
    }
    const onAbort = (): void => finish(() => reject(
      signal.reason instanceof Error ? signal.reason : new Error('aborted')))
    signal.addEventListener('abort', onAbort, { once: true })
    operation.then(
      value => { finish(() => resolve(value)) },
      error => { finish(() => reject(error)) },
    )
    if (signal.aborted) onAbort()
  })
}

/** An acquisition may resolve after its request deadline; release that late lease exactly once. */
async function acquireAbortable(operation: Promise<RegistryTenantRuntimeLease>,
  signal: AbortSignal,
  observe: (selected: Promise<RegistryTenantRuntimeLease>) => Promise<RegistryTenantRuntimeLease>):
Promise<RegistryTenantRuntimeLease> {
  let lease: RegistryTenantRuntimeLease | undefined
  let releaseLate = signal.aborted
  let released = false
  const observed = observe(operation).then((value) => {
    lease = value
    if (releaseLate && !released) {
      released = true
      try { value.release() } catch { /* a late lease has no request to report into */ }
    }
    return value
  })
  try { return await abortable(observed, signal) } catch (error) {
    releaseLate = true
    if (lease !== undefined && !released) {
      released = true
      try { lease.release() } catch { /* preserve the request failure */ }
    }
    throw error
  }
}

function writeJson(response: ServerResponse, status: number, value: unknown,
  maximum: number, allow?: string): void {
  const body = JSON.stringify(value)
  if (Buffer.byteLength(body, 'utf8') > maximum) throw new EndpointFailure(503)
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body, 'utf8')),
    'x-content-type-options': 'nosniff',
    ...(allow === undefined ? {} : { allow }),
  })
  response.end(body)
}

function writeFailure(response: ServerResponse, failure: EndpointFailure, maximum: number): void {
  const code = failure.status === 401 ? 'unauthenticated'
    : failure.status === 403 ? 'forbidden'
      : failure.status === 405 ? 'method-not-allowed'
        : failure.status === 413 ? 'request-too-large'
          : failure.status === 503 ? 'unavailable' : 'invalid-input'
  writeJson(response, failure.status, { version: 1, status: code }, maximum, failure.allow)
}

/** Never keep a socket reusable when a rejection leaves request bytes unread. */
function writeRejectedRequest(request: IncomingMessage, response: ServerResponse,
  failure: EndpointFailure, maximum: number): void {
  if (!request.complete || !request.readableEnded) {
    response.shouldKeepAlive = false
    response.setHeader('connection', 'close')
    const socket = request.socket
    response.once('finish', () => {
      if (socket !== null && !socket.destroyed) socket.destroySoon()
    })
  }
  writeFailure(response, failure, maximum)
}

function responseFailure(error: unknown): EndpointFailure {
  if (error instanceof EndpointFailure) return error
  if (error instanceof RegistryIngestError && error.code === 'not-found') return new EndpointFailure(403)
  return new EndpointFailure(503)
}

/** One registered endpoint; close removes admission, aborts requests and drains admitted work. */
export class RegistryProductionDisclosureBridge {
  private readonly lifetime = new AbortController()
  private readonly requests = new Set<AbortController>()
  private readonly tasks = new Set<Promise<void>>()
  private readonly admissions = new Set<RequestAdmission>()
  private readonly unregister: () => void

  constructor(private readonly router: RegistryTenantRuntimeRouter,
    private readonly keyProvider: RegistryDisclosureKeyProvider,
    private readonly config: RegistryProductionDisclosureBridgeConfig,
    register: (route: WebRoute) => () => void) {
    const resolved = RegistryProductionDisclosureBridgeConfigSchema(structuredClone(config))
    this.config = Object.freeze({ ...resolved })
    this.unregister = register({ kind: 'exact', path: REGISTRY_PRODUCTION_DISCLOSURE_BRIDGE_PATH,
      handler: (request, response) => {
        if (this.admissions.size >= this.config.maxConcurrentRequests) {
          writeRejectedRequest(request, response, new EndpointFailure(503), this.config.maxResponseBytes)
          return
        }
        const admission: RequestAdmission = { pendingOperations: 0, handlerFinished: false }
        this.admissions.add(admission)
        const task = this.handle(request, response, admission)
        this.tasks.add(task)
        const finished = (): void => {
          this.tasks.delete(task)
          admission.handlerFinished = true
          if (admission.pendingOperations === 0) this.admissions.delete(admission)
        }
        void task.then(finished, finished)
        return task
      } })
  }

  /** Stop route admission, abort active handlers and drain every admitted HTTP handler. */
  async close(): Promise<void> {
    this.unregister()
    this.lifetime.abort()
    for (const request of this.requests) request.abort()
    await Promise.allSettled(this.tasks)
    this.requests.clear()
    this.admissions.clear()
  }

  private observe<T>(admission: RequestAdmission, operation: Promise<T>): Promise<T> {
    admission.pendingOperations += 1
    let settled = false
    const finish = (): void => {
      if (settled) return
      settled = true
      admission.pendingOperations -= 1
      if (admission.handlerFinished && admission.pendingOperations === 0) this.admissions.delete(admission)
    }
    void operation.then(finish, finish)
    return operation
  }

  private race<T>(admission: RequestAdmission, operation: Promise<T>, signal: AbortSignal): Promise<T> {
    return abortable(this.observe(admission, operation), signal)
  }

  private async handle(request: IncomingMessage, response: ServerResponse,
    admission: RequestAdmission): Promise<void> {
    const requestAbort = new AbortController()
    this.requests.add(requestAbort)
    const disconnected = (): void => { if (!response.writableEnded) requestAbort.abort() }
    request.once('aborted', disconnected)
    response.once('close', disconnected)
    try {
      const signal = AbortSignal.any([this.lifetime.signal, requestAbort.signal,
        AbortSignal.timeout(this.config.requestTimeoutMs)])
      if (request.url !== REGISTRY_PRODUCTION_DISCLOSURE_BRIDGE_PATH) throw new EndpointFailure(400)
      if (request.method !== 'POST') {
        throw new EndpointFailure(405, 'POST')
      }
      const authenticated = await this.authenticate(request, signal, admission)
      try {
        const operation = decodeOperation(await readJson(request, this.config.maxRequestBytes,
          authenticated.signal), authenticated.binding)
        await this.run(authenticated, operation, response, admission)
      } finally { authenticated.release() }
    } catch (error) {
      if (!response.headersSent && !response.destroyed) {
        try {
          writeRejectedRequest(request, response, responseFailure(error), this.config.maxResponseBytes)
        } catch { response.destroy() }
      }
    } finally {
      request.off('aborted', disconnected)
      response.off('close', disconnected)
      this.requests.delete(requestAbort)
    }
  }

  private async authenticate(request: IncomingMessage, signal: AbortSignal,
    admission: RequestAdmission): Promise<{
    readonly binding: AuthenticatedBinding
    readonly lease: RegistryTenantRuntimeLease
    readonly signal: AbortSignal
    release(): void
  }> {
    let decoded: ReturnType<typeof decodeRegistryBridgeToken>
    try { decoded = decodeRegistryBridgeToken(singleAuthorization(request)) } catch { throw new EndpointFailure(401) }
    const presentedHash = hashRegistryBridgeSecret(decoded.secret)
    const sameRawDeviceHash = hashRegistryDeviceSecret(decoded.secret)
    let lease: RegistryTenantRuntimeLease | undefined
    try {
      signal.throwIfAborted()
      lease = await acquireAbortable(this.router.acquireRuntime(decoded.organizationId), signal,
        operation => this.observe(admission, operation))
      signal.throwIfAborted()
    } catch (error) {
      lease?.release()
      signal.throwIfAborted()
      if (error instanceof RegistryTenancyError && error.code === 'not-found') throw new EndpointFailure(403)
      throw new EndpointFailure(503)
    }
    let unsubscribe: (() => void) | undefined
    const invalidated = new AbortController()
    let instanceId: DshInstanceId | undefined
    try {
      if (lease.runtime.organizationId !== decoded.organizationId || lease.runtime.directory === undefined) {
        throw new EndpointFailure(403)
      }
      unsubscribe = lease.runtime.store.subscribeInvalidation((notice) => {
        if (notice.kind === 'owner-unavailable'
          || notice.kind === 'binding' && (instanceId === undefined || notice.change.instanceId === instanceId)) {
          invalidated.abort()
        }
      })
      const operationSignal = AbortSignal.any([signal, lease.runtime.signal, invalidated.signal])
      operationSignal.throwIfAborted()
      const authenticated = await this.race(admission, lease.runtime.store.authenticateBridgeCredential(
        brandString<RegistryBindingId>(decoded.bindingId), presentedHash, sameRawDeviceHash), operationSignal)
      operationSignal.throwIfAborted()
      const producer = authenticated.producer.connection
      if (authenticated.bindingId !== decoded.bindingId || authenticated.organizationId !== decoded.organizationId
        || producer.organizationId !== authenticated.organizationId
        || producer.instanceId !== authenticated.instanceId
        || authenticated.producer.history.organizationId !== authenticated.organizationId
        || authenticated.producer.history.instanceId !== authenticated.instanceId
        || authenticated.producer.history.status !== 'active') throw new EndpointFailure(403)
      instanceId = producer.instanceId
      const binding: AuthenticatedBinding = Object.freeze({ organizationId: producer.organizationId,
        instanceId: producer.instanceId, memberId: authenticated.memberId, bindingId: authenticated.bindingId })
      let released = false
      return { binding, lease, signal: operationSignal, release: () => {
        if (released) return
        released = true
        unsubscribe?.()
        lease.release()
      } }
    } catch (error) {
      unsubscribe?.()
      lease.release()
      throw error
    }
  }

  private async run(authenticated: { readonly binding: AuthenticatedBinding; readonly lease: RegistryTenantRuntimeLease;
    readonly signal: AbortSignal }, operation: BridgeOperation, response: ServerResponse,
    admission: RequestAdmission): Promise<void> {
    const { binding, lease, signal: operationSignal } = authenticated
    const directoryOwner = lease.runtime.directory
    if (directoryOwner === undefined) throw new EndpointFailure(503)
    const authority = () => ({ subject: { authenticated: true as const,
      organizationId: binding.organizationId, memberId: binding.memberId }, now: Date.now() })
    if (operation.kind === 'authority.read') {
      operationSignal.throwIfAborted()
      const directory = await this.race(admission,
        directoryOwner.read(authority, 'audience', this.config.maxDirectoryBytes), operationSignal)
      operationSignal.throwIfAborted()
      const audience = [
        ...directory.members.map(member => ({ target: { kind: 'member' as const, memberId: member.memberId },
          displayName: member.displayName })),
        ...directory.teams.map(team => ({ target: { kind: 'team' as const, teamId: team.teamId },
          displayName: team.displayName })),
      ]
      const audienceKeys = new Set<string>()
      if (audience.length > this.config.maxAudienceEntries || audience.some((candidate) => {
        const identifier = candidate.target.kind === 'member'
          ? candidate.target.memberId : candidate.target.teamId
        const key = `${candidate.target.kind}:${identifier}`
        if (!IDENTIFIER.test(identifier) || audienceKeys.has(key)) return true
        audienceKeys.add(key)
        return candidate.displayName.length === 0 || !candidate.displayName.isWellFormed()
          || candidate.displayName.includes('\0')
          || Array.from(candidate.displayName).length > this.config.maxDisplayNameCharacters
      })) {
        throw new EndpointFailure(503)
      }
      writeJson(response, 200, { version: 1, status: 'ready', audience }, this.config.maxResponseBytes)
      return
    }
    if (operation.kind === 'authority.capacity') {
      const now = Date.now()
      const exhausted = (operation.request.phase === 'prepare'
        ? operation.request.activePublications >= this.config.maxActivePublications
        : operation.request.activePublications > this.config.maxActivePublications)
        || operation.request.previewBytes > this.config.maxPreviewBytes
        || operation.request.targetCount === 0 || operation.request.targetCount > this.config.maxTargets
        || operation.request.expiresAt <= now
        || operation.request.expiresAt > now + this.config.maxPublicationLifetimeMs
      writeJson(response, 200, { version: 1, status: exhausted ? 'exhausted' : 'available' },
        this.config.maxResponseBytes)
      return
    }
    if (operation.kind === 'keys.readiness') {
      operationSignal.throwIfAborted()
      if (!await this.race(admission,
        this.keyProvider.checkReadiness(binding.organizationId, operationSignal), operationSignal)) {
        throw new EndpointFailure(503)
      }
      operationSignal.throwIfAborted()
      writeJson(response, 200, { version: 1, status: 'ready' }, this.config.maxResponseBytes)
      return
    }

    const raw = Buffer.from(operation.key.material, 'base64url')
    try {
      operationSignal.throwIfAborted()
      const dataKey: DisclosureDataKey = Object.freeze({ keyId: operation.key.keyId,
        scope: Object.freeze({ organizationId: operation.scope.organizationId,
          instanceId: operation.scope.instanceId, conversationId: operation.scope.conversationId }),
        key: createSecretKey(raw) })
      const receipt = await this.race(admission,
        this.keyProvider.publishDataKey(operation.scope, dataKey, operationSignal), operationSignal)
      operationSignal.throwIfAborted()
      if (receipt.keyId !== operation.key.keyId
        || receipt.assurance !== this.keyProvider.protection.assurance
        || receipt.scope.organizationId !== operation.scope.organizationId
        || receipt.scope.instanceId !== operation.scope.instanceId
        || receipt.scope.conversationId !== operation.scope.conversationId
        || receipt.scope.disclosureId !== operation.scope.disclosureId) throw new EndpointFailure(503)
    } finally { raw.fill(0) }
    writeJson(response, 200, { version: 1, status: 'provisioned', scope: operation.scope,
      keyId: operation.key.keyId }, this.config.maxResponseBytes)
  }
}

/** Install the optional SaaS bridge only when every authentication and KMS owner is available. */
export function installRegistryProductionDisclosureBridge(ctx: Context,
  config: RegistryProductionDisclosureBridgeConfig,
  resolvedRouter?: RegistryTenantRuntimeRouter): RegistryProductionDisclosureBridge {
  // The SaaS runtime creates and fully initializes its router in this same
  // plugin fiber. That fiber is not ACTIVE until apply() returns, so its own
  // freshly provided service is intentionally passed directly instead of
  // weakening strict service lookup for every external caller.
  const router = resolvedRouter ?? ctx.get('registryTenantRouter')
  const keyProvider = ctx.get('registryDisclosureKeyProvider')
  if (router === undefined || keyProvider === undefined) {
    throw new Error('Registry production disclosure bridge requires tenant routing and a key provider')
  }
  return new RegistryProductionDisclosureBridge(router, keyProvider, config,
    route => ctx.webServer.register(route))
}
