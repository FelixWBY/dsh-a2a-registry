/** Test-only authenticated Registry reader for explicit local-Harness context refreshes. */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'
import { credentialRef, type CredentialProvider, type CredentialRef } from '@deepseek-ai/dsh-credentials'
import type { DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { RegistryIngestError, type FreshRegistryDirectoryAuthority,
  type FreshRegistryMetadataAuthority } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { z as zod } from 'zod'
import type { RegistryAccountAuthenticator, RegistryAuthenticatedAccount } from './account-auth.ts'
import type { RegistryDisclosureReader } from './reader.ts'

/** Exact private route used only by the generated local MVP. */
export const A2A_LOOPBACK_DISCLOSURE_REFRESH_PATH = '/a2a-loopback/v1/disclosure-refresh'

const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const HASH = /^sha256:[0-9a-f]{64}$/u
const BASE64URL = /^[A-Za-z0-9_-]+$/u
const MIN_SHARED_SECRET_BYTES = 32

/** Fixed synthetic member, source and receiving device for one explicit test-only composition. */
export interface LocalHarnessDisclosureRefreshConfig {
  readonly mode: 'test-only'
  readonly organizationId: OrganizationId
  readonly memberId: MemberId
  readonly sourceInstanceId: DshInstanceId
  readonly targetInstanceId: DshInstanceId
  readonly sharedSecretEnv: string
  readonly clockSkewMs: number
  readonly maxInputBytes: number
  readonly maxResponseBytes: number
  readonly requestTimeoutMs: number
  readonly maxReplayEntries: number
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const timer = () => z.natural().min(1).max(2_147_483_647).required()
const identifier = <T extends Branded<string>>() => z.transform(z.string().pattern(IDENTIFIER).required(),
  value => brandString<T>(value)).required()

/** Loader schema; omission leaves the Registry refresh bridge absent. */
export const LocalHarnessDisclosureRefreshConfigSchema: z<LocalHarnessDisclosureRefreshConfig> = z.object({
  mode: z.const('test-only').required(),
  organizationId: identifier<OrganizationId>(),
  memberId: identifier<MemberId>(),
  sourceInstanceId: identifier<DshInstanceId>(),
  targetInstanceId: identifier<DshInstanceId>(),
  sharedSecretEnv: z.string().role('credential-ref').required(),
  clockSkewMs: timer(), maxInputBytes: positive(), maxResponseBytes: positive(),
  requestTimeoutMs: timer(), maxReplayEntries: positive(),
})

const common = {
  version: zod.literal(1),
  organizationId: zod.string().regex(IDENTIFIER),
  disclosureId: zod.string().regex(IDENTIFIER),
  sourceInstanceId: zod.string().regex(IDENTIFIER),
  targetInstanceId: zod.string().regex(IDENTIFIER),
  currentCheckpointHash: zod.string().regex(HASH),
  currentAuthorizationVersion: zod.number().int().nonnegative(),
}
const readinessSchema = zod.strictObject({ ...common, action: zod.literal('readiness') })
const authorizeSchema = zod.strictObject({ ...common, action: zod.literal('authorize'),
  checkpointHash: zod.string().regex(HASH) })
const requestSchema = zod.discriminatedUnion('action', [readinessSchema, authorizeSchema])
type RefreshRequest = zod.infer<typeof requestSchema>

type FailureCode = 'invalid-input' | 'method-not-allowed' | 'not-configured'
  | 'not-found' | 'replay' | 'unauthenticated' | 'unavailable' | 'conflict' | 'limit'

class EndpointFailure extends Error {
  constructor(readonly status: number, readonly code: FailureCode, readonly allow?: string) {
    super(code)
    this.name = 'A2aDisclosureRefreshEndpointFailure'
  }
}

function optionalHeader(request: IncomingMessage, name: string): string | undefined {
  const values = request.headersDistinct[name]
  if (values === undefined) return undefined
  if (values.length !== 1 || values[0] === undefined || values[0].trim() !== values[0] || values[0] === '') {
    throw new EndpointFailure(400, 'invalid-input')
  }
  return values[0]
}

function requiredHeader(request: IncomingMessage, name: string): string {
  const value = optionalHeader(request, name)
  if (value === undefined) throw new EndpointFailure(401, 'unauthenticated')
  return value
}

function isJsonContentType(value: string | undefined): boolean {
  if (value === undefined) return false
  const parts = value.split(';').map(part => part.trim())
  const [mediaType, parameter, ...extra] = parts
  return mediaType?.toLowerCase() === 'application/json'
    && (parameter === undefined || extra.length === 0 && /^charset=(?:utf-8|"utf-8")$/iu.test(parameter))
}

async function rawBody(request: IncomingMessage, maximum: number, signal: AbortSignal): Promise<Buffer> {
  const declared = optionalHeader(request, 'content-length')
  if (declared !== undefined && (!/^(0|[1-9]\d*)$/u.test(declared) || Number(declared) > maximum)) {
    request.resume()
    throw new EndpointFailure(400, 'invalid-input')
  }
  const chunks: Buffer[] = []
  let size = 0
  const stop = (): void => { request.destroy() }
  signal.addEventListener('abort', stop, { once: true })
  try {
    for await (const raw of request) {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as string)
      size += chunk.byteLength
      if (size > maximum) throw new EndpointFailure(400, 'invalid-input')
      chunks.push(chunk)
    }
  } catch (error) {
    if (error instanceof EndpointFailure) throw error
    throw new EndpointFailure(signal.aborted ? 503 : 400, signal.aborted ? 'unavailable' : 'invalid-input')
  } finally { signal.removeEventListener('abort', stop) }
  if (!request.complete || signal.aborted || size === 0) throw new EndpointFailure(503, 'unavailable')
  return Buffer.concat(chunks, size)
}

function writeJson(response: ServerResponse, status: number, value: unknown, maximum: number, allow?: string): void {
  const body = JSON.stringify(value)
  if (Buffer.byteLength(body, 'utf8') > maximum) {
    writeJson(response, 400, { ok: false, error: { code: 'limit' } }, Number.MAX_SAFE_INTEGER)
    return
  }
  response.writeHead(status, { 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body, 'utf8')), 'x-content-type-options': 'nosniff',
    ...(allow === undefined ? {} : { allow }) })
  response.end(body)
}

function loopback(address: string | undefined): boolean {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

function assertTestOnlyMode(value: unknown): void {
  if (value !== 'test-only') throw new Error('Registry Local Harness refresh requires explicit test-only mode')
}

function mapFailure(error: unknown): EndpointFailure {
  if (error instanceof EndpointFailure) return error
  if (error instanceof RegistryIngestError) {
    if (error.code === 'not-found') return new EndpointFailure(404, 'not-found')
    if (error.code === 'limit') return new EndpointFailure(400, 'limit')
    if (error.code === 'invalid-input') return new EndpointFailure(400, 'invalid-input')
  }
  return new EndpointFailure(503, 'unavailable')
}

function validAccount(account: RegistryAuthenticatedAccount | null,
  config: LocalHarnessDisclosureRefreshConfig): account is RegistryAuthenticatedAccount {
  if (account === null || !account.subject.authenticated || account.subject.membership !== 'active'
    || account.subject.organizationId !== config.organizationId || account.subject.memberId !== config.memberId) return false
  const history = account.historyFor(config.sourceInstanceId)
  return history !== null && history.organizationId === config.organizationId
    && history.instanceId === config.sourceInstanceId && history.status === 'active'
}

/** Read-only route owner. It never retains browser credentials, launch tokens, prefixes or data keys. */
export class LocalHarnessDisclosureRefresh {
  private readonly requests = new Set<AbortController>()
  private readonly tasks = new Set<Promise<void>>()
  private readonly replay = new Map<string, number>()
  private readonly lifetime = new AbortController()
  private unregister = (): void => {}

  private constructor(private readonly reader: RegistryDisclosureReader,
    private readonly authenticator: RegistryAccountAuthenticator,
    private readonly credentials: CredentialProvider,
    private readonly secretRef: CredentialRef,
    private readonly config: LocalHarnessDisclosureRefreshConfig) {}

  /** Validate required local services and claim the exact private route. */
  static async open(ctx: Context, config: LocalHarnessDisclosureRefreshConfig): Promise<LocalHarnessDisclosureRefresh> {
    assertTestOnlyMode(config.mode)
    const webServer = ctx.get('webServer')
    const reader = ctx.get('registryDisclosureReader')
    const authenticator = ctx.get('registryAccountAuthenticator')
    const credentials = ctx.get('credentials')
    if (webServer === undefined || webServer.host !== '127.0.0.1') {
      throw new Error('Registry Local Harness refresh requires a 127.0.0.1 WebServer')
    }
    if (reader === undefined || authenticator === undefined || credentials === undefined) {
      throw new Error('Registry Local Harness refresh requires Registry reader, account identity and credentials')
    }
    const secretRef = credentialRef(config.sharedSecretEnv)
    const secret = await credentials.resolve(secretRef)
    if (secret === undefined || Buffer.byteLength(secret.value, 'utf8') < MIN_SHARED_SECRET_BYTES) {
      throw new Error('Registry Local Harness refresh shared secret is unavailable')
    }
    const owner = new LocalHarnessDisclosureRefresh(reader, authenticator, credentials, secretRef,
      structuredClone(config))
    owner.unregister = webServer.register(owner.route())
    return owner
  }

  /** Stop route admission and drain accepted reads. */
  async close(): Promise<void> {
    this.unregister()
    this.lifetime.abort()
    for (const request of this.requests) request.abort()
    await Promise.allSettled([...this.tasks])
    this.requests.clear()
    this.replay.clear()
  }

  private route(): WebRoute {
    return { kind: 'exact', path: A2A_LOOPBACK_DISCLOSURE_REFRESH_PATH, handler: (request, response) => {
      const task = this.handle(request, response)
      this.tasks.add(task)
      void task.finally(() => { this.tasks.delete(task) })
      return task
    } }
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const requestAbort = new AbortController()
    this.requests.add(requestAbort)
    const disconnect = (): void => { if (!response.writableEnded) requestAbort.abort() }
    request.once('aborted', disconnect)
    response.once('close', disconnect)
    try {
      const signal = AbortSignal.any([this.lifetime.signal, requestAbort.signal,
        AbortSignal.timeout(this.config.requestTimeoutMs)])
      if (!loopback(request.socket.remoteAddress)) throw new EndpointFailure(404, 'not-found')
      const url = new URL(request.url ?? '/', 'http://loopback.invalid')
      if (url.pathname !== A2A_LOOPBACK_DISCLOSURE_REFRESH_PATH || url.search !== '') {
        throw new EndpointFailure(400, 'invalid-input')
      }
      if (request.method !== 'POST') {
        request.resume()
        throw new EndpointFailure(405, 'method-not-allowed', 'POST')
      }
      if (!isJsonContentType(optionalHeader(request, 'content-type'))) {
        request.resume()
        throw new EndpointFailure(400, 'invalid-input')
      }
      const body = await rawBody(request, this.config.maxInputBytes, signal)
      await this.authenticate(request, body, signal)
      let parsed: unknown
      try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)) } catch {
        throw new EndpointFailure(400, 'invalid-input')
      }
      const decoded = requestSchema.safeParse(parsed)
      if (!decoded.success) throw new EndpointFailure(400, 'invalid-input')
      const value = await this.execute(request, decoded.data, signal)
      writeJson(response, 200, { ok: true, value }, this.config.maxResponseBytes)
    } catch (error) {
      if (!response.headersSent && !response.destroyed) {
        const failure = mapFailure(error)
        writeJson(response, failure.status, { ok: false, error: { code: failure.code } },
          this.config.maxResponseBytes, failure.allow)
      }
    } finally {
      request.off('aborted', disconnect)
      response.off('close', disconnect)
      this.requests.delete(requestAbort)
    }
  }

  private async execute(request: IncomingMessage, input: RefreshRequest, signal: AbortSignal): Promise<unknown> {
    if (input.organizationId !== this.config.organizationId || input.sourceInstanceId !== this.config.sourceInstanceId
      || input.targetInstanceId !== this.config.targetInstanceId) throw new EndpointFailure(404, 'not-found')
    const initial = await this.authenticator.authenticate(request, signal).catch(() => null)
    if (!validAccount(initial, this.config)) throw new EndpointFailure(404, 'not-found')
    const pinned = { organizationId: initial.subject.organizationId, memberId: initial.subject.memberId }
    const current = async (): Promise<RegistryAuthenticatedAccount> => {
      signal.throwIfAborted()
      const account = await this.authenticator.authenticate(request, signal).catch(() => null)
      if (!validAccount(account, this.config) || account.subject.organizationId !== pinned.organizationId
        || account.subject.memberId !== pinned.memberId) throw new RegistryIngestError('not-found')
      return account
    }
    const authority: FreshRegistryMetadataAuthority = async () => {
      const account = await current()
      return { subject: structuredClone(account.subject), now: Date.now(), historyFor: account.historyFor }
    }
    const receiveAuthority: FreshRegistryDirectoryAuthority = async () => {
      const account = await current()
      return { subject: { organizationId: account.subject.organizationId,
        memberId: account.subject.memberId, authenticated: true }, now: Date.now() }
    }
    const disclosureId = brandString<DisclosureId>(input.disclosureId)
    const latest = input.action === 'readiness'
      ? await this.reader.readMetadata(authority, disclosureId, 'import', {
        maxResponseBytes: this.config.maxResponseBytes,
      })
      : undefined
    const checkpointHash = brandString<DisclosureHash>(input.action === 'readiness'
      ? latest?.checkpoint.checkpointHash ?? input.currentCheckpointHash : input.checkpointHash)
    return this.reader.withAuthorizedPrefix(authority, disclosureId, this.config.sourceInstanceId, 'import',
      checkpointHash, this.config.maxResponseBytes, { authority: receiveAuthority,
        instanceId: this.config.targetInstanceId, maxResponseBytes: this.config.maxResponseBytes },
      (snapshot): Promise<unknown> => {
        if (snapshot === null) throw new EndpointFailure(404, 'not-found')
        const { metadata, prefix } = snapshot
        const valid = metadata.organizationId === this.config.organizationId
          && metadata.disclosureId === disclosureId && metadata.instanceId === this.config.sourceInstanceId
          && metadata.checkpoint.checkpointHash === checkpointHash
          && metadata.authorizedActions.includes('import')
          && prefix.authorizationVersion === metadata.authorizationVersion
          && prefix.checkpoint.organizationId === this.config.organizationId
          && prefix.checkpoint.disclosureId === disclosureId
          && prefix.checkpoint.instanceId === this.config.sourceInstanceId
          && prefix.checkpoint.checkpointHash === checkpointHash
        if (!valid) throw new EndpointFailure(409, 'conflict')
        if (metadata.authorizationVersion < input.currentAuthorizationVersion) {
          throw new EndpointFailure(409, 'conflict')
        }
        if (input.action === 'readiness') {
          if (latest === undefined || latest.checkpoint.checkpointHash !== checkpointHash
            || latest.authorizationVersion !== metadata.authorizationVersion) throw new EndpointFailure(409, 'conflict')
          return Promise.resolve(checkpointHash === input.currentCheckpointHash ? { status: 'current' } : {
            status: 'available', candidate: {
              checkpointHash: metadata.checkpoint.checkpointHash,
              policyVersion: metadata.checkpoint.policyVersion,
              sourceCursor: metadata.checkpoint.sourceCursor,
              eventCount: metadata.checkpoint.eventCount,
            },
          })
        }
        return Promise.resolve({ prefix: structuredClone(prefix), source: {
          instanceName: String(this.config.sourceInstanceId),
          conversationTitle: String(prefix.conversationId),
        } })
      })
  }

  private async authenticate(request: IncomingMessage, body: Buffer, signal: AbortSignal): Promise<void> {
    const timestampText = requiredHeader(request, 'x-dsh-a2a-timestamp')
    const nonceText = requiredHeader(request, 'x-dsh-a2a-nonce')
    const signatureText = requiredHeader(request, 'x-dsh-a2a-signature')
    if (!/^(0|[1-9]\d{0,15})$/u.test(timestampText) || !BASE64URL.test(nonceText)
      || !BASE64URL.test(signatureText)) throw new EndpointFailure(401, 'unauthenticated')
    const timestamp = Number(timestampText)
    const nonce = Buffer.from(nonceText, 'base64url')
    const signature = Buffer.from(signatureText, 'base64url')
    if (!Number.isSafeInteger(timestamp) || nonce.byteLength < 16 || nonce.byteLength > 64
      || nonce.toString('base64url') !== nonceText || signature.byteLength !== 32
      || signature.toString('base64url') !== signatureText) throw new EndpointFailure(401, 'unauthenticated')
    const now = Date.now()
    if (Math.abs(now - timestamp) > this.config.clockSkewMs) throw new EndpointFailure(401, 'unauthenticated')
    signal.throwIfAborted()
    const credential = await this.credentials.resolve(this.secretRef).catch(() => undefined)
    if (credential === undefined || Buffer.byteLength(credential.value, 'utf8') < MIN_SHARED_SECRET_BYTES) {
      throw new EndpointFailure(503, 'not-configured')
    }
    const bodyHash = createHash('sha256').update(body).digest('hex')
    const canonical = `POST\n${A2A_LOOPBACK_DISCLOSURE_REFRESH_PATH}\n${timestampText}\n${nonceText}\n${bodyHash}`
    const key = Buffer.from(credential.value, 'utf8')
    let expected: Buffer
    try { expected = createHmac('sha256', key).update(canonical).digest() } finally { key.fill(0) }
    if (!timingSafeEqual(expected, signature)) throw new EndpointFailure(401, 'unauthenticated')
    for (const [nonceValue, expiresAt] of this.replay) if (expiresAt < now) this.replay.delete(nonceValue)
    if (this.replay.has(nonceText)) throw new EndpointFailure(409, 'replay')
    if (this.replay.size >= this.config.maxReplayEntries) throw new EndpointFailure(503, 'unavailable')
    this.replay.set(nonceText, timestamp + this.config.clockSkewMs + 1)
  }
}
