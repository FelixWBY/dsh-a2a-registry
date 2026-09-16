/** Signed test-only loopback route for creating one Registry disclosure registration. */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'
import { credentialRef, type CredentialProvider, type CredentialRef } from '@deepseek-ai/dsh-credentials'
import type { InstanceKeyHistory, InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DisclosureCryptoLimits, DisclosureDataKeyId } from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import type { DisclosureConversationId, DisclosureId, DshInstanceId,
  OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId, TeamId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { RegistryIngestError, type FreshProducerAuthority,
  type RegistryDisclosureRegistration, type RegistryIngestReceipt,
  type RegistryProducerSyncStatus } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { z as zod } from 'zod'
import type { RegistryDisclosureControl } from './control.ts'
import { escrowRegistryDisclosureDataKey, LocalHarnessDisclosureContentError, requireRegistryDisclosureDataKey,
  readRegistryDisclosureContent, type LocalHarnessDisclosureKeyEscrowInput } from './local-harness-disclosure-content.ts'
import { LocalDisclosureRegistrationStore, LocalDisclosureRegistrationStoreError } from './local-harness-disclosure-registration-store.ts'
import type { RegistryConfirmedPrefix } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryDisclosureContent } from './operations.ts'

export const A2A_LOOPBACK_DISCLOSURES_PATH = '/a2a-loopback/v1/disclosures'
export const A2A_LOOPBACK_DISCLOSURE_KEYS_PATH = '/a2a-loopback/v1/disclosure-keys'
export const A2A_LOOPBACK_DISCLOSURE_STATUS_PATH = '/a2a-loopback/v1/disclosures/status'
export const A2A_LOOPBACK_DISCLOSURE_CONTROL_PATH = '/a2a-loopback/v1/disclosures/control'
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const BASE64URL = /^[A-Za-z0-9_-]+$/u
const MIN_SHARED_SECRET_BYTES = 32
const MAX_SHARED_SECRET_BYTES = 4_096
const CAPABILITIES = Object.freeze(['conversation.read', 'branch.create'] as const)

/** Explicit fixed source identity, credential reference and endpoint bounds. */
export interface LocalHarnessDisclosureRegistrationConfig {
  readonly mode: 'test-only'
  readonly organizationId: OrganizationId
  readonly sourceInstanceId: DshInstanceId
  readonly sourceKeyId: InstanceKeyId
  readonly sourcePublicKeySpki: string
  readonly sourceKeyValidFrom: number
  readonly sharedSecretEnv: string
  readonly clockSkewMs: number
  readonly requestTimeoutMs: number
  readonly maxInputBytes: number
  readonly maxReplayEntries: number
  readonly maxRegistrations: number
  readonly maxEscrowKeys: number
  readonly maxRecordBytes: number
  readonly maxTargets: number
  readonly maxLifetimeMs: number
  readonly maxContentEvents: number
  readonly crypto: DisclosureCryptoLimits
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const timer = () => z.natural().min(1).max(2_147_483_647).required()
const identifier = <T extends Branded<string>>() => z.transform(z.string().pattern(IDENTIFIER).required(),
  value => brandString<T>(value)).required()

/** Loader schema; absence leaves the route unmounted and mode cannot be inferred. */
export const LocalHarnessDisclosureRegistrationConfigSchema: z<LocalHarnessDisclosureRegistrationConfig> = z.object({
  mode: z.const('test-only').required(),
  organizationId: identifier<OrganizationId>(),
  sourceInstanceId: identifier<DshInstanceId>(),
  sourceKeyId: identifier<InstanceKeyId>(),
  sourcePublicKeySpki: z.string().required(),
  sourceKeyValidFrom: z.natural().max(Number.MAX_SAFE_INTEGER).required(),
  sharedSecretEnv: z.string().role('credential-ref').required(),
  clockSkewMs: timer(), requestTimeoutMs: timer(), maxInputBytes: positive(),
  maxReplayEntries: positive(), maxRegistrations: positive(), maxEscrowKeys: positive(), maxRecordBytes: positive(),
  maxTargets: positive(), maxLifetimeMs: positive(), maxContentEvents: positive(),
  crypto: z.object({ maxPlaintextBytes: positive(), maxCiphertextBytes: positive(),
    maxTrustedKeys: positive() }).required(),
})

type FailureCode = 'invalid-input' | 'method-not-allowed' | 'not-configured'
  | 'not-found' | 'replay' | 'unauthenticated' | 'unavailable' | 'conflict'
  | 'version-conflict' | 'limit'

class EndpointFailure extends Error {
  constructor(readonly status: number, readonly code: FailureCode, readonly allow?: string) {
    super(code)
    this.name = 'A2aDisclosureRegistrationEndpointFailure'
  }
}

const targetSchema = zod.discriminatedUnion('kind', [
  zod.strictObject({ kind: zod.literal('member'), memberId: zod.string().regex(IDENTIFIER) }),
  zod.strictObject({ kind: zod.literal('team'), teamId: zod.string().regex(IDENTIFIER) }),
])
const requestSchema = zod.strictObject({
  version: zod.literal(1),
  disclosureId: zod.string().regex(IDENTIFIER),
  conversationId: zod.string().regex(IDENTIFIER),
  keyId: zod.string().regex(IDENTIFIER),
  policyVersion: zod.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  targets: zod.array(targetSchema).min(1),
  expiresAt: zod.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
})
type RegistrationRequest = zod.infer<typeof requestSchema>

const wrappedKeySchema = zod.strictObject({
  version: zod.literal(1),
  nonce: zod.string().regex(BASE64URL).max(64),
  ciphertext: zod.string().regex(BASE64URL).max(128),
  tag: zod.string().regex(BASE64URL).max(64),
})
const keyEscrowRequestSchema = zod.strictObject({
  version: zod.literal(1),
  organizationId: zod.string().regex(IDENTIFIER),
  sourceInstanceId: zod.string().regex(IDENTIFIER),
  conversationId: zod.string().regex(IDENTIFIER),
  disclosureId: zod.string().regex(IDENTIFIER),
  keyId: zod.string().regex(IDENTIFIER),
  wrappedKey: wrappedKeySchema,
})

const statusRequestSchema = zod.strictObject({
  version: zod.literal(1),
  disclosureId: zod.string().regex(IDENTIFIER),
})
const expectedAuthorizationVersion = zod.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const controlRequestSchema = zod.discriminatedUnion('action', [
  zod.strictObject({ version: zod.literal(1), action: zod.literal('pause'),
    disclosureId: zod.string().regex(IDENTIFIER), expectedAuthorizationVersion }),
  zod.strictObject({ version: zod.literal(1), action: zod.literal('resume'),
    disclosureId: zod.string().regex(IDENTIFIER), expectedAuthorizationVersion }),
  zod.strictObject({ version: zod.literal(1), action: zod.literal('revoke'),
    disclosureId: zod.string().regex(IDENTIFIER), expectedAuthorizationVersion }),
  zod.strictObject({ version: zod.literal(1), action: zod.literal('update-access'),
    disclosureId: zod.string().regex(IDENTIFIER), expectedAuthorizationVersion,
    targets: zod.array(targetSchema).min(1),
    expiresAt: zod.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER) }),
])
type ControlRequest = zod.infer<typeof controlRequestSchema>

interface ControlObservation {
  readonly disclosureId: DisclosureId
  readonly authorizationVersion: number
  readonly control: 'active' | 'paused' | 'revoked'
  readonly expiresAt: number
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
    throw new EndpointFailure(400, 'limit')
  }
  const chunks: Buffer[] = []
  let size = 0
  const stop = (): void => { request.destroy() }
  signal.addEventListener('abort', stop, { once: true })
  try {
    for await (const raw of request) {
      const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as string)
      size += chunk.byteLength
      if (size > maximum) throw new EndpointFailure(400, 'limit')
      chunks.push(chunk)
    }
  } catch (error) {
    if (error instanceof EndpointFailure) throw error
    throw new EndpointFailure(signal.aborted ? 503 : 400, signal.aborted ? 'unavailable' : 'invalid-input')
  } finally { signal.removeEventListener('abort', stop) }
  if (!request.complete || signal.aborted) throw new EndpointFailure(503, 'unavailable')
  return Buffer.concat(chunks, size)
}

function writeJson(response: ServerResponse, status: number, value: unknown, allow?: string): void {
  const body = JSON.stringify(value)
  response.writeHead(status, { 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body, 'utf8')), 'x-content-type-options': 'nosniff',
    ...(allow === undefined ? {} : { allow }) })
  response.end(body)
}

function mapEndpointFailure(error: unknown): EndpointFailure {
  if (error instanceof EndpointFailure) return error
  if (error instanceof LocalDisclosureRegistrationStoreError) {
    if (error.code === 'replay') return new EndpointFailure(409, 'replay')
    if (error.code === 'conflict') return new EndpointFailure(409, 'conflict')
    if (error.code === 'limit') return new EndpointFailure(400, 'limit')
    return new EndpointFailure(503, 'unavailable')
  }
  if (error instanceof LocalHarnessDisclosureContentError) {
    if (error.code === 'conflict') return new EndpointFailure(409, 'conflict')
    if (error.code === 'limit') return new EndpointFailure(400, 'limit')
    return new EndpointFailure(503, 'unavailable')
  }
  if (error instanceof RegistryIngestError) {
    if (error.code === 'not-found') return new EndpointFailure(404, 'not-found')
    if (error.code === 'conflict') return new EndpointFailure(409, 'conflict')
    if (error.code === 'version-conflict') return new EndpointFailure(409, 'version-conflict')
    if (error.code === 'limit') return new EndpointFailure(400, 'limit')
    if (error.code === 'invalid-input' || error.code === 'invalid-transition') {
      return new EndpointFailure(400, 'invalid-input')
    }
  }
  return new EndpointFailure(503, 'unavailable')
}

function targetKey(target: RegistrationRequest['targets'][number]): string {
  return target.kind === 'member' ? `member\0${target.memberId}` : `team\0${target.teamId}`
}

function canonicalRequest(input: RegistrationRequest): string {
  return JSON.stringify({ version: input.version, disclosureId: input.disclosureId,
    conversationId: input.conversationId, keyId: input.keyId, policyVersion: input.policyVersion,
    targets: input.targets, expiresAt: input.expiresAt })
}

function pristine(receipt: RegistryIngestReceipt): boolean {
  return receipt.authorizationVersion === 0 && receipt.lastDisclosureSeq === -1
    && receipt.lastEventHash === null && receipt.checkpointHash === null
    && receipt.control === 'active' && receipt.ingest === 'pending'
}

function controlObservation(status: RegistryProducerSyncStatus): ControlObservation {
  return status.kind === 'deleted'
    ? { disclosureId: status.disclosureId, authorizationVersion: status.authorizationVersion,
      control: 'revoked', expiresAt: 0 }
    : { disclosureId: status.receipt.disclosureId,
      authorizationVersion: status.receipt.authorizationVersion,
      control: status.receipt.control === 'active' || status.receipt.control === 'paused'
        ? status.receipt.control : 'revoked',
      expiresAt: status.expiresAt }
}

function assertTestOnlyMode(value: unknown): void {
  if (value !== 'test-only') throw new Error('Registry disclosure registration requires explicit test-only mode')
}

/** One route owner. It contains no account or production authentication path. */
export class LocalHarnessDisclosureRegistration {
  private readonly requests = new Set<AbortController>()
  private readonly tasks = new Set<Promise<void>>()
  private readonly unregisters: (() => void)[] = []
  private keyTail = Promise.resolve()

  private constructor(private readonly control: RegistryDisclosureControl,
    private readonly credentials: CredentialProvider, private readonly secretRef: CredentialRef,
    private readonly store: LocalDisclosureRegistrationStore,
    private readonly config: LocalHarnessDisclosureRegistrationConfig,
    private readonly lifetime: AbortController) {}

  /** Validate all explicit test-only dependencies, open the ledger, then claim the exact route. */
  static async open(ctx: Context,
    config: LocalHarnessDisclosureRegistrationConfig): Promise<LocalHarnessDisclosureRegistration> {
    assertTestOnlyMode(config.mode)
    const webServer = ctx.get('webServer')
    const control = ctx.get('registryDisclosureControl')
    const credentials = ctx.get('credentials')
    const facility = ctx.get('storageDomain')
    if (webServer === undefined || webServer.host !== '127.0.0.1') {
      throw new Error('Registry disclosure registration requires a 127.0.0.1 WebServer')
    }
    if (control === undefined || credentials === undefined || facility === undefined) {
      throw new Error('Registry disclosure registration requires Registry control, storage and credentials')
    }
    const secretRef = credentialRef(config.sharedSecretEnv)
    const secret = await credentials.resolve(secretRef)
    const secretBytes = secret === undefined ? 0 : Buffer.byteLength(secret.value, 'utf8')
    if (secret === undefined || secretBytes < MIN_SHARED_SECRET_BYTES || secretBytes > MAX_SHARED_SECRET_BYTES) {
      throw new Error('Registry disclosure registration shared secret is unavailable')
    }
    const store = await LocalDisclosureRegistrationStore.open(facility, config)
    const owner = new LocalHarnessDisclosureRegistration(control, credentials, secretRef, store,
      structuredClone(config), new AbortController())
    try {
      for (const path of [A2A_LOOPBACK_DISCLOSURE_KEYS_PATH, A2A_LOOPBACK_DISCLOSURES_PATH,
        A2A_LOOPBACK_DISCLOSURE_STATUS_PATH,
        A2A_LOOPBACK_DISCLOSURE_CONTROL_PATH]) {
        owner.unregisters.push(webServer.register(owner.route(path)))
      }
      return owner
    } catch (error) {
      for (const unregister of owner.unregisters.splice(0).reverse()) unregister()
      await store.close().catch(() => undefined)
      throw error
    }
  }

  /** Release route admission, drain accepted handlers and close the idempotency ledger. */
  async close(): Promise<void> {
    for (const unregister of this.unregisters.splice(0).reverse()) unregister()
    this.lifetime.abort()
    for (const request of this.requests) request.abort()
    await Promise.allSettled(this.tasks)
    await this.keyTail
    await this.store.close()
    this.requests.clear()
  }

  /** Decrypt an already reader-authorized prefix without retaining plaintext. */
  readContent(prefix: RegistryConfirmedPrefix, maxResponseBytes: number,
    signal: AbortSignal): Promise<RegistryDisclosureContent> {
    return readRegistryDisclosureContent(this.credentials, prefix, this.config.crypto,
      this.config.maxContentEvents, maxResponseBytes, signal)
  }

  private route(path: string): WebRoute {
    return { kind: 'exact', path, handler: (request, response) => {
      const task = this.handle(path, request, response)
      this.tasks.add(task)
      void task.then(() => { this.tasks.delete(task) }, () => { this.tasks.delete(task) })
      return task
    } }
  }

  private async handle(path: string, request: IncomingMessage, response: ServerResponse): Promise<void> {
    const requestAbort = new AbortController()
    this.requests.add(requestAbort)
    const disconnect = (): void => { if (!response.writableEnded) requestAbort.abort() }
    request.once('aborted', disconnect)
    response.once('close', disconnect)
    try {
      const signal = AbortSignal.any([this.lifetime.signal, requestAbort.signal,
        AbortSignal.timeout(this.config.requestTimeoutMs)])
      if (!['127.0.0.1', '::ffff:127.0.0.1'].includes(request.socket.remoteAddress ?? '')) {
        throw new EndpointFailure(404, 'not-found')
      }
      const url = new URL(request.url ?? '/', 'http://loopback.invalid')
      if (url.pathname !== path || url.search !== '') {
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
      const sharedSecret = await this.authenticate(path, request, body, signal)
      let parsed: unknown
      try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)) } catch {
        throw new EndpointFailure(400, 'invalid-input')
      }
      if (path === A2A_LOOPBACK_DISCLOSURE_KEYS_PATH) {
        const decoded = keyEscrowRequestSchema.safeParse(parsed)
        if (!decoded.success) throw new EndpointFailure(400, 'invalid-input')
        const input: LocalHarnessDisclosureKeyEscrowInput = {
          version: 1,
          organizationId: brandString<OrganizationId>(decoded.data.organizationId),
          sourceInstanceId: brandString<DshInstanceId>(decoded.data.sourceInstanceId),
          conversationId: brandString<DisclosureConversationId>(decoded.data.conversationId),
          disclosureId: brandString<DisclosureId>(decoded.data.disclosureId),
          keyId: brandString<DisclosureDataKeyId>(decoded.data.keyId),
          wrappedKey: decoded.data.wrappedKey,
        }
        await this.escrow(input, sharedSecret)
        writeJson(response, 200, { ok: true, value: {
          disclosureId: input.disclosureId, keyId: input.keyId,
        } })
      } else if (path === A2A_LOOPBACK_DISCLOSURES_PATH) {
        const decoded = requestSchema.safeParse(parsed)
        if (!decoded.success) throw new EndpointFailure(400, 'invalid-input')
        const input = decoded.data
        this.assertAccessBounds(input.targets, input.expiresAt)
        const value = await this.register(input)
        writeJson(response, 200, { ok: true, value: {
          disclosureId: value.disclosureId, authorizationVersion: value.authorizationVersion,
        } })
      } else if (path === A2A_LOOPBACK_DISCLOSURE_STATUS_PATH) {
        const decoded = statusRequestSchema.safeParse(parsed)
        if (!decoded.success) throw new EndpointFailure(400, 'invalid-input')
        const value = await this.status(brandString<DisclosureId>(decoded.data.disclosureId))
        writeJson(response, 200, { ok: true, value })
      } else {
        const decoded = controlRequestSchema.safeParse(parsed)
        if (!decoded.success) throw new EndpointFailure(400, 'invalid-input')
        if (decoded.data.action === 'update-access') {
          this.assertAccessBounds(decoded.data.targets, decoded.data.expiresAt)
        }
        const value = await this.mutate(decoded.data)
        writeJson(response, 200, { ok: true, value })
      }
    } catch (error) {
      if (!response.headersSent && !response.destroyed) {
        const failure = mapEndpointFailure(error)
        writeJson(response, failure.status, { ok: false, error: { code: failure.code } }, failure.allow)
      }
    } finally {
      request.off('aborted', disconnect)
      response.off('close', disconnect)
      this.requests.delete(requestAbort)
    }
  }

  private assertAccessBounds(targets: RegistrationRequest['targets'], expiresAt: number): void {
    const now = Date.now()
    if (targets.length > this.config.maxTargets || expiresAt <= now
      || expiresAt > now + this.config.maxLifetimeMs
      || new Set(targets.map(targetKey)).size !== targets.length) {
      throw new EndpointFailure(400, 'invalid-input')
    }
  }

  private async authenticate(path: string, request: IncomingMessage, body: Buffer,
    signal: AbortSignal): Promise<string> {
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
    const credential = await this.credentials.resolve(this.secretRef)
    const credentialBytes = credential === undefined ? 0 : Buffer.byteLength(credential.value, 'utf8')
    if (credential === undefined || credentialBytes < MIN_SHARED_SECRET_BYTES
      || credentialBytes > MAX_SHARED_SECRET_BYTES) {
      throw new EndpointFailure(503, 'not-configured')
    }
    const bodyHash = createHash('sha256').update(body).digest('hex')
    const canonical = `POST\n${path}\n${timestampText}\n${nonceText}\n${bodyHash}`
    const key = Buffer.from(credential.value, 'utf8')
    let expected: Buffer
    try { expected = createHmac('sha256', key).update(canonical).digest() } finally { key.fill(0) }
    if (!timingSafeEqual(expected, signature)) throw new EndpointFailure(401, 'unauthenticated')
    await this.store.reserveNonce(nonceText, timestamp + this.config.clockSkewMs + 1, now)
    return credential.value
  }

  private escrow(input: LocalHarnessDisclosureKeyEscrowInput, sharedSecret: string): Promise<void> {
    const operation = this.keyTail.then(async () => {
      if (input.organizationId !== this.config.organizationId
        || input.sourceInstanceId !== this.config.sourceInstanceId) {
        throw new EndpointFailure(404, 'not-found')
      }
      await escrowRegistryDisclosureDataKey(this.credentials, sharedSecret, input,
        this.config.maxEscrowKeys)
    })
    this.keyTail = operation.then(() => {}, () => {})
    return operation
  }

  private authority(): FreshProducerAuthority {
    const history: InstanceKeyHistory = { organizationId: this.config.organizationId,
      instanceId: this.config.sourceInstanceId, status: 'active', keys: [{ keyId: this.config.sourceKeyId,
        publicKeySpki: this.config.sourcePublicKeySpki, validFrom: this.config.sourceKeyValidFrom,
        validUntil: null, revokedAt: null }] }
    return () => ({ connection: { organizationId: this.config.organizationId,
      instanceId: this.config.sourceInstanceId, keyId: this.config.sourceKeyId, now: Date.now() },
    history: structuredClone(history) })
  }

  private registration(input: RegistrationRequest): RegistryDisclosureRegistration {
    const expiresAt = input.expiresAt
    return { conversationId: brandString<DisclosureConversationId>(input.conversationId),
      policyVersion: input.policyVersion, access: {
        organizationId: this.config.organizationId,
        instanceId: this.config.sourceInstanceId,
        disclosureId: brandString<DisclosureId>(input.disclosureId),
        control: 'active', producer: 'idle', ingest: 'pending', expiresAt,
        authorizationVersion: 0, capabilities: [...CAPABILITIES], checkpointHash: null,
        grants: input.targets.map(target => ({
          target: target.kind === 'member'
            ? { kind: 'member' as const, memberId: brandString<MemberId>(target.memberId) }
            : { kind: 'team' as const, teamId: brandString<TeamId>(target.teamId) },
          state: 'active' as const, capabilities: [...CAPABILITIES], expiresAt,
        })),
      } }
  }

  private register(input: RegistrationRequest): Promise<RegistryIngestReceipt> {
    const disclosureId = brandString<DisclosureId>(input.disclosureId)
    const requestHash = `sha256:${createHash('sha256').update(canonicalRequest(input), 'utf8').digest('hex')}` as const
    const authority = this.authority()
    return this.store.register(disclosureId, requestHash, async () => {
      await requireRegistryDisclosureDataKey(this.credentials, {
        organizationId: this.config.organizationId,
        instanceId: this.config.sourceInstanceId,
        conversationId: brandString<DisclosureConversationId>(input.conversationId),
        disclosureId,
      }, brandString<DisclosureDataKeyId>(input.keyId))
      const receipt = await this.control.register(authority, this.registration(input))
      if (receipt.disclosureId !== disclosureId || !pristine(receipt)) {
        throw new EndpointFailure(503, 'unavailable')
      }
      return receipt
    })
  }

  private async status(disclosureId: DisclosureId): Promise<ControlObservation> {
    return controlObservation(await this.control.getSyncStatus(this.authority(), disclosureId))
  }

  private async mutate(input: ControlRequest): Promise<ControlObservation> {
    const disclosureId = brandString<DisclosureId>(input.disclosureId)
    const authority = this.authority()
    const expectedVersion = input.expectedAuthorizationVersion
    const receipt = input.action === 'update-access'
      ? await this.control.updateAccess(authority, disclosureId, { expiresAt: input.expiresAt,
        capabilities: [...CAPABILITIES], grants: input.targets.map(target => ({
          target: target.kind === 'member'
            ? { kind: 'member' as const, memberId: brandString<MemberId>(target.memberId) }
            : { kind: 'team' as const, teamId: brandString<TeamId>(target.teamId) },
          state: 'active' as const, capabilities: [...CAPABILITIES], expiresAt: input.expiresAt,
        })) }, expectedVersion)
      : await this.control.transitionControl(authority, disclosureId,
        input.action === 'pause' ? 'paused' : input.action === 'resume' ? 'active' : 'revoked', expectedVersion)
    if (receipt.disclosureId !== disclosureId) throw new EndpointFailure(503, 'unavailable')
    const value = await this.status(disclosureId)
    if (value.authorizationVersion !== receipt.authorizationVersion) throw new EndpointFailure(503, 'unavailable')
    return value
  }
}
