/** Test-only Registry mailbox owner and authenticated loopback delivery endpoint. */
import { AsyncLocalStorage } from 'node:async_hooks'
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { setTimeout as delay } from 'node:timers/promises'
import type { Context } from '@deepseek-ai/cordis'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'
import { credentialRef, type CredentialProvider, type CredentialRef } from '@deepseek-ai/dsh-credentials'
import type { InstanceKeyHistory, InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import type { RegistryConnectionAuthority } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import { isMailboxExecutionLeaseExpired, MailboxError, openA2aMailbox, type A2aMailbox, type MailboxAuthorizationLease,
  type MailboxBinding, type MailboxLimits, type MailboxOperation, type MailboxReceipt,
  type MailboxTextCodec, type MailboxTransition, type WithMailboxAuthorization } from '@deepseek-ai/dsh-a2a-mailbox'
import type { DisclosureHash, DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { A2aRequestId, DisclosureAccess, DisclosureSubject, MemberId,
  VerifiedDisclosureCheckpoint } from '@deepseek-ai/dsh-a2a-registry-domain'
import { RegistryIngestError, type FreshRegistryMetadataAuthority,
  type RegistryConfirmedPrefix } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryQuestionDelivery } from '@deepseek-ai/dsh-a2a-registry-sync'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import z from '@deepseek-ai/schemastery'
import { z as zod } from 'zod'
import type { RegistryDisclosureOperationSelection, RegistryDisclosureQuestionInput,
  RegistryDisclosureQuestionListOptions, RegistryDisclosureQuestionListScope,
  RegistryDisclosureQuestionMetadata, RegistryDisclosureQuestionPage,
  RegistryDisclosureQuestionResult } from './operations.ts'
import type { RegistryAuthorizedPrefixSnapshot, RegistryDisclosureReader } from './reader.ts'
import type { RegistryQuestionBroker } from './question-broker.ts'
import { LocalQuestionReplayError, LocalQuestionReplayStore } from './local-harness-question-replay.ts'

export const A2A_LOOPBACK_QUESTIONS_PATH = '/a2a-loopback/v1/questions'
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const BASE64URL = /^[A-Za-z0-9_-]+$/u
const MIN_SHARED_SECRET_BYTES = 32

/** Explicit local-MVP identity, authenticated delivery secret, mailbox key and hard limits. */
export interface LocalHarnessQuestionOperationsConfig {
  readonly mode: 'test-only'
  readonly sourceInstanceId: DshInstanceId
  readonly organizationId: OrganizationId
  readonly memberId: MemberId
  readonly sourceKeyId: InstanceKeyId
  readonly sourcePublicKeySpki: string
  readonly sourceKeyValidFrom: number
  /** Independent credential used only for the question endpoint. */
  readonly sharedSecretEnv: string
  /** Registry-only base64url 32-byte AES-256-GCM key. */
  readonly mailboxKeyEnv: string
  readonly clockSkewMs: number
  readonly maxInputBytes: number
  readonly maxAuthorizationResponseBytes: number
  readonly requestTimeoutMs: number
  readonly maxReplayEntries: number
  readonly executionLeaseMs: number
  readonly limits: MailboxLimits
  /** Explicit Registry-owned sweep; absent means no background mailbox cleanup. */
  readonly expiryMaintenance?: {
    readonly intervalMs: number
    readonly maxItems: number
  }
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const timer = () => z.natural().min(1).max(2_147_483_647).required()
const identifier = <T extends Branded<string>>() => z.transform(z.string().pattern(IDENTIFIER).required(),
  value => brandString<T>(value)).required()

/** Loader schema; this provider cannot be enabled without the explicit test-only marker. */
export const LocalHarnessQuestionOperationsConfigSchema: z<LocalHarnessQuestionOperationsConfig> = z.object({
  mode: z.const('test-only').required(),
  sourceInstanceId: identifier<DshInstanceId>(),
  organizationId: identifier<OrganizationId>(),
  memberId: identifier<MemberId>(),
  sourceKeyId: identifier<InstanceKeyId>(),
  sourcePublicKeySpki: z.string().required(),
  sourceKeyValidFrom: z.natural().max(Number.MAX_SAFE_INTEGER).required(),
  sharedSecretEnv: z.string().role('credential-ref').required(),
  mailboxKeyEnv: z.string().role('credential-ref').required(),
  clockSkewMs: timer(), maxInputBytes: positive(), maxAuthorizationResponseBytes: positive(),
  requestTimeoutMs: timer(), maxReplayEntries: positive(), executionLeaseMs: timer(),
  limits: z.object({
    maxTextBytes: positive(), maxTextCharacters: positive(), maxCiphertextBytes: positive(),
    maxAggregateBytes: positive(), maxRequests: positive(), maxRetainedRequests: positive(), maxPendingOperations: positive(),
    maxLifetimeMs: positive(),
  }).required(),
  expiryMaintenance: z.union([z.object({ intervalMs: timer(), maxItems: positive() }).required()]),
})

type CallScope = {
  readonly actor: 'requester' | 'source'
  readonly signal: AbortSignal
  readonly sourceAuthority?: RegistryConnectionAuthority
  prefix?: RegistryConfirmedPrefix
}

type FailureCode = 'invalid-input' | 'method-not-allowed' | 'not-configured'
  | 'not-found' | 'replay' | 'unauthenticated' | 'unavailable' | 'conflict' | 'limit'

class EndpointFailure extends Error {
  constructor(readonly status: number, readonly code: FailureCode, readonly allow?: string) {
    super(code)
    this.name = 'A2aQuestionEndpointFailure'
  }
}

const bindingSchema = zod.strictObject({
  requestId: zod.string().regex(IDENTIFIER),
  organizationId: zod.string().regex(IDENTIFIER),
  disclosureId: zod.string().regex(IDENTIFIER),
  requesterId: zod.string().regex(IDENTIFIER),
  checkpointHash: zod.string().min(1),
  authorizationVersion: zod.number().int().nonnegative(),
  expiresAt: zod.number().int().nonnegative(),
  instanceId: zod.string().regex(IDENTIFIER),
})
const transitionSchema = zod.discriminatedUnion('state', [
  zod.strictObject({ state: zod.literal('completed'), reply: zod.string() }),
  zod.strictObject({ state: zod.literal('failed') }),
])
const dispatchSchema = zod.strictObject({ version: zod.literal(1), action: zod.literal('dispatch'),
  sourceInstanceId: zod.string().regex(IDENTIFIER),
  excludeRequestIds: zod.array(zod.string().regex(IDENTIFIER)).optional() })
const startSchema = zod.strictObject({ version: zod.literal(1), action: zod.literal('start'),
  sourceInstanceId: zod.string().regex(IDENTIFIER), binding: bindingSchema,
  expectedVersion: zod.number().int().positive() })
const renewSchema = zod.strictObject({ version: zod.literal(1), action: zod.literal('renew'),
  sourceInstanceId: zod.string().regex(IDENTIFIER), binding: bindingSchema,
  expectedVersion: zod.number().int().positive() })
const statusSchema = zod.strictObject({ version: zod.literal(1), action: zod.literal('status'),
  sourceInstanceId: zod.string().regex(IDENTIFIER), binding: bindingSchema })
const authorizeImportSchema = zod.strictObject({ version: zod.literal(1), action: zod.literal('authorize-import'),
  sourceInstanceId: zod.string().regex(IDENTIFIER), binding: bindingSchema,
  expectedVersion: zod.number().int().positive() })
const transitionRequestSchema = zod.strictObject({ version: zod.literal(1), action: zod.literal('transition'),
  sourceInstanceId: zod.string().regex(IDENTIFIER), binding: bindingSchema,
  expectedVersion: zod.number().int().positive(), transition: transitionSchema })
const requestSchema = zod.discriminatedUnion('action', [
  dispatchSchema, startSchema, renewSchema, statusSchema, authorizeImportSchema, transitionRequestSchema,
])
type QuestionEndpointRequest = zod.infer<typeof requestSchema>
type OrdinaryQuestionEndpointRequest = Exclude<QuestionEndpointRequest, { readonly action: 'authorize-import' }>

function mailboxBinding(value: zod.infer<typeof bindingSchema>): MailboxBinding {
  return {
    requestId: brandString<A2aRequestId>(value.requestId),
    organizationId: brandString<OrganizationId>(value.organizationId),
    disclosureId: brandString<DisclosureId>(value.disclosureId),
    requesterId: brandString<MemberId>(value.requesterId),
    checkpointHash: brandString<DisclosureHash>(value.checkpointHash),
    authorizationVersion: value.authorizationVersion,
    expiresAt: value.expiresAt,
    instanceId: brandString<DshInstanceId>(value.instanceId),
  }
}

function sameBinding(left: MailboxBinding, right: MailboxBinding): boolean {
  return left.requestId === right.requestId && left.organizationId === right.organizationId
    && left.disclosureId === right.disclosureId && left.requesterId === right.requesterId
    && left.checkpointHash === right.checkpointHash && left.authorizationVersion === right.authorizationVersion
    && left.expiresAt === right.expiresAt && left.instanceId === right.instanceId
}

function requestId(selection: RegistryDisclosureOperationSelection, idempotencyKey: string): A2aRequestId {
  const digest = createHash('sha256').update([
    selection.subject.organizationId, selection.subject.memberId,
    selection.disclosure.disclosureId, selection.disclosure.instanceId, idempotencyKey,
  ].join('\0')).digest('hex')
  return brandString<A2aRequestId>(`question-${digest}`)
}

function questionResult(receipt: MailboxReceipt, reply?: string): RegistryDisclosureQuestionResult {
  if (receipt.state === 'created') throw new Error('Registry Local Harness mailbox returned an invalid state')
  return { requestId: receipt.binding.requestId, checkpointHash: receipt.binding.checkpointHash, status: receipt.state,
    ...(reply === undefined ? {} : { reply }) }
}

function exactBase64Key(value: string): Buffer {
  if (!BASE64URL.test(value)) throw new Error('Registry Local Harness mailbox key is unavailable')
  const key = Buffer.from(value, 'base64url')
  if (key.byteLength !== 32 || key.toString('base64url') !== value) {
    key.fill(0)
    throw new Error('Registry Local Harness mailbox key is unavailable')
  }
  return key
}

function assertTestOnlyMode(value: unknown): void {
  if (value !== 'test-only') throw new Error('Registry Local Harness questions require explicit test-only mode')
}

function codec(credentials: CredentialProvider, keyRef: CredentialRef): MailboxTextCodec {
  async function key(signal: AbortSignal): Promise<Buffer> {
    signal.throwIfAborted()
    const credential = await credentials.resolve(keyRef)
    signal.throwIfAborted()
    if (credential === undefined) throw new Error('Registry Local Harness mailbox key is unavailable')
    return exactBase64Key(credential.value)
  }
  return {
    async seal(text, aad, signal) {
      const material = await key(signal)
      try {
        const nonce = randomBytes(12)
        const cipher = createCipheriv('aes-256-gcm', material, nonce)
        cipher.setAAD(Buffer.from(aad, 'utf8'))
        const body = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])
        return Buffer.concat([nonce, cipher.getAuthTag(), body]).toString('base64url')
      } finally { material.fill(0) }
    },
    async open(encoded, aad, signal) {
      signal.throwIfAborted()
      if (!BASE64URL.test(encoded)) throw new Error('invalid ciphertext')
      const body = Buffer.from(encoded, 'base64url')
      if (body.byteLength < 28 || body.toString('base64url') !== encoded) throw new Error('invalid ciphertext')
      const material = await key(signal)
      try {
        const decipher = createDecipheriv('aes-256-gcm', material, body.subarray(0, 12))
        decipher.setAAD(Buffer.from(aad, 'utf8'))
        decipher.setAuthTag(body.subarray(12, 28))
        const plaintext = Buffer.concat([decipher.update(body.subarray(28)), decipher.final()])
        return new TextDecoder('utf-8', { fatal: true }).decode(plaintext)
      } finally { material.fill(0) }
    },
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

function writeLeaseFrame(response: ServerResponse, value: unknown, maximum: number): void {
  const body = `${JSON.stringify(value)}\n`
  if (Buffer.byteLength(body, 'utf8') > maximum) throw new EndpointFailure(400, 'limit')
  response.writeHead(200, { 'cache-control': 'no-store', 'content-type': 'application/x-ndjson; charset=utf-8',
    'x-content-type-options': 'nosniff' })
  response.write(body)
}

function mapEndpointFailure(error: unknown): EndpointFailure {
  if (error instanceof EndpointFailure) return error
  if (error instanceof LocalQuestionReplayError) {
    return error.code === 'replay' ? new EndpointFailure(409, 'replay') : new EndpointFailure(503, 'unavailable')
  }
  if (error instanceof MailboxError) {
    if (error.code === 'not-found') return new EndpointFailure(404, 'not-found')
    if (error.code === 'conflict') return new EndpointFailure(409, 'conflict')
    if (error.code === 'limit') return new EndpointFailure(400, 'limit')
    if (error.code === 'invalid-input') return new EndpointFailure(400, 'invalid-input')
  }
  return new EndpointFailure(503, 'unavailable')
}

/** One real encrypted mailbox owner shared by the Registry UI and the local source consumer. */
export class LocalHarnessQuestionOperations implements RegistryQuestionBroker {
  private readonly calls = new AsyncLocalStorage<CallScope>()
  private readonly requests = new Set<AbortController>()
  private readonly tasks = new Set<Promise<void>>()
  private maintenance = Promise.resolve()
  private unregister = (): void => {}

  private constructor(private readonly mailbox: A2aMailbox, private readonly reader: RegistryDisclosureReader,
    private readonly credentials: CredentialProvider, private readonly secretRef: CredentialRef,
    private readonly replay: LocalQuestionReplayStore,
    private readonly config: LocalHarnessQuestionOperationsConfig,
    private readonly lifetime: AbortController) {}

  /** Open the durable owner, then claim the single private route. */
  static async open(ctx: Context, config: LocalHarnessQuestionOperationsConfig): Promise<LocalHarnessQuestionOperations> {
    assertTestOnlyMode(config.mode)
    const webServer = ctx.get('webServer')
    const reader = ctx.get('registryDisclosureReader')
    const credentials = ctx.get('credentials')
    if (webServer === undefined || webServer.host !== '127.0.0.1') {
      throw new Error('Registry Local Harness questions require a 127.0.0.1 WebServer')
    }
    if (reader === undefined || credentials === undefined || ctx.get('storageDomain') === undefined) {
      throw new Error('Registry Local Harness questions require Registry reader, storage and credentials')
    }
    const secretRef = credentialRef(config.sharedSecretEnv)
    const keyRef = credentialRef(config.mailboxKeyEnv)
    const secret = await credentials.resolve(secretRef)
    if (secret === undefined || Buffer.byteLength(secret.value, 'utf8') < MIN_SHARED_SECRET_BYTES) {
      throw new Error('Registry Local Harness question shared secret is unavailable')
    }
    const initialKeyCredential = await credentials.resolve(keyRef)
    if (initialKeyCredential === undefined) throw new Error('Registry Local Harness mailbox key is unavailable')
    const initialKey = exactBase64Key(initialKeyCredential.value)
    initialKey.fill(0)
    const replay = await LocalQuestionReplayStore.open(ctx.storageDomain, config)
    const ownerCell: { current?: LocalHarnessQuestionOperations } = {}
    const lifetime = new AbortController()
    const authorize: WithMailboxAuthorization = (binding, operation, commit, signal) => {
      const current = ownerCell.current
      if (current === undefined) throw new MailboxError('authority-failed')
      return current.authorize(binding, operation, commit, signal)
    }
    let mailbox: A2aMailbox
    try {
      mailbox = await openA2aMailbox(ctx.storageDomain, {
        limits: structuredClone(config.limits), executionLeaseMs: config.executionLeaseMs,
        codec: codec(credentials, keyRef), withAuthorization: authorize,
        signal: lifetime.signal,
      })
    } catch (error) {
      await replay.close().catch(() => undefined)
      throw error
    }
    const owner = new LocalHarnessQuestionOperations(mailbox, reader, credentials, secretRef, replay,
      structuredClone(config), lifetime)
    ownerCell.current = owner
    try {
      const retained = await mailbox.pending()
      if (retained.some(receipt => receipt.binding.organizationId !== config.organizationId
        || receipt.binding.requesterId !== config.memberId
        || receipt.binding.instanceId !== config.sourceInstanceId)) {
        throw new Error('Registry Local Harness mailbox identity does not match configuration')
      }
      owner.unregister = webServer.register(owner.route())
      owner.maintenance = owner.runExpiryMaintenance(ctx)
      return owner
    } catch (error) {
      await Promise.allSettled([mailbox.close(), replay.close()])
      throw error
    }
  }

  /** Select one current delivery for the authenticated WSS source. */
  async dispatch(source: RegistryConnectionAuthority, excludeRequestIds: readonly string[],
    signal: AbortSignal): Promise<RegistryQuestionDelivery | null> {
    this.assertSource(source)
    if (excludeRequestIds.length > this.config.limits.maxRequests
      || new Set(excludeRequestIds).size !== excludeRequestIds.length
      || excludeRequestIds.some(id => !IDENTIFIER.test(id))) throw new MailboxError('invalid-input')
    return this.dispatchSource(new Set(excludeRequestIds), signal, source)
  }

  /** Acquire one current execution fence for the authenticated WSS source. */
  async start(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    signal: AbortSignal): Promise<{ receipt: MailboxReceipt; started: boolean; renewAfterMs: number }> {
    this.assertSource(source)
    const selected = await this.retainedBinding(binding)
    return (await this.sourceCall(signal,
      () => this.mailbox.startExecution(selected, expectedVersion), source)).value
  }

  /** Renew one current execution fence for the authenticated WSS source. */
  async renew(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    signal: AbortSignal): Promise<{ receipt: MailboxReceipt; renewAfterMs: number }> {
    this.assertSource(source)
    const selected = await this.retainedBinding(binding)
    return (await this.sourceCall(signal,
      () => this.mailbox.renewExecution(selected, expectedVersion), source)).value
  }

  /** Read current source-authorized request metadata. */
  async status(source: RegistryConnectionAuthority, binding: MailboxBinding,
    signal: AbortSignal): Promise<MailboxReceipt> {
    this.assertSource(source)
    const selected = await this.retainedBinding(binding)
    return (await this.sourceCall(signal, () => this.mailbox.status(selected), source)).value
  }

  /** Commit one source-owned terminal result through the current version fence. */
  async transition(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    transition: MailboxTransition, signal: AbortSignal): Promise<MailboxReceipt> {
    this.assertSource(source)
    if (transition.state !== 'completed' && transition.state !== 'failed') throw new MailboxError('invalid-input')
    if (transition.state === 'completed'
      && (Buffer.byteLength(transition.reply, 'utf8') > this.config.limits.maxTextBytes
        || Array.from(transition.reply).length > this.config.limits.maxTextCharacters)) throw new MailboxError('limit')
    const selected = await this.retainedBinding(binding)
    return (await this.sourceCall(signal,
      () => this.mailbox.transition(selected, expectedVersion, transition), source)).value
  }

  /** Hold current Registry and device authority while the WSS receiver persists one fixed prefix. */
  async withAuthorization(source: RegistryConnectionAuthority, binding: MailboxBinding, expectedVersion: number,
    receive: (delivery: RegistryQuestionDelivery, signal: AbortSignal) => Promise<void>,
    signal: AbortSignal): Promise<void> {
    this.assertSource(source)
    await this.withSourceImportAuthorization(binding, expectedVersion, signal,
      delivery => receive(delivery, signal), source)
  }

  /** Persist one immutable, checkpoint-pinned question. */
  async askDisclosure(selection: RegistryDisclosureOperationSelection, input: RegistryDisclosureQuestionInput,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult> {
    this.assertSelection(selection)
    signal.throwIfAborted()
    const id = requestId(selection, input.idempotencyKey)
    const existing = (await this.mailbox.pending()).find(receipt => receipt.binding.requestId === id)
    let binding: MailboxBinding
    if (existing === undefined) {
      const now = Date.now()
      binding = { requestId: id, organizationId: selection.subject.organizationId,
        disclosureId: selection.disclosure.disclosureId, requesterId: selection.subject.memberId,
        checkpointHash: selection.disclosure.checkpoint.checkpointHash,
        authorizationVersion: selection.disclosure.authorizationVersion,
        expiresAt: Math.min(selection.disclosure.expiresAt, now + this.config.limits.maxLifetimeMs),
        instanceId: selection.disclosure.instanceId }
    } else {
      binding = existing.binding
      if (!this.ownedBySelection(binding, selection)) throw new RegistryIngestError('not-found')
    }
    return this.browserCall(signal, async () => questionResult(await this.mailbox.enqueue(binding, input.question)))
  }

  /** List only current-account, freshly authorized request metadata; raw mailbox receipts never leave this owner. */
  async listQuestions(scope: RegistryDisclosureQuestionListScope, options: RegistryDisclosureQuestionListOptions,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionPage> {
    signal.throwIfAborted()
    if (!scope.subject.authenticated || scope.subject.membership !== 'active'
      || scope.subject.organizationId !== this.config.organizationId
      || scope.subject.memberId !== this.config.memberId) {
      throw new RegistryIngestError('not-found')
    }
    if (!Number.isSafeInteger(options.pageSize) || options.pageSize < 1
      || options.pageSize > this.config.limits.maxRetainedRequests
      || options.cursor !== undefined && !IDENTIFIER.test(options.cursor)) {
      throw new RegistryIngestError('invalid-input')
    }
    const retained = await this.mailbox.pending()
    const candidates = retained
      .filter(receipt => receipt.binding.organizationId === scope.subject.organizationId
        && receipt.binding.requesterId === scope.subject.memberId)
      .sort((left, right) => String(left.binding.requestId).localeCompare(String(right.binding.requestId)))
    let start = 0
    if (options.cursor !== undefined) {
      const index = candidates.findIndex(receipt => receipt.binding.requestId === options.cursor)
      if (index < 0) throw new RegistryIngestError('invalid-input')
      start = index + 1
    }
    const authorized: RegistryDisclosureQuestionMetadata[] = []
    for (let index = start; index < candidates.length && authorized.length <= options.pageSize; index += 1) {
      signal.throwIfAborted()
      const candidate = candidates[index]
      if (candidate === undefined) continue
      try {
        const selection = await scope.selectDisclosure(candidate.binding.disclosureId,
          candidate.binding.instanceId, signal)
        this.assertSelection(selection)
        if (!this.ownedBySelection(candidate.binding, selection)) throw new RegistryIngestError('not-found')
        const receipt = await this.browserCall(signal, () => this.mailbox.status(candidate.binding))
        if (receipt.state === 'created') throw new Error('Registry Local Harness mailbox returned an invalid state')
        authorized.push({
          requestId: receipt.binding.requestId,
          disclosureId: receipt.binding.disclosureId,
          sourceInstanceId: receipt.binding.instanceId,
          checkpointHash: receipt.binding.checkpointHash,
          status: receipt.state,
          expiresAt: receipt.binding.expiresAt,
          updatedAt: receipt.updatedAt,
        })
      } catch (error) {
        if (error instanceof RegistryIngestError && error.code === 'not-found') continue
        throw error
      }
    }
    const hasMore = authorized.length > options.pageSize
    const items = hasMore ? authorized.slice(0, options.pageSize) : authorized
    return { items, nextCursor: hasMore ? items.at(-1)?.requestId ?? null : null }
  }

  /** Read metadata, and only decrypt a completed reply, under a fresh ask authorization. */
  async readQuestion(selection: RegistryDisclosureOperationSelection, id: A2aRequestId,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult> {
    this.assertSelection(selection)
    const binding = await this.bindingFor(selection, id)
    return this.browserCall(signal, async () => {
      const receipt = await this.mailbox.status(binding)
      if (receipt.state !== 'completed') return questionResult(receipt)
      const reply = await this.mailbox.reply(binding)
      return questionResult(reply.receipt, reply.text ?? undefined)
    })
  }

  /** Cancel queued work; already claimed or terminal work is returned unchanged. */
  async cancelQuestion(selection: RegistryDisclosureOperationSelection, id: A2aRequestId,
    signal: AbortSignal): Promise<RegistryDisclosureQuestionResult> {
    this.assertSelection(selection)
    const binding = await this.bindingFor(selection, id)
    return this.browserCall(signal, async () => {
      let receipt = await this.mailbox.status(binding)
      if (receipt.state !== 'queued') return questionResult(receipt)
      try { receipt = await this.mailbox.transition(binding, receipt.version, { state: 'cancelled' }) }
      catch (error) {
        if (!(error instanceof MailboxError) || error.code !== 'conflict') throw error
        receipt = await this.mailbox.status(binding)
      }
      return questionResult(receipt)
    })
  }

  /** Release route admission, drain handlers, then close the real mailbox owner. */
  async close(): Promise<void> {
    this.unregister()
    this.lifetime.abort()
    for (const request of this.requests) request.abort()
    await Promise.allSettled([...this.tasks, this.maintenance])
    const closed = await Promise.allSettled([this.mailbox.close(), this.replay.close()])
    this.requests.clear()
    if (closed.some(outcome => outcome.status === 'rejected')) {
      throw new Error('Registry Local Harness question storage cleanup failed')
    }
  }

  /** Sweep this owner's ciphertext while the source consumer may be offline. */
  private async runExpiryMaintenance(ctx: Context): Promise<void> {
    const maintenance = this.config.expiryMaintenance
    if (maintenance === undefined) return
    while (!this.lifetime.signal.aborted) {
      try {
        await this.mailbox.processExpiryBatch({ organizationId: this.config.organizationId, now: Date.now(),
          maxItems: maintenance.maxItems, signal: this.lifetime.signal })
      } catch (error) {
        if (error instanceof MailboxError && error.code === 'closed') return
        const code = error instanceof MailboxError ? error.code : 'unexpected-failure'
        ctx.logger.error('Registry Local Harness mailbox expiry maintenance stopped: %s', code)
        return
      }
      try { await delay(maintenance.intervalMs, undefined, { signal: this.lifetime.signal }) }
      catch { return }
    }
  }

  private async bindingFor(selection: RegistryDisclosureOperationSelection, id: A2aRequestId): Promise<MailboxBinding> {
    const receipt = (await this.mailbox.pending()).find(candidate => candidate.binding.requestId === id)
    if (receipt === undefined || !this.ownedBySelection(receipt.binding, selection)) throw new RegistryIngestError('not-found')
    return receipt.binding
  }

  private async retainedBinding(binding: MailboxBinding): Promise<MailboxBinding> {
    const retained = (await this.mailbox.pending()).find(receipt => receipt.binding.requestId === binding.requestId)
    if (retained === undefined || !sameBinding(retained.binding, binding)
      || binding.instanceId !== this.config.sourceInstanceId) throw new MailboxError('not-found')
    return retained.binding
  }

  private assertSelection(selection: RegistryDisclosureOperationSelection): void {
    if (selection.subject.organizationId !== this.config.organizationId
      || selection.subject.memberId !== this.config.memberId
      || selection.disclosure.organizationId !== this.config.organizationId
      || selection.disclosure.instanceId !== this.config.sourceInstanceId) throw new RegistryIngestError('not-found')
  }

  private ownedBySelection(binding: MailboxBinding, selection: RegistryDisclosureOperationSelection): boolean {
    return binding.organizationId === selection.subject.organizationId
      && binding.requesterId === selection.subject.memberId
      && binding.disclosureId === selection.disclosure.disclosureId
      && binding.instanceId === selection.disclosure.instanceId
  }

  private async browserCall<T>(signal: AbortSignal, operation: () => Promise<T>): Promise<T> {
    signal.throwIfAborted()
    try { return await this.calls.run({ actor: 'requester', signal }, operation) } catch (error) {
      if (error instanceof MailboxError) {
        if (error.code === 'not-found') throw new RegistryIngestError('not-found')
        if (error.code === 'invalid-input' || error.code === 'conflict' || error.code === 'limit') {
          throw new RegistryIngestError('invalid-input')
        }
      }
      throw error
    }
  }

  private async sourceCall<T>(signal: AbortSignal, operation: () => Promise<T>,
    sourceAuthority?: RegistryConnectionAuthority): Promise<{ value: T; prefix?: RegistryConfirmedPrefix }> {
    const scope: CallScope = { actor: 'source', signal,
      ...(sourceAuthority === undefined ? {} : { sourceAuthority }) }
    const value = await this.calls.run(scope, operation)
    return { value, ...(scope.prefix === undefined ? {} : { prefix: scope.prefix }) }
  }

  private subject(): DisclosureSubject {
    return { organizationId: this.config.organizationId, memberId: this.config.memberId,
      authenticated: true, membership: 'active', role: 'owner', currentTeamIds: [] }
  }

  private history(): InstanceKeyHistory {
    return { organizationId: this.config.organizationId, instanceId: this.config.sourceInstanceId,
      status: 'active', keys: [{ keyId: this.config.sourceKeyId,
        publicKeySpki: this.config.sourcePublicKeySpki, validFrom: this.config.sourceKeyValidFrom,
        validUntil: null, revokedAt: null }] }
  }

  private assertSource(source: RegistryConnectionAuthority): void {
    const connection = source.connection
    const history = source.history
    if (connection.organizationId !== this.config.organizationId
      || connection.instanceId !== this.config.sourceInstanceId
      || history.organizationId !== connection.organizationId || history.instanceId !== connection.instanceId) {
      throw new MailboxError('authority-failed')
    }
  }

  private async authorize(binding: Readonly<MailboxBinding>, _operation: MailboxOperation,
    commit: (lease: MailboxAuthorizationLease) => Promise<void>, ownerSignal: AbortSignal): Promise<void> {
    const scope = this.calls.getStore()
    if (scope === undefined) throw new MailboxError('authority-failed')
    const signal = AbortSignal.any([ownerSignal, this.lifetime.signal, scope.signal])
    signal.throwIfAborted()
    const subject = this.subject()
    const source = scope.sourceAuthority?.history ?? this.history()
    const validIdentity = binding.organizationId === this.config.organizationId
      && binding.requesterId === this.config.memberId && binding.instanceId === this.config.sourceInstanceId
    const useSnapshot = async (snapshot: RegistryAuthorizedPrefixSnapshot | null): Promise<void> => {
      let access: DisclosureAccess | null = null
      let checkpoint: VerifiedDisclosureCheckpoint | null = null
      let prefix: RegistryConfirmedPrefix | undefined
      if (snapshot !== null) {
        const metadata = snapshot.metadata
        prefix = snapshot.prefix
        const valid = metadata.organizationId === binding.organizationId && metadata.instanceId === binding.instanceId
          && metadata.disclosureId === binding.disclosureId
          && metadata.checkpoint.checkpointHash === binding.checkpointHash
          && prefix.authorizationVersion === metadata.authorizationVersion
          && prefix.checkpoint.organizationId === binding.organizationId
          && prefix.checkpoint.instanceId === binding.instanceId
          && prefix.checkpoint.disclosureId === binding.disclosureId
          && prefix.checkpoint.checkpointHash === binding.checkpointHash
          && metadata.authorizedActions.includes('ask')
        if (valid) {
          access = { organizationId: metadata.organizationId, disclosureId: metadata.disclosureId,
            instanceId: metadata.instanceId, control: metadata.control, producer: metadata.producer,
            ingest: metadata.ingest, expiresAt: metadata.expiresAt,
            authorizationVersion: metadata.authorizationVersion,
            capabilities: ['conversation.read', 'branch.create'], checkpointHash: metadata.checkpoint.checkpointHash,
            grants: [{ target: { kind: 'member', memberId: binding.requesterId }, state: 'active',
              capabilities: ['conversation.read', 'branch.create'], expiresAt: metadata.expiresAt }] }
          checkpoint = { authorizationVersion: prefix.authorizationVersion, checkpoint: {
            organizationId: prefix.checkpoint.organizationId, instanceId: prefix.checkpoint.instanceId,
            disclosureId: prefix.checkpoint.disclosureId, checkpointHash: prefix.checkpoint.checkpointHash,
          } }
          scope.prefix = prefix
        }
      }
      let active = true
      const authorizationVersion = access?.authorizationVersion ?? null
      try {
        await commit({ actor: scope.actor === 'source'
          ? { kind: 'source', organizationId: this.config.organizationId, instanceId: this.config.sourceInstanceId }
          : { kind: 'requester', organizationId: this.config.organizationId, memberId: this.config.memberId },
        subject, access, checkpoint, now: Date.now(), sourceOnline: scope.actor === 'source', signal,
        assertCurrent(version) {
          signal.throwIfAborted()
          if (!active || version !== authorizationVersion) throw new MailboxError('authority-failed')
        } })
      } finally { active = false }
    }
    if (!validIdentity) return useSnapshot(null)
    const authority: FreshRegistryMetadataAuthority = () => ({ subject: this.subject(), now: Date.now(),
      historyFor: instanceId => instanceId === source.instanceId ? structuredClone(source) : null })
    const receive = scope.actor === 'source' ? { authority: () => {
      signal.throwIfAborted()
      return { subject: { organizationId: this.config.organizationId, memberId: this.config.memberId,
        authenticated: true }, now: Date.now() }
    }, instanceId: this.config.sourceInstanceId,
    maxResponseBytes: this.config.maxAuthorizationResponseBytes } : undefined
    try {
      await this.reader.withAuthorizedPrefix(authority, binding.disclosureId, binding.instanceId, 'ask',
        binding.checkpointHash, this.config.maxAuthorizationResponseBytes, receive, useSnapshot)
      return
    } catch (error) {
      // A loopback caller can disappear while its fully awaited authorization callback is settling.
      // Treat that owned request lifetime as closed, not as an uncertain late provider callback that
      // would permanently quarantine the durable mailbox until the Registry restarts.
      if (signal.aborted) throw new MailboxError('closed')
      throw error
    }
  }

  private route(): WebRoute {
    return { kind: 'exact', path: A2A_LOOPBACK_QUESTIONS_PATH, handler: (request, response) => {
      const task = this.handle(request, response)
      this.tasks.add(task)
      void task.then(() => { this.tasks.delete(task) }, () => { this.tasks.delete(task) })
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
      if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(request.socket.remoteAddress ?? '')) {
        throw new EndpointFailure(404, 'not-found')
      }
      const url = new URL(request.url ?? '/', 'http://loopback.invalid')
      if (url.pathname !== A2A_LOOPBACK_QUESTIONS_PATH || url.search !== '') throw new EndpointFailure(400, 'invalid-input')
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
      if (decoded.data.sourceInstanceId !== this.config.sourceInstanceId) throw new EndpointFailure(404, 'not-found')
      if (decoded.data.action === 'dispatch' && decoded.data.excludeRequestIds !== undefined) {
        if (decoded.data.excludeRequestIds.length > this.config.limits.maxRequests) {
          throw new EndpointFailure(400, 'limit')
        }
        if (new Set(decoded.data.excludeRequestIds).size !== decoded.data.excludeRequestIds.length) {
          throw new EndpointFailure(400, 'invalid-input')
        }
      }
      if (decoded.data.action === 'authorize-import') {
        await this.authorizeImport(decoded.data, response, signal)
        return
      }
      const value = await this.execute(decoded.data, signal)
      writeJson(response, 200, { ok: true, value })
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

  private async authorizeImport(input: zod.infer<typeof authorizeImportSchema>, response: ServerResponse,
    requestSignal: AbortSignal): Promise<void> {
    const selectedBinding = mailboxBinding(input.binding)
    const released = Promise.withResolvers<void>()
    const onRelease = () => { released.resolve() }
    requestSignal.addEventListener('abort', onRelease, { once: true })
    try {
      await this.withSourceImportAuthorization(selectedBinding, input.expectedVersion, requestSignal, async (delivery) => {
        writeLeaseFrame(response, { delivery }, this.config.maxAuthorizationResponseBytes)
        await released.promise
      })
    } catch (error) {
      if (!response.headersSent && error instanceof MailboxError && error.code === 'authority-failed') {
        throw new EndpointFailure(404, 'not-found')
      }
      throw error
    } finally {
      requestSignal.removeEventListener('abort', onRelease)
      released.resolve()
      if (response.headersSent && !response.writableEnded && !response.destroyed) response.end()
    }
  }

  private async withSourceImportAuthorization(binding: MailboxBinding, expectedVersion: number,
    requestSignal: AbortSignal, receive: (delivery: RegistryQuestionDelivery) => Promise<void>,
    sourceAuthority?: RegistryConnectionAuthority): Promise<void> {
    const selectedBinding = await this.retainedBinding(binding)
    const retained = (await this.mailbox.pending()).find(receipt => receipt.binding.requestId === selectedBinding.requestId)
    if (retained === undefined) throw new MailboxError('not-found')
    const admissible = retained.state === 'delivered' && retained.version === expectedVersion
      || retained.state === 'running' && retained.version === expectedVersion + 1
    if (!admissible) throw new MailboxError('conflict')
    const dispatched = await this.sourceCall(requestSignal,
      () => this.mailbox.dispatch(selectedBinding, retained.version), sourceAuthority)
    if (dispatched.value.question === null) throw new MailboxError('not-found')
    const remaining = selectedBinding.expiresAt - Date.now()
    if (remaining <= 0) throw new MailboxError('not-found')
    const leaseSignal = AbortSignal.any([
      requestSignal,
      AbortSignal.timeout(Math.min(remaining, 2_147_483_647)),
    ])
    const scope: CallScope = { actor: 'source', signal: leaseSignal,
      ...(sourceAuthority === undefined ? {} : { sourceAuthority }) }
    await this.calls.run(scope, () => this.authorize(selectedBinding, 'dispatch', async (authorization) => {
      const freshPrefix = scope.prefix
      if (authorization.now >= selectedBinding.expiresAt || freshPrefix === undefined
        || freshPrefix.authorizationVersion < selectedBinding.authorizationVersion) {
        throw new MailboxError('authority-failed')
      }
      authorization.assertCurrent(freshPrefix.authorizationVersion)
      await receive({ binding: selectedBinding,
        receipt: { ...dispatched.value.receipt, authorizationVersion: freshPrefix.authorizationVersion },
        question: dispatched.value.question as string, prefix: freshPrefix,
        source: { instanceName: selectedBinding.instanceId,
          conversationTitle: String(freshPrefix.conversationId) } })
      authorization.signal.throwIfAborted()
      authorization.assertCurrent(freshPrefix.authorizationVersion)
    }, leaseSignal))
  }

  private async dispatchSource(excluded: ReadonlySet<string>, signal: AbortSignal,
    sourceAuthority?: RegistryConnectionAuthority): Promise<RegistryQuestionDelivery | null> {
    await this.mailbox.processExpiryBatch({ organizationId: this.config.organizationId, now: Date.now(),
      maxItems: Math.min(this.config.limits.maxRequests, 10), signal })
    const now = Date.now()
    const candidates = (await this.mailbox.pending()).filter(receipt => receipt.binding.instanceId === this.config.sourceInstanceId
      && (receipt.state === 'queued' || receipt.state === 'delivered'
        || isMailboxExecutionLeaseExpired(receipt, now, this.config.executionLeaseMs))
      && !excluded.has(receipt.binding.requestId))
      .sort((left, right) => this.dispatchRank(left, now) - this.dispatchRank(right, now)
        || left.updatedAt - right.updatedAt || left.binding.requestId.localeCompare(right.binding.requestId))
    for (const candidate of candidates) {
      try {
        const dispatched = await this.sourceCall(signal,
          () => this.mailbox.dispatch(candidate.binding, candidate.version), sourceAuthority)
        if (dispatched.value.question === null || dispatched.prefix === undefined) continue
        return { binding: candidate.binding, receipt: dispatched.value.receipt,
          question: dispatched.value.question, prefix: dispatched.prefix,
          source: { instanceName: candidate.binding.instanceId,
            conversationTitle: String(dispatched.prefix.conversationId) } }
      } catch (error) {
        if (error instanceof MailboxError && (error.code === 'not-found' || error.code === 'conflict')) continue
        throw error
      }
    }
    return null
  }

  private async execute(input: OrdinaryQuestionEndpointRequest, signal: AbortSignal): Promise<unknown> {
    if (input.action === 'dispatch') {
      return { delivery: await this.dispatchSource(new Set(input.excludeRequestIds ?? []), signal) }
    }
    const binding = mailboxBinding(input.binding)
    const retained = (await this.mailbox.pending()).find(receipt => receipt.binding.requestId === binding.requestId)
    if (retained === undefined || !sameBinding(retained.binding, binding)
      || binding.instanceId !== this.config.sourceInstanceId) throw new EndpointFailure(404, 'not-found')
    if (input.action === 'start') {
      const result = await this.sourceCall(signal,
        () => this.mailbox.startExecution(binding, input.expectedVersion))
      return result.value
    }
    if (input.action === 'status') {
      const result = await this.sourceCall(signal, () => this.mailbox.status(binding))
      return { receipt: result.value }
    }
    if (input.action === 'renew') {
      const result = await this.sourceCall(signal,
        () => this.mailbox.renewExecution(binding, input.expectedVersion))
      return result.value
    }
    if (input.transition.state === 'completed'
      && (Buffer.byteLength(input.transition.reply, 'utf8') > this.config.limits.maxTextBytes
        || Array.from(input.transition.reply).length > this.config.limits.maxTextCharacters)) {
      throw new EndpointFailure(400, 'limit')
    }
    const transition: MailboxTransition = input.transition.state === 'completed'
      ? { state: 'completed', reply: input.transition.reply } : { state: 'failed' }
    const result = await this.sourceCall(signal,
      () => this.mailbox.transition(binding, input.expectedVersion, transition))
    return { receipt: result.value }
  }

  private dispatchRank(receipt: MailboxReceipt, now: number): number {
    if (receipt.state === 'delivered') return 0
    if (isMailboxExecutionLeaseExpired(receipt, now, this.config.executionLeaseMs)) return 1
    return 2
  }

  private async authenticate(request: IncomingMessage, body: Buffer, signal: AbortSignal): Promise<void> {
    const timestampText = requiredHeader(request, 'x-dsh-a2a-timestamp')
    const nonceText = requiredHeader(request, 'x-dsh-a2a-nonce')
    const signatureText = requiredHeader(request, 'x-dsh-a2a-signature')
    if (!/^(0|[1-9]\d{0,15})$/u.test(timestampText) || !BASE64URL.test(nonceText) || !BASE64URL.test(signatureText)) {
      throw new EndpointFailure(401, 'unauthenticated')
    }
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
    if (credential === undefined || Buffer.byteLength(credential.value, 'utf8') < MIN_SHARED_SECRET_BYTES) {
      throw new EndpointFailure(503, 'not-configured')
    }
    const bodyHash = createHash('sha256').update(body).digest('hex')
    const canonical = `POST\n${A2A_LOOPBACK_QUESTIONS_PATH}\n${timestampText}\n${nonceText}\n${bodyHash}`
    const key = Buffer.from(credential.value, 'utf8')
    let expected: Buffer
    try { expected = createHmac('sha256', key).update(canonical).digest() } finally { key.fill(0) }
    if (!timingSafeEqual(expected, signature)) throw new EndpointFailure(401, 'unauthenticated')
    await this.replay.reserve(nonceText, timestamp + this.config.clockSkewMs + 1, now)
  }
}
