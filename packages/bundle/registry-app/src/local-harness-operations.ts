/** Durable Registry-to-Local-Harness context-import bridge for explicit loopback deployments. */
import { createHash, createHmac, randomBytes } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { credentialRef, type CredentialProvider, type CredentialRef } from '@deepseek-ai/dsh-credentials'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { DisclosureHash, DisclosureId, DshInstanceId } from '@deepseek-ai/dsh-a2a-protocol'
import type { InstanceKeyHistory, InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import type { RegistryConnectionAuthority } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import { RegistryIngestError, type FreshRegistryMetadataAuthority,
  type RegistryConfirmedPrefix } from '@deepseek-ai/dsh-a2a-registry-ingest'
import type { RegistryImportDelivery, RegistryImportOutcome } from '@deepseek-ai/dsh-a2a-registry-sync'
import { defineDomain, domainTable, type Domain, type DomainFacility, type KvTable } from '@deepseek-ai/dsh-storage-domain'
import z from '@deepseek-ai/schemastery'
import { z as zod } from 'zod'
import type { RegistryDisclosureImportResult, RegistryDisclosureOperations,
  RegistryDisclosureOperationSelection, RegistryImportOperationId, RegistryImportedSessionId } from './operations.ts'
import { LocalHarnessQuestionOperations, LocalHarnessQuestionOperationsConfigSchema,
  type LocalHarnessQuestionOperationsConfig } from './local-harness-question-operations.ts'
import { LocalHarnessDisclosureRegistration, LocalHarnessDisclosureRegistrationConfigSchema,
  type LocalHarnessDisclosureRegistrationConfig } from './local-harness-disclosure-registration.ts'
import { LocalHarnessDisclosureRefresh, LocalHarnessDisclosureRefreshConfigSchema,
  type LocalHarnessDisclosureRefreshConfig } from './local-harness-disclosure-refresh.ts'
import type { RegistryImportBroker } from './import-broker.ts'
import type { RegistryDisclosureReader } from './reader.ts'
import type { RegistryTransportObservation } from './transport-observation.ts'

const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const STATUS_PATH = '/a2a-loopback/v1/status'
const IMPORTS_PATH = '/a2a-loopback/v1/imports'

/** Explicit bounds and addressing for one trusted loopback receiver. */
export interface LocalHarnessOperationsConfig {
  /** HTTP origin of the Local Harness receiver; only 127.0.0.1 is accepted. */
  readonly receiverUrl: string
  /** Exact enrolled Local DSH identity expected from status and import responses. */
  readonly targetInstanceId: DshInstanceId
  /** Credential reference resolved separately for every signed request. */
  readonly sharedSecretEnv: string
  /** Complete timeout for one status or import HTTP request. */
  readonly requestTimeoutMs: number
  /** Durable operation capacity; no record eviction occurs. */
  readonly maxOperations: number
  /** Maximum serialized import request bytes, including the encrypted prefix. */
  readonly maxRequestBytes: number
  /** Maximum receiver response bytes before JSON decoding. */
  readonly maxResponseBytes: number
  /** Maximum serialized durable operation-record bytes. */
  readonly maxRecordBytes: number
  /** Payload delivery transport; omission preserves the legacy signed loopback adapter. */
  readonly importTransport?: 'loopback' | 'registry-sync'
  /** Fixed one-shot withdrawal acceptance hook for the generated local MVP seed only. */
  readonly testOnlyRevoke?: {
    readonly mode: 'test-only'
    readonly disclosureId: DisclosureId
    readonly sourceInstanceId: DshInstanceId
    readonly sourceKeyId: InstanceKeyId
    readonly expectedAuthorizationVersion: number
  }
  /** Explicit test-only Registry question mailbox and source polling endpoint. */
  readonly question?: LocalHarnessQuestionOperationsConfig
  /** Explicit test-only source-to-Registry disclosure registration endpoint. */
  readonly registration?: LocalHarnessDisclosureRegistrationConfig
  /** Explicit test-only Registry-to-Harness disclosure refresh endpoint. */
  readonly refresh?: LocalHarnessDisclosureRefreshConfig
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const timer = () => z.natural().min(1).max(2_147_483_647).required()
/** Loader schema for the optional Local Harness bridge. */
export const Config: z<LocalHarnessOperationsConfig> = z.object({
  receiverUrl: z.string().required(),
  targetInstanceId: z.transform(z.string().pattern(IDENTIFIER).required(), value => brandString<DshInstanceId>(value)).required(),
  sharedSecretEnv: z.string().role('credential-ref').required(),
  requestTimeoutMs: timer(), maxOperations: positive(), maxRequestBytes: positive(),
  maxResponseBytes: positive(), maxRecordBytes: positive(),
  importTransport: z.union([z.const('loopback'), z.const('registry-sync')]),
  testOnlyRevoke: z.union([z.object({
    mode: z.const('test-only').required(),
    disclosureId: z.transform(z.string().pattern(IDENTIFIER).required(),
      value => brandString<DisclosureId>(value)).required(),
    sourceInstanceId: z.transform(z.string().pattern(IDENTIFIER).required(),
      value => brandString<DshInstanceId>(value)).required(),
    sourceKeyId: z.transform(z.string().pattern(IDENTIFIER).required(),
      value => brandString<InstanceKeyId>(value)).required(),
    expectedAuthorizationVersion: z.natural().max(Number.MAX_SAFE_INTEGER).required(),
  })]),
  question: z.union([LocalHarnessQuestionOperationsConfigSchema]),
  registration: z.union([LocalHarnessDisclosureRegistrationConfigSchema]),
  refresh: z.union([LocalHarnessDisclosureRefreshConfigSchema]),
})

const commonRecord = {
  operationId: zod.string().regex(IDENTIFIER),
  organizationId: zod.string().regex(IDENTIFIER),
  memberId: zod.string().regex(IDENTIFIER),
  disclosureId: zod.string().regex(IDENTIFIER),
  sourceInstanceId: zod.string().regex(IDENTIFIER),
  checkpointHash: zod.string().min(1),
  authorizationVersion: zod.number().int().nonnegative(),
  targetInstanceId: zod.string().regex(IDENTIFIER),
  createdAt: zod.number().int().nonnegative(),
  updatedAt: zod.number().int().nonnegative(),
}
const importRecordSchema = zod.discriminatedUnion('status', [
  zod.strictObject({ ...commonRecord, status: zod.literal('queued') }).readonly(),
  zod.strictObject({ ...commonRecord, status: zod.literal('failed') }).readonly(),
  zod.strictObject({ ...commonRecord, status: zod.literal('completed'),
    sessionId: zod.string().regex(IDENTIFIER) }).readonly(),
])
type ImportRecord = zod.infer<typeof importRecordSchema>

function byteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

function specification(maxRecordBytes: number) {
  return defineDomain({ name: 'a2a_registry_local_imports', version: 4, layout: 'single', tables: {
    imports: domainTable<RegistryImportOperationId, ImportRecord>(importRecordSchema.superRefine((record, context) => {
      if (byteLength(record) > maxRecordBytes) context.addIssue({ code: 'custom', message: 'record exceeds configured limit' })
    })),
  } })
}

function baseUrl(value: string): URL {
  let url: URL
  try { url = new URL(value) } catch { throw new Error('Registry Local Harness receiverUrl must be an absolute URL') }
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1'
    || url.username !== '' || url.password !== '' || url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    throw new Error('Registry Local Harness receiverUrl must be a credential-free 127.0.0.1 HTTP origin')
  }
  return url
}

function endpoint(base: URL, pathname: string): URL {
  const value = new URL(base)
  value.pathname = pathname
  return value
}

function operationId(selection: RegistryDisclosureOperationSelection, targetInstanceId: DshInstanceId,
  idempotencyKey: string): RegistryImportOperationId {
  const digest = createHash('sha256').update([
    selection.subject.organizationId, selection.subject.memberId,
    selection.disclosure.disclosureId, targetInstanceId, idempotencyKey,
  ].join('\0')).digest('hex')
  return brandString<RegistryImportOperationId>(`import-${digest}`)
}

function stableSessionId(instanceId: string, importOperationId: string): string {
  const digest = createHash('sha256').update(`${instanceId}\0${importOperationId}`, 'utf8').digest('hex')
  return `a2a-import-${digest}`
}

function resultOf(record: ImportRecord, base: URL): RegistryDisclosureImportResult {
  const sessionUrl = new URL(base)
  if (record.status === 'completed') sessionUrl.searchParams.set('session', record.sessionId)
  return record.status === 'completed'
    ? { operationId: brandString<RegistryImportOperationId>(record.operationId), status: record.status,
      sessionId: brandString<RegistryImportedSessionId>(record.sessionId), sessionUrl: sessionUrl.href }
    : { operationId: brandString<RegistryImportOperationId>(record.operationId), status: record.status }
}

function sameOwner(record: ImportRecord, selection: RegistryDisclosureOperationSelection): boolean {
  return record.organizationId === selection.subject.organizationId
    && record.memberId === selection.subject.memberId
    && record.disclosureId === selection.disclosure.disclosureId
}

function mergedSignal(owner: AbortSignal, request: AbortSignal, timeoutMs: number): { signal: AbortSignal; dispose: () => void } {
  const controller = new AbortController()
  const abort = () => { controller.abort() }
  owner.addEventListener('abort', abort, { once: true })
  request.addEventListener('abort', abort, { once: true })
  const timer = setTimeout(abort, timeoutMs)
  if (owner.aborted || request.aborted) abort()
  return { signal: controller.signal, dispose: () => {
    clearTimeout(timer)
    owner.removeEventListener('abort', abort)
    request.removeEventListener('abort', abort)
  } }
}

async function abandonOnAbort<T>(operation: () => T | Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  const aborted = Promise.withResolvers<never>()
  const onAbort = () => { aborted.reject(new Error('Registry Local Harness request cancelled')) }
  signal.addEventListener('abort', onAbort, { once: true })
  try { return await Promise.race([Promise.resolve().then(operation), aborted.promise]) }
  finally { signal.removeEventListener('abort', onAbort) }
}

async function responseJson(response: Response, maximum: number): Promise<unknown> {
  const declared = response.headers.get('content-length')
  if (declared !== null && (!/^(0|[1-9]\d*)$/u.test(declared) || Number(declared) > maximum)) {
    throw new Error('receiver response unavailable')
  }
  const reader = response.body?.getReader()
  if (reader === undefined) throw new Error('receiver response unavailable')
  const chunks: Uint8Array[] = []
  let total = 0
  while (true) {
    const part = await reader.read()
    if (part.done) break
    total += part.value.byteLength
    if (total > maximum) {
      await reader.cancel()
      throw new Error('receiver response unavailable')
    }
    chunks.push(part.value)
  }
  const bytes = Buffer.concat(chunks.map(chunk => Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)), total)
  let text: string
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes) } catch {
    throw new Error('receiver response unavailable')
  }
  try { return JSON.parse(text) as unknown } catch { throw new Error('receiver response unavailable') }
}

const statusResponse = zod.strictObject({ ok: zod.literal(true), value: zod.strictObject({
  instanceId: zod.string().regex(IDENTIFIER), acceptingA2A: zod.boolean(), activeRequests: zod.number().int().nonnegative(),
}) })
const importResponse = zod.strictObject({ ok: zod.literal(true), value: zod.strictObject({
  sessionId: zod.string().regex(IDENTIFIER), sessionUrl: zod.url(),
}) })
const failureResponse = zod.strictObject({ ok: zod.literal(false), error: zod.strictObject({
  code: zod.enum(['invalid-input', 'method-not-allowed', 'not-configured', 'not-found', 'replay',
    'unauthenticated', 'unavailable']),
}) })

/** One serialized durable import owner. Ciphertext prefixes leave only through signed loopback requests. */
export class LocalHarnessOperations implements RegistryDisclosureOperations, RegistryImportBroker {
  private readonly table: KvTable<RegistryImportOperationId, ImportRecord>
  private readonly ownerAbort = new AbortController()
  private chain = Promise.resolve()
  private disposal: Promise<void> | undefined
  private unavailable = false

  private constructor(private readonly domain: Domain<ReturnType<typeof specification>>,
    private readonly credentials: CredentialProvider, private readonly secretRef: CredentialRef,
    private readonly base: URL, private readonly config: LocalHarnessOperationsConfig,
    private readonly reader?: RegistryDisclosureReader) {
    this.table = domain.table('imports')
  }

  /** Open and validate the durable ledger before publishing the provider. */
  static async open(facility: DomainFacility, credentials: CredentialProvider,
    config: LocalHarnessOperationsConfig, reader?: RegistryDisclosureReader): Promise<LocalHarnessOperations> {
    const resolved = structuredClone(config)
    const base = baseUrl(resolved.receiverUrl)
    const secretRef = credentialRef(resolved.sharedSecretEnv)
    let domain: Domain<ReturnType<typeof specification>>
    try { domain = await facility.open(specification(resolved.maxRecordBytes)) } catch {
      throw new Error('Registry Local Harness import ledger is unavailable')
    }
    if (resolved.importTransport === 'registry-sync' && (resolved.question === undefined || reader === undefined)) {
      await domain.close()
      throw new Error('Registry Sync imports require the configured local question identity and Registry reader')
    }
    const owner = new LocalHarnessOperations(domain, credentials, secretRef, base, resolved, reader)
    if ([...owner.table.entries()].some(([, record]) => record.targetInstanceId !== resolved.targetInstanceId)) {
      await domain.close()
      throw new Error('Registry Local Harness import ledger target does not match configuration')
    }
    if (owner.table.size > resolved.maxOperations) {
      await domain.close()
      throw new Error('Registry Local Harness import ledger exceeds configured capacity')
    }
    return owner
  }

  /** Probe authenticated receiver state only after current target-binding authorization. */
  listImportTargets(selection: RegistryDisclosureOperationSelection, signal: AbortSignal) {
    return this.run(async () => {
      let transport: RegistryTransportObservation
      try { transport = await selection.authorizeTarget(this.config.targetInstanceId, signal) } catch (error) {
        if (error instanceof RegistryIngestError && error.code === 'not-found') return []
        throw error
      }
      if (this.config.importTransport === 'registry-sync' && transport.kind !== 'connected') {
        return [{ instanceId: this.config.targetInstanceId, transport: 'not-observed' as const,
          acceptingA2A: null, activeRequests: null }]
      }
      if (transport.kind === 'connected' && transport.report !== undefined) {
        return [{ instanceId: this.config.targetInstanceId, transport: 'connected' as const,
          acceptingA2A: transport.report.acceptingA2A, activeRequests: transport.report.activeRequests }]
      }
      try {
        const response = await this.request(STATUS_PATH, '', signal)
        if (!response.ok) throw new Error('receiver status unavailable')
        const parsed = statusResponse.parse(response.value).value
        if (parsed.instanceId !== this.config.targetInstanceId) throw new Error('receiver status unavailable')
        return [{ instanceId: this.config.targetInstanceId, transport: 'connected' as const,
          acceptingA2A: parsed.acceptingA2A, activeRequests: parsed.activeRequests }]
      } catch {
        if (signal.aborted) throw new Error('Registry Local Harness status request cancelled')
        return [{ instanceId: this.config.targetInstanceId,
          transport: this.config.importTransport === 'registry-sync' ? 'connected' as const : 'not-observed' as const,
          acceptingA2A: null, activeRequests: null }]
      }
    })
  }

  /** Persist acceptance, reauthorize the exact checkpoint, then invoke the signed receiver idempotently. */
  importDisclosure(selection: RegistryDisclosureOperationSelection,
    input: { readonly targetInstanceId: DshInstanceId; readonly idempotencyKey: string }, signal: AbortSignal) {
    return this.run(async () => {
      if (input.targetInstanceId !== this.config.targetInstanceId) throw new RegistryIngestError('not-found')
      const id = operationId(selection, input.targetInstanceId, input.idempotencyKey)
      let record = this.table.get(id)
      if (record !== undefined) {
        if (!sameOwner(record, selection)
          || record.targetInstanceId !== input.targetInstanceId) throw new RegistryIngestError('invalid-input')
        if (record.status !== 'queued') {
          await selection.authorizeTarget(input.targetInstanceId, signal)
          return resultOf(record, this.base)
        }
      } else {
        await selection.authorizeTarget(input.targetInstanceId, signal)
        if (this.table.size >= this.config.maxOperations) throw new Error('Registry Local Harness import capacity reached')
        const now = Date.now()
        record = { operationId: id, organizationId: selection.subject.organizationId,
          memberId: selection.subject.memberId, disclosureId: selection.disclosure.disclosureId,
          sourceInstanceId: selection.disclosure.instanceId,
          checkpointHash: selection.disclosure.checkpoint.checkpointHash,
          authorizationVersion: selection.disclosure.authorizationVersion,
          targetInstanceId: input.targetInstanceId, status: 'queued',
          createdAt: now, updatedAt: now }
        await this.put(id, record)
      }
      return this.config.importTransport === 'registry-sync'
        ? resultOf(record, this.base)
        : this.resume(record, selection, signal)
    })
  }

  /** Read a member-owned fixed-checkpoint operation after the browser API reauthorized that checkpoint. */
  readImport(selection: RegistryDisclosureOperationSelection, id: RegistryImportOperationId, signal: AbortSignal) {
    return this.run(async () => {
      const record = this.table.get(id)
      if (record === undefined || !sameOwner(record, selection)) throw new RegistryIngestError('not-found')
      if (record.status === 'queued' && this.config.importTransport !== 'registry-sync') {
        return this.resume(record, selection, signal)
      }
      await selection.authorizeTarget(brandString<DshInstanceId>(record.targetInstanceId), signal)
      return resultOf(record, this.base)
    })
  }

  /** Deliver one queued operation to its authenticated target while Registry authorization remains current. */
  dispatch(target: RegistryConnectionAuthority,
    receive: (delivery: RegistryImportDelivery) => Promise<RegistryImportOutcome>,
    signal: AbortSignal): Promise<boolean> {
    return this.run(async () => {
      if (this.config.importTransport !== 'registry-sync') throw new RegistryIngestError('not-found')
      const identity = this.config.question
      const reader = this.reader
      if (identity === undefined || reader === undefined) throw new RegistryIngestError('not-found')
      this.assertImportTarget(target)
      signal.throwIfAborted()
      const record = [...this.table.entries()].map(([, candidate]) => candidate)
        .filter((candidate): candidate is Extract<ImportRecord, { status: 'queued' }> => candidate.status === 'queued'
          && candidate.targetInstanceId === target.connection.instanceId)
        .sort((left, right) => left.createdAt - right.createdAt || left.operationId.localeCompare(right.operationId))[0]
      if (record === undefined) return false
      const authority: FreshRegistryMetadataAuthority = () => {
        signal.throwIfAborted()
        this.assertImportTarget(target)
        return {
          subject: this.importSubject(), now: Date.now(),
          historyFor: instanceId => instanceId === identity.sourceInstanceId ? this.sourceHistory() : null,
        }
      }
      const delivered = await reader.withAuthorizedPrefix(authority,
        brandString<DisclosureId>(record.disclosureId), brandString<DshInstanceId>(record.sourceInstanceId),
        'import', brandString<DisclosureHash>(record.checkpointHash), identity.maxAuthorizationResponseBytes,
        { authority: () => {
          signal.throwIfAborted()
          this.assertImportTarget(target)
          return { subject: { organizationId: identity.organizationId, memberId: identity.memberId,
            authenticated: true }, now: Date.now() }
        }, instanceId: this.config.targetInstanceId, maxResponseBytes: identity.maxAuthorizationResponseBytes },
        async (snapshot) => {
          if (snapshot === null || snapshot.metadata.organizationId !== record.organizationId
            || snapshot.metadata.instanceId !== record.sourceInstanceId
            || snapshot.metadata.disclosureId !== record.disclosureId
            || snapshot.metadata.checkpoint.checkpointHash !== record.checkpointHash
            || snapshot.prefix.authorizationVersion < record.authorizationVersion) {
            await this.put(brandString<RegistryImportOperationId>(record.operationId),
              { ...record, status: 'failed', updatedAt: Date.now() })
            return false
          }
          const delivery: RegistryImportDelivery = {
            operationId: record.operationId,
            targetInstanceId: brandString<DshInstanceId>(record.targetInstanceId),
            organizationId: identity.organizationId,
            disclosureId: brandString<DisclosureId>(record.disclosureId),
            sourceInstanceId: brandString<DshInstanceId>(record.sourceInstanceId),
            checkpointHash: brandString<DisclosureHash>(record.checkpointHash),
            prefix: snapshot.prefix,
            source: { instanceName: record.sourceInstanceId,
              conversationTitle: String(snapshot.prefix.conversationId) },
          }
          const outcome = await receive(delivery)
          signal.throwIfAborted()
          this.assertImportTarget(target)
          if (outcome.status === 'completed') {
            const expected = stableSessionId(record.targetInstanceId, record.operationId)
            if (outcome.sessionId !== expected) throw new RegistryIngestError('invalid-input')
            await this.put(brandString<RegistryImportOperationId>(record.operationId),
              { ...record, status: 'completed', sessionId: outcome.sessionId, updatedAt: Date.now() })
          }
          return true
        })
      return delivered
    })
  }

  /** Reauthorize and redeliver one durable queued record with its stable operation identity. */
  private async resume(record: Extract<ImportRecord, { status: 'queued' }>,
    selection: RegistryDisclosureOperationSelection, signal: AbortSignal): Promise<RegistryDisclosureImportResult> {
    let prefix: RegistryConfirmedPrefix
    let body: string
    try {
      prefix = await selection.readAuthorizedPrefix({ sourceInstanceId: brandString<DshInstanceId>(record.sourceInstanceId),
        checkpointHash: brandString<DisclosureHash>(record.checkpointHash) }, signal)
      if (prefix.authorizationVersion < record.authorizationVersion
        || prefix.checkpoint.checkpointHash !== record.checkpointHash
        || prefix.checkpoint.organizationId !== record.organizationId
        || prefix.checkpoint.instanceId !== record.sourceInstanceId
        || prefix.checkpoint.disclosureId !== record.disclosureId) throw new RegistryIngestError('not-found')
      body = JSON.stringify({ version: 1, operationId: record.operationId,
        targetInstanceId: record.targetInstanceId, organizationId: record.organizationId,
        disclosureId: record.disclosureId, checkpointHash: record.checkpointHash, prefix,
        source: { instanceName: record.sourceInstanceId, conversationTitle: String(prefix.conversationId) } })
      if (Buffer.byteLength(body, 'utf8') > this.config.maxRequestBytes) throw new RegistryIngestError('limit')
      await selection.authorizeTarget(brandString<DshInstanceId>(record.targetInstanceId), signal)
    } catch (error) {
      const terminal = error instanceof RegistryIngestError
        && (error.code === 'not-found' || error.code === 'invalid-input' || error.code === 'limit')
      if (signal.aborted || !terminal) return resultOf(record, this.base)
      const failed: ImportRecord = { ...record, status: 'failed', updatedAt: Date.now() }
      await this.put(brandString<RegistryImportOperationId>(record.operationId), failed)
      throw error
    }

    let accepted: zod.infer<typeof importResponse>['value'] | undefined
    let terminalReceiverFailure = false
    try {
      const response = await this.request(IMPORTS_PATH, body, signal)
      if (!response.ok) {
        const failure = failureResponse.safeParse(response.value)
        terminalReceiverFailure = failure.success
          && ((response.status === 400 && failure.data.error.code === 'invalid-input')
            || (response.status === 404 && failure.data.error.code === 'not-found'))
        if (!terminalReceiverFailure) throw new Error('import receiver unavailable')
      } else {
        accepted = importResponse.parse(response.value).value
        const sessionUrl = new URL(accepted.sessionUrl)
        const query = [...sessionUrl.searchParams]
        if (sessionUrl.origin !== this.base.origin || sessionUrl.username !== '' || sessionUrl.password !== ''
          || sessionUrl.pathname !== '/' || sessionUrl.hash !== '' || query.length !== 1
          || query[0]?.[0] !== 'session' || query[0][1] !== accepted.sessionId) {
          throw new Error('import receiver unavailable')
        }
      }
    } catch {
      return resultOf(record, this.base)
    }
    if (terminalReceiverFailure) {
      const failed: ImportRecord = { ...record, status: 'failed', updatedAt: Date.now() }
      await this.put(brandString<RegistryImportOperationId>(record.operationId), failed)
      return resultOf(failed, this.base)
    }
    if (accepted === undefined) return resultOf(record, this.base)
    const completed: ImportRecord = { ...record, status: 'completed', sessionId: accepted.sessionId,
      updatedAt: Date.now() }
    await this.put(brandString<RegistryImportOperationId>(record.operationId), completed)
    return resultOf(completed, this.base)
  }

  /** Stop new work, abort HTTP requests and close the ledger after admitted operations settle. */
  close(): Promise<void> {
    this.ownerAbort.abort()
    this.disposal ??= this.chain.then(() => this.domain.close())
    return this.disposal
  }

  private run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.ownerAbort.signal.aborted || this.unavailable) return Promise.reject(new Error('Registry Local Harness operations unavailable'))
    const result = this.chain.then(async () => {
      if (this.ownerAbort.signal.aborted || this.unavailable) throw new Error('Registry Local Harness operations unavailable')
      return operation()
    })
    this.chain = result.then(() => {}, () => {})
    return result
  }

  private async put(id: RegistryImportOperationId, record: ImportRecord): Promise<void> {
    if (byteLength(record) > this.config.maxRecordBytes) throw new Error('Registry Local Harness import record exceeds configured limit')
    try { await this.table.put(id, Object.freeze(record)) } catch {
      this.unavailable = true
      this.ownerAbort.abort()
      throw new Error('Registry Local Harness import ledger is unavailable')
    }
  }

  private async request(path: string, body: string,
    requestSignal: AbortSignal): Promise<{ ok: boolean; status: number; value: unknown }> {
    const lifetime = mergedSignal(this.ownerAbort.signal, requestSignal, this.config.requestTimeoutMs)
    try {
      const credential = await abandonOnAbort(() => this.credentials.resolve(this.secretRef), lifetime.signal)
      if (credential === undefined || Buffer.byteLength(credential.value, 'utf8') < 32) {
        throw new Error('Registry Local Harness shared secret is unavailable')
      }
      const timestamp = String(Date.now())
      const nonce = randomBytes(18).toString('base64url')
      const bodyHash = createHash('sha256').update(body).digest('hex')
      const key = Buffer.from(credential.value, 'utf8')
      let signature: string
      try { signature = createHmac('sha256', key).update(`${timestamp}\n${nonce}\n${bodyHash}`).digest('base64url') }
      finally { key.fill(0) }
      const url = endpoint(this.base, path)
      const response = await fetch(url, {
        method: body === '' ? 'GET' : 'POST',
        redirect: 'error',
        headers: { 'x-dsh-a2a-timestamp': timestamp, 'x-dsh-a2a-nonce': nonce,
          'x-dsh-a2a-signature': signature, ...(body === '' ? {} : { 'content-type': 'application/json; charset=utf-8' }) },
        ...(body === '' ? {} : { body }), signal: lifetime.signal,
      })
      if (response.url !== url.href) throw new Error('Registry Local Harness receiver redirected')
      return { ok: response.ok, status: response.status,
        value: await responseJson(response, this.config.maxResponseBytes) }
    } finally { lifetime.dispose() }
  }

  private importSubject() {
    const identity = this.config.question
    if (identity === undefined) throw new RegistryIngestError('not-found')
    return { organizationId: identity.organizationId, memberId: identity.memberId,
      authenticated: true as const, membership: 'active' as const, role: 'owner' as const,
      currentTeamIds: [] }
  }

  private sourceHistory(): InstanceKeyHistory {
    const identity = this.config.question
    if (identity === undefined) throw new RegistryIngestError('not-found')
    return { organizationId: identity.organizationId, instanceId: identity.sourceInstanceId,
      status: 'active', keys: [{ keyId: identity.sourceKeyId,
        publicKeySpki: identity.sourcePublicKeySpki, validFrom: identity.sourceKeyValidFrom,
        validUntil: null, revokedAt: null }] }
  }

  private assertImportTarget(target: RegistryConnectionAuthority): void {
    const identity = this.config.question
    if (identity === undefined || target.connection.organizationId !== identity.organizationId
      || target.connection.instanceId !== this.config.targetInstanceId
      || target.history.organizationId !== identity.organizationId
      || target.history.instanceId !== this.config.targetInstanceId) throw new RegistryIngestError('not-found')
  }
}

/** Private Cordis plugin name; registry-app owns its optional composition. */
export const name = 'registry-local-harness-operations'
/** Explicit storage and credential providers are required by the opt-in bridge. */
export const inject = ['storageDomain', 'credentials']

/** Open configured durable owners and publish one combined browser operation surface. */
export async function apply(ctx: Context, config: LocalHarnessOperationsConfig): Promise<void> {
  if (ctx.get('registryDisclosureOperations') !== undefined) {
    throw new Error('Registry disclosure operations already have a provider')
  }
  const owner = await LocalHarnessOperations.open(ctx.storageDomain, ctx.credentials, config,
    ctx.get('registryDisclosureReader'))
  let questions: LocalHarnessQuestionOperations | undefined
  let registration: LocalHarnessDisclosureRegistration | undefined
  let refresh: LocalHarnessDisclosureRefresh | undefined
  try {
    if (config.question !== undefined) questions = await LocalHarnessQuestionOperations.open(ctx, config.question)
    if (config.registration !== undefined) {
      registration = await LocalHarnessDisclosureRegistration.open(ctx, config.registration)
    }
    if (config.refresh !== undefined) refresh = await LocalHarnessDisclosureRefresh.open(ctx, config.refresh)
  } catch (error) {
    await Promise.allSettled([refresh?.close(), registration?.close(), questions?.close(), owner.close()])
    throw error
  }
  const provider: RegistryDisclosureOperations = Object.freeze({
    listImportTargets: owner.listImportTargets.bind(owner),
    importDisclosure: owner.importDisclosure.bind(owner),
    readImport: owner.readImport.bind(owner),
    ...(registration === undefined ? {} : { readContent: registration.readContent.bind(registration) }),
    ...(questions === undefined ? {} : {
      listQuestions: questions.listQuestions.bind(questions),
      askDisclosure: questions.askDisclosure.bind(questions),
      readQuestion: questions.readQuestion.bind(questions),
      cancelQuestion: questions.cancelQuestion.bind(questions),
    }),
  })
  ctx.effect(() => async () => {
    const outcomes = await Promise.allSettled([refresh?.close(), registration?.close(), questions?.close(), owner.close()])
    if (outcomes.some(outcome => outcome.status === 'rejected')) {
      throw new Error('Registry Local Harness operations cleanup failed')
    }
  }, 'registry-app: Local Harness durable owners')
  if (questions !== undefined) ctx.provide('registryQuestionBroker', questions)
  if (config.importTransport === 'registry-sync') ctx.provide('registryImportBroker', owner)
  ctx.provide('registryDisclosureOperations', provider)
}
