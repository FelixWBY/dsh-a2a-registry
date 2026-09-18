/**
 * Tenant-scoped software envelope encryption for a single-process, single-replica Registry MVP.
 * The deployment supplies a root key; PostgreSQL/storage-domain persists only wrapped keys.
 * This package deliberately provides no HSM, attestation, secret loading, network protocol, or content projection.
 * @module @deepseek-ai/dsh-a2a-registry-kms-software
 */
import {
  createHash, createSecretKey, randomBytes, randomUUID, timingSafeEqual, type KeyObject,
} from 'node:crypto'
import { brandString } from '@deepseek-ai/dsh-brand'
import type {
  DisclosureDataKey, DisclosureDataKeyGrantScope, DisclosureDataKeyId,
} from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import {
  defineDomain, domainTable, type Domain, type DomainFacility,
} from '@deepseek-ai/dsh-storage-domain'
import { z } from 'zod'
import { requireAes256Key, unwrapKey, wrapKey } from './crypto.ts'
import {
  SOFTWARE_LOCAL_KEY_PROTECTION, SoftwareLocalKmsError,
  type SoftwareLocalDisclosureKeyReceipt, type SoftwareLocalDisclosureKeyStoreOptions,
  type SoftwareLocalWrappedKey,
} from './types.ts'

export * from './types.ts'

const FORMAT_VERSION = 1
const OWNER_RECORD_KEY = 'owner'
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/
const DOMAIN_NAME_PREFIX = /^[a-z][a-z0-9_]*$/

const identifierSchema = z.string().regex(IDENTIFIER)
const organizationIdSchema = identifierSchema.transform(
  value => brandString<DisclosureDataKeyGrantScope['organizationId']>(value),
)
const instanceIdSchema = identifierSchema.transform(
  value => brandString<DisclosureDataKeyGrantScope['instanceId']>(value),
)
const conversationIdSchema = identifierSchema.transform(
  value => brandString<DisclosureDataKeyGrantScope['conversationId']>(value),
)
const disclosureIdSchema = identifierSchema.transform(
  value => brandString<DisclosureDataKeyGrantScope['disclosureId']>(value),
)
const wrappedKeySchema = z.strictObject({
  version: z.literal(FORMAT_VERSION),
  algorithm: z.literal('A256GCM'),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{16}$/),
  ciphertext: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  tag: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
}).readonly()
const grantScopeSchema = z.strictObject({
  organizationId: organizationIdSchema,
  instanceId: instanceIdSchema,
  conversationId: conversationIdSchema,
  disclosureId: disclosureIdSchema,
}).readonly()

interface OwnerRecord {
  readonly version: 1
  readonly organizationId: DisclosureDataKeyGrantScope['organizationId']
  readonly rootKeyId: string
  readonly organizationKeyId: string
  readonly wrappedOrganizationKey: SoftwareLocalWrappedKey
}

interface DataKeyRecord {
  readonly version: 1
  readonly organizationKeyId: string
  readonly scope: DisclosureDataKeyGrantScope
  readonly keyId: DisclosureDataKeyId
  readonly wrappedDataKey: SoftwareLocalWrappedKey
}

function requireKms(condition: unknown, code: ConstructorParameters<typeof SoftwareLocalKmsError>[0]): asserts condition {
  if (!condition) throw new SoftwareLocalKmsError(code)
}

function storeSpecification(options: SoftwareLocalDisclosureKeyStoreOptions) {
  const ownerSchema: z.ZodType<OwnerRecord> = z.strictObject({
    version: z.literal(FORMAT_VERSION),
    organizationId: z.literal(options.organizationId),
    rootKeyId: identifierSchema,
    organizationKeyId: identifierSchema,
    wrappedOrganizationKey: wrappedKeySchema,
  }).readonly()
  const dataKeySchema: z.ZodType<DataKeyRecord> = z.strictObject({
    version: z.literal(FORMAT_VERSION),
    organizationKeyId: identifierSchema,
    scope: z.strictObject({
      organizationId: z.literal(options.organizationId),
      instanceId: instanceIdSchema,
      conversationId: conversationIdSchema,
      disclosureId: disclosureIdSchema,
    }).readonly(),
    keyId: identifierSchema.transform(value => brandString<DisclosureDataKeyId>(value)),
    wrappedDataKey: wrappedKeySchema,
  }).readonly()
  return defineDomain({
    name: softwareLocalDisclosureKeyDomainName(options.storage.domainNamePrefix, options.organizationId),
    tenantId: options.storage.tenantId,
    version: FORMAT_VERSION,
    layout: 'single',
    tables: {
      owner: domainTable<string, OwnerRecord>(ownerSchema),
      data_keys: domainTable<string, DataKeyRecord>(dataKeySchema),
    },
  })
}

/**
 * Derive the collision-resistant physical storage-domain name for one organization.
 * @param prefix - Deployment-selected lowercase storage unit prefix.
 * @param organizationId - Authenticated organization owning the domain.
 * @returns The stable prefix plus a 128-bit organization hash suffix.
 */
export function softwareLocalDisclosureKeyDomainName(prefix: string, organizationId: string): string {
  requireKms(DOMAIN_NAME_PREFIX.test(prefix) && IDENTIFIER.test(organizationId), 'invalid-input')
  const digest = createHash('sha256').update(organizationId, 'utf8').digest('hex').slice(0, 32)
  return `${prefix}_${digest}`
}

type StoreDomain = Domain<ReturnType<typeof storeSpecification>>

function identifier(value: unknown, code: 'invalid-input' | 'invalid-root-key'): string {
  requireKms(typeof value === 'string' && IDENTIFIER.test(value), code)
  return value
}

function positiveInteger(value: unknown): number {
  requireKms(Number.isSafeInteger(value) && (value as number) > 0, 'invalid-input')
  return value as number
}

function parseScope(value: unknown): DisclosureDataKeyGrantScope {
  const parsed = grantScopeSchema.safeParse(value)
  requireKms(parsed.success, 'invalid-input')
  return Object.freeze(parsed.data as DisclosureDataKeyGrantScope)
}

function sameScope(left: DisclosureDataKeyGrantScope, right: DisclosureDataKeyGrantScope): boolean {
  return left.organizationId === right.organizationId
    && left.instanceId === right.instanceId
    && left.conversationId === right.conversationId
    && left.disclosureId === right.disclosureId
}

function dataKeyRecordKey(scope: DisclosureDataKeyGrantScope, keyId: DisclosureDataKeyId): string {
  return `k_${createHash('sha256').update(JSON.stringify([
    scope.organizationId, scope.instanceId, scope.conversationId, scope.disclosureId, keyId,
  ]), 'utf8').digest('hex')}`
}

function organizationKeyAad(owner: Pick<OwnerRecord, 'organizationId' | 'rootKeyId' | 'organizationKeyId'>): Buffer {
  return Buffer.from(JSON.stringify([
    'dsh-registry-software-kms', FORMAT_VERSION, 'organization-key',
    owner.rootKeyId, owner.organizationId, owner.organizationKeyId,
  ]), 'utf8')
}

function dataKeyAad(record: Pick<DataKeyRecord, 'organizationKeyId' | 'scope' | 'keyId'>): Buffer {
  return Buffer.from(JSON.stringify([
    'dsh-registry-software-kms', FORMAT_VERSION, 'data-key', record.organizationKeyId,
    record.scope.organizationId, record.scope.instanceId, record.scope.conversationId,
    record.scope.disclosureId, record.keyId,
  ]), 'utf8')
}

function exportKey(key: KeyObject, code: 'invalid-input' | 'invalid-root-key'): Buffer {
  requireAes256Key(key, code)
  try {
    const exported = key.export()
    // Secret KeyObject exports are Buffers; return that exact allocation so the caller can zero every raw copy.
    return Buffer.isBuffer(exported) ? exported : Buffer.from(exported)
  } catch {
    throw new SoftwareLocalKmsError(code)
  }
}

function createAesKey(material: Buffer): KeyObject {
  try { return createSecretKey(material) } catch { throw new SoftwareLocalKmsError('unavailable') }
}

function receipt(scope: DisclosureDataKeyGrantScope, keyId: DisclosureDataKeyId): SoftwareLocalDisclosureKeyReceipt {
  return Object.freeze({ scope: Object.freeze({ ...scope }), keyId, assurance: 'software-local' })
}

async function bootstrapOwner(domain: StoreDomain, options: SoftwareLocalDisclosureKeyStoreOptions): Promise<{
  owner: OwnerRecord
  organizationKey: KeyObject
}> {
  const owners = domain.table('owner')
  const dataKeys = domain.table('data_keys')
  requireKms(owners.size <= 1, 'invalid-storage')
  const retained = owners.get(OWNER_RECORD_KEY)
  requireKms(retained !== undefined || owners.size === 0, 'invalid-storage')
  requireKms(retained !== undefined || dataKeys.size === 0, 'invalid-storage')
  if (retained !== undefined) {
    requireKms(retained.rootKeyId === options.rootKey.keyId, 'root-key-unavailable')
    const material = unwrapKey(options.rootKey.key, retained.wrappedOrganizationKey, organizationKeyAad(retained))
    try { return { owner: retained, organizationKey: createAesKey(material) } }
    finally { material.fill(0) }
  }

  let material: Buffer | undefined
  let owner: OwnerRecord
  try {
    try { material = randomBytes(32) } catch { throw new SoftwareLocalKmsError('unavailable') }
    const organizationKeyId = `organization-key:${randomUUID()}`
    const ownerMetadata = {
      organizationId: options.organizationId,
      rootKeyId: options.rootKey.keyId,
      organizationKeyId,
    }
    owner = Object.freeze({
      version: FORMAT_VERSION,
      ...ownerMetadata,
      wrappedOrganizationKey: wrapKey(options.rootKey.key, material, organizationKeyAad(ownerMetadata)),
    })
  } finally { material?.fill(0) }
  try { await owners.put(OWNER_RECORD_KEY, owner) } catch {
    throw new SoftwareLocalKmsError('storage-failed')
  }
  const rehydrated = unwrapKey(options.rootKey.key, owner.wrappedOrganizationKey, organizationKeyAad(owner))
  try { return { owner, organizationKey: createAesKey(rehydrated) } }
  finally { rehydrated.fill(0) }
}

/**
 * Open one organization-owned wrapped-key store over the existing storage-domain facility.
 * `tenantId` must equal the authenticated organization so PostgreSQL RLS cannot be accidentally bypassed.
 * The caller owns the returned handle and must await `close()`, including after its lifecycle signal aborts.
 */
export async function openSoftwareLocalDisclosureKeyStore(
  facility: DomainFacility,
  options: SoftwareLocalDisclosureKeyStoreOptions,
): Promise<SoftwareLocalDisclosureKeyStore> {
  const organizationId = brandString<DisclosureDataKeyGrantScope['organizationId']>(
    identifier(options.organizationId, 'invalid-input'),
  )
  const rootKeyId = identifier(options.rootKey.keyId, 'invalid-root-key')
  const rootKey = options.rootKey.key
  requireAes256Key(rootKey, 'invalid-root-key')
  requireKms(options.storage.tenantId === organizationId, 'scope-mismatch')
  softwareLocalDisclosureKeyDomainName(options.storage.domainNamePrefix, organizationId)
  const maxDataKeys = positiveInteger(options.limits.maxDataKeys)
  const maxPendingOperations = positiveInteger(options.limits.maxPendingOperations)
  const signal = options.signal
  requireKms(signal instanceof AbortSignal && !signal.aborted, 'closed')
  const resolved: SoftwareLocalDisclosureKeyStoreOptions = Object.freeze({
    organizationId,
    rootKey: Object.freeze({ keyId: rootKeyId, key: rootKey }),
    storage: Object.freeze({ domainNamePrefix: options.storage.domainNamePrefix,
      tenantId: options.storage.tenantId }),
    limits: Object.freeze({ maxDataKeys, maxPendingOperations }),
    signal,
  })

  let domain: StoreDomain
  try { domain = await facility.open(storeSpecification(resolved)) } catch {
    throw new SoftwareLocalKmsError('invalid-storage')
  }
  try {
    requireKms(!resolved.signal.aborted, 'closed')
    const { owner, organizationKey } = await bootstrapOwner(domain, resolved)
    const table = domain.table('data_keys')
    requireKms(table.size <= resolved.limits.maxDataKeys, 'invalid-storage')
    for (const [key, record] of table.entries()) {
      requireKms(record.organizationKeyId === owner.organizationKeyId
        && record.scope.organizationId === resolved.organizationId
        && key === dataKeyRecordKey(record.scope, record.keyId), 'invalid-storage')
      const material = unwrapKey(organizationKey, record.wrappedDataKey, dataKeyAad(record))
      material.fill(0)
    }
    requireKms(!resolved.signal.aborted, 'closed')
    return new SoftwareLocalDisclosureKeyStore(domain, owner, organizationKey, resolved)
  } catch (error) {
    // Cleanup must never replace a sanitized authentication/storage failure with backend diagnostics.
    try { await domain.close() } catch {}
    if (error instanceof SoftwareLocalKmsError) throw error
    throw new SoftwareLocalKmsError('invalid-storage')
  }
}

/** Single-process owner for one RLS tenant; writes are serialized and ambiguous failures quarantine the handle. */
export class SoftwareLocalDisclosureKeyStore {
  readonly protection = SOFTWARE_LOCAL_KEY_PROTECTION
  private readonly controller = new AbortController()
  private chain: Promise<void> = Promise.resolve()
  private pending = 0
  private unavailable = false
  private disposal: Promise<void> | undefined
  private organizationKey: KeyObject | undefined
  private readonly abort: () => void
  private readonly organizationId: DisclosureDataKeyGrantScope['organizationId']
  private readonly limits: SoftwareLocalDisclosureKeyStoreOptions['limits']
  private readonly lifecycleSignal: AbortSignal

  /** Constructed only after the complete durable key hierarchy authenticates. */
  constructor(
    private readonly domain: StoreDomain,
    private readonly owner: OwnerRecord,
    organizationKey: KeyObject,
    options: SoftwareLocalDisclosureKeyStoreOptions,
  ) {
    this.organizationKey = organizationKey
    this.organizationId = options.organizationId
    this.limits = Object.freeze({ ...options.limits })
    this.lifecycleSignal = options.signal
    this.abort = () => { this.controller.abort() }
    this.lifecycleSignal.addEventListener('abort', this.abort, { once: true })
    if (this.lifecycleSignal.aborted) this.abort()
  }

  /** Persist a Harness-generated DEK before acknowledging it; exact retries are idempotent. */
  publishDataKey(scope: DisclosureDataKeyGrantScope, dataKey: DisclosureDataKey,
    signal: AbortSignal): Promise<SoftwareLocalDisclosureKeyReceipt> {
    const captured = parseScope(scope)
    requireKms(captured.organizationId === this.organizationId, 'scope-mismatch')
    const keyId = brandString<DisclosureDataKeyId>(identifier(dataKey.keyId, 'invalid-input'))
    const candidateKey = dataKey.key
    requireAes256Key(candidateKey, 'invalid-input')
    requireKms(dataKey.scope !== undefined
      && dataKey.scope.organizationId === captured.organizationId
      && dataKey.scope.instanceId === captured.instanceId
      && dataKey.scope.conversationId === captured.conversationId, 'scope-mismatch')
    return this.run(signal, async () => {
      const table = this.domain.table('data_keys')
      const recordKey = dataKeyRecordKey(captured, keyId)
      const existing = table.get(recordKey)
      if (existing !== undefined) {
        requireKms(sameScope(existing.scope, captured) && existing.keyId === keyId, 'invalid-storage')
        const retained = unwrapKey(this.requireOrganizationKey(), existing.wrappedDataKey, dataKeyAad(existing))
        const candidate = exportKey(candidateKey, 'invalid-input')
        try { requireKms(timingSafeEqual(retained, candidate), 'conflict') }
        finally { retained.fill(0); candidate.fill(0) }
        return receipt(captured, keyId)
      }
      requireKms(table.size < this.limits.maxDataKeys, 'limit')
      const material = exportKey(candidateKey, 'invalid-input')
      let record: DataKeyRecord
      try {
        record = Object.freeze({
          version: FORMAT_VERSION,
          organizationKeyId: this.owner.organizationKeyId,
          scope: captured,
          keyId,
          wrappedDataKey: wrapKey(this.requireOrganizationKey(), material, dataKeyAad({
            organizationKeyId: this.owner.organizationKeyId, scope: captured, keyId,
          })),
        })
      } finally { material.fill(0) }
      try { await table.put(recordKey, record) } catch {
        this.isolate()
        throw new SoftwareLocalKmsError('storage-failed')
      }
      this.assertLive(signal)
      return receipt(captured, keyId)
    })
  }

  /** Return all authenticated current/historical keys for one exact disclosure scope. */
  readDataKeys(scope: DisclosureDataKeyGrantScope, signal: AbortSignal): Promise<readonly DisclosureDataKey[]> {
    const captured = parseScope(scope)
    requireKms(captured.organizationId === this.organizationId, 'scope-mismatch')
    return this.run(signal, () => {
      const records = [...this.domain.table('data_keys').entries()]
        .map(([, record]) => record)
        .filter(record => sameScope(record.scope, captured))
        .sort((left, right) => left.keyId.localeCompare(right.keyId))
      requireKms(records.length > 0, 'not-found')
      return Object.freeze(records.map((record): DisclosureDataKey => {
        const material = unwrapKey(this.requireOrganizationKey(), record.wrappedDataKey, dataKeyAad(record))
        try {
          return Object.freeze({
            keyId: record.keyId,
            scope: Object.freeze({
              organizationId: record.scope.organizationId,
              instanceId: record.scope.instanceId,
              conversationId: record.scope.conversationId,
            }),
            key: createAesKey(material),
          })
        } finally { material.fill(0) }
      }))
    })
  }

  /** Reauthenticate every cached wrapped DEK; readiness never claims hardware protection. */
  checkReadiness(signal: AbortSignal): Promise<boolean> {
    return this.run(signal, () => {
      for (const [, record] of this.domain.table('data_keys').entries()) {
        const material = unwrapKey(this.requireOrganizationKey(), record.wrappedDataKey, dataKeyAad(record))
        material.fill(0)
      }
      return true
    })
  }

  /** Abort admission, drain already-started operations, and release the tenant domain. */
  close(): Promise<void> {
    if (this.disposal === undefined) {
      this.controller.abort()
      this.lifecycleSignal.removeEventListener('abort', this.abort)
      this.disposal = this.chain.then(async () => {
        this.organizationKey = undefined
        try { await this.domain.close() } catch { throw new SoftwareLocalKmsError('storage-failed') }
      })
    }
    return this.disposal
  }

  private requireOrganizationKey(): KeyObject {
    this.assertLive()
    requireKms(this.organizationKey !== undefined, 'closed')
    return this.organizationKey
  }

  private assertLive(signal?: AbortSignal): void {
    requireKms(!this.unavailable, 'unavailable')
    requireKms(!this.controller.signal.aborted && !this.lifecycleSignal.aborted
      && (signal === undefined || !signal.aborted), 'closed')
  }

  private isolate(): void {
    this.unavailable = true
    this.controller.abort()
  }

  private run<T>(signal: AbortSignal, job: () => T | Promise<T>): Promise<T> {
    requireKms(signal instanceof AbortSignal, 'invalid-input')
    this.assertLive(signal)
    requireKms(this.pending < this.limits.maxPendingOperations, 'limit')
    this.pending++
    const result = this.chain.then(() => { this.assertLive(signal); return job() })
    this.chain = result.then(() => { this.pending-- }, () => { this.pending-- })
    return result
  }
}
