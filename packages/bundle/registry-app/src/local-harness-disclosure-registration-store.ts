/** Durable replay and idempotency ledger for the test-only loopback disclosure registration endpoint. */
import { createHash } from 'node:crypto'
import type { InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DisclosureId, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { RegistryIngestReceipt } from '@deepseek-ai/dsh-a2a-registry-ingest'
import { defineDomain, domainTable, type Domain, type DomainFacility, type KvTable } from '@deepseek-ai/dsh-storage-domain'
import { z } from 'zod'

const DIGEST = /^sha256:[a-f0-9]{64}$/u
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const CONFIGURATION_KEY = 'configuration'

const configurationRecordSchema = z.strictObject({ configurationHash: z.string().regex(DIGEST) }).readonly()
const nonceRecordSchema = z.strictObject({
  expiresAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
}).readonly()
const registrationRecordSchema = z.strictObject({
  requestHash: z.string().regex(DIGEST),
  authorizationVersion: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
}).readonly()

type ConfigurationKey = typeof CONFIGURATION_KEY
type Digest = `sha256:${string}`
type ConfigurationRecord = z.infer<typeof configurationRecordSchema>
type NonceRecord = z.infer<typeof nonceRecordSchema>
type RegistrationRecord = z.infer<typeof registrationRecordSchema>

function byteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

function specification(maxRecordBytes: number) {
  const boundedRegistration = registrationRecordSchema.superRefine((record, context) => {
    if (byteLength(record) > maxRecordBytes) {
      context.addIssue({ code: 'custom', message: 'record exceeds configured limit' })
    }
  })
  return defineDomain({
    name: 'a2a_registry_local_disclosure_registrations', version: 1, layout: 'single', tables: {
      configuration: domainTable<ConfigurationKey, ConfigurationRecord>(configurationRecordSchema),
      nonces: domainTable<Digest, NonceRecord>(nonceRecordSchema),
      registrations: domainTable<DisclosureId, RegistrationRecord>(boundedRegistration),
    },
  })
}

/** Identity and resource bounds permanently attached to one endpoint ledger. */
export interface LocalDisclosureRegistrationStoreConfig {
  readonly organizationId: OrganizationId
  readonly sourceInstanceId: DshInstanceId
  readonly sourceKeyId: InstanceKeyId
  readonly sourcePublicKeySpki: string
  readonly sourceKeyValidFrom: number
  readonly sharedSecretEnv: string
  readonly clockSkewMs: number
  readonly maxReplayEntries: number
  readonly maxRegistrations: number
  readonly maxRecordBytes: number
}

export type LocalDisclosureRegistrationStoreFailure = 'replay' | 'conflict' | 'limit' | 'unavailable'

/** Metadata-only store failure safe to expose through the local endpoint's fixed error map. */
export class LocalDisclosureRegistrationStoreError extends Error {
  constructor(readonly code: LocalDisclosureRegistrationStoreFailure) {
    super(code)
    this.name = 'LocalDisclosureRegistrationStoreError'
  }
}

function digest(value: string): Digest {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`
}

function configurationHash(config: LocalDisclosureRegistrationStoreConfig): Digest {
  return digest(JSON.stringify({
    organizationId: config.organizationId,
    sourceInstanceId: config.sourceInstanceId,
    sourceKeyId: config.sourceKeyId,
    sourcePublicKeySpki: config.sourcePublicKeySpki,
    sourceKeyValidFrom: config.sourceKeyValidFrom,
    sharedSecretEnv: config.sharedSecretEnv,
    clockSkewMs: config.clockSkewMs,
    maxReplayEntries: config.maxReplayEntries,
    maxRegistrations: config.maxRegistrations,
    maxRecordBytes: config.maxRecordBytes,
  }))
}

/** One fail-closed serialized owner for durable nonce replay and exact registration retries. */
export class LocalDisclosureRegistrationStore {
  private readonly configurations: KvTable<ConfigurationKey, ConfigurationRecord>
  private readonly nonces: KvTable<Digest, NonceRecord>
  private readonly registrations: KvTable<DisclosureId, RegistrationRecord>
  private readonly abort = new AbortController()
  private chain = Promise.resolve()
  private disposal: Promise<void> | undefined
  private unavailable = false

  private constructor(private readonly domain: Domain<ReturnType<typeof specification>>,
    private readonly config: LocalDisclosureRegistrationStoreConfig) {
    this.configurations = domain.table('configuration')
    this.nonces = domain.table('nonces')
    this.registrations = domain.table('registrations')
  }

  /** Open and bind retained state before the route becomes reachable. */
  static async open(facility: DomainFacility, config: LocalDisclosureRegistrationStoreConfig,
    now = Date.now()): Promise<LocalDisclosureRegistrationStore> {
    let domain: Domain<ReturnType<typeof specification>>
    try { domain = await facility.open(specification(config.maxRecordBytes)) } catch {
      throw new LocalDisclosureRegistrationStoreError('unavailable')
    }
    const owner = new LocalDisclosureRegistrationStore(domain, structuredClone(config))
    try {
      await owner.initialize(now)
      return owner
    } catch (error) {
      owner.unavailable = true
      owner.abort.abort()
      await domain.close().catch(() => undefined)
      if (error instanceof LocalDisclosureRegistrationStoreError) throw error
      throw new LocalDisclosureRegistrationStoreError('unavailable')
    }
  }

  /** Persist a nonce before performing any operation selected by its signed request. */
  reserveNonce(nonce: string, expiresAt: number, now = Date.now()): Promise<void> {
    return this.run(async () => {
      if (!Number.isSafeInteger(expiresAt) || expiresAt < now) {
        throw new LocalDisclosureRegistrationStoreError('unavailable')
      }
      await this.removeExpiredNonces(now)
      const key = digest(nonce)
      if (this.nonces.get(key) !== undefined) throw new LocalDisclosureRegistrationStoreError('replay')
      if (this.nonces.size >= this.config.maxReplayEntries) {
        throw new LocalDisclosureRegistrationStoreError('limit')
      }
      await this.write(() => this.nonces.put(key, Object.freeze({ expiresAt })))
    })
  }

  /** Run one Registry-exact-idempotent registration and record only a confirmed Registry success. */
  register(disclosureId: DisclosureId, requestHash: Digest,
    execute: () => Promise<RegistryIngestReceipt>): Promise<RegistryIngestReceipt> {
    return this.run(async () => {
      const retained = this.registrations.get(disclosureId)
      if (retained !== undefined && retained.requestHash !== requestHash) {
        throw new LocalDisclosureRegistrationStoreError('conflict')
      }
      if (retained !== undefined) {
        return { disclosureId, authorizationVersion: retained.authorizationVersion,
          lastDisclosureSeq: -1, lastEventHash: null, checkpointHash: null,
          control: 'active', ingest: 'pending' }
      }
      if (this.registrations.size >= this.config.maxRegistrations) {
        throw new LocalDisclosureRegistrationStoreError('limit')
      }
      const receipt = await execute()
      const completed = Object.freeze({ requestHash, authorizationVersion: receipt.authorizationVersion })
      if (byteLength(completed) > this.config.maxRecordBytes) {
        throw new LocalDisclosureRegistrationStoreError('limit')
      }
      await this.write(() => this.registrations.put(disclosureId, completed))
      return receipt
    })
  }

  /** Stop admission, drain accepted operations, then release the durable domain. */
  close(): Promise<void> {
    this.abort.abort()
    this.disposal ??= this.chain.then(async () => {
      try { await this.domain.close() } catch {
        this.unavailable = true
        throw new LocalDisclosureRegistrationStoreError('unavailable')
      }
    })
    return this.disposal
  }

  private async initialize(now: number): Promise<void> {
    if (!Number.isSafeInteger(now) || now < 0) throw new LocalDisclosureRegistrationStoreError('unavailable')
    const largestRecord = { requestHash: `sha256:${'f'.repeat(64)}`,
      authorizationVersion: Number.MAX_SAFE_INTEGER }
    if (byteLength(largestRecord) > this.config.maxRecordBytes) {
      throw new LocalDisclosureRegistrationStoreError('unavailable')
    }
    const expected = Object.freeze({ configurationHash: configurationHash(this.config) })
    const retained = this.configurations.get(CONFIGURATION_KEY)
    if (retained === undefined) await this.write(() => this.configurations.put(CONFIGURATION_KEY, expected))
    else if (retained.configurationHash !== expected.configurationHash) {
      throw new LocalDisclosureRegistrationStoreError('unavailable')
    }
    for (const [key] of this.nonces.entries()) {
      if (!DIGEST.test(key)) throw new LocalDisclosureRegistrationStoreError('unavailable')
    }
    for (const [key] of this.registrations.entries()) {
      if (!IDENTIFIER.test(key)) throw new LocalDisclosureRegistrationStoreError('unavailable')
    }
    await this.removeExpiredNonces(now)
    if (this.nonces.size > this.config.maxReplayEntries || this.registrations.size > this.config.maxRegistrations) {
      throw new LocalDisclosureRegistrationStoreError('unavailable')
    }
  }

  private async removeExpiredNonces(now: number): Promise<void> {
    const expired = [...this.nonces.entries()].filter(([, record]) => record.expiresAt < now)
      .sort(([left], [right]) => left.localeCompare(right))
    for (const [key] of expired) await this.write(() => this.nonces.delete(key))
  }

  private run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.abort.signal.aborted || this.unavailable) {
      return Promise.reject(new LocalDisclosureRegistrationStoreError('unavailable'))
    }
    const result = this.chain.then(async () => {
      if (this.abort.signal.aborted || this.unavailable) {
        throw new LocalDisclosureRegistrationStoreError('unavailable')
      }
      return operation()
    })
    this.chain = result.then(() => {}, () => {})
    return result
  }

  private async write<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation() } catch {
      this.unavailable = true
      this.abort.abort()
      throw new LocalDisclosureRegistrationStoreError('unavailable')
    }
  }
}
