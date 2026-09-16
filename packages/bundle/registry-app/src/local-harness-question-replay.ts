/** Durable replay admission for the authenticated local question endpoint. */
import { createHash } from 'node:crypto'
import type { InstanceKeyId } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { defineDomain, domainTable, type Domain, type DomainFacility, type KvTable } from '@deepseek-ai/dsh-storage-domain'
import { z } from 'zod'

const NONCE_DIGEST = /^sha256:[a-f0-9]{64}$/u
const CONFIGURATION_KEY = 'configuration'

const configurationRecordSchema = z.strictObject({
  configurationHash: z.string().regex(NONCE_DIGEST),
}).readonly()
const nonceRecordSchema = z.strictObject({
  expiresAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
}).readonly()

type ConfigurationKey = typeof CONFIGURATION_KEY
type NonceDigest = `sha256:${string}`
type ConfigurationRecord = z.infer<typeof configurationRecordSchema>
type NonceRecord = z.infer<typeof nonceRecordSchema>

const replaySpecification = defineDomain({
  name: 'a2a_registry_local_question_replay',
  version: 1,
  layout: 'single',
  tables: {
    configuration: domainTable<ConfigurationKey, ConfigurationRecord>(configurationRecordSchema),
    nonces: domainTable<NonceDigest, NonceRecord>(nonceRecordSchema),
  },
})

/** Identity and fixed bounds permanently bound to one replay ledger. */
export interface LocalQuestionReplayConfig {
  readonly organizationId: OrganizationId
  readonly memberId: MemberId
  readonly sourceInstanceId: DshInstanceId
  readonly sourceKeyId: InstanceKeyId
  readonly sharedSecretEnv: string
  readonly clockSkewMs: number
  readonly maxReplayEntries: number
}

export type LocalQuestionReplayFailure = 'replay' | 'unavailable'

/** Stable, body-free failure mapped by the private loopback endpoint. */
export class LocalQuestionReplayError extends Error {
  constructor(readonly code: LocalQuestionReplayFailure) {
    super(code)
    this.name = 'LocalQuestionReplayError'
  }
}

function digest(value: string): NonceDigest {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`
}

function configurationHash(config: LocalQuestionReplayConfig): NonceDigest {
  return digest(JSON.stringify({
    organizationId: config.organizationId,
    memberId: config.memberId,
    sourceInstanceId: config.sourceInstanceId,
    sourceKeyId: config.sourceKeyId,
    sharedSecretEnv: config.sharedSecretEnv,
    clockSkewMs: config.clockSkewMs,
    maxReplayEntries: config.maxReplayEntries,
  }))
}

/** One serialized, fail-closed owner over the deployment's routed JSON storage. */
export class LocalQuestionReplayStore {
  private readonly configurations: KvTable<ConfigurationKey, ConfigurationRecord>
  private readonly nonces: KvTable<NonceDigest, NonceRecord>
  private readonly abort = new AbortController()
  private chain = Promise.resolve()
  private disposal: Promise<void> | undefined
  private unavailable = false

  private constructor(private readonly domain: Domain<typeof replaySpecification>,
    private readonly config: LocalQuestionReplayConfig) {
    this.configurations = domain.table('configuration')
    this.nonces = domain.table('nonces')
  }

  /** Open, bind and clean the durable ledger before endpoint admission begins. */
  static async open(facility: DomainFacility, config: LocalQuestionReplayConfig,
    now = Date.now()): Promise<LocalQuestionReplayStore> {
    let domain: Domain<typeof replaySpecification>
    try { domain = await facility.open(replaySpecification) } catch {
      throw new LocalQuestionReplayError('unavailable')
    }
    const owner = new LocalQuestionReplayStore(domain, structuredClone(config))
    try {
      await owner.initialize(now)
      return owner
    } catch (error) {
      owner.unavailable = true
      owner.abort.abort()
      await domain.close().catch(() => undefined)
      if (error instanceof LocalQuestionReplayError) throw error
      throw new LocalQuestionReplayError('unavailable')
    }
  }

  /** Atomically reject a retained nonce or persist it before its request executes. */
  reserve(nonce: string, expiresAt: number, now = Date.now()): Promise<void> {
    return this.run(async () => {
      if (!Number.isSafeInteger(expiresAt) || expiresAt < now) {
        throw new LocalQuestionReplayError('unavailable')
      }
      await this.removeExpired(now)
      const key = digest(nonce)
      if (this.nonces.get(key) !== undefined) throw new LocalQuestionReplayError('replay')
      if (this.nonces.size >= this.config.maxReplayEntries) {
        throw new LocalQuestionReplayError('unavailable')
      }
      await this.write(() => this.nonces.put(key, Object.freeze({ expiresAt })))
    })
  }

  /** Stop admission, drain accepted reservations, then release the durable domain. */
  close(): Promise<void> {
    this.abort.abort()
    this.disposal ??= this.chain.then(async () => {
      try { await this.domain.close() } catch {
        this.unavailable = true
        throw new LocalQuestionReplayError('unavailable')
      }
    })
    return this.disposal
  }

  private async initialize(now: number): Promise<void> {
    if (!Number.isSafeInteger(now) || now < 0) throw new LocalQuestionReplayError('unavailable')
    const expected = Object.freeze({ configurationHash: configurationHash(this.config) })
    const retained = this.configurations.get(CONFIGURATION_KEY)
    if (retained === undefined) {
      await this.write(() => this.configurations.put(CONFIGURATION_KEY, expected))
    } else if (retained.configurationHash !== expected.configurationHash) {
      throw new LocalQuestionReplayError('unavailable')
    }
    for (const [key] of this.nonces.entries()) {
      if (!NONCE_DIGEST.test(key)) throw new LocalQuestionReplayError('unavailable')
    }
    await this.removeExpired(now)
    if (this.nonces.size > this.config.maxReplayEntries) throw new LocalQuestionReplayError('unavailable')
  }

  private async removeExpired(now: number): Promise<void> {
    const expired = [...this.nonces.entries()]
      .filter(([, record]) => record.expiresAt < now)
      .sort(([left], [right]) => left.localeCompare(right))
    for (const [key] of expired) await this.write(() => this.nonces.delete(key))
  }

  private run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.abort.signal.aborted || this.unavailable) {
      return Promise.reject(new LocalQuestionReplayError('unavailable'))
    }
    const result = this.chain.then(async () => {
      if (this.abort.signal.aborted || this.unavailable) throw new LocalQuestionReplayError('unavailable')
      return operation()
    })
    this.chain = result.then(() => {}, () => {})
    return result
  }

  private async write<T>(operation: () => Promise<T>): Promise<T> {
    try { return await operation() } catch {
      this.unavailable = true
      this.abort.abort()
      throw new LocalQuestionReplayError('unavailable')
    }
  }
}
