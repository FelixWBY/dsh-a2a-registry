/** Production assembly for the deliberately single-instance software disclosure-key provider. */
import { createSecretKey, type KeyObject } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import {
  encodeDisclosureDataKeyGrant,
  type DisclosureDataKey, type DisclosureDataKeyGrantScope,
} from '@deepseek-ai/dsh-a2a-disclosure-crypto'
import {
  openSoftwareLocalDisclosureKeyStore,
  SOFTWARE_LOCAL_KEY_PROTECTION,
  SoftwareLocalKmsError,
  type SoftwareLocalDisclosureKeyStore,
} from '@deepseek-ai/dsh-a2a-registry-kms-software'
import {
  decodeRegistryImportKeyGrant,
  RegistryDisclosureKeyProvider,
  type RegistryImportKeyGrant,
  type RegistryDisclosureKeyReceipt,
} from '@deepseek-ai/dsh-registry-app/src/disclosure-key-provider.ts'
import { credentialRef, type ResolvedCredential } from '@deepseek-ai/dsh-credentials'
import type { DomainFacility } from '@deepseek-ai/dsh-storage-domain'

/** The only environment entry allowed to carry the software root-key material. */
export const DISCLOSURE_ROOT_KEY_ENV = 'DSH_REGISTRY_DISCLOSURE_ROOT_KEY'

/** Loader configuration. `singleInstance` is an explicit acknowledgement, not a deployment default. */
export interface Config {
  readonly singleInstance: true
  readonly rootKeyId: string
  readonly domainNamePrefix: string
  readonly maxDataKeysPerOrganization: number
  readonly maxPendingOperationsPerOrganization: number
  readonly maxActiveOrganizations: number
}

const positive = () => z.natural().min(1).max(Number.MAX_SAFE_INTEGER).required()
const identifier = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/
const domainPrefix = /^[a-z][a-z0-9_]{0,62}$/

/** Strict loader schema; software-local mode cannot start without the single-writer acknowledgement. */
export const Config: z<Config> = z.object({
  singleInstance: z.const(true).required(),
  rootKeyId: z.string().pattern(identifier).required(),
  domainNamePrefix: z.string().pattern(domainPrefix).default('a2a_registry_disclosure_keys'),
  maxDataKeysPerOrganization: positive().default(10_000),
  maxPendingOperationsPerOrganization: positive().default(64),
  maxActiveOrganizations: positive().max(10_000).default(256),
})

/** Private Cordis plugin name; deployments select this concrete provider explicitly. */
export const name = 'registry-kms-software-app'
/** Storage and an environment-aware credential provider are mandatory production dependencies. */
export const inject = ['storageDomain', 'credentials']

interface StoreEntry {
  readonly pending: Promise<SoftwareLocalDisclosureKeyStore>
  references: number
  lastUsed: number
  idleWaiters: Array<() => void>
}

interface StoreLease {
  readonly store: SoftwareLocalDisclosureKeyStore
  release(): Promise<void>
}

function closed(): SoftwareLocalKmsError {
  return new SoftwareLocalKmsError('closed')
}

function assertSignal(signal: AbortSignal): void {
  if (!(signal instanceof AbortSignal)) throw new SoftwareLocalKmsError('invalid-input')
  if (signal.aborted) throw closed()
}

/**
 * Decode one already-resolved secret as exactly one canonical unpadded base64url AES-256 key.
 * The returned KeyObject owns its OpenSSL copy; the temporary JavaScript Buffer is always zeroed.
 */
export function parseDisclosureRootKey(encoded: string): KeyObject {
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
    throw new Error(`${DISCLOSURE_ROOT_KEY_ENV} must contain one canonical unpadded base64url 256-bit key`)
  }
  const material = Buffer.from(encoded, 'base64url')
  try {
    if (material.byteLength !== 32 || material.toString('base64url') !== encoded) {
      throw new Error(`${DISCLOSURE_ROOT_KEY_ENV} must contain one canonical unpadded base64url 256-bit key`)
    }
    return createSecretKey(material)
  } finally {
    material.fill(0)
  }
}

/**
 * One process-local service over lazily opened organization stores.
 * Entries are reference-counted while calls run and only idle entries may be evicted.
 */
export class SoftwareLocalRegistryDisclosureKeyProvider extends RegistryDisclosureKeyProvider {
  readonly protection = SOFTWARE_LOCAL_KEY_PROTECTION
  private readonly entries = new Map<DisclosureDataKeyGrantScope['organizationId'], StoreEntry>()
  private readonly lifecycle = new AbortController()
  private allocation: Promise<void> = Promise.resolve()
  private accessSequence = 0
  private closing: Promise<void> | undefined
  private rootKey: KeyObject | undefined

  constructor(ctx: Context, private readonly facility: DomainFacility,
    private readonly config: Config, rootKey: KeyObject) {
    super(ctx)
    this.rootKey = rootKey
  }

  publishDataKey(scope: DisclosureDataKeyGrantScope, dataKey: DisclosureDataKey,
    signal: AbortSignal): Promise<RegistryDisclosureKeyReceipt> {
    return this.withStore(scope.organizationId, signal,
      store => store.publishDataKey(scope, dataKey, signal))
  }

  readDataKeys(scope: DisclosureDataKeyGrantScope,
    maxKeys: number, signal: AbortSignal): Promise<readonly DisclosureDataKey[]> {
    return this.withStore(scope.organizationId, signal,
      store => store.readDataKeys(scope, maxKeys, signal))
  }

  async issueAuthorizedGrant(scope: DisclosureDataKeyGrantScope,
    maxKeys: number, maxBytes: number, signal: AbortSignal): Promise<RegistryImportKeyGrant> {
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new SoftwareLocalKmsError('invalid-input')
    const keys = await this.readDataKeys(scope, maxKeys, signal)
    assertSignal(signal)
    if (keys.length === 0) throw new SoftwareLocalKmsError('not-found')
    if (keys.length > maxKeys) throw new SoftwareLocalKmsError('limit')
    let payload: unknown
    try {
      const encoded = encodeDisclosureDataKeyGrant('registry-app', scope, keys)
      if (encoded.record.kind !== 'grant') throw new Error('invalid grant')
      payload = encoded.record.payload
    } catch { throw new SoftwareLocalKmsError('invalid-storage') }
    const serialized = JSON.stringify(payload)
    if (typeof serialized !== 'string') throw new SoftwareLocalKmsError('invalid-storage')
    if (Buffer.byteLength(serialized, 'utf8') > maxBytes) throw new SoftwareLocalKmsError('limit')
    try { return decodeRegistryImportKeyGrant(payload, scope, maxKeys, maxBytes) } catch {
      throw new SoftwareLocalKmsError('invalid-storage')
    }
  }

  checkReadiness(organizationId: DisclosureDataKeyGrantScope['organizationId'],
    signal: AbortSignal): Promise<boolean> {
    return this.withStore(organizationId, signal, store => store.checkReadiness(signal))
  }

  /** Stop admission, drain every borrowed store, close all domains, then release the root-key handle. */
  close(): Promise<void> {
    this.closing ??= this.closeAll()
    return this.closing
  }

  private async withStore<T>(organizationId: DisclosureDataKeyGrantScope['organizationId'],
    signal: AbortSignal, operation: (store: SoftwareLocalDisclosureKeyStore) => Promise<T>): Promise<T> {
    assertSignal(signal)
    const lease = await this.acquire(organizationId)
    try {
      assertSignal(signal)
      return await operation(lease.store)
    } finally {
      await lease.release()
    }
  }

  private async acquire(organizationId: DisclosureDataKeyGrantScope['organizationId']): Promise<StoreLease> {
    const entry = await this.serialize(async () => {
      if (this.closing !== undefined) throw closed()
      const retained = this.entries.get(organizationId)
      if (retained !== undefined) {
        retained.references += 1
        retained.lastUsed = ++this.accessSequence
        return retained
      }
      if (this.entries.size >= this.config.maxActiveOrganizations) {
        const idle = [...this.entries.entries()]
          .filter(([, candidate]) => candidate.references === 0)
          .sort((left, right) => left[1].lastUsed - right[1].lastUsed)[0]
        if (idle === undefined) throw new SoftwareLocalKmsError('limit')
        this.entries.delete(idle[0])
        const evicted = await idle[1].pending.catch(() => undefined)
        await evicted?.close()
      }
      if (this.closing !== undefined) throw closed()
      const rootKey = this.rootKey
      if (rootKey === undefined) throw closed()
      const created: StoreEntry = {
        pending: openSoftwareLocalDisclosureKeyStore(this.facility, {
          organizationId,
          rootKey: { keyId: this.config.rootKeyId, key: rootKey },
          storage: { domainNamePrefix: this.config.domainNamePrefix, tenantId: organizationId },
          limits: {
            maxDataKeys: this.config.maxDataKeysPerOrganization,
            maxPendingOperations: this.config.maxPendingOperationsPerOrganization,
          },
          signal: this.lifecycle.signal,
        }),
        references: 1,
        lastUsed: ++this.accessSequence,
        idleWaiters: [],
      }
      this.entries.set(organizationId, created)
      void created.pending.catch(() => {
        // A late opening failure must not leave a rejected promise or a poisoned cache entry behind.
        void this.serialize(() => {
          if (this.entries.get(organizationId) === created) this.entries.delete(organizationId)
        }).catch(() => { /* Cache cleanup is content-free and cannot make the observed opening failure less final. */ })
      })
      return created
    })
    try {
      const store = await entry.pending
      let released = false
      return Object.freeze({
        store,
        release: async () => {
          if (released) return
          released = true
          await this.release(entry)
        },
      })
    } catch (error) {
      await this.release(entry)
      throw error
    }
  }

  private release(entry: StoreEntry): Promise<void> {
    return this.serialize(() => {
      if (entry.references <= 0) return
      entry.references -= 1
      entry.lastUsed = ++this.accessSequence
      if (entry.references !== 0) return
      const waiters = entry.idleWaiters.splice(0)
      for (const resolve of waiters) resolve()
    })
  }

  private waitForIdle(entry: StoreEntry): Promise<void> {
    if (entry.references === 0) return Promise.resolve()
    return new Promise(resolve => entry.idleWaiters.push(resolve))
  }

  private async closeAll(): Promise<void> {
    const entries = await this.serialize(() => {
      const retained = [...this.entries.values()]
      this.entries.clear()
      return retained
    })
    await Promise.all(entries.map(entry => this.waitForIdle(entry)))
    this.lifecycle.abort()
    const opened = await Promise.allSettled(entries.map(entry => entry.pending))
    const outcomes = await Promise.allSettled(opened.flatMap(
      result => result.status === 'fulfilled' ? [result.value.close()] : [],
    ))
    this.rootKey = undefined
    if (outcomes.some(outcome => outcome.status === 'rejected')) {
      throw new SoftwareLocalKmsError('storage-failed')
    }
  }

  private serialize<T>(operation: () => T | Promise<T>): Promise<T> {
    const result = this.allocation.then(operation, operation)
    this.allocation = result.then(() => undefined, () => undefined)
    return result
  }
}

/** Resolve the fixed environment-only root secret and mount one provider for this plugin lifetime. */
export async function apply(ctx: Context, config: Config): Promise<void> {
  const options = Config(config)
  let resolved: ResolvedCredential | undefined
  try { resolved = await ctx.credentials.resolve(credentialRef(DISCLOSURE_ROOT_KEY_ENV)) } catch {
    throw new Error(`${DISCLOSURE_ROOT_KEY_ENV} must resolve from the inherited process environment`)
  }
  if (resolved === undefined || resolved.source !== 'env') {
    throw new Error(`${DISCLOSURE_ROOT_KEY_ENV} must resolve from the inherited process environment`)
  }
  const rootKey = parseDisclosureRootKey(resolved.value)
  const provider = new SoftwareLocalRegistryDisclosureKeyProvider(ctx, ctx.storageDomain,
    Object.freeze({ ...options }), rootKey)
  ctx.effect(() => async () => { await provider.close() }, 'registry-kms-software-app: provider lifecycle')
}
