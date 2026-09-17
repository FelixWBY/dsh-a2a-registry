/** Lazy organization runtime routing for the SaaS Registry. */
import { createHash } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import type { RegistryAccountId, RegistryOrganizationAccess, RegistryTenancyStore } from './tenancy.ts'
import { RegistryTenancyError } from './tenancy.ts'
import { openRegistryTenantRuntime, type RegistryIngestRuntimeConfig,
  type RegistryTenantRuntime } from './ingest-runtime.ts'
import { RegistryOperationalAlertExporter } from './operational-alerts.ts'

/** Account and organization control plane plus isolated data-plane runtime selection. */
export interface RegistryTenantRuntimeRouter {
  readonly tenancy: RegistryTenancyStore
  listOrganizations(accountId: RegistryAccountId): Promise<readonly RegistryOrganizationAccess[]>
  runtimeForAccount(accountId: RegistryAccountId, organizationId: OrganizationId):
  Promise<{ readonly access: RegistryOrganizationAccess; readonly lease: RegistryTenantRuntimeLease } | null>
  acquireRuntime(organizationId: OrganizationId): Promise<RegistryTenantRuntimeLease>
  provision(access: RegistryOrganizationAccess, ownerDisplayName: string): Promise<RegistryTenantRuntimeLease>
  close(): Promise<void>
}

/** One reference to a resident organization runtime. Release is idempotent and the lease cannot be reused. */
export interface RegistryTenantRuntimeLease {
  readonly runtime: RegistryTenantRuntime
  release(): void
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    registryTenantRouter: RegistryTenantRuntimeRouter
  }
}

function physicalDomainName(organizationId: OrganizationId, legacyOrganizationId: OrganizationId): string {
  if (organizationId === legacyOrganizationId) return 'a2a_registry_ingest'
  const digest = createHash('sha256').update(organizationId, 'utf8').digest('hex').slice(0, 32)
  return `a2a_registry_ingest_${digest}`
}

/** Single-process lazy runtime router. Each organization retains the existing exclusive owner semantics. */
export class DefaultRegistryTenantRuntimeRouter implements RegistryTenantRuntimeRouter {
  private readonly runtimes = new Map<OrganizationId, {
    readonly pending: Promise<RegistryTenantRuntime>
    references: number
    lastUsed: number
  }>()
  private readonly alerts: RegistryOperationalAlertExporter | undefined
  private allocation = Promise.resolve()
  private accessSequence = 0
  private closing: Promise<void> | undefined

  constructor(private readonly ctx: Context, readonly tenancy: RegistryTenancyStore,
    private readonly template: RegistryIngestRuntimeConfig,
    private readonly legacyOrganizationId: OrganizationId,
    private readonly maxActiveOrganizations: number) {
    this.alerts = template.alerts === undefined ? undefined : new RegistryOperationalAlertExporter(ctx, template.alerts)
  }

  listOrganizations(accountId: RegistryAccountId): Promise<readonly RegistryOrganizationAccess[]> {
    return this.tenancy.listOrganizations(accountId)
  }

  async runtimeForAccount(accountId: RegistryAccountId, organizationId: OrganizationId):
  Promise<{ readonly access: RegistryOrganizationAccess; readonly lease: RegistryTenantRuntimeLease } | null> {
    const access = await this.tenancy.getOrganizationForAccount(accountId, organizationId)
    if (access === null || access.membership.state !== 'active' || access.organization.state !== 'active') return null
    return { access, lease: await this.acquire(organizationId, undefined) }
  }

  async acquireRuntime(organizationId: OrganizationId): Promise<RegistryTenantRuntimeLease> {
    const organization = await this.tenancy.getOrganizationInternal(organizationId)
    if (organization === null || organization.state !== 'active') throw new RegistryTenancyError('not-found')
    return this.acquire(organizationId, organizationId === this.legacyOrganizationId
      ? this.template.directory?.bootstrapOwner : undefined)
  }

  async provision(access: RegistryOrganizationAccess, ownerDisplayName: string): Promise<RegistryTenantRuntimeLease> {
    if (access.membership.role !== 'owner' || access.membership.state !== 'active'
      || (access.organization.state !== 'provisioning' && access.organization.state !== 'failed')) {
      throw new RegistryTenancyError('not-found')
    }
    if (this.template.directory === undefined) throw new RegistryTenancyError('unavailable')
    let lease: RegistryTenantRuntimeLease | undefined
    try {
      lease = await this.acquire(access.organization.organizationId, {
        memberId: access.membership.memberId,
        displayName: ownerDisplayName,
      })
      await this.tenancy.markOrganizationState(access.organization.organizationId, 'active')
      return lease
    } catch (error) {
      lease?.release()
      await this.tenancy.markOrganizationState(access.organization.organizationId, 'failed').catch(() => undefined)
      throw error
    }
  }

  close(): Promise<void> {
    this.closing ??= this.serialize(async () => {
      const pending = [...this.runtimes.values()].map(entry => entry.pending)
      this.runtimes.clear()
      const runtimes = await Promise.allSettled(pending)
      const closes = runtimes.flatMap((result) => result.status === 'fulfilled' ? [result.value.close()] : [])
      const outcomes = await Promise.allSettled([...closes, this.alerts?.close(), this.tenancy.close()])
      if (outcomes.some(outcome => outcome.status === 'rejected')) throw new Error('Registry tenant router cleanup failed')
    })
    return this.closing
  }

  private async acquire(organizationId: OrganizationId,
    bootstrapOwner: { readonly memberId: MemberId; readonly displayName: string } | undefined):
  Promise<RegistryTenantRuntimeLease> {
    if (this.closing !== undefined) throw new RegistryTenancyError('closed')
    const current = this.runtimes.get(organizationId)
    if (current !== undefined) return this.lease(organizationId, current)
    return this.serialize(async () => {
      if (this.closing !== undefined) throw new RegistryTenancyError('closed')
      const retained = this.runtimes.get(organizationId)
      if (retained !== undefined) return this.lease(organizationId, retained)
      if (this.runtimes.size >= this.maxActiveOrganizations) {
        const idle = [...this.runtimes.entries()]
          .filter(([, entry]) => entry.references === 0)
          .sort((left, right) => left[1].lastUsed - right[1].lastUsed)[0]
        if (idle === undefined) throw new RegistryTenancyError('unavailable')
        this.runtimes.delete(idle[0])
        const evicted = await idle[1].pending.catch(() => undefined)
        await evicted?.close()
      }
      const directory = this.template.directory === undefined ? undefined
        : { ...this.template.directory, bootstrapOwner }
      const config: RegistryIngestRuntimeConfig = {
        ...this.template,
        organizationId,
        ...(directory === undefined ? {} : { directory }),
      }
      const entry = {
        pending: openRegistryTenantRuntime(this.ctx, config, {
          storage: {
            domainName: physicalDomainName(organizationId, this.legacyOrganizationId),
            tenantId: organizationId,
          },
          ...(this.alerts === undefined ? {} : { alerts: this.alerts }),
        }),
        references: 1,
        lastUsed: ++this.accessSequence,
      }
      this.runtimes.set(organizationId, entry)
      try {
        const runtime = await entry.pending
        return this.createdLease(organizationId, entry, runtime)
      } catch (error) {
        if (this.runtimes.get(organizationId) === entry) this.runtimes.delete(organizationId)
        throw error
      }
    })
  }

  private async lease(organizationId: OrganizationId,
    entry: { readonly pending: Promise<RegistryTenantRuntime>; references: number; lastUsed: number }):
  Promise<RegistryTenantRuntimeLease> {
    entry.references += 1
    entry.lastUsed = ++this.accessSequence
    try {
      return this.createdLease(organizationId, entry, await entry.pending)
    } catch (error) {
      this.release(organizationId, entry)
      throw error
    }
  }

  private createdLease(organizationId: OrganizationId,
    entry: { readonly pending: Promise<RegistryTenantRuntime>; references: number; lastUsed: number },
    runtime: RegistryTenantRuntime): RegistryTenantRuntimeLease {
    let released = false
    return Object.freeze({
      runtime,
      release: () => {
        if (released) return
        released = true
        this.release(organizationId, entry)
      },
    })
  }

  private release(organizationId: OrganizationId,
    entry: { readonly pending: Promise<RegistryTenantRuntime>; references: number; lastUsed: number }): void {
    if (entry.references <= 0) return
    entry.references -= 1
    entry.lastUsed = ++this.accessSequence
    // A removed entry is already closing or closed; references only protect entries while resident.
    if (this.runtimes.get(organizationId) !== entry) return
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.allocation.then(operation, operation)
    this.allocation = result.then(() => undefined, () => undefined)
    return result
  }
}
