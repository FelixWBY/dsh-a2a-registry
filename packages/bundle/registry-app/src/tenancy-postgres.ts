/** PostgreSQL SaaS control plane with transaction-local account/organization RLS contexts. */
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { Pool, type PoolClient } from 'pg'
import {
  RegistryTenancyError,
  type RegistryAccount,
  type RegistryAccountId,
  type RegistryLegacyOrganizationInput,
  type RegistryInvitation,
  type RegistryInvitationClaim,
  type RegistryInvitationCreation,
  type RegistryInvitationCreationInput,
  type RegistryInvitationPreview,
  type RegistryInvitationRole,
  type RegistryInvitationState,
  type RegistryOidcAccountInput,
  type RegistryOrganization,
  type RegistryOrganizationAccess,
  type RegistryOrganizationCreationInput,
  type RegistryOrganizationMembership,
  type RegistryOrganizationState,
  type RegistryTenancyStore,
} from './tenancy.ts'

const SCHEMA_VERSION = 2
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
const IDEMPOTENCY_KEY = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const SCHEMA_NAME = /^[a-z][a-z0-9_]*$/u
const CONTROL_ACCOUNT_CONTEXT = '__registry_control_plane__'
const EMPTY_ORGANIZATION_CONTEXT = ''
const INVITATION_TOKEN = /^[A-Za-z0-9_-]{43}$/u
const DEFAULT_INVITATION_TTL_SECONDS = 3 * 24 * 60 * 60
const MIN_INVITATION_TTL_SECONDS = 5 * 60
const MAX_INVITATION_TTL_SECONDS = 7 * 24 * 60 * 60
const MAX_PENDING_INVITATIONS = 100

export interface PostgresRegistryTenancyConfig {
  readonly connectionString: string
  readonly schema?: string
  /** This independent pool is deliberately small; a transaction-mode pooler may sit in front of it. */
  readonly maxConnections?: number
  readonly idleTimeoutMs?: number
  readonly statementTimeoutMs?: number
  /** Hard per-account creation bound, including failed organizations, to prevent unbounded self-service allocation. */
  readonly maxOrganizationsPerAccount?: number
}

interface AccountRow {
  readonly id: string
  readonly member_id: string
  readonly display_name: string
  readonly created_at: Date
  readonly updated_at: Date
}

interface OrganizationRow {
  readonly id: string
  readonly slug: string
  readonly display_name: string
  readonly state: RegistryOrganizationState
  readonly created_at: Date
  readonly updated_at: Date
}

interface MembershipRow {
  readonly organization_id: string
  readonly account_id: string
  readonly member_id: string
  readonly role: RegistryOrganizationMembership['role']
  readonly state: RegistryOrganizationMembership['state']
  readonly created_at: Date
  readonly updated_at: Date
}

interface OrganizationAccessRow {
  readonly organization_id: string
  readonly organization_slug: string
  readonly organization_display_name: string
  readonly organization_state: RegistryOrganizationState
  readonly organization_created_at: Date
  readonly organization_updated_at: Date
  readonly membership_account_id: string
  readonly membership_member_id: string
  readonly membership_role: RegistryOrganizationMembership['role']
  readonly membership_state: RegistryOrganizationMembership['state']
  readonly membership_created_at: Date
  readonly membership_updated_at: Date
}

interface CreationRow {
  readonly organization_id: string
  readonly request_hash: string
}

interface InvitationRow {
  readonly invitation_id: string
  readonly organization_id: string
  readonly organization_display_name?: string
  readonly role: RegistryInvitationRole
  readonly display_name: string | null
  readonly status: RegistryInvitationState
  readonly expires_at: Date
  readonly created_at: Date
  readonly created_by_member_id: string
  readonly claimed_by_account_id: string | null
  readonly claimed_by_member_id?: string | null
}

function quoteIdentifier(value: string): string {
  if (!SCHEMA_NAME.test(value)) throw new RegistryTenancyError('invalid-input')
  return `"${value}"`
}

function nonEmptyBounded(value: string, maximumBytes: number): boolean {
  return value.length > 0 && value === value.trim() && !/[\u0000-\u001f\u007f]/u.test(value)
    && Buffer.byteLength(value, 'utf8') <= maximumBytes
}

function accountId(value: string): RegistryAccountId {
  if (!UUID.test(value)) throw new RegistryTenancyError('invalid-input')
  return brandString<RegistryAccountId>(value)
}

function organizationId(value: string): OrganizationId {
  if (!IDENTIFIER.test(value)) throw new RegistryTenancyError('invalid-input')
  return brandString<OrganizationId>(value)
}

function memberId(value: string): MemberId {
  if (!IDENTIFIER.test(value)) throw new RegistryTenancyError('invalid-input')
  return brandString<MemberId>(value)
}

function milliseconds(value: Date): number {
  const result = value.getTime()
  if (!Number.isSafeInteger(result) || result < 0) throw new RegistryTenancyError('unavailable')
  return result
}

function accountOf(row: AccountRow): RegistryAccount {
  return {
    accountId: accountId(row.id),
    memberId: memberId(row.member_id),
    displayName: row.display_name,
    createdAt: milliseconds(row.created_at),
    updatedAt: milliseconds(row.updated_at),
  }
}

function organizationOf(row: OrganizationRow): RegistryOrganization {
  return {
    organizationId: organizationId(row.id),
    slug: row.slug,
    displayName: row.display_name,
    state: row.state,
    createdAt: milliseconds(row.created_at),
    updatedAt: milliseconds(row.updated_at),
  }
}

function membershipOf(row: MembershipRow): RegistryOrganizationMembership {
  return {
    organizationId: organizationId(row.organization_id),
    accountId: accountId(row.account_id),
    memberId: memberId(row.member_id),
    role: row.role,
    state: row.state,
    createdAt: milliseconds(row.created_at),
    updatedAt: milliseconds(row.updated_at),
  }
}

function accessOf(row: OrganizationAccessRow): RegistryOrganizationAccess {
  return {
    organization: organizationOf({
      id: row.organization_id,
      slug: row.organization_slug,
      display_name: row.organization_display_name,
      state: row.organization_state,
      created_at: row.organization_created_at,
      updated_at: row.organization_updated_at,
    }),
    membership: membershipOf({
      organization_id: row.organization_id,
      account_id: row.membership_account_id,
      member_id: row.membership_member_id,
      role: row.membership_role,
      state: row.membership_state,
      created_at: row.membership_created_at,
      updated_at: row.membership_updated_at,
    }),
  }
}

function normalizedSlug(displayName: string): string {
  const normalized = displayName.normalize('NFKD').replace(/[\u0300-\u036f]/gu, '').toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-').replace(/^-+|-+$/gu, '').slice(0, 55).replace(/-+$/u, '')
  return normalized.length === 0 ? 'organization' : normalized
}

function creationHash(displayName: string): string {
  return createHash('sha256').update(`registry-organization-v1\0${displayName}`, 'utf8').digest('hex')
}

function invitationHash(token: string): string {
  return createHash('sha256').update(`registry-invitation-v1\0${token}`, 'utf8').digest('hex')
}

function invitationOf(row: InvitationRow): RegistryInvitation {
  if (!UUID.test(row.invitation_id)) throw new RegistryTenancyError('unavailable')
  return {
    invitationId: row.invitation_id,
    organizationId: organizationId(row.organization_id),
    role: row.role,
    displayName: row.display_name,
    status: row.status,
    expiresAt: milliseconds(row.expires_at),
    createdAt: milliseconds(row.created_at),
    createdByMemberId: memberId(row.created_by_member_id),
  }
}

function invitationPreviewOf(row: InvitationRow): RegistryInvitationPreview {
  if (row.organization_display_name === undefined) throw new RegistryTenancyError('unavailable')
  const invitation = invitationOf(row)
  return {
    invitationId: invitation.invitationId,
    organizationId: invitation.organizationId,
    organizationDisplayName: row.organization_display_name,
    role: invitation.role,
    displayName: invitation.displayName,
    status: invitation.status,
    expiresAt: invitation.expiresAt,
  }
}

function postgresCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const value = Reflect.get(error, 'code')
  return typeof value === 'string' ? value : undefined
}

/** Dedicated PostgreSQL implementation; construction waits for the complete schema and RLS policy transaction. */
export class PostgresRegistryTenancy implements RegistryTenancyStore {
  private readonly pool: Pool
  private readonly schemaName: string
  private readonly schema: string
  private readonly maxOrganizationsPerAccount: number
  private closed = false
  private closing: Promise<void> | undefined

  private constructor(config: PostgresRegistryTenancyConfig) {
    if (!nonEmptyBounded(config.connectionString, 8_192)) throw new RegistryTenancyError('invalid-input')
    const maximum = config.maxConnections ?? 4
    const idle = config.idleTimeoutMs ?? 30_000
    const statement = config.statementTimeoutMs ?? 15_000
    const maxOrganizationsPerAccount = config.maxOrganizationsPerAccount ?? 5
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 16
      || !Number.isSafeInteger(idle) || idle < 1_000 || idle > 600_000
      || !Number.isSafeInteger(statement) || statement < 1_000 || statement > 120_000
      || !Number.isSafeInteger(maxOrganizationsPerAccount) || maxOrganizationsPerAccount < 1
      || maxOrganizationsPerAccount > 100) {
      throw new RegistryTenancyError('invalid-input')
    }
    this.schemaName = config.schema ?? 'registry'
    this.schema = quoteIdentifier(this.schemaName)
    this.maxOrganizationsPerAccount = maxOrganizationsPerAccount
    this.pool = new Pool({
      connectionString: config.connectionString,
      max: maximum,
      idleTimeoutMillis: idle,
      connectionTimeoutMillis: 10_000,
      statement_timeout: statement,
      idle_in_transaction_session_timeout: 30_000,
      application_name: 'dsh-a2a-registry-tenancy',
    })
  }

  /** Open only after DDL, role checks and FORCE RLS policies commit together. */
  static async open(config: PostgresRegistryTenancyConfig): Promise<PostgresRegistryTenancy> {
    const store = new PostgresRegistryTenancy(config)
    try {
      await store.initialize()
      return store
    } catch (error) {
      await store.pool.end().catch(() => {})
      if (error instanceof RegistryTenancyError) throw error
      throw new RegistryTenancyError('unavailable')
    }
  }

  async resolveOrCreateAccount(input: RegistryOidcAccountInput): Promise<RegistryAccount> {
    if (!nonEmptyBounded(input.issuer, 2_048) || !nonEmptyBounded(input.subject, 1_024)
      || !IDENTIFIER.test(input.memberId) || !nonEmptyBounded(input.displayName, 256)) {
      throw new RegistryTenancyError('invalid-input')
    }
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, EMPTY_ORGANIZATION_CONTEXT, async (client) => {
      await this.advisoryLock(client, `oidc\0${input.issuer}\0${input.subject}`)
      const existing = await client.query<AccountRow>(
        `select account.id, account.member_id, account.display_name, account.created_at, account.updated_at
         from ${this.schema}.account_identities as identity
         join ${this.schema}.accounts as account on account.id = identity.account_id
         where identity.issuer = $1 and identity.subject = $2`,
        [input.issuer, input.subject],
      )
      const found = existing.rows[0]
      if (found !== undefined) {
        if (found.member_id !== input.memberId) throw new RegistryTenancyError('conflict')
        if (found.display_name === input.displayName) return accountOf(found)
        const updated = await client.query<AccountRow>(
          `update ${this.schema}.accounts set display_name = $2, updated_at = now()
           where id = $1 returning id, member_id, display_name, created_at, updated_at`,
          [found.id, input.displayName],
        )
        const row = updated.rows[0]
        if (row === undefined) throw new RegistryTenancyError('unavailable')
        return accountOf(row)
      }
      const nextAccountId = randomUUID()
      let inserted: AccountRow
      try {
        const account = await client.query<AccountRow>(
          `insert into ${this.schema}.accounts (id, member_id, display_name)
           values ($1, $2, $3)
           returning id, member_id, display_name, created_at, updated_at`,
          [nextAccountId, input.memberId, input.displayName],
        )
        const row = account.rows[0]
        if (row === undefined) throw new RegistryTenancyError('unavailable')
        inserted = row
        await client.query(
          `insert into ${this.schema}.account_identities (issuer, subject, account_id) values ($1, $2, $3)`,
          [input.issuer, input.subject, nextAccountId],
        )
      } catch (error) {
        if (postgresCode(error) === '23505') throw new RegistryTenancyError('conflict')
        throw error
      }
      return accountOf(inserted)
    })
  }

  async listOrganizations(value: RegistryAccountId): Promise<readonly RegistryOrganizationAccess[]> {
    const selectedAccountId = accountId(value)
    return this.transaction(selectedAccountId, EMPTY_ORGANIZATION_CONTEXT, async (client) => {
      const result = await client.query<OrganizationAccessRow>(this.accessQuery(
        `membership.account_id = $1 and membership.state = 'active'`, 'organization.slug, organization.id'),
      [selectedAccountId])
      return result.rows.map(accessOf)
    })
  }

  async createOrganization(account: RegistryAccount,
    input: RegistryOrganizationCreationInput): Promise<RegistryOrganizationAccess> {
    const selectedAccountId = accountId(account.accountId)
    const selectedMemberId = memberId(account.memberId)
    if (!nonEmptyBounded(input.displayName, 256) || !IDEMPOTENCY_KEY.test(input.idempotencyKey)) {
      throw new RegistryTenancyError('invalid-input')
    }
    const requestedHash = creationHash(input.displayName)
    const nextOrganizationId = randomUUID()
    return this.transaction(selectedAccountId, nextOrganizationId, async (client) => {
      const persistedAccount = await this.requireAccount(client, selectedAccountId, selectedMemberId)
      await this.advisoryLock(client, `organization-creation\0${selectedAccountId}\0${input.idempotencyKey}`)
      const previous = await client.query<CreationRow>(
        `select organization_id, request_hash from ${this.schema}.organization_creations
         where account_id = $1 and idempotency_key = $2`,
        [selectedAccountId, input.idempotencyKey],
      )
      const existing = previous.rows[0]
      if (existing !== undefined) {
        if (existing.request_hash !== requestedHash) throw new RegistryTenancyError('conflict')
        await this.setContext(client, selectedAccountId, existing.organization_id)
        const access = await this.selectAccess(client, selectedAccountId, existing.organization_id)
        if (access === null) throw new RegistryTenancyError('unavailable')
        return access
      }
      const allocation = await client.query<{ readonly count: string }>(
        `select count(*)::text as count from ${this.schema}.organization_creations where account_id = $1`,
        [selectedAccountId],
      )
      if (BigInt(allocation.rows[0]?.count ?? '0') >= BigInt(this.maxOrganizationsPerAccount)) {
        throw new RegistryTenancyError('conflict')
      }
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, nextOrganizationId)
      const slug = await this.uniqueSlug(client, input.displayName, nextOrganizationId)
      await this.setContext(client, selectedAccountId, nextOrganizationId)
      await client.query(
        `insert into ${this.schema}.organizations (id, slug, display_name, state, created_by_account_id)
         values ($1, $2, $3, 'provisioning', $4)`,
        [nextOrganizationId, slug, input.displayName, selectedAccountId],
      )
      await client.query(
        `insert into ${this.schema}.organization_memberships
          (organization_id, account_id, member_id, role, state)
         values ($1, $2, $3, 'owner', 'active')`,
        [nextOrganizationId, selectedAccountId, persistedAccount.member_id],
      )
      await client.query(
        `insert into ${this.schema}.organization_creations
          (account_id, idempotency_key, request_hash, organization_id)
         values ($1, $2, $3, $4)`,
        [selectedAccountId, input.idempotencyKey, requestedHash, nextOrganizationId],
      )
      const access = await this.selectAccess(client, selectedAccountId, nextOrganizationId)
      if (access === null) throw new RegistryTenancyError('unavailable')
      return access
    })
  }

  async getOrganizationForAccount(value: RegistryAccountId,
    valueOrganizationId: OrganizationId): Promise<RegistryOrganizationAccess | null> {
    const selectedAccountId = accountId(value)
    const selectedOrganizationId = organizationId(valueOrganizationId)
    return this.transaction(selectedAccountId, selectedOrganizationId,
      client => this.selectAccess(client, selectedAccountId, selectedOrganizationId))
  }

  async getOrganizationInternal(value: OrganizationId): Promise<RegistryOrganization | null> {
    const selectedOrganizationId = organizationId(value)
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId, async (client) => {
      const result = await client.query<OrganizationRow>(
        `select id, slug, display_name, state, created_at, updated_at
         from ${this.schema}.organizations where id = $1`,
        [selectedOrganizationId],
      )
      const row = result.rows[0]
      return row === undefined ? null : organizationOf(row)
    })
  }

  async markOrganizationState(value: OrganizationId,
    state: Extract<RegistryOrganizationState, 'active' | 'failed'>): Promise<RegistryOrganization> {
    const selectedOrganizationId = organizationId(value)
    if (state !== 'active' && state !== 'failed') throw new RegistryTenancyError('invalid-input')
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId, async (client) => {
      const result = await client.query<OrganizationRow>(
        `update ${this.schema}.organizations set state = $2, updated_at = now()
         where id = $1 returning id, slug, display_name, state, created_at, updated_at`,
        [selectedOrganizationId, state],
      )
      const row = result.rows[0]
      if (row === undefined) throw new RegistryTenancyError('not-found')
      return organizationOf(row)
    })
  }

  async ensureLegacyOrganization(input: RegistryLegacyOrganizationInput): Promise<RegistryOrganization> {
    const selectedOrganizationId = organizationId(input.organizationId)
    if (!nonEmptyBounded(input.displayName, 256)) throw new RegistryTenancyError('invalid-input')
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId, async (client) => {
      await this.advisoryLock(client, `legacy-organization\0${selectedOrganizationId}`)
      const existing = await client.query<OrganizationRow>(
        `select id, slug, display_name, state, created_at, updated_at
         from ${this.schema}.organizations where id = $1`,
        [selectedOrganizationId],
      )
      const found = existing.rows[0]
      if (found !== undefined) return organizationOf(found)
      const slug = await this.uniqueSlug(client, input.displayName, selectedOrganizationId)
      const inserted = await client.query<OrganizationRow>(
        `insert into ${this.schema}.organizations (id, slug, display_name, state, created_by_account_id)
         values ($1, $2, $3, 'active', null)
         returning id, slug, display_name, state, created_at, updated_at`,
        [selectedOrganizationId, slug, input.displayName],
      )
      const row = inserted.rows[0]
      if (row === undefined) throw new RegistryTenancyError('unavailable')
      return organizationOf(row)
    })
  }

  async claimLegacyOwner(account: RegistryAccount,
    valueOrganizationId: OrganizationId): Promise<RegistryOrganizationAccess> {
    const selectedAccountId = accountId(account.accountId)
    const selectedMemberId = memberId(account.memberId)
    const selectedOrganizationId = organizationId(valueOrganizationId)
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId, async (client) => {
      const organization = await client.query<{ readonly id: string }>(
        `select id from ${this.schema}.organizations where id = $1`, [selectedOrganizationId])
      if (organization.rows[0] === undefined) throw new RegistryTenancyError('not-found')
      await this.setContext(client, selectedAccountId, selectedOrganizationId)
      await this.requireAccount(client, selectedAccountId, selectedMemberId)
      try {
        await client.query(
          `insert into ${this.schema}.organization_memberships
            (organization_id, account_id, member_id, role, state)
           values ($1, $2, $3, 'owner', 'active')
           on conflict (organization_id, account_id) do nothing`,
          [selectedOrganizationId, selectedAccountId, selectedMemberId],
        )
      } catch (error) {
        if (postgresCode(error) === '23505') throw new RegistryTenancyError('conflict')
        throw error
      }
      const access = await this.selectAccess(client, selectedAccountId, selectedOrganizationId)
      if (access === null || access.membership.memberId !== selectedMemberId
        || access.membership.role !== 'owner' || access.membership.state !== 'active') {
        throw new RegistryTenancyError('conflict')
      }
      return access
    })
  }

  async listInvitations(valueAccountId: RegistryAccountId, valueMemberId: MemberId,
    actorRole: RegistryOrganizationMembership['role'], valueOrganizationId: OrganizationId):
  Promise<readonly RegistryInvitation[]> {
    const selectedAccountId = accountId(valueAccountId)
    const selectedMemberId = memberId(valueMemberId)
    const selectedOrganizationId = organizationId(valueOrganizationId)
    this.requireInvitationActorRole(actorRole)
    return this.transaction(selectedAccountId, selectedOrganizationId, async (client) => {
      await this.requireActiveMembership(client, selectedAccountId, selectedMemberId, selectedOrganizationId)
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId)
      await this.expireInvitations(client, 'organization_id = $1', [selectedOrganizationId])
      const result = await client.query<InvitationRow>(
        `select invitation_id, organization_id, role, display_name, status, expires_at, created_at,
          created_by_member_id, claimed_by_account_id, claimed_by_member_id
         from ${this.schema}.organization_invitations
         where organization_id = $1 order by created_at desc, invitation_id desc limit $2`,
        [selectedOrganizationId, MAX_PENDING_INVITATIONS],
      )
      return result.rows.map(invitationOf)
    })
  }

  async createInvitation(valueAccountId: RegistryAccountId, valueMemberId: MemberId,
    actorRole: RegistryOrganizationMembership['role'], valueOrganizationId: OrganizationId,
    input: RegistryInvitationCreationInput): Promise<RegistryInvitationCreation> {
    const selectedAccountId = accountId(valueAccountId)
    const selectedMemberId = memberId(valueMemberId)
    const selectedOrganizationId = organizationId(valueOrganizationId)
    this.requireInvitationActorRole(actorRole)
    if ((input.role !== 'admin' && input.role !== 'member') || (actorRole === 'admin' && input.role !== 'member')
      || (input.displayName !== undefined && !nonEmptyBounded(input.displayName, 256))) {
      throw new RegistryTenancyError('invalid-input')
    }
    const ttl = input.expiresInSeconds ?? DEFAULT_INVITATION_TTL_SECONDS
    if (!Number.isSafeInteger(ttl) || ttl < MIN_INVITATION_TTL_SECONDS || ttl > MAX_INVITATION_TTL_SECONDS) {
      throw new RegistryTenancyError('invalid-input')
    }
    const invitationId = randomUUID()
    const token = randomBytes(32).toString('base64url')
    const tokenHash = invitationHash(token)
    return this.transaction(selectedAccountId, selectedOrganizationId, async (client) => {
      await this.requireActiveMembership(client, selectedAccountId, selectedMemberId, selectedOrganizationId)
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId)
      await this.expireInvitations(client, 'organization_id = $1', [selectedOrganizationId])
      const count = await client.query<{ readonly count: string }>(
        `select count(*)::text as count from ${this.schema}.organization_invitations
         where organization_id = $1 and status = 'pending'`, [selectedOrganizationId])
      if (BigInt(count.rows[0]?.count ?? '0') >= BigInt(MAX_PENDING_INVITATIONS)) {
        throw new RegistryTenancyError('conflict')
      }
      const inserted = await client.query<InvitationRow>(
        `insert into ${this.schema}.organization_invitations
          (invitation_id, organization_id, token_hash, role, display_name, status, expires_at,
           created_by_account_id, created_by_member_id)
         values ($1, $2, $3, $4, $5, 'pending', now() + ($6::bigint * interval '1 second'), $7, $8)
         returning invitation_id, organization_id, role, display_name, status, expires_at, created_at,
           created_by_member_id, claimed_by_account_id, claimed_by_member_id`,
        [invitationId, selectedOrganizationId, tokenHash, input.role, input.displayName ?? null,
          ttl, selectedAccountId, selectedMemberId],
      )
      const row = inserted.rows[0]
      if (row === undefined) throw new RegistryTenancyError('unavailable')
      return { invitation: invitationOf(row), token }
    })
  }

  async revokeInvitation(valueAccountId: RegistryAccountId, valueMemberId: MemberId,
    actorRole: RegistryOrganizationMembership['role'], valueOrganizationId: OrganizationId,
    valueInvitationId: string): Promise<RegistryInvitation> {
    const selectedAccountId = accountId(valueAccountId)
    const selectedMemberId = memberId(valueMemberId)
    const selectedOrganizationId = organizationId(valueOrganizationId)
    if (!UUID.test(valueInvitationId)) throw new RegistryTenancyError('invalid-input')
    this.requireInvitationActorRole(actorRole)
    return this.transaction(selectedAccountId, selectedOrganizationId, async (client) => {
      await this.requireActiveMembership(client, selectedAccountId, selectedMemberId, selectedOrganizationId)
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId)
      await this.expireInvitations(client, 'organization_id = $1 and invitation_id = $2',
        [selectedOrganizationId, valueInvitationId])
      const selected = await client.query<InvitationRow>(
        `select invitation_id, organization_id, role, display_name, status, expires_at, created_at,
          created_by_member_id, claimed_by_account_id, claimed_by_member_id
         from ${this.schema}.organization_invitations
         where organization_id = $1 and invitation_id = $2 for update`,
        [selectedOrganizationId, valueInvitationId],
      )
      const current = selected.rows[0]
      if (current === undefined || (actorRole === 'admin' && current.role !== 'member')) {
        throw new RegistryTenancyError('not-found')
      }
      if (current.status === 'revoked') return invitationOf(current)
      if (current.status !== 'pending') throw new RegistryTenancyError('conflict')
      const result = await client.query<InvitationRow>(
        `update ${this.schema}.organization_invitations set status = 'revoked', updated_at = now()
         where invitation_id = $1
         returning invitation_id, organization_id, role, display_name, status, expires_at, created_at,
           created_by_member_id, claimed_by_account_id, claimed_by_member_id`, [valueInvitationId])
      if (current.claimed_by_account_id !== null) {
        await client.query(
          `update ${this.schema}.organization_memberships set state = 'removed', updated_at = now()
           where organization_id = $1 and account_id = $2 and state = 'suspended'`,
          [selectedOrganizationId, current.claimed_by_account_id],
        )
      }
      const row = result.rows[0]
      if (row === undefined) throw new RegistryTenancyError('unavailable')
      return invitationOf(row)
    })
  }

  async previewInvitation(valueAccountId: RegistryAccountId, token: string): Promise<RegistryInvitationPreview> {
    const selectedAccountId = accountId(valueAccountId)
    if (!INVITATION_TOKEN.test(token)) throw new RegistryTenancyError('not-found')
    const hash = invitationHash(token)
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, EMPTY_ORGANIZATION_CONTEXT, async (client) => {
      await this.requireAccountId(client, selectedAccountId)
      await this.expireInvitations(client, 'token_hash = $1', [hash])
      const selected = await client.query<InvitationRow>(this.invitationPreviewQuery('invitation.token_hash = $1'), [hash])
      const row = selected.rows[0]
      if (row === undefined) throw new RegistryTenancyError('not-found')
      return invitationPreviewOf(row)
    })
  }

  async claimInvitation(account: RegistryAccount, token: string): Promise<RegistryInvitationClaim> {
    const selectedAccountId = accountId(account.accountId)
    const selectedMemberId = memberId(account.memberId)
    if (!INVITATION_TOKEN.test(token)) throw new RegistryTenancyError('not-found')
    const hash = invitationHash(token)
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, EMPTY_ORGANIZATION_CONTEXT, async (client) => {
      const persistedAccount = await this.requireAccount(client, selectedAccountId, selectedMemberId)
      await this.advisoryLock(client, `invitation-claim\0${hash}`)
      await this.expireInvitations(client, 'token_hash = $1', [hash])
      const selected = await client.query<InvitationRow>(
        `select invitation_id, organization_id, role, display_name, status, expires_at, created_at,
          created_by_member_id, claimed_by_account_id, claimed_by_member_id
         from ${this.schema}.organization_invitations where token_hash = $1 for update`, [hash])
      const invitation = selected.rows[0]
      if (invitation === undefined || (invitation.claimed_by_account_id !== null
        && invitation.claimed_by_account_id !== selectedAccountId)
        || (invitation.claimed_by_member_id !== undefined && invitation.claimed_by_member_id !== null
          && invitation.claimed_by_member_id !== selectedMemberId)
        || (invitation.status !== 'pending' && invitation.status !== 'accepted')) {
        throw new RegistryTenancyError('not-found')
      }
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, invitation.organization_id)
      const organization = await client.query<{ readonly state: RegistryOrganizationState }>(
        `select state from ${this.schema}.organizations where id = $1`, [invitation.organization_id])
      if (organization.rows[0]?.state !== 'active') throw new RegistryTenancyError('not-found')
      if (invitation.status === 'pending') {
        const creator = await client.query(
          `select 1 from ${this.schema}.organization_memberships
           where organization_id = $1 and member_id = $2 and state = 'active'`,
          [invitation.organization_id, invitation.created_by_member_id])
        if (creator.rows[0] === undefined) throw new RegistryTenancyError('not-found')
      }
      const byAccount = await client.query<MembershipRow>(
        `select organization_id, account_id, member_id, role, state, created_at, updated_at
         from ${this.schema}.organization_memberships
         where organization_id = $1 and account_id = $2 for update`,
        [invitation.organization_id, selectedAccountId],
      )
      const existing = byAccount.rows[0]
      if (existing === undefined) {
        const collision = await client.query(
          `select 1 from ${this.schema}.organization_memberships
           where organization_id = $1 and member_id = $2`, [invitation.organization_id, selectedMemberId])
        if (collision.rows.length !== 0) throw new RegistryTenancyError('conflict')
        await client.query(
          `insert into ${this.schema}.organization_memberships
            (organization_id, account_id, member_id, role, state)
           values ($1, $2, $3, $4, 'suspended')`,
          [invitation.organization_id, selectedAccountId, selectedMemberId, invitation.role],
        )
      } else if (existing.member_id !== selectedMemberId
        || (invitation.status === 'pending' && existing.role !== invitation.role)
        || (existing.state !== 'suspended' && existing.state !== 'active')) {
        throw new RegistryTenancyError('conflict')
      }
      if (invitation.claimed_by_account_id === null) {
        await client.query(
          `update ${this.schema}.organization_invitations
           set claimed_by_account_id = $2, claimed_by_member_id = $3, claimed_at = now(), updated_at = now()
           where invitation_id = $1`, [invitation.invitation_id, selectedAccountId, selectedMemberId])
      } else if (invitation.claimed_by_member_id !== undefined
        && invitation.claimed_by_member_id !== null && invitation.claimed_by_member_id !== selectedMemberId) {
        throw new RegistryTenancyError('not-found')
      }
      return { invitation: invitationOf({ ...invitation, claimed_by_account_id: selectedAccountId }),
        account: accountOf(persistedAccount) }
    })
  }

  async activateInvitation(account: RegistryAccount, valueInvitationId: string): Promise<RegistryOrganizationAccess> {
    const selectedAccountId = accountId(account.accountId)
    const selectedMemberId = memberId(account.memberId)
    if (!UUID.test(valueInvitationId)) throw new RegistryTenancyError('invalid-input')
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, EMPTY_ORGANIZATION_CONTEXT, async (client) => {
      await this.requireAccount(client, selectedAccountId, selectedMemberId)
      const selected = await client.query<InvitationRow>(
        `select invitation_id, organization_id, role, display_name, status, expires_at, created_at,
          created_by_member_id, claimed_by_account_id, claimed_by_member_id
         from ${this.schema}.organization_invitations
         where invitation_id = $1 and claimed_by_account_id = $2 for update`,
        [valueInvitationId, selectedAccountId],
      )
      const invitation = selected.rows[0]
      if (invitation === undefined) throw new RegistryTenancyError('not-found')
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, invitation.organization_id)
      await this.expireInvitations(client, 'invitation_id = $1', [valueInvitationId])
      const refreshed = await client.query<InvitationRow>(
        `select invitation_id, organization_id, role, display_name, status, expires_at, created_at,
          created_by_member_id, claimed_by_account_id, claimed_by_member_id
         from ${this.schema}.organization_invitations where invitation_id = $1 for update`, [valueInvitationId])
      const current = refreshed.rows[0]
      if (current === undefined || (current.status !== 'pending' && current.status !== 'accepted')) {
        throw new RegistryTenancyError('not-found')
      }
      if (current.status === 'pending') {
        const creator = await client.query(
          `select 1 from ${this.schema}.organization_memberships
           where organization_id = $1 and member_id = $2 and state = 'active'`,
          [current.organization_id, current.created_by_member_id])
        if (creator.rows[0] === undefined) throw new RegistryTenancyError('not-found')
      }
      const membership = await client.query<MembershipRow>(
        `select organization_id, account_id, member_id, role, state, created_at, updated_at
         from ${this.schema}.organization_memberships
         where organization_id = $1 and account_id = $2 for update`,
        [current.organization_id, selectedAccountId],
      )
      const linked = membership.rows[0]
      if (linked === undefined || linked.member_id !== selectedMemberId
        || (current.status === 'pending' && linked.role !== current.role)
        || (linked.state !== 'suspended' && linked.state !== 'active')) {
        throw new RegistryTenancyError('conflict')
      }
      if (current.status === 'accepted' && linked.state !== 'active') throw new RegistryTenancyError('not-found')
      if (current.status === 'pending') {
        await client.query(
          `update ${this.schema}.organization_memberships set state = 'active', updated_at = now()
           where organization_id = $1 and account_id = $2`, [current.organization_id, selectedAccountId])
        await client.query(
          `update ${this.schema}.organization_invitations set status = 'accepted', accepted_at = now(), updated_at = now()
           where invitation_id = $1`, [valueInvitationId])
      }
      await this.setContext(client, selectedAccountId, current.organization_id)
      const access = await this.selectAccess(client, selectedAccountId, current.organization_id)
      if (access === null) throw new RegistryTenancyError('unavailable')
      return access
    })
  }

  async declineInvitation(account: RegistryAccount, token: string): Promise<RegistryInvitationPreview> {
    const selectedAccountId = accountId(account.accountId)
    const selectedMemberId = memberId(account.memberId)
    if (!INVITATION_TOKEN.test(token)) throw new RegistryTenancyError('not-found')
    const hash = invitationHash(token)
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, EMPTY_ORGANIZATION_CONTEXT, async (client) => {
      await this.requireAccount(client, selectedAccountId, selectedMemberId)
      await this.advisoryLock(client, `invitation-claim\0${hash}`)
      await this.expireInvitations(client, 'token_hash = $1', [hash])
      const selected = await client.query<InvitationRow>(this.invitationPreviewQuery(
        'invitation.token_hash = $1', true), [hash])
      const current = selected.rows[0]
      if (current === undefined || (current.claimed_by_account_id !== null
        && current.claimed_by_account_id !== selectedAccountId)) throw new RegistryTenancyError('not-found')
      if (current.status === 'declined') return invitationPreviewOf(current)
      if (current.status !== 'pending') throw new RegistryTenancyError('conflict')
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, current.organization_id)
      await client.query(
        `update ${this.schema}.organization_invitations
         set status = 'declined', claimed_by_account_id = coalesce(claimed_by_account_id, $2),
           claimed_by_member_id = coalesce(claimed_by_member_id, $3),
           claimed_at = coalesce(claimed_at, now()),
           declined_at = now(), updated_at = now()
         where invitation_id = $1`, [current.invitation_id, selectedAccountId, selectedMemberId])
      await client.query(
        `update ${this.schema}.organization_memberships set state = 'removed', updated_at = now()
         where organization_id = $1 and account_id = $2 and state = 'suspended'`,
        [current.organization_id, selectedAccountId],
      )
      return invitationPreviewOf({ ...current, status: 'declined', claimed_by_account_id: selectedAccountId })
    })
  }

  async syncMembershipFromDirectory(valueOrganizationId: OrganizationId, valueMemberId: MemberId,
    role: RegistryOrganizationMembership['role'], state: RegistryOrganizationMembership['state']): Promise<void> {
    const selectedOrganizationId = organizationId(valueOrganizationId)
    const selectedMemberId = memberId(valueMemberId)
    if ((role !== 'owner' && role !== 'admin' && role !== 'member')
      || (state !== 'active' && state !== 'suspended' && state !== 'removed')) {
      throw new RegistryTenancyError('invalid-input')
    }
    await this.transaction(CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId, async (client) => {
      const linked = await client.query<{ readonly account_id: string; readonly state: string }>(
        `select account_id, state from ${this.schema}.organization_memberships
         where organization_id = $1 and member_id = $2 for update`, [selectedOrganizationId, selectedMemberId])
      const membership = linked.rows[0]
      if (membership === undefined || membership.state === 'removed') return
      if (membership.state === 'suspended') {
        if (state !== 'active') return
        const accepted = await client.query(
          `select 1 from ${this.schema}.organization_invitations
           where organization_id = $1 and claimed_by_account_id = $2 and status = 'accepted' limit 1`,
          [selectedOrganizationId, membership.account_id],
        )
        // Only an accepted linkage can be resumed. Pending, revoked, expired and removed rows remain
        // fail-closed even if an orphan directory entry exists.
        if (accepted.rows[0] === undefined) return
      }
      await client.query(
        `update ${this.schema}.organization_memberships set role = $3, state = $4, updated_at = now()
         where organization_id = $1 and member_id = $2`, [selectedOrganizationId, selectedMemberId, role, state])
    })
  }

  close(): Promise<void> {
    if (this.closing !== undefined) return this.closing
    this.closed = true
    this.closing = this.pool.end()
    return this.closing
  }

  private async initialize(): Promise<void> {
    const client = await this.pool.connect()
    let begun = false
    try {
      await client.query('begin')
      begun = true
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, EMPTY_ORGANIZATION_CONTEXT)
      const role = await client.query<{ readonly rolsuper: boolean; readonly rolbypassrls: boolean }>(
        'select rolsuper, rolbypassrls from pg_roles where rolname = current_user')
      if (role.rows.length !== 1 || role.rows[0]?.rolsuper || role.rows[0]?.rolbypassrls) {
        throw new RegistryTenancyError('unavailable')
      }
      await this.advisoryLock(client, `registry-tenancy-schema\0${this.schema}`)
      const namespace = await client.query<{ readonly present: boolean }>(
        'select exists (select 1 from pg_namespace where nspname = $1) as present', [this.schemaName])
      if (namespace.rows[0]?.present !== true) await client.query(`create schema ${this.schema}`)
      await client.query(`create table if not exists ${this.schema}.tenancy_meta (
        singleton boolean primary key default true check (singleton),
        schema_version integer not null check (schema_version > 0)
      )`)
      await client.query(`insert into ${this.schema}.tenancy_meta (singleton, schema_version) values (true, $1)
        on conflict (singleton) do nothing`, [SCHEMA_VERSION])
      const version = await client.query<{ readonly schema_version: number }>(
        `select schema_version from ${this.schema}.tenancy_meta where singleton = true`)
      if (version.rows.length !== 1 || (version.rows[0]?.schema_version !== 1
        && version.rows[0]?.schema_version !== SCHEMA_VERSION)) {
        throw new RegistryTenancyError('unavailable')
      }
      await client.query(`create table if not exists ${this.schema}.accounts (
        id uuid primary key,
        member_id text not null check (member_id ~ '^[A-Za-z0-9]([A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'),
        display_name text not null check (display_name = btrim(display_name) and display_name <> ''
          and octet_length(display_name) <= 256 and display_name !~ '[[:cntrl:]]'),
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        check (updated_at >= created_at)
      )`)
      await client.query(`create unique index if not exists accounts_member_id_uidx
        on ${this.schema}.accounts (member_id)`)
      await client.query(`create unique index if not exists accounts_id_member_id_uidx
        on ${this.schema}.accounts (id, member_id)`)
      await client.query(`create table if not exists ${this.schema}.account_identities (
        issuer text not null check (issuer = btrim(issuer) and issuer <> '' and octet_length(issuer) <= 2048),
        subject text not null check (subject = btrim(subject) and subject <> '' and octet_length(subject) <= 1024),
        account_id uuid not null references ${this.schema}.accounts(id) on delete cascade,
        created_at timestamptz not null default now(),
        primary key (issuer, subject)
      )`)
      await client.query(`create index if not exists account_identities_account_id_idx
        on ${this.schema}.account_identities (account_id)`)
      await client.query(`create table if not exists ${this.schema}.organizations (
        id text primary key check (id ~ '^[A-Za-z0-9]([A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'),
        slug text not null unique check (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
        display_name text not null check (display_name = btrim(display_name) and display_name <> ''
          and octet_length(display_name) <= 256 and display_name !~ '[[:cntrl:]]'),
        state text not null check (state in ('provisioning', 'active', 'failed')),
        created_by_account_id uuid references ${this.schema}.accounts(id) on delete restrict,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        check (updated_at >= created_at)
      )`)
      await client.query(`create index if not exists organizations_created_by_account_id_idx
        on ${this.schema}.organizations (created_by_account_id) where created_by_account_id is not null`)
      await client.query(`create table if not exists ${this.schema}.organization_memberships (
        organization_id text not null references ${this.schema}.organizations(id) on delete cascade,
        account_id uuid not null references ${this.schema}.accounts(id) on delete cascade,
        member_id text not null check (member_id ~ '^[A-Za-z0-9]([A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'),
        role text not null check (role in ('owner', 'admin', 'member')),
        state text not null check (state in ('active', 'suspended', 'removed')),
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        primary key (organization_id, account_id),
        unique (organization_id, member_id),
        check (updated_at >= created_at)
      )`)
      await client.query(`create index if not exists organization_memberships_account_id_idx
        on ${this.schema}.organization_memberships (account_id, organization_id)`)
      await client.query(`create table if not exists ${this.schema}.organization_creations (
        account_id uuid not null references ${this.schema}.accounts(id) on delete cascade,
        idempotency_key text not null check (idempotency_key ~ '^[A-Za-z0-9]([A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'),
        request_hash text not null check (request_hash ~ '^[0-9a-f]{64}$'),
        organization_id text not null unique references ${this.schema}.organizations(id) on delete cascade,
        created_at timestamptz not null default now(),
        primary key (account_id, idempotency_key)
      )`)
      await client.query(`create table if not exists ${this.schema}.organization_invitations (
        invitation_id uuid primary key,
        organization_id text not null references ${this.schema}.organizations(id) on delete cascade,
        token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
        role text not null check (role in ('admin', 'member')),
        display_name text check (display_name is null or (display_name = btrim(display_name)
          and display_name <> '' and octet_length(display_name) <= 256 and display_name !~ '[[:cntrl:]]')),
        status text not null check (status in ('pending', 'accepted', 'declined', 'revoked', 'expired')),
        expires_at timestamptz not null,
        created_by_account_id uuid not null,
        created_by_member_id text not null,
        claimed_by_account_id uuid references ${this.schema}.accounts(id) on delete restrict,
        claimed_by_member_id text,
        claimed_at timestamptz,
        accepted_at timestamptz,
        declined_at timestamptz,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        foreign key (organization_id, created_by_account_id)
          references ${this.schema}.organization_memberships(organization_id, account_id) on delete restrict,
        foreign key (organization_id, created_by_member_id)
          references ${this.schema}.organization_memberships(organization_id, member_id) on delete restrict,
        foreign key (claimed_by_account_id, claimed_by_member_id)
          references ${this.schema}.accounts(id, member_id) on delete restrict,
        check (expires_at > created_at),
        check ((claimed_by_account_id is null) = (claimed_by_member_id is null)),
        check ((claimed_by_account_id is null) = (claimed_at is null)),
        check (accepted_at is null or status = 'accepted'),
        check (declined_at is null or status = 'declined'),
        check (updated_at >= created_at)
      )`)
      await client.query(`create index if not exists organization_invitations_pending_idx
        on ${this.schema}.organization_invitations (organization_id, expires_at, invitation_id)
        where status = 'pending'`)
      await client.query(`create index if not exists organization_invitations_creator_idx
        on ${this.schema}.organization_invitations (organization_id, created_by_account_id, created_at desc)`)
      await client.query(`create unique index if not exists organization_invitations_pending_claim_uidx
        on ${this.schema}.organization_invitations (organization_id, claimed_by_account_id)
        where status = 'pending' and claimed_by_account_id is not null`)
      await this.installPolicies(client)
      await client.query(`update ${this.schema}.tenancy_meta set schema_version = $1 where singleton = true`,
        [SCHEMA_VERSION])
      await client.query('commit')
      begun = false
    } catch (error) {
      if (begun) {
        try { await client.query('rollback') } catch (rollbackError) {
          throw new AggregateError([error, rollbackError], 'Registry tenancy schema rollback failed')
        }
      }
      throw error
    } finally { client.release() }
  }

  private async installPolicies(client: PoolClient): Promise<void> {
    for (const table of ['organizations', 'organization_memberships', 'organization_creations',
      'organization_invitations']) {
      await client.query(`alter table ${this.schema}.${table} enable row level security`)
      await client.query(`alter table ${this.schema}.${table} force row level security`)
    }
    const policies = [
      'organizations_select', 'organizations_insert', 'organizations_update',
      'organization_memberships_select', 'organization_memberships_insert',
      'organization_memberships_update',
      'organization_creations_select', 'organization_creations_insert',
      'organization_invitations_select', 'organization_invitations_insert', 'organization_invitations_update',
    ]
    for (const policy of policies) {
      const table = policy.startsWith('organization_memberships') ? 'organization_memberships'
        : policy.startsWith('organization_creations') ? 'organization_creations' : 'organizations'
      const selectedTable = policy.startsWith('organization_invitations') ? 'organization_invitations' : table
      await client.query(`drop policy if exists ${policy} on ${this.schema}.${selectedTable}`)
    }
    const accountSetting = "nullif(current_setting('app.account_id', true), '')"
    const organizationSetting = "nullif(current_setting('app.organization_id', true), '')"
    await client.query(`create policy organizations_select on ${this.schema}.organizations for select using (
      ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}'
      or exists (
        select 1 from ${this.schema}.organization_memberships as membership
        where membership.organization_id = organizations.id
          and membership.account_id::text = ${accountSetting}
          and membership.state = 'active'
      )
    )`)
    await client.query(`create policy organizations_insert on ${this.schema}.organizations for insert with check (
      id = ${organizationSetting} and (
        created_by_account_id::text = ${accountSetting}
        or (created_by_account_id is null and ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}')
      )
    )`)
    await client.query(`create policy organizations_update on ${this.schema}.organizations for update
      using (id = ${organizationSetting} and ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}')
      with check (id = ${organizationSetting} and ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}')`)
    await client.query(`create policy organization_memberships_select on ${this.schema}.organization_memberships
      for select using (
        account_id::text = ${accountSetting}
        or (${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}' and organization_id = ${organizationSetting})
      )`)
    await client.query(`create policy organization_memberships_insert on ${this.schema}.organization_memberships
      for insert with check (
        organization_id = ${organizationSetting} and (
          (account_id::text = ${accountSetting} and role = 'owner' and state = 'active')
          or ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}'
        )
      )`)
    await client.query(`create policy organization_memberships_update on ${this.schema}.organization_memberships
      for update using (
        organization_id = ${organizationSetting} and ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}'
      ) with check (
        organization_id = ${organizationSetting} and ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}'
      )`)
    await client.query(`create policy organization_creations_select on ${this.schema}.organization_creations
      for select using (account_id::text = ${accountSetting})`)
    await client.query(`create policy organization_creations_insert on ${this.schema}.organization_creations
      for insert with check (
        account_id::text = ${accountSetting} and organization_id = ${organizationSetting}
      )`)
    await client.query(`create policy organization_invitations_select on ${this.schema}.organization_invitations
      for select using (
        ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}'
        and (${organizationSetting} is null or organization_id = ${organizationSetting})
      )`)
    await client.query(`create policy organization_invitations_insert on ${this.schema}.organization_invitations
      for insert with check (
        ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}' and organization_id = ${organizationSetting}
      )`)
    await client.query(`create policy organization_invitations_update on ${this.schema}.organization_invitations
      for update using (
        ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}'
        and (${organizationSetting} is null or organization_id = ${organizationSetting})
      ) with check (
        ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}'
        and (${organizationSetting} is null or organization_id = ${organizationSetting})
      )`)
  }

  private requireInvitationActorRole(role: RegistryOrganizationMembership['role']): void {
    if (role !== 'owner' && role !== 'admin') throw new RegistryTenancyError('not-found')
  }

  private async requireAccountId(client: PoolClient, selectedAccountId: RegistryAccountId): Promise<void> {
    const result = await client.query('select 1 from ' + this.schema + '.accounts where id = $1',
      [selectedAccountId])
    if (result.rows[0] === undefined) throw new RegistryTenancyError('not-found')
  }

  private async requireActiveMembership(client: PoolClient, selectedAccountId: RegistryAccountId,
    selectedMemberId: MemberId, selectedOrganizationId: OrganizationId): Promise<MembershipRow> {
    const result = await client.query<MembershipRow>(
      `select organization_id, account_id, member_id, role, state, created_at, updated_at
       from ${this.schema}.organization_memberships
       where organization_id = $1 and account_id = $2 and member_id = $3 and state = 'active'`,
      [selectedOrganizationId, selectedAccountId, selectedMemberId],
    )
    const row = result.rows[0]
    if (row === undefined) throw new RegistryTenancyError('not-found')
    return row
  }

  private invitationPreviewQuery(where: string, lock = false): string {
    return `select invitation.invitation_id, invitation.organization_id,
      organization.display_name as organization_display_name, invitation.role, invitation.display_name,
      invitation.status, invitation.expires_at, invitation.created_at, invitation.created_by_member_id,
      invitation.claimed_by_account_id, invitation.claimed_by_member_id
      from ${this.schema}.organization_invitations as invitation
      join ${this.schema}.organizations as organization on organization.id = invitation.organization_id
      where ${where}${lock ? ' for update of invitation' : ''}`
  }

  /** Expiry is decided by PostgreSQL time while holding row locks; a claimed membership remains inaccessible. */
  private async expireInvitations(client: PoolClient, predicate: string,
    values: readonly unknown[]): Promise<void> {
    const expired = await client.query<{
      readonly organization_id: string
      readonly claimed_by_account_id: string | null
    }>(
      `update ${this.schema}.organization_invitations
       set status = 'expired', updated_at = now()
       where status = 'pending' and expires_at <= now() and ${predicate}
       returning organization_id, claimed_by_account_id`, [...values],
    )
    for (const row of expired.rows) {
      if (row.claimed_by_account_id === null) continue
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, row.organization_id)
      await client.query(
        `update ${this.schema}.organization_memberships set state = 'removed', updated_at = now()
         where organization_id = $1 and account_id = $2 and state = 'suspended'`,
        [row.organization_id, row.claimed_by_account_id],
      )
    }
  }

  private async transaction<T>(selectedAccountId: string, selectedOrganizationId: string,
    operation: (client: PoolClient) => Promise<T>): Promise<T> {
    if (this.closed) throw new RegistryTenancyError('closed')
    const client = await this.pool.connect().catch(() => { throw new RegistryTenancyError('unavailable') })
    let begun = false
    try {
      await client.query('begin')
      begun = true
      await this.setContext(client, selectedAccountId, selectedOrganizationId)
      const result = await operation(client)
      await client.query('commit')
      begun = false
      return result
    } catch (error) {
      if (begun) {
        try { await client.query('rollback') } catch {
          throw new RegistryTenancyError('unavailable')
        }
      }
      if (error instanceof RegistryTenancyError) throw error
      throw new RegistryTenancyError('unavailable')
    } finally { client.release() }
  }

  private async setContext(client: PoolClient, selectedAccountId: string,
    selectedOrganizationId: string): Promise<void> {
    const result = await client.query<{ readonly account_id: string; readonly organization_id: string }>(
      `select set_config('app.account_id', $1, true) as account_id,
        set_config('app.organization_id', $2, true) as organization_id`,
      [selectedAccountId, selectedOrganizationId],
    )
    const row = result.rows[0]
    if (row?.account_id !== selectedAccountId || row.organization_id !== selectedOrganizationId) {
      throw new RegistryTenancyError('unavailable')
    }
  }

  private advisoryLock(client: PoolClient, value: string): Promise<unknown> {
    const lockKey = createHash('sha256').update(value, 'utf8').digest().readBigInt64BE(0).toString()
    return client.query('select pg_advisory_xact_lock($1::bigint)', [lockKey])
  }

  private async requireAccount(client: PoolClient, selectedAccountId: RegistryAccountId,
    selectedMemberId: MemberId): Promise<AccountRow> {
    const result = await client.query<AccountRow>(
      `select id, member_id, display_name, created_at, updated_at
       from ${this.schema}.accounts where id = $1 and member_id = $2`,
      [selectedAccountId, selectedMemberId],
    )
    const row = result.rows[0]
    if (row === undefined) throw new RegistryTenancyError('not-found')
    return row
  }

  private accessQuery(where: string, orderBy?: string): string {
    return `select organization.id as organization_id, organization.slug as organization_slug,
      organization.display_name as organization_display_name, organization.state as organization_state,
      organization.created_at as organization_created_at, organization.updated_at as organization_updated_at,
      membership.account_id as membership_account_id, membership.member_id as membership_member_id,
      membership.role as membership_role, membership.state as membership_state,
      membership.created_at as membership_created_at, membership.updated_at as membership_updated_at
      from ${this.schema}.organizations as organization
      join ${this.schema}.organization_memberships as membership on membership.organization_id = organization.id
      where ${where}${orderBy === undefined ? '' : ` order by ${orderBy}`}`
  }

  private async selectAccess(client: PoolClient, selectedAccountId: RegistryAccountId,
    selectedOrganizationId: OrganizationId | string): Promise<RegistryOrganizationAccess | null> {
    const result = await client.query<OrganizationAccessRow>(this.accessQuery(
      `membership.account_id = $1 and membership.organization_id = $2 and membership.state = 'active'`),
    [selectedAccountId, selectedOrganizationId])
    const row = result.rows[0]
    return row === undefined ? null : accessOf(row)
  }

  private async uniqueSlug(client: PoolClient, displayName: string, uniqueId: string): Promise<string> {
    const base = normalizedSlug(displayName)
    await this.advisoryLock(client, `organization-slug\0${base}`)
    const existing = await client.query<{ readonly slug: string }>(
      `select slug from ${this.schema}.organizations where slug = $1`, [base])
    if (existing.rows.length === 0) return base
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const suffix = createHash('sha256').update(`${uniqueId}\0${String(attempt)}`, 'utf8').digest('hex').slice(0, 12)
      const candidate = `${base.slice(0, 50).replace(/-+$/u, '')}-${suffix}`
      const collision = await client.query(`select 1 from ${this.schema}.organizations where slug = $1`, [candidate])
      if (collision.rows.length === 0) return candidate
    }
    throw new RegistryTenancyError('conflict')
  }
}
