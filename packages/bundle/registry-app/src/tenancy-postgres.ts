/** PostgreSQL SaaS control plane with transaction-local account/organization RLS contexts. */
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import type { MemberId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { Pool, type PoolClient } from 'pg'
import type {
  RegistryBillingCheckoutAttachment,
  RegistryBillingEvent,
  RegistryBillingEventType,
  RegistryBillingOrder,
  RegistryBillingOrderReservation,
  RegistryBillingOrderState,
  RegistryBillingProviderName,
} from './billing.ts'
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
import { STORAGE_POSTGRES_SCHEMA_VERSION } from '@deepseek-ai/dsh-storage-postgres'

const SCHEMA_VERSION = 3
const READINESS_QUERY_TIMEOUT_MS = 1_500
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
const MAX_BILLING_ORDERS = 100
const SHA256 = /^[0-9a-f]{64}$/u
const CURRENCY = /^[A-Z]{3}$/u
const TENANCY_TABLES = [
  'tenancy_meta',
  'accounts',
  'account_identities',
  'organizations',
  'organization_memberships',
  'organization_creations',
  'organization_invitations',
  'billing_orders',
  'billing_provider_events',
] as const
const REGISTRY_META_TABLES = ['storage_meta', 'tenancy_meta'] as const
const REGISTRY_BUSINESS_TABLES = [
  'units', 'unit_globals', 'unit_records',
  'accounts', 'account_identities', 'organizations', 'organization_memberships',
  'organization_creations', 'organization_invitations', 'billing_orders', 'billing_provider_events',
] as const
const TENANT_SCOPED_TABLES = [
  'organizations',
  'organization_memberships',
  'organization_creations',
  'organization_invitations',
  'billing_orders',
  'billing_provider_events',
] as const
const TENANCY_POLICIES = [
  { table: 'organizations', name: 'organizations_select', command: 'r', using: true, check: false },
  { table: 'organizations', name: 'organizations_insert', command: 'a', using: false, check: true },
  { table: 'organizations', name: 'organizations_update', command: 'w', using: true, check: true },
  { table: 'organization_memberships', name: 'organization_memberships_select', command: 'r',
    using: true, check: false },
  { table: 'organization_memberships', name: 'organization_memberships_insert', command: 'a',
    using: false, check: true },
  { table: 'organization_memberships', name: 'organization_memberships_update', command: 'w',
    using: true, check: true },
  { table: 'organization_creations', name: 'organization_creations_select', command: 'r',
    using: true, check: false },
  { table: 'organization_creations', name: 'organization_creations_insert', command: 'a',
    using: false, check: true },
  { table: 'organization_invitations', name: 'organization_invitations_select', command: 'r',
    using: true, check: false },
  { table: 'organization_invitations', name: 'organization_invitations_insert', command: 'a',
    using: false, check: true },
  { table: 'organization_invitations', name: 'organization_invitations_update', command: 'w',
    using: true, check: true },
  { table: 'billing_orders', name: 'billing_orders_select', command: 'r', using: true, check: false },
  { table: 'billing_orders', name: 'billing_orders_insert', command: 'a', using: false, check: true },
  { table: 'billing_orders', name: 'billing_orders_update', command: 'w', using: true, check: true },
  { table: 'billing_provider_events', name: 'billing_provider_events_select', command: 'r',
    using: true, check: false },
  { table: 'billing_provider_events', name: 'billing_provider_events_insert', command: 'a',
    using: false, check: true },
] as const

export type PostgresRegistryTenancySchemaMode = 'migrate' | 'validate'

export interface PostgresRegistryTenancyConfig {
  readonly connectionString: string
  readonly schema?: string
  /** `migrate` owns offline DDL; `validate` is the least-privilege online startup path. */
  readonly schemaMode?: PostgresRegistryTenancySchemaMode
  /** Local migration escape hatch; production must leave this false. */
  readonly allowUnsafeSharedDatabase?: boolean
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

interface BillingOrderRow {
  readonly order_id: string
  readonly organization_id: string
  readonly provider: RegistryBillingProviderName
  readonly plan_id: string
  readonly currency: string
  readonly unit_amount: string
  readonly interval: RegistryBillingOrder['interval']
  readonly state: RegistryBillingOrderState
  readonly provider_checkout_id: string | null
  readonly checkout_expires_at: Date | null
  readonly paid_at: Date | null
  readonly refunded_at: Date | null
  readonly disputed_at: Date | null
  readonly last_event_at: Date | null
  readonly created_at: Date
  readonly updated_at: Date
}

interface BillingEventRow {
  readonly organization_id: string
  readonly order_id: string
  readonly provider: RegistryBillingProviderName
  readonly event_id: string
  readonly event_type: RegistryBillingEventType
  readonly payload_hash: string
  readonly occurred_at: Date
}

interface TenancyTableRow {
  readonly relname: string
  readonly relrowsecurity: boolean
  readonly relforcerowsecurity: boolean
  readonly owner_member: boolean
  readonly can_select: boolean
  readonly can_insert: boolean
  readonly can_update: boolean
  readonly can_delete: boolean
  readonly reachable_insert: boolean
  readonly reachable_update: boolean
  readonly reachable_delete: boolean
  readonly reachable_truncate: boolean
  readonly reachable_references: boolean
  readonly reachable_trigger: boolean
  readonly reachable_maintain: boolean
}

export interface TenancyPolicyRow {
  readonly table_name: string
  readonly policy_name: string
  readonly command: string
  readonly permissive: boolean
  readonly public_only: boolean
  readonly has_using: boolean
  readonly has_check: boolean
  readonly roles_definition: string
  readonly using_definition: string | null
  readonly check_definition: string | null
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

function billingRequestHash(input: RegistryBillingOrderReservation): string {
  return createHash('sha256').update('registry-billing-order-v1\0', 'utf8').update(JSON.stringify([
    input.provider, input.planId, input.currency, input.unitAmount, input.interval,
  ]), 'utf8').digest('hex')
}

function billingOrderOf(row: BillingOrderRow): RegistryBillingOrder {
  if (!UUID.test(row.order_id)) throw new RegistryTenancyError('unavailable')
  const unitAmount = Number(row.unit_amount)
  if (!Number.isSafeInteger(unitAmount) || unitAmount < 0) throw new RegistryTenancyError('unavailable')
  return {
    orderId: row.order_id,
    organizationId: organizationId(row.organization_id),
    provider: row.provider,
    planId: row.plan_id,
    currency: row.currency,
    unitAmount,
    interval: row.interval,
    state: row.state,
    providerCheckoutId: row.provider_checkout_id,
    checkoutExpiresAt: row.checkout_expires_at === null ? null : milliseconds(row.checkout_expires_at),
    paidAt: row.paid_at === null ? null : milliseconds(row.paid_at),
    refundedAt: row.refunded_at === null ? null : milliseconds(row.refunded_at),
    disputedAt: row.disputed_at === null ? null : milliseconds(row.disputed_at),
    lastEventAt: row.last_event_at === null ? null : milliseconds(row.last_event_at),
    createdAt: milliseconds(row.created_at),
    updatedAt: milliseconds(row.updated_at),
  }
}

function billingEventState(eventType: RegistryBillingEventType): RegistryBillingOrderState {
  if (eventType === 'checkout-paid') return 'paid'
  if (eventType === 'checkout-expired') return 'expired'
  if (eventType === 'checkout-failed') return 'failed'
  if (eventType === 'refunded') return 'refunded'
  if (eventType === 'disputed') return 'disputed'
  throw new RegistryTenancyError('invalid-input')
}

function sameBillingEvent(row: BillingEventRow, input: RegistryBillingEvent,
  selectedOrganizationId: OrganizationId): boolean {
  return row.organization_id === selectedOrganizationId && row.order_id === input.orderId
    && row.provider === input.provider && row.event_type === input.eventType
    && row.payload_hash === input.payloadHash && milliseconds(row.occurred_at) === input.occurredAt
}

const BILLING_STATE_PRIORITY: Readonly<Record<RegistryBillingOrderState, number>> = {
  creating: 0,
  'checkout-pending': 1,
  failed: 2,
  expired: 3,
  paid: 4,
  disputed: 5,
  refunded: 6,
}

function advancesBillingState(current: RegistryBillingOrderState,
  target: RegistryBillingOrderState): boolean {
  return BILLING_STATE_PRIORITY[target] > BILLING_STATE_PRIORITY[current]
}

function postgresCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const value = Reflect.get(error, 'code')
  return typeof value === 'string' ? value : undefined
}

/** Stable across dump/restore because policy expressions and roles contain no catalog object OIDs. */
export function fingerprintTenancyPolicies(rows: readonly TenancyPolicyRow[]): string {
  const definitions = [...rows].sort((left, right) => {
    if (left.table_name !== right.table_name) return left.table_name < right.table_name ? -1 : 1
    if (left.policy_name !== right.policy_name) return left.policy_name < right.policy_name ? -1 : 1
    return 0
  }).map(row => JSON.stringify([
    row.table_name,
    row.policy_name,
    row.command,
    row.permissive,
    row.public_only,
    row.has_using,
    row.has_check,
    row.roles_definition,
    row.using_definition,
    row.check_definition,
  ])).join('\n')
  return createHash('sha256').update('registry-tenancy-policy-v3\0', 'utf8').update(definitions, 'utf8').digest('hex')
}

export const TENANCY_POLICY_DEPARSE_SEARCH_PATH = 'pg_catalog'
export const TENANCY_POLICY_DEPARSE_QUOTE_ALL_IDENTIFIERS = 'off'

/** Session-local settings are part of the canonical deparse contract and must be verified before hashing. */
export const TENANCY_POLICY_DEPARSE_SETTINGS_QUERY = `select
       pg_catalog.set_config('search_path', $1, true) as search_path,
       pg_catalog.set_config('quote_all_identifiers', $2, true) as quote_all_identifiers`

/** Catalog query is exported only so the restore-stability contract can be covered without a live database. */
export const TENANCY_POLICY_CATALOG_QUERY = `select c.relname as table_name,
       p.polname as policy_name,
       p.polcmd::text as command,
       p.polpermissive as permissive,
       (cardinality(p.polroles) = 1 and 0::oid = any(p.polroles)) as public_only,
       p.polqual is not null as has_using,
       p.polwithcheck is not null as has_check,
       (
         select coalesce(pg_catalog.jsonb_agg(role_name order by role_name), '[]'::jsonb)::text
         from (
           select case when selected_role.role_oid = 0 then 'PUBLIC' else role.rolname end as role_name
           from pg_catalog.unnest(p.polroles) as selected_role(role_oid)
           left join pg_catalog.pg_roles as role on role.oid = selected_role.role_oid
         ) as policy_roles
       ) as roles_definition,
       pg_catalog.pg_get_expr(p.polqual, p.polrelid, false) as using_definition,
       pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid, false) as check_definition
from pg_catalog.pg_policy as p
join pg_catalog.pg_class as c on c.oid = p.polrelid
join pg_catalog.pg_namespace as n on n.oid = c.relnamespace
where n.nspname = $1 and c.relname = any($2::text[])`

async function requireExactRegistryBackupRole(client: PoolClient): Promise<number> {
  const state = await client.query<{ readonly oid: number; readonly unsafe: boolean }>(
    `with backup_role as (
       select oid, rolcanlogin, rolinherit, rolconnlimit, rolbypassrls,
              rolsuper, rolcreatedb, rolcreaterole, rolreplication
       from pg_roles where rolname = 'registry_backup'
     )
     select backup_role.oid,
       not backup_role.rolcanlogin
       or backup_role.rolinherit
       or backup_role.rolconnlimit <> 2
       or not backup_role.rolbypassrls
       or backup_role.rolsuper
       or backup_role.rolcreatedb
       or backup_role.rolcreaterole
       or backup_role.rolreplication
       or exists (
         select 1 from pg_auth_members membership
         where membership.member = backup_role.oid or membership.roleid = backup_role.oid
       )
       or not has_database_privilege(backup_role.oid, current_database(), 'CONNECT')
       or has_database_privilege(backup_role.oid, current_database(), 'CREATE')
       or has_database_privilege(backup_role.oid, current_database(), 'TEMP')
       or exists (
         select 1 from pg_database database
         where database.datname <> current_database()
           and has_database_privilege(backup_role.oid, database.oid, 'CONNECT')
       )
       or exists (
         select 1 from pg_database database
         where database.datname <> current_database()
           and database.datname <> 'postgres' and not database.datistemplate
       )
       or not exists (
         select 1
         from pg_database database
         cross join lateral aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) acl
         where database.datname = current_database()
           and acl.grantee = backup_role.oid
           and acl.privilege_type = 'CONNECT'
           and not acl.is_grantable
       )
       or exists (
         select 1
         from pg_database database
         cross join lateral aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) acl
         where database.datname = current_database()
           and acl.grantee = backup_role.oid
           and (acl.privilege_type <> 'CONNECT' or acl.is_grantable)
       )
       or exists (
         select 1
         from pg_namespace namespace
         where namespace.nspname <> 'information_schema'
           and namespace.nspname !~ '^pg_'
           and (
             has_schema_privilege(backup_role.oid, namespace.oid, 'CREATE')
             or exists (
               select 1
               from aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) acl
               where acl.grantee = backup_role.oid
                 and (acl.privilege_type <> 'USAGE' or acl.is_grantable)
             )
           )
       )
       or exists (
         select 1
         from pg_class relation
         join pg_namespace namespace on namespace.oid = relation.relnamespace
         where namespace.nspname <> 'information_schema'
           and namespace.nspname !~ '^pg_'
           and relation.relkind in ('r', 'p', 'v', 'm', 'f')
           and (
             has_table_privilege(backup_role.oid, relation.oid,
               'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
             or has_any_column_privilege(backup_role.oid, relation.oid, 'INSERT, UPDATE, REFERENCES')
             or exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) acl
               where acl.grantee = backup_role.oid
                 and (acl.privilege_type <> 'SELECT' or acl.is_grantable)
             )
             or exists (
               select 1
               from pg_attribute attribute
               cross join lateral aclexplode(attribute.attacl) acl
               where attribute.attrelid = relation.oid
                 and attribute.attnum > 0
                 and not attribute.attisdropped
                 and acl.grantee = backup_role.oid
             )
           )
       )
       or exists (
         select 1
         from pg_sequence sequence
         join pg_class relation on relation.oid = sequence.seqrelid
         join pg_namespace namespace on namespace.oid = relation.relnamespace
         where namespace.nspname <> 'information_schema'
           and namespace.nspname !~ '^pg_'
           and (
             has_sequence_privilege(backup_role.oid, relation.oid, 'USAGE, UPDATE')
             or exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) acl
               where acl.grantee = backup_role.oid
                 and (acl.privilege_type <> 'SELECT' or acl.is_grantable)
             )
           )
       ) as unsafe
     from backup_role`,
  )
  const selected = state.rows[0]
  if (state.rows.length !== 1 || selected?.unsafe || selected.oid === undefined) {
    throw new RegistryTenancyError('unavailable')
  }
  return selected.oid
}

async function requireRegistryBackupTargetIsolation(client: PoolClient, schemaName: string,
  backupRoleOid: number): Promise<void> {
  const state = await client.query<{ readonly unsafe: boolean }>(
    `select exists (
       select 1
       from pg_namespace namespace
       where namespace.nspname <> $1
         and namespace.nspname <> 'information_schema'
         and namespace.nspname !~ '^pg_'
         and (
           has_schema_privilege($2::oid, namespace.oid, 'USAGE')
           or has_schema_privilege($2::oid, namespace.oid, 'CREATE')
           or exists (
             select 1
             from aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) acl
             where acl.grantee = $2::oid
           )
         )
     ) or exists (
       select 1
       from pg_class relation
       join pg_namespace namespace on namespace.oid = relation.relnamespace
       where namespace.nspname <> $1
         and namespace.nspname <> 'information_schema'
         and namespace.nspname !~ '^pg_'
         and relation.relkind in ('r', 'p', 'v', 'm', 'f')
         and (
           has_table_privilege($2::oid, relation.oid,
             'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
           or has_any_column_privilege($2::oid, relation.oid,
             'SELECT, INSERT, UPDATE, REFERENCES')
         )
     ) or exists (
       select 1
       from pg_sequence sequence
       join pg_class relation on relation.oid = sequence.seqrelid
       join pg_namespace namespace on namespace.oid = relation.relnamespace
       where namespace.nspname <> $1
         and namespace.nspname <> 'information_schema'
         and namespace.nspname !~ '^pg_'
         and has_sequence_privilege($2::oid, relation.oid, 'USAGE, SELECT, UPDATE')
     ) as unsafe`,
    [schemaName, backupRoleOid],
  )
  if (state.rows.length !== 1 || state.rows[0]?.unsafe) throw new RegistryTenancyError('unavailable')
}

async function requireRegistryBackupDefaultPrivileges(client: PoolClient, schemaName: string,
  backupRoleOid: number): Promise<void> {
  const state = await client.query<{ readonly unsafe: boolean }>(
    `select exists (
       select 1
       from pg_default_acl defaults
       join pg_roles owner on owner.oid = defaults.defaclrole
       left join pg_namespace namespace on namespace.oid = defaults.defaclnamespace
       cross join lateral aclexplode(defaults.defaclacl) acl
       where acl.grantee = $2::oid
         and (defaults.defaclnamespace = 0
           or owner.rolname <> 'registry_migrator'
           or defaults.defaclobjtype not in ('r', 'S')
           or acl.privilege_type <> 'SELECT'
           or acl.is_grantable
           or namespace.nspname is distinct from $1)
     ) or (
       select count(distinct defaults.defaclobjtype)
       from pg_default_acl defaults
       join pg_roles owner on owner.oid = defaults.defaclrole
       join pg_namespace namespace on namespace.oid = defaults.defaclnamespace
       cross join lateral aclexplode(defaults.defaclacl) acl
       where owner.rolname = 'registry_migrator'
         and namespace.nspname = $1
         and defaults.defaclobjtype in ('r', 'S')
         and acl.grantee = $2::oid
         and acl.privilege_type = 'SELECT'
         and not acl.is_grantable
     ) <> 2 as unsafe`,
    [schemaName, backupRoleOid],
  )
  if (state.rows.length !== 1 || state.rows[0]?.unsafe) throw new RegistryTenancyError('unavailable')
}

async function requireExactRegistryObjectPrivileges(client: PoolClient, schemaName: string,
  backupRoleOid: number): Promise<void> {
  const state = await client.query<{ readonly unsafe: boolean }>(
    `with runtime_role as (
       select oid from pg_roles where rolname = current_user
     )
     select not exists (select 1 from runtime_role)
       or exists (
         select 1
         from pg_class relation
         join pg_namespace namespace on namespace.oid = relation.relnamespace
         cross join runtime_role
         where namespace.nspname = $1 and relation.relkind in ('r', 'p', 'v', 'm', 'f')
           and (
             pg_get_userbyid(relation.relowner) <> 'registry_migrator'
             or exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) acl
               where acl.grantee not in (relation.relowner, runtime_role.oid, $4::oid)
                 or (acl.grantee = runtime_role.oid and (
                   acl.is_grantable
                   or case
                     when relation.relname = any($2::text[]) then acl.privilege_type <> 'SELECT'
                     when relation.relname = any($3::text[]) then not (
                       acl.privilege_type = any(array['SELECT', 'INSERT', 'UPDATE', 'DELETE']::text[])
                     )
                     else true
                   end
                 ))
                 or (acl.grantee = $4::oid and (
                   acl.privilege_type <> 'SELECT' or acl.is_grantable
                 ))
             )
             or exists (
               select 1
               from pg_attribute attribute
               cross join lateral aclexplode(attribute.attacl) acl
               where attribute.attrelid = relation.oid and attribute.attnum > 0
                 and not attribute.attisdropped and acl.grantee <> relation.relowner
             )
             or not exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) acl
               where acl.grantee = $4::oid
                 and acl.privilege_type = 'SELECT'
                 and not acl.is_grantable
             )
             or not has_table_privilege($4::oid, relation.oid, 'SELECT')
             or has_table_privilege($4::oid, relation.oid, 'INSERT')
             or has_table_privilege($4::oid, relation.oid, 'UPDATE')
             or has_table_privilege($4::oid, relation.oid, 'DELETE')
             or has_table_privilege($4::oid, relation.oid, 'TRUNCATE')
             or has_table_privilege($4::oid, relation.oid, 'REFERENCES')
             or has_table_privilege($4::oid, relation.oid, 'TRIGGER')
             or has_table_privilege($4::oid, relation.oid, 'MAINTAIN')
             or case
               when relation.relname = any($2::text[]) then
                 not has_table_privilege(runtime_role.oid, relation.oid, 'SELECT')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'INSERT')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'UPDATE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'DELETE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'TRUNCATE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'REFERENCES')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'TRIGGER')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'MAINTAIN')
               when relation.relname = any($3::text[]) then
                 not has_table_privilege(runtime_role.oid, relation.oid, 'SELECT')
                 or not has_table_privilege(runtime_role.oid, relation.oid, 'INSERT')
                 or not has_table_privilege(runtime_role.oid, relation.oid, 'UPDATE')
                 or not has_table_privilege(runtime_role.oid, relation.oid, 'DELETE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'TRUNCATE')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'REFERENCES')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'TRIGGER')
                 or has_table_privilege(runtime_role.oid, relation.oid, 'MAINTAIN')
               else has_table_privilege(runtime_role.oid, relation.oid,
                 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
             end
           )
       )
       or exists (
         select 1
         from pg_sequence sequence
         join pg_class relation on relation.oid = sequence.seqrelid
         join pg_namespace namespace on namespace.oid = relation.relnamespace
         cross join runtime_role
         where namespace.nspname = $1
           and (
             pg_get_userbyid(relation.relowner) <> 'registry_migrator'
             or exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) acl
               where acl.grantee not in (relation.relowner, $4::oid)
                 or (acl.grantee = $4::oid and (
                   acl.privilege_type <> 'SELECT' or acl.is_grantable
                 ))
             )
             or has_sequence_privilege(runtime_role.oid, relation.oid, 'USAGE, SELECT, UPDATE')
             or not exists (
               select 1
               from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) acl
               where acl.grantee = $4::oid
                 and acl.privilege_type = 'SELECT'
                 and not acl.is_grantable
             )
             or not has_sequence_privilege($4::oid, relation.oid, 'SELECT')
             or has_sequence_privilege($4::oid, relation.oid, 'USAGE')
             or has_sequence_privilege($4::oid, relation.oid, 'UPDATE')
           )
       ) as unsafe`,
    [schemaName, [...REGISTRY_META_TABLES], [...REGISTRY_BUSINESS_TABLES], backupRoleOid],
  )
  if (state.rows.length !== 1 || state.rows[0]?.unsafe) throw new RegistryTenancyError('unavailable')
}

/** Dedicated PostgreSQL implementation; construction waits for schema migration or read-only validation. */
export class PostgresRegistryTenancy implements RegistryTenancyStore {
  private readonly pool: Pool
  private readonly schemaName: string
  private readonly schema: string
  private readonly schemaMode: PostgresRegistryTenancySchemaMode
  private readonly allowUnsafeSharedDatabase: boolean
  private readonly maxOrganizationsPerAccount: number
  private policyFingerprint: string | undefined
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
    this.schemaMode = config.schemaMode ?? 'migrate'
    if (this.schemaMode !== 'migrate' && this.schemaMode !== 'validate') {
      throw new RegistryTenancyError('invalid-input')
    }
    this.allowUnsafeSharedDatabase = config.allowUnsafeSharedDatabase ?? false
    this.maxOrganizationsPerAccount = maxOrganizationsPerAccount
    this.pool = new Pool({
      connectionString: config.connectionString,
      max: maximum,
      idleTimeoutMillis: idle,
      connectionTimeoutMillis: 10_000,
      query_timeout: statement,
      statement_timeout: statement,
      idle_in_transaction_session_timeout: 30_000,
      application_name: 'dsh-a2a-registry-tenancy',
    })
  }

  /** Open after either the offline migration or the read-only online validation has completed. */
  static async open(config: PostgresRegistryTenancyConfig): Promise<PostgresRegistryTenancy> {
    const store = new PostgresRegistryTenancy(config)
    try {
      if (store.schemaMode === 'migrate') await store.applySchemaMigration()
      else await store.validateSchema()
      return store
    } catch (error) {
      await store.pool.end().catch(() => {})
      if (error instanceof RegistryTenancyError) throw error
      throw new RegistryTenancyError('unavailable')
    }
  }

  /** Explicit one-shot entry point for an offline migration CLI. It never returns a live store. */
  static async migrateSchema(config: Omit<PostgresRegistryTenancyConfig, 'schemaMode'>): Promise<void> {
    const store = new PostgresRegistryTenancy({ ...config, schemaMode: 'migrate' })
    try {
      await store.applySchemaMigration()
    } catch (error) {
      if (error instanceof RegistryTenancyError) throw error
      throw new RegistryTenancyError('unavailable')
    } finally {
      await store.pool.end().catch(() => {})
    }
  }

  /**
   * Check the live authoritative database through the online pool without
   * changing state. Both metadata rows are required so readiness cannot report
   * success for a reachable PostgreSQL server that has lost either Registry
   * authority.
   */
  async checkReadiness(): Promise<boolean> {
    if (this.closed) return false
    try {
      const result = await this.pool.query<{
        readonly policy_fingerprint: string | null
        readonly storage_version: number
        readonly tenancy_version: number
      }>({
        text: `select storage.schema_version as storage_version,
            tenancy.schema_version as tenancy_version, tenancy.policy_fingerprint
          from ${this.schema}.storage_meta as storage
          cross join ${this.schema}.tenancy_meta as tenancy
          where storage.singleton = true and tenancy.singleton = true`,
        query_timeout: READINESS_QUERY_TIMEOUT_MS,
      } as { readonly text: string; readonly query_timeout: number })
      return result.rows.length === 1
        && result.rows[0]?.storage_version === STORAGE_POSTGRES_SCHEMA_VERSION
        && result.rows[0]?.tenancy_version === SCHEMA_VERSION
        && this.policyFingerprint !== undefined
        && result.rows[0]?.policy_fingerprint === this.policyFingerprint
    } catch {
      return false
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

  async reserveBillingOrder(valueAccountId: RegistryAccountId, valueMemberId: MemberId,
    input: RegistryBillingOrderReservation): Promise<RegistryBillingOrder> {
    const selectedAccountId = accountId(valueAccountId)
    const selectedMemberId = memberId(valueMemberId)
    const selectedOrganizationId = organizationId(input.organizationId)
    if ((input.provider !== 'stripe' && input.provider !== 'alipay') || !IDENTIFIER.test(input.planId)
      || !IDEMPOTENCY_KEY.test(input.idempotencyKey) || !CURRENCY.test(input.currency)
      || !Number.isSafeInteger(input.unitAmount) || input.unitAmount < 0
      || (input.interval !== 'month' && input.interval !== 'year')) {
      throw new RegistryTenancyError('invalid-input')
    }
    const requestHash = billingRequestHash(input)
    const nextOrderId = randomUUID()
    return this.transaction(selectedAccountId, selectedOrganizationId, async (client) => {
      const membership = await this.requireActiveMembership(client, selectedAccountId, selectedMemberId,
        selectedOrganizationId)
      if (membership.role !== 'owner') throw new RegistryTenancyError('not-found')
      await this.advisoryLock(client,
        `billing-order\0${selectedOrganizationId}\0${input.idempotencyKey}`)
      const previous = await client.query<BillingOrderRow & { readonly request_hash: string }>(
        this.billingOrderQuery('organization_id = $1 and idempotency_key = $2', '', ', request_hash'),
        [selectedOrganizationId, input.idempotencyKey],
      )
      const existing = previous.rows[0]
      if (existing !== undefined) {
        if (existing.request_hash !== requestHash) throw new RegistryTenancyError('conflict')
        return billingOrderOf(existing)
      }
      const inserted = await client.query<BillingOrderRow>(
        `insert into ${this.schema}.billing_orders
          (order_id, organization_id, idempotency_key, request_hash, provider, plan_id,
           currency, unit_amount, interval, state)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'creating')
         returning ${this.billingOrderColumns()}`,
        [nextOrderId, selectedOrganizationId, input.idempotencyKey, requestHash, input.provider,
          input.planId, input.currency, input.unitAmount, input.interval],
      )
      const row = inserted.rows[0]
      if (row === undefined) throw new RegistryTenancyError('unavailable')
      return billingOrderOf(row)
    })
  }

  async attachBillingCheckout(input: RegistryBillingCheckoutAttachment): Promise<RegistryBillingOrder> {
    const selectedOrganizationId = organizationId(input.organizationId)
    if (!UUID.test(input.orderId) || (input.provider !== 'stripe' && input.provider !== 'alipay')
      || !nonEmptyBounded(input.providerCheckoutId, 512) || !Number.isSafeInteger(input.expiresAt)
      || input.expiresAt < 0) throw new RegistryTenancyError('invalid-input')
    const expiresAt = new Date(input.expiresAt)
    if (!Number.isFinite(expiresAt.getTime())) throw new RegistryTenancyError('invalid-input')
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId, async (client) => {
      const selected = await client.query<BillingOrderRow>(
        this.billingOrderQuery('organization_id = $1 and order_id = $2', ' for update'),
        [selectedOrganizationId, input.orderId],
      )
      const current = selected.rows[0]
      if (current === undefined) throw new RegistryTenancyError('not-found')
      if (current.provider !== input.provider
        || (current.provider_checkout_id !== null && current.provider_checkout_id !== input.providerCheckoutId)
        || (current.checkout_expires_at !== null
          && milliseconds(current.checkout_expires_at) !== input.expiresAt)) {
        throw new RegistryTenancyError('conflict')
      }
      if (current.provider_checkout_id !== null) return billingOrderOf(current)
      let updated: BillingOrderRow
      try {
        const result = await client.query<BillingOrderRow>(
          `update ${this.schema}.billing_orders
           set provider_checkout_id = $3, checkout_expires_at = $4,
             state = case when state = 'creating' then 'checkout-pending' else state end,
             updated_at = now()
           where organization_id = $1 and order_id = $2
           returning ${this.billingOrderColumns()}`,
          [selectedOrganizationId, input.orderId, input.providerCheckoutId, expiresAt],
        )
        const row = result.rows[0]
        if (row === undefined) throw new RegistryTenancyError('unavailable')
        updated = row
      } catch (error) {
        if (postgresCode(error) === '23505') throw new RegistryTenancyError('conflict')
        throw error
      }
      return billingOrderOf(updated)
    })
  }

  async listBillingOrders(valueAccountId: RegistryAccountId, valueMemberId: MemberId,
    valueOrganizationId: OrganizationId): Promise<readonly RegistryBillingOrder[]> {
    const selectedAccountId = accountId(valueAccountId)
    const selectedMemberId = memberId(valueMemberId)
    const selectedOrganizationId = organizationId(valueOrganizationId)
    return this.transaction(selectedAccountId, selectedOrganizationId, async (client) => {
      const membership = await this.requireActiveMembership(client, selectedAccountId, selectedMemberId,
        selectedOrganizationId)
      if (membership.role !== 'owner') throw new RegistryTenancyError('not-found')
      const result = await client.query<BillingOrderRow>(
        this.billingOrderQuery('organization_id = $1',
          ' order by created_at desc, order_id desc limit $2'),
        [selectedOrganizationId, MAX_BILLING_ORDERS],
      )
      return result.rows.map(billingOrderOf)
    })
  }

  async applyVerifiedBillingEvent(input: RegistryBillingEvent): Promise<RegistryBillingOrder> {
    const selectedOrganizationId = organizationId(input.organizationId)
    if (!UUID.test(input.orderId) || (input.provider !== 'stripe' && input.provider !== 'alipay')
      || !nonEmptyBounded(input.eventId, 512) || !nonEmptyBounded(input.eventType, 64)
      || !SHA256.test(input.payloadHash) || !Number.isSafeInteger(input.occurredAt) || input.occurredAt < 0) {
      throw new RegistryTenancyError('invalid-input')
    }
    const targetState = billingEventState(input.eventType)
    const occurredAt = new Date(input.occurredAt)
    if (!Number.isFinite(occurredAt.getTime())) throw new RegistryTenancyError('invalid-input')
    return this.transaction(CONTROL_ACCOUNT_CONTEXT, selectedOrganizationId, async (client) => {
      const retained = await client.query<BillingEventRow>(
        `select organization_id, order_id, provider, event_id, event_type, payload_hash, occurred_at
         from ${this.schema}.billing_provider_events where provider = $1 and event_id = $2`,
        [input.provider, input.eventId],
      )
      const duplicate = retained.rows[0]
      if (duplicate !== undefined) {
        if (!sameBillingEvent(duplicate, input, selectedOrganizationId)) throw new RegistryTenancyError('conflict')
        const order = await client.query<BillingOrderRow>(
          this.billingOrderQuery('organization_id = $1 and order_id = $2'),
          [selectedOrganizationId, input.orderId],
        )
        const row = order.rows[0]
        if (row === undefined || row.provider !== input.provider) throw new RegistryTenancyError('unavailable')
        return billingOrderOf(row)
      }
      const selected = await client.query<BillingOrderRow>(
        this.billingOrderQuery('organization_id = $1 and order_id = $2', ' for update'),
        [selectedOrganizationId, input.orderId],
      )
      const current = selected.rows[0]
      if (current === undefined) throw new RegistryTenancyError('not-found')
      if (current.provider !== input.provider) throw new RegistryTenancyError('conflict')
      const recorded = await client.query<{ readonly provider: string }>(
          `insert into ${this.schema}.billing_provider_events
            (provider, event_id, organization_id, order_id, event_type, payload_hash, occurred_at)
           values ($1, $2, $3, $4, $5, $6, $7)
           on conflict (provider, event_id) do nothing returning provider`,
          [input.provider, input.eventId, selectedOrganizationId, input.orderId, input.eventType,
            input.payloadHash, occurredAt],
        )
      if (recorded.rows.length === 0) {
        const raced = await client.query<BillingEventRow>(
          `select organization_id, order_id, provider, event_id, event_type, payload_hash, occurred_at
           from ${this.schema}.billing_provider_events where provider = $1 and event_id = $2`,
          [input.provider, input.eventId],
        )
        const row = raced.rows[0]
        if (row === undefined || !sameBillingEvent(row, input, selectedOrganizationId)) {
          throw new RegistryTenancyError('conflict')
        }
        return billingOrderOf(current)
      }
      // Persist the verified event before projecting it. The materialized order state is monotonic by financial
      // severity, so delivery order and provider timestamp ties cannot regress it.
      const projectedState = advancesBillingState(current.state, targetState) ? targetState : current.state
      const result = await client.query<BillingOrderRow>(
        `update ${this.schema}.billing_orders set state = $3,
           paid_at = case
             when $5 = 'checkout-paid' then least(coalesce(paid_at, $4), $4)
             when $3 in ('paid', 'disputed', 'refunded') then coalesce(paid_at, $4)
             else paid_at end,
           refunded_at = case when $5 = 'refunded'
             then least(coalesce(refunded_at, $4), $4) else refunded_at end,
           disputed_at = case when $5 = 'disputed'
             then least(coalesce(disputed_at, $4), $4) else disputed_at end,
           last_event_at = greatest(coalesce(last_event_at, $4), $4), updated_at = now()
         where organization_id = $1 and order_id = $2
         returning ${this.billingOrderColumns()}`,
        [selectedOrganizationId, input.orderId, projectedState, occurredAt, input.eventType],
      )
      const row = result.rows[0]
      if (row === undefined) throw new RegistryTenancyError('unavailable')
      return billingOrderOf(row)
    })
  }

  close(): Promise<void> {
    if (this.closing !== undefined) return this.closing
    this.closed = true
    this.closing = this.pool.end()
    return this.closing
  }

  /** Production startup is catalog-only and runs inside a read-only transaction. */
  private async validateSchema(): Promise<void> {
    const client = await this.pool.connect()
    let begun = false
    try {
      await client.query('begin isolation level repeatable read read only')
      begun = true
      const runtimeIdentity = await client.query<{ readonly expected: boolean }>(
        `select current_user = 'registry_app' as expected`)
      if (runtimeIdentity.rows.length !== 1 || runtimeIdentity.rows[0]?.expected !== true) {
        throw new RegistryTenancyError('unavailable')
      }
      const backupRoleOid = await requireExactRegistryBackupRole(client)
      const namespace = await client.query<{
        readonly acl_is_exact: boolean
        readonly backup_can_create: boolean
        readonly backup_can_use: boolean
        readonly backup_enabled: boolean
        readonly can_create: boolean
        readonly can_use: boolean
        readonly oid: number
        readonly owner_is_migrator: boolean
      }>(`select n.oid, has_schema_privilege(current_user, n.oid, 'CREATE') as can_create,
                 has_schema_privilege(current_user, n.oid, 'USAGE') as can_use,
                 has_schema_privilege($2::oid, n.oid, 'CREATE') as backup_can_create,
                 has_schema_privilege($2::oid, n.oid, 'USAGE') as backup_can_use,
                 exists (
                   select 1
                   from aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) acl
                   where acl.grantee = $2::oid
                     and acl.privilege_type = 'USAGE'
                     and not acl.is_grantable
                 ) as backup_enabled,
                 pg_get_userbyid(n.nspowner) = 'registry_migrator' as owner_is_migrator,
                 not exists (
                   select 1
                   from aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) acl
                   where acl.grantee not in (
                       n.nspowner, (select oid from pg_roles where rolname = current_user), $2::oid
                     )
                     or (acl.grantee = (select oid from pg_roles where rolname = current_user)
                       and (acl.privilege_type <> 'USAGE' or acl.is_grantable))
                     or (acl.grantee = $2::oid
                       and (acl.privilege_type <> 'USAGE' or acl.is_grantable))
                 ) as acl_is_exact
          from pg_namespace as n where n.nspname = $1`, [this.schemaName, backupRoleOid])
      const selectedNamespace = namespace.rows[0]
      if (namespace.rows.length !== 1 || selectedNamespace?.can_create || selectedNamespace?.can_use !== true
        || selectedNamespace.backup_can_create || selectedNamespace.backup_can_use !== true
        || selectedNamespace.backup_enabled !== true
        || selectedNamespace.owner_is_migrator !== true || selectedNamespace.acl_is_exact !== true) {
        throw new RegistryTenancyError('unavailable')
      }
      await this.requireSafeRuntimeRole(client, selectedNamespace.oid, this.allowUnsafeSharedDatabase)
      await requireRegistryBackupTargetIsolation(client, this.schemaName, backupRoleOid)
      await requireRegistryBackupDefaultPrivileges(client, this.schemaName, backupRoleOid)
      await requireExactRegistryObjectPrivileges(client, this.schemaName, backupRoleOid)
      const tables = await client.query<TenancyTableRow>(
        `select c.relname, c.relrowsecurity, c.relforcerowsecurity,
                pg_has_role(current_user, c.relowner, 'MEMBER') as owner_member,
                has_table_privilege(current_user, c.oid, 'SELECT') as can_select,
                has_table_privilege(current_user, c.oid, 'INSERT') as can_insert,
                has_table_privilege(current_user, c.oid, 'UPDATE') as can_update,
                has_table_privilege(current_user, c.oid, 'DELETE') as can_delete,
                exists (
                  select 1 from pg_roles as role
                  where (role.rolname = current_user
                         or pg_has_role(current_user, role.oid, 'MEMBER')
                         or pg_has_role(current_user, role.oid, 'SET'))
                    and (has_table_privilege(role.oid, c.oid, 'INSERT')
                         or has_any_column_privilege(role.oid, c.oid, 'INSERT'))
                ) as reachable_insert,
                exists (
                  select 1 from pg_roles as role
                  where (role.rolname = current_user
                         or pg_has_role(current_user, role.oid, 'MEMBER')
                         or pg_has_role(current_user, role.oid, 'SET'))
                    and (has_table_privilege(role.oid, c.oid, 'UPDATE')
                         or has_any_column_privilege(role.oid, c.oid, 'UPDATE'))
                ) as reachable_update,
                exists (
                  select 1 from pg_roles as role
                  where (role.rolname = current_user
                         or pg_has_role(current_user, role.oid, 'MEMBER')
                         or pg_has_role(current_user, role.oid, 'SET'))
                    and has_table_privilege(role.oid, c.oid, 'DELETE')
                ) as reachable_delete,
                exists (
                  select 1 from pg_roles as role
                  where (role.rolname = current_user
                         or pg_has_role(current_user, role.oid, 'MEMBER')
                         or pg_has_role(current_user, role.oid, 'SET'))
                    and has_table_privilege(role.oid, c.oid, 'TRUNCATE')
                ) as reachable_truncate,
                exists (
                  select 1 from pg_roles as role
                  where (role.rolname = current_user
                         or pg_has_role(current_user, role.oid, 'MEMBER')
                         or pg_has_role(current_user, role.oid, 'SET'))
                    and (has_table_privilege(role.oid, c.oid, 'REFERENCES')
                         or has_any_column_privilege(role.oid, c.oid, 'REFERENCES'))
                ) as reachable_references,
                exists (
                  select 1 from pg_roles as role
                  where (role.rolname = current_user
                         or pg_has_role(current_user, role.oid, 'MEMBER')
                         or pg_has_role(current_user, role.oid, 'SET'))
                    and has_table_privilege(role.oid, c.oid, 'TRIGGER')
                ) as reachable_trigger,
                exists (
                  select 1 from pg_roles as role
                  where (role.rolname = current_user
                         or pg_has_role(current_user, role.oid, 'MEMBER')
                         or pg_has_role(current_user, role.oid, 'SET'))
                    and has_table_privilege(role.oid, c.oid, 'MAINTAIN')
                ) as reachable_maintain
         from pg_class as c
         join pg_namespace as n on n.oid = c.relnamespace
         where n.nspname = $1 and c.relname = any($2::text[]) and c.relkind in ('r', 'p')`,
        [this.schemaName, [...TENANCY_TABLES]],
      )
      if (tables.rows.length !== TENANCY_TABLES.length) throw new RegistryTenancyError('unavailable')
      const tableByName = new Map(tables.rows.map(row => [row.relname, row]))
      for (const tableName of TENANCY_TABLES) {
        const table = tableByName.get(tableName)
        if (table === undefined || table.owner_member) throw new RegistryTenancyError('unavailable')
        const hasUnsafeDdl = table.reachable_truncate || table.reachable_references
          || table.reachable_trigger || table.reachable_maintain
        if (tableName === 'tenancy_meta') {
          if (!table.can_select || table.reachable_insert || table.reachable_update
            || table.reachable_delete || hasUnsafeDdl) {
            throw new RegistryTenancyError('unavailable')
          }
        } else if (!table.can_select || !table.can_insert || !table.can_update || !table.can_delete
          || hasUnsafeDdl) {
          throw new RegistryTenancyError('unavailable')
        }
      }
      for (const tableName of TENANT_SCOPED_TABLES) {
        const table = tableByName.get(tableName)
        if (table?.relrowsecurity !== true || table.relforcerowsecurity !== true) {
          throw new RegistryTenancyError('unavailable')
        }
      }
      const version = await client.query<{
        readonly policy_fingerprint: string | null
        readonly schema_version: number
      }>(`select schema_version, policy_fingerprint
          from ${this.schema}.tenancy_meta where singleton = true`)
      const selectedVersion = version.rows[0]
      if (version.rows.length !== 1 || selectedVersion?.schema_version !== SCHEMA_VERSION
        || selectedVersion.policy_fingerprint === null) {
        throw new RegistryTenancyError('unavailable')
      }
      const policies = await this.readPolicies(client)
      this.requireExpectedPolicies(policies)
      if (fingerprintTenancyPolicies(policies) !== selectedVersion.policy_fingerprint) {
        throw new RegistryTenancyError('unavailable')
      }
      this.policyFingerprint = selectedVersion.policy_fingerprint
      await client.query('commit')
      begun = false
    } catch (error) {
      if (begun) {
        try { await client.query('rollback') } catch (rollbackError) {
          throw new AggregateError([error, rollbackError], 'Registry tenancy schema validation rollback failed')
        }
      }
      throw error
    } finally { client.release() }
  }

  private async applySchemaMigration(): Promise<void> {
    const client = await this.pool.connect()
    let begun = false
    try {
      await client.query('begin')
      begun = true
      await this.setContext(client, CONTROL_ACCOUNT_CONTEXT, EMPTY_ORGANIZATION_CONTEXT)
      await this.requireSafeMigrationRole(client)
      const schemaLock = await client.query<{ readonly acquired: boolean }>(
        `select pg_try_advisory_xact_lock(
           hashtextextended('dsh-registry-schema:' || $1::text, 0)
         ) as acquired`, [this.schemaName])
      if (schemaLock.rows[0]?.acquired !== true) throw new RegistryTenancyError('unavailable')
      const namespace = await client.query<{ readonly present: boolean }>(
        'select exists (select 1 from pg_namespace where nspname = $1) as present', [this.schemaName])
      if (namespace.rows[0]?.present !== true) await client.query(`create schema ${this.schema}`)
      await client.query(`create table if not exists ${this.schema}.tenancy_meta (
        singleton boolean primary key default true check (singleton),
        schema_version integer not null check (schema_version > 0),
        policy_fingerprint text check (policy_fingerprint is null or policy_fingerprint ~ '^[0-9a-f]{64}$')
      )`)
      await client.query(`alter table ${this.schema}.tenancy_meta add column if not exists policy_fingerprint text
        check (policy_fingerprint is null or policy_fingerprint ~ '^[0-9a-f]{64}$')`)
      await client.query(`insert into ${this.schema}.tenancy_meta (singleton, schema_version) values (true, $1)
        on conflict (singleton) do nothing`, [SCHEMA_VERSION])
      const version = await client.query<{ readonly schema_version: number }>(
        `select schema_version from ${this.schema}.tenancy_meta where singleton = true`)
      if (version.rows.length !== 1 || (version.rows[0]?.schema_version !== 1
        && version.rows[0]?.schema_version !== 2 && version.rows[0]?.schema_version !== SCHEMA_VERSION)) {
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
      await client.query(`create table if not exists ${this.schema}.billing_orders (
        order_id uuid primary key,
        organization_id text not null references ${this.schema}.organizations(id) on delete restrict,
        idempotency_key text not null check (
          idempotency_key ~ '^[A-Za-z0-9]([A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'),
        request_hash text not null check (request_hash ~ '^[0-9a-f]{64}$'),
        provider text not null check (provider in ('stripe', 'alipay')),
        plan_id text not null check (plan_id ~ '^[A-Za-z0-9]([A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'),
        currency text not null check (currency ~ '^[A-Z]{3}$'),
        unit_amount bigint not null check (unit_amount >= 0 and unit_amount <= 9007199254740991),
        interval text not null check (interval in ('month', 'year')),
        state text not null check (
          state in ('creating', 'checkout-pending', 'paid', 'refunded', 'disputed', 'failed', 'expired')),
        provider_checkout_id text check (provider_checkout_id is null or (
          provider_checkout_id = btrim(provider_checkout_id) and provider_checkout_id <> ''
          and octet_length(provider_checkout_id) <= 512 and provider_checkout_id !~ '[[:cntrl:]]')),
        checkout_expires_at timestamptz,
        paid_at timestamptz,
        refunded_at timestamptz,
        disputed_at timestamptz,
        last_event_at timestamptz,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        unique (organization_id, idempotency_key),
        unique (organization_id, order_id, provider),
        check ((provider_checkout_id is null) = (checkout_expires_at is null)),
        check (checkout_expires_at is null or checkout_expires_at > created_at),
        check ((paid_at is not null) = (state in ('paid', 'refunded', 'disputed'))),
        check (refunded_at is null or state = 'refunded'),
        check (disputed_at is null or paid_at is not null),
        check (updated_at >= created_at)
      )`)
      await client.query(`create unique index if not exists billing_orders_provider_checkout_uidx
        on ${this.schema}.billing_orders (provider, provider_checkout_id)
        where provider_checkout_id is not null`)
      await client.query(`create index if not exists billing_orders_owner_list_idx
        on ${this.schema}.billing_orders (organization_id, created_at desc, order_id desc)`)
      await client.query(`create table if not exists ${this.schema}.billing_provider_events (
        provider text not null check (provider in ('stripe', 'alipay')),
        event_id text not null check (event_id = btrim(event_id) and event_id <> ''
          and octet_length(event_id) <= 512 and event_id !~ '[[:cntrl:]]'),
        organization_id text not null,
        order_id uuid not null,
        event_type text not null check (event_type in (
          'checkout-paid', 'checkout-expired', 'checkout-failed', 'refunded', 'disputed')),
        payload_hash text not null check (payload_hash ~ '^[0-9a-f]{64}$'),
        occurred_at timestamptz not null,
        received_at timestamptz not null default now(),
        primary key (provider, event_id),
        foreign key (organization_id, order_id, provider)
          references ${this.schema}.billing_orders(organization_id, order_id, provider) on delete restrict
      )`)
      await client.query(`create index if not exists billing_provider_events_order_idx
        on ${this.schema}.billing_provider_events
          (organization_id, order_id, received_at desc, provider, event_id)`)
      await this.installPolicies(client)
      const policies = await this.readPolicies(client)
      this.requireExpectedPolicies(policies)
      const policyFingerprint = fingerprintTenancyPolicies(policies)
      await client.query(`update ${this.schema}.tenancy_meta
        set schema_version = $1, policy_fingerprint = $2 where singleton = true`,
      [SCHEMA_VERSION, policyFingerprint])
      this.policyFingerprint = policyFingerprint
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

  private async requireSafeMigrationRole(client: PoolClient): Promise<void> {
    const role = await client.query<{ readonly dangerous: boolean }>(
      `select exists (
         select 1 from pg_roles as role
         where (role.rolname = current_user
                or pg_has_role(current_user, role.oid, 'MEMBER')
                or pg_has_role(current_user, role.oid, 'SET'))
           and (role.rolsuper or role.rolbypassrls or role.rolcreatedb
                or role.rolcreaterole or role.rolreplication
                or (role.rolname <> current_user and role.rolname <> 'pg_read_all_stats'))
       ) as dangerous`)
    if (role.rows.length !== 1 || role.rows[0]?.dangerous !== false) {
      throw new RegistryTenancyError('unavailable')
    }
  }

  private async requireSafeRuntimeRole(client: PoolClient, schemaOid: number,
    allowUnsafeSharedDatabase: boolean): Promise<void> {
    const result = await client.query<{ readonly unsafe: boolean }>(
      `select exists (
         select 1 from pg_roles as role
         where (pg_has_role(current_user, role.oid, 'MEMBER')
                or pg_has_role(current_user, role.oid, 'SET'))
           and (role.rolname <> current_user
                or role.rolsuper or role.rolbypassrls or role.rolcreatedb or role.rolcreaterole
                or role.rolreplication or role.rolname = 'pg_read_all_stats'
                or has_database_privilege(role.oid, current_database(), 'CREATE')
                or has_database_privilege(role.oid, current_database(), 'TEMP')
                or has_schema_privilege(role.oid, $1::oid, 'CREATE')
                or (not $2::boolean and exists (
                  select 1 from pg_namespace as namespace
                  where has_schema_privilege(role.oid, namespace.oid, 'CREATE')
                )))
       ) as unsafe`, [schemaOid, allowUnsafeSharedDatabase])
    if (result.rows.length !== 1 || result.rows[0]?.unsafe !== false) {
      throw new RegistryTenancyError('unavailable')
    }
  }

  private async readPolicies(client: PoolClient): Promise<readonly TenancyPolicyRow[]> {
    // Rule deparsing uses search_path to decide whether object names need qualification and
    // quote_all_identifiers to decide whether every identifier is quoted. Fix and verify both settings so
    // migrator and runtime roles produce the same representation on every restored cluster.
    const settings = await client.query<{
      readonly quote_all_identifiers: string
      readonly search_path: string
    }>(TENANCY_POLICY_DEPARSE_SETTINGS_QUERY,
      [TENANCY_POLICY_DEPARSE_SEARCH_PATH, TENANCY_POLICY_DEPARSE_QUOTE_ALL_IDENTIFIERS])
    const selectedSettings = settings.rows[0]
    if (settings.rows.length !== 1 || selectedSettings?.search_path !== TENANCY_POLICY_DEPARSE_SEARCH_PATH
      || selectedSettings.quote_all_identifiers !== TENANCY_POLICY_DEPARSE_QUOTE_ALL_IDENTIFIERS) {
      throw new RegistryTenancyError('unavailable')
    }
    const result = await client.query<TenancyPolicyRow>(TENANCY_POLICY_CATALOG_QUERY,
      [this.schemaName, [...TENANT_SCOPED_TABLES]])
    return result.rows
  }

  private requireExpectedPolicies(policies: readonly TenancyPolicyRow[]): void {
    if (policies.length !== TENANCY_POLICIES.length) throw new RegistryTenancyError('unavailable')
    const policyByKey = new Map(policies.map(row => [`${row.table_name}\0${row.policy_name}`, row]))
    for (const expected of TENANCY_POLICIES) {
      const policy = policyByKey.get(`${expected.table}\0${expected.name}`)
      if (policy === undefined || policy.command !== expected.command || !policy.permissive || !policy.public_only
        || policy.has_using !== expected.using || policy.has_check !== expected.check) {
        throw new RegistryTenancyError('unavailable')
      }
    }
  }

  private async installPolicies(client: PoolClient): Promise<void> {
    for (const table of TENANT_SCOPED_TABLES) {
      await client.query(`alter table ${this.schema}.${table} enable row level security`)
      await client.query(`alter table ${this.schema}.${table} force row level security`)
    }
    for (const policy of TENANCY_POLICIES) {
      await client.query(`drop policy if exists ${policy.name} on ${this.schema}.${policy.table}`)
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
    await client.query(`create policy billing_orders_select on ${this.schema}.billing_orders
      for select using (
        (${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}' and organization_id = ${organizationSetting})
        or (organization_id = ${organizationSetting} and exists (
          select 1 from ${this.schema}.organization_memberships as membership
          where membership.organization_id = billing_orders.organization_id
            and membership.account_id::text = ${accountSetting}
            and membership.role = 'owner' and membership.state = 'active'
        ))
      )`)
    await client.query(`create policy billing_orders_insert on ${this.schema}.billing_orders
      for insert with check (
        organization_id = ${organizationSetting} and exists (
          select 1 from ${this.schema}.organization_memberships as membership
          where membership.organization_id = billing_orders.organization_id
            and membership.account_id::text = ${accountSetting}
            and membership.role = 'owner' and membership.state = 'active'
        )
      )`)
    await client.query(`create policy billing_orders_update on ${this.schema}.billing_orders
      for update using (
        ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}' and organization_id = ${organizationSetting}
      ) with check (
        ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}' and organization_id = ${organizationSetting}
      )`)
    await client.query(`create policy billing_provider_events_select
      on ${this.schema}.billing_provider_events for select using (
        ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}' and organization_id = ${organizationSetting}
      )`)
    await client.query(`create policy billing_provider_events_insert
      on ${this.schema}.billing_provider_events for insert with check (
        ${accountSetting} = '${CONTROL_ACCOUNT_CONTEXT}' and organization_id = ${organizationSetting}
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

  private billingOrderColumns(): string {
    return `order_id, organization_id, provider, plan_id, currency, unit_amount, interval, state,
      provider_checkout_id, checkout_expires_at, paid_at, refunded_at, disputed_at, last_event_at,
      created_at, updated_at`
  }

  private billingOrderQuery(where: string, suffix = '', extraColumns = ''): string {
    return `select ${this.billingOrderColumns()}${extraColumns}
      from ${this.schema}.billing_orders where ${where}${suffix}`
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
