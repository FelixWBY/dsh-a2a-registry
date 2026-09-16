/** Directory validation and policy; the ingest owner owns authentication, serialization and atomic publication. */
import { z } from 'zod'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'
import type { DisclosureSubject, MemberId, TeamId } from '@deepseek-ai/dsh-a2a-registry-domain'
import { byteLength, RegistryIngestError, requireIngest } from './record.ts'
import type { RegistryDirectoryChange, RegistryDirectoryConfig, RegistryDirectoryState } from './directory-types.ts'

const identifier = <T extends Branded<string>>() => z.string().max(128)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]*[A-Za-z0-9])?$/u).transform(value => brandString<T>(value))
const member = z.strictObject({ memberId: identifier<MemberId>(), displayName: z.string(),
  role: z.enum(['owner', 'admin', 'member']), state: z.enum(['active', 'suspended', 'removed']) }).readonly()
const team = z.strictObject({ teamId: identifier<TeamId>(), displayName: z.string(),
  memberIds: z.array(identifier<MemberId>()).readonly() }).readonly()
const state = z.strictObject({ revision: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  members: z.array(member).readonly(), teams: z.array(team).readonly() }).readonly()
const change = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('put-member'), member }),
  z.strictObject({ kind: z.literal('put-team'), team }),
  z.strictObject({ kind: z.literal('remove-team'), teamId: identifier<TeamId>() }),
])

function assertNever(_value: never): never {
  throw new RegistryIngestError('invalid-input')
}

/** Validate explicit limits and first-open owner before any durable state is opened.
 * @param config - Deployment-selected complete storage bounds and first owner. */
export function validateDirectoryConfig(config: RegistryDirectoryConfig): void {
  for (const value of [config.maxMembers, config.maxTeams, config.maxTeamMembers, config.maxNameBytes, config.maxBytes]) {
    requireIngest(Number.isSafeInteger(value) && value > 0, 'limit')
  }
  initialDirectory(config)
}

/** Provision only an empty domain; this is trusted configuration, not account authentication.
 * @param config - Validated explicit owner and limits.
 * @returns A detached initial directory with one active owner and no teams. */
export function initialDirectory(config: RegistryDirectoryConfig): RegistryDirectoryState {
  return parseDirectory({ revision: 0, members: [{ ...config.bootstrapOwner, role: 'owner', state: 'active' }], teams: [] }, config)
}

/** Validate a complete retained directory, including referential integrity and owner availability.
 * @param input - Untrusted durable or queued JSON.
 * @param config - Explicit complete record and collection bounds.
 * @returns Detached deeply frozen state; parser details never escape.
 * @throws RegistryIngestError with invalid-storage for malformed or oversized state. */
export function parseDirectory(input: unknown, config: RegistryDirectoryConfig): RegistryDirectoryState {
  try {
    requireIngest(byteLength(input) <= config.maxBytes, 'invalid-storage')
    const parsed = state.parse(input)
    requireIngest(parsed.members.length <= config.maxMembers && parsed.teams.length <= config.maxTeams, 'invalid-storage')
    const members = new Map(parsed.members.map(value => [value.memberId, value]))
    requireIngest(members.size === parsed.members.length && new Set(parsed.teams.map(value => value.teamId)).size === parsed.teams.length,
      'invalid-storage')
    requireIngest(parsed.members.some(value => value.role === 'owner' && value.state === 'active'), 'invalid-storage')
    for (const value of [...parsed.members, ...parsed.teams]) {
      requireIngest(value.displayName.trim().length > 0 && value.displayName === value.displayName.trim()
        && !/[\u0000-\u001f\u007f]/u.test(value.displayName)
        && Buffer.byteLength(value.displayName, 'utf8') <= config.maxNameBytes, 'invalid-storage')
    }
    for (const value of parsed.teams) {
      requireIngest(value.memberIds.length <= config.maxTeamMembers && new Set(value.memberIds).size === value.memberIds.length,
        'invalid-storage')
      requireIngest(value.memberIds.every((id) => {
        const member = members.get(id)
        return member !== undefined && member.state !== 'removed'
      }), 'invalid-storage')
    }
    return parsed
  } catch {
    // Parser diagnostics can contain names and identifiers; expose only the bounded category.
    throw new RegistryIngestError('invalid-storage')
  }
}

/** Derive membership only after an external caller has authenticated the member identity.
 * @param directory - Current serialized organization state.
 * @param subject - Trusted authenticated identity; any supplied role/team fields are ignored.
 * @returns Fresh directory-owned role and team membership, or uniform not-found. */
export function directorySubject(directory: RegistryDirectoryState,
  subject: Pick<DisclosureSubject, 'organizationId' | 'memberId' | 'authenticated'>): DisclosureSubject {
  const member = directory.members.find(value => value.memberId === subject.memberId)
  requireIngest(subject.authenticated && member !== undefined && member.state === 'active', 'not-found')
  return { organizationId: subject.organizationId, memberId: member.memberId, authenticated: true,
    membership: member.state, role: member.role,
    currentTeamIds: directory.teams.filter(value => value.memberIds.includes(member.memberId)).map(value => value.teamId) }
}

/** Apply a queued administrative command without granting implicit disclosure access.
 * @param directory - Current validated state.
 * @param actor - Authenticated identity; stored role decides management authority.
 * @param input - Command captured before queuing.
 * @param expectedRevision - Optimistic directory version, checked after authority.
 * @param config - Explicit storage bounds.
 * @returns The original state for an exact no-op, otherwise the next validated revision.
 * @throws RegistryIngestError for denied roles, stale versions, invalid transitions or bounds. */
export function changeDirectory(directory: RegistryDirectoryState,
  actor: Pick<DisclosureSubject, 'organizationId' | 'memberId' | 'authenticated'>,
  input: RegistryDirectoryChange, expectedRevision: number, config: RegistryDirectoryConfig): RegistryDirectoryState {
  const current = directorySubject(directory, actor)
  requireIngest(current.role === 'owner' || current.role === 'admin', 'not-found')
  requireIngest(directory.revision === expectedRevision, 'version-conflict')
  const parsed = change.safeParse(input)
  requireIngest(parsed.success, 'invalid-input')
  const command = parsed.data
  let members = [...directory.members]
  let teams = [...directory.teams]
  switch (command.kind) {
    case 'put-member': {
      const value = command.member
      const previous = members.find(member => member.memberId === value.memberId)
      requireIngest(current.role === 'owner' || (value.role === 'member' && (previous === undefined || previous.role === 'member')), 'not-found')
      requireIngest(previous?.state !== 'removed' || value.state === 'removed', 'invalid-transition')
      requireIngest(previous !== undefined || value.state === 'active', 'invalid-transition')
      members = previous === undefined ? [...members, value] : members.map(member => member.memberId === value.memberId ? value : member)
      if (value.state === 'removed') teams = teams.map(team => ({ ...team, memberIds: team.memberIds.filter(id => id !== value.memberId) }))
      break
    }
    case 'put-team':
      teams = teams.some(team => team.teamId === command.team.teamId)
        ? teams.map(team => team.teamId === command.team.teamId ? command.team : team) : [...teams, command.team]
      break
    case 'remove-team':
      teams = teams.filter(team => team.teamId !== command.teamId)
      break
    default: return assertNever(command)
  }
  const candidate = { ...directory, members, teams }
  if (JSON.stringify(candidate) === JSON.stringify(directory)) return directory
  requireIngest(directory.revision < Number.MAX_SAFE_INTEGER, 'limit')
  try { return parseDirectory({ ...candidate, revision: directory.revision + 1 }, config) } catch {
    // Command/state failures are input failures, not evidence that the retained directory is corrupt.
    throw new RegistryIngestError('invalid-input')
  }
}
