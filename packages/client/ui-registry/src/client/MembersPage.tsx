import { useEffect, useState } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import { RegistryApiError, type RegistryDirectoryChange,
  type RegistryDirectoryMemberState, type RegistryDirectoryPage, type RegistryDirectoryRole } from './registry-api.ts'
import css from './Registry.module.css'

type MembersProps = Pick<RegistryOrganizationPageProps, 't' | 'readDirectory' | 'changeDirectory'>
type MembersState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly directory: RegistryDirectoryPage }

const ROLE_KEYS: Record<RegistryDirectoryRole, 'directoryRoleOwner' | 'directoryRoleAdmin' | 'directoryRoleMember'> = {
  owner: 'directoryRoleOwner', admin: 'directoryRoleAdmin', member: 'directoryRoleMember',
}
const STATE_KEYS: Record<RegistryDirectoryMemberState,
'directoryStateActive' | 'directoryStateSuspended' | 'directoryStateRemoved'> = {
  active: 'directoryStateActive', suspended: 'directoryStateSuspended', removed: 'directoryStateRemoved',
}

function failureState(error: unknown): 'unconfigured' | 'accessLoss' | 'retry' {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured') return 'unconfigured'
  if (error.code === 'unauthenticated' || error.code === 'not-found') return 'accessLoss'
  return 'retry'
}

/** Owner/admin organization directory with optimistic, server-authorized mutations. */
export function MembersPage({ t, readDirectory, changeDirectory }: MembersProps) {
  const [requestRevision, setRequestRevision] = useState(0)
  const [state, setState] = useState<MembersState>({ kind: 'loading' })
  const [memberId, setMemberId] = useState('')
  const [memberName, setMemberName] = useState('')
  const [memberRole, setMemberRole] = useState<RegistryDirectoryRole>('member')
  const [teamId, setTeamId] = useState('')
  const [teamName, setTeamName] = useState('')
  const [teamMembers, setTeamMembers] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setState({ kind: 'loading' })
    void readDirectory(controller.signal).then((directory) => {
      if (!controller.signal.aborted) {
        setState({ kind: 'ready', directory })
        setSaving(false)
      }
    }, (error: unknown) => {
      if (!controller.signal.aborted) {
        setState({ kind: failureState(error) })
        setSaving(false)
      }
    })
    return () => { controller.abort() }
  }, [readDirectory, requestRevision])

  const mutate = (change: RegistryDirectoryChange): void => {
    if (state.kind !== 'ready' || saving) return
    const controller = new AbortController()
    setSaving(true)
    setMessage(null)
    void changeDirectory(state.directory.revision, change, controller.signal).then((receipt) => {
      setMessage(receipt.invalidatedDisclosures === 0
        ? t('directorySaved') : t('directorySavedInvalidated').replace('{count}', String(receipt.invalidatedDisclosures)))
      setRequestRevision(value => value + 1)
    }, (error: unknown) => {
      setSaving(false)
      setMessage(t(error instanceof RegistryApiError && error.code === 'conflict'
        ? 'directoryConflict' : 'directorySaveFailed'))
    })
  }

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  return <section>
    <div className={css.pageHeading}><h1>{t('members')}</h1><p>{t('membersDescription')}</p></div>
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingDirectory')}</p></div>}
    {state.kind === 'unconfigured' && <div className={css.tableFrame}><UnconfiguredPanel t={t} /></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRequestRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'ready' && <>
      <div className={css.directoryMeta} role="status"><RegistryIcon name="info" /><p>{t('directoryRevision')} <strong>{state.directory.revision}</strong> · {t(state.directory.actorRole === 'owner' ? 'directoryOwnerAccess' : 'directoryAdminAccess')}</p></div>
      {message !== null && <p className={css.directoryMessage} role="status">{message}</p>}
      <section className={css.directorySection} aria-labelledby="directory-members-heading">
        <div className={css.cardHeading}><div><h2 id="directory-members-heading">{t('directoryMembersHeading')}</h2><p>{t('directoryMembersDescription')}</p></div></div>
        <form className={css.directoryEditor} onSubmit={(event) => {
          event.preventDefault()
          const id = memberId.trim(); const displayName = memberName.trim()
          if (id === '' || displayName === '') return
          mutate({ kind: 'put-member', member: { memberId: id, displayName,
            role: state.directory.actorRole === 'owner' ? memberRole : 'member', state: 'active' } })
          setMemberId(''); setMemberName(''); setMemberRole('member')
        }}>
          <label><span>{t('directoryMemberId')}</span><input value={memberId} required pattern="[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?" onChange={event => { setMemberId(event.currentTarget.value) }} /></label>
          <label><span>{t('directoryMemberName')}</span><input value={memberName} required onChange={event => { setMemberName(event.currentTarget.value) }} /></label>
          <label><span>{t('directoryMemberRole')}</span><select value={memberRole} disabled={state.directory.actorRole !== 'owner'} onChange={event => { setMemberRole(event.currentTarget.value as RegistryDirectoryRole) }}><option value="member">{t('directoryRoleMember')}</option><option value="admin">{t('directoryRoleAdmin')}</option><option value="owner">{t('directoryRoleOwner')}</option></select></label>
          <button className={css.primaryAction} type="submit" disabled={saving}>{t('directoryAddMember')}</button>
        </form>
        {state.directory.members.length === 0
          ? <div className={css.statePanel}><p>{t('directoryMembersEmpty')}</p></div>
          : <div className={css.tableFrame}><div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region" aria-label={t('directoryMembersHeading')}>
            <table className={`${css.table} ${css.directoryTable} ${css.responsiveTable}`}>
              <thead><tr>{(['directoryMemberName', 'directoryMemberId', 'directoryMemberRole', 'directoryMemberState', 'actions'] as const).map(key => <th scope="col" key={key}>{t(key)}</th>)}</tr></thead>
              <tbody>{state.directory.members.map(member => <tr key={member.memberId}>
                <td data-label={t('directoryMemberName')}>{member.displayName}</td>
                <td data-label={t('directoryMemberId')}><bdi className={css.tableIdentifier} title={member.memberId}>{member.memberId}</bdi></td>
                <td data-label={t('directoryMemberRole')}>{state.directory.actorRole === 'owner' && member.role !== 'owner' && member.state !== 'removed'
                  ? <select aria-label={t('directoryMemberRole')} value={member.role} disabled={saving} onChange={event => { mutate({ kind: 'put-member', member: { ...member, role: event.currentTarget.value as RegistryDirectoryRole } }) }}><option value="member">{t('directoryRoleMember')}</option><option value="admin">{t('directoryRoleAdmin')}</option></select>
                  : t(ROLE_KEYS[member.role])}</td>
                <td data-label={t('directoryMemberState')}>{t(STATE_KEYS[member.state])}</td>
                <td data-label={t('actions')}><div className={css.directoryRowActions}>{member.role === 'owner' || member.state === 'removed'
                  || state.directory.actorRole === 'admin' && member.role !== 'member' ? '—' : <>
                  <button type="button" disabled={saving} onClick={() => { mutate({ kind: 'put-member', member: { ...member, state: member.state === 'active' ? 'suspended' : 'active' } }) }}>{t(member.state === 'active' ? 'directorySuspend' : 'directoryActivate')}</button>
                  <button type="button" disabled={saving} onClick={() => { mutate({ kind: 'put-member', member: { ...member, state: 'removed' } }) }}>{t('directoryRemove')}</button>
                </>}</div></td>
              </tr>)}</tbody>
            </table>
          </div></div>}
      </section>
      <section className={css.directorySection} aria-labelledby="directory-teams-heading">
        <div className={css.cardHeading}><div><h2 id="directory-teams-heading">{t('directoryTeamsHeading')}</h2><p>{t('directoryTeamsDescription')}</p></div></div>
        <form className={css.directoryEditor} onSubmit={(event) => {
          event.preventDefault()
          const id = teamId.trim(); const displayName = teamName.trim()
          const memberIds = teamMembers.split(',').map(value => value.trim()).filter(Boolean)
          if (id === '' || displayName === '') return
          mutate({ kind: 'put-team', team: { teamId: id, displayName, memberIds } })
          setTeamId(''); setTeamName(''); setTeamMembers('')
        }}>
          <label><span>{t('directoryTeamId')}</span><input value={teamId} required pattern="[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?" onChange={event => { setTeamId(event.currentTarget.value) }} /></label>
          <label><span>{t('directoryTeamName')}</span><input value={teamName} required onChange={event => { setTeamName(event.currentTarget.value) }} /></label>
          <label><span>{t('directoryTeamMembers')}</span><input value={teamMembers} placeholder={t('directoryTeamMembersPlaceholder')} onChange={event => { setTeamMembers(event.currentTarget.value) }} /></label>
          <button className={css.primaryAction} type="submit" disabled={saving}>{t('directorySaveTeam')}</button>
        </form>
        {state.directory.teams.length === 0
          ? <div className={css.statePanel}><RegistryIcon name="emptyNodes" size={56} /><p>{t('directoryTeamsEmpty')}</p></div>
          : <div className={css.tableFrame}><div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region" aria-label={t('directoryTeamsHeading')}>
            <table className={`${css.table} ${css.directoryTable} ${css.responsiveTable}`}>
              <thead><tr>{(['directoryTeamName', 'directoryTeamId', 'directoryTeamMembers', 'actions'] as const).map(key => <th scope="col" key={key}>{t(key)}</th>)}</tr></thead>
              <tbody>{state.directory.teams.map(team => <tr key={team.teamId}>
                <td data-label={t('directoryTeamName')}>{team.displayName}</td>
                <td data-label={t('directoryTeamId')}><bdi className={css.tableIdentifier} title={team.teamId}>{team.teamId}</bdi></td>
                <td data-label={t('directoryTeamMembers')}>{team.memberIds.length === 0 ? t('directoryTeamNoMembers') : team.memberIds.join(' · ')}</td>
                <td data-label={t('actions')}><div className={css.directoryRowActions}><button type="button" disabled={saving} onClick={() => { mutate({ kind: 'remove-team', teamId: team.teamId }) }}>{t('directoryRemoveTeam')}</button></div></td>
              </tr>)}</tbody>
            </table>
          </div></div>}
      </section>
    </>}
  </section>
}
