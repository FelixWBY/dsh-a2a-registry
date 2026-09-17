import { useEffect, useRef, useState } from 'react'
import type { RegistryOrganizationPageProps } from './contract.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import { RegistryApiError, type RegistryDirectoryChange,
  type RegistryDirectoryMemberState, type RegistryDirectoryPage, type RegistryDirectoryRole,
  type RegistryInvitation, type RegistryInvitationRole, type RegistryInvitationStatus } from './registry-api.ts'
import { invitationHref } from './navigation.ts'
import css from './Registry.module.css'

type MembersProps = Pick<RegistryOrganizationPageProps, 't' | 'readDirectory' | 'changeDirectory'
| 'listInvitations' | 'createInvitation' | 'revokeInvitation'>
type MembersState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'accessLoss' }
  | { readonly kind: 'retry' }
  | { readonly kind: 'ready'; readonly directory: RegistryDirectoryPage; readonly invitations: readonly RegistryInvitation[] }

const ROLE_KEYS: Record<RegistryDirectoryRole, 'directoryRoleOwner' | 'directoryRoleAdmin' | 'directoryRoleMember'> = {
  owner: 'directoryRoleOwner', admin: 'directoryRoleAdmin', member: 'directoryRoleMember',
}
const STATE_KEYS: Record<RegistryDirectoryMemberState,
'directoryStateActive' | 'directoryStateSuspended' | 'directoryStateRemoved'> = {
  active: 'directoryStateActive', suspended: 'directoryStateSuspended', removed: 'directoryStateRemoved',
}
const INVITATION_STATUS_KEYS: Record<RegistryInvitationStatus,
'invitationStatusPending' | 'invitationStatusAccepted' | 'invitationStatusDeclined' | 'invitationStatusRevoked' | 'invitationStatusExpired'> = {
  pending: 'invitationStatusPending', accepted: 'invitationStatusAccepted', declined: 'invitationStatusDeclined',
  revoked: 'invitationStatusRevoked', expired: 'invitationStatusExpired',
}

function effectiveInvitationStatus(invitation: RegistryInvitation): RegistryInvitationStatus {
  return invitation.status === 'pending' && invitation.expiresAt <= Date.now() ? 'expired' : invitation.status
}

function invitationLink(token: string): string {
  return `${window.location.origin}${window.location.pathname}${invitationHref(token)}`
}

function failureState(error: unknown): 'unconfigured' | 'accessLoss' | 'retry' {
  if (!(error instanceof RegistryApiError)) return 'retry'
  if (error.code === 'identity-not-configured' || error.code === 'registry-not-configured') return 'unconfigured'
  if (error.code === 'unauthenticated' || error.code === 'not-found') return 'accessLoss'
  return 'retry'
}

/** Owner/admin organization directory with optimistic, server-authorized mutations. */
export function MembersPage({ t, readDirectory, changeDirectory, listInvitations, createInvitation,
  revokeInvitation }: MembersProps) {
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
  const [inviteName, setInviteName] = useState('')
  const [inviteRole, setInviteRole] = useState<RegistryInvitationRole>('member')
  const [invitationSaving, setInvitationSaving] = useState(false)
  const [revokingInvitationId, setRevokingInvitationId] = useState<string | null>(null)
  const [createdLink, setCreatedLink] = useState<string | null>(null)
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const createdLinkRef = useRef<HTMLInputElement>(null)
  const invitationController = useRef<AbortController | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setState({ kind: 'loading' })
    void Promise.all([readDirectory(controller.signal), listInvitations(controller.signal)]).then(([directory, invitations]) => {
      if (!controller.signal.aborted) {
        setState({ kind: 'ready', directory, invitations: invitations.items })
        setSaving(false)
        setInvitationSaving(false)
        setRevokingInvitationId(null)
      }
    }, (error: unknown) => {
      if (!controller.signal.aborted) {
        setState({ kind: failureState(error) })
        setSaving(false)
      }
    })
    return () => { controller.abort() }
  }, [listInvitations, readDirectory, requestRevision])

  useEffect(() => () => { invitationController.current?.abort() }, [])

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

  const submitInvitation = (): void => {
    if (state.kind !== 'ready' || state.directory.actorRole === 'member' || invitationSaving) return
    invitationController.current?.abort()
    const controller = new AbortController()
    invitationController.current = controller
    const displayName = inviteName.trim()
    const role: RegistryInvitationRole = state.directory.actorRole === 'owner' ? inviteRole : 'member'
    setInvitationSaving(true)
    setMessage(null)
    setCreatedLink(null)
    setCopyState('idle')
    void createInvitation({ role, ...(displayName === '' ? {} : { displayName }) }, controller.signal).then((created) => {
      if (controller.signal.aborted) return
      setState(current => current.kind === 'ready'
        ? { ...current, invitations: [created.invitation,
          ...current.invitations.filter(item => item.invitationId !== created.invitation.invitationId)] }
        : current)
      setCreatedLink(invitationLink(created.token))
      setInviteName('')
      setInviteRole('member')
      setInvitationSaving(false)
      setMessage(t('invitationCreated'))
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      const failure = failureState(error)
      if (failure === 'accessLoss' || failure === 'unconfigured') setState({ kind: failure })
      setInvitationSaving(false)
      setMessage(t(error instanceof RegistryApiError && error.code === 'invalid-input'
        ? 'invitationInvalidInput' : 'invitationCreateFailed'))
    })
  }

  const revoke = (invitationId: string): void => {
    if (state.kind !== 'ready' || revokingInvitationId !== null) return
    invitationController.current?.abort()
    const controller = new AbortController()
    invitationController.current = controller
    setRevokingInvitationId(invitationId)
    setMessage(null)
    void revokeInvitation(invitationId, controller.signal).then((updated) => {
      if (controller.signal.aborted) return
      setState(current => current.kind === 'ready' ? { ...current,
        invitations: current.invitations.map(item => item.invitationId === updated.invitationId ? updated : item) } : current)
      setRevokingInvitationId(null)
      setMessage(t('invitationRevoked'))
    }, (error: unknown) => {
      if (controller.signal.aborted) return
      const failure = failureState(error)
      if (failure === 'accessLoss' || failure === 'unconfigured') setState({ kind: failure })
      setRevokingInvitationId(null)
      setMessage(t('invitationRevokeFailed'))
    })
  }

  const copyCreatedLink = (): void => {
    if (createdLink === null) return
    if (navigator.clipboard === undefined) {
      setCopyState('failed')
      createdLinkRef.current?.focus()
      createdLinkRef.current?.select()
      return
    }
    void navigator.clipboard.writeText(createdLink).then(() => {
      setCopyState('copied')
    }, () => {
      setCopyState('failed')
      createdLinkRef.current?.focus()
      createdLinkRef.current?.select()
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
      <section className={css.directorySection} aria-labelledby="directory-invitations-heading">
        <div className={css.cardHeading}><div><h2 id="directory-invitations-heading">{t('invitationsHeading')}</h2><p>{t('invitationsDescription')}</p></div></div>
        {state.directory.actorRole === 'member' ? <p className={css.directoryMessage}>{t('directoryReadOnly')}</p> : <form className={css.invitationEditor} onSubmit={(event) => { event.preventDefault(); submitInvitation() }}>
          <label><span>{t('invitationDisplayName')}</span><input value={inviteName} maxLength={80} disabled={invitationSaving} placeholder={t('invitationDisplayNamePlaceholder')} onChange={event => { setInviteName(event.currentTarget.value) }} /></label>
          <label><span>{t('directoryMemberRole')}</span><select value={state.directory.actorRole === 'owner' ? inviteRole : 'member'} disabled={invitationSaving || state.directory.actorRole !== 'owner'} onChange={event => { setInviteRole(event.currentTarget.value as RegistryInvitationRole) }}><option value="member">{t('directoryRoleMember')}</option>{state.directory.actorRole === 'owner' ? <option value="admin">{t('directoryRoleAdmin')}</option> : null}</select></label>
          <button className={css.primaryAction} type="submit" disabled={invitationSaving}>{t(invitationSaving ? 'invitationCreating' : 'invitationCreate')}</button>
        </form>}
        {createdLink !== null ? <div className={css.createdInvitation} role="status">
          <div><strong>{t('invitationLinkReady')}</strong><p>{t('invitationLinkOnce')}</p></div>
          <div className={css.invitationLinkRow}><input ref={createdLinkRef} readOnly value={createdLink} aria-label={t('invitationLink')} onFocus={event => { event.currentTarget.select() }} /><button className={css.secondaryAction} type="button" onClick={copyCreatedLink}>{t(copyState === 'copied' ? 'copied' : 'copyLink')}</button></div>
          {copyState === 'failed' ? <p className={css.invitationCopyHelp}>{t('copyFailed')}</p> : null}
        </div> : null}
        {state.invitations.length === 0
          ? <div className={css.statePanel}><RegistryIcon name="members" size={48} /><p>{t('invitationsEmpty')}</p></div>
          : <div className={css.tableFrame}><div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region" aria-label={t('invitationsHeading')}>
            <table className={`${css.table} ${css.directoryTable} ${css.responsiveTable}`}>
              <thead><tr>{(['invitationDisplayName', 'directoryMemberRole', 'directoryMemberState', 'expiry', 'actions'] as const).map(key => <th scope="col" key={key}>{t(key)}</th>)}</tr></thead>
              <tbody>{state.invitations.map(invitation => {
                const status = effectiveInvitationStatus(invitation)
                return <tr key={invitation.invitationId}>
                  <td data-label={t('invitationDisplayName')}>{invitation.displayName ?? t('invitationAnyoneWithLink')}</td>
                  <td data-label={t('directoryMemberRole')}>{t(invitation.role === 'admin' ? 'directoryRoleAdmin' : 'directoryRoleMember')}</td>
                  <td data-label={t('directoryMemberState')}><span className={status === 'pending' ? css.invitationPending : css.invitationClosed}>{t(INVITATION_STATUS_KEYS[status])}</span></td>
                  <td data-label={t('expiry')}><time dateTime={new Date(invitation.expiresAt).toISOString()}>{new Date(invitation.expiresAt).toLocaleString()}</time></td>
                  <td data-label={t('actions')}><div className={css.directoryRowActions}>{status === 'pending'
                    && !(state.directory.actorRole === 'admin' && invitation.role === 'admin')
                    ? <button type="button" disabled={revokingInvitationId !== null} onClick={() => { revoke(invitation.invitationId) }}>{t(revokingInvitationId === invitation.invitationId ? 'invitationRevoking' : 'invitationRevoke')}</button>
                    : '—'}</div></td>
                </tr>
              })}</tbody>
            </table>
          </div></div>}
      </section>
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
