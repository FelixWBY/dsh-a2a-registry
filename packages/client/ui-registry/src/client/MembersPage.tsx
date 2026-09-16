import { useEffect, useState } from 'react'
import type { RegistryPageProps } from './contract.ts'
import { AccessLossPage } from './AccessLossPage.tsx'
import { RegistryIcon } from './RegistryIcon.tsx'
import { UnconfiguredPanel } from './UnconfiguredPanel.tsx'
import { RegistryApiError, type RegistryDirectoryMemberState, type RegistryDirectoryPage,
  type RegistryDirectoryRole } from './registry-api.ts'
import css from './Registry.module.css'

type MembersProps = Pick<RegistryPageProps, 't' | 'readDirectory'>
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

/** Read-only administration projection of the Registry-owned member and team directory. */
export function MembersPage({ t, readDirectory }: MembersProps) {
  const [requestRevision, setRequestRevision] = useState(0)
  const [state, setState] = useState<MembersState>({ kind: 'loading' })

  useEffect(() => {
    const controller = new AbortController()
    setState({ kind: 'loading' })
    void readDirectory(controller.signal).then((directory) => {
      if (!controller.signal.aborted) setState({ kind: 'ready', directory })
    }, (error: unknown) => {
      if (!controller.signal.aborted) setState({ kind: failureState(error) })
    })
    return () => { controller.abort() }
  }, [readDirectory, requestRevision])

  if (state.kind === 'accessLoss') return <AccessLossPage t={t} />
  return <section>
    <div className={css.pageHeading}><h1>{t('members')}</h1><p>{t('membersDescription')}</p></div>
    {state.kind === 'loading' && <div className={css.statePanel} role="status"><span className={css.spinner} aria-hidden="true" /><p>{t('loadingDirectory')}</p></div>}
    {state.kind === 'unconfigured' && <div className={css.tableFrame}><UnconfiguredPanel t={t} /></div>}
    {state.kind === 'retry' && <div className={css.statePanel} role="alert"><RegistryIcon name="notFound" size={48} /><h2>{t('requestUnavailable')}</h2><p>{t('requestUnavailableDescription')}</p><button className={css.primaryButton} onClick={() => { setRequestRevision(value => value + 1) }}>{t('retry')}</button></div>}
    {state.kind === 'ready' && <>
      <div className={css.directoryMeta} role="status"><RegistryIcon name="info" /><p>{t('directoryRevision')} <strong>{state.directory.revision}</strong> · {t('directoryReadOnly')}</p></div>
      <section className={css.directorySection} aria-labelledby="directory-members-heading">
        <div className={css.cardHeading}><div><h2 id="directory-members-heading">{t('directoryMembersHeading')}</h2><p>{t('directoryMembersDescription')}</p></div></div>
        {state.directory.members.length === 0
          ? <div className={css.statePanel}><p>{t('directoryMembersEmpty')}</p></div>
          : <div className={css.tableFrame}><div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region" aria-label={t('directoryMembersHeading')}>
            <table className={`${css.table} ${css.directoryTable} ${css.responsiveTable}`}>
              <thead><tr>{(['directoryMemberName', 'directoryMemberId', 'directoryMemberRole', 'directoryMemberState'] as const).map(key => <th scope="col" key={key}>{t(key)}</th>)}</tr></thead>
              <tbody>{state.directory.members.map(member => <tr key={member.memberId}>
                <td data-label={t('directoryMemberName')}>{member.displayName}</td>
                <td data-label={t('directoryMemberId')}><bdi className={css.tableIdentifier} title={member.memberId}>{member.memberId}</bdi></td>
                <td data-label={t('directoryMemberRole')}>{t(ROLE_KEYS[member.role])}</td>
                <td data-label={t('directoryMemberState')}>{t(STATE_KEYS[member.state])}</td>
              </tr>)}</tbody>
            </table>
          </div></div>}
      </section>
      <section className={css.directorySection} aria-labelledby="directory-teams-heading">
        <div className={css.cardHeading}><div><h2 id="directory-teams-heading">{t('directoryTeamsHeading')}</h2><p>{t('directoryTeamsDescription')}</p></div></div>
        {state.directory.teams.length === 0
          ? <div className={css.statePanel}><RegistryIcon name="emptyNodes" size={56} /><p>{t('directoryTeamsEmpty')}</p></div>
          : <div className={css.tableFrame}><div className={`${css.tableScroll} ${css.responsiveTableScroll}`} tabIndex={0} role="region" aria-label={t('directoryTeamsHeading')}>
            <table className={`${css.table} ${css.directoryTable} ${css.responsiveTable}`}>
              <thead><tr>{(['directoryTeamName', 'directoryTeamId', 'directoryTeamMembers'] as const).map(key => <th scope="col" key={key}>{t(key)}</th>)}</tr></thead>
              <tbody>{state.directory.teams.map(team => <tr key={team.teamId}>
                <td data-label={t('directoryTeamName')}>{team.displayName}</td>
                <td data-label={t('directoryTeamId')}><bdi className={css.tableIdentifier} title={team.teamId}>{team.teamId}</bdi></td>
                <td data-label={t('directoryTeamMembers')}>{team.memberIds.length === 0 ? t('directoryTeamNoMembers') : team.memberIds.join(' · ')}</td>
              </tr>)}</tbody>
            </table>
          </div></div>}
      </section>
    </>}
  </section>
}
