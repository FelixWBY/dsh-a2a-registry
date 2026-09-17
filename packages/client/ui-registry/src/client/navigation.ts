/** Public pages, organization pages and opaque authorized object addresses. */
export type RegistryStaticPage = 'overview' | 'members' | 'nodes' | 'disclosures' | 'branches' | 'audit' | 'settings'
  | 'signIn' | 'signUp' | 'newOrganization' | 'joinOrganization' | 'binding' | 'notFound'
export type RegistryOrganizationStaticPage = 'overview' | 'members' | 'nodes' | 'disclosures' | 'branches' | 'audit'
  | 'settings' | 'binding'
export type RegistryOrganizationPage = RegistryOrganizationStaticPage
  | { readonly kind: 'nodeDetail'; readonly instanceId: string }
  | { readonly kind: 'disclosureDetail'; readonly disclosureId: string }
  | { readonly kind: 'questionDetail'; readonly disclosureId: string; readonly requestId: string }
export type RegistryPage = 'bootstrap' | 'signIn' | 'signUp' | 'newOrganization' | 'notFound'
  | { readonly kind: 'join'; readonly token: string | null }
  | { readonly kind: 'organization'; readonly organizationId: string; readonly page: RegistryOrganizationPage }

/** Primary navigation shared by the shell and its route tests. */
export const PRIMARY_PAGES = ['overview', 'members', 'nodes', 'disclosures', 'branches', 'audit', 'settings'] as const

const OPAQUE_ID = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const INVITATION_TOKEN = /^[A-Za-z0-9_-]{43}$/u
const AUTH_RETURN_PATH = /^\/#\/(?:[A-Za-z0-9._~!$&'()*+,;=:@/?%-]{0,240})$/u

function decodeIdentifier(value: string): string | null {
  let decoded: string
  try { decoded = decodeURIComponent(value) } catch { return null }
  return OPAQUE_ID.test(decoded) ? decoded : null
}

/** Locale/navigation key for a route, without exposing object IDs in shell chrome. */
export function registryPageKey(route: RegistryPage): RegistryStaticPage | 'nodeDetail' | 'disclosureDetail' | 'questionDetail' {
  if (route === 'bootstrap') return 'overview'
  if (typeof route === 'string') return route
  if (route.kind === 'join') return 'joinOrganization'
  return typeof route.page === 'string' ? route.page : route.page.kind
}

/** The selected organization ID is carried only by the URL and every scoped request. */
export function registryOrganizationId(route: RegistryPage): string | null {
  return typeof route === 'object' && route.kind === 'organization' ? route.organizationId : null
}

/** Build a join address without retaining the single-use token outside the browser address. */
export function invitationHref(token: string): string {
  return `#/join/${encodeURIComponent(token)}`
}

/** Create one organization-scoped hash without relying on browser storage or a selected-tenant cookie. */
export function organizationHref(organizationId: string, page: RegistryOrganizationStaticPage): string {
  return `#/organizations/${encodeURIComponent(organizationId)}/${page}`
}

export function nodeHref(organizationId: string, instanceId: string): string {
  return `${organizationHref(organizationId, 'nodes')}/${encodeURIComponent(instanceId)}`
}

export function disclosureHref(organizationId: string, disclosureId: string): string {
  return `${organizationHref(organizationId, 'disclosures')}/${encodeURIComponent(disclosureId)}`
}

export function questionHref(organizationId: string, disclosureId: string, requestId: string): string {
  return `${disclosureHref(organizationId, disclosureId)}/questions/${encodeURIComponent(requestId)}`
}

/** Preserve one validated protected route through OIDC without browser storage or an open redirect. */
export function authenticationEntryHref(route: RegistryPage): string {
  let hash = '#/'
  if (route === 'newOrganization') hash = '#/new-organization'
  else if (typeof route === 'object' && route.kind === 'organization') {
    hash = typeof route.page === 'string'
      ? organizationHref(route.organizationId, route.page)
      : route.page.kind === 'nodeDetail'
        ? nodeHref(route.organizationId, route.page.instanceId)
        : route.page.kind === 'disclosureDetail'
          ? disclosureHref(route.organizationId, route.page.disclosureId)
          : questionHref(route.organizationId, route.page.disclosureId, route.page.requestId)
  }
  const returnTo = `/${hash}`
  return `/?returnTo=${encodeURIComponent(AUTH_RETURN_PATH.test(returnTo) ? returnTo : '/#/')}#/sign-in`
}

/** Read only the signed-OIDC-compatible continuation parameter used by the account entry page. */
export function authenticationReturnTo(search: string, fallback: string): string {
  const params = new URLSearchParams(search)
  if ([...params.keys()].some(key => key !== 'returnTo')) return fallback
  const values = params.getAll('returnTo')
  return values.length === 1 && AUTH_RETURN_PATH.test(values[0]!) ? values[0]! : fallback
}

/** Decode an untrusted browser fragment into a public or explicitly organization-scoped route. */
export function parseRegistryPage(hash: string): RegistryPage {
  switch (hash) {
    case '': case '#': case '#/': return 'bootstrap'
    case '#/sign-in': return 'signIn'
    case '#/sign-up': return 'signUp'
    case '#/new-organization': return 'newOrganization'
    case '#/join': return { kind: 'join', token: null }
    default: {
      const joinMatch = /^#\/join\/([^/?#]+)$/u.exec(hash)
      if (joinMatch?.[1] !== undefined) {
        let token: string
        try { token = decodeURIComponent(joinMatch[1]) } catch { return 'notFound' }
        return { kind: 'join', token: INVITATION_TOKEN.test(token) ? token : '' }
      }
      const match = /^#\/organizations\/([^/?#]+)(?:\/(.*))?$/u.exec(hash)
      if (match?.[1] === undefined) return 'notFound'
      const organizationId = decodeIdentifier(match[1])
      const path = match[2] ?? 'overview'
      if (organizationId === null) return 'notFound'
      if (path === 'overview' || path === 'members' || path === 'nodes' || path === 'disclosures'
        || path === 'branches' || path === 'audit' || path === 'settings' || path === 'binding') {
        return { kind: 'organization', organizationId, page: path }
      }
      const nodeMatch = /^nodes\/([^/?#]+)$/u.exec(path)
      if (nodeMatch?.[1] !== undefined) {
        const instanceId = decodeIdentifier(nodeMatch[1])
        return instanceId === null ? 'notFound' : { kind: 'organization', organizationId,
          page: { kind: 'nodeDetail', instanceId } }
      }
      const disclosureMatch = /^disclosures\/([^/?#]+)(?:\/questions\/([^/?#]+))?$/u.exec(path)
      if (disclosureMatch?.[1] === undefined) return 'notFound'
      const disclosureId = decodeIdentifier(disclosureMatch[1])
      const requestId = disclosureMatch[2] === undefined ? undefined : decodeIdentifier(disclosureMatch[2])
      if (disclosureId === null || requestId === null) return 'notFound'
      return requestId === undefined
        ? { kind: 'organization', organizationId, page: { kind: 'disclosureDetail', disclosureId } }
        : { kind: 'organization', organizationId, page: { kind: 'questionDetail', disclosureId, requestId } }
    }
  }
}
