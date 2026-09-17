/** Public pages, organization pages and opaque authorized object addresses. */
export type RegistryStaticPage = 'overview' | 'members' | 'nodes' | 'disclosures' | 'branches' | 'audit' | 'settings'
  | 'signIn' | 'signUp' | 'newOrganization' | 'binding' | 'notFound'
export type RegistryOrganizationStaticPage = 'overview' | 'members' | 'nodes' | 'disclosures' | 'branches' | 'audit'
  | 'settings' | 'binding'
export type RegistryOrganizationPage = RegistryOrganizationStaticPage
  | { readonly kind: 'nodeDetail'; readonly instanceId: string }
  | { readonly kind: 'disclosureDetail'; readonly disclosureId: string }
  | { readonly kind: 'questionDetail'; readonly disclosureId: string; readonly requestId: string }
export type RegistryPage = 'bootstrap' | 'signIn' | 'signUp' | 'newOrganization' | 'notFound'
  | { readonly kind: 'organization'; readonly organizationId: string; readonly page: RegistryOrganizationPage }

/** Primary navigation shared by the shell and its route tests. */
export const PRIMARY_PAGES = ['overview', 'members', 'nodes', 'disclosures', 'branches', 'audit', 'settings'] as const

const OPAQUE_ID = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u

function decodeIdentifier(value: string): string | null {
  let decoded: string
  try { decoded = decodeURIComponent(value) } catch { return null }
  return OPAQUE_ID.test(decoded) ? decoded : null
}

/** Locale/navigation key for a route, without exposing object IDs in shell chrome. */
export function registryPageKey(route: RegistryPage): RegistryStaticPage | 'nodeDetail' | 'disclosureDetail' | 'questionDetail' {
  if (route === 'bootstrap') return 'overview'
  if (typeof route === 'string') return route
  return typeof route.page === 'string' ? route.page : route.page.kind
}

/** The selected organization ID is carried only by the URL and every scoped request. */
export function registryOrganizationId(route: RegistryPage): string | null {
  return typeof route === 'object' && route.kind === 'organization' ? route.organizationId : null
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

/** Decode an untrusted browser fragment into a public or explicitly organization-scoped route. */
export function parseRegistryPage(hash: string): RegistryPage {
  switch (hash) {
    case '': case '#': case '#/': return 'bootstrap'
    case '#/sign-in': return 'signIn'
    case '#/sign-up': return 'signUp'
    case '#/new-organization': return 'newOrganization'
    default: {
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
