/** Public pages plus opaque authorized object addresses. */
export type RegistryStaticPage = 'overview' | 'members' | 'nodes' | 'disclosures' | 'branches' | 'audit' | 'settings' | 'signIn' | 'signUp' | 'newOrganization' | 'binding' | 'notFound'
export type RegistryPage = RegistryStaticPage
  | { readonly kind: 'nodeDetail'; readonly instanceId: string }
  | { readonly kind: 'disclosureDetail'; readonly disclosureId: string }
  | { readonly kind: 'questionDetail'; readonly disclosureId: string; readonly requestId: string }

/** Primary navigation shared by the shell and its route tests. */
export const PRIMARY_PAGES = ['overview', 'members', 'nodes', 'disclosures', 'branches', 'audit', 'settings'] as const

const OPAQUE_ID = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u

/** Locale/navigation key for a route, without exposing a detail identifier in shell chrome. */
export function registryPageKey(page: RegistryPage): RegistryStaticPage | 'nodeDetail' | 'disclosureDetail' | 'questionDetail' {
  return typeof page === 'string' ? page : page.kind
}

/**
 * Decode an untrusted browser fragment without echoing object IDs or query text.
 * @param hash - Current location fragment.
 * @returns Known public page, or the uniform access-loss page.
 */
export function parseRegistryPage(hash: string): RegistryPage {
  switch (hash) {
    case '': case '#': case '#/': case '#/disclosures': return 'disclosures'
    case '#/overview': return 'overview'
    case '#/members': return 'members'
    case '#/nodes': return 'nodes'
    case '#/branches': return 'branches'
    case '#/audit': return 'audit'
    case '#/settings': return 'settings'
    case '#/sign-in': return 'signIn'
    case '#/sign-up': return 'signUp'
    case '#/new-organization': return 'newOrganization'
    case '#/binding': return 'binding'
    default: {
      const nodeMatch = /^#\/nodes\/([^/?#]+)$/u.exec(hash)
      if (nodeMatch?.[1] !== undefined) {
        let instanceId: string
        try {
          instanceId = decodeURIComponent(nodeMatch[1])
        } catch {
          return 'notFound'
        }
        return OPAQUE_ID.test(instanceId) ? { kind: 'nodeDetail', instanceId } : 'notFound'
      }
      const match = /^#\/disclosures\/([^/?#]+)(?:\/questions\/([^/?#]+))?$/u.exec(hash)
      if (match === null || match[1] === undefined) return 'notFound'
      let disclosureId: string
      let requestId: string | undefined
      try {
        disclosureId = decodeURIComponent(match[1])
        requestId = match[2] === undefined ? undefined : decodeURIComponent(match[2])
      } catch {
        return 'notFound'
      }
      if (!OPAQUE_ID.test(disclosureId) || (requestId !== undefined && !OPAQUE_ID.test(requestId))) return 'notFound'
      return requestId === undefined
        ? { kind: 'disclosureDetail', disclosureId }
        : { kind: 'questionDetail', disclosureId, requestId }
    }
  }
}
