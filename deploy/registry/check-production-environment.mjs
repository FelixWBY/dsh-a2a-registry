#!/usr/bin/env node
import { createPrivateKey } from 'node:crypto'
import { isIP } from 'node:net'
import { isAbsolute, resolve } from 'node:path'

const issues = []
const [scope = 'all', ...extraArguments] = process.argv.slice(2)
if (!['edge', 'registry', 'harness', 'all'].includes(scope) || extraArguments.length > 0) {
  process.stderr.write('usage: node deploy/registry/check-production-environment.mjs [edge|registry|harness|all]\n')
  process.exit(2)
}
const checkEdge = scope === 'edge' || scope === 'all'
const checkRegistry = scope === 'registry' || scope === 'all'
const checkHarness = scope === 'harness' || scope === 'all'

function issue(message) {
  issues.push(message)
}

function checkNodeRuntime() {
  const [major = 0, minor = 0] = process.versions.node.split('.').map(Number)
  if (!(major === 22 && minor >= 19) && major < 24) {
    issue('Node ^22.19.0 or >=24.0.0 is required')
  }
}

function required(name, options = {}) {
  const value = process.env[name]
  if (value === undefined || value.trim().length === 0) {
    issue(`${name} is required`)
    return ''
  }
  if (value !== value.trim()) issue(`${name} must not have leading or trailing whitespace`)
  if (options.secret === true) {
    if (Buffer.byteLength(value, 'utf8') < options.minimumBytes) {
      issue(`${name} must contain at least ${options.minimumBytes} bytes`)
    }
    return value
  }
  if (/change[-_ ]?me|\btodo\b|<[^>]+>|example\.(?:com|org|net)/i.test(value)) {
    issue(`${name} still contains an example or placeholder value`)
  }
  if (/[\r\n]/.test(value)) issue(`${name} must be a single line`)
  return value
}

function identifier(name, value) {
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u.test(value)) {
    issue(`${name} must be a valid DSH identifier`)
  }
}

function canonicalBase64Url(value, expectedBytes) {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) return false
  const decoded = Buffer.from(value, 'base64url')
  return (expectedBytes === undefined || decoded.byteLength === expectedBytes)
    && decoded.toString('base64url') === value
}

function deviceToken(value, expectedOrganizationId) {
  const parts = value.split('.')
  if (parts.length !== 4 || parts[0] !== 'dsh1'
    || !canonicalBase64Url(parts[1]) || !canonicalBase64Url(parts[3], 32)
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(parts[2])) {
    issue('DSH_REGISTRY_DEVICE_TOKEN must be one canonical dsh1 device credential')
    return null
  }
  const organizationId = Buffer.from(parts[1], 'base64url').toString('utf8')
  if (Buffer.from(organizationId, 'utf8').toString('base64url') !== parts[1]
    || !/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u.test(organizationId)
    || organizationId !== expectedOrganizationId) {
    issue('DSH_REGISTRY_DEVICE_TOKEN must select DSH_REGISTRY_ORGANIZATION_ID')
    return null
  }
  return { bindingId: parts[2], secret: parts[3] }
}

function disclosureToken(value, expectedOrganizationId) {
  const parts = value.split('.')
  if (parts.length !== 4 || parts[0] !== 'dshb1'
    || !canonicalBase64Url(parts[1]) || !canonicalBase64Url(parts[3], 32)
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(parts[2])) {
    issue('DSH_REGISTRY_DISCLOSURE_TOKEN must be one canonical dshb1 bridge credential')
    return null
  }
  const organizationId = Buffer.from(parts[1], 'base64url').toString('utf8')
  if (Buffer.from(organizationId, 'utf8').toString('base64url') !== parts[1]
    || !/^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u.test(organizationId)
    || organizationId !== expectedOrganizationId) {
    issue('DSH_REGISTRY_DISCLOSURE_TOKEN must select DSH_REGISTRY_ORGANIZATION_ID')
    return null
  }
  return { bindingId: parts[2], secret: parts[3] }
}

function devicePrivateKey(value) {
  if (!canonicalBase64Url(value)) {
    issue('DSH_REGISTRY_DEVICE_PRIVATE_KEY must be canonical base64url Ed25519 PKCS8')
    return
  }
  const bytes = Buffer.from(value, 'base64url')
  try {
    const key = createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' })
    const canonical = key.export({ format: 'der', type: 'pkcs8' })
    if (key.asymmetricKeyType !== 'ed25519' || !Buffer.isBuffer(canonical) || !canonical.equals(bytes)) {
      issue('DSH_REGISTRY_DEVICE_PRIVATE_KEY must be canonical base64url Ed25519 PKCS8')
    }
  } catch {
    issue('DSH_REGISTRY_DEVICE_PRIVATE_KEY must be canonical base64url Ed25519 PKCS8')
  } finally {
    bytes.fill(0)
  }
}

function publicDomain(value) {
  const labels = value.toLowerCase().split('.')
  if (value.length > 253 || labels.length < 2 || isIP(value) !== 0
    || labels.some(label => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label))) {
    issue('REGISTRY_DOMAIN must be a DNS hostname without a scheme, port or path')
  }
  if (value.toLowerCase() === 'localhost'
    || value.toLowerCase().endsWith('.localhost')
    || value.toLowerCase().endsWith('.local')
    || value.toLowerCase() === 'example'
    || value.toLowerCase().endsWith('.example')
    || value.toLowerCase().endsWith('.test')
    || value.toLowerCase().endsWith('.invalid')) {
    issue('REGISTRY_DOMAIN must not be a loopback or reserved test hostname')
  }
}

function httpsUrl(name, value) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    issue(`${name} must be an absolute URL`)
    return undefined
  }
  if (parsed.protocol !== 'https:') issue(`${name} must use https://`)
  if (parsed.username.length > 0 || parsed.password.length > 0) issue(`${name} must not contain credentials`)
  if (parsed.search.length > 0 || parsed.hash.length > 0) issue(`${name} must not contain a query or fragment`)
  return parsed
}

function registryOrigin(value, domain) {
  const parsed = httpsUrl('DSH_REGISTRY_PUBLIC_ORIGIN', value)
  if (parsed === undefined) return
  if (parsed.hostname.toLowerCase() !== domain.toLowerCase() || parsed.port !== ''
    || parsed.pathname !== '/' || parsed.href !== `https://${domain.toLowerCase()}/`) {
    issue('DSH_REGISTRY_PUBLIC_ORIGIN must be the canonical REGISTRY_DOMAIN HTTPS origin')
  }
}

function postgresUrl(value) {
  let parsed
  try { parsed = new URL(value) } catch {
    issue('DSH_REGISTRY_POSTGRES_URL must be an absolute PostgreSQL URL')
    return undefined
  }
  if (parsed.protocol !== 'postgresql:' && parsed.protocol !== 'postgres:') {
    issue('DSH_REGISTRY_POSTGRES_URL must use postgresql://')
  }
  if (parsed.hostname.length === 0 || parsed.username.length === 0 || parsed.password.length === 0
    || parsed.pathname.length <= 1) issue('DSH_REGISTRY_POSTGRES_URL must include host, user, password and database')
  if (parsed.hash.length > 0) issue('DSH_REGISTRY_POSTGRES_URL must not contain a fragment')
  return parsed
}

function syncUrl(name, value, domain) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    issue(`${name} must be an absolute URL`)
    return
  }
  if (parsed.protocol !== 'wss:') issue(`${name} must use wss://`)
  if (parsed.hostname.toLowerCase() !== domain.toLowerCase()) {
    issue(`${name} must use REGISTRY_DOMAIN`)
  }
  if (parsed.port !== '' || parsed.href !== `wss://${domain.toLowerCase()}/a2a/v1/sync`) {
    issue(`${name} must be the canonical public WSS endpoint on port 443`)
  }
  if (parsed.pathname !== '/a2a/v1/sync' || parsed.search.length > 0 || parsed.hash.length > 0) {
    issue(`${name} must end at /a2a/v1/sync without query or fragment data`)
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    issue(`${name} must not contain credentials`)
  }
}

function disclosureBridgeUrl(name, value, domain) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    issue(`${name} must be an absolute URL`)
    return
  }
  const expected = `https://${domain.toLowerCase()}/a2a/v1/disclosure-publication`
  if (value !== expected || parsed.href !== expected || parsed.protocol !== 'https:'
    || parsed.username.length > 0 || parsed.password.length > 0 || parsed.port !== ''
    || parsed.pathname !== '/a2a/v1/disclosure-publication'
    || parsed.search.length > 0 || parsed.hash.length > 0) {
    issue(`${name} must be the exact public HTTPS disclosure bridge URL on REGISTRY_DOMAIN`)
  }
}

function absolutePath(name, value) {
  if (value.length === 0) return ''
  if (!isAbsolute(value)) {
    issue(`${name} must be an absolute local-filesystem path`)
    return ''
  }
  return resolve(value)
}

const domain = required('REGISTRY_DOMAIN')
checkNodeRuntime()
if (domain.length > 0) publicDomain(domain)

if (checkEdge) {
  const acmeEmail = required('ACME_EMAIL')
  if (acmeEmail.length > 0 && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(acmeEmail)) {
    issue('ACME_EMAIL must be a valid email address')
  }
}

let selectedOrganizationId = ''
if (checkRegistry || checkHarness) {
  selectedOrganizationId = required('DSH_REGISTRY_ORGANIZATION_ID')
  if (selectedOrganizationId.length > 0) identifier('DSH_REGISTRY_ORGANIZATION_ID', selectedOrganizationId)
}

if (checkRegistry) {
  for (const name of ['DSH_REGISTRY_BOOTSTRAP_MEMBER_ID', 'DSH_REGISTRY_BOOTSTRAP_MEMBER_NAME',
    'DSH_REGISTRY_ORGANIZATION_NAME']) required(name)
  const publicOrigin = required('DSH_REGISTRY_PUBLIC_ORIGIN')
  if (publicOrigin.length > 0 && domain.length > 0) registryOrigin(publicOrigin, domain)
  const oidcIssuer = required('DSH_REGISTRY_OIDC_ISSUER')
  if (oidcIssuer.length > 0) httpsUrl('DSH_REGISTRY_OIDC_ISSUER', oidcIssuer)
  required('DSH_REGISTRY_OIDC_CLIENT_ID')
  const audience = required('DSH_REGISTRY_SYNC_AUDIENCE')
  if (audience.length > 0 && domain.length > 0) syncUrl('DSH_REGISTRY_SYNC_AUDIENCE', audience, domain)
  const disclosureRootKeyId = required('DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID')
  if (disclosureRootKeyId.length > 0) {
    identifier('DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID', disclosureRootKeyId)
  }
  const previousRootKeyIdPresent = (process.env.DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID?.trim().length ?? 0) > 0
  const previousRootKeyPresent = (process.env.DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY?.trim().length ?? 0) > 0
  if (previousRootKeyIdPresent !== previousRootKeyPresent) {
    issue('DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID and DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY must be set together')
  }
  if (previousRootKeyIdPresent) {
    const previousRootKeyId = required('DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID')
    identifier('DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID', previousRootKeyId)
    if (previousRootKeyId === disclosureRootKeyId) {
      issue('active and previous disclosure root-key identifiers must be different')
    }
  }
}

// The production Registry scope is the public multi-tenant SaaS contract. A
// single-organization SQLite deployment remains useful for local development,
// but must never satisfy this production gate.
const selectedPostgresUrl = checkRegistry ? required('DSH_REGISTRY_POSTGRES_URL') : ''
if (selectedPostgresUrl.length > 0) {
  const parsedPostgresUrl = postgresUrl(selectedPostgresUrl)
  if (parsedPostgresUrl !== undefined && parsedPostgresUrl.username.toLowerCase() !== 'registry_app') {
    issue('DSH_REGISTRY_POSTGRES_URL must authenticate as the dedicated registry_app runtime role')
  }
}
if (checkRegistry && (process.env.DSH_REGISTRY_POSTGRES_MIGRATOR_URL?.trim().length ?? 0) > 0) {
  issue('DSH_REGISTRY_POSTGRES_MIGRATOR_URL must not be present in the Registry runtime environment')
}
if (checkRegistry && (process.env.DSH_REGISTRY_POSTGRES_BACKUP_URL?.trim().length ?? 0) > 0) {
  issue('DSH_REGISTRY_POSTGRES_BACKUP_URL must not be present in the Registry runtime environment')
}
if (checkRegistry && (process.env.REGISTRY_BACKUP_PASSWORD?.trim().length ?? 0) > 0) {
  issue('REGISTRY_BACKUP_PASSWORD must not be present in the Registry runtime environment')
}

if (checkHarness) {
  const instanceId = required('DSH_INSTANCE_ID')
  if (instanceId.length > 0) identifier('DSH_INSTANCE_ID', instanceId)
}

if (checkRegistry) {
  const alertEndpoint = required('DSH_REGISTRY_ALERT_ENDPOINT')
  if (alertEndpoint.length > 0) httpsUrl('DSH_REGISTRY_ALERT_ENDPOINT', alertEndpoint)
}

if (checkHarness) {
  const registrySyncUrl = required('DSH_REGISTRY_SYNC_URL')
  if (registrySyncUrl.length > 0 && domain.length > 0) {
    syncUrl('DSH_REGISTRY_SYNC_URL', registrySyncUrl, domain)
  }
  const disclosureBridge = required('DSH_REGISTRY_DISCLOSURE_BRIDGE_URL')
  if (disclosureBridge.length > 0 && domain.length > 0) {
    disclosureBridgeUrl('DSH_REGISTRY_DISCLOSURE_BRIDGE_URL', disclosureBridge, domain)
  }
}

const pathNames = [
  ...((checkRegistry || checkHarness) ? ['DSH_HOME'] : []),
  ...(checkRegistry ? [
    'DSH_REGISTRY_SQLITE_PATH',
    'DSH_REGISTRY_ADMISSION_SQLITE_PATH',
    'DSH_REGISTRY_ALERT_OUTBOX_SQLITE_PATH',
  ] : []),
  ...(checkHarness ? ['DSH_DISCLOSURE_STATE_PATH'] : []),
]
const paths = pathNames.map(name => [name, absolutePath(name, required(name))])
const comparable = value => process.platform === 'win32' ? value.toLowerCase() : value
for (let left = 0; left < paths.length; left += 1) {
  for (let right = left + 1; right < paths.length; right += 1) {
    if (paths[left][1].length > 0 && comparable(paths[left][1]) === comparable(paths[right][1])) {
      issue(`${paths[left][0]} and ${paths[right][0]} must use different paths`)
    }
  }
}

const secrets = [
  ...(checkRegistry ? [
    ['DSH_REGISTRY_ADMISSION_HMAC', 32],
    ['DSH_REGISTRY_ALERT_BEARER_TOKEN', 16],
    ['DSH_REGISTRY_OIDC_CLIENT_SECRET', 16],
    ['DSH_REGISTRY_SESSION_SECRET', 32],
    ['DSH_REGISTRY_MAILBOX_KEY', 32],
    ['DSH_REGISTRY_DISCLOSURE_ROOT_KEY', 32],
  ] : []),
  ...(checkHarness ? [
    ['DSH_REGISTRY_DEVICE_TOKEN', 16],
    ['DSH_REGISTRY_DISCLOSURE_TOKEN', 16],
    ['DSH_REGISTRY_DEVICE_PRIVATE_KEY', 32],
    ['DEEPSEEK_API_KEY', 16],
  ] : []),
]
for (const [name, minimumBytes] of secrets) required(name, { secret: true, minimumBytes })
if (checkRegistry) {
  const mailboxKey = process.env.DSH_REGISTRY_MAILBOX_KEY?.trim() ?? ''
  if (mailboxKey.length > 0 && !canonicalBase64Url(mailboxKey, 32)) {
    issue('DSH_REGISTRY_MAILBOX_KEY must be canonical base64url 32-byte key material')
  }
  const disclosureRootKey = process.env.DSH_REGISTRY_DISCLOSURE_ROOT_KEY?.trim() ?? ''
  if (disclosureRootKey.length > 0 && !canonicalBase64Url(disclosureRootKey, 32)) {
    issue('DSH_REGISTRY_DISCLOSURE_ROOT_KEY must be canonical base64url 32-byte key material')
  }
  if (mailboxKey.length > 0 && disclosureRootKey.length > 0 && mailboxKey === disclosureRootKey) {
    issue('DSH_REGISTRY_DISCLOSURE_ROOT_KEY must be independent from DSH_REGISTRY_MAILBOX_KEY')
  }
  const previousRootKey = process.env.DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY?.trim() ?? ''
  if (previousRootKey.length > 0) {
    required('DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY', { secret: true, minimumBytes: 32 })
    if (!canonicalBase64Url(previousRootKey, 32)) {
      issue('DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY must be canonical base64url 32-byte key material')
    }
    if (previousRootKey === disclosureRootKey || previousRootKey === mailboxKey) {
      issue('DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY must be independent from active and mailbox root keys')
    }
  }
}
if (checkHarness) {
  const token = process.env.DSH_REGISTRY_DEVICE_TOKEN?.trim() ?? ''
  const disclosure = process.env.DSH_REGISTRY_DISCLOSURE_TOKEN?.trim() ?? ''
  const privateKey = process.env.DSH_REGISTRY_DEVICE_PRIVATE_KEY?.trim() ?? ''
  const device = token.length > 0 && selectedOrganizationId.length > 0
    ? deviceToken(token, selectedOrganizationId) : null
  const bridge = disclosure.length > 0 && selectedOrganizationId.length > 0
    ? disclosureToken(disclosure, selectedOrganizationId) : null
  if (device !== null && bridge !== null
    && (device.bindingId !== bridge.bindingId || device.secret === bridge.secret)) {
    issue('Harness dsh1 and dshb1 credentials must select the same binding and use independent secrets')
  }
  if (privateKey.length > 0) devicePrivateKey(privateKey)
}

if (issues.length > 0) {
  process.stderr.write(`registry-production-environment: failed (${issues.length})\n`)
  for (const message of issues) process.stderr.write(`- ${message}\n`)
  process.exitCode = 1
} else {
  process.stdout.write([
    `registry-production-environment: static inputs valid (${scope})`,
    `- public domain: ${domain.toLowerCase()}`,
    ...(checkEdge ? ['- ACME account email: valid'] : []),
    ...(checkRegistry ? ['- HTTPS alert endpoint and Registry WSS audience: valid'] : []),
    ...(checkRegistry && selectedPostgresUrl.length > 0 ? ['- Registry domain storage: PostgreSQL URL present (value hidden)'] : []),
    ...(checkHarness ? ['- Harness Registry Sync WSS URL: valid'] : []),
    ...(pathNames.length > 0
      ? [`- ${pathNames.join(', ')}: absolute${pathNames.length > 1 ? ' and distinct' : ''}`]
      : []),
    ...(secrets.length > 0 ? ['- required secret variables: present (values hidden)'] : []),
    ...(scope === 'edge'
      ? ['- certificate issuance and live public probes still require deployment verification']
      : ['- live IdP login, KMS, operation providers, public probes, restore and SLO evidence still require deployment verification']),
    '',
  ].join('\n'))
}
