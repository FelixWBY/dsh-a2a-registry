import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { verifyRuntimeConfigurationValue } from '../deploy/registry/verify-public-registry.mjs'

const registryVariables = /^(?:DSH_|REGISTRY_DOMAIN$|REGISTRY_BACKUP_PASSWORD$)/u

function productionEnvironment() {
  const env = Object.fromEntries(Object.entries(process.env)
    .filter(([name]) => !registryVariables.test(name)))
  const root = join(tmpdir(), 'dsh-registry-production-preflight')
  return {
    ...env,
    REGISTRY_DOMAIN: 'registry.acme.dev',
    DSH_HOME: join(root, 'home'),
    DSH_REGISTRY_ORGANIZATION_ID: 'legacy-organization',
    DSH_REGISTRY_ORGANIZATION_NAME: 'Legacy organization',
    DSH_REGISTRY_BOOTSTRAP_MEMBER_ID: 'owner-1',
    DSH_REGISTRY_BOOTSTRAP_MEMBER_NAME: 'Registry Owner',
    DSH_REGISTRY_PUBLIC_ORIGIN: 'https://registry.acme.dev/',
    DSH_REGISTRY_OIDC_ISSUER: 'https://identity.acme.dev/realms/registry',
    DSH_REGISTRY_OIDC_CLIENT_ID: 'dsh-registry',
    DSH_REGISTRY_SYNC_AUDIENCE: 'wss://registry.acme.dev/a2a/v1/sync',
    DSH_REGISTRY_ALERT_ENDPOINT: 'https://alerts.acme.dev/registry',
    DSH_REGISTRY_POSTGRES_URL: 'postgresql://registry_app:runtime-password@postgres.acme.dev:5432/registry',
    DSH_REGISTRY_SQLITE_PATH: join(root, 'fallback.sqlite'),
    DSH_REGISTRY_ADMISSION_SQLITE_PATH: join(root, 'admission.sqlite'),
    DSH_REGISTRY_ALERT_OUTBOX_SQLITE_PATH: join(root, 'alert-outbox.sqlite'),
    DSH_REGISTRY_ADMISSION_HMAC: 'admission-secret-material-32-bytes',
    DSH_REGISTRY_ALERT_BEARER_TOKEN: 'alert-bearer-token',
    DSH_REGISTRY_OIDC_CLIENT_SECRET: 'oidc-client-secret',
    DSH_REGISTRY_SESSION_SECRET: 'session-secret-material-at-least-32-bytes',
    DSH_REGISTRY_MAILBOX_KEY: Buffer.alloc(32, 7).toString('base64url'),
  }
}

function preflight(env) {
  return spawnSync(process.execPath, ['deploy/registry/check-production-environment.mjs', 'registry'], {
    cwd: new URL('..', import.meta.url), env, encoding: 'utf8',
  })
}

test('production Registry preflight requires the PostgreSQL SaaS inputs', () => {
  const valid = productionEnvironment()
  const accepted = preflight(valid)
  assert.equal(accepted.status, 0, accepted.stderr)

  const sqliteOnly = { ...valid }
  delete sqliteOnly.DSH_REGISTRY_POSTGRES_URL
  const rejectedStorage = preflight(sqliteOnly)
  assert.equal(rejectedStorage.status, 1)
  assert.match(rejectedStorage.stderr, /DSH_REGISTRY_POSTGRES_URL is required/u)

  const unnamedLegacyOrganization = { ...valid }
  delete unnamedLegacyOrganization.DSH_REGISTRY_ORGANIZATION_NAME
  const rejectedOrganization = preflight(unnamedLegacyOrganization)
  assert.equal(rejectedOrganization.status, 1)
  assert.match(rejectedOrganization.stderr, /DSH_REGISTRY_ORGANIZATION_NAME is required/u)
})

test('public production status requires the live SaaS tenant-router marker', () => {
  const configured = Object.fromEntries([
    'identity', 'registry', 'disclosureOperations', 'deviceBinding',
    'audit', 'rateLimits', 'disclosureCleanup', 'mailboxCleanup',
  ].map(name => [name, 'configured']))
  assert.throws(() => verifyRuntimeConfigurationValue({
    deploymentMode: 'standard', tenancy: 'single-organization', ...configured,
  }), /does not report a loaded SaaS tenant router/u)
  assert.doesNotThrow(() => verifyRuntimeConfigurationValue({
    deploymentMode: 'standard', tenancy: 'saas', ...configured,
  }))
})
