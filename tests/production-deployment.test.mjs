import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { composeEntries, loadOverlayPatches } from '@deepseek-ai/dsh-app-boot'
import {
  buildHttpRedirectProbes,
  verifyHttpRedirectValue,
  verifyRuntimeConfigurationValue,
} from '../deploy/registry/verify-public-registry.mjs'

const registryVariables = /^(?:DSH_|REGISTRY_DOMAIN$|REGISTRY_BACKUP_PASSWORD$)/u

function deploymentEntries(...patches) {
  return composeEntries([
    'packages/bundle/registry-app/cordis.patch.yml',
    ...patches,
  ].map(path => loadOverlayPatches('production-deployment-test', resolve(path))))
}

function assertDisclosureContentProvider(entries, maxContentEvents) {
  const provider = entries.find(entry => entry.id === 'registry-disclosure-content-provider')
  assert.equal(provider?.name, '@deepseek-ai/dsh-registry-disclosure-content-app')
  assert.deepEqual(provider?.inject, ['registryDisclosureKeyProvider'])
  assert.deepEqual(provider?.config, {
    maxContentEvents,
    crypto: { maxPlaintextBytes: 65536, maxCiphertextBytes: 262144, maxTrustedKeys: 4 },
  })
  const runtime = entries.find(entry => entry.id === 'registry-runtime')
  assert.equal(runtime?.config?.saas?.disclosureContentProvider, true)
  assert.ok(runtime?.inject?.includes('registryDisclosureContentProvider'))
}

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
    DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID: 'registry-root:v1',
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
    DSH_REGISTRY_DISCLOSURE_ROOT_KEY: Buffer.alloc(32, 8).toString('base64url'),
  }
}

function harnessEnvironment() {
  const env = Object.fromEntries(Object.entries(process.env)
    .filter(([name]) => !registryVariables.test(name)))
  const root = join(tmpdir(), 'dsh-harness-production-preflight')
  const organizationId = 'harness-organization'
  const encodedOrganization = Buffer.from(organizationId, 'utf8').toString('base64url')
  const bindingId = '00000000-0000-4000-8000-000000000008'
  return {
    ...env,
    REGISTRY_DOMAIN: 'registry.acme.dev',
    DSH_HOME: join(root, 'home'),
    DSH_REGISTRY_ORGANIZATION_ID: organizationId,
    DSH_INSTANCE_ID: 'harness-instance',
    DSH_REGISTRY_SYNC_URL: 'wss://registry.acme.dev/a2a/v1/sync',
    DSH_REGISTRY_DISCLOSURE_BRIDGE_URL: 'https://registry.acme.dev/a2a/v1/disclosure-publication',
    DSH_DISCLOSURE_STATE_PATH: join(root, 'disclosures'),
    DSH_REGISTRY_DEVICE_TOKEN:
      `dsh1.${encodedOrganization}.${bindingId}.${Buffer.alloc(32, 9).toString('base64url')}`,
    DSH_REGISTRY_DISCLOSURE_TOKEN:
      `dshb1.${encodedOrganization}.${bindingId}.${Buffer.alloc(32, 10).toString('base64url')}`,
    DSH_REGISTRY_DEVICE_PRIVATE_KEY: generateKeyPairSync('ed25519').privateKey
      .export({ format: 'der', type: 'pkcs8' }).toString('base64url'),
  }
}

function preflight(env, scope = 'registry') {
  return spawnSync(process.execPath, ['deploy/registry/check-production-environment.mjs', scope], {
    cwd: new URL('..', import.meta.url), env, encoding: 'utf8',
  })
}

test('Registry deployment overlays install the bounded disclosure content provider', () => {
  assertDisclosureContentProvider(deploymentEntries(
    'deploy/registry/registry-single-host.example.patch.yml',
    'deploy/registry/registry-postgres.example.patch.yml',
    'deploy/registry/registry-production.example.patch.yml',
  ), 1000)
  assertDisclosureContentProvider(deploymentEntries(
    'deploy/registry/registry-keycloak-local.example.patch.yml',
  ), 100)
})

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

test('production Registry preflight requires canonical disclosure root-key inputs', () => {
  const missingId = productionEnvironment()
  delete missingId.DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID
  const rejectedId = preflight(missingId)
  assert.equal(rejectedId.status, 1)
  assert.match(rejectedId.stderr, /DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID is required/u)

  const invalidId = { ...productionEnvironment(), DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID: 'root key v1' }
  const rejectedInvalidId = preflight(invalidId)
  assert.equal(rejectedInvalidId.status, 1)
  assert.match(rejectedInvalidId.stderr, /DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID must be a valid DSH identifier/u)

  const missingKey = productionEnvironment()
  delete missingKey.DSH_REGISTRY_DISCLOSURE_ROOT_KEY
  const rejectedMissingKey = preflight(missingKey)
  assert.equal(rejectedMissingKey.status, 1)
  assert.match(rejectedMissingKey.stderr, /DSH_REGISTRY_DISCLOSURE_ROOT_KEY is required/u)

  const paddedKey = {
    ...productionEnvironment(),
    DSH_REGISTRY_DISCLOSURE_ROOT_KEY: Buffer.alloc(32, 8).toString('base64'),
  }
  const rejectedPaddedKey = preflight(paddedKey)
  assert.equal(rejectedPaddedKey.status, 1)
  assert.match(rejectedPaddedKey.stderr,
    /DSH_REGISTRY_DISCLOSURE_ROOT_KEY must be canonical base64url 32-byte key material/u)

  const reusedKey = productionEnvironment()
  reusedKey.DSH_REGISTRY_DISCLOSURE_ROOT_KEY = reusedKey.DSH_REGISTRY_MAILBOX_KEY
  const rejectedReusedKey = preflight(reusedKey)
  assert.equal(rejectedReusedKey.status, 1)
  assert.match(rejectedReusedKey.stderr,
    /DSH_REGISTRY_DISCLOSURE_ROOT_KEY must be independent from DSH_REGISTRY_MAILBOX_KEY/u)

  const pairedPrevious = {
    ...productionEnvironment(),
    DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID: 'registry-root:v0',
    DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY: Buffer.alloc(32, 9).toString('base64url'),
  }
  assert.equal(preflight(pairedPrevious).status, 0)

  const missingPreviousMaterial = { ...productionEnvironment(),
    DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID: 'registry-root:v0' }
  const rejectedMissingPreviousMaterial = preflight(missingPreviousMaterial)
  assert.equal(rejectedMissingPreviousMaterial.status, 1)
  assert.match(rejectedMissingPreviousMaterial.stderr, /must be set together/u)

  const duplicatePreviousId = { ...pairedPrevious,
    DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID: pairedPrevious.DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID }
  const rejectedDuplicatePreviousId = preflight(duplicatePreviousId)
  assert.equal(rejectedDuplicatePreviousId.status, 1)
  assert.match(rejectedDuplicatePreviousId.stderr, /identifiers must be different/u)

  const reusedPreviousMaterial = { ...pairedPrevious,
    DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY: pairedPrevious.DSH_REGISTRY_DISCLOSURE_ROOT_KEY }
  const rejectedReusedPreviousMaterial = preflight(reusedPreviousMaterial)
  assert.equal(rejectedReusedPreviousMaterial.status, 1)
  assert.match(rejectedReusedPreviousMaterial.stderr, /must be independent from active and mailbox root keys/u)
})

test('production Harness preflight pins the disclosure bridge to the exact public HTTPS endpoint', () => {
  const valid = harnessEnvironment()
  const accepted = preflight(valid, 'harness')
  assert.equal(accepted.status, 0, accepted.stderr)

  for (const invalidUrl of [
    'https://registry.acme.dev:443/a2a/v1/disclosure-publication',
    'https://registry.acme.dev/a2a/v1/disclosure-publication?target=other',
    'https://other.acme.dev/a2a/v1/disclosure-publication',
    'http://registry.acme.dev/a2a/v1/disclosure-publication',
  ]) {
    const rejected = preflight({ ...valid, DSH_REGISTRY_DISCLOSURE_BRIDGE_URL: invalidUrl }, 'harness')
    assert.equal(rejected.status, 1)
    assert.match(rejected.stderr,
      /DSH_REGISTRY_DISCLOSURE_BRIDGE_URL must be the exact public HTTPS disclosure bridge URL/u)
  }

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

test('public HTTP entry redirects permanently to the exact same HTTPS request target', () => {
  const expected = new URL('https://registry.acme.dev/')
  const requested = new URL('http://registry.acme.dev/.well-known/dsh-registry-http-redirect-check?verification=public-entry')
  const valid = 'https://registry.acme.dev/.well-known/dsh-registry-http-redirect-check?verification=public-entry'
  assert.doesNotThrow(() => verifyHttpRedirectValue(expected, requested, 301, valid))
  assert.doesNotThrow(() => verifyHttpRedirectValue(expected, requested, 308, valid))
  assert.throws(() => verifyHttpRedirectValue(expected, requested, 302, valid), /permanent redirect/u)
  assert.throws(() => verifyHttpRedirectValue(expected, requested, 308,
    'https://other.acme.dev/.well-known/dsh-registry-http-redirect-check?verification=public-entry'),
    /leaves the public Registry origin/u)
  assert.throws(() => verifyHttpRedirectValue(expected, requested, 308,
    'https://user:secret@registry.acme.dev/.well-known/dsh-registry-http-redirect-check?verification=public-entry'),
    /contains credentials/u)
  assert.throws(() => verifyHttpRedirectValue(expected, requested, 308,
    'http://registry.acme.dev/.well-known/dsh-registry-http-redirect-check?verification=public-entry'),
    /HTTPS on port 443/u)
  assert.throws(() => verifyHttpRedirectValue(expected, requested, 308,
    'https://registry.acme.dev:444/.well-known/dsh-registry-http-redirect-check?verification=public-entry'),
    /HTTPS on port 443/u)
  assert.throws(() => verifyHttpRedirectValue(expected, requested, 308,
    'https://registry.acme.dev/wrong?verification=public-entry'), /does not preserve/u)
})

test('public HTTP redirect probes cover unpredictable page, API and WSS targets with GET and POST', () => {
  const nonce = '0123456789abcdef0123456789abcdef'
  const probes = buildHttpRedirectProbes(nonce)
  assert.equal(probes.length, 5)
  assert.deepEqual(new Set(probes.map(probe => probe.method)), new Set(['GET', 'POST']))
  assert.ok(probes.some(probe => probe.path.startsWith('/?verification=')))
  assert.ok(probes.some(probe => probe.path.startsWith('/registry-api/v1/status?verification=')))
  assert.ok(probes.some(probe => probe.path.startsWith('/a2a/v1/sync?verification=')))
  assert.ok(probes.some(probe => probe.path.includes(nonce)))
  assert.equal(new Set(probes.map(probe => probe.path)).size, probes.length)
  assert.throws(() => buildHttpRedirectProbes('predictable'), /nonce is invalid/u)
})

test('systemd production examples disable runtime injection, core dumps and private device access', () => {
  for (const relativePath of [
    'deploy/registry/dsh-registry.service.example',
    'deploy/registry/dsh-harness.service.example',
    'deploy/registry/caddy-registry.service.conf.example',
  ]) {
    const unit = readFileSync(new URL(`../${relativePath}`, import.meta.url), 'utf8')
    assert.match(unit,
      /^UnsetEnvironment=NODE_OPTIONS NODE_PATH NODE_TLS_REJECT_UNAUTHORIZED LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT$/mu,
      `${relativePath} must clear inherited runtime injection variables`)
    assert.match(unit, /^LimitCORE=0$/mu, `${relativePath} must disable core dumps`)
    assert.match(unit, /^PrivateDevices=true$/mu, `${relativePath} must hide host devices`)
  }
  const harness = readFileSync(new URL('../deploy/registry/dsh-harness.service.example', import.meta.url), 'utf8')
  assert.match(harness,
    /^Documentation=file:\/opt\/dsh-a2a-registry\/deploy\/registry\/README\.md$/mu)
  assert.match(harness,
    /^ExecStartPre=\/usr\/bin\/node \/opt\/dsh-a2a-registry\/deploy\/registry\/check-production-environment\.mjs harness$/mu)
  assert.doesNotMatch(harness, /deepseek-harness\/deploy\/registry/u)
})

test('Windows Harness runtime preparer declares the static release and ACL gates', () => {
  const preparer = readFileSync(new URL(
    '../deploy/registry/prepare-bound-harness-runtime.ps1', import.meta.url), 'utf8')
  assert.match(preparer, /--install-strategy=hoisted/u)
  assert.match(preparer, /'--ignore-scripts', '--omit=optional'/u)
  assert.doesNotMatch(preparer, /EnableLifecycleScripts/u)
  assert.doesNotMatch(preparer, /Get-Command 'tar\.exe'|& icacls\.exe/u)
  const nodeTrust = preparer.indexOf(
    "Assert-NoUntrustedNamespaceReplacement $nodeSourceRoot 'NodePath 父目录'")
  const nodeExecution = preparer.indexOf("$nodeVersion = @(& $NodePath -p 'process.versions.node'")
  assert.ok(nodeTrust >= 0 && nodeExecution > nodeTrust,
    'the source Node.js namespace must be trusted before execution')
  assert.match(preparer, /Assert-NoReparsePointsRecursively \$stagingRoot/u)
  assert.match(preparer, /runtime-files\.sha256/u)
  assert.match(preparer, /Assert-PublishOrder/u)
  assert.match(preparer, /runtime-package-lock\.json/u)
  assert.match(preparer, /未由输入 tarball 提供的 DeepSeek 包/u)
  assert.match(preparer, /\[IO\.Directory\]::Move\(\$stagingRoot, \$DestinationRoot\)/u)
  assert.match(preparer, /productionRegistryConnection:/u)
  for (const forbidden of [
    'testOnlyDisclosurePublication:',
    'productionDisclosureHttpsBridge:',
    'productionDisclosurePublication:',
    'registryDisclosureImport:',
    'productionRegistryDisclosureImport:',
    'registryA2aConsumer:',
    'productionDisclosureAuthority',
    'registryDisclosureKeyPublisher',
    'a2aDisclosureDecryption:',
    'loopbackDisclosureImport:',
    'loopbackA2aConsumer:',
    'loopbackDisclosureRefresh:',
    'registryUrl:',
    'sharedSecretEnv:',
  ]) {
    assert.ok(preparer.includes(`'${forbidden}'`), `preparer must reject ${forbidden}`)
  }
  assert.match(preparer, /Remove-StagingDirectory \$stagingRoot \$destinationParent \$stagingName/u)

  const launcher = readFileSync(new URL(
    '../deploy/registry/start-bound-harness.ps1', import.meta.url), 'utf8')
  assert.match(launcher, /\[ValidateRange\(1, 65535\)\][\s\S]*\[int\]\$Port = 3080/u)
  assert.match(launcher, /Test-PortInUse \$Port/u)
  assert.match(launcher, /Test-ProcessOwnsLoopbackListener \$process\.Id \$Port/u)
  const namespaceCheck = launcher.indexOf(
    "Assert-NoUntrustedNamespaceReplacement (Split-Path -Parent $NodePath) 'NodePath 父目录'")
  const nodeProbe = launcher.indexOf("$nodeVersion = @(& $NodePath -p 'process.versions.node'")
  assert.ok(namespaceCheck >= 0 && nodeProbe > namespaceCheck,
    'Node.js must not execute before its parent namespace is trusted')
  assert.match(launcher, /\$requiredDeviceEnvironmentNames = @\([\s\S]*DSH_REGISTRY_DEVICE_PRIVATE_KEY[\s\S]*\)/u)
  assert.match(launcher,
    /\$values\.Count -ne \$requiredDeviceEnvironmentNames\.Count[\s\S]*\$values\.Count -ne \$deviceEnvironmentNames\.Count/u)
  assert.match(launcher, /\$values\.ContainsKey\('DSH_REGISTRY_DISCLOSURE_TOKEN'\)/u)
  assert.match(launcher, /const hasDisclosureToken = disclosureToken\.length > 0/u)
  assert.match(launcher, /if \(hasDisclosureToken\)[\s\S]*disclosureParts\[2\] !== parts\[2\][\s\S]*\.equals\(deviceSecretBytes\)/u)
  assert.match(launcher, /foreach \(\$name in @\(\$deviceEnvironment\.Keys\)\)/u)
})
