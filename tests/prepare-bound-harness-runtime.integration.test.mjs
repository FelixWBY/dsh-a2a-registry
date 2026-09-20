import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash, generateKeyPairSync } from 'node:crypto'
import {
  cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const npmCli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')

function run(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    encoding: 'utf8', windowsHide: true, timeout: 120_000, ...options,
  })
  assert.equal(result.error, undefined)
  assert.equal(result.status, 0, result.stderr || result.stdout)
  return result
}

function protectDirectory(path) {
  const sid = run('pwsh.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
  ]).stdout.trim()
  run(join(process.env.SystemRoot, 'System32', 'icacls.exe'), [
    path, '/inheritance:r', '/grant:r',
    `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
  ])
}

function createPackage(root, name, version, cli = false) {
  mkdirSync(root, { recursive: true })
  writeFileSync(join(root, 'package.json'), `${JSON.stringify({
    name, version, type: 'module', files: cli ? ['lib/bin.js'] : ['index.js'],
  }, null, 2)}\n`)
  if (cli) {
    mkdirSync(join(root, 'lib'), { recursive: true })
    writeFileSync(join(root, 'lib', 'bin.js'), `
const args = process.argv.slice(2)
if (args.includes('--version')) console.log(${JSON.stringify(version)})
else if (args.includes('--dump-config')) {
  const patch = args[args.indexOf('--patch') + 1] ?? ''
  if (patch.includes('harness-production-publication')) console.log(\`- id: web-runtime
  name: '@deepseek-ai/dsh-web-app'
  inject:
    - webStartup
    - credentials
  config:
    productionRegistryConnection:
      mode: production
      organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID
      instanceId: !!js process.env.DSH_INSTANCE_ID
      tokenEnv: DSH_REGISTRY_DEVICE_TOKEN
      privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY
      transport:
        url: !!js process.env.DSH_REGISTRY_SYNC_URL
    productionDisclosureHttpsBridge:
      url: !!js process.env.DSH_REGISTRY_DISCLOSURE_BRIDGE_URL
      tokenEnv: DSH_REGISTRY_DISCLOSURE_TOKEN
    productionDisclosurePublication:
      storageRoot: !!js process.env.DSH_DISCLOSURE_STATE_PATH
    productionRegistryDisclosureImport:
      maxRetainedBytes: 16777216
    productionRegistryQuestionConsumer:
      handling: automatic
      localModel:
        provider: deepseek-official
        model: deepseek-flash
      modelCredentialEnv: DEEPSEEK_API_KEY
      maxClaims: 10000
      mailboxLimits:
        maxRequests: 10000
        maxRetainedRequests: 100000
        maxPendingOperations: 256
- id: session-controller
  name: '@deepseek-ai/dsh-api-session-controller'
  config:
    disclosurePreview: {}\`)
  else console.log(\`- id: web-runtime
  name: '@deepseek-ai/dsh-web-app'
  inject:
    - webStartup
    - credentials
  config:
    productionRegistryConnection:
      mode: production
      organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID
      instanceId: !!js process.env.DSH_INSTANCE_ID
      tokenEnv: DSH_REGISTRY_DEVICE_TOKEN
      privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY
      transport:
        url: !!js process.env.DSH_REGISTRY_SYNC_URL\`)
}
else {
  const { createServer } = await import('node:http')
  const port = Number(args[args.indexOf('--port') + 1])
  createServer((_request, response) => response.end('ok')).listen(port, '127.0.0.1')
}
`.trimStart())
  } else {
    writeFileSync(join(root, 'index.js'), 'export {}\n')
  }
}

function packPackage(packageRoot, destination) {
  run(process.execPath, [npmCli, 'pack', '--pack-destination', destination], {
    cwd: packageRoot,
    env: Object.fromEntries(Object.entries(process.env)
      .filter(([name]) => name !== 'NODE_OPTIONS' && name !== 'NODE_PATH')),
  })
}

function writeHashManifest(root) {
  const files = []
  const visit = directory => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const fullPath = join(directory, entry.name)
      if (entry.isDirectory()) visit(fullPath)
      else if (entry.isFile() && entry.name !== 'runtime-files.sha256') files.push(fullPath)
    }
  }
  visit(root)
  const lines = files.map(path => {
    const relative = path.slice(root.length + 1).replaceAll('\\', '/')
    const hash = createHash('sha256').update(readFileSync(path)).digest('hex')
    return { relative, line: `${hash}  ${relative}` }
  }).sort((left, right) => left.relative.localeCompare(right.relative, 'en'))
  writeFileSync(join(root, 'runtime-files.sha256'), `${lines.map(item => item.line).join('\n')}\n`)
}

test('Windows prepares one physical production runtime from reviewed release groups', {
  skip: process.platform !== 'win32' ? 'Windows runtime integration test' : false,
  timeout: 360_000,
}, t => {
  const root = mkdtempSync(join(homedir(), 'dsh-runtime-preparer-'))
  protectDirectory(root)
  let launchedPid
  t.after(() => {
    if (launchedPid !== undefined) {
      spawnSync('pwsh.exe', [
        '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
        'Stop-Process -Id $env:HARNESS_TEST_PID -Force -ErrorAction SilentlyContinue',
      ], { env: { ...process.env, HARNESS_TEST_PID: String(launchedPid) }, windowsHide: true })
    }
    const resolved = join(homedir(), root.slice(homedir().length + 1))
    assert.equal(resolved, root)
    rmSync(root, { recursive: true, force: true, maxRetries: 3 })
  })

  const builder = join(root, 'builder')
  mkdirSync(builder)
  for (const name of [
    'prepare-bound-harness-runtime.ps1', 'start-bound-harness.ps1',
    'windows-private-path-gate.ps1', 'harness-registry-connection.example.patch.yml',
    'harness-production-publication.example.patch.yml',
  ]) {
    cpSync(join(repository, 'deploy', 'registry', name), join(builder, name))
  }
  const trustedNodeRoot = join(root, 'trusted-node')
  mkdirSync(join(trustedNodeRoot, 'node_modules'), { recursive: true })
  cpSync(process.execPath, join(trustedNodeRoot, 'node.exe'))
  cpSync(join(dirname(process.execPath), 'node_modules', 'npm'),
    join(trustedNodeRoot, 'node_modules', 'npm'), { recursive: true })

  const sources = join(root, 'sources')
  const outputs = [join(root, 'dsh'), join(root, 'vendor'), join(root, 'system-native')]
  for (const path of [sources, ...outputs]) mkdirSync(path)
  createPackage(join(sources, 'dsh'), '@deepseek-ai/dsh', '0.1.2-rc.1', true)
  createPackage(join(sources, 'cordis'), '@deepseek-ai/cordis', '4.0.2')
  createPackage(join(sources, 'schemastery'), '@deepseek-ai/schemastery', '3.18.2')
  createPackage(join(sources, 'system-native'), '@deepseek-ai/node-addon-system', '0.1.2')
  packPackage(join(sources, 'dsh'), outputs[0])
  packPackage(join(sources, 'cordis'), outputs[1])
  packPackage(join(sources, 'schemastery'), outputs[1])
  packPackage(join(sources, 'system-native'), outputs[2])
  for (const output of outputs) {
    writeFileSync(join(output, 'publish-order.txt'),
      `${readdirSync(output).filter(name => name.endsWith('.tgz')).sort().join('\n')}\n`)
  }

  const destination = join(root, 'bound-runtime')
  const environment = {
    ...Object.fromEntries(Object.entries(process.env)
      .filter(([name]) => name !== 'NODE_OPTIONS' && name !== 'NODE_PATH')),
    PREPARER: join(builder, 'prepare-bound-harness-runtime.ps1'),
    TARBALL_0: outputs[0], TARBALL_1: outputs[1], TARBALL_2: outputs[2],
    PREPARER_NODE: join(trustedNodeRoot, 'node.exe'), PREPARER_DESTINATION: destination,
  }
  run('pwsh.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '& $env:PREPARER -TarballDirectory @($env:TARBALL_0,$env:TARBALL_1,$env:TARBALL_2) '
      + '-NodePath $env:PREPARER_NODE -DestinationRoot $env:PREPARER_DESTINATION '
      + '-RuntimeMode Production',
  ], { cwd: root, env: environment })

  assert.equal(existsSync(join(destination, 'harness', 'apps', 'cli', 'lib', 'bin.js')), true)
  assert.equal(existsSync(join(destination, 'node', 'node.exe')), true)
  assert.equal(existsSync(join(destination, 'runtime-package-lock.json')), true)
  assert.equal(existsSync(join(destination, 'runtime-files.sha256')), true)
  const evidence = JSON.parse(readFileSync(join(destination, 'runtime-build.json'), 'utf8'))
  assert.equal(evidence.harnessVersion, '0.1.2-rc.1')
  assert.equal(evidence.lifecycleScripts, false)
  assert.equal(evidence.optionalDependenciesInstalled, false)
  assert.equal(evidence.credentialInputs, 'external-at-launch')
  assert.equal(evidence.runtimeMode, 'Production')
  assert.deepEqual(evidence.validatedModes, ['ConnectionOnly', 'Production'])
  assert.deepEqual(evidence.registryDeepseekDependencies, [])
  const aclResult = run('pwsh.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '@($env:RUNTIME_HARNESS,$env:RUNTIME_NODE,$env:RUNTIME_LAUNCHER) | '
      + 'ForEach-Object { (Get-Acl -LiteralPath $_).AreAccessRulesProtected }',
  ], { env: {
    ...process.env,
    RUNTIME_HARNESS: join(destination, 'harness'),
    RUNTIME_NODE: join(destination, 'node'),
    RUNTIME_LAUNCHER: join(destination, 'launcher'),
  } })
  assert.deepEqual(aclResult.stdout.trim().split(/\r?\n/u), ['True', 'True', 'True'])

  const launchRuntime = join(root, 'launch-runtime')
  mkdirSync(launchRuntime)
  protectDirectory(launchRuntime)
  mkdirSync(join(launchRuntime, 'harness', 'apps'), { recursive: true })
  cpSync(join(destination, 'harness', 'apps', 'cli'),
    join(launchRuntime, 'harness', 'apps', 'cli'), { recursive: true })
  mkdirSync(join(launchRuntime, 'node'))
  cpSync(join(destination, 'node', 'node.exe'), join(launchRuntime, 'node', 'node.exe'))
  cpSync(join(destination, 'launcher'), join(launchRuntime, 'launcher'), { recursive: true })
  cpSync(join(destination, 'runtime-package-lock.json'),
    join(launchRuntime, 'runtime-package-lock.json'))
  cpSync(join(destination, 'runtime-build.json'), join(launchRuntime, 'runtime-build.json'))
  for (const path of [
    join(launchRuntime, 'harness'), join(launchRuntime, 'node'), join(launchRuntime, 'launcher'),
  ]) protectDirectory(path)
  writeHashManifest(launchRuntime)

  const privateRoot = join(root, 'private')
  mkdirSync(privateRoot)
  protectDirectory(privateRoot)
  const dshHome = join(privateRoot, 'home')
  const logDirectory = join(privateRoot, 'logs')
  const stateDirectory = join(privateRoot, 'disclosures')
  for (const path of [dshHome, logDirectory, stateDirectory]) {
    mkdirSync(path)
    protectDirectory(path)
  }
  const organizationId = 'runtime-test-organization'
  const encodedOrganization = Buffer.from(organizationId, 'utf8').toString('base64url')
  const bindingId = '00000000-0000-4000-8000-000000000018'
  const privateKey = generateKeyPairSync('ed25519').privateKey
    .export({ format: 'der', type: 'pkcs8' }).toString('base64url')
  const envFile = join(privateRoot, 'harness.env')
  writeFileSync(envFile, [
    `DSH_REGISTRY_ORGANIZATION_ID=${organizationId}`,
    'DSH_INSTANCE_ID=runtime-test-instance',
    'DSH_REGISTRY_SYNC_URL=wss://registry.invalid/a2a/v1/sync',
    `DSH_REGISTRY_DEVICE_TOKEN=dsh1.${encodedOrganization}.${bindingId}.${Buffer.alloc(32, 8).toString('base64url')}`,
    `DSH_REGISTRY_DEVICE_PRIVATE_KEY=${privateKey}`,
    `DSH_REGISTRY_DISCLOSURE_TOKEN=dshb1.${encodedOrganization}.${bindingId}.${Buffer.alloc(32, 9).toString('base64url')}`,
    'DSH_REGISTRY_DISCLOSURE_BRIDGE_URL=https://registry.invalid/a2a/v1/disclosure-publication',
    `DSH_DISCLOSURE_STATE_PATH=${stateDirectory}`,
    'DEEPSEEK_API_KEY=runtime-test-model-key',
    '',
  ].join('\n'))
  const caCertificate = join(privateRoot, 'registry-ca.pem')
  writeFileSync(caCertificate, '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n')
  const port = Number(run('pwsh.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); '
      + '$listener.Start(); $listener.LocalEndpoint.Port; $listener.Stop()',
  ]).stdout.trim())
  const launched = spawnSync('pwsh.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
    join(launchRuntime, 'launcher', 'start-bound-harness.ps1'),
    '-HarnessRoot', join(launchRuntime, 'harness'),
    '-NodePath', join(launchRuntime, 'node', 'node.exe'),
    '-EnvFile', envFile,
    '-CaCertificate', caCertificate,
    '-DshHome', dshHome,
    '-LogDirectory', logDirectory,
    '-RuntimeMode', 'Production',
    '-Port', String(port),
  ], {
    env: Object.fromEntries(Object.entries(process.env)
      .filter(([name]) => name !== 'NODE_OPTIONS' && name !== 'NODE_PATH')),
    stdio: 'ignore',
    windowsHide: true,
    timeout: 90_000,
  })
  assert.equal(launched.error, undefined)
  assert.equal(launched.status, 0)
  launchedPid = Number(run('pwsh.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '(Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 '
      + '-LocalPort $env:HARNESS_TEST_PORT -ErrorAction Stop).OwningProcess',
  ], { env: { ...process.env, HARNESS_TEST_PORT: String(port) } }).stdout.trim())
  assert.equal(Number.isInteger(launchedPid), true)
  assert.equal(readdirSync(root).some(name => name.includes('.staging-')), false)
})
