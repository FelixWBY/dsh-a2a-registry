import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
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
else if (args.includes('--dump-config')) console.log(\`- id: web-runtime
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
else process.exitCode = 2
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

test('Windows prepares one physical connection-only runtime from reviewed release groups', {
  skip: process.platform !== 'win32' ? 'Windows runtime integration test' : false,
  timeout: 180_000,
}, t => {
  const root = mkdtempSync(join(homedir(), 'dsh-runtime-preparer-'))
  protectDirectory(root)
  t.after(() => {
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
  const outputs = [join(root, 'dsh'), join(root, 'vendor'), join(root, 'landlock')]
  for (const path of [sources, ...outputs]) mkdirSync(path)
  createPackage(join(sources, 'dsh'), '@deepseek-ai/dsh', '0.1.2-rc.1', true)
  createPackage(join(sources, 'cordis'), '@deepseek-ai/cordis', '4.0.2')
  createPackage(join(sources, 'schemastery'), '@deepseek-ai/schemastery', '3.18.2')
  createPackage(join(sources, 'landlock'), '@deepseek-ai/node-addon-landlock-run', '0.1.1')
  packPackage(join(sources, 'dsh'), outputs[0])
  packPackage(join(sources, 'cordis'), outputs[1])
  packPackage(join(sources, 'schemastery'), outputs[1])
  packPackage(join(sources, 'landlock'), outputs[2])
  for (const output of outputs.slice(0, 2)) {
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
      + '-NodePath $env:PREPARER_NODE -DestinationRoot $env:PREPARER_DESTINATION',
  ], { cwd: root, env: environment })

  assert.equal(existsSync(join(destination, 'harness', 'apps', 'cli', 'lib', 'bin.js')), true)
  assert.equal(existsSync(join(destination, 'node', 'node.exe')), true)
  assert.equal(existsSync(join(destination, 'runtime-package-lock.json')), true)
  assert.equal(existsSync(join(destination, 'runtime-files.sha256')), true)
  const evidence = JSON.parse(readFileSync(join(destination, 'runtime-build.json'), 'utf8'))
  assert.equal(evidence.harnessVersion, '0.1.2-rc.1')
  assert.equal(evidence.lifecycleScripts, false)
  assert.equal(readdirSync(root).some(name => name.includes('.staging-')), false)
})
