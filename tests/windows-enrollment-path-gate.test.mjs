import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { assertPrivateWindowsSecretPath } from '../deploy/registry/enroll-registry-device.mjs'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const enrollment = join(repository, 'deploy', 'registry', 'enroll-registry-device.mjs')
const windowsGate = join(repository, 'deploy', 'registry', 'windows-private-path-gate.ps1')

function run(command, arguments_, options) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, arguments_, { ...options, shell: false, windowsHide: true })
    const output = { stdout: [], stderr: [] }
    let timer
    child.stdout.on('data', chunk => output.stdout.push(chunk))
    child.stderr.on('data', chunk => output.stderr.push(chunk))
    child.once('error', rejectPromise)
    child.once('close', code => {
      clearTimeout(timer)
      resolvePromise({
        code,
        stdout: Buffer.concat(output.stdout).toString('utf8'),
        stderr: Buffer.concat(output.stderr).toString('utf8'),
      })
    })
    timer = setTimeout(() => {
      child.kill()
      rejectPromise(new Error('enrollment path-gate test timed out'))
    }, 10_000)
    timer.unref()
  })
}

function windowsCommand(command, arguments_) {
  const result = spawnSync(command, arguments_, { encoding: 'utf8', windowsHide: true })
  assert.equal(result.status, 0, result.stderr || result.stdout)
  return result.stdout.trim()
}

function protectDirectory(path) {
  const sid = windowsCommand('powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
  ])
  windowsCommand('icacls.exe', [path, '/inheritance:r', '/grant:r',
    `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'])
}

test('Windows private-path gate is injectable and skipped on non-Windows hosts', async () => {
  const calls = []
  const runGate = async (...arguments_) => calls.push(arguments_)
  await assertPrivateWindowsSecretPath('C:\\private\\device.json', 'NewFile', {
    platform: 'win32', environment: {
      OS: 'Windows_NT', SystemRoot: 'C:\\Windows', DSH_REGISTRY_DEVICE_TOKEN: 'must-not-pass',
    }, runGate,
  })
  await assertPrivateWindowsSecretPath('/private/device.json', 'ReadFile', {
    platform: 'linux', environment: {}, runGate,
  })
  assert.deepEqual(calls, [[
    'C:\\private\\device.json', 'NewFile', { OS: 'Windows_NT', SystemRoot: 'C:\\Windows' },
  ]])
})

test('Windows executable trust gate accepts protected system tools and ignores read-only localized principals', {
  skip: process.platform !== 'win32' ? 'Windows ACL integration test' : false,
}, () => {
  const quotedGate = windowsGate.replaceAll("'", "''")
  windowsCommand('pwsh.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    `$ErrorActionPreference='Stop'; . '${quotedGate}'; `
      + '$system=[Environment]::GetFolderPath([Environment+SpecialFolder]::System); '
      + "Assert-NoUntrustedNamespaceReplacement $system 'system'; "
      + "foreach($name in 'icacls.exe','tar.exe','cmd.exe'){"
      + "$path=Resolve-ExistingFile (Join-Path $system $name) $name;"
      + 'Assert-NoUnauthorizedWriteAcl $path $name $false}',
  ])
})

test('Windows enrollment rejects an inherited parent ACL before network or state-file creation', {
  skip: process.platform !== 'win32' ? 'Windows ACL integration test' : false,
}, async t => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-enrollment-inherited-acl-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const state = join(root, 'registry-device.json')
  let requests = 0
  const server = createServer((_request, response) => {
    requests += 1
    response.writeHead(500, { 'content-type': 'application/json; charset=utf-8' })
    response.end('{"ok":false}')
  })
  await new Promise((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise)
    server.listen(0, '127.0.0.1', resolvePromise)
  })
  t.after(() => new Promise(resolvePromise => server.close(resolvePromise)))
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  const result = await run(process.execPath, [
    enrollment,
    'start',
    '--registry-origin', `http://127.0.0.1:${address.port}/`,
    '--organization-id', 'path-gate-test',
    '--instance-name', 'Path gate test',
    '--state', state,
  ], { cwd: repository, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] })
  assert.notEqual(result.code, 0)
  assert.match(result.stderr, /Windows 长期凭据路径或 ACL 检查失败/u)
  assert.equal(result.stdout, '')
  assert.equal(requests, 0)
  assert.equal(existsSync(state), false)
})

test('Windows private-path gate rejects Deny ACEs and replaceable ancestor namespaces', {
  skip: process.platform !== 'win32' ? 'Windows ACL integration test' : false,
}, async t => {
  const root = mkdtempSync(join(homedir(), 'dsh-enrollment-private-acl-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  protectDirectory(root)
  const privateDirectory = join(root, 'device')
  mkdirSync(privateDirectory)
  protectDirectory(privateDirectory)
  const state = join(privateDirectory, 'registry-device.json')

  await assertPrivateWindowsSecretPath(state, 'NewFile')

  windowsCommand('icacls.exe', [privateDirectory, '/deny', '*S-1-1-0:(D)'])
  await assert.rejects(assertPrivateWindowsSecretPath(state, 'NewFile'), /路径或 ACL 检查失败/u)
  windowsCommand('icacls.exe', [privateDirectory, '/remove:d', '*S-1-1-0'])
  await assertPrivateWindowsSecretPath(state, 'NewFile')

  windowsCommand('icacls.exe', [root, '/grant', '*S-1-1-0:(DC)'])
  await assert.rejects(assertPrivateWindowsSecretPath(state, 'NewFile'), /路径或 ACL 检查失败/u)
})
