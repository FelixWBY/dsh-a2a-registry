import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'

test('standalone Registry boots, serves its UI, and denies unauthenticated operations', { timeout: 45000 }, async () => {
  const home = await mkdtemp(join(tmpdir(), 'registry-smoke-'))
  const child = spawn(process.execPath, ['--import','tsx/esm','src/dsh.ts','--profile','registry','--port','0'], {
    env: { ...process.env, DSH_HOME: home }, stdio: ['ignore','pipe','pipe'], windowsHide: true,
  })
  let output = ''
  child.stdout.on('data', chunk => { output += chunk })
  child.stderr.on('data', chunk => { output += chunk })
  const exit = once(child, 'exit')
  try {
    let base
    for (let i = 0; i < 100; i++) {
      if (child.exitCode !== null) throw new Error(output)
      base = output.match(/dsh registry: (http:\/\/127\.0\.0\.1:\d+)\//)?.[1]
      if (base) break
      await new Promise(resolve => setTimeout(resolve, 200))
    }
    assert.ok(base, output)
    assert.equal((await fetch(`${base}/readyz`)).status, 200)
    const page = await fetch(base)
    assert.equal(page.status, 200)
    assert.match(await page.text(), /__DSH_BOOT__/)
    assert.ok(page.headers.get('content-security-policy'))
    const status = await (await fetch(`${base}/registry-api/v1/status`)).json()
    assert.equal(status.value.tenancy, 'unconfigured')
    assert.equal(status.value.identity, 'unconfigured')
    assert.equal(status.value.identityProvider, 'unconfigured')
    assert.equal(status.value.billing, 'unconfigured')
    assert.equal(status.value.billingProvider, 'unconfigured')
    assert.equal((await fetch(`${base}/registry-api/v1/directory`)).status, 503)
    assert.equal((await fetch(`${base}/.env`)).status, 404)
    assert.equal((await fetch(`${base}/src/dsh.ts`)).status, 404)
  } finally {
    if (child.exitCode === null) child.kill('SIGTERM')
    await exit
    await rm(home, { recursive: true, force: true })
  }
})
