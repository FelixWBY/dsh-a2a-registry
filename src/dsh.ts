/** Independent Registry profile launcher. Never starts a Harness agent. */
import { mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { boot, loadLayeredEnv, loadOverlayPatches } from '@deepseek-ai/dsh-app-boot'
import { DSH_LAUNCH_ENVIRONMENT_KEY } from '@deepseek-ai/dsh-launch-environment'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const { values } = parseArgs({ options: {
  profile: { type: 'string', default: 'registry' },
  patch: { type: 'string', multiple: true, default: [] },
  host: { type: 'string' },
  port: { type: 'string' },
} })
if (values.profile !== 'registry') throw new Error('This installation supports only --profile registry')
process.env.DSH_HOME ??= resolve(root, '.registry')
mkdirSync(process.env.DSH_HOME, { recursive: true })
const environment = loadLayeredEnv('dsh-registry')
const patches = [
  ...loadOverlayPatches('dsh-registry', resolve(root, 'packages/bundle/registry-app/cordis.patch.yml')),
  ...values.patch.flatMap(file => loadOverlayPatches('dsh-registry', resolve(file))),
]
if (values.host !== undefined || values.port !== undefined) {
  const port = Number(values.port ?? process.env.PORT ?? 3081)
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('port must be 0..65535 (0 assigns a free port)')
  patches.push({ id: 'registry-webserver', config: {
    host: values.host ?? '127.0.0.1', port,
    compression: 'gzip', compressionLevel: 1, compressionThresholdBytes: 1024,
  } })
}
let ctx: Awaited<ReturnType<typeof boot>> | undefined
let stopping = false
async function stop(code: number) {
  if (stopping) return
  stopping = true
  const timer = setTimeout(() => process.exit(code || 1), 10_000)
  timer.unref()
  await ctx?.fiber.dispose()
  clearTimeout(timer)
  process.exit(code)
}
process.on('SIGINT', () => { void stop(130) })
process.on('SIGTERM', () => { void stop(0) })
try {
  ctx = await boot('dsh-registry', resolve(root, 'config/cordis.yml'), patches, context => {
    ctx = context
    context.provide(DSH_LAUNCH_ENVIRONMENT_KEY, environment)
  }, pathToFileURL(`${root}/`).href)
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Registry startup failed')
  await stop(1)
}
