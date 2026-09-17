/** Optional Registry producer upgrade route; TLS termination is an explicit external deployment responsibility. */
import type { Context } from '@deepseek-ai/cordis'
import { WebSocketServer } from 'ws'
import type { RegistryProducerAuthenticator } from '@deepseek-ai/dsh-a2a-device-identity/runtime'
import { REGISTRY_SYNC_PATH } from '@deepseek-ai/dsh-a2a-registry-sync'
import type {} from '@deepseek-ai/dsh-host-webserver'
import { RegistrySyncConnection, registryAuthenticatorTarget,
  type RegistryRuntimeStoreResolver } from './sync-connection.ts'
import { RegistrySyncAdmission } from './sync-admission.ts'
import type { RegistrySyncConfig } from './sync-config.ts'
import type { RegistryRuntimeStore } from './runtime-store.ts'

/** Install one bounded route; its caller registers this resource as a Cordis effect.
 * @param ctx - Runtime context with the loopback HTTP service.
 * @param config - Explicit TLS proxy declaration, canonical audience and transport bounds.
 * @param provider - External identity adapter, never a Local cookie or development token.
 * @param store - Fixed legacy owner or tenant resolver returning a connection-lifetime store lease.
 * @param signal - Runtime cancellation; every connection drains before disposal settles.
 * @returns Idempotent disposer which first withdraws admission, then closes and drains connections. */
export function installRegistrySync(ctx: Context, config: RegistrySyncConfig, provider: RegistryProducerAuthenticator,
  store: RegistryRuntimeStore | RegistryRuntimeStoreResolver, signal: AbortSignal): () => Promise<void> {
  const webServer = ctx.get('webServer')
  if (webServer === undefined || webServer.host !== '127.0.0.1') {
    throw new Error('Registry sync TLS proxy requires a 127.0.0.1 HTTP listener')
  }
  const server = new WebSocketServer({ noServer: true, maxPayload: config.maxFrameBytes, perMessageDeflate: false })
  const admission = new RegistrySyncAdmission(config.admission, undefined, ctx.get('registrySharedAdmission', false))
  const tasks = new Set<Promise<void>>()
  let closing: Promise<void> | undefined
  const unregister = webServer.registerUpgrade({ path: REGISTRY_SYNC_PATH, handler(req, socket, head) {
    if (signal.aborted || (typeof store !== 'function' && !store.active())
      || registryAuthenticatorTarget(ctx.get('registryProducerAuthenticator')) !== registryAuthenticatorTarget(provider)
      || req.url !== REGISTRY_SYNC_PATH || req.headers.origin !== undefined || tasks.size >= config.maxConnections) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
      return
    }
    let upgrade
    try { upgrade = admission.admitUpgrade() } catch {
      socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
      return
    }
    if (!upgrade.admitted) {
      socket.end(`HTTP/1.1 503 Service Unavailable\r\nRetry-After: ${String(upgrade.retryAfterSeconds)}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`)
      return
    }
    server.handleUpgrade(req, socket, head, (websocket) => {
      const connection = new RegistrySyncConnection(ctx, websocket, config, provider, store, signal, admission)
      const task = connection.run().catch(() => { ctx.logger.error('Registry sync identity cleanup failed') })
      tasks.add(task)
      void task.then(() => { tasks.delete(task) })
    })
  } })
  return () => {
    closing ??= (async () => {
      unregister()
      for (const socket of server.clients) socket.terminate()
      const closeError = await new Promise<Error | undefined>((resolve) => {
        server.close((error) => { resolve(error === undefined ? undefined : new Error('Registry sync listener close failed')) })
      })
      await Promise.all(tasks)
      if (closeError !== undefined) throw closeError
    })()
    return closing
  }
}
