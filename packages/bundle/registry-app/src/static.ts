/** Public Registry shell serving over a fixed, application-resolved frontend artifact. */
import { access, readFile } from 'node:fs/promises'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { serveStatic } from '@deepseek-ai/dsh-host-frontend-static'
import type {} from '@deepseek-ai/dsh-host-webserver'

class RegistryConfigurationUnavailable extends Error {}

const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "base-uri 'self'",
  "connect-src 'self'",
  "font-src 'self' data:",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "img-src 'self' data:",
  "manifest-src 'none'",
  "object-src 'none'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "worker-src 'self' blob:",
].join('; ')

const REGISTRY_FAVICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none">'
  + '<g stroke="#4388ff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
  + '<path d="M16 8v5M16 19v5M8 16h5M19 16h5"/>'
  + '<circle cx="16" cy="16" r="3.5"/><circle cx="16" cy="5" r="2.5"/>'
  + '<circle cx="16" cy="27" r="2.5"/><circle cx="5" cy="16" r="2.5"/><circle cx="27" cy="16" r="2.5"/>'
  + '</g></svg>'

function setPublicSecurityHeaders(res: ServerResponse): void {
  res.setHeader('content-security-policy', CONTENT_SECURITY_POLICY)
  res.setHeader('cross-origin-opener-policy', 'same-origin')
  res.setHeader('cross-origin-resource-policy', 'same-origin')
  res.setHeader('permissions-policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=()')
  res.setHeader('referrer-policy', 'no-referrer')
  res.setHeader('x-content-type-options', 'nosniff')
  res.setHeader('x-frame-options', 'DENY')
}

function writeProbe(req: IncomingMessage, res: ServerResponse, ready: boolean): void {
  setPublicSecurityHeaders(res)
  res.setHeader('cache-control', 'no-store')
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { allow: 'GET, HEAD' })
    res.end()
    return
  }
  const text = ready ? 'ok\n' : 'not-ready\n'
  res.setHeader('content-type', 'text/plain; charset=utf-8')
  res.setHeader('content-length', Buffer.byteLength(text))
  res.writeHead(ready ? 200 : 503)
  res.end(req.method === 'HEAD' ? undefined : text)
}

/** Install one public fallback restricted to the shipped shell and Vite assets.
 * @param ctx - Owning plugin context with the HTTP service.
 * @param distIndex - Trusted package-resolved index file, never a request or deployment path.
 * @param available - Whether the required public browser configuration is currently contributed.
 * @param runtimeReady - Bounded live dependency check; failures remain readiness failures.
 */
export function installRegistryStatic(ctx: Context, distIndex: string, available: () => boolean,
  runtimeReady: () => boolean | Promise<boolean> = available): void {
  const distRoot = dirname(distIndex)
  const ready = async (): Promise<boolean> => {
    if (!available()) return false
    try { await access(distIndex) } catch { return false }
    if (!available()) return false
    try {
      if (!await runtimeReady()) return false
    } catch { return false }
    return available()
  }
  const render = async (): Promise<string> => {
    const html = await readFile(distIndex, 'utf8')
    // A graph target can disappear while the artifact read is pending.
    if (!available()) throw new RegistryConfigurationUnavailable('Registry browser configuration unavailable')
    return ctx.webServer.renderIndex(html)
      .replace(/<title>[^<]*<\/title>/i, '<title>DSH Registry</title>')
      .replace(/<link\b[^>]*\brel="manifest"[^>]*>/gi, '')
      .replace(/<head(?:\s[^>]*)?>/i, open => `${open}<base href="/"><link rel="icon" type="image/svg+xml" href="/favicon.svg">`)
  }
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact', path: '/healthz', handler: (req, res) => { writeProbe(req, res, true) },
  }), 'registry-app: liveness probe')
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact', path: '/readyz', handler: async (req, res) => { writeProbe(req, res, await ready()) },
  }), 'registry-app: browser-shell readiness probe')
  ctx.effect(() => ctx.webServer.registerFallback(async (req, res) => {
    setPublicSecurityHeaders(res)
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' })
      res.end()
      return
    }
    /* v8 ignore next -- node:http assigns url on every incoming request. */
    const path = decodeURIComponent(new URL(req.url ?? '/', 'http://registry.invalid').pathname)
    const shell = path === '/' || path === '/index.html'
    if (!shell && path !== '/favicon.svg'
      && !/^\/assets\/[A-Za-z0-9_.-]+\.(?:js|css|svg|png|jpe?g|webp|woff2?)$/u.test(path)) {
      res.writeHead(404)
      res.end()
      return
    }
    if (path === '/favicon.svg') {
      res.setHeader('cache-control', 'public, max-age=86400')
      res.setHeader('content-type', 'image/svg+xml')
      res.setHeader('content-length', Buffer.byteLength(REGISTRY_FAVICON))
      res.writeHead(200)
      res.end(req.method === 'HEAD' ? undefined : REGISTRY_FAVICON)
      return
    }
    if (shell) {
      res.setHeader('cache-control', 'no-store')
      if (!available()) {
        res.writeHead(503)
        res.end()
        return
      }
    }
    // The public document contains code and unconfigured UI, not account or disclosure data.
    try {
      await serveStatic(path, res, distRoot, distIndex, () => true, render)
    } catch (error) {
      if (!(error instanceof RegistryConfigurationUnavailable)) throw error
      res.writeHead(503)
      res.end()
    }
  }), 'registry-app: public static fallback')
}
