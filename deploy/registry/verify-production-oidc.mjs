#!/usr/bin/env node
import { randomBytes } from 'node:crypto'
import { realpathSync } from 'node:fs'
import { isIP } from 'node:net'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const DEFAULT_TIMEOUT_MS = 10_000
const MAX_DISCOVERY_BYTES = 64 * 1024
const MAX_INTROSPECTION_BYTES = 8 * 1024
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*charset=utf-8)?$/iu

class UsageFailure extends Error {}
class VerificationFailure extends Error {}

function usage() {
  return [
    '用法：',
    '  node deploy/registry/verify-production-oidc.mjs --issuer <URL> --client-id <ID> --client-secret-env <环境变量名>',
    '  本地回环 mock 可额外使用 --allow-loopback-http；生产验收禁止使用该参数。',
  ].join('\n')
}

function fail(message) {
  throw new VerificationFailure(message)
}

function checkNodeRuntime() {
  const [major = 0] = process.versions.node.split('.').map(Number)
  if (major < 24) fail('需要 Node.js 24 或更高版本。')
}

export function parseProductionOidcArguments(argv) {
  const selected = new Map()
  let allowLoopbackHttp = false
  for (let index = 0; index < argv.length;) {
    const name = argv[index]
    if (name === '--allow-loopback-http') {
      if (allowLoopbackHttp) throw new UsageFailure()
      allowLoopbackHttp = true
      index += 1
      continue
    }
    if (!['--issuer', '--client-id', '--client-secret-env'].includes(name)
      || index + 1 >= argv.length || selected.has(name)) throw new UsageFailure()
    const value = argv[index + 1]
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) throw new UsageFailure()
    selected.set(name, value)
    index += 2
  }
  if (selected.size !== 3) throw new UsageFailure()
  return Object.freeze({
    issuer: selected.get('--issuer'),
    clientId: selected.get('--client-id'),
    clientSecretEnv: selected.get('--client-secret-env'),
    allowLoopbackHttp,
  })
}

function loopbackHostname(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/gu, '')
  if (normalized === 'localhost') return true
  const family = isIP(normalized)
  return family === 4 ? normalized.startsWith('127.') : family === 6 && normalized === '::1'
}

function hasUserInfo(value) {
  const scheme = value.indexOf('://')
  if (scheme < 0) return false
  const remainder = value.slice(scheme + 3)
  const end = remainder.search(/[/?#]/u)
  const authority = end < 0 ? remainder : remainder.slice(0, end)
  return authority.includes('@')
}

function secureUrl(value, label, { allowLoopbackHttp, issuer = false }) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096
    || value.trim() !== value || !value.isWellFormed()) fail(`${label} 无效。`)
  let parsed
  try { parsed = new URL(value) } catch { fail(`${label} 必须是绝对 URL。`) }
  if (hasUserInfo(value) || parsed.username !== '' || parsed.password !== ''
    || value.includes('#') || parsed.hash !== '') fail(`${label} 不能包含用户信息或片段。`)
  if (issuer && (value.includes('?') || parsed.search !== '')) fail('OIDC issuer 不能包含查询或片段。')
  if (parsed.protocol === 'https:') return parsed
  if (parsed.protocol === 'http:' && allowLoopbackHttp && loopbackHostname(parsed.hostname)) return parsed
  fail(`${label} 必须使用 HTTPS；只有显式本地验收可使用回环 HTTP。`)
}

function requiredStringArray(metadata, name, required) {
  const present = Object.prototype.hasOwnProperty.call(metadata, name)
  if (!present && !required) return undefined
  const value = metadata[name]
  if (!Array.isArray(value) || value.some(entry => typeof entry !== 'string')) {
    fail(`发现文档 ${name} 无效。`)
  }
  return value
}

export function validateProductionOidcDiscovery(metadata, options) {
  if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata)) {
    fail('发现文档必须是 JSON 对象。')
  }
  if (metadata.issuer !== options.issuer) fail('发现文档 issuer 与命令行 issuer 不精确匹配。')

  for (const [name, label] of [
    ['authorization_endpoint', 'authorization endpoint'],
    ['token_endpoint', 'token endpoint'],
    ['introspection_endpoint', 'introspection endpoint'],
    ['jwks_uri', 'JWKS endpoint'],
  ]) {
    secureUrl(metadata[name], label, { allowLoopbackHttp: options.allowLoopbackHttp })
  }

  const responseTypes = requiredStringArray(metadata, 'response_types_supported', true)
  if (!responseTypes.includes('code')) fail('发现文档必须支持 response_type=code。')
  const grantTypes = requiredStringArray(metadata, 'grant_types_supported', false)
  if (grantTypes !== undefined && !grantTypes.includes('authorization_code')) {
    fail('发现文档存在 grant_types_supported 时必须包含 authorization_code。')
  }
  const scopes = requiredStringArray(metadata, 'scopes_supported', false)
  if (scopes !== undefined && !scopes.includes('openid')) {
    fail('发现文档存在 scopes_supported 时必须包含 openid。')
  }
  const challengeMethods = requiredStringArray(metadata, 'code_challenge_methods_supported', true)
  if (!challengeMethods.includes('S256')) fail('发现文档必须支持 PKCE S256。')
  return metadata
}

async function discard(response) {
  try { await response.body?.cancel() } catch {}
}

async function boundedUtf8(response, maximumBytes, label) {
  const declared = response.headers.get('content-length')
  if (declared !== null && (!/^(0|[1-9]\d*)$/u.test(declared) || Number(declared) > maximumBytes)) {
    await discard(response)
    fail(`${label} 超过大小限制。`)
  }
  const reader = response.body?.getReader()
  if (reader === undefined) fail(`${label} 缺少响应正文。`)
  const chunks = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maximumBytes) {
      await reader.cancel().catch(() => {})
      fail(`${label} 超过大小限制。`)
    }
    chunks.push(Buffer.from(value))
  }
  try { return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total)) } catch {
    fail(`${label} 不是有效 UTF-8。`)
  }
}

async function fetchJsonText(fetchImpl, url, init, maximumBytes, timeoutMs, label) {
  let response
  try {
    response = await fetchImpl(url, {
      ...init,
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch {
    fail(`${label} 请求失败或超时。`)
  }
  if (response.status !== 200) {
    await discard(response)
    fail(`${label} 必须返回 HTTP 200。`)
  }
  const contentType = response.headers.get('content-type') ?? ''
  if (!JSON_CONTENT_TYPE.test(contentType)) {
    await discard(response)
    fail(`${label} 必须返回 application/json。`)
  }
  return boundedUtf8(response, maximumBytes, label)
}

function parseJsonObject(text, label) {
  let parsed
  try { parsed = JSON.parse(text) } catch { fail(`${label} 不是有效 JSON。`) }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) fail(`${label} 必须是 JSON 对象。`)
  return parsed
}

function discoveryUrl(issuer) {
  return new URL(`${issuer}${issuer.endsWith('/') ? '' : '/'}.well-known/openid-configuration`)
}

function clientSecret(environment, name) {
  if (!ENVIRONMENT_NAME.test(name)) fail('--client-secret-env 不是有效环境变量名。')
  const value = environment[name]
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value
    || Buffer.byteLength(value, 'utf8') < 16 || Buffer.byteLength(value, 'utf8') > 4096) {
    fail('指定环境变量中的 OIDC client secret 缺失或无效。')
  }
  return value
}

function validateClientId(value) {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value
    || !value.isWellFormed() || /[\u0000-\u001f\u007f]/u.test(value)
    || Buffer.byteLength(value, 'utf8') > 256) fail('--client-id 无效。')
}

function validateExactInactiveIntrospection(text) {
  const value = parseJsonObject(text, 'Introspection 响应')
  if (!/^\s*\{\s*"active"\s*:\s*false\s*\}\s*$/u.test(text)
    || Object.keys(value).length !== 1 || value.active !== false) {
    fail('随机不存在 token 的 Introspection 响应必须精确为 {"active":false}。')
  }
}

export async function verifyProductionOidc({
  issuer,
  clientId,
  clientSecretEnv,
  allowLoopbackHttp = false,
  environment = process.env,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  validateClientId(clientId)
  if (!ENVIRONMENT_NAME.test(clientSecretEnv)) fail('--client-secret-env 不是有效环境变量名。')
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) fail('请求超时配置无效。')
  const issuerUrl = secureUrl(issuer, 'OIDC issuer', { allowLoopbackHttp, issuer: true })
  if (allowLoopbackHttp && !loopbackHostname(issuerUrl.hostname)) {
    fail('--allow-loopback-http 只能用于本地回环 issuer。')
  }

  const discoveryText = await fetchJsonText(fetchImpl, discoveryUrl(issuer), {
    method: 'GET',
    headers: { accept: 'application/json' },
    cache: 'no-store',
  }, MAX_DISCOVERY_BYTES, timeoutMs, 'OIDC 发现文档')
  const metadata = validateProductionOidcDiscovery(parseJsonObject(discoveryText, 'OIDC 发现文档'), {
    issuer,
    allowLoopbackHttp,
  })

  const secret = clientSecret(environment, clientSecretEnv)
  const probeToken = `dsh-oidc-conformance-${randomBytes(32).toString('base64url')}`
  const body = new URLSearchParams({
    token: probeToken,
    token_type_hint: 'access_token',
    client_id: clientId,
    client_secret: secret,
  }).toString()
  const introspectionText = await fetchJsonText(fetchImpl, metadata.introspection_endpoint, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
    },
    body,
    cache: 'no-store',
  }, MAX_INTROSPECTION_BYTES, timeoutMs, 'OIDC Token Introspection')
  validateExactInactiveIntrospection(introspectionText)
}

async function main() {
  try {
    checkNodeRuntime()
    const options = parseProductionOidcArguments(process.argv.slice(2))
    await verifyProductionOidc(options)
    process.stdout.write([
      'registry-production-oidc: 验收通过。',
      '- 发现文档、Authorization Code、PKCE S256 与必需端点符合生产门禁。',
      '- 随机不存在 token 的最小非活动响应符合失败关闭契约。',
      '- client secret 只从指定环境变量读取，值未输出。',
      '- 本检查未执行用户登录，也未申请或读取真实 token。',
      '',
    ].join('\n'))
  } catch (error) {
    if (error instanceof UsageFailure) {
      process.stderr.write(`${usage()}\n`)
      process.exitCode = 2
      return
    }
    const message = error instanceof VerificationFailure ? error.message : '发生未公开细节的内部错误。'
    process.stderr.write(`registry-production-oidc: 验收失败：${message}\n`)
    process.exitCode = 1
  }
}

const invoked = process.argv[1]
if (invoked !== undefined
  && realpathSync.native(resolve(invoked)) === realpathSync.native(fileURLToPath(import.meta.url))) await main()
