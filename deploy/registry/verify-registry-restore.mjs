#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, closeSync, existsSync, lstatSync, openSync, readFileSync, renameSync, rmSync,
  mkdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'

const FORMAT = 'dsh-registry-restore-expectation'
const VERSION = 1
const MAX_BODY_BYTES = 4 * 1024 * 1024
const MAX_EXPECTATION_BYTES = 4 * 1024 * 1024
const MAX_PAGES = 40
const MAX_ITEMS = 2_000
const CONTENT_SAMPLES = 20
const AUDIT_SAMPLES = 10

function fail(message) {
  throw new Error(`registry-restore-verification: ${message}`)
}

function absolutePath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`)
  }
  return value
}

function origin(value) {
  let parsed
  try { parsed = new URL(value) } catch { fail('origin is not a URL') }
  const loopback = parsed.protocol === 'http:' && (parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]')
  if ((!loopback && parsed.protocol !== 'https:') || parsed.username !== '' || parsed.password !== ''
    || parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== '' || parsed.origin !== value) {
    fail('origin must be a canonical HTTPS origin or an HTTP loopback origin')
  }
  return parsed.origin
}

function object(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`)
  return value
}

const cookie = process.env.DSH_REGISTRY_RESTORE_COOKIE
delete process.env.DSH_REGISTRY_RESTORE_COOKIE
if (cookie !== undefined && (cookie.length === 0 || cookie.length > 8_192 || /[\r\n]/u.test(cookie))) {
  fail('DSH_REGISTRY_RESTORE_COOKIE is invalid')
}

async function responseBody(response) {
  const declared = response.headers.get('content-length')
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_BODY_BYTES)) fail('response is oversized')
  const reader = response.body?.getReader()
  if (reader === undefined) fail('response body is unavailable')
  const chunks = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > MAX_BODY_BYTES) { await reader.cancel(); fail('response is oversized') }
    chunks.push(value)
  }
  return Buffer.concat(chunks, total).toString('utf8')
}

async function api(selectedOrigin, path) {
  const response = await fetch(`${selectedOrigin}/registry-api/v1${path}`, {
    headers: { accept: 'application/json', ...(cookie === undefined ? {} : { cookie }) },
    cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10_000),
  })
  const type = response.headers.get('content-type') ?? ''
  if (!type.toLowerCase().startsWith('application/json')) fail(`${path} did not return JSON`)
  let envelope
  try { envelope = JSON.parse(await responseBody(response)) } catch (error) {
    if (error instanceof Error && error.message.startsWith('registry-restore-verification:')) throw error
    fail(`${path} returned invalid JSON`)
  }
  const parsed = object(envelope, `${path} envelope`)
  if (!response.ok || parsed.ok !== true || !Object.hasOwn(parsed, 'value')) fail(`${path} was not authorized and successful`)
  return parsed.value
}

async function pages(selectedOrigin, path) {
  const items = []
  let cursor
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const query = cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`
    const value = object(await api(selectedOrigin, `${path}${query}`), `${path} page`)
    if (!Array.isArray(value.items) || !(value.nextCursor === null || typeof value.nextCursor === 'string')) {
      fail(`${path} returned an invalid page`)
    }
    items.push(...value.items)
    if (items.length > MAX_ITEMS) fail(`${path} exceeded the verification item limit`)
    if (value.nextCursor === null) return items
    if (value.nextCursor.length === 0 || value.nextCursor === cursor) fail(`${path} returned an invalid cursor`)
    cursor = value.nextCursor
  }
  fail(`${path} exceeded the verification page limit`)
}

function digest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex')
}

function disclosure(value) {
  const item = object(value, 'disclosure metadata')
  const checkpoint = object(item.checkpoint, 'disclosure checkpoint')
  if (typeof item.disclosureId !== 'string' || typeof item.instanceId !== 'string'
    || typeof checkpoint.checkpointHash !== 'string' || !Array.isArray(item.authorizedActions)) {
    fail('disclosure metadata is invalid')
  }
  return {
    disclosureId: item.disclosureId, instanceId: item.instanceId, control: item.control, producer: item.producer,
    ingest: item.ingest, expiresAt: item.expiresAt, authorizationVersion: item.authorizationVersion,
    checkpointVerifiedAt: item.checkpointVerifiedAt, authorizedActions: [...item.authorizedActions],
    checkpoint: { checkpointHash: checkpoint.checkpointHash, policyVersion: checkpoint.policyVersion,
      sourceCursor: checkpoint.sourceCursor, eventCount: checkpoint.eventCount,
      lastDisclosureSeq: checkpoint.lastDisclosureSeq, lastEventHash: checkpoint.lastEventHash },
  }
}

function instance(value) {
  const item = object(value, 'instance metadata')
  if (typeof item.bindingId !== 'string' || typeof item.instanceId !== 'string'
    || typeof item.instanceName !== 'string' || !Array.isArray(item.requestedScopes)) fail('instance metadata is invalid')
  return { bindingId: item.bindingId, instanceId: item.instanceId, instanceName: item.instanceName,
    phase: item.phase, requestedScopes: [...item.requestedScopes] }
}

function sorted(values, field) {
  return values.sort((left, right) => String(left[field]).localeCompare(String(right[field]), 'en'))
}

async function snapshot(selectedOrigin) {
  const status = object(await api(selectedOrigin, '/status'), 'runtime status')
  const directory = object(await api(selectedOrigin, '/directory'), 'directory')
  const instancesValue = object(await api(selectedOrigin, '/instances'), 'instances')
  if (!Array.isArray(instancesValue.items)) fail('instances result is invalid')
  const disclosures = sorted((await pages(selectedOrigin, '/disclosures')).map(disclosure), 'disclosureId')
  const contents = []
  for (const item of disclosures.filter(value => value.authorizedActions.includes('read')).slice(0, CONTENT_SAMPLES)) {
    const content = object(await api(selectedOrigin,
      `/disclosures/${encodeURIComponent(item.disclosureId)}/content?checkpoint=${encodeURIComponent(item.checkpoint.checkpointHash)}`),
    'disclosure content')
    if (content.checkpointHash !== item.checkpoint.checkpointHash || !Array.isArray(content.events)) {
      fail('disclosure content does not match its fixed checkpoint')
    }
    contents.push({ disclosureId: item.disclosureId, checkpointHash: item.checkpoint.checkpointHash,
      eventCount: content.events.length, sha256: digest(content.events) })
  }
  const auditPage = object(await api(selectedOrigin, '/audit'), 'audit page')
  if (!Array.isArray(auditPage.items)) fail('audit result is invalid')
  const auditSample = auditPage.items.slice(0, AUDIT_SAMPLES).map(value => {
    const item = object(value, 'audit metadata')
    if (typeof item.operationId !== 'string') fail('audit metadata is invalid')
    return item.operationId
  })
  return {
    status,
    directory,
    instances: sorted(instancesValue.items.map(instance), 'bindingId'),
    disclosures,
    contents: sorted(contents, 'disclosureId'),
    auditSample,
  }
}

function writeExpectation(path, selectedOrigin, state) {
  if (existsSync(path)) fail('expectation file already exists')
  const document = `${JSON.stringify({ format: FORMAT, version: VERSION, capturedAt: new Date().toISOString(),
    sourceOrigin: selectedOrigin, state }, undefined, 2)}\n`
  if (Buffer.byteLength(document, 'utf8') > MAX_EXPECTATION_BYTES) fail('expectation file would exceed the size limit')
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const partial = `${path}.partial-${randomUUID()}`
  closeSync(openSync(partial, 'wx', 0o600))
  try {
    writeFileSync(partial, document, { encoding: 'utf8' })
    chmodSync(partial, 0o600)
    renameSync(partial, path)
  } catch (error) {
    rmSync(partial, { force: true })
    throw error
  }
}

function readExpectation(path) {
  if (!existsSync(path)) fail('expectation file does not exist')
  const info = lstatSync(path)
  if (!info.isFile() || info.isSymbolicLink() || statSync(path).size > MAX_EXPECTATION_BYTES) {
    fail('expectation file is invalid')
  }
  let document
  try { document = JSON.parse(readFileSync(path, 'utf8')) } catch { fail('expectation file is invalid JSON') }
  const parsed = object(document, 'expectation')
  if (parsed.format !== FORMAT || parsed.version !== VERSION || Number.isNaN(Date.parse(parsed.capturedAt))) {
    fail('expectation header is invalid')
  }
  return object(parsed.state, 'expectation state')
}

function equal(left, right, label) {
  if (JSON.stringify(left) !== JSON.stringify(right)) fail(`${label} differs from the captured Registry state`)
}

const [command, originInput, expectationInput, ...rest] = process.argv.slice(2)
if ((command !== 'capture' && command !== 'verify') || originInput === undefined
  || expectationInput === undefined || rest.length !== 0) {
  fail('usage: node verify-registry-restore.mjs <capture|verify> <origin> <absolute-expectation-file>')
}
const selectedOrigin = origin(originInput)
const expectation = absolutePath(expectationInput, 'expectation file')
if (command === 'capture') {
  const state = await snapshot(selectedOrigin)
  writeExpectation(expectation, selectedOrigin, state)
  process.stdout.write(`${JSON.stringify({ captured: true, expectation, disclosures: state.disclosures.length,
    contentSamples: state.contents.length, instances: state.instances.length,
    auditSamples: state.auditSample.length })}\n`)
} else {
  const expected = readExpectation(expectation)
  const actual = await snapshot(selectedOrigin)
  equal(actual.status, expected.status, 'runtime configuration')
  equal(actual.directory, expected.directory, 'organization directory')
  equal(actual.instances, expected.instances, 'durable instance bindings')
  equal(actual.disclosures, expected.disclosures, 'authorized disclosure metadata')
  equal(actual.contents, expected.contents, 'fixed-checkpoint content digests')
  const auditPage = object(await api(selectedOrigin, '/audit'), 'audit page')
  if (!Array.isArray(auditPage.items)) fail('audit result is invalid')
  const actualAudit = new Set(auditPage.items.map(value => object(value, 'audit metadata').operationId))
  if (!Array.isArray(expected.auditSample) || expected.auditSample.some(value => !actualAudit.has(value))) {
    fail('captured audit records were not found after restore')
  }
  process.stdout.write(`${JSON.stringify({ verified: true, origin: selectedOrigin,
    disclosures: actual.disclosures.length, contentSamples: actual.contents.length,
    instances: actual.instances.length, preservedAuditSamples: expected.auditSample.length })}\n`)
}
