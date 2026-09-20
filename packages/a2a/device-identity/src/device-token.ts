/** Canonical device-only credential material for Registry binding authentication. */
import { createHash, randomBytes } from 'node:crypto'
import { brandString, type Branded } from '@deepseek-ai/dsh-brand'
import type { OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'

const SECRET_BYTES = 32
const SECRET = /^[A-Za-z0-9_-]{43}$/u
const HASH = /^sha256:[0-9a-f]{64}$/u
const IDENTIFIER = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
const DEVICE_HASH_DOMAIN = Buffer.from('dsh:a2a:registry-device-secret:v1\0', 'utf8')
const BRIDGE_HASH_DOMAIN = Buffer.from('dsh:a2a:registry-disclosure-bridge-secret:v1\0', 'utf8')

/** Complete canonical token bound, applied before any token component is decoded. */
export const REGISTRY_DEVICE_TOKEN_MAX_BYTES = 512
export const REGISTRY_BRIDGE_TOKEN_MAX_BYTES = 512

/** SHA-256 commitment to a device-only 32-byte secret, never the enrollment code. */
export type RegistryDeviceSecretHash = Branded<'A2ARegistryDeviceSecretHash'>

/** SHA-256 commitment to a bridge-only 32-byte secret, never a device or enrollment secret. */
export type RegistryBridgeSecretHash = Branded<'A2ARegistryBridgeSecretHash'>

/** Decoded token routing data. Authentication still requires the device's Ed25519 proof. */
export interface RegistryDeviceTokenParts {
  readonly organizationId: OrganizationId
  readonly bindingId: string
  readonly secret: string
}

/** Decoded bridge credential routing data; selectors remain untrusted until Registry lookup. */
export interface RegistryBridgeTokenParts {
  readonly organizationId: OrganizationId
  readonly bindingId: string
  readonly secret: string
}

/** Fixed diagnostic which never includes credential input. */
export class RegistryDeviceTokenError extends Error {
  constructor() {
    super('invalid Registry device token')
    this.name = 'RegistryDeviceTokenError'
  }
}

/** Fixed diagnostic which never includes bridge credential input. */
export class RegistryBridgeTokenError extends Error {
  constructor() {
    super('invalid Registry disclosure bridge token')
    this.name = 'RegistryBridgeTokenError'
  }
}

function invalid(): never {
  throw new RegistryDeviceTokenError()
}

function invalidBridge(): never {
  throw new RegistryBridgeTokenError()
}

function secretBytes(secret: unknown, reject: () => never = invalid): Buffer {
  if (typeof secret !== 'string' || !SECRET.test(secret)) reject()
  const bytes = Buffer.from(secret, 'base64url')
  if (bytes.length !== SECRET_BYTES || bytes.toString('base64url') !== secret) reject()
  return bytes
}

function organizationId(value: unknown, reject: () => never = invalid): OrganizationId {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) reject()
  return brandString<OrganizationId>(value)
}

function bindingId(value: unknown, reject: () => never = invalid): string {
  if (typeof value !== 'string' || !UUID.test(value)) reject()
  return value
}

function hashSecret(domain: Buffer, secret: string, reject: () => never): string {
  const bytes = secretBytes(secret, reject)
  try { return `sha256:${createHash('sha256').update(domain).update(bytes).digest('hex')}` }
  finally { bytes.fill(0) }
}

/** Generate a canonical 256-bit secret which remains only in the Harness secret store. */
export function generateRegistryDeviceSecret(): string {
  return randomBytes(SECRET_BYTES).toString('base64url')
}

/** Commit to one canonical device secret with protocol domain separation. */
export function hashRegistryDeviceSecret(secret: string): RegistryDeviceSecretHash {
  return brandString<RegistryDeviceSecretHash>(hashSecret(DEVICE_HASH_DOMAIN, secret, invalid))
}

/** Generate an independent canonical 256-bit secret for HTTPS disclosure bridge operations. */
export function generateRegistryBridgeSecret(): string {
  return randomBytes(SECRET_BYTES).toString('base64url')
}

/** Commit to one canonical bridge secret with a domain that cannot collide with dsh1 authentication. */
export function hashRegistryBridgeSecret(secret: string): RegistryBridgeSecretHash {
  return brandString<RegistryBridgeSecretHash>(hashSecret(BRIDGE_HASH_DOMAIN, secret, invalidBridge))
}

/** Encode the device-only secret together with its untrusted tenant-routing selectors. */
export function encodeRegistryDeviceToken(parts: RegistryDeviceTokenParts): string {
  const selectedOrganization = organizationId(parts.organizationId)
  const selectedBinding = bindingId(parts.bindingId)
  secretBytes(parts.secret)
  const encodedOrganization = Buffer.from(selectedOrganization, 'utf8').toString('base64url')
  const token = `dsh1.${encodedOrganization}.${selectedBinding}.${parts.secret}`
  if (Buffer.byteLength(token, 'utf8') > REGISTRY_DEVICE_TOKEN_MAX_BYTES) invalid()
  return token
}

/** Strictly decode one canonical token; selectors remain untrusted until the binding owner checks them. */
export function decodeRegistryDeviceToken(token: unknown,
  maxBytes = REGISTRY_DEVICE_TOKEN_MAX_BYTES): RegistryDeviceTokenParts {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || typeof token !== 'string'
    || Buffer.byteLength(token, 'utf8') > Math.min(maxBytes, REGISTRY_DEVICE_TOKEN_MAX_BYTES)) invalid()
  const parts = token.split('.')
  if (parts.length !== 4 || parts[0] !== 'dsh1') invalid()
  const encodedOrganization = parts[1]
  if (encodedOrganization === undefined || !/^[A-Za-z0-9_-]+$/u.test(encodedOrganization)) invalid()
  const organizationBytes = Buffer.from(encodedOrganization, 'base64url')
  if (organizationBytes.length === 0 || organizationBytes.toString('base64url') !== encodedOrganization) invalid()
  const decodedOrganization = organizationBytes.toString('utf8')
  if (Buffer.from(decodedOrganization, 'utf8').toString('base64url') !== encodedOrganization) invalid()
  const result = {
    organizationId: organizationId(decodedOrganization),
    bindingId: bindingId(parts[2]),
    secret: parts[3] ?? invalid(),
  }
  secretBytes(result.secret)
  if (encodeRegistryDeviceToken(result) !== token) invalid()
  return Object.freeze(result)
}

/** Encode a bridge-only bearer; it is deliberately not accepted by the dsh1 WSS decoder. */
export function encodeRegistryBridgeToken(parts: RegistryBridgeTokenParts): string {
  const selectedOrganization = organizationId(parts.organizationId, invalidBridge)
  const selectedBinding = bindingId(parts.bindingId, invalidBridge)
  secretBytes(parts.secret, invalidBridge)
  const encodedOrganization = Buffer.from(selectedOrganization, 'utf8').toString('base64url')
  const token = `dshb1.${encodedOrganization}.${selectedBinding}.${parts.secret}`
  if (Buffer.byteLength(token, 'utf8') > REGISTRY_BRIDGE_TOKEN_MAX_BYTES) invalidBridge()
  return token
}

/** Strictly decode one canonical bridge token; authentication still requires current binding ownership. */
export function decodeRegistryBridgeToken(token: unknown,
  maxBytes = REGISTRY_BRIDGE_TOKEN_MAX_BYTES): RegistryBridgeTokenParts {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || typeof token !== 'string'
    || Buffer.byteLength(token, 'utf8') > Math.min(maxBytes, REGISTRY_BRIDGE_TOKEN_MAX_BYTES)) invalidBridge()
  const parts = token.split('.')
  if (parts.length !== 4 || parts[0] !== 'dshb1') invalidBridge()
  const encodedOrganization = parts[1]
  if (encodedOrganization === undefined || !/^[A-Za-z0-9_-]+$/u.test(encodedOrganization)) invalidBridge()
  const organizationBytes = Buffer.from(encodedOrganization, 'base64url')
  if (organizationBytes.length === 0 || organizationBytes.toString('base64url') !== encodedOrganization) invalidBridge()
  const decodedOrganization = organizationBytes.toString('utf8')
  if (Buffer.from(decodedOrganization, 'utf8').toString('base64url') !== encodedOrganization) invalidBridge()
  const result = {
    organizationId: organizationId(decodedOrganization, invalidBridge),
    bindingId: bindingId(parts[2], invalidBridge),
    secret: parts[3] ?? invalidBridge(),
  }
  secretBytes(result.secret, invalidBridge)
  if (encodeRegistryBridgeToken(result) !== token) invalidBridge()
  return Object.freeze(result)
}

/** Validate a persisted or received hash without accepting aliases. */
export function decodeRegistryDeviceSecretHash(value: unknown): RegistryDeviceSecretHash {
  if (typeof value !== 'string' || !HASH.test(value)) invalid()
  return brandString<RegistryDeviceSecretHash>(value)
}

/** Validate a persisted or received bridge hash without accepting device-secret hashes as the same type. */
export function decodeRegistryBridgeSecretHash(value: unknown): RegistryBridgeSecretHash {
  if (typeof value !== 'string' || !HASH.test(value)) invalidBridge()
  return brandString<RegistryBridgeSecretHash>(value)
}
