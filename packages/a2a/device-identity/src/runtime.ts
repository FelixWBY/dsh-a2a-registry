/** Narrow identity-provider definitions and device-challenge crypto; no default account or binding provider. */
import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto'
import { Context, Service } from '@deepseek-ai/cordis'
import { brandString } from '@deepseek-ai/dsh-brand'
import type { DisclosureSignature, DshInstanceId, OrganizationId } from '@deepseek-ai/dsh-a2a-protocol'
import { decodeInstanceKeyHistory, InstanceIdentityError } from './index.ts'
import type { InstanceKeyHistory, InstanceKeyId, InstanceVerificationContext } from './types.ts'
import type { LocalRegistryConnection, RegistryChallenge, RegistryChallengeAttempt, RegistryConnectionIdentity } from './runtime-types.ts'

export type * from './runtime-types.ts'

declare module '@deepseek-ai/cordis' {
  interface Context {
    localRegistryIdentity: LocalRegistryIdentity
    registryProducerAuthenticator: RegistryProducerAuthenticator
  }
}

/** External Local provider; credentials and bound private keys never come from browser request fields. */
export abstract class LocalRegistryIdentity extends Service {
  /** @param ctx - Provider-owned lifecycle context. */
  constructor(ctx: Context) { super(ctx, 'localRegistryIdentity') }
  /** Obtain credentials for an existing binding, never silently enroll or switch organization.
   * @param audience - Canonical WSS destination, fixed by trusted configuration.
   * @param binding - Explicit organization and source instance.
   * @param signal - Consumer cancellation; failure must release all partially acquired resources.
   * @returns A provider-owned connection credential handle. */
  abstract open(audience: string, binding: { organizationId: OrganizationId; instanceId: DshInstanceId },
    signal: AbortSignal): Promise<LocalRegistryConnection>
}

/** External Registry provider; token verification and current organization membership belong here. */
export abstract class RegistryProducerAuthenticator extends Service {
  /** @param ctx - Provider-owned lifecycle context. */
  constructor(ctx: Context) { super(ctx, 'registryProducerAuthenticator') }
  /** Validate the token and create one bounded, one-shot device challenge.
   * @param token - Untrusted short-lived bearer token from the bounded hello frame.
   * @param audience - Trusted canonical WSS destination, never selected by request headers.
   * @param signal - Consumer cancellation; failure must release all partially acquired resources.
   * @returns An attempt owning its nonce and completion; no business authority before completion. */
  abstract begin(token: string, audience: string, signal: AbortSignal): Promise<RegistryChallengeAttempt>
}

function requireIdentity(condition: boolean): asserts condition {
  if (!condition) throw new InstanceIdentityError('invalid Registry connection identity or challenge')
}

function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  requireIdentity(typeof input === 'object' && input !== null && !Array.isArray(input))
  const value = input as Record<string, unknown>
  requireIdentity(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)))
  return value
}

function identifier(value: unknown): string {
  requireIdentity(typeof value === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/.test(value))
  return value
}

function integer(value: unknown): number {
  requireIdentity(Number.isSafeInteger(value) && (value as number) >= 0 && !Object.is(value, -0))
  return value as number
}

function bytes(value: unknown, length: number): string {
  requireIdentity(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value))
  const decoded = Buffer.from(value, 'base64url')
  requireIdentity(decoded.length === length && decoded.toString('base64url') === value)
  return value
}

/** Decode the canonical WSS audience without credentials, query or fragment.
 * @param input - Untrusted destination value.
 * @returns Exact canonical URL, not a normalized alias.
 * @throws InstanceIdentityError for unsupported or noncanonical destinations. */
export function decodeRegistryAudience(input: unknown): string {
  requireIdentity(typeof input === 'string')
  let url: URL
  try { url = new URL(input) } catch {
    // URL diagnostics can contain caller data; report only the identity category.
    throw new InstanceIdentityError('invalid Registry audience')
  }
  requireIdentity(url.protocol === 'wss:' && url.href === input && url.username === '' && url.password === ''
    && url.search === '' && url.hash === '')
  return input
}

/** Decode a fixed connection identity; this validates syntax, not authentication.
 * @param input - Parsed JSON with exactly the three identity fields.
 * @returns Detached canonical identifiers. */
export function decodeRegistryConnectionIdentity(input: unknown): RegistryConnectionIdentity {
  const value = exact(input, ['organizationId', 'instanceId', 'keyId'])
  requireIdentity(typeof value.keyId === 'string' && /^sha256:[0-9a-f]{64}$/.test(value.keyId))
  return { organizationId: brandString<OrganizationId>(identifier(value.organizationId)),
    instanceId: brandString<DshInstanceId>(identifier(value.instanceId)), keyId: brandString<InstanceKeyId>(value.keyId) }
}

/** Decode a 64-byte Ed25519 proof without verifying ownership.
 * @param input - Untrusted canonical base64url signature.
 * @returns Branded signature bytes. */
export function decodeRegistryProof(input: unknown): DisclosureSignature {
  return brandString<DisclosureSignature>(bytes(input, 64))
}

/** Decode a challenge with exact fields; byte bounds and one-shot lifetime belong to the transport/provider.
 * @param input - Untrusted parsed JSON.
 * @returns Detached challenge; no token or identity is authenticated by decoding. */
export function decodeRegistryChallenge(input: unknown): RegistryChallenge {
  const value = exact(input, ['version', 'audience', 'organizationId', 'instanceId', 'keyId', 'nonce', 'expiresAt'])
  requireIdentity(value.version === 1)
  const identity = decodeRegistryConnectionIdentity({
    organizationId: value.organizationId, instanceId: value.instanceId, keyId: value.keyId,
  })
  return { version: 1, audience: decodeRegistryAudience(value.audience), ...identity,
    nonce: bytes(value.nonce, 32), expiresAt: integer(value.expiresAt) }
}

function challengeBytes(value: RegistryChallenge): Buffer {
  return Buffer.from(JSON.stringify(['dsh:a2a:registry-device-proof', value.version, value.audience,
    value.organizationId, value.instanceId, value.keyId, value.nonce, value.expiresAt]), 'utf8')
}

/** Sign the domain-separated challenge tuple, never a disclosure event commitment.
 * @param challenge - Challenge already matched to the Local handle's audience, binding and clock.
 * @param privateKey - Matching Ed25519 private key held by the Local provider.
 * @returns Canonical Ed25519 signature; no nonce is consumed or persisted. */
export function signRegistryChallenge(challenge: RegistryChallenge, privateKey: KeyObject): DisclosureSignature {
  const value = decodeRegistryChallenge(challenge)
  requireIdentity(privateKey.type === 'private' && privateKey.asymmetricKeyType === 'ed25519')
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  requireIdentity(value.keyId === `sha256:${createHash('sha256').update(spki).digest('hex')}`)
  return brandString<DisclosureSignature>(sign(null, challengeBytes(value), privateKey).toString('base64url'))
}

/** Verify proof against the Registry-owned attempt, current clock and authenticated key history.
 * @param challenge - Challenge issued by this connection's attempt.
 * @param proof - Untrusted signature.
 * @param history - Registry-owned current key history, never sender-supplied authority.
 * @param context - Current identity and receive time, checked inside the provider's authorization lease.
 * @param expected - Audience and nonce retained by that exact attempt.
 * @returns Detached verified challenge; the provider still must atomically consume it once. */
export function verifyRegistryChallenge(challenge: unknown, proof: unknown, history: InstanceKeyHistory,
  context: InstanceVerificationContext, expected: { audience: string; nonce: string }): RegistryChallenge {
  const value = decodeRegistryChallenge(challenge)
  const current = decodeInstanceKeyHistory(history)
  const signature = decodeRegistryProof(proof)
  requireIdentity(value.audience === expected.audience && value.nonce === expected.nonce
    && value.organizationId === context.organizationId && value.instanceId === context.instanceId && value.keyId === context.keyId
    && current.organizationId === context.organizationId && current.instanceId === context.instanceId && current.status === 'active')
  const now = integer(context.now)
  const key = current.keys.find(candidate => candidate.keyId === context.keyId)
  requireIdentity(now < value.expiresAt && key !== undefined && key.revokedAt === null && now >= key.validFrom
    && (key.validUntil === null || now < key.validUntil))
  const publicKey = createPublicKey({ key: Buffer.from(key.publicKeySpki, 'base64url'), format: 'der', type: 'spki' })
  requireIdentity(verify(null, challengeBytes(value), publicKey, Buffer.from(signature, 'base64url')))
  return value
}
