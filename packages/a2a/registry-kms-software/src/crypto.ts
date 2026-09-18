/** AES-256-GCM wrapping primitives with exact, versioned associated data. */
import { createCipheriv, createDecipheriv, type KeyObject, randomBytes } from 'node:crypto'
import { SoftwareLocalKmsError, type SoftwareLocalWrappedKey } from './types.ts'

const KEY_BYTES = 32
const NONCE_BYTES = 12
const TAG_BYTES = 16

function requireKms(condition: unknown, code: ConstructorParameters<typeof SoftwareLocalKmsError>[0]): asserts condition {
  if (!condition) throw new SoftwareLocalKmsError(code)
}

function decodeCanonical(value: unknown, exactBytes: number): Buffer {
  requireKms(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), 'invalid-storage')
  const bytes = Buffer.from(value, 'base64url')
  requireKms(bytes.byteLength === exactBytes && bytes.toString('base64url') === value, 'invalid-storage')
  return bytes
}

/** Validate a Node secret-key handle without exporting its material. */
export function requireAes256Key(key: unknown, code: 'invalid-root-key' | 'invalid-input'): asserts key is KeyObject {
  requireKms(typeof key === 'object' && key !== null
    && (key as KeyObject).type === 'secret' && (key as KeyObject).symmetricKeySize === KEY_BYTES, code)
}

/** Wrap exactly one 256-bit key under an already validated 256-bit KEK. */
export function wrapKey(kek: KeyObject, material: Buffer, aad: Buffer): SoftwareLocalWrappedKey {
  requireKms(material.byteLength === KEY_BYTES, 'invalid-input')
  try {
    const nonce = randomBytes(NONCE_BYTES)
    const cipher = createCipheriv('aes-256-gcm', kek, nonce, { authTagLength: TAG_BYTES })
    cipher.setAAD(aad)
    const ciphertext = Buffer.concat([cipher.update(material), cipher.final()])
    return Object.freeze({
      version: 1,
      algorithm: 'A256GCM',
      nonce: nonce.toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url'),
    })
  } catch {
    throw new SoftwareLocalKmsError('unavailable')
  }
}

/** Authenticate and unwrap exactly one 256-bit key; OpenSSL diagnostics never cross this boundary. */
export function unwrapKey(kek: KeyObject, envelope: SoftwareLocalWrappedKey, aad: Buffer): Buffer {
  requireKms(envelope.version === 1 && envelope.algorithm === 'A256GCM', 'invalid-storage')
  const nonce = decodeCanonical(envelope.nonce, NONCE_BYTES)
  const ciphertext = decodeCanonical(envelope.ciphertext, KEY_BYTES)
  const tag = decodeCanonical(envelope.tag, TAG_BYTES)
  let partial: Buffer | undefined
  let tail: Buffer | undefined
  try {
    const decipher = createDecipheriv('aes-256-gcm', kek, nonce, { authTagLength: TAG_BYTES })
    decipher.setAAD(aad)
    decipher.setAuthTag(tag)
    // GCM releases update output before final() authenticates the tag; keep and wipe that unauthenticated plaintext.
    partial = decipher.update(ciphertext)
    tail = decipher.final()
    const material = Buffer.concat([partial, tail])
    partial.fill(0)
    tail.fill(0)
    partial = undefined
    tail = undefined
    if (material.byteLength !== KEY_BYTES) {
      material.fill(0)
      throw new SoftwareLocalKmsError('authentication-failed')
    }
    return material
  } catch {
    partial?.fill(0)
    tail?.fill(0)
    throw new SoftwareLocalKmsError('authentication-failed')
  } finally {
    nonce.fill(0)
    ciphertext.fill(0)
    tag.fill(0)
  }
}
