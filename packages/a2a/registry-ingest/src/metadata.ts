/** Shared prefix authorization and body-free projection; opaque page anchors carry no access authority. */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { brandString } from '@deepseek-ai/dsh-brand'
import { verifyDisclosureCheckpoint, verifyDisclosureEvent, type InstanceKeyHistory } from '@deepseek-ai/dsh-a2a-device-identity'
import type { DisclosureHash, DisclosureId, DshInstanceId } from '@deepseek-ai/dsh-a2a-protocol'
import { authorizeDisclosure, type DisclosureAction, type DisclosureSubject } from '@deepseek-ai/dsh-a2a-registry-domain'
import { publishedCheckpoint, RegistryIngestError, requireIngest, type IngestRecord } from './record.ts'
import type { RegistryAuthorizedAction, RegistryDisclosureMetadata } from './types.ts'

const metadataActions: readonly RegistryAuthorizedAction[] = ['read', 'import', 'ask']

/** Check the same current grants, selected prefix and source keys for body and metadata reads.
 * @param record - Current stored aggregate or absent resource.
 * @param subject - Current authenticated organization member.
 * @param now - Clock from the same trusted authority snapshot.
 * @param action - Read or derivation operation being authorized.
 * @param historyFor - Synchronous organization-scoped key resolver, invoked only after access allows.
 * @param checkpointHash - Optional exact retained prefix; absence selects latest.
 * @returns Verified internal prefix or null for an inaccessible resource; resolver failures reject the operation. */
export function confirmedPrefix(record: IngestRecord | undefined, subject: DisclosureSubject, now: number,
  action: DisclosureAction, historyFor: (instanceId: DshInstanceId) => InstanceKeyHistory | null, checkpointHash?: DisclosureHash) {
  const decision = authorizeDisclosure(subject, action, record?.kind === 'disclosure' ? record.access : null, now)
  if (!decision.allowed || record?.kind !== 'disclosure') return null
  const checkpoint = checkpointHash === undefined ? publishedCheckpoint(record)
    : record.checkpoints.find(receipt => receipt.value.checkpointHash === checkpointHash) ?? null
  if (checkpoint === null) return null
  let history: InstanceKeyHistory | null
  try {
    history = historyFor(record.access.instanceId)
  } catch {
    // The resolver can contain account or storage diagnostics; never return them to callers.
    throw new RegistryIngestError('not-found')
  }
  if (history === null || history.status !== 'active' || history.organizationId !== record.access.organizationId
    || history.instanceId !== record.access.instanceId) return null
  const events = record.events.slice(0, checkpoint.value.eventCount)
  try {
    for (const receipt of events) {
      verifyDisclosureEvent(receipt.value, history, { organizationId: record.access.organizationId,
        instanceId: record.access.instanceId, keyId: receipt.keyId, now: receipt.verifiedAt })
    }
    verifyDisclosureCheckpoint(checkpoint.value, history, { organizationId: record.access.organizationId,
      instanceId: record.access.instanceId, keyId: checkpoint.keyId, now: checkpoint.verifiedAt })
  } catch {
    // Current key removal/revocation and failed signatures all hide the resource.
    return null
  }
  return { access: record.access, conversationId: record.conversationId, checkpoint: checkpoint.value,
    checkpointVerifiedAt: checkpoint.verifiedAt, events }
}

/** Project only fixed metadata and current effective actions from the already verified prefix.
 * @param prefix - Successful shared authorization and signature result.
 * @param subject - Same authenticated subject used to authorize the prefix.
 * @param now - Same trusted clock used to authorize the prefix.
 * @returns Detached body-free fields, including the selected rather than latest checkpoint. */
export function metadataOf(prefix: NonNullable<ReturnType<typeof confirmedPrefix>>, subject: DisclosureSubject,
  now: number): RegistryDisclosureMetadata {
  const { access, checkpoint, checkpointVerifiedAt } = prefix
  return {
    organizationId: access.organizationId, disclosureId: access.disclosureId, instanceId: access.instanceId,
    control: access.control, producer: access.producer, ingest: access.ingest, expiresAt: access.expiresAt,
    authorizationVersion: access.authorizationVersion, checkpointVerifiedAt,
    authorizedActions: metadataActions.filter(action => authorizeDisclosure(subject, action, access, now).allowed),
    checkpoint: { checkpointHash: checkpoint.checkpointHash, policyVersion: checkpoint.policyVersion,
      sourceCursor: checkpoint.sourceCursor, eventCount: checkpoint.eventCount,
      lastDisclosureSeq: checkpoint.lastDisclosureSeq, lastEventHash: checkpoint.lastEventHash },
  }
}

/** Owner-local authenticated-encryption key; tokens hide only previously authorized anchors, not grant access. */
export class MetadataCursor {
  private readonly key = randomBytes(32)

  /** @param subject - Authenticated page owner.
   * @param anchor - Last authorized ID returned on this page.
   * @returns Opaque token, valid only in this open store and for this organization/member. */
  seal(subject: DisclosureSubject, anchor: DisclosureId): string {
    const nonce = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce)
    cipher.setAAD(this.aad(subject))
    const ciphertext = Buffer.concat([cipher.update(anchor, 'utf8'), cipher.final()])
    return Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]).toString('base64url')
  }

  /** @param subject - Freshly authenticated page owner, not a token-derived identity.
   * @param token - Input already bounded by the store's complete input-byte limit.
   * @returns Previously issued authorized anchor; rejects foreign, modified or old-owner tokens. */
  open(subject: DisclosureSubject, token: string): DisclosureId {
    try {
      const bytes = Buffer.from(token, 'base64url')
      requireIngest(bytes.length > 28 && bytes.toString('base64url') === token, 'invalid-input')
      const decipher = createDecipheriv('aes-256-gcm', this.key, bytes.subarray(0, 12))
      decipher.setAAD(this.aad(subject))
      decipher.setAuthTag(bytes.subarray(12, 28))
      // Only seal() under this owner key can authenticate plaintext, and it accepts a stored canonical ID.
      return brandString<DisclosureId>(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8'))
    } catch {
      throw new RegistryIngestError('invalid-input')
    }
  }

  /** Discard the key after admitted operations and storage teardown have drained. */
  close(): void { this.key.fill(0) }

  private aad(subject: DisclosureSubject): Buffer {
    return Buffer.from(JSON.stringify(['dsh-registry-metadata-cursor-v1', subject.organizationId, subject.memberId]), 'utf8')
  }
}
