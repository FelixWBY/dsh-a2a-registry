/** Explicitly public Client configuration: lossless JSON, detached from the registering Host. */
import { deepFreeze, snapshotJsonValue } from '@deepseek-ai/dsh-util-values'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'

/** Public plugin configuration, never an automatically forwarded Host configuration. */
export type ClientPublicConfig = { readonly [key: string]: JsonValue }

/**
 * Validate and freeze a detached public configuration record without invoking accessors.
 * @param subject - Target package or wire row for diagnostics.
 * @param value - Explicit public configuration candidate.
 * @returns A detached, deeply frozen JSON object.
 * @throws When the record contains non-JSON data, accessors, or prototype-mutating keys.
 */
export function parseClientPublicConfig(subject: string, value: unknown): ClientPublicConfig {
  const invalid = () => new Error(`client-modules: ${subject} config must be a plain lossless JSON object without accessors or prototype keys`)
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw invalid()
  const pending: unknown[] = [value]
  const visited = new Set<object>()
  while (pending.length > 0) {
    const item = pending.pop()
    if (typeof item !== 'object' || item === null || visited.has(item)) continue
    visited.add(item)
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(item))) {
      if (key === '__proto__' || key === 'prototype' || key === 'constructor') throw invalid()
      if (!('value' in descriptor)) throw invalid()
      pending.push(descriptor.value)
    }
  }
  const snapshot = snapshotJsonValue(value)
  if (snapshot === undefined) throw invalid()
  JSON.stringify(snapshot)
  return deepFreeze(snapshot as ClientPublicConfig)
}
