/**
 * Change events identify each durably changed record or global singleton.
 * A batch installs all values before its first event. Events carry the new
 * snapshot and an operation discriminant, never the old value; a diffing
 * consumer keeps its own previous snapshot.
 * @module @deepseek-ai/dsh-storage-domain/src/events
 */

/** Shared location fields of one durable domain change. */
export interface DomainChangedBase {
  /** Owning domain name. */
  readonly domain: string
  /** Table name; `''` for a global-singleton write. */
  readonly table: string
  /** Record key; `''` for a global-singleton write. */
  readonly key: string
}

/** A record (or the global singleton) was inserted or overwritten. */
export interface DomainChangedPut extends DomainChangedBase {
  readonly operation: 'put'
  /** The new snapshot. */
  readonly value: unknown
}

/** A record was deleted; tombstones carry no value. */
export interface DomainChangedDeleted extends DomainChangedBase {
  readonly operation: 'deleted'
  readonly value?: never
}

/** One durable domain change; a closed union — switch on `operation`. */
export type DomainChanged = DomainChangedPut | DomainChangedDeleted

declare module '@deepseek-ai/cordis' {
  interface Events {
    /**
     * A domain record or the global singleton changed, emitted once per
     * location after backend durability. All batch values are readable before
     * its first event; notifications follow batch input and domain write-chain order.
     * @param change - domain, table (`''` for global), key (`''` for global),
     * operation discriminant, and on `put` the new snapshot.
     * @mode emit
     */
    'domain/changed'(change: DomainChanged): void
  }
}
