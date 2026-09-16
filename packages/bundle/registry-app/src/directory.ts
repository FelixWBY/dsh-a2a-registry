/** Trusted Host directory operations; authentication is supplied independently by the caller. */
import type { FreshRegistryDirectoryAuthority, RegistryDirectoryChange, RegistryDirectoryReceipt,
  RegistryDirectoryState } from '@deepseek-ai/dsh-a2a-registry-ingest'

/** Runtime-scoped directory capability; it exposes neither login nor an HTTP route. */
export interface RegistryDirectory {
  /** Read the current bounded member and team directory.
   * @param authority - Externally authenticated member identity, rechecked in the owner's queue.
   * @param scope - Active audience metadata or owner/admin-only administration records.
   * @param maxResponseBytes - Trusted bound on the complete response.
   * @returns Detached directory records, never a disclosure grant. */
  read(authority: FreshRegistryDirectoryAuthority, scope: 'audience' | 'administration',
    maxResponseBytes: number): Promise<RegistryDirectoryState>
  /** Commit a directory change with disclosure authorization invalidation.
   * @param authority - Externally authenticated identity; stored membership and role decide permission.
   * @param command - Command copied synchronously before entering the runtime queue.
   * @param expectedRevision - Required current directory revision.
   * @returns A confirmed receipt; uncertain writes reject after isolating and closing the owner.
   * A failed input copy queues an unattributed rejection without requesting authority. */
  change(authority: FreshRegistryDirectoryAuthority, command: RegistryDirectoryChange,
    expectedRevision: number): Promise<RegistryDirectoryReceipt>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Available only with explicit directory configuration; every operation checks runtime availability. */
    registryDirectory: RegistryDirectory
  }
}
