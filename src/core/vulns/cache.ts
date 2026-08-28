/**
 * Cache port. `core/` never touches the filesystem, so the OSV client talks to
 * this interface and `cli/` supplies the on-disk implementation. Tests use the
 * in-memory one, which also keeps them off the network.
 */
export interface VulnCache {
  get(key: string): Promise<string | undefined>
  set(key: string, value: string): Promise<void>
}

export class MemoryCache implements VulnCache {
  private readonly entries = new Map<string, string>()

  get(key: string): Promise<string | undefined> {
    return Promise.resolve(this.entries.get(key))
  }

  set(key: string, value: string): Promise<void> {
    this.entries.set(key, value)
    return Promise.resolve()
  }

  get size(): number {
    return this.entries.size
  }
}

/** A cache that stores nothing, for `--no-cache` runs. */
export const NULL_CACHE: VulnCache = {
  get: () => Promise.resolve(undefined),
  set: () => Promise.resolve(),
}
