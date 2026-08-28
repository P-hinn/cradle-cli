import { existsSync } from 'node:fs'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import type { VulnCache } from '../core/vulns/cache.js'

/**
 * Where advisory details are cached between runs.
 *
 * `node_modules/.cache` is the conventional spot and is already ignored by every
 * npm project, but it does not exist before an install and is ambiguous in a
 * monorepo — so there is a fallback, and an override for CI images that mount a
 * cache elsewhere (SPEC.md §5e).
 */
export function cacheDirFor(projectDir: string): string {
  const override = process.env.CRADLE_CACHE_DIR
  if (override !== undefined && override !== '') return override

  const nodeModules = join(projectDir, 'node_modules')
  if (existsSync(nodeModules)) return join(nodeModules, '.cache', 'cradle')

  const xdg = process.env.XDG_CACHE_HOME
  if (xdg !== undefined && xdg !== '') return join(xdg, 'cradle')

  const home = homedir()
  return home === '' ? join(tmpdir(), 'cradle-cache') : join(home, '.cache', 'cradle')
}

export class FileCache implements VulnCache {
  constructor(private readonly root: string) {}

  async get(key: string): Promise<string | undefined> {
    try {
      return await readFile(this.pathFor(key), 'utf8')
    } catch {
      // A missing or unreadable entry is a cache miss, never a failure.
      return undefined
    }
  }

  async set(key: string, value: string): Promise<void> {
    const path = this.pathFor(key)
    try {
      await mkdir(dirname(path), { recursive: true })
      await writeFile(path, value, 'utf8')
    } catch {
      // A cache we cannot write to must not break the scan — a read-only
      // filesystem is a perfectly normal CI setup.
    }
  }

  private pathFor(key: string): string {
    // Keys look like `osv/v1/GHSA-x@2026-01-01T00:00:00Z`; keep the shape but
    // strip anything that would escape the directory or upset a filesystem.
    const safe = key.replace(/[^a-zA-Z0-9._/@-]/g, '_').replace(/\.\.+/g, '_')
    return join(this.root, `${safe}.json`)
  }
}
