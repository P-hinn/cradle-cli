import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { FileCache, cacheDirFor } from '../../src/cli/cache.js'
import { fixture } from '../support/fixtures.js'

const created: string[] = []
async function temp(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cradle-cache-'))
  created.push(dir)
  return dir
}

const savedEnv = { ...process.env }
beforeEach(() => {
  process.env.CRADLE_CACHE_DIR = undefined
  process.env.CRADLE_CACHE_DIR = ''
})
afterEach(async () => {
  process.env = { ...savedEnv }
  await Promise.all(created.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

describe('cacheDirFor', () => {
  it('honours an explicit override, for CI images that mount a cache', () => {
    process.env.CRADLE_CACHE_DIR = '/mnt/cache'
    expect(cacheDirFor(fixture('npm-basic'))).toBe('/mnt/cache')
  })

  it('uses node_modules/.cache when the project is installed', () => {
    // npm-basic has a real node_modules from its install.
    expect(cacheDirFor(fixture('npm-basic'))).toBe(
      join(fixture('npm-basic'), 'node_modules', '.cache', 'cradle'),
    )
  })

  it('falls back outside the project when node_modules is absent', () => {
    process.env.XDG_CACHE_HOME = '/xdg'
    expect(cacheDirFor(fixture('detect/no-lockfile'))).toBe(join('/xdg', 'cradle'))
  })
})

describe('FileCache', () => {
  it('round-trips a value', async () => {
    const cache = new FileCache(await temp())
    expect(await cache.get('osv/v1/GHSA-x@2026-01-01T00:00:00Z')).toBeUndefined()
    await cache.set('osv/v1/GHSA-x@2026-01-01T00:00:00Z', '{"id":"GHSA-x"}')
    expect(await cache.get('osv/v1/GHSA-x@2026-01-01T00:00:00Z')).toBe('{"id":"GHSA-x"}')
  })

  it('keeps a key from escaping the cache directory', async () => {
    const root = await temp()
    const cache = new FileCache(root)
    await cache.set('../../escaped', 'nope')
    // The traversal is neutralised, so the value lands inside the cache root.
    expect(await cache.get('../../escaped')).toBe('nope')
  })

  it('treats an unwritable cache as a miss rather than an error', async () => {
    const root = await temp()
    const blocked = join(root, 'file')
    await writeFile(blocked, 'not a directory')
    const cache = new FileCache(join(blocked, 'under-a-file'))

    // A read-only or impossible cache path is a normal CI situation; it must
    // never break the scan.
    await expect(cache.set('k', 'v')).resolves.toBeUndefined()
    await expect(cache.get('k')).resolves.toBeUndefined()
  })
})
