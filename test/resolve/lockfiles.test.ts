import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { CradleError } from '../../src/core/errors.js'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { resolvePnpm } from '../../src/core/resolve/pnpm.js'
import {
  parseBerryLockfile,
  parseClassicLockfile,
  resolveYarn,
} from '../../src/core/resolve/yarn.js'
import type { DependencyGraph } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'

/**
 * All four fixtures declare the same three production dependencies, so the four
 * parsers must agree. That equivalence is the real test: a lockfile parser that
 * is merely self-consistent is not much use.
 */
const MANAGERS = [
  { name: 'npm', dir: 'npm-basic', resolve: resolveNpm },
  { name: 'pnpm', dir: 'pnpm-basic', resolve: resolvePnpm },
  {
    name: 'yarn-classic',
    dir: 'yarn-classic-basic',
    resolve: (o: { projectDir: string; includeDev: boolean }) => resolveYarn('yarn-classic', o),
  },
  {
    name: 'yarn-berry',
    dir: 'yarn-berry-basic',
    resolve: (o: { projectDir: string; includeDev: boolean }) => resolveYarn('yarn-berry', o),
  },
] as const

describe('every parser agrees on the same dependency set', () => {
  const graphs = new Map<string, DependencyGraph>()

  beforeAll(async () => {
    for (const manager of MANAGERS) {
      graphs.set(
        manager.name,
        await manager.resolve({ projectDir: fixture(manager.dir), includeDev: false }),
      )
    }
  })

  it.each(MANAGERS.map((m) => m.name))('%s resolves the same three components', (name) => {
    const graph = graphs.get(name)
    expect(graph?.components.map((c) => c.purl).sort()).toEqual([
      'pkg:npm/%40sindresorhus/is@7.0.1',
      'pkg:npm/debug@4.3.7',
      'pkg:npm/ms@2.1.3',
    ])
  })

  it.each(MANAGERS.map((m) => m.name))('%s builds the same edges', (name) => {
    const graph = graphs.get(name)
    if (graph === undefined) throw new Error('no graph')
    // ms hangs off debug, not off the root.
    expect(graph.edges.get(graph.root.bomRef)).toEqual([
      'pkg:npm/%40sindresorhus/is@7.0.1',
      'pkg:npm/debug@4.3.7',
    ])
    expect(graph.edges.get('pkg:npm/debug@4.3.7')).toEqual(['pkg:npm/ms@2.1.3'])
  })

  it.each(MANAGERS.map((m) => m.name))('%s separates direct from transitive', (name) => {
    const graph = graphs.get(name)
    const byName = new Map(graph?.components.map((c) => [c.name, c]))
    expect(byName.get('debug')?.direct).toBe(true)
    expect(byName.get('ms')?.direct).toBe(false)
  })

  it.each(MANAGERS.map((m) => m.name))('%s finds a licence for every component', (name) => {
    // npm reads them from its lockfile; the others from node_modules on disk.
    for (const component of graphs.get(name)?.components ?? []) {
      expect(component.licenseUnknown).toBe(false)
      expect(component.licenses).toEqual([{ kind: 'id', id: 'MIT' }])
    }
  })

  it.each(['npm', 'pnpm', 'yarn-classic'])('%s carries tarball hashes', (name) => {
    for (const component of graphs.get(name)?.components ?? []) {
      expect(component.hashes[0]?.alg).toBe('SHA-512')
      expect(component.hashes[0]?.content).toMatch(/^[0-9a-f]{128}$/)
    }
  })

  it('npm, pnpm and yarn-classic agree on the hash itself', () => {
    const digest = (name: string): string | undefined =>
      graphs.get(name)?.components.find((component) => component.name === 'debug')?.hashes[0]
        ?.content
    expect(digest('pnpm')).toBe(digest('npm'))
    expect(digest('yarn-classic')).toBe(digest('npm'))
  })

  it('yarn-berry carries no hashes, because its checksum is not the tarball digest', () => {
    // Berry's checksum is sha512-sized but is Yarn's own cache key over its own
    // archive: for the same package npm records 4162e5d8… and Yarn 6d43a916….
    // Emitting it as a CycloneDX SHA-512 would be a plausible-looking lie.
    for (const component of graphs.get('yarn-berry')?.components ?? []) {
      expect(component.hashes).toEqual([])
    }
  })
})

describe('development dependencies', () => {
  it.each(MANAGERS.map((m) => [m.name, m.dir, m.resolve] as const))(
    '%s excludes them by default and includes them on request',
    async (_name, dir, resolve) => {
      // Neither Yarn format records a dev marker at all, so the split has to be
      // derived by walking the graph from package.json.
      const production = await resolve({ projectDir: fixture(dir), includeDev: false })
      expect(production.components.map((c) => c.name)).not.toContain('chalk')

      const all = await resolve({ projectDir: fixture(dir), includeDev: true })
      const chalk = all.components.find((c) => c.name === 'chalk')
      expect(chalk?.dev).toBe(true)
      expect(chalk?.direct).toBe(true)
      expect(all.components.find((c) => c.name === 'ansi-styles')?.direct).toBe(false)
      expect(all.components.find((c) => c.name === 'debug')?.dev).toBe(false)
    },
  )
})

describe('parseClassicLockfile', () => {
  it('reads one entry with several descriptors', () => {
    const entries = parseClassicLockfile(`# a comment

"@scope/pkg@^1.0.0", "@scope/pkg@^1.2.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz#abc"
  integrity sha512-AAAA
  dependencies:
    ms "^2.1.0"
`)
    expect(entries).toHaveLength(1)
    expect(entries[0]?.name).toBe('@scope/pkg')
    expect(entries[0]?.version).toBe('1.2.3')
    expect(entries[0]?.descriptors).toEqual(['@scope/pkg@^1.0.0', '@scope/pkg@^1.2.0'])
    expect(entries[0]?.integrity).toBe('sha512-AAAA')
    // The #sha1 fragment is part of yarn's URL, not of the package location.
    expect(entries[0]?.resolvedUrl).toBe('https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz')
    expect(entries[0]?.dependencies.get('ms')).toBe('^2.1.0')
  })

  it('handles an unquoted descriptor', () => {
    const entries = parseClassicLockfile('ms@^2.1.0:\n  version "2.1.3"\n')
    expect(entries[0]?.name).toBe('ms')
    expect(entries[0]?.descriptors).toEqual(['ms@^2.1.0'])
  })

  it('marks peer dependencies as such', () => {
    const entries = parseClassicLockfile(`pkg@1.0.0:
  version "1.0.0"
  peerDependencies:
    react "^18"
`)
    expect(entries[0]?.peers.has('react')).toBe(true)
    expect(entries[0]?.dependencies.get('react')).toBe('^18')
  })

  it('drops an entry with no version rather than inventing one', () => {
    expect(parseClassicLockfile('broken@1.0.0:\n  resolved "https://x"\n')).toEqual([])
  })

  it('returns nothing for an empty file', () => {
    expect(parseClassicLockfile('# yarn lockfile v1\n\n')).toEqual([])
  })
})

describe('parseBerryLockfile', () => {
  const LOCK = `__metadata:
  version: 8
  cacheKey: 10c0

"@scope/pkg@npm:^1.0.0":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"
  dependencies:
    ms: "npm:^2.1.0"
  peerDependencies:
    react: ^18
  checksum: 10c0/deadbeef
  languageName: node
  linkType: hard

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
  languageName: unknown
  linkType: soft
`

  it('strips the npm protocol from descriptors and ranges', () => {
    const entries = parseBerryLockfile(LOCK, 'yarn.lock')
    const pkg = entries.find((entry) => entry.name === '@scope/pkg')
    expect(pkg?.descriptors).toEqual(['@scope/pkg@^1.0.0'])
    expect(pkg?.dependencies.get('ms')).toBe('^2.1.0')
  })

  it('never reads the checksum as an integrity value', () => {
    const pkg = parseBerryLockfile(LOCK, 'yarn.lock').find((e) => e.name === '@scope/pkg')
    expect(pkg?.integrity).toBeUndefined()
  })

  it('recognises the workspace entry', () => {
    const workspace = parseBerryLockfile(LOCK, 'yarn.lock').find((e) => e.name === 'my-app')
    expect(workspace?.workspace).toBe(true)
  })

  it('skips the metadata block', () => {
    expect(parseBerryLockfile(LOCK, 'yarn.lock').map((e) => e.name)).not.toContain('__metadata')
  })

  it('records peer dependencies', () => {
    const pkg = parseBerryLockfile(LOCK, 'yarn.lock').find((e) => e.name === '@scope/pkg')
    expect(pkg?.peers.has('react')).toBe(true)
  })
})

describe('pnpm lockfile versions', () => {
  const temporaries: string[] = []
  afterEach(async () => {
    await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
  })

  async function project(lockfile: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'cradle-pnpm-'))
    temporaries.push(dir)
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'app', version: '1.0.0', private: true }),
      'utf8',
    )
    await writeFile(join(dir, 'pnpm-lock.yaml'), lockfile, 'utf8')
    return dir
  }

  it('refuses a pre-v9 lockfile instead of silently resolving nothing', async () => {
    // Before v9 there was no packages/snapshots split, so the old layout would
    // parse into an empty tree and read as a project with no dependencies.
    const dir = await project("lockfileVersion: '6.0'\n")
    const error = await resolvePnpm({ projectDir: dir, includeDev: false }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(CradleError)
    expect((error as CradleError).message).toContain('lockfileVersion 6.0')
    expect((error as CradleError).hint).toContain('pnpm 9')
  })

  it('accepts v9 and v10', async () => {
    for (const version of ['9.0', '10.0']) {
      const dir = await project(`lockfileVersion: '${version}'\n`)
      await expect(resolvePnpm({ projectDir: dir, includeDev: false })).resolves.toBeDefined()
    }
  })
})
