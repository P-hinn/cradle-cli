import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { resolvePnpm } from '../../src/core/resolve/pnpm.js'
import { resolveYarn } from '../../src/core/resolve/yarn.js'
import { buildBom } from '../../src/core/sbom/cyclonedx.js'
import type { DependencyGraph } from '../../src/types/index.js'
import { validateBom } from '../support/schema.js'

/**
 * A corpus entry is a real lockfile at real size. The hand-written fixtures under
 * test/fixtures/ answer "what does cradle do with this shape"; these answer "does
 * cradle survive what people actually have", which is a different question and
 * the one that produces bug reports.
 *
 * `count` is an independent count of the lockfile, derived from the format's own
 * rules rather than from cradle's output. If cradle and the lockfile disagree
 * about how many packages there are, one of them is wrong — and the whole point
 * of an SBOM is that it is the same tree the package manager installed.
 */
interface CorpusEntry {
  directory: string
  manager: 'npm' | 'pnpm' | 'yarn-berry'
  /** Committed tripwire: production components, then all components. */
  snapshot: { production: number; all: number }
  count: (directory: string) => number
}

const CORPUS: readonly CorpusEntry[] = [
  {
    directory: 'next-app',
    manager: 'npm',
    snapshot: { production: 54, all: 410 },
    count: countNpm,
  },
  {
    directory: 'nuxt-app',
    manager: 'npm',
    snapshot: { production: 733, all: 733 },
    count: countNpm,
  },
  {
    directory: 'angular-app',
    manager: 'npm',
    snapshot: { production: 10, all: 1088 },
    count: countNpm,
  },
  {
    directory: 'pnpm-workspace',
    manager: 'pnpm',
    snapshot: { production: 89, all: 184 },
    count: countPnpm,
  },
  {
    directory: 'yarn-berry',
    manager: 'yarn-berry',
    snapshot: { production: 73, all: 191 },
    count: countYarnBerry,
  },
]

function path(directory: string): string {
  return fileURLToPath(new URL(directory, import.meta.url))
}

function read(directory: string, file: string): string {
  return readFileSync(fileURLToPath(new URL(`${directory}/${file}`, import.meta.url)), 'utf8')
}

/**
 * npm's `packages` map is the materialised tree, so counting it is counting
 * directories in node_modules. Four kinds of entry are not packages: the root
 * itself, a link (a pointer at a workspace materialised elsewhere), an
 * extraneous entry (installed but not depended on), and an entry with no
 * resolved version.
 */
function countNpm(directory: string): number {
  const lock = JSON.parse(read(directory, 'package-lock.json')) as {
    packages: Record<string, { link?: boolean; extraneous?: boolean; version?: string }>
  }
  return Object.entries(lock.packages).filter(
    ([location, entry]) =>
      location !== '' &&
      entry.link !== true &&
      entry.extraneous !== true &&
      entry.version !== undefined,
  ).length
}

/**
 * pnpm splits the two apart: `packages` is one entry per real package, and
 * `importers` is one per workspace member including the root. The root is the
 * product, not a component of it.
 */
function countPnpm(directory: string): number {
  const lock = parseYaml(read(directory, 'pnpm-lock.yaml')) as {
    packages?: Record<string, unknown>
    importers?: Record<string, unknown>
  }
  const packages = Object.keys(lock.packages ?? {}).length
  const workspaces = Object.keys(lock.importers ?? {}).filter((key) => key !== '.').length
  return packages + workspaces
}

/**
 * Yarn Berry keys one entry by every descriptor that resolves to it, so the
 * count is of distinct `resolution:` values. Two kinds are excluded: workspace
 * resolutions, which are the product's own packages, and `patch:` resolutions,
 * which are Yarn's built-in compatibility patches over a package that also
 * appears under its plain `npm:` resolution. Counting a patch separately would
 * double-count.
 */
function countYarnBerry(directory: string): number {
  const lock = parseYaml(read(directory, 'yarn.lock')) as Record<string, { resolution?: string }>
  const resolutions = new Set<string>()
  for (const [key, entry] of Object.entries(lock)) {
    if (key === '__metadata') continue
    const resolution = entry.resolution
    if (resolution === undefined) continue
    if (resolution.includes('@workspace:')) continue
    if (resolution.includes('@patch:')) continue
    resolutions.add(resolution)
  }
  return resolutions.size
}

async function resolveEntry(entry: CorpusEntry, includeDev: boolean): Promise<DependencyGraph> {
  const projectDir = path(entry.directory)
  if (entry.manager === 'npm') return resolveNpm({ projectDir, includeDev })
  if (entry.manager === 'pnpm') return resolvePnpm({ projectDir, includeDev })
  return resolveYarn('yarn-berry', { projectDir, includeDev })
}

describe.each(CORPUS)('corpus: $directory', (entry) => {
  it('resolves without throwing', async () => {
    const graph = await resolveEntry(entry, true)
    expect(graph.packageManager).toBe(entry.manager)
    expect(graph.components.length).toBeGreaterThan(0)
  })

  it('finds exactly as many components as the lockfile has packages', async () => {
    // The independent count, not a snapshot. A parser that drops a shape and a
    // parser that invents one both fail here.
    const graph = await resolveEntry(entry, true)
    expect(graph.components).toHaveLength(entry.count(entry.directory))
  })

  it('gives every component a purl', async () => {
    const graph = await resolveEntry(entry, true)
    for (const component of graph.components) {
      expect(component.purl, component.name).toMatch(/^pkg:npm\//)
      // A name that still carries a protocol or a range never round-trips
      // through a purl; it would look like a package that does not exist.
      expect(component.purl, component.name).not.toMatch(/patch:|workspace:|npm%3A|file:/)
    }
  })

  it('gives every component a unique bom-ref', async () => {
    // A duplicate bom-ref does not fail schema validation, it silently breaks
    // the dependencies block - which is the difference between an SBOM and a
    // list of names (SPEC.md §5c).
    const graph = await resolveEntry(entry, true)
    const refs = graph.components.map((component) => component.bomRef)
    expect(new Set(refs).size).toBe(refs.length)
  })

  it('points every dependency edge at a bom-ref that exists', async () => {
    const graph = await resolveEntry(entry, true)
    const known = new Set([graph.root.bomRef, ...graph.components.map((c) => c.bomRef)])

    for (const [from, targets] of graph.edges) {
      expect(known, `edge source ${from}`).toContain(from)
      for (const target of targets) {
        expect(known, `${from} -> ${target}`).toContain(target)
      }
    }
  })

  it('reaches every component from the root', async () => {
    // An unreachable component is one the product does not actually depend on.
    // It would inflate the SBOM and, worse, the finding count.
    const graph = await resolveEntry(entry, true)
    const seen = new Set<string>()
    const queue = [graph.root.bomRef]
    while (queue.length > 0) {
      const ref = queue.shift()
      if (ref === undefined || seen.has(ref)) continue
      seen.add(ref)
      queue.push(...(graph.edges.get(ref) ?? []))
    }

    const orphans = graph.components
      .filter((component) => !seen.has(component.bomRef))
      .map((component) => `${component.name}@${component.version}`)
    expect(orphans).toEqual([])
  })

  it('validates against the CycloneDX 1.6 and 1.7 schemas', async () => {
    const graph = await resolveEntry(entry, true)
    for (const specVersion of ['1.6', '1.7'] as const) {
      const bom = buildBom(graph, {
        specVersion,
        timestamp: '2026-09-26T00:00:00.000Z',
        serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
      })
      const { valid, errors } = validateBom(bom, specVersion)
      expect(errors.slice(0, 5), `${entry.directory} ${specVersion}`).toEqual([])
      expect(valid).toBe(true)
    }
  })

  it('matches the committed component count', async () => {
    // The tripwire. Every invariant above says the output is self-consistent;
    // this says it has not silently changed size. A parser change that quietly
    // drops a shape satisfies all of them and is still a regression.
    const production = await resolveEntry(entry, false)
    const all = await resolveEntry(entry, true)
    expect({
      production: production.components.length,
      all: all.components.length,
    }).toEqual(entry.snapshot)
  })

  it('never lets the production scope exceed the full one', async () => {
    const production = await resolveEntry(entry, false)
    const all = await resolveEntry(entry, true)
    expect(production.components.length).toBeLessThanOrEqual(all.components.length)

    // And production must be a subset, not merely smaller.
    const everything = new Set(all.components.map((component) => component.purl))
    for (const component of production.components) {
      expect(everything, component.purl).toContain(component.purl)
    }
  })
})

describe('corpus', () => {
  it('ships no node_modules', () => {
    // A corpus entry with an install in it stops testing what it claims to test -
    // that cradle reads the lockfile - and adds tens of thousands of files to the
    // repository.
    const installed = CORPUS.filter((entry) => existsSync(path(`${entry.directory}/node_modules`)))
    expect(installed.map((entry) => entry.directory)).toEqual([])
  })

  it('covers all three lockfile formats that carry a real tree', () => {
    const managers = new Set(CORPUS.map((entry) => entry.manager))
    expect([...managers].sort()).toEqual(['npm', 'pnpm', 'yarn-berry'])
  })
})
