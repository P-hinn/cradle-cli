import { describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { resolvePnpm } from '../../src/core/resolve/pnpm.js'
import { resolveYarn } from '../../src/core/resolve/yarn.js'
import { buildBom } from '../../src/core/sbom/cyclonedx.js'
import type { DependencyGraph, ResolveNoteKind } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { validateBom } from '../support/schema.js'

const load = {
  npm: () => resolveNpm({ projectDir: fixture('npm-edge-cases'), includeDev: true }),
  pnpm: () => resolvePnpm({ projectDir: fixture('pnpm-edge-cases'), includeDev: true }),
  'yarn-berry': () =>
    resolveYarn('yarn-berry', { projectDir: fixture('yarn-berry-edge-cases'), includeDev: true }),
  'yarn-classic': () =>
    resolveYarn('yarn-classic', {
      projectDir: fixture('yarn-classic-edge-cases'),
      includeDev: true,
    }),
} as const

function kinds(graph: DependencyGraph): ResolveNoteKind[] {
  return [...new Set(graph.notes.map((note) => note.kind))].sort()
}

function named(graph: DependencyGraph, name: string) {
  return graph.components.find((component) => component.name === name)
}

/**
 * Lockfiles carry shapes that an SBOM has no way to state: a package installed
 * under a name it is not published as, one built from a git commit, one vendored
 * from a directory, one patched on the way in.
 *
 * The rule these enforce is not "handle everything". It is **never drop anything
 * in silence**. A skipped dependency leaves output that still looks complete: the
 * component list is plausible, the finding count reads like an answer, and
 * nothing says a package was left out. That is strictly worse than saying so,
 * which is the same reason the readiness checklist reports `not assessable`
 * rather than a confident blank (SPEC.md §6.5).
 */
describe('npm edge cases', () => {
  it('records an npm: alias under its published name, not the alias', async () => {
    const graph = await load.npm()
    // The lockfile installs `@sindresorhus/is` at node_modules/is-alias. OSV is
    // keyed on the published name, so that is what the component must carry - a
    // purl for `is-alias` would name a package that does not exist.
    expect(named(graph, '@sindresorhus/is')?.purl).toBe('pkg:npm/%40sindresorhus/is@7.2.0')
    expect(named(graph, 'is-alias')).toBeUndefined()

    const note = graph.notes.find((candidate) => candidate.kind === 'aliased-dependency')
    expect(note?.message).toContain('is-alias')
  })

  it('reports a git dependency rather than passing its version off as a release', async () => {
    const graph = await load.npm()
    const note = graph.notes.find((candidate) => candidate.kind === 'git-dependency')
    expect(note?.subject).toBe('left-pad@1.3.0')
    expect(note?.hint).toContain('not a published release')
  })

  it('does not mistake a file: dependency for a workspace', async () => {
    const graph = await load.npm()
    // Both are materialised outside node_modules and their lockfile entries are
    // indistinguishable; only the declared range separates them. Calling a
    // vendored dependency a workspace lists somebody else's code as the
    // product's own.
    expect(graph.workspaces).toEqual([])
    expect(named(graph, 'acme-local-lib')?.workspace).toBe(false)
    expect(kinds(graph)).toContain('local-dependency')
  })

  it('includes a bundled dependency and says its hash belongs to the parent', async () => {
    const graph = await load.npm()
    const note = graph.notes.find((candidate) => candidate.kind === 'bundled-dependency')
    expect(note?.subject).toBe('bundled-inner@3.0.1')
    expect(note?.hint).toContain('never fetched separately')
  })

  it('keeps an optional dependency without calling it a problem', async () => {
    const graph = await load.npm()
    const fsevents = named(graph, 'fsevents')
    expect(fsevents?.kinds).toContain('optional')
    // An unmet optional dependency is npm working as designed, not something to
    // report; only a declared dependency that is genuinely missing is.
    expect(graph.notes.filter((note) => note.subject === 'fsevents')).toEqual([])
  })

  it('honours an override by resolving two copies of the same package', async () => {
    const graph = await load.npm()
    // package.json overrides debug's ms to 2.1.2 while the root keeps 2.1.3. The
    // lockfile already carries both; the test is that the edges point at the
    // right copy rather than collapsing to one.
    const versions = graph.components.filter((c) => c.name === 'ms').map((c) => c.version)
    expect(versions.sort()).toEqual(['2.1.2', '2.1.3'])

    const byRef = new Map(graph.components.map((c) => [c.bomRef, `${c.name}@${c.version}`]))
    const debug = named(graph, 'debug')
    const debugEdges = (graph.edges.get(debug?.bomRef ?? '') ?? []).map((ref) => byRef.get(ref))
    expect(debugEdges).toContain('ms@2.1.2')

    const rootEdges = (graph.edges.get(graph.root.bomRef) ?? []).map((ref) => byRef.get(ref))
    expect(rootEdges).toContain('ms@2.1.3')
  })

  it('reports a dependency the lockfile does not carry', async () => {
    const graph = await load.npm()
    const note = graph.notes.find((candidate) => candidate.kind === 'unresolved-dependency')
    expect(note?.subject).toBe('missing-from-lockfile')
    expect(note?.hint).toContain('missing from the SBOM')
  })

  it('keeps a private registry URL out of the purl and out of every hash', async () => {
    const graph = await load.npm()
    const internal = named(graph, '@acme/internal-utils')

    // The tarball URL carries a host and a token. It belongs in an
    // externalReferences entry and nowhere else: a purl or a hash that embeds it
    // would leak the registry into any SBOM sent to a third party, and would not
    // be a valid purl or hash either.
    expect(internal?.purl).toBe('pkg:npm/%40acme/internal-utils@4.1.0')
    expect(internal?.purl).not.toContain('npm.internal.acme.example')
    expect(internal?.purl).not.toContain('token')
    for (const hash of internal?.hashes ?? []) {
      expect(hash.content).toMatch(/^[0-9a-f]+$/)
    }
  })

  it('encodes a scoped name correctly in the purl', async () => {
    const graph = await load.npm()
    expect(named(graph, '@sindresorhus/is')?.purl).toContain('%40sindresorhus')
  })
})

describe('pnpm edge cases', () => {
  it('reads a git dependency’s real version instead of its tarball URL', async () => {
    const graph = await load.pnpm()
    // pnpm keys the entry by the tarball URL, so the tail of the key is a
    // location, not a version. Emitting it produced `pkg:npm/left-pad@https://…`.
    const leftPad = named(graph, 'left-pad')
    expect(leftPad?.version).toBe('1.3.0')
    expect(leftPad?.purl).toBe('pkg:npm/left-pad@1.3.0')
    expect(kinds(graph)).toContain('git-dependency')
  })

  it('reads a directory dependency’s version from its own package.json', async () => {
    const graph = await load.pnpm()
    // The version exists nowhere in the lockfile for a `type: directory`
    // resolution, so the only honest sources are that directory or a note.
    const local = named(graph, 'acme-local-lib')
    expect(local?.version).toBe('0.3.0')
    expect(local?.purl).toBe('pkg:npm/acme-local-lib@0.3.0')
  })

  it('reports a link: that points outside the workspace', async () => {
    const graph = await load.pnpm()
    const note = graph.notes.find((candidate) => candidate.subject === 'acme-outside')
    expect(note?.kind).toBe('local-dependency')
    expect(note?.message).toContain('outside this workspace')
  })

  it('reports a dependency the lockfile does not carry', async () => {
    const graph = await load.pnpm()
    expect(
      graph.notes.some(
        (note) => note.kind === 'unresolved-dependency' && note.subject === 'missing-from-lockfile',
      ),
    ).toBe(true)
  })
})

describe('yarn berry edge cases', () => {
  it('takes the component name from the resolution, not from the descriptor', async () => {
    const graph = await load['yarn-berry']()
    // `is-alias@npm:@sindresorhus/is@^7.0.1` resolves to `@sindresorhus/is@npm:7.2.0`.
    // Reading the descriptor gave a component called `is-alias`.
    expect(named(graph, '@sindresorhus/is')?.version).toBe('7.2.0')
    expect(named(graph, 'is-alias')).toBeUndefined()
    expect(kinds(graph)).toContain('aliased-dependency')
  })

  it('reports a patch instead of dropping it, and does not double-count it', async () => {
    const graph = await load['yarn-berry']()
    // Yarn's built-in patches appear as a second entry over a package that is
    // also present under its plain resolution. They used to vanish without a
    // word - and with a name like `typescript@patch:typescript`, which would
    // have produced a purl for a package that cannot exist.
    expect(graph.components.filter((c) => c.name === 'typescript')).toHaveLength(1)
    const note = graph.notes.find((candidate) => candidate.kind === 'patched-dependency')
    expect(note?.subject).toBe('typescript@5.9.3')
    expect(note?.hint).toContain('unpatched package')
  })

  it('keeps a portal: dependency instead of mistaking it for a workspace', async () => {
    const graph = await load['yarn-berry']()
    // Berry gives portal: and link: dependencies `linkType: soft`, the same as a
    // workspace. Treating that as the signal dropped them from the SBOM and then
    // reported them as missing from a lockfile they were plainly in.
    expect(named(graph, 'acme-local-lib')).toBeDefined()
    expect(graph.workspaces).toEqual([])
    expect(kinds(graph)).toContain('local-dependency')
  })

  it('reports a git dependency and admits it cannot know the published name', async () => {
    const graph = await load['yarn-berry']()
    const note = graph.notes.find((candidate) => candidate.kind === 'git-dependency')
    expect(note?.subject).toBe('left-pad-git@1.3.0')
    expect(note?.hint).toContain('installed under')
  })

  it('carries no hashes, because Berry records a cache key and not a digest', async () => {
    const graph = await load['yarn-berry']()
    for (const component of graph.components) {
      expect(component.hashes, component.name).toEqual([])
    }
  })
})

describe('yarn classic edge cases', () => {
  it('reports a git dependency from the descriptor, which is all Classic records', async () => {
    const graph = await load['yarn-classic']()
    const note = graph.notes.find((candidate) => candidate.kind === 'git-dependency')
    expect(note?.subject).toBe('left-pad-git@1.3.0')
  })

  it('reports a file: dependency', async () => {
    const graph = await load['yarn-classic']()
    expect(kinds(graph)).toContain('local-dependency')
  })

  it('reports a dependency the lockfile does not carry', async () => {
    const graph = await load['yarn-classic']()
    expect(kinds(graph)).toContain('unresolved-dependency')
  })
})

describe('every edge-case fixture', () => {
  for (const [manager, resolve] of Object.entries(load)) {
    describe(manager, () => {
      it('produces a purl that could name a real package', async () => {
        const graph = await resolve()
        for (const component of graph.components) {
          // No protocol, no path, no URL. A purl is an identity; if it carries a
          // location it identifies nothing.
          expect(component.purl, component.name).toMatch(/^pkg:npm\/[^@]+@[^@/:]+$/)
          expect(component.version, component.name).toMatch(/^[0-9]/)
        }
      })

      it('validates against both CycloneDX schemas', async () => {
        const graph = await resolve()
        for (const specVersion of ['1.6', '1.7'] as const) {
          const bom = buildBom(graph, {
            specVersion,
            timestamp: '2026-09-26T00:00:00.000Z',
            serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
          })
          const { valid, errors } = validateBom(bom, specVersion)
          expect(errors.slice(0, 5), `${manager} ${specVersion}`).toEqual([])
          expect(valid).toBe(true)
        }
      })

      it('gives every note a subject, a message and a hint', async () => {
        const graph = await resolve()
        expect(graph.notes.length).toBeGreaterThan(0)
        for (const note of graph.notes) {
          expect(note.subject, note.kind).toBeTruthy()
          // A note that does not end in a full stop reads like a truncated log
          // line, and these are shown to a reader who did not expect them.
          expect(note.message, note.kind).toMatch(/\.$/)
          expect(note.hint, note.kind).toMatch(/\.$/)
        }
      })

      it('reports each shape once, in a stable order', async () => {
        const first = await resolve()
        const second = await resolve()
        expect(first.notes).toEqual(second.notes)

        const seen = first.notes.map((note) => `${note.kind} ${note.subject}`)
        expect(new Set(seen).size).toBe(seen.length)
      })
    })
  }
})
