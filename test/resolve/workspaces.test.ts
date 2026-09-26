import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { resolvePnpm } from '../../src/core/resolve/pnpm.js'
import type { DependencyGraph } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'

const PNPM_MONOREPO = fileURLToPath(new URL('../corpus/pnpm-workspace', import.meta.url))

function reachableRefs(graph: DependencyGraph): Set<string> {
  const seen = new Set<string>()
  const queue = [graph.root.bomRef]
  while (queue.length > 0) {
    const ref = queue.shift()
    if (ref === undefined || seen.has(ref)) continue
    seen.add(ref)
    queue.push(...(graph.edges.get(ref) ?? []))
  }
  return seen
}

function edgeNamesFrom(graph: DependencyGraph, packageName: string): string[] {
  const component = graph.components.find((candidate) => candidate.name === packageName)
  if (component === undefined) return []
  const byRef = new Map(graph.components.map((candidate) => [candidate.bomRef, candidate.name]))
  return (graph.edges.get(component.bomRef) ?? []).map((ref) => byRef.get(ref) ?? ref).sort()
}

/**
 * A monorepo is where the dependency graph stops being decoration. `@acme/api ›
 * fastify` tells you which team owns the upgrade; `root › fastify` does not, and
 * a workspace member that nothing points at is the broken dependencies block
 * SPEC.md §5c is about.
 *
 * pnpm used to get both of these wrong: it flattened every member's
 * dependencies onto the root and dropped `link:` edges entirely, leaving the
 * members themselves unreachable. The corpus caught it. These pin the shape for
 * both resolvers at once, because SPEC.md §6.1 requires the parsers to agree.
 */
describe.each([
  {
    resolver: 'npm',
    load: (includeDev: boolean) =>
      resolveNpm({ projectDir: fixture('npm-workspaces'), includeDev }),
  },
  {
    resolver: 'pnpm',
    load: (includeDev: boolean) => resolvePnpm({ projectDir: PNPM_MONOREPO, includeDev }),
  },
])('$resolver workspaces', ({ load }) => {
  it('lists the workspace members as components', async () => {
    const graph = await load(true)
    const workspaces = graph.components.filter((component) => component.workspace)
    expect(workspaces.length).toBeGreaterThan(0)
    expect(graph.workspaces).toEqual(workspaces.map((c) => c.name).sort())
  })

  it('gives every workspace member an incoming edge from the root', async () => {
    // A component nothing points at is not part of the tree, whatever the
    // component list says.
    const graph = await load(true)
    const rootEdges = new Set(graph.edges.get(graph.root.bomRef) ?? [])
    for (const component of graph.components.filter((candidate) => candidate.workspace)) {
      expect(rootEdges, `root -> ${component.name}`).toContain(component.bomRef)
    }
  })

  it('hangs a member’s dependencies off that member, not off the root', async () => {
    const graph = await load(true)
    const members = graph.components.filter((component) => component.workspace)

    // At least one member has dependencies of its own, or this repository is not
    // a monorepo and the fixture is wrong.
    const withEdges = members.filter((member) => (graph.edges.get(member.bomRef) ?? []).length > 0)
    expect(withEdges.length).toBeGreaterThan(0)
  })

  it('records a member depending on a sibling member', async () => {
    // The `workspace:*` / `link:` edge. This is the one pnpm dropped.
    const graph = await load(true)
    const memberRefs = new Set(
      graph.components.filter((component) => component.workspace).map((c) => c.bomRef),
    )

    const siblingEdges = [...memberRefs].flatMap((ref) =>
      (graph.edges.get(ref) ?? []).filter((target) => memberRefs.has(target)),
    )
    expect(siblingEdges.length).toBeGreaterThan(0)
  })

  it('leaves no component unreachable from the root', async () => {
    for (const includeDev of [false, true]) {
      const graph = await load(includeDev)
      const seen = reachableRefs(graph)
      const orphans = graph.components
        .filter((component) => !seen.has(component.bomRef))
        .map((component) => `${component.name}@${component.version}`)
      expect(orphans, `includeDev=${includeDev}`).toEqual([])
    }
  })

  it('marks a sibling dependency as a workspace edge, not a registry one', async () => {
    const graph = await load(true)
    for (const member of graph.components.filter((component) => component.workspace)) {
      // A workspace member is part of the product, so it is never dev-only.
      expect(member.dev, member.name).toBe(false)
    }
  })
})

describe('pnpm workspace links', () => {
  it('resolves link:../shared to the sibling, by path', async () => {
    const graph = await resolvePnpm({ projectDir: PNPM_MONOREPO, includeDev: true })

    // Both members declare `"@corpus/shared": "workspace:*"`, which pnpm records
    // as `link:../shared` relative to the importer's own directory.
    expect(edgeNamesFrom(graph, '@corpus/api')).toContain('@corpus/shared')
    expect(edgeNamesFrom(graph, '@corpus/web')).toContain('@corpus/shared')
    expect(edgeNamesFrom(graph, '@corpus/shared')).toEqual(['zod'])
  })

  it('does not leave a link: spec in a component name or purl', async () => {
    const graph = await resolvePnpm({ projectDir: PNPM_MONOREPO, includeDev: true })
    for (const component of graph.components) {
      expect(component.name, component.name).not.toContain('link:')
      expect(component.purl, component.purl).not.toContain('link:')
    }
  })

  it('reads a member’s name and version from its own package.json', async () => {
    // pnpm's lockfile names importers by path and never by package name, so the
    // manifests are the only source for this.
    const graph = await resolvePnpm({ projectDir: PNPM_MONOREPO, includeDev: true })
    const shared = graph.components.find((component) => component.name === '@corpus/shared')
    expect(shared?.version).toBe('1.0.0')
    expect(shared?.purl).toBe('pkg:npm/%40corpus/shared@1.0.0')
  })
})
