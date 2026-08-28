import { beforeAll, describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import type { DependencyGraph, ResolvedComponent } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'

const byName = (graph: DependencyGraph, name: string): ResolvedComponent => {
  const found = graph.components.find((c) => c.name === name)
  if (found === undefined) throw new Error(`${name} is not in the graph`)
  return found
}

describe('resolveNpm — production scope', () => {
  let graph: DependencyGraph

  beforeAll(async () => {
    graph = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: false })
  })

  it('reads the real package name, not the directory name', () => {
    // Arborist reports the directory as tree.name; only tree.package.name is the
    // manifest name. Getting this wrong mislabels metadata.component.
    expect(graph.root.name).toBe('acme-widget')
    expect(graph.root.version).toBe('2.3.0')
  })

  it('leaves development dependencies out by default', () => {
    expect(graph.components.map((c) => c.name).sort()).toEqual(['@sindresorhus/is', 'debug', 'ms'])
  })

  it('separates direct from transitive dependencies', () => {
    expect(byName(graph, 'debug').direct).toBe(true)
    expect(byName(graph, 'ms').direct).toBe(false)
  })

  it('builds purls, hashes and licences from the lockfile alone', () => {
    const is = byName(graph, '@sindresorhus/is')
    expect(is.purl).toBe('pkg:npm/%40sindresorhus/is@7.0.1')
    expect(is.licenses).toEqual([{ kind: 'id', id: 'MIT' }])
    expect(is.licenseUnknown).toBe(false)
    expect(is.hashes[0]?.alg).toBe('SHA-512')
    expect(is.hashes[0]?.content).toMatch(/^[0-9a-f]{128}$/)
    expect(is.resolvedUrl).toContain('registry.npmjs.org')
  })

  it('records the real edges, not a flat list', () => {
    expect(graph.edges.get('pkg:npm/acme-widget@2.3.0')).toEqual([
      'pkg:npm/%40sindresorhus/is@7.0.1',
      'pkg:npm/debug@4.3.7',
    ])
    expect(graph.edges.get('pkg:npm/debug@4.3.7')).toEqual(['pkg:npm/ms@2.1.3'])
    expect(graph.edges.get('pkg:npm/ms@2.1.3')).toEqual([])
  })
})

describe('resolveNpm — including dev', () => {
  it('adds the dev tree and flags it as such', async () => {
    const graph = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: true })
    expect(graph.components.map((c) => c.name)).toContain('chalk')
    expect(byName(graph, 'chalk').dev).toBe(true)
    expect(byName(graph, 'chalk').direct).toBe(true)
    expect(byName(graph, 'debug').dev).toBe(false)
    // chalk -> ansi-styles is a transitive dev dependency.
    expect(byName(graph, 'ansi-styles').direct).toBe(false)
  })
})

describe('resolveNpm — workspaces', () => {
  let graph: DependencyGraph

  beforeAll(async () => {
    graph = await resolveNpm({ projectDir: fixture('npm-workspaces'), includeDev: false })
  })

  it('uses the root package as the product', () => {
    expect(graph.root.name).toBe('acme-monorepo')
    // The root is private, so it has no purl — it was never published.
    expect(graph.root.purl).toBeUndefined()
  })

  it('lists each workspace exactly once, despite the node_modules symlink', () => {
    // npm materialises workspaces twice: at packages/ui and as a link at
    // node_modules/@acme/ui. Counting both would double every workspace.
    const ui = graph.components.filter((c) => c.name === '@acme/ui')
    expect(ui).toHaveLength(1)
    expect(ui[0]?.location).toBe('packages/ui')
    expect(ui[0]?.workspace).toBe(true)
    expect(graph.workspaces).toEqual(['@acme/core', '@acme/ui'])
  })

  it('reports a package with no licence instead of guessing one', () => {
    const ui = byName(graph, '@acme/ui')
    expect(ui.licenses).toEqual([])
    expect(ui.licenseUnknown).toBe(true)
  })

  it('records a peer dependency as such', () => {
    expect(byName(graph, 'debug').kinds).toContain('peer')
  })

  it('treats a dependency declared by a workspace as direct', () => {
    // ms is declared by @acme/core, which is part of this product.
    expect(byName(graph, 'ms').direct).toBe(true)
  })

  it('links workspace packages into the dependency graph', () => {
    const core = byName(graph, '@acme/core')
    const ui = byName(graph, '@acme/ui')
    expect(graph.edges.get(ui.bomRef)).toContain(core.bomRef)
    expect(graph.edges.get(core.bomRef)).toContain('pkg:npm/ms@2.1.3')
  })
})

describe('resolveNpm — duplicated packages', () => {
  it('keeps both copies and points each dependent at the right one', async () => {
    // npm hoists ms@2.0.0 for the root and nests ms@2.1.3 under debug.
    const graph = await resolveNpm({ projectDir: fixture('npm-duplicates'), includeDev: false })
    const versions = graph.components
      .filter((c) => c.name === 'ms')
      .map((c) => c.version)
      .sort()
    expect(versions).toEqual(['2.0.0', '2.1.3'])

    expect(graph.edges.get('pkg:npm/acme-duplicates@1.0.0')).toEqual([
      'pkg:npm/debug@4.3.7',
      'pkg:npm/ms@2.0.0',
    ])
    expect(graph.edges.get('pkg:npm/debug@4.3.7')).toEqual(['pkg:npm/ms@2.1.3'])
  })

  it('gives every component a distinct bom-ref', () => {
    // A repeated bom-ref would make the dependencies block describe a tree that
    // does not exist.
    return resolveNpm({ projectDir: fixture('npm-duplicates'), includeDev: false }).then(
      (graph) => {
        const refs = graph.components.map((c) => c.bomRef)
        expect(new Set(refs).size).toBe(refs.length)
      },
    )
  })
})
