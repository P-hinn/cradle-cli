import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import type { DependencyGraph } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'

/**
 * The npm resolver used to be @npmcli/arborist, which brought 115 transitive
 * dependencies of its own — in a tool whose subject is the size and provenance
 * of dependency trees, that was hard to justify.
 *
 * These snapshots are arborist's own output, captured before it was removed.
 * They are the evidence that the lockfile parser answers identically, and they
 * keep answering it: any drift in resolution, licence reading, hashing or
 * prod/dev classification fails here.
 */
function shape(graph: DependencyGraph): unknown {
  return {
    packageManager: graph.packageManager,
    includeDev: graph.includeDev,
    workspaces: graph.workspaces,
    root: { name: graph.root.name, version: graph.root.version, purl: graph.root.purl ?? null },
    components: graph.components
      .map((component) => ({
        bomRef: component.bomRef,
        name: component.name,
        version: component.version,
        purl: component.purl,
        licenses: component.licenses,
        licenseUnknown: component.licenseUnknown,
        hashes: component.hashes,
        direct: component.direct,
        dev: component.dev,
        workspace: component.workspace,
      }))
      .sort((a, b) => a.bomRef.localeCompare(b.bomRef)),
    edges: [...graph.edges.entries()]
      .map(([from, to]) => [from, [...to].sort()])
      .sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
  }
}

const CASES = ['npm-basic', 'npm-workspaces', 'npm-duplicates'].flatMap((name) => [
  [name, false] as const,
  [name, true] as const,
])

describe('the npm lockfile parser matches what arborist resolved', () => {
  it.each(CASES)('%s, includeDev=%s', async (name, includeDev) => {
    const expected = JSON.parse(
      readFileSync(
        new URL(
          `../fixtures/expected/${name}-${includeDev ? 'all' : 'prod'}.json`,
          import.meta.url,
        ),
        'utf8',
      ),
    ) as unknown

    const graph = await resolveNpm({ projectDir: fixture(name), includeDev })
    expect(shape(graph)).toEqual(expected)
  })
})
