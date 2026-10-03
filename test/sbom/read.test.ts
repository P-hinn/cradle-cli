import { describe, expect, it } from 'vitest'
import { CradleError } from '../../src/core/errors.js'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { buildBom } from '../../src/core/sbom/cyclonedx.js'
import { readCycloneDx } from '../../src/core/sbom/read.js'
import { fixture } from '../support/fixtures.js'

const OPTIONS = { projectDir: '/app', path: 'supplied.cdx.json' }

function document(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      component: { 'bom-ref': 'root', type: 'application', name: 'widget', version: '3.1.0' },
    },
    components: [
      {
        'bom-ref': 'c1',
        type: 'library',
        name: 'lodash',
        version: '4.17.15',
        purl: 'pkg:npm/lodash@4.17.15',
      },
    ],
    dependencies: [{ ref: 'root', dependsOn: ['c1'] }],
    ...overrides,
  })
}

describe('readCycloneDx — round trip', () => {
  it('reads back a document cradle wrote, component for component', async () => {
    // The point of the feature: a shipped product's tree lives in its SBOM, and
    // checking it later must give the same answer as scanning it did.
    const original = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: false })
    const bom = buildBom(original, {
      specVersion: '1.6',
      timestamp: '2026-10-03T00:00:00.000Z',
      serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
    })

    const read = readCycloneDx(JSON.stringify(bom), OPTIONS)

    expect(read.root.name).toBe(original.root.name)
    expect(read.root.version).toBe(original.root.version)
    expect(read.components.map((component) => component.purl).sort()).toEqual(
      original.components.map((component) => component.purl).sort(),
    )
    expect(read.notes).toEqual([])
  })

  it('keeps the edges, not just the component list', async () => {
    // A flat list is the thing cradle exists not to produce; reading one back as
    // flat would lose the route a finding is reported with.
    const original = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: false })
    const bom = buildBom(original, {
      specVersion: '1.6',
      timestamp: '2026-10-03T00:00:00.000Z',
      serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
    })

    const read = readCycloneDx(JSON.stringify(bom), OPTIONS)
    expect(read.edges.get('pkg:npm/debug@4.3.7')).toEqual(['pkg:npm/ms@2.1.3'])
  })

  it('carries licences, hashes and direct/transitive back across', async () => {
    const original = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: false })
    const bom = buildBom(original, {
      specVersion: '1.6',
      timestamp: '2026-10-03T00:00:00.000Z',
      serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
    })

    const read = readCycloneDx(JSON.stringify(bom), OPTIONS)
    const debug = read.components.find((component) => component.name === 'debug')
    const ms = read.components.find((component) => component.name === 'ms')

    expect(debug?.licenses).toEqual([{ kind: 'id', id: 'MIT' }])
    expect(debug?.hashes[0]?.alg).toBe('SHA-512')
    expect(debug?.direct).toBe(true)
    expect(ms?.direct).toBe(false)
  })

  it('records that it came from an SBOM', () => {
    const read = readCycloneDx(document(), OPTIONS)
    expect(read.source).toEqual({ kind: 'sbom', path: 'supplied.cdx.json' })
  })
})

describe('readCycloneDx — a document someone else wrote', () => {
  it('derives directness from the graph when the properties are absent', () => {
    // Only cradle writes cradle:relationship. Everyone else's document still has
    // a dependency graph, and one hop from the product is what direct means.
    const read = readCycloneDx(document(), OPTIONS)
    expect(read.components[0]?.direct).toBe(true)
  })

  it('reports a component from another ecosystem instead of dropping it', () => {
    const read = readCycloneDx(
      document({
        components: [
          {
            'bom-ref': 'c2',
            name: 'requests',
            version: '2.25.1',
            purl: 'pkg:pypi/requests@2.25.1',
          },
        ],
        dependencies: [{ ref: 'root', dependsOn: ['c2'] }],
      }),
      OPTIONS,
    )

    expect(read.components).toHaveLength(0)
    expect(read.notes).toHaveLength(1)
    expect(read.notes[0]?.kind).toBe('non-npm-component')
    expect(read.notes[0]?.message).toContain('pkg:pypi')
  })

  it('separates "wrong ecosystem" from "cannot tell what this is"', () => {
    // The two need different advice: one is scanned with another tool, the other
    // cannot be scanned by anything until the document names it properly.
    const read = readCycloneDx(
      document({
        components: [{ 'bom-ref': 'c3', name: 'mystery-lib' }],
        dependencies: [{ ref: 'root', dependsOn: ['c3'] }],
      }),
      OPTIONS,
    )

    expect(read.notes[0]?.kind).toBe('unidentified-component')
    expect(read.notes[0]?.hint).toContain('purl')
  })

  it('rebuilds the purl rather than trusting the one in the document', () => {
    // A hand-written purl is the field most likely to be subtly wrong, and every
    // later advisory match depends on it.
    const read = readCycloneDx(
      document({
        components: [
          {
            'bom-ref': 'c1',
            name: '@scope/pkg',
            version: '1.0.0',
            purl: 'pkg:npm/@scope/pkg@1.0.0',
          },
        ],
        dependencies: [{ ref: 'root', dependsOn: ['c1'] }],
      }),
      OPTIONS,
    )
    expect(read.components[0]?.purl).toBe('pkg:npm/%40scope/pkg@1.0.0')
  })

  it('drops an edge pointing at a component it could not keep', () => {
    // A dangling ref would make the dependency graph describe a tree that is not
    // in the output.
    const read = readCycloneDx(
      document({
        components: [
          {
            'bom-ref': 'c1',
            name: 'lodash',
            version: '4.17.15',
            purl: 'pkg:npm/lodash@4.17.15',
          },
          { 'bom-ref': 'c2', name: 'requests', version: '1.0', purl: 'pkg:pypi/requests@1.0' },
        ],
        dependencies: [{ ref: 'root', dependsOn: ['c1', 'c2'] }],
      }),
      OPTIONS,
    )
    expect(read.edges.get('root')).toEqual(['c1'])
  })
})

describe('readCycloneDx — refusals', () => {
  it('rejects a document that is not CycloneDX', () => {
    const error = (() => {
      try {
        readCycloneDx(JSON.stringify({ spdxVersion: 'SPDX-2.3' }), OPTIONS)
      } catch (caught) {
        return caught
      }
      return undefined
    })()

    expect(error).toBeInstanceOf(CradleError)
    expect((error as CradleError).hint).toContain('SPDX')
  })

  it('rejects a document that does not say what it describes', () => {
    expect(() =>
      readCycloneDx(JSON.stringify({ bomFormat: 'CycloneDX', components: [] }), OPTIONS),
    ).toThrow(CradleError)
  })

  it('fails loudly on malformed JSON', () => {
    expect(() => readCycloneDx('{oops', OPTIONS)).toThrow(CradleError)
  })
})
