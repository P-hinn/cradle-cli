import { beforeAll, describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { buildBom } from '../../src/core/sbom/cyclonedx.js'
import type { CdxBom, CycloneDxSpecVersion, DependencyGraph } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { validateBom } from '../support/schema.js'

const FIXED = {
  timestamp: '2026-08-28T00:00:00.000Z',
  serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
}

async function bomFor(
  name: string,
  specVersion: CycloneDxSpecVersion = '1.6',
  includeDev = false,
): Promise<{ graph: DependencyGraph; bom: CdxBom }> {
  const graph = await resolveNpm({ projectDir: fixture(name), includeDev })
  return { graph, bom: buildBom(graph, { ...FIXED, specVersion }) }
}

describe('buildBom — schema conformance', () => {
  // The vendored schemas are the authority here; nothing about validity is
  // asserted by hand.
  it.each([
    ['npm-basic', '1.6'],
    ['npm-basic', '1.7'],
    ['npm-workspaces', '1.6'],
    ['npm-workspaces', '1.7'],
    ['npm-duplicates', '1.6'],
  ] as const)('%s validates against CycloneDX %s', async (name, specVersion) => {
    const { bom } = await bomFor(name, specVersion)
    const { valid, errors } = validateBom(bom, specVersion)
    expect(errors).toEqual([])
    expect(valid).toBe(true)
  })

  it('validates with development dependencies included', async () => {
    const { bom } = await bomFor('npm-basic', '1.6', true)
    expect(validateBom(bom, '1.6').errors).toEqual([])
  })
})

describe('buildBom — document shape', () => {
  let bom: CdxBom
  let graph: DependencyGraph

  beforeAll(async () => {
    ;({ bom, graph } = await bomFor('npm-basic'))
  })

  it('declares the requested spec version consistently', () => {
    expect(bom.specVersion).toBe('1.6')
    expect(bom.$schema).toBe('http://cyclonedx.org/schema/bom-1.6.schema.json')
  })

  it('describes the project as metadata.component', () => {
    expect(bom.metadata.component.name).toBe('acme-widget')
    expect(bom.metadata.component.type).toBe('application')
    expect(bom.metadata.component.licenses).toEqual([{ license: { id: 'MIT' } }])
  })

  it('uses the object form of metadata.tools, not the array deprecated in 1.5', () => {
    expect(Array.isArray(bom.metadata.tools)).toBe(false)
    expect(bom.metadata.tools.components[0]?.name).toBe('cradle-cli')
  })

  it('records the scan scope so a reader knows what was left out', () => {
    expect(bom.metadata.properties).toContainEqual({ name: 'cradle:scope', value: 'production' })
    expect(bom.metadata.properties).toContainEqual({ name: 'cradle:packageManager', value: 'npm' })
  })

  it('emits hashes as hex, not the base64 npm stores', () => {
    for (const component of bom.components) {
      for (const hash of component.hashes ?? []) {
        expect(hash.content).toMatch(/^[0-9a-f]+$/)
      }
    }
  })

  it('hangs the tarball hash off the distribution reference too', () => {
    const is = bom.components.find((c) => c.name === '@sindresorhus/is')
    const distribution = is?.externalReferences?.find((r) => r.type === 'distribution')
    expect(distribution?.url).toContain('registry.npmjs.org')
    expect(distribution?.hashes).toEqual(is?.hashes)
  })

  it('is deterministic for a given graph', () => {
    expect(JSON.stringify(buildBom(graph, { ...FIXED, specVersion: '1.6' }))).toBe(
      JSON.stringify(bom),
    )
  })
})

describe('buildBom — dependency graph integrity', () => {
  it.each(['npm-basic', 'npm-workspaces', 'npm-duplicates'])(
    'every ref in %s resolves to a component',
    async (name) => {
      const { bom } = await bomFor(name)
      const known = new Set([
        bom.metadata.component['bom-ref'],
        ...bom.components.map((c) => c['bom-ref']),
      ])

      for (const dependency of bom.dependencies) {
        expect(known).toContain(dependency.ref)
        for (const target of dependency.dependsOn ?? []) expect(known).toContain(target)
      }
    },
  )

  it('gives every component an entry, so "no dependencies" is distinguishable from "not analysed"', async () => {
    const { bom } = await bomFor('npm-basic')
    const refs = new Set(bom.dependencies.map((d) => d.ref))
    expect(refs).toContain(bom.metadata.component['bom-ref'])
    for (const component of bom.components) expect(refs).toContain(component['bom-ref'])
    expect(bom.dependencies).toHaveLength(bom.components.length + 1)
  })

  it('carries the real edges rather than a flat list', async () => {
    const { bom } = await bomFor('npm-basic')
    const root = bom.dependencies.find((d) => d.ref === bom.metadata.component['bom-ref'])
    // ms is a transitive dependency of debug — it must not hang off the root.
    expect(root?.dependsOn).toEqual(['pkg:npm/%40sindresorhus/is@7.0.1', 'pkg:npm/debug@4.3.7'])
    expect(bom.dependencies.find((d) => d.ref === 'pkg:npm/debug@4.3.7')?.dependsOn).toEqual([
      'pkg:npm/ms@2.1.3',
    ])
  })
})
