import { describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { buildBom } from '../../src/core/sbom/cyclonedx.js'
import { buildSpdx, licenseExpression } from '../../src/core/sbom/spdx.js'
import { buildCsaf } from '../../src/core/vex/csaf.js'
import type { DependencyGraph, Finding } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { validateCsaf, validateSpdx } from '../support/schema.js'

const TIMESTAMP = '2026-09-26T12:00:00.000Z'
const SERIAL = 'urn:uuid:11111111-2222-4333-8444-555555555555'

function graphFor(name: string): Promise<DependencyGraph> {
  return resolveNpm({ projectDir: fixture(name), includeDev: true })
}

function spdxFor(graph: DependencyGraph, creator?: { name?: string; email?: string }) {
  return buildSpdx(graph, {
    timestamp: TIMESTAMP,
    serialNumber: SERIAL,
    ...(creator === undefined ? {} : { creator }),
  })
}

function suppressedFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'GHSA-xvch-5gv4-984h',
    aliases: ['CVE-2021-44906'],
    summary: 'Prototype pollution in minimist',
    severity: 'critical',
    severitySource: 'cvss',
    component: {
      bomRef: 'pkg:npm/minimist@1.2.0',
      name: 'minimist',
      version: '1.2.0',
      purl: 'pkg:npm/minimist@1.2.0',
      direct: true,
    },
    path: ['acme', 'minimist'],
    dependents: ['acme'],
    references: [],
    osvUrl: 'https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h',
    suppressed: true,
    suppression: {
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      notes: 'Only our own CI wrapper parses argv here.',
      expired: false,
    },
    ...overrides,
  }
}

const CSAF_OPTIONS = {
  publisher: { name: 'Acme GmbH', namespace: 'mailto:security@acme.example' },
  timestamp: TIMESTAMP,
  trackingId: 'acme-1.0.0-11111111',
  product: { name: 'acme', version: '1.0.0' },
}

/**
 * Two exports that exist because somebody asks for them by name — SPDX in
 * procurement, CSAF in European vulnerability handling — rather than because
 * they say anything the CycloneDX and OpenVEX output does not.
 *
 * Both are validated against the official schemas rather than against our own
 * idea of the shape. A file that claims a format and does not meet it is worse
 * than no file: the consumer finds out, and everything else cradle wrote loses
 * credibility with it.
 */
describe('SPDX 2.3 export', () => {
  it('validates against the official schema', async () => {
    const document = spdxFor(await graphFor('npm-basic'))
    const { valid, errors } = validateSpdx(document)
    expect(errors.slice(0, 5)).toEqual([])
    expect(valid).toBe(true)
  })

  it('validates for a monorepo, a duplicate tree and the edge cases', async () => {
    for (const name of ['npm-workspaces', 'npm-duplicates', 'npm-edge-cases']) {
      const { valid, errors } = validateSpdx(spdxFor(await graphFor(name)))
      expect(errors.slice(0, 3), name).toEqual([])
      expect(valid, name).toBe(true)
    }
  })

  it('describes the product and nothing else', async () => {
    const graph = await graphFor('npm-basic')
    const document = spdxFor(graph)
    expect(document.documentDescribes).toHaveLength(1)
    expect(document.packages[0]?.name).toBe(graph.root.name)
    // One package per component plus the product itself.
    expect(document.packages).toHaveLength(graph.components.length + 1)
  })

  it('gives every package a unique SPDXID even when names collide', async () => {
    // npm-duplicates carries the same package at two versions in one tree, and a
    // duplicate SPDXID breaks the relationship graph the same way a duplicate
    // bom-ref breaks the CycloneDX dependencies block.
    const document = spdxFor(await graphFor('npm-duplicates'))
    const ids = document.packages.map((pkg) => pkg.SPDXID)
    expect(new Set(ids).size).toBe(ids.length)
    for (const id of ids) expect(id, id).toMatch(/^SPDXRef-[0-9a-zA-Z.-]+$/)
  })

  it('points every relationship at a package that exists', async () => {
    const document = spdxFor(await graphFor('npm-workspaces'))
    const known = new Set([...document.packages.map((pkg) => pkg.SPDXID), 'SPDXRef-DOCUMENT'])
    for (const relationship of document.relationships) {
      expect(known, relationship.spdxElementId).toContain(relationship.spdxElementId)
      expect(known, relationship.relatedSpdxElement).toContain(relationship.relatedSpdxElement)
    }
  })

  it('carries the same dependency edges as the CycloneDX document', async () => {
    // Two renderings of one graph. If they disagree, one of them is wrong and a
    // reader has no way to tell which.
    const graph = await graphFor('npm-workspaces')
    const spdx = spdxFor(graph)
    const bom = buildBom(graph, { specVersion: '1.6', timestamp: TIMESTAMP, serialNumber: SERIAL })

    const cdxEdges = bom.dependencies.reduce(
      (count, entry) => count + (entry.dependsOn?.length ?? 0),
      0,
    )
    const spdxEdges = spdx.relationships.filter(
      (relationship) => relationship.relationshipType === 'DEPENDS_ON',
    ).length
    expect(spdxEdges).toBe(cdxEdges)
  })

  it('says NOASSERTION rather than guessing', async () => {
    const document = spdxFor(await graphFor('npm-basic'))
    for (const pkg of document.packages.slice(1)) {
      // cradle reads a lockfile, never the files inside a package, so it has no
      // grounds to conclude a licence or a copyright.
      expect(pkg.licenseConcluded, pkg.name).toBe('NOASSERTION')
      expect(pkg.copyrightText, pkg.name).toBe('NOASSERTION')
      // And filesAnalyzed false, because it has not analysed any files.
      expect(pkg.filesAnalyzed, pkg.name).toBe(false)
    }
  })

  it('names the tool, and the organisation only when one is configured', async () => {
    const graph = await graphFor('npm-basic')
    expect(spdxFor(graph).creationInfo.creators).toEqual([
      expect.stringMatching(/^Tool: cradle-cli-/),
    ])

    const withOrg = spdxFor(graph, { name: 'Acme GmbH', email: 'security@acme.example' })
    expect(withOrg.creationInfo.creators[0]).toBe('Organization: Acme GmbH (security@acme.example)')
  })

  it('spells hash algorithms the SPDX way', async () => {
    const document = spdxFor(await graphFor('npm-basic'))
    const algorithms = document.packages.flatMap((pkg) =>
      (pkg.checksums ?? []).map((checksum) => checksum.algorithm),
    )
    // CycloneDX writes SHA-512, SPDX writes SHA512, and a validator notices.
    expect(algorithms.length).toBeGreaterThan(0)
    for (const algorithm of algorithms) expect(algorithm).not.toContain('-')
  })

  it('joins several licences with AND, and refuses to invent a LicenseRef', () => {
    expect(licenseExpression([{ kind: 'id', id: 'MIT' }])).toBe('MIT')
    expect(
      licenseExpression([
        { kind: 'id', id: 'MIT' },
        { kind: 'id', id: 'Apache-2.0' },
      ]),
    ).toBe('MIT AND Apache-2.0')
    expect(licenseExpression([{ kind: 'expression', expression: 'MIT OR ISC' }])).toBe(
      '(MIT OR ISC)',
    )
    // A name cradle could not map is NOASSERTION. A LicenseRef without the
    // accompanying extracted text would validate and mislead.
    expect(licenseExpression([{ kind: 'name', name: 'Weird Custom Licence' }])).toBe('NOASSERTION')
    expect(licenseExpression([])).toBe('NOASSERTION')
  })
})

describe('CSAF 2.0 VEX export', () => {
  it('validates against the official schema', () => {
    const document = buildCsaf([suppressedFinding()], CSAF_OPTIONS)
    expect(document).toBeDefined()
    const { valid, errors } = validateCsaf(document)
    expect(errors.slice(0, 5)).toEqual([])
    expect(valid).toBe(true)
  })

  it('writes nothing at all when nothing has been suppressed', () => {
    // The schema puts minItems: 1 on both vulnerabilities and full_product_names,
    // so an empty document is not a CSAF document. Absent beats invalid.
    expect(buildCsaf([], CSAF_OPTIONS)).toBeUndefined()
  })

  it('declares the VEX profile', () => {
    const document = buildCsaf([suppressedFinding()], CSAF_OPTIONS)
    expect(document?.document.category).toBe('csaf_vex')
    expect(document?.document.csaf_version).toBe('2.0')
  })

  it('carries the justification as a flag, which is where CSAF puts it', () => {
    // CSAF's flags[].label enumerates exactly the five justifications OpenVEX
    // defines, so a suppression translates without loss.
    const document = buildCsaf([suppressedFinding()], CSAF_OPTIONS)
    const vulnerability = document?.vulnerabilities[0]
    expect(vulnerability?.flags?.[0]?.label).toBe('vulnerable_code_not_in_execute_path')
    expect(vulnerability?.product_status?.known_not_affected).toEqual(
      vulnerability?.flags?.[0]?.product_ids,
    )
  })

  it('puts the CVE in the field built for it and the GHSA alongside', () => {
    const document = buildCsaf([suppressedFinding()], CSAF_OPTIONS)
    const vulnerability = document?.vulnerabilities[0]
    expect(vulnerability?.cve).toBe('CVE-2021-44906')
    expect(vulnerability?.ids?.map((entry) => entry.text)).toContain('GHSA-xvch-5gv4-984h')
  })

  it('matches products to the SBOM by purl', () => {
    const document = buildCsaf([suppressedFinding()], CSAF_OPTIONS)
    const product = document?.product_tree.full_product_names[0]
    expect(product?.product_identification_helper?.purl).toBe('pkg:npm/minimist@1.2.0')
  })

  it('groups several components under one advisory', () => {
    const document = buildCsaf(
      [
        suppressedFinding(),
        suppressedFinding({
          component: {
            bomRef: 'pkg:npm/minimist@0.0.8',
            name: 'minimist',
            version: '0.0.8',
            purl: 'pkg:npm/minimist@0.0.8',
            direct: false,
          },
        }),
      ],
      CSAF_OPTIONS,
    )
    expect(document?.vulnerabilities).toHaveLength(1)
    expect(document?.product_tree.full_product_names).toHaveLength(2)
    expect(document?.vulnerabilities[0]?.product_status?.known_not_affected).toHaveLength(2)
    expect(validateCsaf(document).valid).toBe(true)
  })

  it('states an impact when a hand-edited statement has no justification', () => {
    // cradle's own suppress command makes the justification mandatory, so this
    // only reaches the file through a hand edit - and the VEX profile still wants
    // a reason for every known_not_affected product.
    const document = buildCsaf(
      [
        suppressedFinding({
          suppression: { status: 'not_affected', notes: 'Not reachable.', expired: false },
        }),
      ],
      CSAF_OPTIONS,
    )
    expect(document?.vulnerabilities[0]?.flags).toBeUndefined()
    expect(document?.vulnerabilities[0]?.threats?.[0]?.details).toBe('Not reachable.')
    expect(validateCsaf(document).valid).toBe(true)
  })

  it('still validates with several advisories at once', () => {
    const document = buildCsaf(
      [
        suppressedFinding(),
        suppressedFinding({
          id: 'GHSA-p6mc-m468-83gw',
          aliases: [],
          summary: 'Prototype pollution in lodash',
          component: {
            bomRef: 'pkg:npm/lodash@4.17.15',
            name: 'lodash',
            version: '4.17.15',
            purl: 'pkg:npm/lodash@4.17.15',
            direct: true,
          },
          suppression: {
            status: 'not_affected',
            justification: 'component_not_present',
            expired: false,
          },
        }),
      ],
      CSAF_OPTIONS,
    )
    expect(document?.vulnerabilities).toHaveLength(2)
    const { valid, errors } = validateCsaf(document)
    expect(errors.slice(0, 3)).toEqual([])
    expect(valid).toBe(true)
  })
})
