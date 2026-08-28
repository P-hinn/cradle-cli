import { readFileSync } from 'node:fs'
import { beforeAll, describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { NULL_CACHE } from '../../src/core/vulns/cache.js'
import { countBySeverity, resolveFindings } from '../../src/core/vulns/findings.js'
import { queryOsv } from '../../src/core/vulns/osv.js'
import type { OsvVulnerability } from '../../src/core/vulns/osv-types.js'
import type { DependencyGraph, Finding } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { fakeOsv } from '../support/osv.js'

function advisory(id: string): OsvVulnerability {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/osv/${id}.json`, import.meta.url), 'utf8'),
  ) as OsvVulnerability
}

describe('resolveFindings — against recorded advisories', () => {
  let graph: DependencyGraph
  let findings: Finding[]

  beforeAll(async () => {
    graph = await resolveNpm({ projectDir: fixture('npm-vulnerable'), includeDev: false })
    const osv = await queryOsv(
      graph.components.map((c) => ({ name: c.name, version: c.version })),
      { fetch: fakeOsv().fetch, cache: NULL_CACHE },
    )
    findings = resolveFindings(graph, osv.byPackage)
  })

  it('attaches every advisory to the component it affects', () => {
    expect(findings).toHaveLength(8)
    expect(new Set(findings.map((f) => f.component.name))).toEqual(new Set(['lodash', 'minimist']))
  })

  it('sorts worst first', () => {
    expect(findings[0]?.severity).toBe('critical')
    expect(findings.at(-1)?.severity).toBe('medium')
  })

  it('prefers a computed CVSS score over the advisory label', () => {
    const prototypePollution = findings.find((f) => f.id === 'GHSA-p6mc-m468-83gw')
    expect(prototypePollution?.severitySource).toBe('cvss')
    expect(prototypePollution?.cvss?.score).toBe(7.4)
    expect(prototypePollution?.severity).toBe('high')
  })

  it('carries the CVE alias, which is what people search for', () => {
    expect(findings.find((f) => f.id === 'GHSA-p6mc-m468-83gw')?.aliases).toContain('CVE-2020-8203')
  })

  it('names the lowest version above the installed one that fixes it', () => {
    // The advisory says introduced 3.7.0, fixed 4.17.19; installed is 4.17.15.
    expect(findings.find((f) => f.id === 'GHSA-p6mc-m468-83gw')?.fixedIn).toBe('4.17.19')
  })

  it('links back to the source so a reader can check the claim', () => {
    for (const finding of findings) {
      expect(finding.osvUrl).toBe(`https://osv.dev/vulnerability/${finding.id}`)
    }
  })
})

describe('resolveFindings — path through the tree', () => {
  it('shows the route from the product to a transitive package', async () => {
    // ms is not something this project chose; it arrives through debug. Saying so
    // is the difference between "upgrade this" and "you cannot fix this directly".
    const graph = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: false })
    const findings = resolveFindings(
      graph,
      new Map([['ms@2.1.3', [advisory('GHSA-p6mc-m468-83gw')]]]),
    )

    expect(findings).toHaveLength(1)
    expect(findings[0]?.path).toEqual(['acme-widget', 'debug', 'ms'])
    expect(findings[0]?.dependents).toEqual(['debug'])
    expect(findings[0]?.component.direct).toBe(false)
  })

  it('shows a direct dependency as one hop', async () => {
    const graph = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: false })
    const findings = resolveFindings(
      graph,
      new Map([['debug@4.3.7', [advisory('GHSA-p6mc-m468-83gw')]]]),
    )
    expect(findings[0]?.path).toEqual(['acme-widget', 'debug'])
    expect(findings[0]?.component.direct).toBe(true)
  })

  it('leaves fixedIn unset when no advisory range names the package', async () => {
    // The lodash advisory says nothing about ms, so there is no upgrade to suggest.
    const graph = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: false })
    const findings = resolveFindings(
      graph,
      new Map([['ms@2.1.3', [advisory('GHSA-p6mc-m468-83gw')]]]),
    )
    expect(findings[0]?.fixedIn).toBeUndefined()
  })

  it('ignores advisories for packages that are not in the tree', async () => {
    const graph = await resolveNpm({ projectDir: fixture('npm-basic'), includeDev: false })
    expect(
      resolveFindings(graph, new Map([['not-installed@1.0.0', [advisory('GHSA-p6mc-m468-83gw')]]])),
    ).toEqual([])
  })
})

describe('countBySeverity', () => {
  it('counts each bucket', async () => {
    const graph = await resolveNpm({ projectDir: fixture('npm-vulnerable'), includeDev: false })
    const osv = await queryOsv(
      graph.components.map((c) => ({ name: c.name, version: c.version })),
      { fetch: fakeOsv().fetch, cache: NULL_CACHE },
    )
    const counts = countBySeverity(resolveFindings(graph, osv.byPackage))
    expect(counts.get('critical')).toBe(1)
    expect(counts.get('high')).toBe(3)
    expect(counts.get('medium')).toBe(4)
    expect(counts.get('low')).toBeUndefined()
  })
})
