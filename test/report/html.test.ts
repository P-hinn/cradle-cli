import { beforeAll, describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { NULL_CACHE } from '../../src/core/vulns/cache.js'
import { resolveFindings } from '../../src/core/vulns/findings.js'
import { queryOsv } from '../../src/core/vulns/osv.js'
import { buildReport, type ReportInput } from '../../src/report/html.js'
import type { DependencyGraph, Finding } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { fakeOsv } from '../support/osv.js'

const BASE = {
  timestamp: '2026-08-28T00:00:00.000Z',
  offline: false,
  specVersion: '1.6',
  serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
  toolName: 'cradle-cli',
  toolVersion: '0.0.0',
} satisfies Omit<ReportInput, 'graph' | 'findings'>

async function scanned(name: string): Promise<{ graph: DependencyGraph; findings: Finding[] }> {
  const graph = await resolveNpm({ projectDir: fixture(name), includeDev: false })
  const osv = await queryOsv(
    graph.components.map((c) => ({ name: c.name, version: c.version })),
    { fetch: fakeOsv().fetch, cache: NULL_CACHE },
  )
  return { graph, findings: resolveFindings(graph, osv.byPackage) }
}

describe('buildReport — self-contained', () => {
  let html: string

  beforeAll(async () => {
    html = buildReport({ ...BASE, ...(await scanned('npm-vulnerable')) })
  })

  it('loads nothing from anywhere', () => {
    // The report is emailed and opened from a download folder. A single external
    // reference would break it offline and leak that it was opened.
    expect(html).not.toMatch(/<link\b/i)
    expect(html).not.toMatch(/<img\b/i)
    expect(html).not.toMatch(/<iframe\b/i)
    expect(html).not.toMatch(/<script[^>]+\bsrc=/i)
    expect(html).not.toMatch(/@import/i)
    expect(html).not.toMatch(/url\(\s*['"]?https?:/i)
  })

  it('is a complete document', () => {
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain('<meta charset="utf-8">')
    expect(html.trimEnd().endsWith('</html>')).toBe(true)
  })

  it('states what was scanned, when, and by what', () => {
    expect(html).toContain('acme-vulnerable')
    expect(html).toContain('2026-08-28 00:00:00 UTC')
    expect(html).toContain('Production only')
    expect(html).toContain('CycloneDX 1.6')
    expect(html).toContain('urn:uuid:00000000-0000-4000-8000-000000000000')
    expect(html).toContain('cradle-cli 0.0.0')
  })

  it('carries every finding as its own row', () => {
    const rows = html.match(/data-sort-severity=/g) ?? []
    expect(rows).toHaveLength(8)
  })

  it('never leaves severity to colour alone', () => {
    // Spelled out in text, and repeated as an ordinal glyph for greyscale print.
    expect(html).toContain('>critical</span>')
    expect(html).toContain('data-glyph="●●●"')
    expect(html).toContain('data-glyph="●○○"')
  })

  it('says where each severity came from', () => {
    expect(html).toContain('CVSS v3.1 base score')
    expect(html).toContain('not its exploitability here')
  })

  it('shows the route from the product to the affected package', () => {
    expect(html).toContain('acme-vulnerable<span class="sep">›</span>lodash')
  })

  it('embeds the data it renders, so the file is machine-readable too', () => {
    const block = html.match(
      /<script type="application\/json" id="cradle-data">\n([\s\S]*?)\n<\/script>/,
    )
    expect(block).not.toBeNull()
    const data = JSON.parse(block?.[1] ?? '') as {
      findings: unknown[]
      components: unknown[]
      offline: boolean
    }
    expect(data.findings).toHaveLength(8)
    expect(data.components).toHaveLength(2)
    expect(data.offline).toBe(false)
  })

  it('disclaims what it is not', () => {
    expect(html).toContain('not legal advice')
    expect(html).toContain('not a conformity assessment')
    expect(html).toContain('does not certify compliance')
  })
})

describe('buildReport — offline', () => {
  it('says the lookup was skipped instead of showing an empty findings table', async () => {
    const { graph } = await scanned('npm-vulnerable')
    const html = buildReport({ ...BASE, graph, findings: [], offline: true })

    expect(html).toContain('Scanned offline')
    expect(html).toContain('says nothing about known vulnerabilities')
    expect(html).toContain('<code>--offline</code>')
    // An empty table would read as "we checked and found nothing".
    expect(html).not.toContain('data-table="findings"')
  })
})

describe('buildReport — no findings', () => {
  it('calls a clean result a snapshot, not a guarantee', async () => {
    const { graph } = await scanned('npm-basic')
    const html = buildReport({ ...BASE, graph, findings: [] })
    expect(html).toContain('No known vulnerabilities were reported')
    expect(html).toContain('not "nothing exists"')
  })
})

describe('buildReport — hostile input', () => {
  const hostile = (findings: Finding[], graph: DependencyGraph): string =>
    buildReport({ ...BASE, graph, findings })

  function poisoned(overrides: Partial<Finding>): Finding {
    return {
      id: 'GHSA-x',
      aliases: [],
      summary: '',
      severity: 'high',
      severitySource: 'cvss',
      component: {
        bomRef: 'pkg:npm/x@1.0.0',
        name: 'x',
        version: '1.0.0',
        purl: 'pkg:npm/x@1.0.0',
        direct: true,
      },
      path: ['root', 'x'],
      dependents: [],
      references: [],
      osvUrl: 'https://osv.dev/vulnerability/GHSA-x',
      ...overrides,
    }
  }

  it('escapes an advisory summary that contains markup', async () => {
    // Summaries come from third-party databases and land in a file people open.
    const { graph } = await scanned('npm-basic')
    const html = hostile([poisoned({ summary: '<img src=x onerror="alert(1)">' })], graph)
    expect(html).not.toContain('<img src=x')
    expect(html).toContain('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;')
  })

  it('drops a reference URL that is not http or https', async () => {
    const { graph } = await scanned('npm-basic')
    const html = hostile(
      [
        poisoned({
          references: [
            { type: 'WEB', url: 'javascript:alert(1)' },
            { type: 'ADVISORY', url: 'https://example.test/ok' },
          ],
        }),
      ],
      graph,
    )
    // It must not become a link. It does still appear inside the embedded JSON,
    // which is deliberate: that block is a faithful record of what the advisory
    // said, and it is inert data. Rewriting it there would make the report
    // disagree with findings.json.
    expect(html).not.toMatch(/href="javascript:/i)
    expect(html).not.toMatch(/<a[^>]*javascript:/i)
    expect(html).toContain('href="https://example.test/ok"')

    const block = html.match(
      /<script type="application\/json" id="cradle-data">\n([\s\S]*?)\n<\/script>/,
    )
    const data = JSON.parse(block?.[1] ?? '') as { findings: { references: unknown[] }[] }
    expect(data.findings[0]?.references).toHaveLength(2)
  })

  it('cannot be broken out of the embedded JSON block', async () => {
    const { graph } = await scanned('npm-basic')
    const html = hostile([poisoned({ summary: '</script><script>alert(1)</script>' })], graph)
    // Exactly two script blocks: the data and the behaviour.
    expect(html.match(/<script/g) ?? []).toHaveLength(2)
    expect(html.match(/<\/script>/g) ?? []).toHaveLength(2)
  })
})
