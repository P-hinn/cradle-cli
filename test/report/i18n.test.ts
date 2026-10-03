import { describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import { NULL_CACHE } from '../../src/core/vulns/cache.js'
import { resolveFindings } from '../../src/core/vulns/findings.js'
import { queryOsv } from '../../src/core/vulns/osv.js'
import { buildReport, type ReportInput } from '../../src/report/html.js'
import { de } from '../../src/report/i18n/de.js'
import { en } from '../../src/report/i18n/en.js'
import { isLanguage, LANGUAGES, strings } from '../../src/report/i18n/index.js'
import { buildPullRequestComment } from '../../src/report/markdown.js'
import type { DependencyGraph, Finding } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { fakeOsv } from '../support/osv.js'

const BASE = {
  timestamp: '2026-09-26T00:00:00.000Z',
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

/**
 * Walk two objects of the same shape and collect the paths where they differ in
 * structure — a key present in one and missing from the other, or a string where
 * the other has a function.
 */
function shapeDifferences(a: unknown, b: unknown, path = ''): string[] {
  if (typeof a === 'function' || typeof b === 'function') {
    return typeof a === typeof b ? [] : [path]
  }
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) {
    return typeof a === typeof b ? [] : [path]
  }

  const keys = new Set([...Object.keys(a), ...Object.keys(b)])
  const differences: string[] = []
  for (const key of keys) {
    const left = (a as Record<string, unknown>)[key]
    const right = (b as Record<string, unknown>)[key]
    if (left === undefined || right === undefined) {
      differences.push(`${path}.${key}`)
      continue
    }
    differences.push(...shapeDifferences(left, right, `${path}.${key}`))
  }
  return differences
}

/**
 * A translation is not a decoration here. A German manufacturer sends this report
 * to a German auditor, and a half-translated page — English headings over German
 * prose — reads as carelessness about everything else in it.
 *
 * So the tests are about two things: that neither locale has drifted from the
 * other, and that the German version hedges exactly as hard as the English one.
 * Softening a caveat in translation would make the German report claim more than
 * the English report does, which is the one mistake that matters.
 */
describe('locales', () => {
  it('offers exactly the languages it advertises', () => {
    expect([...LANGUAGES]).toEqual(['en', 'de'])
    expect(isLanguage('de')).toBe(true)
    expect(isLanguage('fr')).toBe(false)
    expect(isLanguage(undefined)).toBe(false)
  })

  it('defaults to English', () => {
    expect(strings()).toBe(en)
    expect(strings('en')).toBe(en)
    expect(strings('de')).toBe(de)
  })

  it('carries the same keys in both languages', () => {
    // A missing key would leave a report that is mostly translated, which reads
    // worse than one that is not translated at all.
    expect(shapeDifferences(en, de)).toEqual([])
  })

  it('translates every string rather than copying the English through', () => {
    // Allowed to be identical: proper nouns, format names, and words German
    // borrowed whole.
    const shared = new Set([
      'Status',
      'Name',
      'Version',
      'Advisory',
      'Findings',
      'Details',
      'dev',
      'Workspaces',
      'SBOM-Format',
      'optional',
      'cradle',
    ])

    const untranslated: string[] = []
    const walk = (a: unknown, b: unknown, path: string): void => {
      if (typeof a === 'string' && typeof b === 'string') {
        if (a === b && !shared.has(a)) untranslated.push(`${path}: ${a}`)
        return
      }
      if (typeof a !== 'object' || a === null || typeof b !== 'object' || b === null) return
      for (const key of Object.keys(a)) {
        walk(
          (a as Record<string, unknown>)[key],
          (b as Record<string, unknown>)[key],
          `${path}.${key}`,
        )
      }
    }
    walk(en, de, '')
    expect(untranslated).toEqual([])
  })

  it('keeps the disclaimers as strong in German as in English', () => {
    // The sentences that stop this tool from claiming more than it knows.
    expect(de.colophon.disclaimerLead).toContain('keine Rechtsberatung')
    expect(de.colophon.disclaimerBody('cradle')).toContain('keine Konformitätsbewertung')
    expect(de.colophon.disclaimerBody('cradle')).toContain('keine Konformitätserklärung')
    expect(de.readiness.caption).toContain('Konformitätsbewertung')
    expect(de.profile.notAConformityAssessment).toContain('keine Konformitätsbewertung')
    expect(de.report.offlineBanner.body).toContain('sagt nichts über bekannte Schwachstellen')
    expect(de.findings.none).toContain('Momentaufnahme')
  })

  it('uses the regulation’s own German terms', () => {
    // A reader holding the German text of 2024/2847 should find the same words.
    expect(de.report.eyebrow).toContain('Schwachstellenbericht')
    expect(de.findings.severity).toBe('Schwere')
    expect(de.suppressed.justification).toBe('Begründung')
    expect(de.components.heading).toBe('Komponenten')
    // Not "Verwundbarkeit", which is the literal translation nobody uses.
    expect(JSON.stringify(de)).not.toContain('Verwundbarkeit')
  })

  it('gets German plurals right rather than appending an (s)', () => {
    expect(de.suppressed.inDays(0)).toBe('heute')
    expect(de.suppressed.inDays(1)).toBe('in 1 Tag')
    expect(de.suppressed.inDays(5)).toBe('in 5 Tagen')
    expect(de.readiness.needAttention(1, 6)).toContain('braucht')
    expect(de.readiness.needAttention(3, 6)).toContain('brauchen')
    expect(de.markdown.knownFindings(1)).toContain('bekanntes Finding')
    expect(de.markdown.knownFindings(2)).toContain('bekannte Findings')
  })
})

describe('the report in German', () => {
  it('declares the language on the document', async () => {
    // A screen reader pronounces by this attribute, and a browser hyphenates by
    // it. Translating the text and leaving lang="en" is the worst of both.
    const { graph, findings } = await scanned('npm-vulnerable')
    const html = buildReport({ ...BASE, graph, findings, lang: 'de' })
    expect(html).toContain('<html lang="de">')
    expect(html).not.toContain('<html lang="en">')
  })

  it('translates the headings and the table columns', async () => {
    const { graph, findings } = await scanned('npm-vulnerable')
    const html = buildReport({ ...BASE, graph, findings, lang: 'de' })

    expect(html).toContain('<h2>Überblick</h2>')
    expect(html).toContain('Komponenten')
    expect(html).toContain('Schwere')
    expect(html).toContain('Behoben in')
    // And nothing left behind from the English original.
    expect(html).not.toContain('<h2>Summary</h2>')
    expect(html).not.toContain('>Fixed in<')
  })

  it('translates the severity words a reader scans for', async () => {
    const { graph, findings } = await scanned('npm-vulnerable')
    const html = buildReport({ ...BASE, graph, findings, lang: 'de' })
    expect(findings.length).toBeGreaterThan(0)
    expect(html).toContain('kritisch')
    // The CSS class stays English: it is the stylesheet's vocabulary, not the
    // reader's, and translating it would unstyle the page.
    expect(html).toContain('class="sev sev-critical"')
  })

  it('leaves the filter vocabulary in English, where the script reads it', async () => {
    // data-relationship and data-severity are what the behaviour script matches
    // on. Translating them would break filtering in German and nowhere else,
    // which is the kind of bug that survives a release.
    const { graph, findings } = await scanned('npm-basic')
    const html = buildReport({ ...BASE, graph, findings, lang: 'de' })
    expect(html).toContain('data-relationship="direct"')
    expect(html).toContain('data-facet="relationship" value="direct"')
  })

  it('keeps the embedded JSON identical in both languages', async () => {
    // The machine-readable block is a record of the scan, not prose. A consumer
    // parsing it must not have to know which language the page was rendered in.
    const { graph, findings } = await scanned('npm-vulnerable')
    const extract = (html: string): string =>
      html.match(
        /<script type="application\/json" id="cradle-data">\n([\s\S]*?)\n<\/script>/,
      )?.[1] ?? ''

    expect(extract(buildReport({ ...BASE, graph, findings, lang: 'de' }))).toBe(
      extract(buildReport({ ...BASE, graph, findings, lang: 'en' })),
    )
  })

  it('renders the same structure in both languages', async () => {
    // Same sections, same rows, same tables - only the words differ.
    const { graph, findings } = await scanned('npm-vulnerable')
    const count = (html: string, pattern: RegExp): number => (html.match(pattern) ?? []).length

    const german = buildReport({ ...BASE, graph, findings, lang: 'de' })
    const english = buildReport({ ...BASE, graph, findings, lang: 'en' })
    for (const pattern of [/<h2>/g, /<tr/g, /<table/g, /<script/g]) {
      expect(count(german, pattern), String(pattern)).toBe(count(english, pattern))
    }
  })
})

describe('the pull-request comment in German', () => {
  const comment = (lang: 'en' | 'de'): string =>
    buildPullRequestComment({
      project: { name: 'acme', version: '1.0.0' },
      packageManager: 'npm',
      scope: 'production',
      componentCount: 42,
      diff: { added: [], known: [], resolved: [], worsened: [] },
      suppressed: 0,
      failing: [],
      thresholds: { severity: 'high', kev: false },
      hasBaseline: true,
      toolName: 'cradle-cli',
      toolVersion: '0.0.0',
      lang,
    })

  it('translates the verdict and the subtitle', () => {
    expect(comment('de')).toContain('Nichts Neues seit der Baseline')
    expect(comment('de')).toContain('42 Komponenten')
    expect(comment('en')).toContain('Nothing new since the baseline')
  })

  it('keeps the marker identical, or the action posts a new comment each push', () => {
    // The marker is how the action finds the comment it wrote last time. It is an
    // identifier, not text, and must not be translated.
    const marker = '<!-- cradle-cli:report -->'
    expect(comment('de')).toContain(marker)
    expect(comment('en')).toContain(marker)
  })
})
