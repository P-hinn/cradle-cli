import { describe, expect, it } from 'vitest'
import { applyVex, expiringSoon } from '../../src/core/vex/apply.js'
import type { Finding, VexDocument, VexStatement } from '../../src/types/index.js'

const NOW = new Date('2026-08-28T00:00:00.000Z')

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'GHSA-p6mc-m468-83gw',
    aliases: ['CVE-2020-8203'],
    summary: 'Prototype Pollution in lodash',
    severity: 'high',
    severitySource: 'cvss',
    component: {
      bomRef: 'pkg:npm/lodash@4.17.15',
      name: 'lodash',
      version: '4.17.15',
      purl: 'pkg:npm/lodash@4.17.15',
      direct: true,
    },
    path: ['app', 'lodash'],
    dependents: ['app'],
    references: [],
    osvUrl: 'https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw',
    ...overrides,
  }
}

function document(...statements: VexStatement[]): VexDocument {
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': 'urn:uuid:x',
    author: 'someone@example.test',
    timestamp: '2026-08-01T00:00:00.000Z',
    version: 1,
    statements,
  }
}

const notAffected = (overrides: Partial<VexStatement> = {}): VexStatement => ({
  vulnerability: { name: 'GHSA-p6mc-m468-83gw' },
  products: [{ '@id': 'pkg:npm/lodash@4.17.15' }],
  status: 'not_affected',
  justification: 'vulnerable_code_not_present',
  ...overrides,
})

describe('applyVex — matching', () => {
  it('moves a matched finding out of the active count but keeps it', () => {
    const result = applyVex([finding()], document(notAffected()), NOW)
    expect(result.active).toHaveLength(0)
    expect(result.suppressed).toHaveLength(1)
    expect(result.suppressed[0]?.suppressed).toBe(true)
    expect(result.suppressed[0]?.suppression?.justification).toBe('vulnerable_code_not_present')
  })

  it('matches on the CVE alias as well as the GHSA id', () => {
    // People write down the CVE they read about; OSV keys npm advisories by GHSA.
    const result = applyVex(
      [finding()],
      document(notAffected({ vulnerability: { name: 'CVE-2020-8203' } })),
      NOW,
    )
    expect(result.suppressed).toHaveLength(1)
  })

  it('ignores case in the identifier', () => {
    const result = applyVex(
      [finding()],
      document(notAffected({ vulnerability: { name: 'cve-2020-8203' } })),
      NOW,
    )
    expect(result.suppressed).toHaveLength(1)
  })

  it('accepts a versionless purl, which is how people write these by hand', () => {
    const result = applyVex(
      [finding()],
      document(notAffected({ products: [{ '@id': 'pkg:npm/lodash' }] })),
      NOW,
    )
    expect(result.suppressed).toHaveLength(1)
  })

  it('does not let a versionless purl bleed onto a different package', () => {
    const other = finding({
      component: {
        bomRef: 'pkg:npm/lodash-es@4.17.15',
        name: 'lodash-es',
        version: '4.17.15',
        purl: 'pkg:npm/lodash-es@4.17.15',
        direct: true,
      },
    })
    const result = applyVex(
      [other],
      document(notAffected({ products: [{ '@id': 'pkg:npm/lodash' }] })),
      NOW,
    )
    expect(result.active).toHaveLength(1)
  })

  it('matches through subcomponents, the shape used for a product-level statement', () => {
    const result = applyVex(
      [finding()],
      document(
        notAffected({
          products: [
            { '@id': 'pkg:npm/my-app@1.0.0', subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.15' }] },
          ],
        }),
      ),
      NOW,
    )
    expect(result.suppressed).toHaveLength(1)
  })

  it('leaves a different version of the same package alone', () => {
    const newer = finding({
      component: {
        bomRef: 'pkg:npm/lodash@4.17.21',
        name: 'lodash',
        version: '4.17.21',
        purl: 'pkg:npm/lodash@4.17.21',
        direct: true,
      },
    })
    expect(applyVex([newer], document(notAffected()), NOW).active).toHaveLength(1)
  })

  it('reports statements that matched nothing', () => {
    // Usually the finding was fixed by an upgrade, leaving dead weight behind.
    const result = applyVex([], document(notAffected()), NOW)
    expect(result.unmatched).toHaveLength(1)
  })
})

describe('applyVex — statuses', () => {
  it.each([
    ['not_affected', true],
    ['fixed', true],
    ['affected', false],
    ['under_investigation', false],
  ] as const)('%s suppresses: %s', (status, suppresses) => {
    const statement: VexStatement =
      status === 'not_affected'
        ? notAffected()
        : {
            vulnerability: { name: 'GHSA-p6mc-m468-83gw' },
            products: [{ '@id': 'pkg:npm/lodash@4.17.15' }],
            status,
          }
    const result = applyVex([finding()], document(statement), NOW)
    expect(result.suppressed).toHaveLength(suppresses ? 1 : 0)
  })

  it('keeps an affected statement visible but carries its action statement', () => {
    const result = applyVex(
      [finding()],
      document({
        vulnerability: { name: 'GHSA-p6mc-m468-83gw' },
        products: [{ '@id': 'pkg:npm/lodash@4.17.15' }],
        status: 'affected',
        action_statement: 'Upgrade before the next release.',
      }),
      NOW,
    )
    expect(result.active).toHaveLength(1)
    expect(result.active[0]?.suppressed).toBe(false)
    expect(result.active[0]?.suppression?.actionStatement).toBe('Upgrade before the next release.')
  })
})

describe('applyVex — expiry', () => {
  it('stops suppressing once the date has passed', () => {
    // The entire point of an expiry: a decision made two years ago about a
    // dependency has to be renewed, not quietly outlive its reasoning.
    const result = applyVex(
      [finding()],
      document(notAffected({ 'cradle:expires': '2026-08-01' })),
      NOW,
    )
    expect(result.active).toHaveLength(1)
    expect(result.suppressed).toHaveLength(0)
  })

  it('still attaches the lapsed statement, so the finding does not just reappear', () => {
    const result = applyVex(
      [finding()],
      document(notAffected({ 'cradle:expires': '2026-08-01' })),
      NOW,
    )
    expect(result.active[0]?.suppression?.expired).toBe(true)
    expect(result.active[0]?.suppression?.expires).toBe('2026-08-01')
    expect(result.active[0]?.suppression?.expiresInDays).toBe(-27)
  })

  it('still suppresses while the date is in the future, and counts the days', () => {
    const result = applyVex(
      [finding()],
      document(notAffected({ 'cradle:expires': '2026-09-15' })),
      NOW,
    )
    expect(result.suppressed).toHaveLength(1)
    expect(result.suppressed[0]?.suppression?.expiresInDays).toBe(18)
  })

  it('treats a statement with no expiry as open-ended', () => {
    const result = applyVex([finding()], document(notAffected()), NOW)
    expect(result.suppressed[0]?.suppression?.expired).toBe(false)
    expect(result.suppressed[0]?.suppression?.expires).toBeUndefined()
  })
})

describe('applyVex — no document', () => {
  it('passes findings through untouched', () => {
    const findings = [finding()]
    expect(applyVex(findings, undefined, NOW).active).toEqual(findings)
    expect(applyVex(findings, document(), NOW).active).toEqual(findings)
  })
})

describe('expiringSoon', () => {
  it('lists statements lapsing inside the window, soonest first', () => {
    const soon = expiringSoon(
      document(
        notAffected({ 'cradle:expires': '2026-10-30' }),
        notAffected({ 'cradle:expires': '2026-09-05' }),
        notAffected({ 'cradle:expires': '2026-09-20' }),
      ),
      NOW,
      30,
    )
    expect(soon.map((entry) => entry.inDays)).toEqual([8, 23])
  })

  it('leaves out ones that have already lapsed', () => {
    // Those are reported as findings again, which is a louder signal.
    expect(expiringSoon(document(notAffected({ 'cradle:expires': '2020-01-01' })), NOW)).toEqual([])
  })

  it('says nothing when there is no document', () => {
    expect(expiringSoon(undefined, NOW)).toEqual([])
  })
})
