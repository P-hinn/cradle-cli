import { describe, expect, it } from 'vitest'
import { MemoryCache } from '../../src/core/vulns/cache.js'
import {
  byExploitPriority,
  cvesOf,
  fetchExploitSignals,
  withExploitSignals,
} from '../../src/core/vulns/priority.js'
import { severityRank } from '../../src/core/vulns/severity.js'
import type { Finding, Severity } from '../../src/types/index.js'
import { fakeOsv } from '../support/osv.js'

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'GHSA-xvch-5gv4-984h',
    aliases: ['CVE-2021-44906'],
    summary: 'Prototype pollution',
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
    ...overrides,
  }
}

function options(overrides: Parameters<typeof fakeOsv>[0] = {}) {
  const osv = fakeOsv(overrides)
  return {
    osv,
    input: { fetch: osv.fetch, cache: new MemoryCache(), today: '2026-09-26' },
  }
}

/**
 * A CVSS base score answers "how bad would this be". Triage under a clock needs
 * "is anyone doing it", which is a different question — and the two disagree
 * often enough that ordering by severity alone puts the wrong thing first.
 *
 * Both signals are additional. `--fail-on` stays CVSS-based, because a gate whose
 * threshold moves daily with somebody else's model goes red overnight for reasons
 * nobody on the team changed.
 */
describe('exploit signals', () => {
  it('collects the CVE aliases, because both sources are keyed on CVE', () => {
    // cradle keys npm advisories on GHSA, so the CVE lives in aliases.
    expect(cvesOf([finding()])).toEqual(['CVE-2021-44906'])
    expect(cvesOf([finding({ aliases: [] })])).toEqual([])
    expect(cvesOf([finding({ id: 'CVE-2020-8203', aliases: [] })])).toEqual(['CVE-2020-8203'])
  })

  it('deduplicates and sorts, so one CVE is asked about once', () => {
    const cves = cvesOf([
      finding(),
      finding({ id: 'GHSA-other' }),
      finding({ aliases: ['CVE-2020-8203'] }),
    ])
    expect(cves).toEqual(['CVE-2020-8203', 'CVE-2021-44906'])
  })

  it('reads the EPSS score and percentile', async () => {
    const { input } = options()
    const { byCve, unavailable } = await fetchExploitSignals([finding()], input)

    expect(unavailable).toEqual([])
    expect(byCve.get('CVE-2021-44906')?.epss).toBeCloseTo(0.04581)
    expect(byCve.get('CVE-2021-44906')?.epssPercentile).toBeCloseTo(0.91291)
    // The model run date, so a stale number is visibly stale rather than just old.
    expect(byCve.get('CVE-2021-44906')?.epssDate).toBe('2026-09-25')
  })

  it('reads the CISA catalogue and the date it was added', async () => {
    const { input } = options()
    const { byCve } = await fetchExploitSignals([finding({ aliases: ['CVE-2020-8203'] })], input)

    const signals = byCve.get('CVE-2020-8203')
    expect(signals?.knownExploited).toBe(true)
    expect(signals?.knownExploitedSince).toBe('2024-05-01')
  })

  it('leaves a CVE that is on neither list absent, not zero', async () => {
    // "No data" and "no risk" are different answers, and a zero would assert the
    // second one.
    const { input } = options()
    const { byCve } = await fetchExploitSignals([finding({ aliases: ['CVE-1999-0001'] })], input)
    expect(byCve.has('CVE-1999-0001')).toBe(false)
  })

  it('asks nothing when no finding carries a CVE', async () => {
    const { osv, input } = options()
    const result = await fetchExploitSignals([finding({ aliases: [] })], input)
    expect(result.byCve.size).toBe(0)
    expect(osv.priorityCalls).toEqual([])
  })

  it('serves a repeat run from the cache', async () => {
    // Both sources are re-keyed daily, so a second run on the same day is free
    // and a run the next day is not - which is the behaviour we want, because
    // yesterday's EPSS is a different answer.
    const { osv, input } = options()
    await fetchExploitSignals([finding()], input)
    const cold = osv.priorityCalls.length
    expect(cold).toBe(2)

    await fetchExploitSignals([finding()], input)
    expect(osv.priorityCalls).toHaveLength(cold)

    await fetchExploitSignals([finding()], { ...input, today: '2026-09-27' })
    expect(osv.priorityCalls.length).toBeGreaterThan(cold)
  })

  it('names a source it could not reach, and carries on', async () => {
    // These improve the ordering of work; they are not the purpose of the tool,
    // and an outage at FIRST must not fail a scan. It must not fail silently
    // either, or a missing column reads as "no signal".
    const { input } = options({ epssDown: true })
    const { byCve, unavailable } = await fetchExploitSignals(
      [finding({ aliases: ['CVE-2020-8203'] })],
      input,
    )

    expect(unavailable).toEqual(['EPSS (api.first.org)'])
    // And the other source still answered.
    expect(byCve.get('CVE-2020-8203')?.knownExploited).toBe(true)
  })

  it('survives both sources being down', async () => {
    const { input } = options({ epssDown: true, kevDown: true })
    const { byCve, unavailable } = await fetchExploitSignals([finding()], input)
    expect(byCve.size).toBe(0)
    expect(unavailable).toHaveLength(2)
  })

  it('attaches the signals to the finding by its alias', async () => {
    const { input } = options()
    const { byCve } = await fetchExploitSignals([finding()], input)
    const enriched = withExploitSignals(finding(), byCve)
    expect(enriched.exploit?.epss).toBeCloseTo(0.04581)

    // And leaves a finding with no match untouched rather than giving it an
    // empty object, which would render as a column with nothing in it.
    expect(withExploitSignals(finding({ aliases: [] }), byCve).exploit).toBeUndefined()
  })
})

describe('exploit ordering', () => {
  const rank = (candidate: Finding): number => severityRank(candidate.severity)
  const sorted = (findings: Finding[]): string[] =>
    [...findings].sort((a, b) => byExploitPriority(a, b, rank)).map((f) => f.id)

  it('puts a known-exploited medium ahead of an untouched critical', () => {
    // The whole reason the ranking exists. Sorting by severity says the opposite.
    const known = finding({
      id: 'known-medium',
      severity: 'medium' as Severity,
      exploit: { knownExploited: true },
    })
    const quiet = finding({ id: 'quiet-critical', severity: 'critical' as Severity })
    expect(sorted([quiet, known])).toEqual(['known-medium', 'quiet-critical'])
  })

  it('orders by EPSS when neither is on the CISA list', () => {
    const likely = finding({ id: 'likely', severity: 'low' as Severity, exploit: { epss: 0.9 } })
    const unlikely = finding({
      id: 'unlikely',
      severity: 'high' as Severity,
      exploit: { epss: 0.01 },
    })
    expect(sorted([unlikely, likely])).toEqual(['likely', 'unlikely'])
  })

  it('falls back to severity, so a list with no signals sorts as before', () => {
    const critical = finding({ id: 'critical', severity: 'critical' as Severity })
    const low = finding({ id: 'low', severity: 'low' as Severity })
    expect(sorted([low, critical])).toEqual(['critical', 'low'])
  })

  it('sorts a finding with no data below one with a score, not above', () => {
    // Absent data must not win the top of the list by default.
    const scored = finding({ id: 'scored', severity: 'low' as Severity, exploit: { epss: 0.001 } })
    const unknown = finding({ id: 'unknown', severity: 'low' as Severity })
    expect(sorted([unknown, scored])).toEqual(['scored', 'unknown'])
  })
})
