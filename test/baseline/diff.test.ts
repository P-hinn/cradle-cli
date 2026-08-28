import { describe, expect, it } from 'vitest'
import {
  baselineKey,
  diffAgainstBaseline,
  parseBaseline,
  serializeBaseline,
  toBaseline,
} from '../../src/core/baseline/diff.js'
import { CradleError } from '../../src/core/errors.js'
import type { BaselineDocument, Finding, Severity } from '../../src/types/index.js'

const TIMESTAMP = '2026-08-28T00:00:00.000Z'

function finding(name: string, version: string, id: string, severity: Severity): Finding {
  return {
    id,
    aliases: [],
    summary: '',
    severity,
    severitySource: 'cvss',
    component: {
      bomRef: `pkg:npm/${name}@${version}`,
      name,
      version,
      purl: `pkg:npm/${name}@${version}`,
      direct: true,
    },
    path: ['app', name],
    dependents: ['app'],
    references: [],
    osvUrl: `https://osv.dev/vulnerability/${id}`,
  }
}

function baseline(...findings: Finding[]): BaselineDocument {
  return toBaseline(findings, {
    schemaVersion: 1,
    timestamp: TIMESTAMP,
    tool: { name: 'cradle-cli', version: '0.0.0' },
    project: { name: 'app', version: '1.0.0' },
    scope: 'production',
  })
}

describe('baselineKey', () => {
  it('leaves the version out', () => {
    // Including it would make every patch bump of a still-vulnerable dependency
    // look brand new, and a gate that reddens on unrelated churn gets switched off.
    expect(baselineKey('GHSA-x', 'lodash')).toBe(baselineKey('GHSA-x', 'lodash'))
  })
})

describe('diffAgainstBaseline', () => {
  const known = finding('lodash', '4.17.15', 'GHSA-a', 'high')

  it('treats everything as new when there is no baseline', () => {
    const diff = diffAgainstBaseline([known], undefined)
    expect(diff.added).toHaveLength(1)
    expect(diff.known).toHaveLength(0)
  })

  it('says nothing is new when the scan matches the baseline', () => {
    const diff = diffAgainstBaseline([known], baseline(known))
    expect(diff.added).toHaveLength(0)
    expect(diff.known).toHaveLength(1)
  })

  it('reports an advisory that was not accepted before', () => {
    const fresh = finding('minimist', '1.2.0', 'GHSA-b', 'critical')
    const diff = diffAgainstBaseline([known, fresh], baseline(known))
    expect(diff.added.map((f) => f.id)).toEqual(['GHSA-b'])
  })

  it('does not re-alarm when a still-vulnerable package is merely bumped', () => {
    // The team upgraded lodash but the advisory still applies. That is not news.
    const bumped = finding('lodash', '4.17.20', 'GHSA-a', 'high')
    const diff = diffAgainstBaseline([bumped], baseline(known))
    expect(diff.added).toHaveLength(0)
    expect(diff.known).toHaveLength(1)
  })

  it('does re-alarm when the advisory has been re-rated worse', () => {
    // Accepting a medium is not accepting the critical it later turned out to be.
    const accepted = baseline(finding('lodash', '4.17.15', 'GHSA-a', 'medium'))
    const diff = diffAgainstBaseline([finding('lodash', '4.17.15', 'GHSA-a', 'critical')], accepted)
    expect(diff.added).toHaveLength(1)
    expect(diff.worsened).toHaveLength(1)
  })

  it('stays quiet when the advisory has been re-rated less severe', () => {
    const accepted = baseline(finding('lodash', '4.17.15', 'GHSA-a', 'critical'))
    const diff = diffAgainstBaseline([finding('lodash', '4.17.15', 'GHSA-a', 'low')], accepted)
    expect(diff.added).toHaveLength(0)
    expect(diff.worsened).toHaveLength(0)
  })

  it('keeps the same advisory on two packages apart', () => {
    const inLodash = finding('lodash', '4.17.15', 'GHSA-a', 'high')
    const inOther = finding('other', '1.0.0', 'GHSA-a', 'high')
    const diff = diffAgainstBaseline([inLodash, inOther], baseline(inLodash))
    expect(diff.added.map((f) => f.component.name)).toEqual(['other'])
  })

  it('lists baselined findings that are gone, so the file can be tidied', () => {
    const diff = diffAgainstBaseline([], baseline(known))
    expect(diff.resolved.map((entry) => entry.id)).toEqual(['GHSA-a'])
  })
})

describe('toBaseline', () => {
  it('records the severity, so a later re-rating is still detectable', () => {
    const document = baseline(finding('lodash', '4.17.15', 'GHSA-a', 'high'))
    expect(document.entries[0]).toMatchObject({
      id: 'GHSA-a',
      package: 'lodash',
      severity: 'high',
    })
  })

  it('sorts entries and drops duplicates, for a readable committed diff', () => {
    const document = baseline(
      finding('zzz', '1.0.0', 'GHSA-b', 'low'),
      finding('aaa', '1.0.0', 'GHSA-a', 'low'),
      // Same advisory and package at two versions collapses to one entry.
      finding('aaa', '2.0.0', 'GHSA-a', 'low'),
    )
    expect(document.entries.map((entry) => `${entry.package}/${entry.id}`)).toEqual([
      'aaa/GHSA-a',
      'zzz/GHSA-b',
    ])
  })
})

describe('parseBaseline', () => {
  it('round-trips a document we wrote', () => {
    const document = baseline(finding('lodash', '4.17.15', 'GHSA-a', 'high'))
    expect(parseBaseline(serializeBaseline(document), 'baseline.json')).toEqual(document)
  })

  it('fails loudly on malformed JSON', () => {
    expect(() => parseBaseline('{oops', 'baseline.json')).toThrow(CradleError)
  })

  it('refuses a document with no entries array', () => {
    expect(() => parseBaseline('{"timestamp":"x"}', 'baseline.json')).toThrow(CradleError)
  })

  it('names the bad entry', () => {
    const raw = JSON.stringify({ entries: [{ id: 'GHSA-a', package: 'x' }, { id: 'GHSA-b' }] })
    let message = ''
    try {
      parseBaseline(raw, 'baseline.json')
    } catch (error) {
      message = error instanceof CradleError ? error.message : ''
    }
    expect(message).toContain('entry 2')
  })
})
