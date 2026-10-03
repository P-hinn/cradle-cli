import { describe, expect, it } from 'vitest'
import {
  describeReasons,
  describeThresholds,
  failingFindings,
  gateIsOff,
} from '../../src/core/vulns/gate.js'
import type { Finding, Severity } from '../../src/types/index.js'

function finding(id: string, severity: Severity, exploit?: Finding['exploit']): Finding {
  return {
    id,
    aliases: [],
    summary: '',
    severity,
    severitySource: 'cvss',
    component: {
      bomRef: `pkg:npm/${id}@1.0.0`,
      name: id,
      version: '1.0.0',
      purl: `pkg:npm/${id}@1.0.0`,
      direct: true,
    },
    path: ['app', id],
    dependents: ['app'],
    references: [],
    osvUrl: '',
    ...(exploit === undefined ? {} : { exploit }),
  }
}

const SEVERITY_ONLY = { severity: 'high' as const, kev: false }

describe('failingFindings — severity', () => {
  it('catches at and above the threshold', () => {
    const failures = failingFindings(
      [finding('crit', 'critical'), finding('high', 'high'), finding('med', 'medium')],
      SEVERITY_ONLY,
    )
    expect(failures.map((failure) => failure.finding.id)).toEqual(['crit', 'high'])
  })

  it('catches nothing when the severity dimension is off', () => {
    expect(
      failingFindings([finding('crit', 'critical')], { severity: 'never', kev: false }),
    ).toEqual([])
  })
})

describe('failingFindings — active exploitation', () => {
  it('catches a finding below the severity threshold', () => {
    // The whole point: a medium that CISA records as being exploited right now
    // is more urgent than a critical nobody has ever touched.
    const exploited = finding('med', 'medium', { knownExploited: true })
    const failures = failingFindings([exploited], { severity: 'critical', kev: true })

    expect(failures).toHaveLength(1)
    expect(failures[0]?.reasons).toEqual(['kev'])
  })

  it('is off unless asked for', () => {
    const exploited = finding('med', 'medium', { knownExploited: true })
    expect(failingFindings([exploited], { severity: 'critical', kev: false })).toEqual([])
  })

  it('does not treat an absent signal as a negative one', () => {
    // A finding with no CVE alias has no signals at all. It must not fail, and
    // it must not silently pass as "not exploited" either — that is the caller's
    // problem, handled by refusing the flag when the lookup is switched off.
    expect(failingFindings([finding('none', 'low')], { severity: 'never', kev: true })).toEqual([])
  })
})

describe('failingFindings — EPSS', () => {
  it('catches at and above the probability', () => {
    const findings = [
      finding('likely', 'low', { epss: 0.62 }),
      finding('borderline', 'low', { epss: 0.5 }),
      finding('unlikely', 'low', { epss: 0.01 }),
    ]
    const failures = failingFindings(findings, { severity: 'never', kev: false, epss: 0.5 })
    expect(failures.map((failure) => failure.finding.id)).toEqual(['likely', 'borderline'])
  })

  it('ignores a finding with no EPSS score', () => {
    expect(
      failingFindings([finding('none', 'low')], { severity: 'never', kev: false, epss: 0.1 }),
    ).toEqual([])
  })
})

describe('failingFindings — several thresholds at once', () => {
  it('records every reason a finding was caught by', () => {
    // Which threshold caught it changes what to do about it, so one reason is
    // not enough.
    const both = finding('both', 'critical', { knownExploited: true, epss: 0.9 })
    const failures = failingFindings([both], { severity: 'high', kev: true, epss: 0.5 })
    expect(failures[0]?.reasons).toEqual(['severity', 'kev', 'epss'])
  })

  it('reports a finding once however many thresholds it crosses', () => {
    const both = finding('both', 'critical', { knownExploited: true })
    expect(failingFindings([both], { severity: 'high', kev: true })).toHaveLength(1)
  })
})

describe('gateIsOff', () => {
  it.each([
    [{ severity: 'never' as const, kev: false }, true],
    [{ severity: 'high' as const, kev: false }, false],
    [{ severity: 'never' as const, kev: true }, false],
    [{ severity: 'never' as const, kev: false, epss: 0.5 }, false],
  ])('%o -> %s', (thresholds, expected) => {
    expect(gateIsOff(thresholds)).toBe(expected)
  })
})

describe('describeThresholds', () => {
  it.each([
    [{ severity: 'high' as const, kev: false }, 'at or above high'],
    [{ severity: 'never' as const, kev: true }, 'known to be exploited'],
    [{ severity: 'never' as const, kev: false, epss: 0.5 }, 'EPSS at or above 50%'],
    [
      { severity: 'high' as const, kev: true, epss: 0.25 },
      'at or above high, known to be exploited or EPSS at or above 25%',
    ],
    [{ severity: 'never' as const, kev: false }, 'nothing (the gate is off)'],
  ])('%o reads as "%s"', (thresholds, expected) => {
    expect(describeThresholds(thresholds)).toBe(expected)
  })
})

describe('describeReasons', () => {
  it('names each one', () => {
    expect(describeReasons(['severity'])).toBe('severity')
    expect(describeReasons(['kev', 'epss'])).toBe('exploited + EPSS')
  })
})
