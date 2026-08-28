import { describe, expect, it } from 'vitest'
import { findingsWithoutFix, recommendUpgrades } from '../../src/core/vulns/recommend.js'
import type { Finding, Severity } from '../../src/types/index.js'

function finding(
  overrides: Partial<Finding> & { name: string; version: string; severity: Severity },
): Finding {
  const { name, version, severity, ...rest } = overrides
  return {
    id: rest.id ?? `GHSA-${name}-${severity}`,
    aliases: [],
    summary: '',
    severity,
    severitySource: 'cvss',
    component: {
      bomRef: `pkg:npm/${name}@${version}`,
      name,
      version,
      purl: `pkg:npm/${name}@${version}`,
      direct: rest.component?.direct ?? true,
    },
    path: [],
    dependents: [],
    references: [],
    osvUrl: '',
    ...rest,
  }
}

describe('recommendUpgrades', () => {
  it('collapses several advisories on one package into one upgrade', () => {
    const recommendations = recommendUpgrades([
      finding({ name: 'lodash', version: '4.17.15', severity: 'medium', fixedIn: '4.17.19' }),
      finding({ name: 'lodash', version: '4.17.15', severity: 'high', fixedIn: '4.17.21' }),
      finding({ name: 'lodash', version: '4.17.15', severity: 'low', fixedIn: '4.18.0' }),
    ])

    expect(recommendations).toHaveLength(1)
    // The target has to clear all three, so it is the highest of the fixes.
    expect(recommendations[0]).toMatchObject({
      package: 'lodash',
      from: '4.17.15',
      to: '4.18.0',
      findingCount: 3,
      worstSeverity: 'high',
    })
  })

  it('puts the worst severity first', () => {
    const recommendations = recommendUpgrades([
      finding({ name: 'a', version: '1.0.0', severity: 'medium', fixedIn: '1.1.0' }),
      finding({ name: 'b', version: '1.0.0', severity: 'critical', fixedIn: '1.1.0' }),
      finding({ name: 'c', version: '1.0.0', severity: 'high', fixedIn: '1.1.0' }),
    ])
    expect(recommendations.map((r) => r.package)).toEqual(['b', 'c', 'a'])
  })

  it('breaks a severity tie on how much the upgrade clears', () => {
    const recommendations = recommendUpgrades([
      finding({ name: 'one', version: '1.0.0', severity: 'high', fixedIn: '1.1.0' }),
      finding({ name: 'two', version: '1.0.0', severity: 'high', fixedIn: '1.1.0', id: 'x' }),
      finding({ name: 'two', version: '1.0.0', severity: 'high', fixedIn: '1.2.0', id: 'y' }),
    ])
    expect(recommendations[0]?.package).toBe('two')
  })

  it('keeps different versions of one package apart', () => {
    const recommendations = recommendUpgrades([
      finding({ name: 'ms', version: '2.0.0', severity: 'high', fixedIn: '2.1.0' }),
      finding({ name: 'ms', version: '2.1.3', severity: 'high', fixedIn: '2.2.0' }),
    ])
    expect(recommendations).toHaveLength(2)
    expect(recommendations.map((r) => r.from).sort()).toEqual(['2.0.0', '2.1.3'])
  })

  it('says nothing about findings that have no fix', () => {
    expect(recommendUpgrades([finding({ name: 'a', version: '1.0.0', severity: 'high' })])).toEqual(
      [],
    )
  })
})

describe('findingsWithoutFix', () => {
  it('picks out the ones that need a decision rather than an upgrade', () => {
    const unfixable = finding({ name: 'a', version: '1.0.0', severity: 'high' })
    const fixable = finding({ name: 'b', version: '1.0.0', severity: 'high', fixedIn: '1.1.0' })
    expect(findingsWithoutFix([unfixable, fixable])).toEqual([unfixable])
  })
})
