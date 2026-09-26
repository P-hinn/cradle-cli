import { describe, expect, it } from 'vitest'
import { buildSarif } from '../../src/report/sarif.js'
import type { Finding, Severity } from '../../src/types/index.js'
import { validateSarif } from '../support/schema.js'

const MANIFEST = `{
  "name": "acme",
  "version": "1.0.0",
  "dependencies": {
    "minimist": "1.2.0",
    "lodash": "4.17.15"
  }
}`

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'GHSA-xvch-5gv4-984h',
    aliases: ['CVE-2021-44906'],
    summary: 'Prototype pollution in minimist',
    severity: 'critical',
    severitySource: 'cvss',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8, version: '3.1' },
    component: {
      bomRef: 'pkg:npm/minimist@1.2.0',
      name: 'minimist',
      version: '1.2.0',
      purl: 'pkg:npm/minimist@1.2.0',
      direct: true,
    },
    fixedIn: '1.2.6',
    path: ['acme', 'minimist'],
    dependents: ['acme'],
    references: [],
    osvUrl: 'https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h',
    ...overrides,
  }
}

/**
 * The same finding with no CVSS vector at all — not with an explicit undefined,
 * which under exactOptionalPropertyTypes is a different thing and would not
 * exercise the band-midpoint path.
 */
function findingWithoutCvss(overrides: Partial<Finding> = {}): Finding {
  const { cvss: _cvss, ...rest } = finding(overrides)
  return rest
}

const OPTIONS = {
  toolName: 'cradle-cli',
  toolVersion: '0.0.0',
  manifest: MANIFEST,
  manifestPath: 'package.json',
  lockfilePath: 'package-lock.json',
}

/**
 * SARIF is the one format GitHub Code Scanning and GitLab's security dashboard
 * both ingest, which means neither needs a cradle-specific integration. That is
 * worth more than a nicer format nobody consumes — and it only holds if the file
 * actually validates, so it is checked against the official schema rather than
 * against our own idea of the shape.
 */
describe('SARIF 2.1.0 export', () => {
  it('validates against the official schema', () => {
    const log = buildSarif([finding()], OPTIONS)
    const { valid, errors } = validateSarif(log)
    expect(errors.slice(0, 5)).toEqual([])
    expect(valid).toBe(true)
  })

  it('validates with no findings, with several, and offline', () => {
    for (const [label, log] of [
      ['empty', buildSarif([], OPTIONS)],
      [
        'several',
        buildSarif(
          [finding(), findingWithoutCvss({ id: 'GHSA-other', severity: 'low' as Severity })],
          OPTIONS,
        ),
      ],
      ['offline', buildSarif([], { ...OPTIONS, offline: true })],
      ['degraded', buildSarif([finding()], { ...OPTIONS, unavailable: ['EPSS (api.first.org)'] })],
    ] as const) {
      const { valid, errors } = validateSarif(log)
      expect(errors.slice(0, 3), label).toEqual([])
      expect(valid, label).toBe(true)
    }
  })

  it('carries a security-severity number, which is what the platforms sort on', () => {
    // Both GitHub and GitLab band by a number, not by a word. The computed CVSS
    // base score goes here where there is one.
    const log = buildSarif([finding()], OPTIONS)
    expect(log.runs[0]?.tool.driver.rules[0]?.properties['security-severity']).toBe('9.8')
  })

  it('uses the band midpoint where no CVSS vector was published, and says so', () => {
    // A midpoint is visibly a stand-in. 7.4 would look like a measurement.
    const log = buildSarif(
      [findingWithoutCvss({ severity: 'high' as Severity, severitySource: 'database' })],
      OPTIONS,
    )
    expect(log.runs[0]?.tool.driver.rules[0]?.properties['security-severity']).toBe('7.5')
    expect(log.runs[0]?.tool.driver.rules[0]?.help.text).toContain('not a measurement')
  })

  it('anchors a direct dependency to its line in package.json', () => {
    // An annotation next to the line you can change gets read; one on line 1 does
    // not.
    const log = buildSarif([finding()], OPTIONS)
    const location = log.runs[0]?.results[0]?.locations[0]?.physicalLocation
    expect(location?.artifactLocation.uri).toBe('package.json')
    expect(location?.region?.startLine).toBe(5)
  })

  it('anchors a transitive dependency to the lockfile instead', () => {
    // It is declared nowhere in package.json, so a line there would be a guess.
    const log = buildSarif(
      [
        finding({
          component: { ...finding().component, name: 'ms', direct: false },
          path: ['acme', 'minimist', 'ms'],
        }),
      ],
      OPTIONS,
    )
    const location = log.runs[0]?.results[0]?.locations[0]?.physicalLocation
    expect(location?.artifactLocation.uri).toBe('package-lock.json')
    expect(location?.region).toBeUndefined()
  })

  it('fingerprints without the version, matching the baseline’s identity', () => {
    // A patch bump of a still-vulnerable package must not read as a new finding,
    // or a platform reopens a dismissal for no reason (SPEC.md §6.4).
    const first = buildSarif([finding()], OPTIONS)
    const second = buildSarif(
      [finding({ component: { ...finding().component, version: '1.2.5' } })],
      OPTIONS,
    )
    expect(first.runs[0]?.results[0]?.partialFingerprints).toEqual(
      second.runs[0]?.results[0]?.partialFingerprints,
    )
  })

  it('groups several packages under one advisory rule', () => {
    const log = buildSarif(
      [
        finding(),
        finding({
          component: { ...finding().component, name: 'minimist-nested', direct: false },
        }),
      ],
      OPTIONS,
    )
    expect(log.runs[0]?.tool.driver.rules).toHaveLength(1)
    expect(log.runs[0]?.results).toHaveLength(2)
    expect(log.runs[0]?.results[1]?.ruleIndex).toBe(0)
  })

  it('marks the run unsuccessful when nothing was looked up', () => {
    // The difference between "we looked and found nothing" and "we did not look"
    // is the whole reason --offline exists, and a dashboard has to be able to
    // tell them apart.
    const offline = buildSarif([], { ...OPTIONS, offline: true })
    expect(offline.runs[0]?.invocations[0]?.executionSuccessful).toBe(false)
    expect(
      offline.runs[0]?.invocations[0]?.toolExecutionNotifications?.[0]?.message.text,
    ).toContain('not checked')

    const online = buildSarif([], OPTIONS)
    expect(online.runs[0]?.invocations[0]?.executionSuccessful).toBe(true)
  })

  it('reports an unreachable exploit source as a notification', () => {
    const log = buildSarif([finding()], { ...OPTIONS, unavailable: ['CISA KEV (cisa.gov)'] })
    const notifications = log.runs[0]?.invocations[0]?.toolExecutionNotifications ?? []
    expect(notifications.map((entry) => entry.message.text).join(' ')).toContain('CISA KEV')
  })

  it('tags a known-exploited finding so a dashboard can filter on it', () => {
    const log = buildSarif(
      [
        finding({
          exploit: { knownExploited: true, knownExploitedSince: '2024-05-01', epss: 0.9 },
        }),
      ],
      OPTIONS,
    )
    expect(log.runs[0]?.tool.driver.rules[0]?.properties.tags).toContain('exploit/cisa-kev')
    expect(log.runs[0]?.results[0]?.message.text).toContain('since 2024-05-01')
    expect(log.runs[0]?.results[0]?.message.text).toContain('EPSS 90.0%')
  })

  it('keeps the abstract-versus-reachable distinction in the help text', () => {
    // The sentence the whole report rests on. A dashboard shows the help text, so
    // it has to be there too.
    const log = buildSarif([finding()], OPTIONS)
    const rule = log.runs[0]?.tool.driver.rules[0]
    expect(rule?.help.text).toContain('says nothing about whether the vulnerable code is reachable')
    expect(rule?.help.markdown).toContain('reachable')
  })

  it('maps severities onto the four levels SARIF has', () => {
    const levels = (['critical', 'high', 'medium', 'low', 'none', 'unknown'] as const).map(
      (severity) =>
        buildSarif([findingWithoutCvss({ severity })], OPTIONS).runs[0]?.results[0]?.level,
    )
    expect(levels).toEqual(['error', 'error', 'warning', 'note', 'none', 'warning'])
  })

  it('works without a manifest at all', () => {
    // A scan can be pointed at a directory whose package.json is unreadable; the
    // result still has to be a valid document.
    const log = buildSarif([finding()], { toolName: 'cradle-cli', toolVersion: '0.0.0' })
    expect(log.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      'package.json',
    )
    expect(validateSarif(log).valid).toBe(true)
  })
})
