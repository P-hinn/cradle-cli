import { describe, expect, it } from 'vitest'
import { evaluateReadiness, type ReadinessInput } from '../../src/core/readiness/checks.js'
import type { PackageFacts } from '../../src/core/readiness/registry.js'
import type {
  BaselineDocument,
  DependencyGraph,
  Finding,
  ReadinessCheck,
  ResolvedComponent,
} from '../../src/types/index.js'

const NOW = new Date('2026-08-28T00:00:00.000Z')

function component(overrides: Partial<ResolvedComponent> = {}): ResolvedComponent {
  const name = overrides.name ?? 'lodash'
  const version = overrides.version ?? '4.17.15'
  return {
    bomRef: `pkg:npm/${name}@${version}`,
    name,
    version,
    purl: `pkg:npm/${name}@${version}`,
    location: `node_modules/${name}`,
    licenses: [{ kind: 'id', id: 'MIT' }],
    licenseUnknown: false,
    hashes: [],
    direct: true,
    dev: false,
    workspace: false,
    kinds: ['prod'],
    ...overrides,
  }
}

function graph(...components: ResolvedComponent[]): DependencyGraph {
  return {
    packageManager: 'npm',
    projectDir: '/app',
    root: { bomRef: 'pkg:npm/app@1.0.0', name: 'app', version: '1.0.0', licenses: [] },
    components: components.length > 0 ? components : [component()],
    edges: new Map(),
    includeDev: false,
    workspaces: [],
  }
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'GHSA-a',
    aliases: [],
    summary: '',
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
    osvUrl: '',
    ...overrides,
  }
}

function evaluate(overrides: Partial<ReadinessInput> = {}): Map<string, ReadinessCheck> {
  const report = evaluateReadiness({
    graph: graph(),
    findings: [],
    suppressed: [],
    baseline: undefined,
    config: undefined,
    now: NOW,
    offline: false,
    packageFacts: new Map<string, PackageFacts>(),
    ...overrides,
  })
  return new Map(report.checks.map((check) => [check.id, check]))
}

describe('SBOM freshness', () => {
  it('is open when no SBOM has been written', () => {
    expect(evaluate().get('sbom')?.status).toBe('open')
  })

  it('is open when the lockfile changed after the SBOM was written', () => {
    const check = evaluate({
      sbomWrittenAt: new Date('2026-01-01'),
      lockfileChangedAt: new Date('2026-06-01'),
    }).get('sbom')
    expect(check?.status).toBe('open')
    expect(check?.detail).toContain('older than the lockfile')
  })

  it('is met when the SBOM is at least as new as the lockfile', () => {
    expect(
      evaluate({
        sbomWrittenAt: new Date('2026-06-02'),
        lockfileChangedAt: new Date('2026-06-01'),
      }).get('sbom')?.status,
    ).toBe('met')
  })
})

describe('disclosure policy', () => {
  it('is open without a SECURITY.md', () => {
    expect(evaluate().get('disclosure')?.status).toBe('open')
  })

  it('is only partial when the policy names no way to reach anyone', () => {
    // A policy nobody can act on is half a policy.
    const check = evaluate({ securityPolicy: '# Security\n\nWe take security seriously.' }).get(
      'disclosure',
    )
    expect(check?.status).toBe('partial')
    expect(check?.nextStep).toContain('address')
  })

  it('accepts an email address', () => {
    expect(
      evaluate({ securityPolicy: 'Report to security@acme.example.' }).get('disclosure')?.status,
    ).toBe('met')
  })

  it('accepts a reporting URL', () => {
    expect(
      evaluate({
        securityPolicy: 'Use https://acme.example/security/report to reach us.',
      }).get('disclosure')?.status,
    ).toBe('met')
  })

  it('suggests the configured contact when one is missing from the file', () => {
    const check = evaluate({
      securityPolicy: '# Security',
      config: { contactEmail: 'security@acme.example' },
    }).get('disclosure')
    expect(check?.nextStep).toContain('security@acme.example')
  })
})

describe('support period', () => {
  it('is open when nothing is recorded', () => {
    expect(evaluate().get('support-period')?.status).toBe('open')
  })

  it('is open when the recorded period has already ended', () => {
    const check = evaluate({ config: { supportPeriodEnd: '2020-01-01' } }).get('support-period')
    expect(check?.status).toBe('open')
    expect(check?.detail).toContain('ended on 2020-01-01')
  })

  it('is only partial without a start date, because the floor cannot be checked', () => {
    expect(
      evaluate({ config: { supportPeriodEnd: '2032-01-01' } }).get('support-period')?.status,
    ).toBe('partial')
  })

  it('treats exactly five calendar years as meeting the floor', () => {
    // Five years is 1826 days across a leap year. Dividing by an average year
    // length reads that as 4.999 and would tell a compliant user otherwise.
    const check = evaluate({
      config: { placedOnMarket: '2026-01-15', supportPeriodEnd: '2031-01-15' },
    }).get('support-period')
    expect(check?.status).toBe('met')
    expect(check?.detail).toContain('clears the five-year floor')
  })

  it('catches one day short', () => {
    expect(
      evaluate({
        config: { placedOnMarket: '2026-01-15', supportPeriodEnd: '2031-01-14' },
      }).get('support-period')?.status,
    ).toBe('partial')
  })

  it('names the date that would satisfy the floor', () => {
    const check = evaluate({
      config: { placedOnMarket: '2026-01-15', supportPeriodEnd: '2030-06-01' },
    }).get('support-period')
    expect(check?.nextStep).toContain('2031-01-15')
  })

  it('mentions the ten-year update and retention obligations', () => {
    const check = evaluate({
      config: { placedOnMarket: '2026-01-15', supportPeriodEnd: '2031-01-15' },
    }).get('support-period')
    expect(check?.nextStep).toContain('ten years')
  })
})

describe('licence coverage', () => {
  it('is met when every component declares one', () => {
    expect(evaluate().get('licences')?.status).toBe('met')
  })

  it('names the components that do not', () => {
    const check = evaluate({
      graph: graph(
        component(),
        component({ name: '@acme/ui', licenses: [], licenseUnknown: true }),
      ),
    }).get('licences')
    expect(check?.status).toBe('partial')
    expect(check?.detail).toContain('@acme/ui')
  })
})

describe('maintenance', () => {
  it('cannot be assessed offline, and says so instead of guessing', () => {
    const check = evaluate({ offline: true }).get('maintenance')
    expect(check?.status).toBe('not-assessable')
    expect(check?.nextStep).toContain('--offline')
  })

  it('is met when nothing is deprecated or stale', () => {
    expect(
      evaluate({
        packageFacts: new Map([['pkg:npm/lodash@4.17.15', { lastPublish: '2026-04-01' }]]),
      }).get('maintenance')?.status,
    ).toBe('met')
  })

  it('reports a deprecated package', () => {
    const check = evaluate({
      packageFacts: new Map([['pkg:npm/lodash@4.17.15', { deprecated: 'use something else' }]]),
    }).get('maintenance')
    expect(check?.status).toBe('partial')
    expect(check?.detail).toContain('1 deprecated')
  })

  it('reports a package with no release in two years', () => {
    const check = evaluate({
      packageFacts: new Map([['pkg:npm/lodash@4.17.15', { lastPublish: '2023-01-01' }]]),
    }).get('maintenance')
    expect(check?.status).toBe('partial')
    expect(check?.detail).toContain('2023-01-01')
  })

  it('states which part of the tree each signal covers', () => {
    // Release dates are only fetched for direct dependencies; the report must not
    // imply the whole tree was checked.
    const check = evaluate({
      packageFacts: new Map([['pkg:npm/lodash@4.17.15', { lastPublish: '2026-04-01' }]]),
    }).get('maintenance')
    expect(check?.detail).toContain('release dates for the direct dependencies only')
  })
})

describe('unresolved findings', () => {
  it('is met when there is nothing open', () => {
    expect(evaluate().get('unresolved')?.status).toBe('met')
  })

  it('mentions VEX-ruled findings without counting them as open', () => {
    const check = evaluate({ suppressed: [finding()] }).get('unresolved')
    expect(check?.status).toBe('met')
    expect(check?.detail).toContain('ruled out by VEX')
  })

  it('is only partial when everything open can be fixed by upgrading', () => {
    expect(
      evaluate({ findings: [finding({ fixedIn: '4.17.21' })] }).get('unresolved')?.status,
    ).toBe('partial')
  })

  it('is open when a finding has no fix and no ruling', () => {
    // This is the category that turns into a 24-hour deadline if it is ever
    // actively exploited.
    const check = evaluate({ findings: [finding()] }).get('unresolved')
    expect(check?.status).toBe('open')
    expect(check?.nextStep).toContain('cradle suppress')
    expect(check?.nextStep).toContain('24 hours')
  })

  it('counts a baselined finding as open, because a baseline is not a ruling', () => {
    // cradle check stays green on it; this list must not, or the baseline would
    // quietly launder findings exactly where it matters most.
    const baseline: BaselineDocument = {
      schemaVersion: 1,
      timestamp: NOW.toISOString(),
      tool: { name: 'cradle-cli', version: '0.0.0' },
      project: { name: 'app', version: '1.0.0' },
      scope: 'production',
      entries: [
        { id: 'GHSA-a', package: 'lodash', severity: 'high', acceptedAt: NOW.toISOString() },
      ],
    }
    const check = evaluate({ findings: [finding()], baseline }).get('unresolved')
    expect(check?.status).toBe('open')
    expect(check?.detail).toContain('is not a ruling')
  })
})

describe('evaluateReadiness', () => {
  it('counts the statuses', () => {
    const report = evaluateReadiness({
      graph: graph(),
      findings: [],
      suppressed: [],
      baseline: undefined,
      config: undefined,
      now: NOW,
      offline: true,
    })
    expect(report.checks).toHaveLength(6)
    const total = Object.values(report.counts).reduce((sum, count) => sum + count, 0)
    expect(total).toBe(6)
    expect(report.counts['not-assessable']).toBe(1)
  })

  it('gives every check a next step', () => {
    // Including the ones that pass: "nothing to do" is still an answer.
    for (const check of evaluateReadiness({
      graph: graph(),
      findings: [],
      suppressed: [],
      baseline: undefined,
      config: undefined,
      now: NOW,
      offline: false,
    }).checks) {
      expect(check.nextStep.length).toBeGreaterThan(0)
      expect(check.detail.length).toBeGreaterThan(0)
    }
  })
})
