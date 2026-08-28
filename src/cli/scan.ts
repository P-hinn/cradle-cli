import { randomUUID } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { CradleError } from '../core/errors.js'
import { buildBom } from '../core/sbom/cyclonedx.js'
import { expiringSoon } from '../core/vex/apply.js'
import type { VulnCache } from '../core/vulns/cache.js'
import { countBySeverity } from '../core/vulns/findings.js'
import { findingsWithoutFix, recommendUpgrades } from '../core/vulns/recommend.js'
import { buildReport } from '../report/html.js'
import {
  ARTIFACT_SCHEMA_VERSION,
  type CycloneDxSpecVersion,
  type DependencyGraph,
  type Finding,
  type FindingsDocument,
  type ReadinessReport,
  SEVERITY_ORDER,
  SUPPORTED_SPEC_VERSIONS,
  type VexDocument,
} from '../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../version.generated.js'
import { runPipeline } from './pipeline.js'
import { gatherReadiness } from './readiness.js'

export const SCAN_HELP = `cradle scan — resolve dependencies, write an SBOM and look up vulnerabilities

Usage:
  cradle scan [path] [options]

Options:
  --include-dev            Include development dependencies (default: production only)
  --offline                Skip the vulnerability lookup and mark the output offline
  --no-cache               Do not read or write the local advisory cache
  --spec-version <1.6|1.7> CycloneDX version to emit (default: 1.6)
  --output-dir <dir>       Where to write results (default: .cradle)
  -h, --help               Show this help
`

export interface ScanDependencies {
  fetch?: typeof globalThis.fetch
  cache?: VulnCache
  now?: () => Date
  serialNumber?: () => string
}

export async function runScan(
  argv: string[],
  stdout: NodeJS.WritableStream,
  dependencies: ScanDependencies = {},
): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      'include-dev': { type: 'boolean', default: false },
      offline: { type: 'boolean', default: false },
      // Declared literally, not as a negation: node's parseArgs has no --no-
      // prefix support, so `cache: {...}` alone would reject `--no-cache`.
      'no-cache': { type: 'boolean', default: false },
      'spec-version': { type: 'string', default: '1.6' },
      'output-dir': { type: 'string', default: '.cradle' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  if (values.help === true) {
    stdout.write(SCAN_HELP)
    return 0
  }

  const specVersion = values['spec-version']
  if (!isSpecVersion(specVersion)) {
    throw new CradleError(
      `Unsupported CycloneDX version '${specVersion}'`,
      `Pass one of: ${SUPPORTED_SPEC_VERSIONS.join(', ')}.`,
    )
  }

  const projectDir = resolve(positionals[0] ?? process.cwd())
  const outputDir = resolve(projectDir, values['output-dir'] ?? '.cradle')
  const includeDev = values['include-dev'] === true
  const offline = values.offline === true
  const now = dependencies.now ?? (() => new Date())

  // Shared with `check`, so a green gate and a clean report can never disagree
  // about what a finding is.
  const { graph, findings, suppressed, vex, unmatchedStatements, cacheHits } = await runPipeline({
    projectDir,
    outputDir,
    includeDev,
    offline,
    useCache: values['no-cache'] !== true,
    now: now(),
    ...(dependencies.fetch === undefined ? {} : { fetch: dependencies.fetch }),
    ...(dependencies.cache === undefined ? {} : { cache: dependencies.cache }),
  })

  const timestamp = now().toISOString()
  const serialNumber = dependencies.serialNumber?.() ?? `urn:uuid:${randomUUID()}`
  const bom = buildBom(graph, { specVersion, timestamp, serialNumber })

  const findingsDocument: FindingsDocument = {
    schemaVersion: ARTIFACT_SCHEMA_VERSION,
    timestamp,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    project: { name: graph.root.name, version: graph.root.version },
    scope: includeDev ? 'all' : 'production',
    packageManager: graph.packageManager,
    offline,
    componentCount: graph.components.length,
    findings,
    suppressed,
  }

  await mkdir(outputDir, { recursive: true })
  await writeFile(join(outputDir, 'sbom.cdx.json'), `${JSON.stringify(bom, null, 2)}\n`, 'utf8')
  await writeFile(
    join(outputDir, 'findings.json'),
    `${JSON.stringify(findingsDocument, null, 2)}\n`,
    'utf8',
  )
  // Evaluated after the SBOM is written, so the report describes the state it
  // ships with rather than the one it replaced.
  const readiness = await gatherReadiness({
    projectDir,
    outputDir,
    graph,
    findings,
    suppressed,
    now: now(),
    offline,
    ...(dependencies.fetch === undefined ? {} : { fetch: dependencies.fetch }),
    ...(dependencies.cache === undefined ? {} : { cache: dependencies.cache }),
  })

  await writeFile(
    join(outputDir, 'report.html'),
    buildReport({
      graph,
      findings,
      suppressed,
      readiness,
      timestamp,
      offline,
      specVersion,
      serialNumber,
      toolName: TOOL_NAME,
      toolVersion: TOOL_VERSION,
    }),
    'utf8',
  )

  stdout.write(
    summarize({
      graph,
      findings,
      suppressed,
      readiness,
      unusedStatements: unmatchedStatements.length,
      expiringSoon: expiringSoon(vex, now()),
      specVersion,
      offline,
      cacheHits,
      outputDir,
      projectDir,
    }),
  )
  return 0
}

function isSpecVersion(value: string | undefined): value is CycloneDxSpecVersion {
  return SUPPORTED_SPEC_VERSIONS.includes(value as CycloneDxSpecVersion)
}

interface SummaryInput {
  graph: DependencyGraph
  findings: Finding[]
  suppressed: Finding[]
  readiness: ReadinessReport
  unusedStatements: number
  expiringSoon: { inDays: number }[]
  specVersion: CycloneDxSpecVersion
  offline: boolean
  cacheHits: number
  outputDir: string
  projectDir: string
}

function summarize(input: SummaryInput): string {
  const { graph, findings, offline } = input
  const direct = graph.components.filter((c) => c.direct).length
  const unknownLicence = graph.components.filter((c) => c.licenseUnknown)
  const relative = (path: string): string =>
    path.startsWith(input.projectDir) ? path.slice(input.projectDir.length + 1) : path

  const lines = [
    '',
    `cradle ${TOOL_VERSION} · ${graph.root.name} ${graph.root.version} · ${graph.packageManager} · ` +
      `${graph.includeDev ? 'all dependencies' : 'production only'}`,
    '',
    `  Components   ${graph.components.length} (${direct} direct, ${graph.components.length - direct} transitive)`,
    `  Licences     ${graph.components.length - unknownLicence.length} known, ${unknownLicence.length} unknown`,
  ]

  if (offline) {
    lines.push('  Findings     not checked (--offline)')
  } else {
    const counts = countBySeverity(findings)
    const breakdown = SEVERITY_ORDER.filter((s) => (counts.get(s) ?? 0) > 0)
      .map((s) => `${counts.get(s) ?? 0} ${s}`)
      .join(', ')
    lines.push(`  Findings     ${findings.length}${breakdown === '' ? '' : ` (${breakdown})`}`)
    if (input.suppressed.length > 0) {
      lines.push(`  Suppressed   ${input.suppressed.length} by VEX statements`)
    }
  }

  const { counts } = input.readiness
  const readinessParts = [
    `${counts.met} met`,
    counts.partial > 0 ? `${counts.partial} partial` : '',
    counts.open > 0 ? `${counts.open} open` : '',
    counts['not-assessable'] > 0 ? `${counts['not-assessable']} not assessable` : '',
  ].filter((part) => part !== '')
  lines.push(`  CRA checks   ${readinessParts.join(', ')}`)
  lines.push(`  Report       ${relative(join(input.outputDir, 'report.html'))}`)
  lines.push(`  Output       ${relative(input.outputDir)}/ · CycloneDX ${input.specVersion}`)
  if (graph.workspaces.length > 0) {
    lines.push(`  Workspaces   ${graph.workspaces.length}: ${graph.workspaces.join(', ')}`)
  }
  lines.push('')

  if (offline) {
    lines.push('  Ran offline: the SBOM is complete, the vulnerability lookup was skipped.')
    lines.push('  findings.json records this, and so will the report.')
    lines.push('')
  } else if (findings.length > 0) {
    const recommendations = recommendUpgrades(findings).slice(0, 3)
    if (recommendations.length > 0) {
      lines.push('  Next steps')
      for (const r of recommendations) {
        const scope = r.direct ? 'direct' : 'transitive'
        const clears = r.findingCount === 1 ? '1 finding' : `${r.findingCount} findings`
        lines.push(
          `    · ${r.package} ${r.from} -> ${r.to}  (clears ${clears}, worst ${r.worstSeverity}, ${scope})`,
        )
      }
      lines.push('')
    }

    const unfixed = findingsWithoutFix(findings)
    if (unfixed.length > 0) {
      const label = unfixed.length === 1 ? 'finding has' : 'findings have'
      lines.push(
        `  ${unfixed.length} ${label} no fix available. Those need a decision, not an upgrade —`,
      )
      lines.push('  `cradle suppress` will record one with an auditable justification.')
      lines.push('')
    }
  }

  const openChecks = input.readiness.checks.filter((check) => check.status === 'open')
  if (openChecks.length > 0) {
    lines.push('  CRA readiness')
    for (const check of openChecks.slice(0, 3)) {
      lines.push(`    · ${check.title}`)
    }
    lines.push(
      `    See the report for what to do about ${openChecks.length === 1 ? 'it' : 'them'}.`,
    )
    lines.push('')
  }

  const lapsing = input.expiringSoon
  if (lapsing.length > 0) {
    const soonest = lapsing[0]?.inDays ?? 0
    const when = soonest === 0 ? 'today' : soonest === 1 ? 'tomorrow' : `in ${soonest} days`
    const label = lapsing.length === 1 ? 'suppression expires' : 'suppressions expire'
    lines.push(`  ! ${lapsing.length} ${label} soon, the first ${when}.`)
    lines.push('')
  }

  if (input.unusedStatements > 0) {
    const label = input.unusedStatements === 1 ? 'VEX statement matches' : 'VEX statements match'
    lines.push(
      `  ${input.unusedStatements} ${label} nothing in this scan — likely fixed by an upgrade.`,
    )
    lines.push('')
  }

  if (unknownLicence.length > 0) {
    const names = unknownLicence.slice(0, 3).map((c) => `${c.name}@${c.version}`)
    const more = unknownLicence.length > 3 ? `, +${unknownLicence.length - 3} more` : ''
    lines.push(`  ! No licence declared: ${names.join(', ')}${more}`)
    lines.push('')
  }

  return lines.join('\n')
}
