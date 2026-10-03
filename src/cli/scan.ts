import { randomUUID } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { CradleError } from '../core/errors.js'
import { BSI_TR_03183_2, checkBsiProfile } from '../core/readiness/profiles/bsi-tr-03183.js'
import { workspaceNames } from '../core/resolve/workspace.js'
import { buildBom } from '../core/sbom/cyclonedx.js'
import { buildSpdx } from '../core/sbom/spdx.js'
import { expiringSoon } from '../core/vex/apply.js'
import { buildCsaf } from '../core/vex/csaf.js'
import type { VulnCache } from '../core/vulns/cache.js'
import { countBySeverity } from '../core/vulns/findings.js'
import { findingsWithoutFix, recommendUpgrades } from '../core/vulns/recommend.js'
import { buildReport } from '../report/html.js'
import { isLanguage, LANGUAGES } from '../report/i18n/index.js'
import { renderProfileText } from '../report/profile.js'
import {
  ARTIFACT_SCHEMA_VERSION,
  type CycloneDxSpecVersion,
  type DependencyGraph,
  type Finding,
  type FindingsDocument,
  type ReadinessReport,
  SEVERITY_ORDER,
  SUPPORTED_SPEC_VERSIONS,
} from '../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../version.generated.js'
import { runPipeline } from './pipeline.js'
import { creatorFrom, gatherReadiness, readConfig } from './readiness.js'
import { workspaceTarget } from './workspace-target.js'

export const SCAN_HELP = `cradle scan — resolve dependencies, write an SBOM and look up vulnerabilities

Usage:
  cradle scan [path] [options]

Options:
  --include-dev            Include development dependencies (default: production only)
  --offline                Skip the vulnerability lookup and mark the output offline
  --no-cache               Do not read or write the local advisory cache
  --from-sbom <file>       Read the dependency graph from a CycloneDX file
                           instead of resolving a lockfile
  --no-priority            Skip the EPSS and CISA KEV lookup. --offline already
                           does; this keeps the advisories without the extras
  --spec-version <1.6|1.7> CycloneDX version to emit (default: 1.6)
  --sbom-format <f>        cyclonedx (default), spdx, or both. SPDX 2.3 JSON is
                           written as sbom.spdx.json
  --vex-format <f>         openvex (default), csaf, or both. CSAF 2.0 VEX is
                           written as vex.csaf.json, from the same statements
  --workspace <name|all>   Report on one workspace package, or one report each
  --lang <en|de>           Language of the report (default: en)
  --profile <name>         Add a profile section to the report. Currently:
                           bsi-tr-03183 (BSI TR-03183-2 v2.1.0)
  --timestamp <iso>        Use this timestamp instead of now
  --serial-number <urn>    Use this SBOM serial number instead of a fresh UUID
  --output-dir <dir>       Where to write results (default: .cradle)
  -h, --help               Show this help

--timestamp and --serial-number exist for reproducible builds: two runs over the
same lockfile with the same values produce byte-identical sbom.cdx.json. Without
them each run stamps the current time and a fresh UUID, which is the right default
for a report that says when it was made.

With --workspace, that package becomes the product and only its own dependencies
are reported. Results land in the package's own directory, next to the code they
describe. --workspace all writes one report per package and cannot be combined
with --output-dir, which would make every package overwrite the last.
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
      'from-sbom': { type: 'string' },
      'no-priority': { type: 'boolean', default: false },
      'spec-version': { type: 'string', default: '1.6' },
      'sbom-format': { type: 'string', default: 'cyclonedx' },
      'vex-format': { type: 'string', default: 'openvex' },
      workspace: { type: 'string' },
      profile: { type: 'string' },
      lang: { type: 'string', default: 'en' },
      timestamp: { type: 'string' },
      'serial-number': { type: 'string' },
      'output-dir': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  if (values.help === true) {
    stdout.write(SCAN_HELP)
    return 0
  }

  const lang = values.lang
  if (!isLanguage(lang)) {
    throw new CradleError(
      `Unknown --lang '${lang}'`,
      `cradle writes its report in: ${LANGUAGES.join(', ')}.`,
    )
  }

  const profileName = values.profile
  if (profileName !== undefined && profileName !== BSI_TR_03183_2.id) {
    throw new CradleError(
      `Unknown --profile '${profileName}'`,
      `The only profile cradle ships is ${BSI_TR_03183_2.id} (BSI TR-03183-2 v${BSI_TR_03183_2.version}).`,
    )
  }

  const sbomFormats = parseFormats(values['sbom-format'], 'sbom-format', ['cyclonedx', 'spdx'])
  const vexFormats = parseFormats(values['vex-format'], 'vex-format', ['openvex', 'csaf'])

  const specVersion = values['spec-version']
  if (!isSpecVersion(specVersion)) {
    throw new CradleError(
      `Unsupported CycloneDX version '${specVersion}'`,
      `Pass one of: ${SUPPORTED_SPEC_VERSIONS.join(', ')}.`,
    )
  }

  const projectDir = resolve(positionals[0] ?? process.cwd())
  const outputOverride = values['output-dir']
  const outputDir = resolve(projectDir, outputOverride ?? '.cradle')
  const workspace = values.workspace
  if (workspace === 'all' && outputOverride !== undefined) {
    throw new CradleError(
      '--workspace all cannot be combined with --output-dir',
      'Every package would write to the same directory and only the last would survive. ' +
        'Drop --output-dir, or name a single package with --workspace <name>.',
    )
  }
  if (workspace === 'all' && values['serial-number'] !== undefined) {
    throw new CradleError(
      '--workspace all cannot be combined with --serial-number',
      'A serial number identifies one BOM, and every package would be handed the same one. ' +
        'For a reproducible monorepo build, run one package at a time: ' +
        'cradle scan --workspace <name> --serial-number <urn>.',
    )
  }
  const includeDev = values['include-dev'] === true
  const offline = values.offline === true
  const now = dependencies.now ?? (() => new Date())

  // Shared with `check`, so a green gate and a clean report can never disagree
  // about what a finding is.
  const {
    graph,
    findings,
    suppressed,
    vex,
    unmatchedStatements,
    cacheHits,
    osvByPackage,
    priorityUnavailable,
  } = await runPipeline({
    projectDir,
    outputDir,
    includeDev,
    offline,
    useCache: values['no-cache'] !== true,
    now: now(),
    ...(values['from-sbom'] === undefined ? {} : { fromSbom: resolve(values['from-sbom']) }),
    ...(dependencies.fetch === undefined ? {} : { fetch: dependencies.fetch }),
    ...(dependencies.cache === undefined ? {} : { cache: dependencies.cache }),
  })

  // A run stamps the current time and a fresh UUID by default, because a report
  // should say when it was made. Both are overridable so that a build can be
  // reproducible: same lockfile and same values in, byte-identical SBOM out.
  // Read once, ahead of the loop: the creator is a property of the repository,
  // not of a workspace package.
  const rootConfig = await readConfig(outputDir)
  const creator = creatorFrom(rootConfig)
  const timestamp = parseTimestamp(values.timestamp) ?? now().toISOString()
  const fixedSerial = parseSerialNumber(values['serial-number'])

  // One pipeline run, however many reports come out of it. Slicing the finished
  // graph rather than resolving each package on its own is what keeps a
  // per-package report and the repository-wide one from disagreeing about
  // versions — there is one lockfile, so there is one resolution.
  const targets =
    workspace === undefined
      ? [
          {
            graph,
            outputDir,
            findings,
            suppressed,
            vex,
            unmatchedStatements,
          },
        ]
      : await Promise.all(
          namesToScan(graph, workspace).map((name) =>
            workspaceTarget({
              repo: graph,
              name,
              projectDir,
              rootOutputDir: outputDir,
              outputOverride,
              osvByPackage,
              offline,
              now: now(),
            }),
          ),
        )

  for (const target of targets) {
    const serialNumber = fixedSerial ?? dependencies.serialNumber?.() ?? `urn:uuid:${randomUUID()}`
    const bom = buildBom(target.graph, {
      specVersion,
      timestamp,
      serialNumber,
      ...(creator === undefined ? {} : { creator }),
    })

    const findingsDocument: FindingsDocument = {
      schemaVersion: ARTIFACT_SCHEMA_VERSION,
      timestamp,
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      project: { name: target.graph.root.name, version: target.graph.root.version },
      scope: includeDev ? 'all' : 'production',
      packageManager: target.graph.packageManager,
      ...(target.graph.source === undefined ? {} : { source: target.graph.source }),
      offline,
      componentCount: target.graph.components.length,
      findings: target.findings,
      suppressed: target.suppressed,
      notes: target.graph.notes,
    }

    await mkdir(target.outputDir, { recursive: true })
    if (sbomFormats.has('cyclonedx')) {
      await writeFile(
        join(target.outputDir, 'sbom.cdx.json'),
        `${JSON.stringify(bom, null, 2)}\n`,
        'utf8',
      )
    }
    if (sbomFormats.has('spdx')) {
      // Same graph, same timestamp, same serial number in the namespace: two
      // renderings of one scan rather than two scans.
      const spdx = buildSpdx(target.graph, {
        timestamp,
        serialNumber,
        ...(creator === undefined ? {} : { creator }),
      })
      await writeFile(
        join(target.outputDir, 'sbom.spdx.json'),
        `${JSON.stringify(spdx, null, 2)}\n`,
        'utf8',
      )
    }
    let csafWritten = false
    if (vexFormats.has('csaf')) {
      // Only suppressed findings. An active finding is not a VEX statement, and
      // a CSAF document that listed everything would be a vulnerability report -
      // a different document with different obligations attached.
      const csaf = buildCsaf(target.suppressed, {
        publisher: {
          name: rootConfig?.productName ?? target.graph.root.name,
          namespace: csafNamespace(rootConfig?.contactEmail),
        },
        timestamp,
        trackingId: `${target.graph.root.name}-${target.graph.root.version}-${serialNumber.slice('urn:uuid:'.length)}`,
        product: { name: target.graph.root.name, version: target.graph.root.version },
      })
      // Absent rather than empty when nothing has been suppressed: a CSAF
      // document needs at least one vulnerability to be a CSAF document.
      if (csaf !== undefined) {
        await writeFile(
          join(target.outputDir, 'vex.csaf.json'),
          `${JSON.stringify(csaf, null, 2)}\n`,
          'utf8',
        )
      }
      csafWritten = csaf !== undefined
    }
    await writeFile(
      join(target.outputDir, 'findings.json'),
      `${JSON.stringify(findingsDocument, null, 2)}\n`,
      'utf8',
    )
    // Evaluated after the SBOM is written, so the report describes the state it
    // ships with rather than the one it replaced.
    const readiness = await gatherReadiness({
      projectDir,
      outputDir: target.outputDir,
      graph: target.graph,
      findings: target.findings,
      suppressed: target.suppressed,
      now: now(),
      offline,
      ...(dependencies.fetch === undefined ? {} : { fetch: dependencies.fetch }),
      ...(dependencies.cache === undefined ? {} : { cache: dependencies.cache }),
    })

    // Checked against the document that is about to be written, not against the
    // graph in memory: the profile is a statement about the file a reader gets.
    const profile =
      profileName === undefined
        ? undefined
        : checkBsiProfile({ bom, config: rootConfig ?? {}, offline })

    await writeFile(
      join(target.outputDir, 'report.html'),
      buildReport({
        graph: target.graph,
        findings: target.findings,
        suppressed: target.suppressed,
        readiness,
        ...(profile === undefined ? {} : { profile }),
        timestamp,
        offline,
        specVersion,
        serialNumber,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        lang,
        priorityUnavailable,
      }),
      'utf8',
    )

    stdout.write(
      summarize({
        graph: target.graph,
        findings: target.findings,
        suppressed: target.suppressed,
        readiness,
        unusedStatements: target.unmatchedStatements.length,
        expiringSoon: expiringSoon(target.vex, now()),
        specVersion,
        offline,
        cacheHits,
        outputDir: target.outputDir,
        projectDir,
        sbomFormats: [...sbomFormats].sort(),
        csaf: vexFormats.has('csaf') ? (csafWritten ? 'written' : 'empty') : 'off',
      }),
    )
    if (profile !== undefined) stdout.write(renderProfileText(profile))
  }
  return 0
}

/** Which packages `--workspace` selected, with a usable error when it selected none. */
function namesToScan(graph: DependencyGraph, workspace: string): string[] {
  if (workspace !== 'all') return [workspace]

  const names = workspaceNames(graph)
  if (names.length === 0) {
    throw new CradleError(
      `${graph.root.name} has no workspace packages`,
      'Run cradle without --workspace to scan the whole project.',
    )
  }
  return names
}

/**
 * Accept an ISO 8601 instant and nothing else.
 *
 * `new Date('nonsense')` is an Invalid Date whose toISOString() throws, and a
 * loose parse would let `--timestamp 2026` through as midnight on New Year — a
 * plausible-looking wrong answer in a field an auditor reads as "when was this
 * scanned".
 */
function parseTimestamp(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    throw new CradleError(
      `--timestamp '${value}' is not a valid ISO 8601 timestamp`,
      'Pass something like 2026-09-26T12:00:00Z. Omit it to stamp the current time.',
    )
  }
  return parsed.toISOString()
}

/**
 * CycloneDX requires `serialNumber` to be a UUID URN, and the schema enforces the
 * pattern. Checking here means a typo is an error with a hint rather than a
 * validation failure in whatever consumes the file next.
 */
function parseSerialNumber(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) {
    throw new CradleError(
      `--serial-number '${value}' is not a UUID URN`,
      'CycloneDX requires the form urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, lowercase. ' +
        'Omit it to generate a fresh one.',
    )
  }
  return value
}

/**
 * Parse a `--*-format` value into the set of formats to write.
 *
 * `both` is spelled out rather than accepting a comma list, because two formats
 * is the only combination there is and a list invites `cyclonedx,cyclonedx`.
 */
function parseFormats(
  value: string | undefined,
  flag: string,
  allowed: readonly [string, string],
): Set<string> {
  if (value === 'both') return new Set(allowed)
  if (value !== undefined && allowed.includes(value)) return new Set([value])
  throw new CradleError(
    `Unknown --${flag} '${value}'`,
    `Use ${allowed[0]} (the default), ${allowed[1]}, or both.`,
  )
}

/**
 * CSAF requires a publisher namespace, which must be a URI identifying who is
 * speaking. An email address is not one, so it becomes a mailto: URI; with
 * nothing configured the document says so rather than naming somebody else.
 */
function csafNamespace(contactEmail: string | undefined): string {
  return contactEmail === undefined
    ? 'https://cradle.invalid/unconfigured'
    : `mailto:${contactEmail}`
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
  sbomFormats: string[]
  /** Whether a CSAF file was asked for, and whether there was anything to put in it. */
  csaf: 'off' | 'written' | 'empty'
}

function summarize(input: SummaryInput): string {
  const { graph, findings, offline } = input
  const direct = graph.components.filter((c) => c.direct).length
  const unknownLicence = graph.components.filter((c) => c.licenseUnknown)
  const relative = (path: string): string =>
    path.startsWith(input.projectDir) ? path.slice(input.projectDir.length + 1) : path

  const lines = [
    '',
    `cradle ${TOOL_VERSION} · ${graph.root.name} ${graph.root.version} · ` +
      `${graph.source === undefined ? graph.packageManager : `from ${relative(graph.source.path)}`} · ` +
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
  const formats = input.sbomFormats
    .map((format) => (format === 'cyclonedx' ? `CycloneDX ${input.specVersion}` : 'SPDX 2.3'))
    .join(' + ')
  lines.push(`  Output       ${relative(input.outputDir)}/ · ${formats}`)
  if (input.csaf === 'written') lines.push('  CSAF         vex.csaf.json')
  if (input.csaf === 'empty') {
    lines.push('  CSAF         nothing suppressed, so no document was written')
  }
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

  // Last, and never omitted: a shape cradle could not represent is the one thing
  // a reader cannot infer from the numbers above. A silently skipped dependency
  // leaves an SBOM that still looks complete.
  if (graph.notes.length > 0) {
    const label = graph.notes.length === 1 ? 'note' : 'notes'
    lines.push(`  ${graph.notes.length} resolution ${label}`)
    for (const note of graph.notes.slice(0, 5)) {
      lines.push(`    · ${note.message}`)
      lines.push(`      ${note.hint}`)
    }
    if (graph.notes.length > 5) {
      lines.push(`    +${graph.notes.length - 5} more, all of them in the report.`)
    }
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
