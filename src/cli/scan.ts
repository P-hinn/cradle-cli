import { randomUUID } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { CradleError } from '../core/errors.js'
import { detectPackageManager } from '../core/resolve/detect.js'
import { resolveNpm } from '../core/resolve/npm.js'
import { buildBom } from '../core/sbom/cyclonedx.js'
import { NULL_CACHE, type VulnCache } from '../core/vulns/cache.js'
import { countBySeverity, resolveFindings } from '../core/vulns/findings.js'
import { queryOsv } from '../core/vulns/osv.js'
import { findingsWithoutFix, recommendUpgrades } from '../core/vulns/recommend.js'
import {
  ARTIFACT_SCHEMA_VERSION,
  type CycloneDxSpecVersion,
  type DependencyGraph,
  type Finding,
  type FindingsDocument,
  SEVERITY_ORDER,
  SUPPORTED_SPEC_VERSIONS,
} from '../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../version.generated.js'
import { cacheDirFor, FileCache } from './cache.js'

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
      cache: { type: 'boolean', default: true },
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

  const detection = await detectPackageManager(projectDir)
  if (detection.manager !== 'npm') throw unsupportedManager(detection.manager, detection.lockfile)

  const graph = await resolveNpm({ projectDir, includeDev })

  let findings: Finding[] = []
  let cacheHits = 0
  if (!offline) {
    const cache =
      dependencies.cache ??
      (values.cache === false ? NULL_CACHE : new FileCache(cacheDirFor(projectDir)))
    const result = await queryOsv(
      graph.components.map((c) => ({ name: c.name, version: c.version })),
      {
        fetch: dependencies.fetch ?? globalThis.fetch,
        cache,
        userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
      },
    )
    cacheHits = result.cacheHits
    findings = resolveFindings(graph, result.byPackage)
  }

  const timestamp = now().toISOString()
  const bom = buildBom(graph, {
    specVersion,
    timestamp,
    serialNumber: dependencies.serialNumber?.() ?? `urn:uuid:${randomUUID()}`,
  })

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
  }

  await mkdir(outputDir, { recursive: true })
  await writeFile(join(outputDir, 'sbom.cdx.json'), `${JSON.stringify(bom, null, 2)}\n`, 'utf8')
  await writeFile(
    join(outputDir, 'findings.json'),
    `${JSON.stringify(findingsDocument, null, 2)}\n`,
    'utf8',
  )

  stdout.write(
    summarize({ graph, findings, specVersion, offline, cacheHits, outputDir, projectDir }),
  )
  return 0
}

function isSpecVersion(value: string | undefined): value is CycloneDxSpecVersion {
  return SUPPORTED_SPEC_VERSIONS.includes(value as CycloneDxSpecVersion)
}

function unsupportedManager(manager: string, lockfile: string): CradleError {
  if (manager === 'bun') {
    return new CradleError(
      `Bun projects are not supported yet (found ${lockfile})`,
      'Bun support is deliberately out of scope for now. If the project also builds with npm, ' +
        'run `npm install --package-lock-only` to produce a package-lock.json and scan that.',
    )
  }
  return new CradleError(
    `${manager} projects are not supported yet (found ${lockfile})`,
    'pnpm and Yarn support is the next parser milestone. Until then, `npm install ' +
      '--package-lock-only` produces a package-lock.json cradle can read.',
  )
}

interface SummaryInput {
  graph: DependencyGraph
  findings: Finding[]
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
  }

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

  if (unknownLicence.length > 0) {
    const names = unknownLicence.slice(0, 3).map((c) => `${c.name}@${c.version}`)
    const more = unknownLicence.length > 3 ? `, +${unknownLicence.length - 3} more` : ''
    lines.push(`  ! No licence declared: ${names.join(', ')}${more}`)
    lines.push('')
  }

  return lines.join('\n')
}
