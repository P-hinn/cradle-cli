import { randomUUID } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { CradleError } from '../core/errors.js'
import { detectPackageManager } from '../core/resolve/detect.js'
import { resolveNpm } from '../core/resolve/npm.js'
import { buildBom } from '../core/sbom/cyclonedx.js'
import {
  type CycloneDxSpecVersion,
  type DependencyGraph,
  SUPPORTED_SPEC_VERSIONS,
} from '../types/index.js'
import { TOOL_VERSION } from '../version.generated.js'

export const SCAN_HELP = `cradle scan — resolve dependencies and write an SBOM

Usage:
  cradle scan [path] [options]

Options:
  --include-dev            Include development dependencies (default: production only)
  --offline                Skip the vulnerability lookup and mark the output offline
  --spec-version <1.6|1.7> CycloneDX version to emit (default: 1.6)
  --output-dir <dir>       Where to write results (default: .cradle)
  -h, --help               Show this help
`

export async function runScan(argv: string[], stdout: NodeJS.WritableStream): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      'include-dev': { type: 'boolean', default: false },
      offline: { type: 'boolean', default: false },
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

  const detection = await detectPackageManager(projectDir)
  if (detection.manager !== 'npm') throw unsupportedManager(detection.manager, detection.lockfile)

  const graph = await resolveNpm({ projectDir, includeDev })
  const bom = buildBom(graph, {
    specVersion,
    timestamp: new Date().toISOString(),
    serialNumber: `urn:uuid:${randomUUID()}`,
  })

  await mkdir(outputDir, { recursive: true })
  const sbomPath = join(outputDir, 'sbom.cdx.json')
  await writeFile(sbomPath, `${JSON.stringify(bom, null, 2)}\n`, 'utf8')

  stdout.write(summarize(graph, specVersion, sbomPath, projectDir))
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

function summarize(
  graph: DependencyGraph,
  specVersion: CycloneDxSpecVersion,
  sbomPath: string,
  projectDir: string,
): string {
  const direct = graph.components.filter((c) => c.direct).length
  const unknown = graph.components.filter((c) => c.licenseUnknown)
  const relative = sbomPath.startsWith(projectDir)
    ? sbomPath.slice(projectDir.length + 1)
    : sbomPath

  const lines = [
    '',
    `cradle ${TOOL_VERSION} · ${graph.root.name} ${graph.root.version} · ${graph.packageManager} · ` +
      `${graph.includeDev ? 'all dependencies' : 'production only'}`,
    '',
    `  Components   ${graph.components.length} (${direct} direct, ${graph.components.length - direct} transitive)`,
    `  Licences     ${graph.components.length - unknown.length} known, ${unknown.length} unknown`,
    `  SBOM         ${relative} (CycloneDX ${specVersion})`,
  ]

  if (graph.workspaces.length > 0) {
    lines.push(`  Workspaces   ${graph.workspaces.length}: ${graph.workspaces.join(', ')}`)
  }

  lines.push('')
  if (unknown.length > 0) {
    const names = unknown.slice(0, 3).map((c) => `${c.name}@${c.version}`)
    const more = unknown.length > 3 ? `, +${unknown.length - 3} more` : ''
    lines.push(`  ! No licence declared: ${names.join(', ')}${more}`)
    lines.push('')
  }

  // Say plainly what has not run yet rather than implying a clean bill of health.
  lines.push('  Vulnerability lookup is not implemented yet — this run resolved dependencies and')
  lines.push('  wrote the SBOM only. Findings, VEX and the report follow in the next milestones.')
  lines.push('')

  return lines.join('\n')
}
