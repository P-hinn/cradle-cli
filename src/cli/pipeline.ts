import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { CradleError } from '../core/errors.js'
import { detectPackageManager } from '../core/resolve/detect.js'
import { resolveNpm } from '../core/resolve/npm.js'
import { resolvePnpm } from '../core/resolve/pnpm.js'
import { resolveYarn } from '../core/resolve/yarn.js'
import { readCycloneDx } from '../core/sbom/read.js'
import { applyVex } from '../core/vex/apply.js'
import { parseDocument } from '../core/vex/document.js'
import { NULL_CACHE, type VulnCache } from '../core/vulns/cache.js'
import { resolveFindings } from '../core/vulns/findings.js'
import { queryOsv } from '../core/vulns/osv.js'
import type { OsvVulnerability } from '../core/vulns/osv-types.js'
import { fetchExploitSignals, withExploitSignals } from '../core/vulns/priority.js'
import type {
  DependencyGraph,
  Finding,
  PackageManager,
  VexDocument,
  VexStatement,
} from '../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../version.generated.js'
import { cacheDirFor, FileCache } from './cache.js'

/**
 * Everything `scan` and `check` do before they diverge.
 *
 * They have to agree on what a finding is, or a green gate would mean something
 * different from a clean report. Sharing the pipeline is what guarantees that.
 */
export interface PipelineOptions {
  projectDir: string
  outputDir: string
  includeDev: boolean
  offline: boolean
  useCache: boolean
  now: Date
  /**
   * Read the dependency graph from this CycloneDX file instead of resolving a
   * lockfile. For a shipped product whose tree is frozen, or a supplier's SBOM.
   */
  fromSbom?: string
  /**
   * Skip the EPSS and CISA KEV lookup. Off by default; `--offline` implies it,
   * and so does `--no-priority` for a run that wants the advisories without two
   * more network destinations.
   */
  noPriority?: boolean
  fetch?: typeof globalThis.fetch
  cache?: VulnCache
}

export interface PipelineResult {
  graph: DependencyGraph
  /**
   * The raw OSV answer, keyed by `name@version`. Exposed so that a per-workspace
   * report can re-derive findings against a narrowed graph without asking the
   * network a second time — the advisories are the same, only the routes differ.
   */
  osvByPackage: Map<string, OsvVulnerability[]>
  /** Findings that still count, after live VEX statements are applied. */
  findings: Finding[]
  /** Findings a live VEX statement rules out. Recorded, never discarded. */
  suppressed: Finding[]
  vex: VexDocument | undefined
  /** Statements that matched nothing in this scan. */
  unmatchedStatements: VexStatement[]
  cacheHits: number
  /** Exploit-signal sources that could not be reached. Named, never swallowed. */
  priorityUnavailable: string[]
}

export async function runPipeline(options: PipelineOptions): Promise<PipelineResult> {
  let graph: DependencyGraph
  if (options.fromSbom === undefined) {
    const detection = await detectPackageManager(options.projectDir)
    graph = await resolveTree(detection.manager, options, detection.lockfile)
  } else {
    graph = await readGraphFromSbom(options.fromSbom, options.projectDir)
  }

  let findings: Finding[] = []
  let cacheHits = 0
  let osvByPackage = new Map<string, OsvVulnerability[]>()
  let priorityUnavailable: string[] = []
  if (!options.offline) {
    const cache =
      options.cache ??
      (options.useCache ? new FileCache(cacheDirFor(options.projectDir)) : NULL_CACHE)
    const result = await queryOsv(
      graph.components.map((component) => ({
        name: component.name,
        version: component.version,
      })),
      {
        fetch: options.fetch ?? globalThis.fetch,
        cache,
        userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
      },
    )
    cacheHits = result.cacheHits
    osvByPackage = result.byPackage
    findings = resolveFindings(graph, result.byPackage)

    // Enrichment, after the findings exist and before VEX is applied, so a
    // suppressed finding still carries the signals a reviewer needs to judge
    // the suppression.
    if (options.noPriority !== true) {
      const signals = await fetchExploitSignals(findings, {
        fetch: options.fetch ?? globalThis.fetch,
        cache,
        userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
        today: options.now.toISOString().slice(0, 10),
      })
      priorityUnavailable = signals.unavailable
      findings = findings.map((finding) => withExploitSignals(finding, signals.byCve))
    }
  }

  // Suppressions are applied after the lookup, never instead of it: a suppressed
  // finding is still recorded, just moved out of the active count.
  const vex = await loadVex(options.outputDir)
  const applied = applyVex(findings, vex, options.now)

  return {
    graph,
    osvByPackage,
    findings: applied.active,
    suppressed: applied.suppressed,
    vex,
    unmatchedStatements: applied.unmatched,
    cacheHits,
    priorityUnavailable,
  }
}

/**
 * Read `.cradle/vex.json` if the project has one. A broken file is an error, not
 * something to skip past: silently ignoring it would re-report findings the team
 * has already ruled on.
 */
export async function loadVex(outputDir: string): Promise<VexDocument | undefined> {
  const path = join(outputDir, 'vex.json')
  if (!existsSync(path)) return undefined
  return parseDocument(await readFile(path, 'utf8'), path)
}

async function readGraphFromSbom(path: string, projectDir: string): Promise<DependencyGraph> {
  let raw: string
  try {
    raw = await readFile(path, 'utf8')
  } catch (cause) {
    throw new CradleError(`Could not read ${path}`, 'Check the path to the SBOM.', { cause })
  }
  return readCycloneDx(raw, { projectDir, path })
}

async function resolveTree(
  manager: PackageManager,
  options: PipelineOptions,
  lockfile: string,
): Promise<DependencyGraph> {
  const shared = { projectDir: options.projectDir, includeDev: options.includeDev }
  switch (manager) {
    case 'npm':
      return resolveNpm(shared)
    case 'pnpm':
      return resolvePnpm(shared)
    case 'yarn-classic':
    case 'yarn-berry':
      return resolveYarn(manager, shared)
    case 'bun':
      throw new CradleError(
        `Bun projects are not supported (found ${lockfile})`,
        'Bun support is deliberately out of scope. If the project also builds with npm, run ' +
          '`npm install --package-lock-only` to produce a package-lock.json and scan that.',
      )
  }
}
