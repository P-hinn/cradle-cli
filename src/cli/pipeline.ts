import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { CradleError } from '../core/errors.js'
import { detectPackageManager } from '../core/resolve/detect.js'
import { resolveNpm } from '../core/resolve/npm.js'
import { resolvePnpm } from '../core/resolve/pnpm.js'
import { resolveYarn } from '../core/resolve/yarn.js'
import { applyVex } from '../core/vex/apply.js'
import { parseDocument } from '../core/vex/document.js'
import { NULL_CACHE, type VulnCache } from '../core/vulns/cache.js'
import { resolveFindings } from '../core/vulns/findings.js'
import { queryOsv } from '../core/vulns/osv.js'
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
  fetch?: typeof globalThis.fetch
  cache?: VulnCache
}

export interface PipelineResult {
  graph: DependencyGraph
  /** Findings that still count, after live VEX statements are applied. */
  findings: Finding[]
  /** Findings a live VEX statement rules out. Recorded, never discarded. */
  suppressed: Finding[]
  vex: VexDocument | undefined
  /** Statements that matched nothing in this scan. */
  unmatchedStatements: VexStatement[]
  cacheHits: number
}

export async function runPipeline(options: PipelineOptions): Promise<PipelineResult> {
  const detection = await detectPackageManager(options.projectDir)
  const graph = await resolveTree(detection.manager, options, detection.lockfile)

  let findings: Finding[] = []
  let cacheHits = 0
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
    findings = resolveFindings(graph, result.byPackage)
  }

  // Suppressions are applied after the lookup, never instead of it: a suppressed
  // finding is still recorded, just moved out of the active count.
  const vex = await loadVex(options.outputDir)
  const applied = applyVex(findings, vex, options.now)

  return {
    graph,
    findings: applied.active,
    suppressed: applied.suppressed,
    vex,
    unmatchedStatements: applied.unmatched,
    cacheHits,
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
