import { existsSync } from 'node:fs'
import { readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { parseBaseline } from '../core/baseline/diff.js'
import { evaluateReadiness, type ReadinessInput } from '../core/readiness/checks.js'
import { parseConfig } from '../core/readiness/config.js'
import { fetchPackageFacts } from '../core/readiness/registry.js'
import { NULL_CACHE, type VulnCache } from '../core/vulns/cache.js'
import type {
  BaselineDocument,
  CradleConfig,
  DependencyGraph,
  Finding,
  ReadinessReport,
} from '../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../version.generated.js'

/** Filenames a project might use for its disclosure policy, in the order we look. */
const SECURITY_FILES = ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md', 'SECURITY']

/** Lockfiles, so the SBOM's age can be compared against the tree it describes. */
const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock']

export interface GatherOptions {
  projectDir: string
  outputDir: string
  graph: DependencyGraph
  findings: readonly Finding[]
  suppressed: readonly Finding[]
  now: Date
  offline: boolean
  fetch?: typeof globalThis.fetch
  cache?: VulnCache
}

/**
 * Collect the facts the readiness checks need and evaluate them.
 *
 * All the filesystem and network work lives here; `core/readiness` is given the
 * answers and does nothing but judge them.
 */
export async function gatherReadiness(options: GatherOptions): Promise<ReadinessReport> {
  const input: ReadinessInput = {
    graph: options.graph,
    findings: options.findings,
    suppressed: options.suppressed,
    baseline: await readBaseline(options.outputDir),
    config: await readConfig(options.outputDir),
    now: options.now,
    offline: options.offline,
  }

  const sbomWrittenAt = await modifiedAt(join(options.outputDir, 'sbom.cdx.json'))
  if (sbomWrittenAt !== undefined) input.sbomWrittenAt = sbomWrittenAt

  const lockfileChangedAt = await newestLockfile(options.projectDir)
  if (lockfileChangedAt !== undefined) input.lockfileChangedAt = lockfileChangedAt

  const securityPolicy = await readSecurityPolicy(options.projectDir)
  if (securityPolicy !== undefined) input.securityPolicy = securityPolicy

  if (!options.offline) {
    input.packageFacts = await fetchPackageFacts(options.graph.components, {
      fetch: options.fetch ?? globalThis.fetch,
      cache: options.cache ?? NULL_CACHE,
      userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
    })
  }

  return evaluateReadiness(input)
}

export async function readConfig(outputDir: string): Promise<CradleConfig | undefined> {
  const path = join(outputDir, 'config.json')
  if (!existsSync(path)) return undefined
  return parseConfig(await readFile(path, 'utf8'), path)
}

async function readBaseline(outputDir: string): Promise<BaselineDocument | undefined> {
  const path = join(outputDir, 'baseline.json')
  if (!existsSync(path)) return undefined
  return parseBaseline(await readFile(path, 'utf8'), path)
}

async function readSecurityPolicy(projectDir: string): Promise<string | undefined> {
  for (const candidate of SECURITY_FILES) {
    try {
      return await readFile(join(projectDir, candidate), 'utf8')
    } catch {
      // Try the next location.
    }
  }
  return undefined
}

async function newestLockfile(projectDir: string): Promise<Date | undefined> {
  let newest: Date | undefined
  for (const name of LOCKFILES) {
    const at = await modifiedAt(join(projectDir, name))
    if (at !== undefined && (newest === undefined || at > newest)) newest = at
  }
  return newest
}

async function modifiedAt(path: string): Promise<Date | undefined> {
  try {
    return (await stat(path)).mtime
  } catch {
    return undefined
  }
}
