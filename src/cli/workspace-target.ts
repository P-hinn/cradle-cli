import { resolve } from 'node:path'
import { sliceWorkspace } from '../core/resolve/workspace.js'
import { applyVex } from '../core/vex/apply.js'
import { resolveFindings } from '../core/vulns/findings.js'
import type { OsvVulnerability } from '../core/vulns/osv-types.js'
import type { DependencyGraph, Finding, VexDocument, VexStatement } from '../types/index.js'
import { loadVex } from './pipeline.js'

/** One package's worth of report, derived from the repository-wide pipeline run. */
export interface WorkspaceTarget {
  graph: DependencyGraph
  /** The package's own directory, where its `.cradle/` goes. */
  outputDir: string
  findings: Finding[]
  suppressed: Finding[]
  vex: VexDocument | undefined
  unmatchedStatements: VexStatement[]
}

export interface WorkspaceTargetInput {
  repo: DependencyGraph
  name: string
  projectDir: string
  /** The repository root's `.cradle`, read for repository-level VEX statements. */
  rootOutputDir: string
  /** An explicit `--output-dir`, which overrides the package's own directory. */
  outputOverride: string | undefined
  osvByPackage: Map<string, OsvVulnerability[]>
  offline: boolean
  now: Date
}

/**
 * Derive one workspace package's view from the repository-wide run.
 *
 * Nothing is resolved a second time and nothing is fetched a second time: the
 * graph is sliced and the same OSV answers are re-applied to it. What changes is
 * the root, and therefore the route — which is the whole point, because the route
 * is what says whose problem a finding is.
 *
 * Output goes to the package's own directory rather than under the repository
 * root, so a report sits with the code it describes. The nested-directory
 * gitignore pattern the README documents is written the way it is precisely so
 * this case works.
 */
export async function workspaceTarget(input: WorkspaceTargetInput): Promise<WorkspaceTarget> {
  const sliced = sliceWorkspace(input.repo, input.name)
  const member = input.repo.components.find(
    (component) => component.workspace && component.name === input.name,
  )

  const outputDir =
    input.outputOverride === undefined
      ? resolve(input.projectDir, member?.location ?? '.', '.cradle')
      : resolve(input.projectDir, input.outputOverride)

  // Statements from the repository root as well as the package's own, the package
  // winning where both rule on the same vulnerability and product. Reading only
  // the package's file would re-report findings the team had already ruled on at
  // the repository level — the exact failure a VEX file exists to prevent, and the
  // one a broken vex.json aborts the scan over.
  const vex = mergeVex(await loadVex(input.rootOutputDir), await loadVex(outputDir))

  const findings = input.offline ? [] : resolveFindings(sliced, input.osvByPackage)
  const applied = applyVex(findings, vex, input.now)

  return {
    graph: sliced,
    outputDir,
    findings: applied.active,
    suppressed: applied.suppressed,
    vex,
    unmatchedStatements: applied.unmatched,
  }
}

/**
 * Merge two VEX documents for the purpose of deciding what one report counts. The
 * result is never written back — it is not a document anybody authored.
 */
function mergeVex(
  root: VexDocument | undefined,
  local: VexDocument | undefined,
): VexDocument | undefined {
  if (root === undefined) return local
  if (local === undefined) return root

  const key = (statement: VexStatement): string =>
    `${statement.vulnerability.name} ${(statement.products ?? [])
      .map((product) => product['@id'])
      .sort()
      .join(',')}`

  const merged = new Map(root.statements.map((statement) => [key(statement), statement]))
  for (const statement of local.statements) merged.set(key(statement), statement)

  return { ...local, statements: [...merged.values()] }
}
