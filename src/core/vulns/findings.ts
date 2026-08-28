import semver from 'semver'
import type { DependencyGraph, Finding, ResolvedComponent, Severity } from '../../types/index.js'
import { packageKey } from './osv.js'
import type { OsvVulnerability } from './osv-types.js'
import { normalizeSeverity, severityRank } from './severity.js'

/**
 * Turn raw OSV advisories into findings a human can act on.
 *
 * The part that matters for triage is the path: knowing that a vulnerable
 * package sits three levels down behind a dependency you chose deliberately is
 * the difference between "upgrade this" and "there is nothing I can do here".
 */
export function resolveFindings(
  graph: DependencyGraph,
  byPackage: ReadonlyMap<string, OsvVulnerability[]>,
): Finding[] {
  const names = componentNames(graph)
  const paths = shortestPaths(graph)
  const dependents = reverseEdges(graph, names)
  const findings: Finding[] = []

  for (const component of graph.components) {
    const vulnerabilities = byPackage.get(packageKey(component.name, component.version))
    if (vulnerabilities === undefined) continue

    for (const vulnerability of vulnerabilities) {
      findings.push(toFinding(vulnerability, component, names, paths, dependents))
    }
  }

  // Worst first, then by package, then by id — stable across runs.
  findings.sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      a.component.name.localeCompare(b.component.name) ||
      a.id.localeCompare(b.id),
  )
  return findings
}

function toFinding(
  vulnerability: OsvVulnerability,
  component: ResolvedComponent,
  names: ReadonlyMap<string, string>,
  paths: ReadonlyMap<string, string[]>,
  dependents: ReadonlyMap<string, Set<string>>,
): Finding {
  const { severity, cvss, source } = normalizeSeverity(vulnerability)
  const finding: Finding = {
    id: vulnerability.id,
    aliases: vulnerability.aliases ?? [],
    summary: vulnerability.summary ?? vulnerability.details?.split('\n')[0] ?? '',
    severity,
    severitySource: source,
    component: {
      bomRef: component.bomRef,
      name: component.name,
      version: component.version,
      purl: component.purl,
      direct: component.direct,
    },
    path: (paths.get(component.bomRef) ?? [component.bomRef]).map((ref) => names.get(ref) ?? ref),
    dependents: [...(dependents.get(component.bomRef) ?? [])].sort(),
    references: vulnerability.references ?? [],
    osvUrl: `https://osv.dev/vulnerability/${vulnerability.id}`,
  }

  if (cvss !== undefined) finding.cvss = cvss
  const fixedIn = lowestFix(vulnerability, component)
  if (fixedIn !== undefined) finding.fixedIn = fixedIn
  if (vulnerability.published !== undefined) finding.published = vulnerability.published
  if (vulnerability.modified !== undefined) finding.modified = vulnerability.modified

  return finding
}

/**
 * The lowest version that fixes this package, above the one installed.
 *
 * OSV lists ranges as introduced/fixed event pairs. Picking the smallest `fixed`
 * greater than the installed version answers the question the user actually
 * has — "what do I upgrade to" — rather than listing every fix ever released.
 */
function lowestFix(
  vulnerability: OsvVulnerability,
  component: ResolvedComponent,
): string | undefined {
  const current = semver.valid(semver.coerce(component.version) ?? '')
  let best: string | undefined

  for (const affected of vulnerability.affected ?? []) {
    if (affected.package?.ecosystem !== 'npm') continue
    if (affected.package.name !== component.name) continue

    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        const fixed = event.fixed
        if (fixed === undefined || semver.valid(fixed) === null) continue
        if (current !== null && !semver.gt(fixed, current)) continue
        if (best === undefined || semver.lt(fixed, best)) best = fixed
      }
    }
  }
  return best
}

/**
 * Breadth-first search from the product outward, so each component gets the
 * shortest route to it. Shortest is the most useful one to show: it is the
 * fewest hops a reader has to understand.
 */
function shortestPaths(graph: DependencyGraph): Map<string, string[]> {
  const paths = new Map<string, string[]>([[graph.root.bomRef, [graph.root.bomRef]]])
  const queue: string[] = [graph.root.bomRef]

  while (queue.length > 0) {
    const current = queue.shift()
    if (current === undefined) continue
    const path = paths.get(current)
    if (path === undefined) continue

    for (const next of graph.edges.get(current) ?? []) {
      if (paths.has(next)) continue
      paths.set(next, [...path, next])
      queue.push(next)
    }
  }
  return paths
}

function componentNames(graph: DependencyGraph): Map<string, string> {
  const names = new Map<string, string>([[graph.root.bomRef, graph.root.name]])
  for (const component of graph.components) names.set(component.bomRef, component.name)
  return names
}

function reverseEdges(
  graph: DependencyGraph,
  names: ReadonlyMap<string, string>,
): Map<string, Set<string>> {
  const dependents = new Map<string, Set<string>>()
  for (const [from, targets] of graph.edges) {
    const fromName = names.get(from)
    if (fromName === undefined) continue
    for (const target of targets) {
      const set = dependents.get(target)
      if (set === undefined) dependents.set(target, new Set([fromName]))
      else set.add(fromName)
    }
  }
  return dependents
}

/** Count findings per severity, worst first, for the console and the report. */
export function countBySeverity(findings: readonly Finding[]): Map<Severity, number> {
  const counts = new Map<Severity, number>()
  for (const finding of findings) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1)
  }
  return counts
}
