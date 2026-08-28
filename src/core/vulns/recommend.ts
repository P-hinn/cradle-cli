import semver from 'semver'
import type { Finding, Severity } from '../../types/index.js'
import { severityRank } from './severity.js'

export interface Recommendation {
  package: string
  from: string
  /** Lowest version that clears every finding on this package. */
  to: string
  findingCount: number
  worstSeverity: Severity
  direct: boolean
}

/**
 * Group findings into the smallest set of upgrades that clears the most.
 *
 * A user does not act on findings, they act on packages. Three lines saying
 * "upgrade X to Y" are worth more than twenty saying "CVE-… affects X", which is
 * why the console summary leads with these.
 */
export function recommendUpgrades(findings: readonly Finding[]): Recommendation[] {
  const byPackage = new Map<string, Finding[]>()
  for (const finding of findings) {
    if (finding.fixedIn === undefined) continue
    const key = `${finding.component.name}@${finding.component.version}`
    const group = byPackage.get(key)
    if (group === undefined) byPackage.set(key, [finding])
    else group.push(finding)
  }

  const recommendations: Recommendation[] = []
  for (const group of byPackage.values()) {
    const first = group[0]
    if (first === undefined) continue

    // Clearing all of them means reaching the highest of the individual fixes.
    let target = ''
    for (const finding of group) {
      const fixedIn = finding.fixedIn
      if (fixedIn === undefined) continue
      if (target === '' || semver.gt(fixedIn, target)) target = fixedIn
    }
    if (target === '') continue

    let worst: Severity = 'unknown'
    for (const finding of group) {
      if (severityRank(finding.severity) < severityRank(worst)) worst = finding.severity
    }

    recommendations.push({
      package: first.component.name,
      from: first.component.version,
      to: target,
      findingCount: group.length,
      worstSeverity: worst,
      direct: first.component.direct,
    })
  }

  // Worst first; then whatever clears the most; then direct dependencies, which
  // the user can actually change without waiting on someone else.
  recommendations.sort(
    (a, b) =>
      severityRank(a.worstSeverity) - severityRank(b.worstSeverity) ||
      b.findingCount - a.findingCount ||
      Number(b.direct) - Number(a.direct) ||
      a.package.localeCompare(b.package),
  )
  return recommendations
}

/**
 * Findings the user cannot fix by upgrading. These are the ones that need a VEX
 * statement or a decision, and the ones most likely to matter under the CRA's
 * reporting duty.
 */
export function findingsWithoutFix(findings: readonly Finding[]): Finding[] {
  return findings.filter((finding) => finding.fixedIn === undefined)
}
