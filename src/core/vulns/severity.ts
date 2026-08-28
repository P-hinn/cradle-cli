import { SEVERITY_ORDER, type Severity, type SeveritySource } from '../../types/index.js'
import { scoreCvssV3 } from './cvss.js'
import type { OsvSeverity, OsvVulnerability } from './osv-types.js'

export function severityRank(severity: Severity): number {
  const index = SEVERITY_ORDER.indexOf(severity)
  return index === -1 ? SEVERITY_ORDER.length : index
}

/** True when `severity` is at least as bad as `threshold`. */
export function atOrAbove(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) <= severityRank(threshold)
}

export interface NormalizedSeverity {
  severity: Severity
  /** Set only when we could compute a score ourselves. */
  cvss?: { vector: string; score: number; version: string }
  /** How we arrived at the severity, so the report can be honest about it. */
  source: SeveritySource
}

/**
 * Work out a severity for a vulnerability.
 *
 * A computed CVSS base score wins, because it is reproducible and sortable. When
 * there is no scoreable vector — a v2 or v4 string, or none at all — the
 * advisory's own label is used instead. Both cases are recorded in `source`; the
 * report says which, because a CVSS base score describes the vulnerability in
 * the abstract and says nothing about exploitability in a given project.
 */
export function normalizeSeverity(vulnerability: OsvVulnerability): NormalizedSeverity {
  const vectors: OsvSeverity[] = [
    ...(vulnerability.severity ?? []),
    ...(vulnerability.affected ?? []).flatMap((a) => a.severity ?? []),
  ]

  let best: { vector: string; score: number; version: string } | undefined
  for (const entry of vectors) {
    const scored = scoreCvssV3(entry.score)
    if (scored === null) continue
    if (best === undefined || scored.score > best.score) {
      best = { vector: entry.score, score: scored.score, version: scored.version }
    }
  }
  if (best !== undefined) {
    return { severity: bucket(best.score), cvss: best, source: 'cvss' }
  }

  const label = readDatabaseSeverity(vulnerability)
  if (label !== undefined) return { severity: label, source: 'database' }

  return { severity: 'unknown', source: 'none' }
}

/** CVSS v3 qualitative ratings. */
function bucket(score: number): Severity {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

function readDatabaseSeverity(vulnerability: OsvVulnerability): Severity | undefined {
  const raw = vulnerability.database_specific?.severity
  if (typeof raw !== 'string') return undefined
  switch (raw.toUpperCase()) {
    case 'CRITICAL':
      return 'critical'
    case 'HIGH':
      return 'high'
    // GitHub says MODERATE where CVSS says MEDIUM.
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium'
    case 'LOW':
      return 'low'
    default:
      return undefined
  }
}
