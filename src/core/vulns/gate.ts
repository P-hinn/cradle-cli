import type { Finding, Severity } from '../../types/index.js'
import { atOrAbove } from './severity.js'

/**
 * What makes a finding fail the gate.
 *
 * Severity answers "how bad would this be". It is the only question `--fail-on`
 * could ask, and it is the wrong one on its own: a medium that CISA records as
 * being exploited right now is more urgent than a critical nobody has ever
 * touched. Article 14's 24-hour clock starts on *actively exploited*, not on a
 * CVSS score, so the gate has to be able to ask that directly.
 */
export interface GateThresholds {
  /** Fail at or above this severity. `never` disables the severity dimension. */
  severity: Severity | 'never'
  /** Fail on anything in CISA's Known Exploited Vulnerabilities catalogue. */
  kev: boolean
  /** Fail at or above this EPSS probability, 0..1. */
  epss?: number
}

/** Why a finding failed. A finding can fail for more than one reason. */
export type GateReason = 'severity' | 'kev' | 'epss'

export interface GateFailure {
  finding: Finding
  reasons: GateReason[]
}

/**
 * The reasons are kept rather than reduced to a boolean, because a gate that
 * says only "failed" leaves the reader to guess which threshold caught it — and
 * the answer changes what they do next. A KEV hit is an upgrade today; a
 * severity hit may be a decision to record.
 */
export function failingFindings(
  findings: readonly Finding[],
  thresholds: GateThresholds,
): GateFailure[] {
  const failures: GateFailure[] = []

  for (const finding of findings) {
    const reasons: GateReason[] = []

    if (thresholds.severity !== 'never' && atOrAbove(finding.severity, thresholds.severity)) {
      reasons.push('severity')
    }
    if (thresholds.kev && finding.exploit?.knownExploited === true) {
      reasons.push('kev')
    }
    const epss = finding.exploit?.epss
    if (thresholds.epss !== undefined && epss !== undefined && epss >= thresholds.epss) {
      reasons.push('epss')
    }

    if (reasons.length > 0) failures.push({ finding, reasons })
  }

  return failures
}

/** True when the gate would fail on nothing at all. */
export function gateIsOff(thresholds: GateThresholds): boolean {
  return thresholds.severity === 'never' && !thresholds.kev && thresholds.epss === undefined
}

/**
 * How the gate describes itself, for the line that says why a run failed or
 * passed. Reads as prose rather than as a flag dump, because this is the
 * sentence someone reads in a CI log at 3am.
 */
export function describeThresholds(thresholds: GateThresholds): string {
  const parts: string[] = []
  if (thresholds.severity !== 'never') parts.push(`at or above ${thresholds.severity}`)
  if (thresholds.kev) parts.push('known to be exploited')
  if (thresholds.epss !== undefined) {
    parts.push(`EPSS at or above ${(thresholds.epss * 100).toFixed(0)}%`)
  }

  if (parts.length === 0) return 'nothing (the gate is off)'
  if (parts.length === 1) return parts[0] ?? ''
  return `${parts.slice(0, -1).join(', ')} or ${parts.at(-1)}`
}

/** The short label shown against an individual failing finding. */
export function describeReasons(reasons: readonly GateReason[]): string {
  const labels: Record<GateReason, string> = {
    severity: 'severity',
    kev: 'exploited',
    epss: 'EPSS',
  }
  return reasons.map((reason) => labels[reason]).join(' + ')
}
