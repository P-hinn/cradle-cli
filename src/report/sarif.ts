import { findManifestLine } from '../cli/github.js'
import type { Finding, Severity } from '../types/index.js'

/**
 * SARIF 2.1.0, for GitHub Code Scanning and GitLab's security dashboard.
 *
 * SARIF is the one interchange format both accept. GitHub Code Scanning has
 * taken it for years; GitLab ingests it through `artifacts:reports:sarif`,
 * generally available since GitLab 19.2. Neither needs a cradle-specific
 * integration as a result, which is the point — a format nobody has to write an
 * adapter for is worth more than a nicer one nobody consumes.
 *
 * Two details carry most of the value.
 *
 * **`security-severity`.** Both platforms sort and filter by a number, not by a
 * word. GitHub maps it onto its own critical/high/medium/low bands using CVSS
 * ranges, so the CVSS base score goes here where cradle has one — and where it
 * does not, the band's midpoint stands in and `severitySource` says so, rather
 * than a precise-looking number nobody computed.
 *
 * **Locations.** A result anchored to the line in `package.json` where the
 * dependency is declared appears next to it in the diff. A transitive dependency
 * is declared nowhere in that file, so it anchors to the lockfile instead: an
 * annotation on a line you can change gets read, one on line 1 does not.
 */

export interface SarifLog {
  $schema: string
  version: '2.1.0'
  runs: SarifRun[]
}

interface SarifRun {
  tool: {
    driver: {
      name: string
      version: string
      informationUri: string
      rules: SarifRule[]
    }
  }
  results: SarifResult[]
  /** So a consumer can tell "we looked and found nothing" from "we did not look". */
  invocations: { executionSuccessful: boolean; toolExecutionNotifications?: SarifNotification[] }[]
  columnKind: 'utf16CodeUnits'
}

interface SarifRule {
  id: string
  name: string
  shortDescription: { text: string }
  fullDescription: { text: string }
  helpUri: string
  help: { text: string; markdown: string }
  defaultConfiguration: { level: SarifLevel }
  properties: {
    tags: string[]
    'security-severity': string
    precision: 'high' | 'medium' | 'low'
  }
}

interface SarifResult {
  ruleId: string
  ruleIndex: number
  level: SarifLevel
  message: { text: string }
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string }
      region?: { startLine: number }
    }
  }[]
  /**
   * What makes a result the *same* result across runs, so a platform does not
   * reopen a dismissal after an unrelated version bump. Advisory plus package
   * name, deliberately without the version — the same identity the baseline uses
   * (SPEC.md §6.4).
   */
  partialFingerprints: { cradleFindingId: string }
  properties: Record<string, unknown>
}

interface SarifNotification {
  level: SarifLevel
  message: { text: string }
}

type SarifLevel = 'error' | 'warning' | 'note' | 'none'

/**
 * SARIF has four levels; cradle has six severities. The mapping is deliberately
 * coarse — critical and high are both `error` — because the number in
 * `security-severity` is what the platforms actually sort on, and pretending to
 * a finer distinction here would just disagree with it.
 */
const LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  none: 'none',
  unknown: 'warning',
}

/**
 * The midpoint of each band, used only when the advisory published no CVSS
 * vector cradle could score. A midpoint is visibly a stand-in; 7.4 would look
 * like a measurement.
 */
const BAND_MIDPOINT: Record<Severity, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5,
  low: 2,
  none: 0,
  unknown: 5,
}

export interface SarifOptions {
  toolName: string
  toolVersion: string
  /** Contents of package.json, for anchoring direct dependencies to a line. */
  manifest?: string
  manifestPath?: string
  /** The lockfile findings were resolved from, where a transitive result lands. */
  lockfilePath?: string
  /** True when the vulnerability lookup did not happen at all. */
  offline?: boolean
  /** Sources that could not be reached, surfaced as notifications rather than hidden. */
  unavailable?: readonly string[]
}

export function buildSarif(findings: readonly Finding[], options: SarifOptions): SarifLog {
  // One rule per advisory, because one advisory can affect several packages and a
  // platform groups by rule.
  const rules: SarifRule[] = []
  const ruleIndex = new Map<string, number>()
  for (const finding of findings) {
    if (ruleIndex.has(finding.id)) continue
    ruleIndex.set(finding.id, rules.length)
    rules.push(toRule(finding))
  }

  const results = findings.map((finding) =>
    toResult(finding, ruleIndex.get(finding.id) ?? 0, options),
  )

  const notifications: SarifNotification[] = []
  if (options.offline === true) {
    notifications.push({
      level: 'warning',
      message: {
        text:
          'The scan ran offline, so no vulnerability lookup was performed. An empty result ' +
          'set here means "not checked", not "nothing found".',
      },
    })
  }
  for (const source of options.unavailable ?? []) {
    notifications.push({
      level: 'note',
      message: { text: `Exploit signals are incomplete: ${source} could not be reached.` },
    })
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: options.toolName,
            version: options.toolVersion,
            informationUri: 'https://github.com/P-hinn/cradle-cli',
            rules,
          },
        },
        results,
        invocations: [
          {
            // False when nothing was looked up: a consumer must be able to tell
            // an empty result set from a clean one.
            executionSuccessful: options.offline !== true,
            ...(notifications.length === 0 ? {} : { toolExecutionNotifications: notifications }),
          },
        ],
        columnKind: 'utf16CodeUnits',
      },
    ],
  }
}

function toRule(finding: Finding): SarifRule {
  const summary = finding.summary === '' ? finding.id : finding.summary
  const tags = ['security', 'dependency', `severity/${finding.severity}`]
  if (finding.exploit?.knownExploited === true) tags.push('exploit/cisa-kev')

  return {
    id: finding.id,
    name: finding.id,
    shortDescription: { text: truncate(summary, 120) },
    fullDescription: { text: summary },
    helpUri: finding.osvUrl,
    help: {
      text: helpText(finding),
      markdown: helpMarkdown(finding),
    },
    defaultConfiguration: { level: LEVEL[finding.severity] },
    properties: {
      tags,
      'security-severity': securitySeverity(finding),
      // The advisory is high-precision about the version range; whether the
      // vulnerable code is reachable in this project is a separate question, and
      // one cradle does not answer.
      precision: 'high',
    },
  }
}

/**
 * The number both platforms sort on.
 *
 * The computed CVSS base score where the advisory published a vector, and the
 * band's midpoint where it did not — never a fabricated decimal. One place
 * decides this, so the report and the dashboard cannot disagree.
 */
function securitySeverity(finding: Finding): string {
  return (finding.cvss?.score ?? BAND_MIDPOINT[finding.severity]).toFixed(1)
}

function toResult(finding: Finding, index: number, options: SarifOptions): SarifResult {
  const line =
    finding.component.direct && options.manifest !== undefined
      ? findManifestLine(options.manifest, finding.component.name)
      : undefined

  // A direct dependency anchors to the line in package.json a reader can change.
  // A transitive one is declared nowhere in that file, so it points at the
  // lockfile rather than at a line nobody can act on.
  const uri =
    line === undefined
      ? (options.lockfilePath ?? options.manifestPath ?? 'package.json')
      : (options.manifestPath ?? 'package.json')

  const fix =
    finding.fixedIn === undefined
      ? 'No fix is available yet.'
      : `Fixed in ${finding.component.name} ${finding.fixedIn}.`
  const route = finding.component.direct
    ? 'A direct dependency.'
    : `Reached as ${finding.path.join(' › ')}.`

  return {
    ruleId: finding.id,
    ruleIndex: index,
    level: LEVEL[finding.severity],
    message: {
      text:
        `${finding.id} affects ${finding.component.name} ${finding.component.version}. ` +
        `${route} ${fix}${exploitSentence(finding)}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          ...(line === undefined ? {} : { region: { startLine: line } }),
        },
      },
    ],
    partialFingerprints: {
      cradleFindingId: `${finding.id}:${finding.component.name}`,
    },
    properties: {
      severity: finding.severity,
      severitySource: finding.severitySource,
      package: finding.component.name,
      version: finding.component.version,
      purl: finding.component.purl,
      direct: finding.component.direct,
      path: finding.path,
      ...(finding.fixedIn === undefined ? {} : { fixedIn: finding.fixedIn }),
      ...(finding.cvss === undefined ? {} : { cvss: finding.cvss }),
      ...(finding.exploit === undefined ? {} : { exploit: finding.exploit }),
      ...(finding.suppression === undefined ? {} : { suppression: finding.suppression }),
    },
  }
}

function exploitSentence(finding: Finding): string {
  const exploit = finding.exploit
  if (exploit === undefined) return ''
  const parts: string[] = []
  if (exploit.knownExploited === true) {
    parts.push(
      ` On the CISA Known Exploited Vulnerabilities catalogue${
        exploit.knownExploitedSince === undefined || exploit.knownExploitedSince === ''
          ? ''
          : ` since ${exploit.knownExploitedSince}`
      }.`,
    )
  }
  if (exploit.epss !== undefined) {
    parts.push(` EPSS ${(exploit.epss * 100).toFixed(1)}%.`)
  }
  return parts.join('')
}

function helpText(finding: Finding): string {
  const lines = [
    finding.summary === '' ? finding.id : finding.summary,
    '',
    `Package: ${finding.component.name} ${finding.component.version}`,
    `Route: ${finding.path.join(' › ')}`,
    finding.fixedIn === undefined
      ? 'No fix available. This needs a decision rather than an upgrade.'
      : `Fixed in ${finding.fixedIn}.`,
    '',
    severitySentence(finding),
    '',
    `Advisory: ${finding.osvUrl}`,
  ]
  return lines.join('\n')
}

function helpMarkdown(finding: Finding): string {
  const lines = [
    `**${finding.id}**${finding.aliases.length === 0 ? '' : ` · ${finding.aliases.join(', ')}`}`,
    '',
    finding.summary === '' ? '_No summary was published._' : finding.summary,
    '',
    `| | |`,
    `| :-- | :-- |`,
    `| Package | \`${finding.component.name}\` ${finding.component.version} |`,
    `| Route | ${finding.path.join(' › ')} |`,
    `| Fixed in | ${finding.fixedIn ?? '—'} |`,
    `| Severity | ${finding.severity} |`,
    '',
    severitySentence(finding),
    '',
    `[Advisory](${finding.osvUrl})`,
  ]
  return lines.join('\n')
}

/** The sentence the whole report rests on, repeated where a dashboard shows it. */
function severitySentence(finding: Finding): string {
  if (finding.cvss !== undefined) {
    return (
      `CVSS v${finding.cvss.version} base score ${finding.cvss.score} (${finding.cvss.vector}), ` +
      'computed from the vector. A base score rates the vulnerability in the abstract and says ' +
      'nothing about whether the vulnerable code is reachable in this project.'
    )
  }
  if (finding.severitySource === 'database') {
    return (
      'Severity as rated by the advisory database; no CVSS vector this tool can score was ' +
      'published. The number reported to this dashboard is the midpoint of that band, not a ' +
      'measurement.'
    )
  }
  return 'The advisory carries neither a scoreable CVSS vector nor a severity rating.'
}

function truncate(value: string, limit: number): string {
  return value.length <= limit ? value : `${value.slice(0, limit - 1)}…`
}
