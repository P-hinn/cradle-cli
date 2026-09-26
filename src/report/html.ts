import type { ProfileFieldResult, ProfileReport } from '../core/readiness/profiles/bsi-tr-03183.js'
import { countBySeverity } from '../core/vulns/findings.js'
import { recommendUpgrades } from '../core/vulns/recommend.js'
import { severityRank } from '../core/vulns/severity.js'
import type {
  CycloneDxSpecVersion,
  DependencyGraph,
  Finding,
  ReadinessCheck,
  ReadinessReport,
  ReadinessStatus,
  ResolvedComponent,
  ResolvedLicense,
  ResolveNote,
  Severity,
} from '../types/index.js'
import { SEVERITY_ORDER, VEX_JUSTIFICATION_TEXT } from '../types/index.js'
import { REPORT_JS } from './behaviour.js'
import { embedJson, escapeHtml, safeUrl } from './escape.js'
import { type Language, type Strings, strings } from './i18n/index.js'
import { REPORT_CSS } from './styles.js'

export interface ReportInput {
  graph: DependencyGraph
  findings: readonly Finding[]
  /** Findings a live VEX statement has ruled out. Shown, never hidden. */
  suppressed?: readonly Finding[]
  readiness?: ReadinessReport
  /** Present only when a profile was asked for; absent leaves the section out. */
  profile?: ProfileReport
  /** Exploit-signal sources that could not be reached, named in the table note. */
  priorityUnavailable?: readonly string[]
  /** ISO 8601 timestamp of the scan. */
  timestamp: string
  offline: boolean
  specVersion: CycloneDxSpecVersion
  /** The SBOM's serial number, so a reader can tie report and SBOM together. */
  serialNumber: string
  toolName: string
  toolVersion: string
  /** Defaults to English. The report is one document in one language. */
  lang?: Language
}

/**
 * An ordinal glyph per severity, so the rank survives greyscale printing and
 * does not depend on telling red from orange.
 */
const SEVERITY_GLYPH: Record<Severity, string> = {
  critical: '●●●',
  high: '●●○',
  medium: '●○○',
  low: '○○○',
  none: '–',
  unknown: '?',
}

/**
 * Render the whole report as one self-contained HTML document.
 *
 * Self-contained is the requirement that drives everything else: no webfonts, no
 * scripts, no stylesheets from anywhere. The file has to survive being attached
 * to an email and opened from a download folder two years from now.
 */
export function buildReport(input: ReportInput): string {
  const { graph } = input
  const t = strings(input.lang)
  const title = t.report.title(graph.root.name, graph.root.version)

  return `<!doctype html>
<html lang="${escapeHtml(t.htmlLang)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="${escapeHtml(`${input.toolName} ${input.toolVersion}`)}">
<title>${escapeHtml(title)}</title>
<style>${REPORT_CSS}</style>
</head>
<body>
<div class="wrap">
${masthead(input, t)}
${summarySection(input, t)}
${readinessSection(input, t)}
${profileSection(input, t)}
${findingsSection(input, t)}
${suppressedSection(input, t)}
${notesSection(graph, t)}
${componentsSection(graph, t)}
${colophon(input, t)}
</div>
${dataBlock(input)}
<script>${REPORT_JS}</script>
</body>
</html>
`
}

// ---------------------------------------------------------------------------
// Masthead
// ---------------------------------------------------------------------------

function masthead(input: ReportInput, t: Strings): string {
  const { graph } = input
  const facts: [string, string][] = [
    [t.report.scanned, formatTimestamp(input.timestamp)],
    [t.report.packageManager, graph.packageManager],
    [t.report.scope, graph.includeDev ? t.report.scopeAll : t.report.scopeProduction],
    [t.report.components, String(graph.components.length)],
    [t.report.sbomFormat, `CycloneDX ${input.specVersion}`],
    [t.report.sbomSerial, input.serialNumber],
    [t.report.generatedBy, `${input.toolName} ${input.toolVersion}`],
  ]
  if (graph.workspaces.length > 0) {
    facts.splice(4, 0, [t.report.workspaces, graph.workspaces.join(', ')])
  }

  return `<header class="masthead">
<p class="eyebrow">${escapeHtml(t.report.eyebrow)}</p>
<h1>${escapeHtml(graph.root.name)} <span class="version">${escapeHtml(graph.root.version)}</span></h1>
${graph.root.description === undefined ? '' : `<p class="section-note">${escapeHtml(graph.root.description)}</p>`}
<dl class="facts">
${facts.map(([term, value]) => `  <div><dt>${escapeHtml(term)}</dt><dd${term === t.report.sbomSerial ? ' class="mono"' : ''}>${escapeHtml(value)}</dd></div>`).join('\n')}
</dl>
${
  input.offline
    ? `<p class="banner"><strong>${escapeHtml(t.report.offlineBanner.lead)}</strong> ${escapeHtml(t.report.offlineBanner.body)}</p>`
    : ''
}
</header>`
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

function summarySection(input: ReportInput, t: Strings): string {
  const { graph, findings, offline } = input
  const direct = graph.components.filter((c) => c.direct).length
  const unknownLicence = graph.components.filter((c) => c.licenseUnknown).length
  const withoutFix = findings.filter((f) => f.fixedIn === undefined).length

  const cards = [
    card(
      t.report.components,
      String(graph.components.length),
      t.summary.componentsDetail(direct, graph.components.length - direct),
    ),
    offline
      ? card(t.summary.findings, '—', t.summary.findingsNotChecked)
      : card(
          t.summary.findings,
          String(findings.length),
          withoutFix === 0
            ? t.summary.findingsAllFixable
            : t.summary.findingsWithoutFix(withoutFix),
        ),
    card(
      t.summary.licences,
      String(graph.components.length - unknownLicence),
      unknownLicence === 0
        ? t.summary.licencesAllDeclared
        : t.summary.licencesUndeclared(unknownLicence),
    ),
  ]

  const suppressedCount = (input.suppressed ?? []).length
  if (suppressedCount > 0) {
    cards.push(card(t.summary.suppressed, String(suppressedCount), t.summary.suppressedDetail))
  }

  return `<section>
<h2>${escapeHtml(t.summary.heading)}</h2>
<div class="cards">
${cards.join('\n')}
</div>
${offline ? '' : severityBreakdown(findings, t)}
${recommendationList(findings, offline, t)}
${licenceBreakdown(graph.components, t)}
</section>`
}

function card(label: string, value: string, detail: string): string {
  return `  <div class="card"><div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(value)}</div><div class="detail">${escapeHtml(detail)}</div></div>`
}

function severityBreakdown(findings: readonly Finding[], t: Strings): string {
  const counts = countBySeverity(findings)
  const present = SEVERITY_ORDER.filter((severity) => (counts.get(severity) ?? 0) > 0)
  if (present.length === 0) {
    return `<p class="section-note">${escapeHtml(t.summary.noVulnerabilities)}</p>`
  }

  const max = Math.max(...present.map((severity) => counts.get(severity) ?? 0))
  return `<ul class="sev-list">
${present
  .map((severity) => {
    const count = counts.get(severity) ?? 0
    const width = Math.round((count / max) * 100)
    return `  <li><span class="sev sev-${severity}" data-glyph="${escapeHtml(SEVERITY_GLYPH[severity])}">${escapeHtml(t.severity[severity])}</span><span class="num">${count}</span><span class="bar" role="presentation"><span style="width:${width}%"></span></span></li>`
  })
  .join('\n')}
</ul>`
}

function recommendationList(findings: readonly Finding[], offline: boolean, t: Strings): string {
  if (offline) return ''
  const recommendations = recommendUpgrades(findings).slice(0, 5)
  if (recommendations.length === 0) return ''

  return `<h2>${escapeHtml(t.nextSteps.heading)} <span class="count">${escapeHtml(t.nextSteps.caption)}</span></h2>
<div class="scroll"><table>
<thead><tr><th>${escapeHtml(t.nextSteps.package)}</th><th>${escapeHtml(t.nextSteps.from)}</th><th>${escapeHtml(t.nextSteps.to)}</th><th>${escapeHtml(t.nextSteps.clears)}</th><th>${escapeHtml(t.nextSteps.worst)}</th></tr></thead>
<tbody>
${recommendations
  .map(
    (r) =>
      `  <tr><td><code>${escapeHtml(r.package)}</code> ${r.direct ? `<span class="tag">${escapeHtml(t.components.direct)}</span>` : `<span class="tag">${escapeHtml(t.components.transitive)}</span>`}</td><td class="mono">${escapeHtml(r.from)}</td><td class="mono">${escapeHtml(r.to)}</td><td>${r.findingCount}</td><td>${severityMark(r.worstSeverity, t)}</td></tr>`,
  )
  .join('\n')}
</tbody>
</table></div>`
}

function licenceBreakdown(components: readonly ResolvedComponent[], t: Strings): string {
  const counts = new Map<string, number>()
  for (const component of components) {
    const label = component.licenseUnknown
      ? t.licences.undeclared
      : licenceLabel(component.licenses, t)
    counts.set(label, (counts.get(label) ?? 0) + 1)
  }
  if (counts.size === 0) return ''

  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
  return `<h2>${escapeHtml(t.licences.heading)} <span class="count">${escapeHtml(t.licences.distinct(rows.length))}</span></h2>
<div class="scroll"><table>
<thead><tr><th>${escapeHtml(t.licences.licence)}</th><th>${escapeHtml(t.licences.components)}</th></tr></thead>
<tbody>
${rows.map(([label, count]) => `  <tr><td>${label === t.licences.undeclared ? `<em>${escapeHtml(label)}</em>` : `<code>${escapeHtml(label)}</code>`}</td><td>${count}</td></tr>`).join('\n')}
</tbody>
</table></div>`
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Standards profile
// ---------------------------------------------------------------------------

/**
 * A published profile, field by field.
 *
 * Placed after the CRA checklist and before the findings, because it answers the
 * same kind of question — is the documentation in order — rather than a
 * vulnerability question. Absent unless a profile was requested, so a reader of an
 * ordinary report is not asked to care about a German technical guideline.
 *
 * Every row carries the clause it comes from. A checklist that cannot be traced
 * back to the document it claims to implement is an opinion with a table around
 * it.
 */
function profileSection(input: ReportInput, t: Strings): string {
  const report = input.profile
  if (report === undefined) return ''

  const { profile } = report
  const counts = (['met', 'partial', 'open', 'not-assessable'] as const)
    .filter((status) => report.counts[status] > 0)
    .map((status) => `${report.counts[status]} ${t.readinessStatus[status]}`)
    .join(', ')

  return `<h2>${escapeHtml(profile.title)} <span class="count">${escapeHtml(counts)}</span></h2>
<p class="section-note"><a href="${escapeHtml(profile.url)}">${escapeHtml(t.profile.caption(profile.title, profile.version, profile.date))}</a> ${t.profile.notAConformityAssessment}</p>
<div class="scroll"><table>
<thead><tr><th>${escapeHtml(t.profile.status)}</th><th>${escapeHtml(t.profile.dataField)}</th><th>${escapeHtml(t.profile.askedFor)}</th><th>${escapeHtml(t.profile.detail)}</th></tr></thead>
<tbody>
${report.fields.map((field) => profileRow(field, t)).join('\n')}
</tbody>
</table></div>`
}

function profileRow(field: ProfileFieldResult, t: Strings): string {
  return `<tr data-status="${escapeHtml(field.status)}">
<td>${escapeHtml(t.profile.statusLabel[field.status])}</td>
<td>${escapeHtml(field.title)}<br><span class="section-note">${escapeHtml(field.clause)} · <code>${escapeHtml(field.cyclonedx)}</code></span></td>
<td>${escapeHtml(t.profile.requirement[field.requirement])}</td>
<td>${escapeHtml(field.detail)}${
    field.status === 'met'
      ? ''
      : `<br><span class="section-note">${escapeHtml(field.nextStep)}</span>`
  }</td>
</tr>`
}

function findingsSection(input: ReportInput, t: Strings): string {
  const { findings, offline } = input

  if (offline) {
    return `<h2>${escapeHtml(t.findings.heading)}</h2>
<div class="empty">${t.findings.offline}</div>`
  }
  if (findings.length === 0) {
    return `<h2>${escapeHtml(t.findings.heading)}</h2>
<div class="empty">${escapeHtml(t.findings.none)}</div>`
  }

  const severities = SEVERITY_ORDER.filter((severity) =>
    findings.some((finding) => finding.severity === severity),
  )

  const exploitNote =
    input.priorityUnavailable === undefined || input.priorityUnavailable.length === 0
      ? ''
      : ` ${escapeHtml(t.findings.exploitUnavailable(input.priorityUnavailable.join(' / ')))}`

  return `<h2>${escapeHtml(t.findings.heading)} <span class="count">${findings.length}</span></h2>
<p class="section-note">${escapeHtml(t.findings.exploitCaption)}${exploitNote}</p>
<div class="controls" data-controls="findings" hidden>
  <input type="search" data-filter="text" placeholder="${escapeHtml(t.findings.filterPlaceholder)}" aria-label="${escapeHtml(t.findings.filterLabel)}">
${severities
  .map(
    (severity) =>
      `  <label><input type="checkbox" data-facet="severity" value="${escapeHtml(severity)}"> ${escapeHtml(t.severity[severity])}</label>`,
  )
  .join('\n')}
  <label><input type="checkbox" data-facet="fix" value="none"> ${escapeHtml(t.findings.noFix)}</label>
  <label><input type="checkbox" data-facet="exploited" value="known"> ${escapeHtml(t.findings.knownExploited)}</label>
  <span class="spacer"></span>
  <span class="result-count" data-result-count aria-live="polite"></span>
</div>
<div class="scroll"><table data-table="findings">
<thead><tr>
  <th data-sort="severity">${escapeHtml(t.findings.severity)}</th>
  <th data-sort="id">${escapeHtml(t.findings.advisory)}</th>
  <th data-sort="package">${escapeHtml(t.findings.package)}</th>
  <th data-sort="exploited">${escapeHtml(t.findings.exploited)}</th>
  <th data-sort="fixversion">${escapeHtml(t.findings.fixedIn)}</th>
  <th><span class="sr-only">${escapeHtml(t.findings.details)}</span></th>
</tr></thead>
<tbody>
${findings.map((finding) => findingRows(finding, t)).join('\n')}
</tbody>
</table></div>`
}

function findingRows(finding: Finding, t: Strings): string {
  const haystack = [
    finding.id,
    ...finding.aliases,
    finding.component.name,
    finding.component.version,
    finding.summary,
    ...finding.path,
  ]
    .join(' ')
    .toLowerCase()

  const osvUrl = safeUrl(finding.osvUrl)
  const path = finding.path.map((name) => escapeHtml(name)).join('<span class="sep">›</span>')

  const row = `  <tr data-search="${escapeHtml(haystack)}" data-severity="${escapeHtml(finding.severity)}" data-fix="${finding.fixedIn === undefined ? 'none' : 'available'}" data-exploited="${finding.exploit?.knownExploited === true ? 'known' : 'unknown'}" data-sort-exploited="${exploitRank(finding)}" data-sort-severity="${severityRank(finding.severity)}" data-sort-id="${escapeHtml(finding.id)}" data-sort-package="${escapeHtml(finding.component.name)}" data-sort-fixversion="${escapeHtml(finding.fixedIn ?? '')}">
    <td>${severityMark(finding.severity, t)}</td>
    <td>${osvUrl === undefined ? `<code>${escapeHtml(finding.id)}</code>` : `<a href="${escapeHtml(osvUrl)}" rel="noopener noreferrer"><code>${escapeHtml(finding.id)}</code></a>`}${finding.aliases.length === 0 ? '' : `<div class="pathline">${finding.aliases.map((a) => escapeHtml(a)).join(', ')}</div>`}</td>
    <td><code>${escapeHtml(finding.component.name)}</code> <span class="mono">${escapeHtml(finding.component.version)}</span>${finding.component.direct ? ` <span class="tag">${escapeHtml(t.components.direct)}</span>` : ''}<div class="pathline">${path}</div></td>
    <td>${exploitCell(finding, t)}</td>
    <td>${finding.fixedIn === undefined ? `<span class="tag">${escapeHtml(t.findings.noFix)}</span>` : `<span class="mono">${escapeHtml(finding.fixedIn)}</span>`}</td>
    <td><button type="button" class="disclose" aria-expanded="false" hidden>${escapeHtml(t.findings.details)}</button></td>
  </tr>`

  return `${row}\n${findingDetail(finding, t)}`
}

/**
 * The exploitation cell.
 *
 * Empty of data is said in words rather than left blank or shown as zero. "No
 * data" and "not being exploited" are different answers, and both sources are
 * keyed on CVE — so an advisory cradle knows only by its GHSA has no score, which
 * says nothing about the vulnerability.
 */
function exploitCell(finding: Finding, t: Strings): string {
  const exploit = finding.exploit
  if (exploit === undefined) {
    return `<span class="tag">${escapeHtml(t.findings.noExploitData)}</span>`
  }

  const parts: string[] = []
  if (exploit.knownExploited === true) {
    const label =
      exploit.knownExploitedSince === undefined || exploit.knownExploitedSince === ''
        ? t.findings.knownExploited
        : t.findings.knownExploitedSince(exploit.knownExploitedSince)
    parts.push(`<strong>${escapeHtml(label)}</strong>`)
  }
  if (exploit.epss !== undefined) {
    parts.push(
      escapeHtml(
        t.findings.epss(
          `${(exploit.epss * 100).toFixed(1)}%`,
          exploit.epssPercentile === undefined ? '—' : formatPercentile(exploit.epssPercentile, t),
        ),
      ),
    )
  }
  return parts.length === 0
    ? `<span class="tag">${escapeHtml(t.findings.noExploitData)}</span>`
    : parts.join('<div class="pathline"></div>')
}

/**
 * The percentile, spelled the way the language spells it: an English ordinal
 * ("91st"), a German one ("91."). "91th" is the kind of wrong a reader notices,
 * and noticing it costs the rest of the page some credibility.
 */
function formatPercentile(percentile: number, t: Strings): string {
  const value = Math.round(percentile * 100)
  if (t.htmlLang === 'de') return String(value)
  const suffix =
    value % 100 >= 11 && value % 100 <= 13 ? 'th' : (['th', 'st', 'nd', 'rd'][value % 10] ?? 'th')
  return `${value}${suffix}`
}

/**
 * A sortable number for the exploitation column. Known-exploited outranks any
 * EPSS score, and no data sorts last rather than as zero.
 */
function exploitRank(finding: Finding): number {
  const exploit = finding.exploit
  if (exploit === undefined) return -1
  if (exploit.knownExploited === true) return 2
  return exploit.epss === undefined ? -1 : exploit.epss
}

function findingDetail(finding: Finding, t: Strings): string {
  const rows: [string, string][] = []
  if (finding.summary !== '') rows.push([t.findings.summary, escapeHtml(finding.summary)])

  rows.push([t.findings.severity, severityProvenance(finding, t)])
  if (finding.dependents.length > 0) {
    rows.push([
      t.findings.pulledInBy,
      finding.dependents.map((name) => `<code>${escapeHtml(name)}</code>`).join(', '),
    ])
  }
  if (finding.published !== undefined)
    rows.push([t.findings.published, escapeHtml(formatDate(finding.published))])
  if (finding.modified !== undefined)
    rows.push([t.findings.updated, escapeHtml(formatDate(finding.modified))])

  const references = finding.references
    .map((reference) => ({ type: reference.type, url: safeUrl(reference.url) }))
    .filter((reference): reference is { type: string; url: string } => reference.url !== undefined)
    .slice(0, 8)
  if (references.length > 0) {
    rows.push([
      t.findings.references,
      `<ul>${references.map((r) => `<li><a href="${escapeHtml(r.url)}" rel="noopener noreferrer">${escapeHtml(r.url)}</a></li>`).join('')}</ul>`,
    ])
  }

  return `  <tr class="detail-row" data-open="false" hidden><td colspan="6">
    <dl class="detail-grid">
${rows.map(([term, value]) => `      <dt>${escapeHtml(term)}</dt><dd>${value}</dd>`).join('\n')}
    </dl>
  </td></tr>`
}

/**
 * Say where the severity came from. A CVSS base score describes a vulnerability
 * in the abstract; whether it is reachable in this project is a separate
 * question, and the report should not blur the two.
 */
function severityProvenance(finding: Finding, t: Strings): string {
  if (finding.cvss !== undefined) {
    return t.findings.severityFromCvss(
      escapeHtml(t.severity[finding.severity]),
      escapeHtml(finding.cvss.version),
      escapeHtml(String(finding.cvss.score)),
      escapeHtml(finding.cvss.vector),
    )
  }
  if (finding.severitySource === 'database') {
    return t.findings.severityFromDatabase(escapeHtml(t.severity[finding.severity]))
  }
  return t.findings.severityUnknown
}

// ---------------------------------------------------------------------------
// CRA readiness
// ---------------------------------------------------------------------------

/** Ordinal marks again, so status never depends on colour. */
const STATUS_GLYPH: Record<ReadinessStatus, string> = {
  met: '✓',
  partial: '~',
  open: '!',
  'not-assessable': '?',
}

/**
 * The readiness checklist.
 *
 * This is the part of the report that is about the regulation rather than the
 * dependency tree, and it is where the wording matters most: every item says
 * what was found and what to do next, and none of them claims that doing so
 * makes anyone compliant.
 */
function readinessSection(input: ReportInput, t: Strings): string {
  const readiness = input.readiness
  if (readiness === undefined || readiness.checks.length === 0) return ''

  const open = readiness.counts.open + readiness.counts.partial
  const summary =
    open === 0
      ? t.readiness.nothingOutstanding
      : t.readiness.needAttention(open, readiness.checks.length)

  return `<h2>${escapeHtml(t.readiness.heading)} <span class="count">${escapeHtml(summary)}</span></h2>
<p class="section-note">${escapeHtml(t.readiness.caption)}</p>
<div class="scroll"><table>
<thead><tr><th>${escapeHtml(t.readiness.status)}</th><th>${escapeHtml(t.readiness.check)}</th><th>${escapeHtml(t.readiness.findingAndNextStep)}</th></tr></thead>
<tbody>
${readiness.checks.map((check) => readinessRow(check, t)).join('\n')}
</tbody>
</table></div>`
}

function readinessRow(check: ReadinessCheck, t: Strings): string {
  return `  <tr class="ready-${check.status}">
    <td><span class="status status-${check.status}" data-glyph="${escapeHtml(STATUS_GLYPH[check.status])}">${escapeHtml(t.readinessStatus[check.status])}</span></td>
    <td>${escapeHtml(check.title)}${check.reference === undefined ? '' : `<div class="pathline">${escapeHtml(check.reference)}</div>`}</td>
    <td>${escapeHtml(check.detail)}<div class="pathline"><strong>${escapeHtml(t.readiness.next)}</strong> ${escapeHtml(check.nextStep)}</div></td>
  </tr>`
}

// ---------------------------------------------------------------------------
// Suppressed findings
// ---------------------------------------------------------------------------

/**
 * Suppressed findings are shown, never hidden.
 *
 * A suppression is a decision someone made and signed their name to, and the
 * whole reason for recording the category is that a reviewer can disagree with
 * it. A report that quietly dropped them would be worth less than one that never
 * had VEX at all.
 */
function suppressedSection(input: ReportInput, t: Strings): string {
  const suppressed = input.suppressed ?? []
  if (suppressed.length === 0) return ''

  return `<h2>${escapeHtml(t.suppressed.heading)} <span class="count">${suppressed.length}</span></h2>
<p class="section-note">${escapeHtml(t.suppressed.caption)}</p>
<div class="scroll"><table>
<thead><tr><th>${escapeHtml(t.findings.severity)}</th><th>${escapeHtml(t.findings.advisory)}</th><th>${escapeHtml(t.findings.package)}</th><th>${escapeHtml(t.suppressed.justification)}</th><th>${escapeHtml(t.suppressed.expires)}</th></tr></thead>
<tbody>
${suppressed.map((finding) => suppressedRow(finding, t)).join('\n')}
</tbody>
</table></div>`
}

function suppressedRow(finding: Finding, t: Strings): string {
  const suppression = finding.suppression
  const justification = suppression?.justification
  const osvUrl = safeUrl(finding.osvUrl)

  const reason =
    justification === undefined
      ? `<em>${escapeHtml(suppression?.status ?? 'suppressed')}</em>`
      : `<code>${escapeHtml(justification)}</code><div class="pathline">${escapeHtml(VEX_JUSTIFICATION_TEXT[justification])}</div>`
  const note =
    suppression?.notes === undefined
      ? ''
      : `<div class="pathline">${escapeHtml(suppression.notes)}</div>`

  const expiry = renderExpiry(suppression?.expires, suppression?.expiresInDays, t)

  return `  <tr>
    <td>${severityMark(finding.severity, t)}</td>
    <td>${osvUrl === undefined ? `<code>${escapeHtml(finding.id)}</code>` : `<a href="${escapeHtml(osvUrl)}" rel="noopener noreferrer"><code>${escapeHtml(finding.id)}</code></a>`}</td>
    <td><code>${escapeHtml(finding.component.name)}</code> <span class="mono">${escapeHtml(finding.component.version)}</span></td>
    <td>${reason}${note}</td>
    <td>${expiry}</td>
  </tr>`
}

function renderExpiry(expires: string | undefined, inDays: number | undefined, t: Strings): string {
  if (expires === undefined) return `<span class="tag">${escapeHtml(t.suppressed.noExpiry)}</span>`
  const date = escapeHtml(formatDate(expires))
  if (inDays === undefined) return `<span class="mono">${date}</span>`
  if (inDays < 0) {
    return `<span class="mono">${date}</span><div class="pathline">${escapeHtml(t.suppressed.lapsed)}</div>`
  }
  return `<span class="mono">${date}</span><div class="pathline">${escapeHtml(t.suppressed.inDays(inDays))}</div>`
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Resolution notes
// ---------------------------------------------------------------------------

/**
 * The caveats. Placed ahead of the component table on purpose: everything above
 * this point is a count, and a count cannot tell the reader that one of the
 * things being counted is not quite what it appears to be. Omitted entirely for
 * an ordinary project, so its presence means something.
 */
function notesSection(graph: DependencyGraph, t: Strings): string {
  if (graph.notes.length === 0) return ''

  return `<h2>${escapeHtml(t.notes.heading)} <span class="count">${graph.notes.length}</span></h2>
<p class="section-note">${escapeHtml(t.notes.caption)}</p>
<div class="scroll"><table>
<thead><tr><th>${escapeHtml(t.notes.what)}</th><th>${escapeHtml(t.notes.package)}</th><th>${escapeHtml(t.notes.detail)}</th></tr></thead>
<tbody>
${graph.notes.map((note) => noteRow(note, t)).join('\n')}
</tbody>
</table></div>`
}

function noteRow(note: ResolveNote, t: Strings): string {
  return `<tr>
<td>${escapeHtml(t.notes.label[note.kind])}</td>
<td><code>${escapeHtml(note.subject)}</code></td>
<td>${escapeHtml(note.message)} <span class="section-note">${escapeHtml(note.hint)}</span></td>
</tr>`
}

function componentsSection(graph: DependencyGraph, t: Strings): string {
  if (graph.components.length === 0) {
    return `<h2>${escapeHtml(t.components.heading)}</h2><div class="empty">${escapeHtml(t.components.none)}</div>`
  }

  return `<h2>${escapeHtml(t.components.heading)} <span class="count">${graph.components.length}</span></h2>
<div class="controls" data-controls="components" hidden>
  <input type="search" data-filter="text" placeholder="${escapeHtml(t.components.filterPlaceholder)}" aria-label="${escapeHtml(t.components.filterLabel)}">
  <label><input type="checkbox" data-facet="relationship" value="direct"> ${escapeHtml(t.components.directOnly)}</label>
  <label><input type="checkbox" data-facet="licence" value="unknown"> ${escapeHtml(t.components.undeclaredLicence)}</label>
  <span class="spacer"></span>
  <span class="result-count" data-result-count aria-live="polite"></span>
</div>
<div class="scroll"><table data-table="components">
<thead><tr>
  <th data-sort="name">${escapeHtml(t.components.name)}</th>
  <th data-sort="version">${escapeHtml(t.components.version)}</th>
  <th data-sort="licence">${escapeHtml(t.components.licence)}</th>
  <th data-sort="relationship">${escapeHtml(t.components.relationship)}</th>
</tr></thead>
<tbody>
${graph.components.map((component) => componentRow(component, t)).join('\n')}
</tbody>
</table></div>`
}

function componentRow(component: ResolvedComponent, t: Strings): string {
  const licence = component.licenseUnknown
    ? t.licences.undeclared
    : licenceLabel(component.licenses, t)
  const haystack = `${component.name} ${component.version} ${licence}`.toLowerCase()
  // The data attributes stay in English: they are the filter's vocabulary, not
  // the reader's, and translating them would break the behaviour script.
  const relationship = component.direct ? 'direct' : 'transitive'
  const relationshipLabel = component.direct ? t.components.direct : t.components.transitive

  const tags = [
    component.workspace ? `<span class="tag">${escapeHtml(t.components.workspace)}</span>` : '',
    component.dev ? `<span class="tag">${escapeHtml(t.components.dev)}</span>` : '',
  ]
    .filter((tag) => tag !== '')
    .join(' ')

  return `  <tr data-search="${escapeHtml(haystack)}" data-relationship="${relationship}" data-licence="${component.licenseUnknown ? 'unknown' : 'known'}" data-sort-name="${escapeHtml(component.name)}" data-sort-version="${escapeHtml(component.version)}" data-sort-licence="${escapeHtml(licence)}" data-sort-relationship="${relationship}">
    <td><code>${escapeHtml(component.name)}</code>${tags === '' ? '' : ` ${tags}`}</td>
    <td class="mono">${escapeHtml(component.version)}</td>
    <td>${component.licenseUnknown ? `<em>${escapeHtml(licence)}</em>` : `<code>${escapeHtml(licence)}</code>`}</td>
    <td>${escapeHtml(relationshipLabel)}</td>
  </tr>`
}

// ---------------------------------------------------------------------------
// Footer and embedded data
// ---------------------------------------------------------------------------

function colophon(input: ReportInput, t: Strings): string {
  return `<footer class="colophon">
<p><strong>${escapeHtml(t.colophon.disclaimerLead)}</strong> ${escapeHtml(t.colophon.disclaimerBody(input.toolName))}</p>
<p>${escapeHtml(t.colophon.advisorySnapshot(formatTimestamp(input.timestamp)))}</p>
<p>${t.colophon.embeddedData}</p>
</footer>`
}

/**
 * The same data the page renders, embedded verbatim so the report can be parsed
 * as well as read. A reviewer who receives only this file still has everything.
 */
function dataBlock(input: ReportInput): string {
  return `<script type="application/json" id="cradle-data">
${embedJson({
  tool: { name: input.toolName, version: input.toolVersion },
  project: { name: input.graph.root.name, version: input.graph.root.version },
  timestamp: input.timestamp,
  packageManager: input.graph.packageManager,
  scope: input.graph.includeDev ? 'all' : 'production',
  offline: input.offline,
  sbom: { specVersion: input.specVersion, serialNumber: input.serialNumber },
  components: input.graph.components,
  findings: input.findings,
  suppressed: input.suppressed ?? [],
  readiness: input.readiness ?? null,
})}
</script>`
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

function severityMark(severity: Severity, t: Strings): string {
  return `<span class="sev sev-${severity}" data-glyph="${escapeHtml(SEVERITY_GLYPH[severity])}">${escapeHtml(t.severity[severity])}</span>`
}

function licenceLabel(licenses: readonly ResolvedLicense[], t: Strings): string {
  if (licenses.length === 0) return t.licences.undeclared
  return licenses
    .map((license) => {
      if (license.kind === 'id') return license.id
      if (license.kind === 'expression') return license.expression
      return license.name
    })
    .join(', ')
}

/** UTC, spelled out. A report read in another timezone must not shift its date. */
function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return `${date.toISOString().replace('T', ' ').slice(0, 19)} UTC`
}

function formatDate(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toISOString().slice(0, 10)
}
