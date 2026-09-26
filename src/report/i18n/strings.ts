import type { ReadinessStatus, ResolveNoteKind, Severity } from '../../types/index.js'

export type Language = 'en' | 'de'

export const LANGUAGES: readonly Language[] = ['en', 'de']

/**
 * Every string the report and the pull-request comment can show.
 *
 * Interpolated strings are functions rather than templates with placeholders,
 * because the two languages do not put the numbers in the same places and a
 * `{count} von {total}` format string invites a translation that reads like one.
 * A function lets German put the verb where German puts the verb.
 *
 * Nothing here is optional. A missing key would fall back to English silently and
 * leave a report that is *mostly* translated, which reads worse than one that is
 * not translated at all — so the type makes both locales carry every key, and a
 * test walks them to make sure neither drifted.
 */
export interface Strings {
  /** Written into the `lang` attribute; a screen reader pronounces by it. */
  htmlLang: string

  report: {
    title: (project: string, version: string) => string
    eyebrow: string
    scanned: string
    packageManager: string
    scope: string
    scopeAll: string
    scopeProduction: string
    components: string
    workspaces: string
    sbomFormat: string
    sbomSerial: string
    generatedBy: string
    offlineBanner: { lead: string; body: string }
  }

  summary: {
    heading: string
    componentsDetail: (direct: number, transitive: number) => string
    findings: string
    findingsNotChecked: string
    findingsAllFixable: string
    findingsWithoutFix: (count: number) => string
    licences: string
    licencesAllDeclared: string
    licencesUndeclared: (count: number) => string
    suppressed: string
    suppressedDetail: string
    noVulnerabilities: string
  }

  nextSteps: {
    heading: string
    caption: string
    package: string
    from: string
    to: string
    clears: string
    worst: string
  }

  licences: {
    heading: string
    distinct: (count: number) => string
    licence: string
    components: string
    undeclared: string
  }

  findings: {
    heading: string
    offline: string
    none: string
    filterPlaceholder: string
    filterLabel: string
    noFix: string
    severity: string
    advisory: string
    package: string
    fixedIn: string
    details: string
    summary: string
    pulledInBy: string
    published: string
    updated: string
    references: string
    /** "critical — CVSS v3.1 base score 9.8 <vector>. …" */
    severityFromCvss: (severity: string, version: string, score: string, vector: string) => string
    severityFromDatabase: (severity: string) => string
    severityUnknown: string
    /** The exploitation column, which is a different question from severity. */
    exploited: string
    knownExploited: string
    knownExploitedSince: (date: string) => string
    epss: (percent: string, percentile: string) => string
    noExploitData: string
    exploitCaption: string
    exploitUnavailable: (sources: string) => string
  }

  readiness: {
    heading: string
    caption: string
    nothingOutstanding: string
    needAttention: (open: number, total: number) => string
    status: string
    check: string
    findingAndNextStep: string
    next: string
  }

  profile: {
    caption: (title: string, version: string, date: string) => string
    notAConformityAssessment: string
    status: string
    dataField: string
    askedFor: string
    detail: string
    statusLabel: Record<ReadinessStatus, string>
    requirement: Record<'required' | 'additional' | 'optional', string>
  }

  suppressed: {
    heading: string
    caption: string
    justification: string
    expires: string
    noExpiry: string
    lapsed: string
    inDays: (days: number) => string
  }

  notes: {
    heading: string
    caption: string
    what: string
    package: string
    detail: string
    label: Record<ResolveNoteKind, string>
  }

  components: {
    heading: string
    none: string
    filterPlaceholder: string
    filterLabel: string
    directOnly: string
    undeclaredLicence: string
    name: string
    version: string
    licence: string
    relationship: string
    direct: string
    transitive: string
    workspace: string
    dev: string
  }

  colophon: {
    disclaimerLead: string
    disclaimerBody: (tool: string) => string
    advisorySnapshot: (timestamp: string) => string
    embeddedData: string
  }

  severity: Record<Severity, string>
  readinessStatus: Record<ReadinessStatus, string>

  markdown: {
    /** The one-line verdict at the top, which is what most readers read. */
    verdictFailing: (count: number, threshold: string) => string
    verdictNewBelowThreshold: (count: number) => string
    verdictClean: string
    subtitle: (components: number, manager: string, scope: string) => string
    scopeAll: string
    scopeProduction: string
    knownFindings: (count: number) => string
    newSinceBaseline: (count: number) => string
    ruledOutByVex: (count: number) => string
    noBaselineYet: string
    severity: string
    advisory: string
    package: string
    fixedIn: string
    noFixYet: string
    truncated: (count: number) => string
    resolved: (count: number) => string
    unfixableSummary: (count: number) => string
    unfixableBody: string
    artifact: (name: string) => string
    footer: (tool: string, version: string) => string
  }
}
