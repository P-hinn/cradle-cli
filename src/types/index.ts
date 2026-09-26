/**
 * Shared types. Everything the rest of the codebase consumes is re-exported from
 * here, so `core/`, `cli/` and `report/` never reach into each other's modules.
 */

/** Semantic version of the on-disk artefacts we write under `.cradle/`. */
export const ARTIFACT_SCHEMA_VERSION = 1 as const

export type PackageManager = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry' | 'bun'

/** CycloneDX spec versions we can emit. 1.6 is the default; see SPEC.md §4. */
export type CycloneDxSpecVersion = '1.6' | '1.7'

export const SUPPORTED_SPEC_VERSIONS: readonly CycloneDxSpecVersion[] = ['1.6', '1.7']

// ---------------------------------------------------------------------------
// Resolved dependency graph
// ---------------------------------------------------------------------------

/**
 * Why a package is in the tree. Mirrors the edge types npm/pnpm/yarn use, so a
 * consumer can tell a peer dependency from a plain production one.
 */
export type DependencyKind = 'prod' | 'dev' | 'optional' | 'peer' | 'workspace'

/** A cryptographic hash taken from the lockfile's integrity field. */
export interface ComponentHash {
  /** CycloneDX algorithm name, e.g. `SHA-512`. */
  alg: 'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
  /** Lowercase hex. CycloneDX requires hex, not the base64 npm stores. */
  content: string
}

/**
 * A license as we resolved it. Exactly one of the three shapes is set, which is
 * also how CycloneDX models it:
 *   - `id`         a single valid SPDX identifier
 *   - `expression` a compound SPDX expression such as `(MIT OR Apache-2.0)`
 *   - `name`       free text we could not map onto SPDX
 */
export type ResolvedLicense =
  | { kind: 'id'; id: string }
  | { kind: 'expression'; expression: string }
  | { kind: 'name'; name: string }

export interface ResolvedComponent {
  /**
   * Unique identifier inside this graph, used verbatim as the CycloneDX
   * `bom-ref`. The purl when it is unique across the tree, otherwise the purl
   * with the install location appended — see SPEC.md §5c for why this matters.
   */
  bomRef: string
  name: string
  version: string
  purl: string
  /** Install location relative to the project root, e.g. `node_modules/debug`. */
  location: string
  /** Empty when the package declares no license we could read. */
  licenses: ResolvedLicense[]
  /** True when no license information was available at all. Feeds the readiness check. */
  licenseUnknown: boolean
  hashes: ComponentHash[]
  /** Registry tarball URL from the lockfile, when present. */
  resolvedUrl?: string
  /** Declared by the root package or one of its workspaces. */
  direct: boolean
  /** Only reachable through development dependencies. */
  dev: boolean
  /** A workspace package of this repository rather than a third-party dependency. */
  workspace: boolean
  kinds: DependencyKind[]
}

/** The product being described — becomes CycloneDX `metadata.component`. */
export interface RootComponent {
  bomRef: string
  name: string
  version: string
  purl?: string
  description?: string
  licenses: ResolvedLicense[]
}

/**
 * Why a note exists. Each value is a lockfile shape whose meaning cradle cannot
 * fully carry into an SBOM, and each one is reported rather than dropped.
 *
 * A silently skipped dependency is the worst failure this tool has: the SBOM
 * still looks complete, the finding count still looks like an answer, and
 * nothing says a package was left out. `not assessable` beats a confident blank
 * in the readiness checklist for the same reason (SPEC.md §6.5), and it applies
 * here too.
 */
export type ResolveNoteKind =
  /** Resolved from a git URL, so there is no registry version to match advisories against. */
  | 'git-dependency'
  /** Resolved from a local path (`file:`, `link:`, `portal:`), so it has no registry identity. */
  | 'local-dependency'
  /** Installed under a different name than it is published under (`npm:` alias). */
  | 'aliased-dependency'
  /** Yarn applied a patch, so the installed code is not the published code. */
  | 'patched-dependency'
  /** Declared in the manifest but absent from the lockfile, so it could not be resolved. */
  | 'unresolved-dependency'
  /** Shipped inside its parent's tarball rather than fetched separately. */
  | 'bundled-dependency'

export interface ResolveNote {
  kind: ResolveNoteKind
  /** The package this is about, as `name` or `name@version`. */
  subject: string
  /** What cradle did, in one sentence, in the user's terms. */
  message: string
  /** What the reader should do about it, or how to read the output. */
  hint: string
}

export interface DependencyGraph {
  packageManager: PackageManager
  /** Absolute path of the scanned project. */
  projectDir: string
  root: RootComponent
  components: ResolvedComponent[]
  /** `bom-ref` -> `bom-ref`s it depends on. Includes the root's own entry. */
  edges: Map<string, string[]>
  /** True when dev dependencies were included in this graph. */
  includeDev: boolean
  /** Names of workspace packages, empty when the project is not a monorepo. */
  workspaces: string[]
  /**
   * Shapes in the lockfile that cradle could not represent faithfully, reported
   * so that nothing is skipped in silence. Empty for an ordinary project.
   */
  notes: ResolveNote[]
}

// ---------------------------------------------------------------------------
// CycloneDX output — only the subset we emit, typed strictly.
// ---------------------------------------------------------------------------

export interface CdxLicenseChoice {
  license?: { id?: string; name?: string }
  expression?: string
}

export interface CdxComponent {
  'bom-ref': string
  type: 'library' | 'application'
  name: string
  version: string
  purl?: string
  description?: string
  scope?: 'required' | 'optional' | 'excluded'
  licenses?: CdxLicenseChoice[]
  hashes?: ComponentHash[]
  externalReferences?: CdxExternalReference[]
  properties?: { name: string; value: string }[]
}

export interface CdxExternalReference {
  url: string
  type: 'distribution' | 'website' | 'vcs' | 'issue-tracker' | 'other'
  hashes?: ComponentHash[]
}

export interface CdxDependency {
  ref: string
  dependsOn?: string[]
}

/** CycloneDX `organizationalEntity`, used for who made the SBOM. */
export interface CdxOrganizationalEntity {
  name?: string
  url?: string[]
  contact?: { name?: string; email?: string }[]
}

export interface CdxBom {
  $schema: string
  bomFormat: 'CycloneDX'
  specVersion: CycloneDxSpecVersion
  serialNumber: string
  version: number
  metadata: {
    timestamp: string
    /**
     * Who created this SBOM. BSI TR-03183-2 §5.2.1 requires it; CycloneDX makes
     * it optional, so it appears only when the project configured a contact.
     */
    manufacturer?: CdxOrganizationalEntity
    /**
     * Object form, not the array form. `metadata.tools` as an array has been
     * deprecated since CycloneDX 1.5 — see SPEC.md §5b.
     */
    tools: { components: CdxComponent[] }
    component: CdxComponent
    properties?: { name: string; value: string }[]
  }
  components: CdxComponent[]
  dependencies: CdxDependency[]
}

// ---------------------------------------------------------------------------
// Vulnerability findings
// ---------------------------------------------------------------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'

/** Ordered worst-first, so a table can sort on the index. */
export const SEVERITY_ORDER: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'none',
  'unknown',
]

/**
 * How a severity was arrived at. The report states this, because a CVSS base
 * score describes a vulnerability in the abstract and says nothing about
 * whether it is reachable in a given project.
 */
export type SeveritySource = 'cvss' | 'database' | 'none'

export interface Finding {
  /** Primary OSV identifier, usually a GHSA. */
  id: string
  /** Other identifiers for the same issue, usually the CVE. */
  aliases: string[]
  summary: string
  severity: Severity
  severitySource: SeveritySource
  cvss?: { vector: string; score: number; version: string }
  component: {
    bomRef: string
    name: string
    version: string
    purl: string
    direct: boolean
  }
  /** Lowest version that fixes it, when the advisory names one. */
  fixedIn?: string
  /**
   * Shortest route from the product to the affected package, by name, e.g.
   * `['acme-widget', 'express', 'body-parser']`.
   */
  path: string[]
  /** Names of the packages that pull the affected one in directly. */
  dependents: string[]
  references: { type: string; url: string }[]
  osvUrl: string
  published?: string
  modified?: string
  /**
   * True when a live VEX statement takes this finding out of the count. An
   * expired statement leaves this false — that is the point of an expiry date.
   */
  suppressed?: boolean
  /** Present whenever a statement matched, including an expired one. */
  suppression?: Suppression
  /**
   * Whether anyone appears to be exploiting this, as distinct from how bad it
   * would be. Absent under `--offline`, and absent for a finding with no CVE
   * alias — both sources are keyed on CVE. See core/vulns/priority.ts.
   */
  exploit?: {
    /** EPSS: probability of exploitation in the next 30 days, 0..1. */
    epss?: number
    epssPercentile?: number
    /** The model run this came from, so a stale number is visibly stale. */
    epssDate?: string
    /** On CISA's Known Exploited Vulnerabilities catalogue. */
    knownExploited?: boolean
    knownExploitedSince?: string
  }
}

export interface FindingsDocument {
  schemaVersion: typeof ARTIFACT_SCHEMA_VERSION
  timestamp: string
  tool: { name: string; version: string }
  project: { name: string; version: string }
  scope: 'production' | 'all'
  packageManager: PackageManager
  /** True when the vulnerability lookup was skipped entirely. */
  offline: boolean
  componentCount: number
  findings: Finding[]
  /**
   * Findings a VEX statement takes out of the count. Kept in the document rather
   * than dropped, because "we looked at this and decided it does not apply" is
   * exactly what an audit wants to see.
   */
  suppressed: Finding[]
  /**
   * Lockfile shapes cradle could not represent faithfully. Recorded here so that
   * a machine reading this file sees the same caveats the report shows a human,
   * rather than a component list that merely looks complete.
   */
  notes: ResolveNote[]
}

// ---------------------------------------------------------------------------
// VEX (OpenVEX v0.2.0)
// ---------------------------------------------------------------------------

export const OPENVEX_CONTEXT = 'https://openvex.dev/ns/v0.2.0'

export type VexStatus = 'not_affected' | 'affected' | 'fixed' | 'under_investigation'

/**
 * The only justifications OpenVEX defines. Free text is available in addition
 * through `status_notes`, but the category is mandatory — that is what makes a
 * suppression auditable instead of a silent dismissal.
 */
export const VEX_JUSTIFICATIONS = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
] as const

export type VexJustification = (typeof VEX_JUSTIFICATIONS)[number]

/** Plain-language gloss for each justification, for the report and the CLI. */
export const VEX_JUSTIFICATION_TEXT: Record<VexJustification, string> = {
  component_not_present: 'The vulnerable component is not in the delivered product.',
  vulnerable_code_not_present: 'The component is present, but the vulnerable code is not.',
  vulnerable_code_not_in_execute_path: 'The vulnerable code is present but never executed.',
  vulnerable_code_cannot_be_controlled_by_adversary:
    'The vulnerable code executes, but an attacker cannot reach or influence it.',
  inline_mitigations_already_exist: 'Existing mitigations already prevent exploitation.',
}

export interface VexProduct {
  '@id': string
  subcomponents?: { '@id': string }[]
}

export interface VexStatement {
  '@id'?: string
  vulnerability: { name: string; '@id'?: string; description?: string; aliases?: string[] }
  timestamp?: string
  last_updated?: string
  products?: VexProduct[]
  status: VexStatus
  justification?: VexJustification
  impact_statement?: string
  action_statement?: string
  action_statement_timestamp?: string
  status_notes?: string
  /**
   * NOT part of OpenVEX — the specification has no notion of expiry, and no
   * extension point either: its JSON Schema sets `additionalProperties: false` on
   * a statement, so a strict validator rejects the whole document rather than
   * ignoring this key. The prefix makes the extension recognisable, not tolerated.
   * See SPEC.md §6.3 and §16.
   */
  'cradle:expires'?: string
}

export interface VexDocument {
  '@context': typeof OPENVEX_CONTEXT
  '@id': string
  author: string
  role?: string
  timestamp: string
  last_updated?: string
  version: number
  tooling?: string
  statements: VexStatement[]
}

/** What a VEX statement means for one finding, once expiry has been applied. */
export interface Suppression {
  statementId?: string
  status: VexStatus
  justification?: VexJustification
  /** The human explanation from `status_notes`, when there is one. */
  notes?: string
  actionStatement?: string
  expires?: string
  /** Negative once the date has passed. */
  expiresInDays?: number
  /** True when the statement has lapsed and therefore no longer applies. */
  expired: boolean
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

export interface BaselineEntry {
  /** Advisory identifier, as cradle reports it. */
  id: string
  /** Package name. Not the purl: see SPEC.md §6.4 for why the version is out. */
  package: string
  /** The severity when this was accepted, so a later re-rating is still news. */
  severity: Severity
  acceptedAt: string
}

export interface BaselineDocument {
  schemaVersion: typeof ARTIFACT_SCHEMA_VERSION
  timestamp: string
  tool: { name: string; version: string }
  project: { name: string; version: string }
  scope: 'production' | 'all'
  entries: BaselineEntry[]
}

export interface BaselineDiff {
  /** Not in the baseline, or worse than when it was accepted. */
  added: Finding[]
  /** Already accepted, at the same severity or better. */
  known: Finding[]
  /** In the baseline but absent from this scan, so presumably fixed. */
  resolved: BaselineEntry[]
  /** Accepted before, but the advisory has since been rated worse. */
  worsened: Finding[]
}

// ---------------------------------------------------------------------------
// CRA readiness
// ---------------------------------------------------------------------------

/**
 * Project facts cradle cannot work out from the code, read from
 * `.cradle/config.json`.
 */
export interface CradleConfig {
  /** The product as it is placed on the market, if that differs from the package name. */
  productName?: string
  /** Where vulnerability reports should be sent. */
  contactEmail?: string
  /** ISO date the support period ends (CRA Art. 13(8)). */
  supportPeriodEnd?: string
  /** ISO date the product was first placed on the market, for the five-year rule. */
  placedOnMarket?: string
}

/**
 * `met`            nothing further to do
 * `partial`        in place but incomplete
 * `open`           not done
 * `not-assessable` cradle cannot tell, and says so rather than guessing
 */
export type ReadinessStatus = 'met' | 'partial' | 'open' | 'not-assessable'

export interface ReadinessCheck {
  id: string
  title: string
  status: ReadinessStatus
  /** What cradle found. */
  detail: string
  /** What to do about it, phrased as an instruction rather than a reproach. */
  nextStep: string
  /** The article this relates to, for a reader holding the regulation. */
  reference?: string
}

export interface ReadinessReport {
  checks: ReadinessCheck[]
  counts: Record<ReadinessStatus, number>
}

// ---------------------------------------------------------------------------
// Scan options
// ---------------------------------------------------------------------------

export interface ScanOptions {
  projectDir: string
  includeDev: boolean
  offline: boolean
  specVersion: CycloneDxSpecVersion
  outputDir: string
}
