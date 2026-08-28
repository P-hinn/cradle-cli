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

export interface CdxBom {
  $schema: string
  bomFormat: 'CycloneDX'
  specVersion: CycloneDxSpecVersion
  serialNumber: string
  version: number
  metadata: {
    timestamp: string
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
   * NOT part of OpenVEX — the specification has no notion of expiry. Namespaced
   * so it reads as an extension and so conforming consumers ignore it. See
   * SPEC.md §6.3.
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
// Scan options
// ---------------------------------------------------------------------------

export interface ScanOptions {
  projectDir: string
  includeDev: boolean
  offline: boolean
  specVersion: CycloneDxSpecVersion
  outputDir: string
}
