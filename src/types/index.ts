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
// Scan options
// ---------------------------------------------------------------------------

export interface ScanOptions {
  projectDir: string
  includeDev: boolean
  offline: boolean
  specVersion: CycloneDxSpecVersion
  outputDir: string
}
