/**
 * Shared types. Everything the rest of the codebase consumes is re-exported from
 * here, so `core/`, `cli/` and `report/` never reach into each other's modules.
 *
 * Populated in milestone 1.
 */

/** Semantic version of the on-disk artefacts we write under `.cradle/`. */
export const ARTIFACT_SCHEMA_VERSION = 1 as const

export type PackageManager = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry' | 'bun'

/** CycloneDX spec versions we can emit. 1.6 is the default; see SPEC.md §4. */
export type CycloneDxSpecVersion = '1.6' | '1.7'
