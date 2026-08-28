/**
 * Library entry point.
 *
 * `core/` functions take their inputs as arguments and return values. They read
 * the project directory where they must — resolving a tree means reading a
 * lockfile — but they never write files and never print. Output and file writing
 * live in `cli/`. See SPEC.md §8.
 */

export { CradleError } from './core/errors.js'
export { type Detection, detectPackageManager } from './core/resolve/detect.js'
export { type ResolveNpmOptions, resolveNpm } from './core/resolve/npm.js'
export { assignBomRefs, type BomRefCandidate } from './core/sbom/bomref.js'
export { type BuildBomOptions, buildBom } from './core/sbom/cyclonedx.js'
export { parseIntegrity } from './core/sbom/hash.js'
export { normalizeLicense, toCycloneDx } from './core/sbom/license.js'
export { npmPurl } from './core/sbom/purl.js'
export { MemoryCache, NULL_CACHE, type VulnCache } from './core/vulns/cache.js'
export { type CvssScore, scoreCvssV3 } from './core/vulns/cvss.js'
export { countBySeverity, resolveFindings } from './core/vulns/findings.js'
export { type OsvClientOptions, type OsvQuery, packageKey, queryOsv } from './core/vulns/osv.js'
export type * from './core/vulns/osv-types.js'
export {
  findingsWithoutFix,
  type Recommendation,
  recommendUpgrades,
} from './core/vulns/recommend.js'
export { atOrAbove, normalizeSeverity, severityRank } from './core/vulns/severity.js'
export * from './types/index.js'
export { TOOL_NAME, TOOL_VERSION } from './version.generated.js'
