import { PackageURL } from 'packageurl-js'

/**
 * Build a package URL for an npm package.
 *
 * Scoped packages are the case that trips people up: the scope is the purl
 * namespace *including* the `@`, which then has to be percent-encoded, giving
 * `pkg:npm/%40scope/name@1.2.3`. `packageurl-js` handles the encoding and the
 * lowercasing the purl spec requires for npm names.
 */
export function npmPurl(name: string, version: string): string {
  const slash = name.indexOf('/')
  const scoped = name.startsWith('@') && slash > 0
  const namespace = scoped ? name.slice(0, slash) : undefined
  const bare = scoped ? name.slice(slash + 1) : name
  return new PackageURL('npm', namespace, bare, version, undefined, undefined).toString()
}
