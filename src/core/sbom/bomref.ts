import { npmPurl } from './purl.js'

export interface BomRefCandidate {
  /** Install location, unique within a tree. */
  location: string
  name: string
  version: string
}

/**
 * Assign a stable `bom-ref` to every component.
 *
 * The purl is used as-is while it is unique, which keeps the document readable.
 * It is not always unique: npm duplicates a package when two dependents need
 * incompatible ranges, and conflicting peer resolutions can land the very same
 * name@version at two locations. A repeated bom-ref silently corrupts the
 * `dependencies` block — every edge to the duplicate collapses onto one node —
 * so colliding refs get their install location appended (SPEC.md §5c).
 */
export function assignBomRefs(candidates: Iterable<BomRefCandidate>): Map<string, string> {
  const byPurl = new Map<string, string[]>()
  for (const { location, name, version } of candidates) {
    const purl = npmPurl(name, version)
    const locations = byPurl.get(purl)
    if (locations === undefined) byPurl.set(purl, [location])
    else locations.push(location)
  }

  const refs = new Map<string, string>()
  for (const [purl, locations] of byPurl) {
    const only = locations.length === 1 ? locations[0] : undefined
    if (only !== undefined) {
      refs.set(only, purl)
      continue
    }
    for (const location of locations) refs.set(location, `${purl}#${location}`)
  }
  return refs
}
