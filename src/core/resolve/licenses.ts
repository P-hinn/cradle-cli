import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { ResolvedLicense } from '../../types/index.js'
import { normalizeLicense } from '../sbom/license.js'
import type { RawPackage } from './graph.js'

/**
 * Read licences off the installed tree.
 *
 * npm writes the licence into its lockfile; pnpm and Yarn do not, so for those
 * the only offline source is `node_modules`. When it is not there — a fresh
 * clone, or Yarn PnP — the licence is reported as unknown and the readiness
 * checklist carries it as an open point. That is the deliberate trade in
 * SPEC.md §4: no silent network access, and no invented answer.
 */
export async function readLicensesFromDisk(
  projectDir: string,
  packages: Iterable<RawPackage>,
  candidatePaths: (pkg: RawPackage) => string[],
): Promise<Map<string, ResolvedLicense[]>> {
  const licenses = new Map<string, ResolvedLicense[]>()

  await Promise.all(
    [...packages].map(async (pkg) => {
      for (const candidate of candidatePaths(pkg)) {
        let raw: string
        try {
          raw = await readFile(join(projectDir, candidate, 'package.json'), 'utf8')
        } catch {
          continue
        }

        let manifest: { name?: unknown; license?: unknown; licenses?: unknown }
        try {
          manifest = JSON.parse(raw) as typeof manifest
        } catch {
          continue
        }
        // A hoisted path can hold a different package of the same name at
        // another version; only trust the file if it is the one we asked for.
        if (typeof manifest.name === 'string' && manifest.name !== pkg.name) continue

        const found = normalizeLicense(manifest)
        if (found.length > 0) {
          licenses.set(pkg.key, found)
          return
        }
      }
    }),
  )

  return licenses
}

/** Where pnpm puts a package: `.pnpm/@scope+name@version/node_modules/@scope/name`. */
export function pnpmCandidates(pkg: RawPackage): string[] {
  const flattened = pkg.name.replace('/', '+')
  return [
    join('node_modules', '.pnpm', `${flattened}@${pkg.version}`, 'node_modules', pkg.name),
    ...(pkg.location === undefined ? [] : [pkg.location]),
    join('node_modules', pkg.name),
  ]
}

/** Yarn hoists, so the plain path is usually right; the recorded one wins. */
export function hoistedCandidates(pkg: RawPackage): string[] {
  return [...(pkg.location === undefined ? [] : [pkg.location]), join('node_modules', pkg.name)]
}
