import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { DependencyGraph, ResolvedLicense } from '../../types/index.js'
import { CradleError } from '../errors.js'
import { normalizeLicense } from '../sbom/license.js'
import { buildGraph, type RawPackage, type RootManifest } from './graph.js'
import { readManifest } from './manifest.js'

/** One entry of the `packages` map, keyed by its path from the project root. */
interface LockEntry {
  name?: string
  version?: string
  resolved?: string
  integrity?: string
  license?: unknown
  licenses?: unknown
  dev?: boolean
  optional?: boolean
  devOptional?: boolean
  peer?: boolean
  link?: boolean
  extraneous?: boolean
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
}

interface Lockfile {
  lockfileVersion?: number
  packages?: Record<string, LockEntry>
}

export interface ResolveNpmOptions {
  projectDir: string
  includeDev: boolean
}

/**
 * Resolve an npm project from `package-lock.json`.
 *
 * The `packages` map of lockfileVersion 2 and 3 is not a list of requirements —
 * it is the materialised tree, keyed by the exact path each package occupies in
 * `node_modules`. Everything needed is already in it: the resolved version, the
 * integrity, and since v2 the licence too. Edges follow node's own resolution
 * rule, walking up the `node_modules` chain from the dependent's own location,
 * which is what makes a nested duplicate resolve to the right copy.
 *
 * This replaced `@npmcli/arborist`, which produced the same answer but brought
 * 115 transitive dependencies of its own — in a tool whose subject is the size
 * and provenance of dependency trees, that was hard to justify. The equivalence
 * is pinned by test/resolve/npm-parity.test.ts.
 */
export async function resolveNpm(options: ResolveNpmOptions): Promise<DependencyGraph> {
  const lock = await readLockfile(options.projectDir)
  const manifest = await readManifest(options.projectDir)

  const entries = new Map(Object.entries(lock.packages ?? {}))
  const packages = new Map<string, RawPackage>()
  const licenses = new Map<string, ResolvedLicense[]>()

  // A workspace is materialised twice: once at its real path, and once as a link
  // in node_modules. The link is only a pointer, so it is followed, never listed.
  const follow = (location: string): string => {
    const entry = entries.get(location)
    if (entry?.link !== true) return location
    return typeof entry.resolved === 'string' ? entry.resolved : location
  }

  for (const [location, entry] of entries) {
    if (location === '') continue
    if (entry.link === true) continue
    if (entry.extraneous === true) continue

    const name = entry.name ?? nameFromLocation(location)
    const version = entry.version
    if (name === undefined || version === undefined) continue

    const pkg: RawPackage = {
      key: location,
      name,
      version,
      dependencies: new Map(),
      peers: new Set(),
      optional: new Set(),
      location,
    }
    if (typeof entry.integrity === 'string') pkg.integrity = entry.integrity
    if (typeof entry.resolved === 'string' && entry.resolved.startsWith('http')) {
      pkg.resolvedUrl = entry.resolved
    }
    // Anything outside node_modules is a workspace of this repository.
    if (!location.startsWith('node_modules/')) pkg.workspace = true

    packages.set(location, pkg)
    licenses.set(location, normalizeLicense(entry))
  }

  for (const [location, pkg] of packages) {
    const entry = entries.get(location)
    if (entry === undefined) continue

    const link = (
      names: Record<string, string> | undefined,
      kind: 'prod' | 'peer' | 'optional',
    ): void => {
      for (const name of Object.keys(names ?? {})) {
        const target = resolveFrom(location, name, entries, follow)
        if (target === undefined || !packages.has(target)) continue
        pkg.dependencies.set(name, target)
        if (kind === 'peer') pkg.peers?.add(name)
        if (kind === 'optional') pkg.optional?.add(name)
      }
    }
    link(entry.dependencies, 'prod')
    link(entry.optionalDependencies, 'optional')
    link(entry.peerDependencies, 'peer')
    // A workspace's own dev dependencies belong to the product's dev tree.
    link(entry.devDependencies, 'prod')
  }

  const root = entries.get('') ?? {}
  const rootProd = new Map<string, string>()
  const rootDev = new Map<string, string>()
  for (const name of [
    ...Object.keys(root.dependencies ?? {}),
    ...Object.keys(root.optionalDependencies ?? {}),
  ]) {
    const target = resolveFrom('', name, entries, follow)
    if (target !== undefined && packages.has(target)) rootProd.set(name, target)
  }
  for (const name of Object.keys(root.devDependencies ?? {})) {
    const target = resolveFrom('', name, entries, follow)
    if (target !== undefined && packages.has(target)) rootDev.set(name, target)
  }
  // Workspaces are declared by the root and are part of the product.
  for (const [location, pkg] of packages) {
    if (pkg.workspace !== true) continue
    rootProd.set(pkg.name, location)
  }

  return buildGraph({
    packageManager: 'npm',
    projectDir: options.projectDir,
    manifest: { ...manifest, ...rootManifestFrom(root, manifest) },
    packages,
    rootProd,
    rootDev,
    includeDev: options.includeDev,
    licenses,
  })
}

/**
 * Node's resolution rule: look in the dependent's own `node_modules`, then in
 * each enclosing one, out to the project root.
 *
 * This is the part that makes a duplicated package resolve correctly. When npm
 * has to install two versions of `ms`, one sits at `node_modules/ms` and the
 * other at `node_modules/debug/node_modules/ms`; only walking up from the
 * dependent finds the copy that dependent actually sees.
 */
function resolveFrom(
  location: string,
  name: string,
  entries: ReadonlyMap<string, LockEntry>,
  follow: (location: string) => string,
): string | undefined {
  let base = location
  for (;;) {
    const candidate = base === '' ? `node_modules/${name}` : `${base}/node_modules/${name}`
    if (entries.has(candidate)) return follow(candidate)
    if (base === '') return undefined
    const cut = base.lastIndexOf('/node_modules/')
    base = cut === -1 ? '' : base.slice(0, cut)
  }
}

/** `node_modules/@scope/name` and `node_modules/name` both yield the name. */
function nameFromLocation(location: string): string | undefined {
  const marker = location.lastIndexOf('node_modules/')
  if (marker === -1) return undefined
  const name = location.slice(marker + 'node_modules/'.length)
  return name === '' ? undefined : name
}

/**
 * The lockfile's root entry repeats the project's own name, version and licence.
 * package.json stays authoritative; this only fills gaps.
 */
function rootManifestFrom(root: LockEntry, manifest: RootManifest): Partial<RootManifest> {
  const filled: Partial<RootManifest> = {}
  if (manifest.name === undefined && typeof root.name === 'string') filled.name = root.name
  if (manifest.version === undefined && typeof root.version === 'string') {
    filled.version = root.version
  }
  return filled
}

async function readLockfile(projectDir: string): Promise<Lockfile> {
  const candidates = ['package-lock.json', 'npm-shrinkwrap.json']
  let lastError: unknown

  for (const name of candidates) {
    const path = join(projectDir, name)
    let raw: string
    try {
      raw = await readFile(path, 'utf8')
    } catch (cause) {
      lastError = cause
      continue
    }

    let parsed: Lockfile
    try {
      parsed = JSON.parse(raw) as Lockfile
    } catch (cause) {
      throw new CradleError(
        `${path} is not valid JSON`,
        'Delete it and run `npm install` to write a fresh one.',
        { cause },
      )
    }

    const version = parsed.lockfileVersion ?? 0
    // v1 had no `packages` map at all, only a nested `dependencies` tree without
    // integrity or licence data. Reading it would mean guessing.
    if (version < 2 || parsed.packages === undefined) {
      throw new CradleError(
        `${path} has lockfileVersion ${version}, which cradle cannot read`,
        'Version 1 predates the packages map, so it carries neither licences nor a ' +
          'materialised tree. Run `npm install` with npm 7 or newer to upgrade it.',
      )
    }
    return parsed
  }

  throw new CradleError(
    `Could not read a lockfile in ${projectDir}`,
    'Run `npm install` and try again.',
    { cause: lastError },
  )
}
