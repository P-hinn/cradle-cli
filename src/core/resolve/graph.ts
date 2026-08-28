import type {
  DependencyGraph,
  DependencyKind,
  PackageManager,
  ResolvedComponent,
  ResolvedLicense,
  RootComponent,
} from '../../types/index.js'
import { assignBomRefs } from '../sbom/bomref.js'
import { parseIntegrity } from '../sbom/hash.js'
import { normalizeLicense } from '../sbom/license.js'
import { npmPurl } from '../sbom/purl.js'

/**
 * What every lockfile parser produces, before the shared machinery turns it into
 * a graph. Keeping this common means prod/dev classification, bom-ref assignment
 * and component construction are written once and behave identically for npm,
 * pnpm and both Yarns.
 */
export interface RawPackage {
  /** Unique within one lockfile. Usually `name@version`. */
  key: string
  name: string
  version: string
  /** Subresource Integrity string, where the lockfile carries a real one. */
  integrity?: string
  resolvedUrl?: string
  /** Dependency name -> the key of the package it resolves to. */
  dependencies: Map<string, string>
  /** Names among `dependencies` that are peer edges. */
  peers?: Set<string>
  /** Names among `dependencies` that are optional edges. */
  optional?: Set<string>
  workspace?: boolean
  /** Path from the project root to this package's directory, for reading its licence. */
  location?: string
}

export interface RootManifest {
  name?: string
  version?: string
  description?: string
  private?: boolean
  license?: unknown
  licenses?: unknown
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
}

export interface BuildGraphInput {
  packageManager: PackageManager
  projectDir: string
  manifest: RootManifest
  packages: Map<string, RawPackage>
  /** Keys the root's production dependencies resolve to. */
  rootProd: Map<string, string>
  /** Keys the root's development dependencies resolve to. */
  rootDev: Map<string, string>
  includeDev: boolean
  /** Licences read from disk, keyed by package key. Empty when none were found. */
  licenses?: ReadonlyMap<string, ResolvedLicense[]>
}

/**
 * Turn a parsed lockfile into a dependency graph.
 *
 * The interesting part is prod/dev classification. npm records it in the
 * lockfile; pnpm records it per importer; neither Yarn records it at all. So it
 * is derived the same way for everyone: walk from the root's production
 * dependencies, then from its development ones, and call a package "dev" only
 * when nothing in the production walk reached it.
 */
export function buildGraph(input: BuildGraphInput): DependencyGraph {
  const prodReachable = reachable(input.packages, input.rootProd.values())
  const devReachable = reachable(input.packages, input.rootDev.values())

  const included = new Map<string, RawPackage>()
  for (const [key, pkg] of input.packages) {
    const isDev = !prodReachable.has(key) && devReachable.has(key)
    if (isDev && !input.includeDev) continue
    if (!prodReachable.has(key) && !devReachable.has(key) && pkg.workspace !== true) continue
    included.set(key, pkg)
  }

  const bomRefs = assignBomRefs(
    [...included.values()].map((pkg) => ({
      location: pkg.location ?? pkg.key,
      name: pkg.name,
      version: pkg.version,
    })),
  )
  const refFor = (pkg: RawPackage): string | undefined => bomRefs.get(pkg.location ?? pkg.key)

  const rootRef = rootBomRef(input.manifest)
  const directKeys = new Set<string>([
    ...input.rootProd.values(),
    ...(input.includeDev ? input.rootDev.values() : []),
  ])
  // A workspace package's own dependencies are declared by this product too.
  for (const pkg of included.values()) {
    if (pkg.workspace !== true) continue
    for (const key of pkg.dependencies.values()) directKeys.add(key)
  }

  const kinds = new Map<string, Set<DependencyKind>>()
  const edges = new Map<string, string[]>()

  const rootEdges = new Set<string>()
  for (const [name, key] of [...input.rootProd, ...(input.includeDev ? input.rootDev : [])]) {
    const target = included.get(key)
    const ref = target === undefined ? undefined : refFor(target)
    if (ref === undefined) continue
    rootEdges.add(ref)
    addKind(kinds, key, input.rootProd.has(name) ? 'prod' : 'dev')
  }
  edges.set(rootRef, [...rootEdges].sort())

  for (const [key, pkg] of included) {
    const from = refFor(pkg)
    if (from === undefined) continue

    const targets = new Set<string>()
    for (const [name, targetKey] of pkg.dependencies) {
      const target = included.get(targetKey)
      const ref = target === undefined ? undefined : refFor(target)
      if (ref === undefined) continue
      targets.add(ref)
      addKind(
        kinds,
        targetKey,
        pkg.peers?.has(name) === true
          ? 'peer'
          : pkg.optional?.has(name) === true
            ? 'optional'
            : pkg.workspace === true
              ? 'workspace'
              : 'prod',
      )
    }
    edges.set(from, [...targets].sort())
    if (!kinds.has(key) && pkg.workspace === true) addKind(kinds, key, 'workspace')
  }

  const components: ResolvedComponent[] = []
  for (const [key, pkg] of included) {
    const bomRef = refFor(pkg)
    if (bomRef === undefined) continue

    const licenses = input.licenses?.get(key) ?? []
    const component: ResolvedComponent = {
      bomRef,
      name: pkg.name,
      version: pkg.version,
      purl: npmPurl(pkg.name, pkg.version),
      location: pkg.location ?? pkg.key,
      licenses,
      licenseUnknown: licenses.length === 0,
      hashes: parseIntegrity(pkg.integrity),
      direct: directKeys.has(key),
      dev: !prodReachable.has(key) && devReachable.has(key),
      workspace: pkg.workspace === true,
      kinds: [...(kinds.get(key) ?? new Set<DependencyKind>())].sort(),
    }
    if (pkg.resolvedUrl !== undefined) component.resolvedUrl = pkg.resolvedUrl
    components.push(component)
  }
  components.sort((a, b) => a.bomRef.localeCompare(b.bomRef))

  return {
    packageManager: input.packageManager,
    projectDir: input.projectDir,
    root: buildRoot(input.manifest, rootRef),
    components,
    edges,
    includeDev: input.includeDev,
    workspaces: components
      .filter((component) => component.workspace)
      .map((component) => component.name)
      .sort(),
  }
}

function addKind(kinds: Map<string, Set<DependencyKind>>, key: string, kind: DependencyKind): void {
  const set = kinds.get(key)
  if (set === undefined) kinds.set(key, new Set([kind]))
  else set.add(kind)
}

/** Every package reachable from these entry points. */
function reachable(packages: Map<string, RawPackage>, roots: Iterable<string>): Set<string> {
  const seen = new Set<string>()
  const queue = [...roots]
  while (queue.length > 0) {
    const key = queue.shift()
    if (key === undefined || seen.has(key)) continue
    seen.add(key)
    const pkg = packages.get(key)
    if (pkg === undefined) continue
    for (const next of pkg.dependencies.values()) {
      if (!seen.has(next)) queue.push(next)
    }
  }
  return seen
}

export function rootBomRef(manifest: RootManifest): string {
  const name = manifest.name
  if (name === undefined || name === '') {
    throw new Error('The project package.json has no "name" field')
  }
  const version = manifest.version
  return version === undefined || version === '' ? `root:${name}` : npmPurl(name, version)
}

function buildRoot(manifest: RootManifest, bomRef: string): RootComponent {
  const name = manifest.name ?? ''
  const version = manifest.version ?? '0.0.0'
  const root: RootComponent = {
    bomRef,
    name,
    version,
    licenses: normalizeLicense(manifest),
  }
  if (manifest.private !== true) root.purl = npmPurl(name, version)
  if (typeof manifest.description === 'string') root.description = manifest.description
  return root
}
