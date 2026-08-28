import type { ArboristManifest, ArboristNode, ArboristRoot, EdgeType } from '@npmcli/arborist'
import Arborist from '@npmcli/arborist'
import type {
  DependencyGraph,
  DependencyKind,
  ResolvedComponent,
  RootComponent,
} from '../../types/index.js'
import { CradleError } from '../errors.js'
import { assignBomRefs } from '../sbom/bomref.js'
import { parseIntegrity } from '../sbom/hash.js'
import { normalizeLicense } from '../sbom/license.js'
import { npmPurl } from '../sbom/purl.js'

export interface ResolveNpmOptions {
  projectDir: string
  includeDev: boolean
}

/** Arborist edge types mapped onto ours; peerOptional collapses into peer. */
const EDGE_KIND: Record<EdgeType, DependencyKind> = {
  prod: 'prod',
  dev: 'dev',
  optional: 'optional',
  peer: 'peer',
  peerOptional: 'peer',
  workspace: 'workspace',
}

/**
 * Resolve an npm project into a dependency graph.
 *
 * Reads the lockfile through Arborist's virtual tree, which is the only way to
 * get the *actually resolved* versions rather than the declared ranges. No
 * network and no node_modules are needed: npm's lockfile carries integrity and,
 * since lockfileVersion 2, the licence of every package.
 */
export async function resolveNpm(options: ResolveNpmOptions): Promise<DependencyGraph> {
  const tree = await loadTree(options.projectDir)

  // Workspace packages appear twice: once at their real path (`packages/ui`) and
  // once as a symlink in node_modules. Keep the real node, resolve edges through
  // the link, and the graph stays free of duplicates.
  const real = (node: ArboristNode): ArboristNode => (node.isLink ? (node.target ?? node) : node)

  const included = new Map<string, ArboristNode>()
  for (const [location, node] of tree.inventory) {
    if (location === '') continue
    if (node.isLink) continue
    if (node.extraneous) continue
    if (node.dev && !options.includeDev) continue
    included.set(location, node)
  }

  const bomRefs = assignBomRefs(
    [...included].flatMap(([location, node]) =>
      node.version === undefined
        ? []
        : [{ location, name: node.package.name ?? node.name, version: node.version }],
    ),
  )

  // "Direct" means declared by a package.json that belongs to this product:
  // the root, or any of its workspaces.
  const productNodes = [tree, ...[...included.values()].filter((n) => n.isWorkspace)]
  const direct = new Set<string>()
  for (const node of productNodes) {
    for (const edge of node.edgesOut.values()) {
      const target = edge.to === null ? null : real(edge.to)
      if (target !== null && included.has(target.location)) direct.add(target.location)
    }
  }

  const kinds = new Map<string, Set<DependencyKind>>()
  const edges = new Map<string, string[]>()

  const rootRef = rootBomRef(tree.package)
  for (const node of [tree, ...included.values()]) {
    const fromRef = node.location === '' ? rootRef : bomRefs.get(node.location)
    if (fromRef === undefined) continue

    const dependsOn = new Set<string>()
    for (const edge of node.edgesOut.values()) {
      // An unresolved edge is an unmet dependency — an optional package that was
      // never installed, or a peer the project chose not to satisfy. Recording a
      // dangling ref would make the dependencies block invalid.
      if (edge.to === null) continue
      if (edge.type === 'dev' && !options.includeDev) continue

      const target = real(edge.to)
      const targetRef = bomRefs.get(target.location)
      if (targetRef === undefined) continue

      dependsOn.add(targetRef)
      const kind = EDGE_KIND[edge.type]
      const seen = kinds.get(target.location)
      if (seen === undefined) kinds.set(target.location, new Set([kind]))
      else seen.add(kind)
    }
    edges.set(fromRef, [...dependsOn].sort())
  }

  const components: ResolvedComponent[] = []
  for (const [location, node] of included) {
    const bomRef = bomRefs.get(location)
    const version = node.version
    if (bomRef === undefined || version === undefined) continue

    const licenses = normalizeLicense(node.package)
    const component: ResolvedComponent = {
      bomRef,
      name: node.package.name ?? node.name,
      version,
      purl: npmPurl(node.package.name ?? node.name, version),
      location,
      licenses,
      licenseUnknown: licenses.length === 0,
      hashes: parseIntegrity(node.integrity),
      direct: direct.has(location),
      dev: node.dev,
      workspace: node.isWorkspace,
      kinds: [...(kinds.get(location) ?? new Set<DependencyKind>())].sort(),
    }
    if (node.resolved !== null) component.resolvedUrl = node.resolved

    components.push(component)
  }
  components.sort((a, b) => a.bomRef.localeCompare(b.bomRef))

  return {
    packageManager: 'npm',
    projectDir: options.projectDir,
    root: buildRoot(tree.package, rootRef),
    components,
    edges,
    includeDev: options.includeDev,
    workspaces: components
      .filter((c) => c.workspace)
      .map((c) => c.name)
      .sort(),
  }
}

async function loadTree(projectDir: string): Promise<ArboristRoot> {
  try {
    return await new Arborist({ path: projectDir }).loadVirtual()
  } catch (cause) {
    throw new CradleError(
      `Could not read the npm dependency tree in ${projectDir}`,
      'The lockfile may be incomplete or out of date. Run `npm install` to refresh it, then try again.',
      { cause },
    )
  }
}

function rootBomRef(manifest: ArboristManifest): string {
  const name = manifest.name
  if (name === undefined || name === '') {
    throw new CradleError(
      'The project package.json has no "name" field',
      'An SBOM has to say what it describes. Add a "name" (and ideally a "version") to package.json.',
    )
  }
  const version = manifest.version
  return version === undefined || version === '' ? `root:${name}` : npmPurl(name, version)
}

function buildRoot(manifest: ArboristManifest, bomRef: string): RootComponent {
  const name = manifest.name ?? ''
  const version = manifest.version ?? '0.0.0'
  const root: RootComponent = {
    bomRef,
    name,
    version,
    licenses: normalizeLicense(manifest),
  }
  // A private root package has no meaningful purl — it was never published.
  if (manifest.private !== true) root.purl = npmPurl(name, version)
  if (typeof manifest.description === 'string') root.description = manifest.description
  return root
}
