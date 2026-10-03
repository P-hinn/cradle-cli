import type {
  CdxLicenseChoice,
  DependencyGraph,
  PackageManager,
  ResolvedComponent,
  ResolvedLicense,
  ResolveNote,
  RootComponent,
} from '../../types/index.js'
import { CradleError } from '../errors.js'
import { npmPurl } from './purl.js'

/**
 * Read a CycloneDX document back into a dependency graph.
 *
 * Two jobs the lockfile parsers cannot do. A product that has shipped has a
 * frozen tree: the lockfile in the repository has moved on, but the SBOM in the
 * technical documentation is what was placed on the market, and that is what the
 * support period obliges you to keep watching. And a supplier's SBOM is often
 * the only description of their component you will ever have.
 *
 * The graph this produces is deliberately the same shape a lockfile produces, so
 * findings, VEX, the baseline and the report all work on it unchanged. What it
 * cannot carry is marked rather than guessed at: a component from another
 * ecosystem, or one without enough identity to ask OSV about, becomes a note.
 */
export interface ReadSbomOptions {
  /** Used only for the graph's `projectDir`; nothing is read from it. */
  projectDir: string
  /** Shown in messages, so a reader knows which file a note is about. */
  path: string
}

interface CdxDocument {
  bomFormat?: unknown
  specVersion?: unknown
  metadata?: {
    component?: CdxComponentLike
    properties?: { name?: unknown; value?: unknown }[]
  }
  components?: CdxComponentLike[]
  dependencies?: { ref?: unknown; dependsOn?: unknown }[]
}

interface CdxComponentLike {
  'bom-ref'?: unknown
  type?: unknown
  name?: unknown
  version?: unknown
  purl?: unknown
  description?: unknown
  licenses?: CdxLicenseChoice[]
  hashes?: { alg?: unknown; content?: unknown }[]
  properties?: { name?: unknown; value?: unknown }[]
  externalReferences?: { url?: unknown; type?: unknown }[]
}

export function readCycloneDx(raw: string, options: ReadSbomOptions): DependencyGraph {
  const document = parse(raw, options.path)
  const notes: ResolveNote[] = []

  const rootSource = document.metadata?.component
  if (rootSource === undefined || typeof rootSource.name !== 'string') {
    throw new CradleError(
      `${options.path} has no metadata.component`,
      'A CycloneDX document has to say what it describes. cradle cannot report on a ' +
        'document that does not name its own product.',
    )
  }

  const metaProperties = propertyMap(document.metadata?.properties)
  const root: RootComponent = {
    bomRef: typeof rootSource['bom-ref'] === 'string' ? rootSource['bom-ref'] : rootSource.name,
    name: rootSource.name,
    version: typeof rootSource.version === 'string' ? rootSource.version : '0.0.0',
    licenses: readLicenses(rootSource.licenses),
  }
  if (typeof rootSource.purl === 'string') root.purl = rootSource.purl
  if (typeof rootSource.description === 'string') root.description = rootSource.description

  const components: ResolvedComponent[] = []
  /** bom-ref of every component we kept, so edges can be filtered to them. */
  const kept = new Set<string>([root.bomRef])

  for (const source of document.components ?? []) {
    const name = typeof source.name === 'string' ? source.name : undefined
    const version = typeof source.version === 'string' ? source.version : undefined
    const purl = typeof source.purl === 'string' ? source.purl : undefined
    const bomRef = typeof source['bom-ref'] === 'string' ? source['bom-ref'] : purl

    // Both advisory sources are keyed on an npm name and version. Anything else
    // is reported rather than dropped: a component count that silently shrank
    // would still look complete.
    if (purl === undefined) {
      notes.push({
        kind: 'unidentified-component',
        subject: describe(name, version, purl),
        message: 'The SBOM lists this component without a package URL.',
        hint:
          'A purl is how a component is matched against advisories. Without one cradle ' +
          'cannot tell which package this is, so it is counted but not checked.',
      })
      continue
    }
    if (!purl.startsWith('pkg:npm/')) {
      notes.push({
        kind: 'non-npm-component',
        subject: describe(name, version, purl),
        message: `The SBOM lists this component as ${purl.split('/')[0]}, not npm.`,
        hint:
          'cradle only knows npm, so it is counted in the SBOM you supplied but not ' +
          'checked against advisories. Scan it with a tool for its ecosystem.',
      })
      continue
    }
    if (name === undefined || version === undefined || bomRef === undefined) {
      notes.push({
        kind: 'unidentified-component',
        subject: describe(name, version, purl),
        message: 'The SBOM lists this component without a name or a version.',
        hint: 'Advisories are matched on name and version, so this one cannot be checked.',
      })
      continue
    }

    const licenses = readLicenses(source.licenses)
    const properties = propertyMap(source.properties)
    const component: ResolvedComponent = {
      bomRef,
      name,
      version,
      // Rebuilt rather than trusted: a hand-written purl is the field most
      // likely to be subtly wrong, and every later match depends on it.
      purl: npmPurl(name, version),
      location: properties.get('cradle:location') ?? `sbom:${name}`,
      licenses,
      licenseUnknown: licenses.length === 0,
      hashes: readHashes(source.hashes),
      // Absent in a foreign SBOM; derived from the dependency graph below.
      direct: properties.get('cradle:relationship') === 'direct',
      dev: properties.get('cradle:dev') === 'true',
      workspace: properties.get('cradle:workspace') === 'true',
      kinds: [],
    }
    const distribution = (source.externalReferences ?? []).find(
      (reference) => reference.type === 'distribution' && typeof reference.url === 'string',
    )
    if (distribution !== undefined) component.resolvedUrl = distribution.url as string

    components.push(component)
    kept.add(bomRef)
  }

  const edges = readEdges(document.dependencies, kept)

  // A document written by another tool carries no cradle:relationship property,
  // so directness comes from the graph: one hop from the product.
  if (!components.some((component) => component.direct)) {
    const direct = new Set(edges.get(root.bomRef) ?? [])
    for (const component of components) {
      if (direct.has(component.bomRef)) component.direct = true
    }
  }

  components.sort((a, b) => a.bomRef.localeCompare(b.bomRef))

  return {
    packageManager: readPackageManager(metaProperties.get('cradle:packageManager')),
    source: { kind: 'sbom', path: options.path },
    projectDir: options.projectDir,
    root,
    components,
    edges,
    includeDev: metaProperties.get('cradle:scope') === 'all',
    workspaces: components
      .filter((component) => component.workspace)
      .map((component) => component.name)
      .sort(),
    notes,
  }
}

function parse(raw: string, path: string): CdxDocument {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (cause) {
    throw new CradleError(`${path} is not valid JSON`, 'cradle reads CycloneDX JSON, not XML.', {
      cause,
    })
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new CradleError(`${path} is not a CycloneDX document`, 'Expected a JSON object.')
  }

  const document = parsed as CdxDocument
  if (document.bomFormat !== 'CycloneDX') {
    throw new CradleError(
      `${path} does not declare itself as CycloneDX`,
      'cradle reads CycloneDX JSON. An SPDX document cannot be read back in yet — ' +
        'cradle writes SPDX but does not parse it.',
    )
  }
  return document
}

/**
 * Only what the document itself claims. A foreign SBOM says nothing about the
 * package manager, and the graph's `source` is what the output shows in that
 * case — this value is a fallback for the few places that need one, not a claim.
 */
function readPackageManager(value: string | undefined): PackageManager {
  const known: readonly string[] = ['npm', 'pnpm', 'yarn-classic', 'yarn-berry', 'bun']
  return known.includes(value ?? '') ? (value as PackageManager) : 'npm'
}

function propertyMap(
  properties: { name?: unknown; value?: unknown }[] | undefined,
): Map<string, string> {
  const map = new Map<string, string>()
  for (const property of properties ?? []) {
    if (typeof property.name === 'string' && typeof property.value === 'string') {
      map.set(property.name, property.value)
    }
  }
  return map
}

function readLicenses(choices: CdxLicenseChoice[] | undefined): ResolvedLicense[] {
  const licenses: ResolvedLicense[] = []
  for (const choice of choices ?? []) {
    if (typeof choice.expression === 'string') {
      licenses.push({ kind: 'expression', expression: choice.expression })
    } else if (typeof choice.license?.id === 'string') {
      licenses.push({ kind: 'id', id: choice.license.id })
    } else if (typeof choice.license?.name === 'string') {
      licenses.push({ kind: 'name', name: choice.license.name })
    }
  }
  return licenses
}

const HASH_ALGORITHMS: readonly string[] = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']

function readHashes(
  hashes: { alg?: unknown; content?: unknown }[] | undefined,
): ResolvedComponent['hashes'] {
  const read: ResolvedComponent['hashes'] = []
  for (const hash of hashes ?? []) {
    if (typeof hash.alg !== 'string' || typeof hash.content !== 'string') continue
    if (!HASH_ALGORITHMS.includes(hash.alg)) continue
    read.push({
      alg: hash.alg as ResolvedComponent['hashes'][number]['alg'],
      content: hash.content,
    })
  }
  return read
}

function readEdges(
  dependencies: { ref?: unknown; dependsOn?: unknown }[] | undefined,
  kept: ReadonlySet<string>,
): Map<string, string[]> {
  const edges = new Map<string, string[]>()
  for (const entry of dependencies ?? []) {
    if (typeof entry.ref !== 'string' || !kept.has(entry.ref)) continue
    const targets = Array.isArray(entry.dependsOn)
      ? entry.dependsOn.filter(
          (target): target is string => typeof target === 'string' && kept.has(target),
        )
      : []
    edges.set(entry.ref, [...targets].sort())
  }
  // A component with no entry is a leaf, not an unanalysed one.
  for (const ref of kept) {
    if (!edges.has(ref)) edges.set(ref, [])
  }
  return edges
}

function describe(name?: string, version?: string, purl?: string): string {
  if (name !== undefined && version !== undefined) return `${name}@${version}`
  return name ?? purl ?? '(unnamed component)'
}
