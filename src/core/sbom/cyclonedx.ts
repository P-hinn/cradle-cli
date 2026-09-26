import type {
  CdxBom,
  CdxComponent,
  CdxDependency,
  CdxExternalReference,
  CdxOrganizationalEntity,
  CycloneDxSpecVersion,
  DependencyGraph,
  ResolvedComponent,
} from '../../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../../version.generated.js'
import { toCycloneDx } from './license.js'

export interface BuildBomOptions {
  specVersion: CycloneDxSpecVersion
  /** ISO 8601. Injectable so tests produce byte-identical documents. */
  timestamp: string
  /** `urn:uuid:...`. Injectable for the same reason. */
  serialNumber: string
  /**
   * Who made this SBOM, from `.cradle/config.json`. Written into
   * `metadata.manufacturer`, which is what BSI TR-03183-2 §5.2.1 asks for and
   * what CycloneDX provides for it. Absent when the project configured nothing —
   * inventing a creator would be worse than leaving the field out.
   */
  creator?: { name?: string; email?: string }
}

/**
 * Render a resolved dependency graph as a CycloneDX BOM.
 *
 * Two details carry most of the value here. The `dependencies` block records the
 * real edges rather than a flat list — that is what makes this an SBOM instead
 * of a text file. And `metadata.tools` uses the object form; the array form has
 * been deprecated since CycloneDX 1.5 (SPEC.md §5b).
 */
export function buildBom(graph: DependencyGraph, options: BuildBomOptions): CdxBom {
  const components = graph.components.map(toComponent)

  // Only refs that actually exist as components may appear in the graph.
  const knownRefs = new Set<string>([graph.root.bomRef, ...components.map((c) => c['bom-ref'])])
  const dependencies: CdxDependency[] = []
  for (const [ref, dependsOn] of graph.edges) {
    if (!knownRefs.has(ref)) continue
    const filtered = dependsOn.filter((target) => knownRefs.has(target))
    dependencies.push(filtered.length > 0 ? { ref, dependsOn: filtered } : { ref })
  }
  // A leaf still needs an entry, otherwise consumers cannot tell "no dependencies"
  // apart from "not analysed".
  for (const ref of knownRefs) {
    if (!graph.edges.has(ref)) dependencies.push({ ref })
  }
  dependencies.sort((a, b) => a.ref.localeCompare(b.ref))

  const manufacturer = toManufacturer(options.creator)

  const rootComponent: CdxComponent = {
    'bom-ref': graph.root.bomRef,
    type: 'application',
    name: graph.root.name,
    version: graph.root.version,
  }
  if (graph.root.purl !== undefined) rootComponent.purl = graph.root.purl
  if (graph.root.description !== undefined) rootComponent.description = graph.root.description
  if (graph.root.licenses.length > 0) rootComponent.licenses = toCycloneDx(graph.root.licenses)

  return {
    $schema: `http://cyclonedx.org/schema/bom-${options.specVersion}.schema.json`,
    bomFormat: 'CycloneDX',
    specVersion: options.specVersion,
    serialNumber: options.serialNumber,
    version: 1,
    metadata: {
      timestamp: options.timestamp,
      ...(manufacturer === undefined ? {} : { manufacturer }),
      tools: {
        components: [
          {
            'bom-ref': `pkg:npm/${TOOL_NAME}@${TOOL_VERSION}`,
            type: 'application',
            name: TOOL_NAME,
            version: TOOL_VERSION,
            purl: `pkg:npm/${TOOL_NAME}@${TOOL_VERSION}`,
          },
        ],
      },
      component: rootComponent,
      properties: [
        { name: 'cradle:packageManager', value: graph.packageManager },
        { name: 'cradle:scope', value: graph.includeDev ? 'all' : 'production' },
      ],
    },
    components,
    dependencies,
  }
}

/** An entity only when there is something real to put in it. */
function toManufacturer(creator: BuildBomOptions['creator']): CdxOrganizationalEntity | undefined {
  if (creator === undefined) return undefined
  const entity: CdxOrganizationalEntity = {}
  if (creator.name !== undefined && creator.name !== '') entity.name = creator.name
  if (creator.email !== undefined && creator.email !== '') {
    entity.contact = [{ email: creator.email }]
  }
  return entity.name === undefined && entity.contact === undefined ? undefined : entity
}

/**
 * The tarball's own filename, which BSI TR-03183-2 §5.2.2 requires under the
 * property name its mapping table defines. Derived from the resolved URL rather
 * than guessed: a component fetched from git or a local path has none, and that
 * is reported rather than filled in.
 */
function tarballFilename(resolvedUrl: string | undefined): string | undefined {
  if (resolvedUrl === undefined) return undefined
  let path: string
  try {
    path = new URL(resolvedUrl).pathname
  } catch {
    return undefined
  }
  const name = path.slice(path.lastIndexOf('/') + 1)
  return name === '' ? undefined : decodeURIComponent(name)
}

function toComponent(component: ResolvedComponent): CdxComponent {
  const out: CdxComponent = {
    'bom-ref': component.bomRef,
    type: 'library',
    name: component.name,
    version: component.version,
    purl: component.purl,
    scope:
      component.kinds.includes('optional') && component.kinds.length === 1
        ? 'optional'
        : 'required',
  }

  if (component.licenses.length > 0) out.licenses = toCycloneDx(component.licenses)
  if (component.hashes.length > 0) out.hashes = component.hashes

  if (component.resolvedUrl !== undefined) {
    // The integrity hash covers the tarball, so it belongs on the distribution
    // reference as well as on the component itself (SPEC.md §5a).
    const reference: CdxExternalReference = { url: component.resolvedUrl, type: 'distribution' }
    if (component.hashes.length > 0) reference.hashes = component.hashes
    out.externalReferences = [reference]
  }

  const properties = [
    { name: 'cradle:relationship', value: component.direct ? 'direct' : 'transitive' },
    { name: 'cradle:location', value: component.location },
  ]
  const filename = tarballFilename(component.resolvedUrl)
  if (filename !== undefined) properties.push({ name: 'bsi:component:filename', value: filename })
  if (component.workspace) properties.push({ name: 'cradle:workspace', value: 'true' })
  if (component.dev) properties.push({ name: 'cradle:dev', value: 'true' })
  if (component.licenseUnknown) properties.push({ name: 'cradle:licenseUnknown', value: 'true' })
  out.properties = properties

  return out
}
