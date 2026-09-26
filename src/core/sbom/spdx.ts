import type { DependencyGraph, ResolvedComponent, ResolvedLicense } from '../../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../../version.generated.js'

/**
 * SPDX 2.3 (JSON) from the same graph the CycloneDX output comes from.
 *
 * Neither format is the "real" one: CRA Annex I Part II(1) names no format, and
 * both SPDX and CycloneDX satisfy "commonly used and machine-readable"
 * (SPEC.md §3.3). SPDX exists here because some customers and procurement
 * processes ask for it by name, not because it says anything CycloneDX does not.
 *
 * **Version 2.3, not 3.0.** 2.3 is what tooling consumes today and what an
 * `SPDX-2.3` request means. Note that BSI TR-03183-2 v2.1.0 §4 sets its SPDX
 * floor at **3.0.1**, so an SPDX 2.3 file does not satisfy that guideline's
 * format requirement — its CycloneDX 1.6 output does. `--profile bsi-tr-03183`
 * checks the CycloneDX document for exactly that reason.
 */

/** Only the subset cradle emits, typed strictly rather than as a bag. */
export interface SpdxDocument {
  spdxVersion: 'SPDX-2.3'
  dataLicense: 'CC0-1.0'
  SPDXID: 'SPDXRef-DOCUMENT'
  name: string
  documentNamespace: string
  creationInfo: {
    created: string
    creators: string[]
  }
  packages: SpdxPackage[]
  relationships: SpdxRelationship[]
  documentDescribes: string[]
}

export interface SpdxPackage {
  SPDXID: string
  name: string
  versionInfo?: string
  downloadLocation: string
  filesAnalyzed: false
  licenseConcluded: string
  licenseDeclared: string
  copyrightText: string
  supplier?: string
  checksums?: { algorithm: string; checksumValue: string }[]
  externalRefs?: {
    referenceCategory: 'PACKAGE-MANAGER' | 'SECURITY' | 'OTHER'
    referenceType: string
    referenceLocator: string
  }[]
}

export interface SpdxRelationship {
  spdxElementId: string
  relationshipType: 'DESCRIBES' | 'DEPENDS_ON'
  relatedSpdxElement: string
}

export interface BuildSpdxOptions {
  /** ISO 8601. Shared with the CycloneDX document so the two describe one scan. */
  timestamp: string
  /** A document namespace must be unique per document; derived from the serial number. */
  serialNumber: string
  creator?: { name?: string; email?: string }
}

/**
 * SPDX says NOASSERTION where a field is unknown, and it means it: the spec
 * distinguishes "no assertion is being made" from an empty string, and a
 * consumer is entitled to treat the two differently. Every unknown field here
 * gets NOASSERTION rather than being omitted or blanked.
 */
const NOASSERTION = 'NOASSERTION'

export function buildSpdx(graph: DependencyGraph, options: BuildSpdxOptions): SpdxDocument {
  const ids = assignSpdxIds(graph)
  const rootId = ids.get(graph.root.bomRef) ?? 'SPDXRef-Package-root'

  const packages: SpdxPackage[] = [
    {
      SPDXID: rootId,
      name: graph.root.name,
      ...(graph.root.version === '' ? {} : { versionInfo: graph.root.version }),
      downloadLocation: NOASSERTION,
      filesAnalyzed: false,
      licenseConcluded: NOASSERTION,
      licenseDeclared: licenseExpression(graph.root.licenses),
      copyrightText: NOASSERTION,
      ...(graph.root.purl === undefined
        ? {}
        : {
            externalRefs: [
              {
                referenceCategory: 'PACKAGE-MANAGER' as const,
                referenceType: 'purl',
                referenceLocator: graph.root.purl,
              },
            ],
          }),
    },
  ]

  for (const component of graph.components) {
    const id = ids.get(component.bomRef)
    if (id === undefined) continue
    packages.push(toPackage(component, id))
  }

  const relationships: SpdxRelationship[] = [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: rootId,
    },
  ]
  for (const [from, targets] of graph.edges) {
    const fromId = ids.get(from)
    if (fromId === undefined) continue
    for (const target of targets) {
      const toId = ids.get(target)
      if (toId === undefined) continue
      relationships.push({
        spdxElementId: fromId,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: toId,
      })
    }
  }
  relationships.sort(
    (a, b) =>
      a.spdxElementId.localeCompare(b.spdxElementId) ||
      a.relatedSpdxElement.localeCompare(b.relatedSpdxElement),
  )

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${graph.root.name}-${graph.root.version}`,
    // The namespace has to be unique per document. The CycloneDX serialNumber is
    // already a UUID URN for this scan, so reusing it ties the two files to one
    // run rather than inventing a second identity for the same thing.
    documentNamespace: `https://cradle.invalid/spdx/${encodeURIComponent(graph.root.name)}/${options.serialNumber}`,
    creationInfo: {
      created: options.timestamp,
      creators: creators(options.creator),
    },
    packages,
    relationships,
    documentDescribes: [rootId],
  }
}

/**
 * SPDX identifiers are restricted to letters, digits, `.` and `-`, which a purl
 * is not. So they are derived from the bom-ref and then made unique by index
 * where sanitising collapsed two refs into one — an SPDXID that is not unique
 * breaks the relationship graph exactly as a duplicate bom-ref does
 * (SPEC.md §5c).
 */
function assignSpdxIds(graph: DependencyGraph): Map<string, string> {
  const ids = new Map<string, string>()
  const used = new Set<string>()

  const assign = (ref: string, hint: string): void => {
    const base = `SPDXRef-Package-${hint.replace(/[^a-zA-Z0-9.-]+/g, '-').replace(/^-+|-+$/g, '')}`
    let candidate = base === 'SPDXRef-Package-' ? 'SPDXRef-Package-unnamed' : base
    let counter = 2
    while (used.has(candidate)) {
      candidate = `${base}-${counter}`
      counter += 1
    }
    used.add(candidate)
    ids.set(ref, candidate)
  }

  assign(graph.root.bomRef, `${graph.root.name}-${graph.root.version}`)
  for (const component of graph.components) {
    assign(component.bomRef, `${component.name}-${component.version}`)
  }
  return ids
}

function toPackage(component: ResolvedComponent, id: string): SpdxPackage {
  const pkg: SpdxPackage = {
    SPDXID: id,
    name: component.name,
    versionInfo: component.version,
    downloadLocation: component.resolvedUrl ?? NOASSERTION,
    // False, and honestly so: cradle reads a lockfile, never the files inside a
    // package. Claiming otherwise would imply a file-level inventory that does
    // not exist, and SPDX requires packageVerificationCode when it is true.
    filesAnalyzed: false,
    licenseConcluded: NOASSERTION,
    licenseDeclared: licenseExpression(component.licenses),
    copyrightText: NOASSERTION,
  }

  if (component.hashes.length > 0) {
    pkg.checksums = component.hashes.map((hash) => ({
      // SPDX spells them without the hyphen CycloneDX uses.
      algorithm: hash.alg.replace('-', ''),
      checksumValue: hash.content,
    }))
  }

  pkg.externalRefs = [
    {
      referenceCategory: 'PACKAGE-MANAGER',
      referenceType: 'purl',
      referenceLocator: component.purl,
    },
  ]
  return pkg
}

/**
 * A single SPDX licence expression, or NOASSERTION.
 *
 * Several licences on one component become an `AND`, which is what SPDX means by
 * a list: all of them apply. A licence cradle could not map onto SPDX is
 * NOASSERTION rather than a `LicenseRef-`, because inventing a reference without
 * the accompanying `hasExtractedLicensingInfos` text would produce a document
 * that validates and misleads.
 */
export function licenseExpression(licenses: readonly ResolvedLicense[]): string {
  const parts: string[] = []
  for (const license of licenses) {
    if (license.kind === 'id') parts.push(license.id)
    else if (license.kind === 'expression') parts.push(`(${license.expression})`)
  }
  if (parts.length === 0) return NOASSERTION
  return parts.length === 1 ? (parts[0] ?? NOASSERTION) : parts.join(' AND ')
}

function creators(creator: BuildSpdxOptions['creator']): string[] {
  const list = [`Tool: ${TOOL_NAME}-${TOOL_VERSION}`]
  if (creator?.email !== undefined && creator.email !== '') {
    list.unshift(`Organization: ${creator.name ?? creator.email} (${creator.email})`)
  } else if (creator?.name !== undefined && creator.name !== '') {
    list.unshift(`Organization: ${creator.name}`)
  }
  return list
}
