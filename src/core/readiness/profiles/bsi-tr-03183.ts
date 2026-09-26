import type { CdxBom, CdxComponent, CradleConfig, ReadinessStatus } from '../../../types/index.js'

/**
 * BSI TR-03183-2 — Cyber Resilience Requirements for Manufacturers and Products,
 * Part 2: Software Bill of Materials (SBOM).
 *
 * Checked against **version 2.1.0, dated 2025-08-20**, published by the
 * Bundesamt für Sicherheit in der Informationstechnik. Every field below cites
 * the section it comes from, because a checklist that cannot be traced back to
 * the document is an opinion.
 *
 * Two things are worth knowing before reading the results.
 *
 * **This is not a conformity assessment.** It compares the SBOM cradle produced
 * against the data fields the guideline lists. Whether a product meets TR-03183
 * is not something this or any tool decides, and several requirements in the
 * guideline are about the build process rather than the file.
 *
 * **Most open results are not cradle's to close.** A lockfile records what was
 * installed; it does not record who maintains a package, whether the delivered
 * artefact is executable, or where its source lives. Those are manufacturer
 * statements. Where cradle cannot know, it says `not assessable` and names what
 * would answer it — the same rule the CRA checklist follows (SPEC.md §6.5).
 */
export const BSI_TR_03183_2 = {
  id: 'bsi-tr-03183',
  title: 'BSI TR-03183-2 (SBOM)',
  version: '2.1.0',
  date: '2025-08-20',
  url: 'https://bsi.bund.de/dok/TR-03183-en',
} as const

/** How strongly the guideline asks for a field. */
export type FieldRequirement = 'required' | 'additional' | 'optional'

export interface ProfileField {
  id: string
  /** Section of TR-03183-2 v2.1.0 this comes from. */
  clause: string
  title: string
  requirement: FieldRequirement
  /** Where the guideline's own mapping table puts it in CycloneDX 1.6 JSON. */
  cyclonedx: string
  check: (input: ProfileInput) => FieldOutcome
}

export interface ProfileInput {
  bom: CdxBom
  config: CradleConfig
  /** True when the run could not reach the network, which limits what is knowable. */
  offline: boolean
}

export interface FieldOutcome {
  status: ReadinessStatus
  /** What cradle found, in the user's terms. */
  detail: string
  /** What would move this field forward, phrased as an instruction. */
  nextStep: string
}

export interface ProfileFieldResult extends FieldOutcome {
  id: string
  clause: string
  title: string
  requirement: FieldRequirement
  cyclonedx: string
}

export interface ProfileReport {
  profile: typeof BSI_TR_03183_2
  fields: ProfileFieldResult[]
  counts: Record<ReadinessStatus, number>
  /** True when no **required** field is open. Never called "compliant". */
  requiredFieldsSatisfied: boolean
}

// ---------------------------------------------------------------------------
// Helpers over the produced BOM
// ---------------------------------------------------------------------------

/** Every component the SBOM describes, including the product itself. */
function allComponents(bom: CdxBom): CdxComponent[] {
  return [bom.metadata.component, ...bom.components]
}

function property(component: CdxComponent, name: string): string | undefined {
  return component.properties?.find((entry) => entry.name === name)?.value
}

/**
 * Count components missing something, and phrase the result the same way every
 * time: a bare count is hard to act on, so up to three names come with it.
 */
function tally(
  components: readonly CdxComponent[],
  missing: (component: CdxComponent) => boolean,
): { total: number; missing: CdxComponent[]; names: string } {
  const failed = components.filter(missing)
  const names = failed
    .slice(0, 3)
    .map((component) => `${component.name}@${component.version}`)
    .join(', ')
  return {
    total: components.length,
    missing: failed,
    names: failed.length > 3 ? `${names}, +${failed.length - 3} more` : names,
  }
}

function allOrNothing(
  components: readonly CdxComponent[],
  missing: (component: CdxComponent) => boolean,
  present: string,
  absent: (names: string, count: number) => string,
  nextStep: string,
): FieldOutcome {
  const result = tally(components, missing)
  if (result.missing.length === 0) {
    return { status: 'met', detail: present, nextStep: 'Nothing to do.' }
  }
  return {
    status: result.missing.length === result.total ? 'open' : 'partial',
    detail: absent(result.names, result.missing.length),
    nextStep,
  }
}

// ---------------------------------------------------------------------------
// The fields
// ---------------------------------------------------------------------------

export const BSI_FIELDS: readonly ProfileField[] = [
  // --- The SBOM itself -----------------------------------------------------
  {
    id: 'sbom-format',
    clause: '§4',
    title: 'SBOM format and version',
    requirement: 'required',
    cyclonedx: 'bomFormat, specVersion',
    check: ({ bom }) => {
      // "CycloneDX, version 1.6 or higher" or "SPDX, version 3.0.1 or higher".
      const version = Number.parseFloat(bom.specVersion)
      if (bom.bomFormat === 'CycloneDX' && version >= 1.6) {
        return {
          status: 'met',
          detail: `CycloneDX ${bom.specVersion}, at or above the required 1.6.`,
          nextStep: 'Nothing to do.',
        }
      }
      return {
        status: 'open',
        detail: `${bom.bomFormat} ${bom.specVersion} is below the required minimum.`,
        nextStep: 'Run cradle scan --spec-version 1.6 or newer.',
      }
    },
  },
  {
    id: 'sbom-creator',
    clause: '§5.2.1',
    title: 'Creator of the SBOM',
    requirement: 'required',
    cyclonedx: 'metadata.manufacturer.contact[].email or .url',
    check: ({ bom, config }) => {
      const manufacturer = bom.metadata.manufacturer
      const email = manufacturer?.contact?.find((entry) => entry.email !== undefined)?.email
      if (email !== undefined || manufacturer?.url !== undefined) {
        return {
          status: 'met',
          detail: `Recorded as ${email ?? manufacturer?.url}.`,
          nextStep: 'Nothing to do.',
        }
      }
      return {
        status: 'open',
        detail: 'The SBOM does not say who created it.',
        nextStep:
          config.contactEmail === undefined
            ? 'Set "contactEmail" in .cradle/config.json and scan again; cradle writes it into metadata.manufacturer.'
            : 'Scan again — the configured contactEmail is written into metadata.manufacturer.',
      }
    },
  },
  {
    id: 'sbom-timestamp',
    clause: '§5.2.1',
    title: 'Timestamp of the SBOM',
    requirement: 'required',
    cyclonedx: 'metadata.timestamp',
    check: ({ bom }) => {
      const timestamp = bom.metadata.timestamp
      const utc = timestamp.endsWith('Z')
      if (!utc) {
        // The guideline recommends UTC rather than requiring it.
        return {
          status: 'partial',
          detail: `Present as ${timestamp}, but not in UTC.`,
          nextStep: 'The guideline recommends Zulu time. Pass --timestamp with a Z suffix.',
        }
      }
      return { status: 'met', detail: `${timestamp}, in UTC.`, nextStep: 'Nothing to do.' }
    },
  },
  {
    id: 'sbom-uri',
    clause: '§5.2.3',
    title: 'SBOM-URI',
    requirement: 'additional',
    cyclonedx: 'serialNumber',
    check: ({ bom }) =>
      bom.serialNumber === undefined || bom.serialNumber === ''
        ? {
            status: 'open',
            detail: 'The SBOM carries no serial number.',
            nextStep: 'Scan again; cradle always writes one.',
          }
        : {
            status: 'met',
            detail: `${bom.serialNumber}.`,
            nextStep: 'Nothing to do.',
          },
  },

  // --- Each component ------------------------------------------------------
  {
    id: 'component-creator',
    clause: '§5.2.2',
    title: 'Component creator',
    requirement: 'required',
    cyclonedx: 'components[].manufacturer.contact[].email or .url',
    check: ({ offline }) => ({
      // A lockfile records what was installed, never who maintains it. The npm
      // registry knows, but that is one request per component and still only an
      // answer for packages that fill the field in.
      status: 'not-assessable',
      detail: offline
        ? 'A lockfile does not record who maintains a package, and this run was offline.'
        : 'A lockfile does not record who maintains a package.',
      nextStep:
        'cradle does not fetch maintainer details, because it would be a registry request per ' +
        'component for an answer many packages leave blank. Add them from your own records if ' +
        'you need this field.',
    }),
  },
  {
    id: 'component-name',
    clause: '§5.2.2',
    title: 'Component name',
    requirement: 'required',
    cyclonedx: 'components[].name',
    check: ({ bom }) =>
      allOrNothing(
        allComponents(bom),
        (component) => component.name === '',
        `All ${allComponents(bom).length} components are named.`,
        (names) => `Unnamed: ${names}.`,
        'A component with no name cannot be identified; check the lockfile entry.',
      ),
  },
  {
    id: 'component-version',
    clause: '§5.2.2',
    title: 'Component version',
    requirement: 'required',
    cyclonedx: 'components[].version',
    check: ({ bom }) =>
      allOrNothing(
        allComponents(bom),
        (component) => component.version === '',
        `All ${allComponents(bom).length} components carry a version.`,
        (names) => `Without a version: ${names}.`,
        'Resolve the dependency properly; a lockfile entry without a version cannot be matched ' +
          'against any advisory either.',
      ),
  },
  {
    id: 'component-filename',
    clause: '§5.2.2',
    title: 'Filename of the component',
    requirement: 'required',
    cyclonedx: 'components[].properties["bsi:component:filename"]',
    check: ({ bom }) =>
      allOrNothing(
        bom.components,
        (component) => property(component, 'bsi:component:filename') === undefined,
        `All ${bom.components.length} components record the tarball they came from.`,
        (names, count) => `${count} without a filename: ${names}.`,
        'cradle derives this from the resolved tarball URL. A component without one came from ' +
          'somewhere other than a registry — git, or a local path — and the filename has to be ' +
          'stated by hand.',
      ),
  },
  {
    id: 'component-dependencies',
    clause: '§5.2.2',
    title: 'Dependencies on other components',
    requirement: 'required',
    cyclonedx: 'dependencies[], completeness via compositions[]',
    check: ({ bom }) => {
      const refs = new Set(bom.dependencies.map((entry) => entry.ref))
      const componentRefs = allComponents(bom).map((component) => component['bom-ref'])
      const missing = componentRefs.filter((ref) => !refs.has(ref))

      // The guideline also asks that the completeness of the enumeration be
      // clearly indicated, which CycloneDX expresses with `compositions`.
      if (missing.length > 0) {
        return {
          status: 'open',
          detail: `${missing.length} components have no entry in the dependency graph.`,
          nextStep: 'Every component needs an entry, even an empty one. Scan again.',
        }
      }
      return {
        status: 'partial',
        detail:
          `All ${refs.size} components appear in the dependency graph, but the SBOM does not ` +
          'state whether the enumeration is complete.',
        nextStep:
          'The guideline asks for completeness to be indicated (compositions[].aggregate). ' +
          'cradle does not write it, because completeness depends on your build rather than on ' +
          'the lockfile: a dependency installed outside the package manager is invisible here.',
      }
    },
  },
  {
    id: 'component-licences',
    clause: '§5.2.2, §6.1',
    title: 'Distribution licences',
    requirement: 'required',
    cyclonedx: 'components[].licenses[]',
    check: ({ bom }) =>
      allOrNothing(
        bom.components,
        (component) => component.licenses === undefined || component.licenses.length === 0,
        `All ${bom.components.length} components declare a licence.`,
        (names, count) => `${count} without a licence: ${names}.`,
        'cradle reads licences from the lockfile where the format carries them, and from ' +
          'node_modules otherwise. Install dependencies and scan again, or record the licence ' +
          'yourself for packages that declare none.',
      ),
  },
  {
    id: 'component-hash',
    clause: '§5.2.2',
    title: 'Hash of the deployable component',
    requirement: 'required',
    cyclonedx: 'components[].externalReferences[type=distribution].hashes[alg=SHA-512]',
    check: ({ bom }) =>
      allOrNothing(
        bom.components,
        (component) =>
          !(component.externalReferences ?? []).some(
            (reference) =>
              reference.type === 'distribution' &&
              (reference.hashes ?? []).some((hash) => hash.alg === 'SHA-512'),
          ),
        `All ${bom.components.length} components carry a SHA-512 over their tarball.`,
        (names, count) => `${count} without a SHA-512: ${names}.`,
        'The guideline names SHA-512 specifically. Yarn Berry lockfiles carry no usable digest ' +
          'at all (SPEC.md §6.1), and git or local dependencies have none; those need a hash ' +
          'taken from the delivered artefact.',
      ),
  },
  {
    id: 'component-executable',
    clause: '§5.2.2, §8.1.4',
    title: 'Executable property',
    requirement: 'required',
    cyclonedx: 'components[].properties["bsi:component:executable"]',
    check: () => ({
      status: 'not-assessable',
      detail: 'Whether a delivered component is executable is a statement about your delivery.',
      nextStep:
        'cradle will not guess. An npm package is a directory of files whose executability ' +
        'depends on how you ship it, and a wrong answer here is worse than none.',
    }),
  },
  {
    id: 'component-archive',
    clause: '§5.2.2, §8.1.5',
    title: 'Archive property',
    requirement: 'required',
    cyclonedx: 'components[].properties["bsi:component:archive"]',
    check: () => ({
      status: 'not-assessable',
      detail: 'Whether a delivered component is an archive depends on how it is delivered.',
      nextStep:
        'A package is fetched as a .tgz and installed as a directory. Which of those you ship ' +
        'is not something the lockfile records.',
    }),
  },
  {
    id: 'component-structured',
    clause: '§5.2.2, §8.1.6',
    title: 'Structured property',
    requirement: 'required',
    cyclonedx: 'components[].properties["bsi:component:structured"]',
    check: () => ({
      status: 'not-assessable',
      detail: 'Whether a delivered component keeps its content metadata depends on the delivery.',
      nextStep: 'Declare it from your build, as with the executable and archive properties.',
    }),
  },

  // --- Additional fields ---------------------------------------------------
  {
    id: 'component-source-uri',
    clause: '§5.2.4',
    title: 'Source code URI',
    requirement: 'additional',
    cyclonedx: 'components[].externalReferences[type=source-distribution].url',
    check: ({ offline }) => ({
      status: 'not-assessable',
      detail:
        'A lockfile records the tarball, not the repository it was built from.' +
        (offline ? ' This run was offline.' : ''),
      nextStep:
        'The registry manifest carries "repository" for packages that set it, but not all do, ' +
        'and cradle does not fetch a manifest per component. Required only where it exists.',
    }),
  },
  {
    id: 'component-deployable-uri',
    clause: '§5.2.4',
    title: 'URI of the deployable form',
    requirement: 'additional',
    cyclonedx: 'components[].externalReferences[type=distribution].url',
    check: ({ bom }) =>
      allOrNothing(
        bom.components,
        (component) =>
          !(component.externalReferences ?? []).some(
            (reference) => reference.type === 'distribution' && reference.url !== '',
          ),
        `All ${bom.components.length} components link to the tarball they came from.`,
        (names, count) => `${count} without a distribution URL: ${names}.`,
        'A component resolved from git or a local path has no registry URL. State where the ' +
          'delivered artefact comes from if you need this field.',
      ),
  },
  {
    id: 'component-identifiers',
    clause: '§5.2.4',
    title: 'Other unique identifiers',
    requirement: 'additional',
    cyclonedx: 'components[].purl, .cpe or .swid',
    check: ({ bom }) =>
      allOrNothing(
        bom.components,
        (component) => component.purl === undefined,
        `All ${bom.components.length} components carry a package URL.`,
        (names, count) => `${count} without a purl: ${names}.`,
        'Every component resolved from a registry gets one. Check the resolution notes for any ' +
          'that did not.',
      ),
  },
  {
    id: 'component-original-licences',
    clause: '§5.2.4, §6.1',
    title: 'Original licences',
    requirement: 'additional',
    cyclonedx: 'components[].licenses[] with acknowledgement "declared"',
    check: () => ({
      status: 'not-assessable',
      detail:
        'cradle records the licence a package declares, without separating declared from ' +
        'concluded.',
      nextStep:
        'The guideline distinguishes the licence the creator assigned from the one concluded ' +
        'after review. cradle only ever sees the first, and marking it as concluded would ' +
        'claim a review that did not happen.',
    }),
  },
] as const

/**
 * Run every field check against a produced SBOM.
 *
 * `requiredFieldsSatisfied` deliberately does not say "compliant". It says that
 * no field the guideline marks as required came back open — which is a statement
 * about this file, not about a product.
 */
export function checkBsiProfile(input: ProfileInput): ProfileReport {
  const fields: ProfileFieldResult[] = BSI_FIELDS.map((field) => ({
    id: field.id,
    clause: field.clause,
    title: field.title,
    requirement: field.requirement,
    cyclonedx: field.cyclonedx,
    ...field.check(input),
  }))

  const counts: Record<ReadinessStatus, number> = {
    met: 0,
    partial: 0,
    open: 0,
    'not-assessable': 0,
  }
  for (const field of fields) counts[field.status] += 1

  return {
    profile: BSI_TR_03183_2,
    fields,
    counts,
    requiredFieldsSatisfied: !fields.some(
      (field) => field.requirement === 'required' && field.status === 'open',
    ),
  }
}
