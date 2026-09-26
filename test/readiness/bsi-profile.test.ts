import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { resolveNpm } from '../../src/core/resolve/npm.js'
import {
  BSI_FIELDS,
  BSI_TR_03183_2,
  checkBsiProfile,
  type ProfileInput,
} from '../../src/core/readiness/profiles/bsi-tr-03183.js'
import { buildBom } from '../../src/core/sbom/cyclonedx.js'
import type { CdxBom } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'

const BASE = {
  specVersion: '1.6',
  timestamp: '2026-09-26T00:00:00.000Z',
  serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
} as const

async function bomFor(
  name: string,
  creator?: { name?: string; email?: string },
): Promise<CdxBom> {
  const graph = await resolveNpm({ projectDir: fixture(name), includeDev: false })
  return buildBom(graph, { ...BASE, ...(creator === undefined ? {} : { creator }) })
}

function check(bom: CdxBom, overrides: Partial<ProfileInput> = {}) {
  return checkBsiProfile({ bom, config: {}, offline: false, ...overrides })
}

function field(bom: CdxBom, id: string, overrides: Partial<ProfileInput> = {}) {
  const found = check(bom, overrides).fields.find((entry) => entry.id === id)
  expect(found, id).toBeDefined()
  return found
}

/**
 * The profile is a description, not a verdict. These check two separate things:
 * that the field list is faithful to the guideline it cites, and that each check
 * reports what is actually in the document rather than what cradle hoped to put
 * there.
 */
describe('BSI TR-03183-2 profile', () => {
  it('names the version and date it was written against', () => {
    // If the guideline moves, this is the line that has to be revisited, and a
    // profile that does not say which version it implements cannot be audited.
    expect(BSI_TR_03183_2.version).toBe('2.1.0')
    expect(BSI_TR_03183_2.date).toBe('2025-08-20')
  })

  it('cites a section of the guideline for every field', () => {
    for (const entry of BSI_FIELDS) {
      expect(entry.clause, entry.id).toMatch(/^§\d/)
      expect(entry.title, entry.id).toBeTruthy()
      expect(entry.cyclonedx, entry.id).toBeTruthy()
    }
  })

  it('covers every required and additional data field the guideline lists', () => {
    // Counted from TR-03183-2 v2.1.0: §5.2.1 two SBOM-level required fields,
    // §5.2.2 ten per-component required fields, §5.2.3 one additional SBOM-level
    // field, §5.2.4 four additional per-component fields, plus §4 on the format.
    const byRequirement = BSI_FIELDS.reduce<Record<string, number>>((counts, entry) => {
      counts[entry.requirement] = (counts[entry.requirement] ?? 0) + 1
      return counts
    }, {})
    expect(byRequirement.required).toBe(13)
    expect(byRequirement.additional).toBe(5)
  })

  it('gives every field a unique id', () => {
    const ids = BSI_FIELDS.map((entry) => entry.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('gives every outcome a detail and a next step', async () => {
    const report = check(await bomFor('npm-basic'))
    for (const entry of report.fields) {
      expect(entry.detail, entry.id).toMatch(/\.$/)
      expect(entry.nextStep, entry.id).toMatch(/\.$/)
    }
  })

  it('counts every field exactly once', async () => {
    const report = check(await bomFor('npm-basic'))
    const total = Object.values(report.counts).reduce((sum, count) => sum + count, 0)
    expect(total).toBe(report.fields.length)
  })
})

describe('BSI profile: what the SBOM does carry', () => {
  it('accepts CycloneDX 1.6 and refuses anything below it', async () => {
    const bom = await bomFor('npm-basic')
    expect(field(bom, 'sbom-format')?.status).toBe('met')

    // §4 sets the floor at 1.6; the guideline is explicit that only officially
    // released versions count.
    const older = { ...bom, specVersion: '1.5' } as unknown as CdxBom
    expect(field(older, 'sbom-format')?.status).toBe('open')
  })

  it('reports the creator as open until the project configures one', async () => {
    const without = await bomFor('npm-basic')
    const missing = field(without, 'sbom-creator')
    expect(missing?.status).toBe('open')
    // The next step has to name the thing the user can change.
    expect(missing?.nextStep).toContain('contactEmail')

    const withCreator = await bomFor('npm-basic', { email: 'security@acme.example' })
    const present = field(withCreator, 'sbom-creator', {
      config: { contactEmail: 'security@acme.example' },
    })
    expect(present?.status).toBe('met')
    expect(present?.detail).toContain('security@acme.example')
  })

  it('wants the timestamp in UTC, and says so without failing on it', async () => {
    const bom = await bomFor('npm-basic')
    expect(field(bom, 'sbom-timestamp')?.status).toBe('met')

    // The guideline recommends Zulu time rather than requiring it, so a local
    // offset is partial, not open.
    const local = {
      ...bom,
      metadata: { ...bom.metadata, timestamp: '2026-09-26T02:00:00+02:00' },
    }
    const outcome = field(local, 'sbom-timestamp')
    expect(outcome?.status).toBe('partial')
    expect(outcome?.nextStep).toContain('Zulu')
  })

  it('finds the filename cradle derives from the tarball URL', async () => {
    const bom = await bomFor('npm-basic')
    expect(field(bom, 'component-filename')?.status).toBe('met')

    // The property name is the one the guideline's own mapping table defines.
    const names = bom.components.flatMap((component) =>
      (component.properties ?? []).map((entry) => entry.name),
    )
    expect(names).toContain('bsi:component:filename')
  })

  it('reports a missing filename as partial rather than open when only some lack one', async () => {
    // A git or local dependency has no tarball URL, so it has no filename.
    const bom = await bomFor('npm-edge-cases')
    const outcome = field(bom, 'component-filename')
    expect(outcome?.status).toBe('partial')
    expect(outcome?.detail).toMatch(/without a filename/)
  })

  it('checks the hash the guideline names, not just any hash', async () => {
    const bom = await bomFor('npm-basic')
    expect(field(bom, 'component-hash')?.status).toBe('met')

    // §5.2.2 says SHA-512. A SHA-256 in its place does not satisfy it.
    const downgraded = {
      ...bom,
      components: bom.components.map((component) => ({
        ...component,
        externalReferences: (component.externalReferences ?? []).map((reference) => ({
          ...reference,
          hashes: (reference.hashes ?? []).map((hash) => ({ ...hash, alg: 'SHA-256' as const })),
        })),
      })),
    }
    expect(field(downgraded, 'component-hash')?.status).toBe('open')
  })

  it('will not call the dependency graph complete', async () => {
    // Every component has an entry, which is the part cradle can guarantee. Whether
    // the enumeration is complete depends on the build, not on the lockfile - a
    // dependency installed outside the package manager is invisible here.
    const bom = await bomFor('npm-basic')
    const outcome = field(bom, 'component-dependencies')
    expect(outcome?.status).toBe('partial')
    expect(outcome?.nextStep).toContain('compositions')
  })

  it('reports a licence-less component instead of averaging it away', async () => {
    const withLicences = await bomFor('npm-basic')
    expect(field(withLicences, 'component-licences')?.status).toBe('met')

    const stripped = {
      ...withLicences,
      components: withLicences.components.map(({ licenses: _licenses, ...rest }) => rest),
    }
    expect(field(stripped, 'component-licences')?.status).toBe('open')
  })
})

describe('BSI profile: what cradle refuses to guess', () => {
  it('reports the manufacturer statements as not assessable', async () => {
    // Executable, archive and structured describe the artefact as delivered. An
    // npm package is fetched as a .tgz and installed as a directory; which of
    // those ships is not in the lockfile, and a wrong answer is worse than none.
    const bom = await bomFor('npm-basic')
    for (const id of ['component-executable', 'component-archive', 'component-structured']) {
      expect(field(bom, id)?.status, id).toBe('not-assessable')
    }
  })

  it('reports the component creator as not assessable, and says why', async () => {
    const bom = await bomFor('npm-basic')
    const outcome = field(bom, 'component-creator')
    expect(outcome?.status).toBe('not-assessable')
    expect(outcome?.detail).toContain('lockfile does not record')
    // The reason is a cost, not an impossibility, and the user is told which.
    expect(outcome?.nextStep).toContain('registry request per component')
  })

  it('mentions the offline run where it changes what is knowable', async () => {
    const bom = await bomFor('npm-basic')
    expect(field(bom, 'component-source-uri', { offline: true })?.detail).toContain('offline')
    expect(field(bom, 'component-source-uri', { offline: false })?.detail).not.toContain('offline')
  })

  it('will not present a declared licence as a concluded one', async () => {
    // The guideline separates the licence the creator assigned from the one
    // concluded after review. cradle only ever sees the first.
    const bom = await bomFor('npm-basic')
    const outcome = field(bom, 'component-original-licences')
    expect(outcome?.status).toBe('not-assessable')
    expect(outcome?.nextStep).toContain('claim a review that did not happen')
  })
})

describe('BSI profile: the verdict it is willing to give', () => {
  it('says only that no required field is open, never that anything is compliant', async () => {
    const bom = await bomFor('npm-basic', { email: 'security@acme.example' })
    const report = check(bom, { config: { contactEmail: 'security@acme.example' } })

    expect(report.requiredFieldsSatisfied).toBe(true)
    // A not-assessable required field does not block that statement, because it
    // is not a failure - but it is also not a pass, which is why the wording is
    // about open fields and nothing more.
    expect(report.counts['not-assessable']).toBeGreaterThan(0)

    const source = readFileSync(
      new URL('../../src/core/readiness/profiles/bsi-tr-03183.ts', import.meta.url),
      'utf8',
    )
    expect(source).not.toMatch(/\bis compliant\b|\bcompliance\b/i)
  })

  it('turns the verdict false as soon as a required field is open', async () => {
    const bom = await bomFor('npm-basic')
    // No creator configured, so sbom-creator is open and required.
    expect(check(bom).requiredFieldsSatisfied).toBe(false)
  })
})
