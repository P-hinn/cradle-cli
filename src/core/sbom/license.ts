import parseSpdx from 'spdx-expression-parse'
import type { CdxLicenseChoice, ResolvedLicense } from '../../types/index.js'
import { SPDX_LICENSE_IDS } from './spdx-ids.generated.js'

/** The legacy `licenses: [{ type, url }]` array some old packages still ship. */
interface LegacyLicenseEntry {
  type?: unknown
  url?: unknown
}

/**
 * Turn whatever a package.json says about licensing into a normalised form.
 *
 * Three outcomes, matching how CycloneDX models the field:
 *   - a single valid SPDX identifier      -> `{ kind: 'id' }`
 *   - a compound but parseable expression -> `{ kind: 'expression' }`
 *   - anything else, e.g. "SEE LICENSE IN LICENSE.md" -> `{ kind: 'name' }`
 *
 * An empty result is meaningful: it means we found no licence information at
 * all, which the readiness check reports as an open point rather than hiding.
 */
export function normalizeLicense(pkg: {
  license?: unknown
  licenses?: unknown
}): ResolvedLicense[] {
  const fromLicense = readLicenseField(pkg.license)
  if (fromLicense.length > 0) return fromLicense
  return readLegacyLicensesField(pkg.licenses)
}

function readLicenseField(value: unknown): ResolvedLicense[] {
  // Very old packages used `license: { type, url }`.
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const type = (value as LegacyLicenseEntry).type
    return typeof type === 'string' ? classify(type) : []
  }
  return typeof value === 'string' ? classify(value) : []
}

function readLegacyLicensesField(value: unknown): ResolvedLicense[] {
  if (!Array.isArray(value)) return []
  const out: ResolvedLicense[] = []
  for (const entry of value as LegacyLicenseEntry[]) {
    if (entry === null || typeof entry !== 'object') continue
    if (typeof entry.type === 'string') out.push(...classify(entry.type))
  }
  return out
}

function classify(raw: string): ResolvedLicense[] {
  const text = raw.trim()
  if (text === '') return []

  // `UNLICENSED` is npm's marker for "deliberately proprietary". It is not an
  // SPDX identifier, and treating it as unknown would be wrong — the intent is
  // documented, it just is not an open-source licence.
  if (text.toUpperCase() === 'UNLICENSED') return [{ kind: 'name', name: 'UNLICENSED' }]

  let parsed: ReturnType<typeof parseSpdx>
  try {
    parsed = parseSpdx(text)
  } catch {
    return [{ kind: 'name', name: text }]
  }

  // A bare identifier with no operators and no exception.
  if ('license' in parsed && parsed.plus === undefined && parsed.exception === undefined) {
    return SPDX_LICENSE_IDS.has(parsed.license)
      ? [{ kind: 'id', id: parsed.license }]
      : // Parseable per the SPDX grammar but not in the enum CycloneDX validates
        // against — emit it as a name so the document stays schema-valid.
        [{ kind: 'name', name: text }]
  }

  return [{ kind: 'expression', expression: text }]
}

/** Render normalised licences into the CycloneDX `licenses` array. */
export function toCycloneDx(licenses: ResolvedLicense[]): CdxLicenseChoice[] {
  return licenses.map((license) => {
    if (license.kind === 'id') return { license: { id: license.id } }
    if (license.kind === 'expression') return { expression: license.expression }
    return { license: { name: license.name } }
  })
}
