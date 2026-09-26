import type { Finding, VexJustification } from '../../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../../version.generated.js'

/**
 * CSAF 2.0 in the VEX profile, from the same suppressions that produce
 * `vex.json`.
 *
 * Two formats say the same thing here, and cradle writes OpenVEX by default
 * because it is smaller and easier to read in a pull request (SPEC.md §6.3).
 * CSAF exists because it is what European procurement and the BSI ask for by
 * name: TR-03183-3 covers vulnerability reports in CSAF, and the ENISA reporting
 * route expects it. So this is a second rendering of one decision, never a
 * second decision.
 *
 * The mapping is closer than it looks. CSAF's `flags[].label` enumerates exactly
 * the five justifications OpenVEX defines, so a suppression translates without
 * loss. What does not translate is cradle's expiry extension: CSAF has no notion
 * of it either, and an expired suppression simply does not appear here, because
 * an expired statement does not suppress anything (SPEC.md §6.3).
 */

export interface CsafDocument {
  document: {
    category: 'csaf_vex'
    csaf_version: '2.0'
    title: string
    publisher: {
      category: 'vendor'
      name: string
      namespace: string
    }
    tracking: {
      id: string
      status: 'final'
      version: string
      initial_release_date: string
      current_release_date: string
      revision_history: { number: string; date: string; summary: string }[]
      generator: { engine: { name: string; version: string }; date: string }
    }
    notes?: { category: string; text: string; title?: string }[]
  }
  product_tree: {
    full_product_names: {
      product_id: string
      name: string
      product_identification_helper?: { purl: string }
    }[]
  }
  vulnerabilities: CsafVulnerability[]
}

export interface CsafVulnerability {
  title?: string
  cve?: string
  ids?: { system_name: string; text: string }[]
  notes?: { category: string; text: string; title?: string }[]
  product_status?: {
    known_not_affected?: string[]
    known_affected?: string[]
    fixed?: string[]
    under_investigation?: string[]
  }
  flags?: { label: VexJustification; product_ids: string[] }[]
  threats?: { category: 'impact'; details: string; product_ids: string[] }[]
  remediations?: {
    category: 'vendor_fix' | 'none_available' | 'mitigation' | 'no_fix_planned' | 'workaround'
    details: string
    product_ids: string[]
  }[]
  references?: { category?: 'self' | 'external'; summary: string; url: string }[]
}

export interface BuildCsafOptions {
  /** Whose statement this is. CSAF requires a named publisher. */
  publisher: { name: string; namespace: string }
  /** ISO 8601, shared with every other artefact from the same scan. */
  timestamp: string
  /** Unique tracking id for the document, derived from the scan's serial number. */
  trackingId: string
  product: { name: string; version: string }
}

/**
 * Render suppressed findings as a CSAF VEX document.
 *
 * Only suppressed findings appear. An active finding is not a VEX statement — it
 * is a finding, and `findings.json` is where it belongs. A CSAF document that
 * listed everything would be a vulnerability report, which is a different
 * document with different obligations attached to it.
 */
export function buildCsaf(
  suppressed: readonly Finding[],
  options: BuildCsafOptions,
): CsafDocument | undefined {
  // The CSAF schema puts `minItems: 1` on both `vulnerabilities` and
  // `full_product_names`, so a document with nothing in it does not validate.
  // Returning undefined rather than an empty shell is the difference between
  // "there is nothing to state" and a file that claims to be CSAF and is not.
  if (suppressed.length === 0) return undefined

  // One product entry per affected component, keyed by purl so a consumer can
  // match it against the SBOM.
  const products = new Map<string, { product_id: string; name: string; purl: string }>()
  const productIdFor = (finding: Finding): string => {
    const purl = finding.component.purl
    const existing = products.get(purl)
    if (existing !== undefined) return existing.product_id
    const productId = `CSAFPID-${products.size + 1}`
    products.set(purl, {
      product_id: productId,
      name: `${finding.component.name} ${finding.component.version}`,
      purl,
    })
    return productId
  }

  const byAdvisory = new Map<string, Finding[]>()
  for (const finding of suppressed) {
    const list = byAdvisory.get(finding.id)
    if (list === undefined) byAdvisory.set(finding.id, [finding])
    else list.push(finding)
  }

  const vulnerabilities: CsafVulnerability[] = []
  for (const [id, findings] of [...byAdvisory].sort(([a], [b]) => a.localeCompare(b))) {
    vulnerabilities.push(toVulnerability(id, findings, productIdFor))
  }

  return {
    document: {
      category: 'csaf_vex',
      csaf_version: '2.0',
      title: `VEX statements for ${options.product.name} ${options.product.version}`,
      publisher: {
        category: 'vendor',
        name: options.publisher.name,
        namespace: options.publisher.namespace,
      },
      tracking: {
        id: options.trackingId,
        // Final, not draft: these are decisions somebody recorded and committed.
        status: 'final',
        version: '1',
        initial_release_date: options.timestamp,
        current_release_date: options.timestamp,
        revision_history: [
          { number: '1', date: options.timestamp, summary: 'Generated from .cradle/vex.json.' },
        ],
        generator: {
          engine: { name: TOOL_NAME, version: TOOL_VERSION },
          date: options.timestamp,
        },
      },
      notes: [
        {
          category: 'legal_disclaimer',
          title: 'Scope',
          text:
            'Generated from the VEX statements recorded in this repository. It is a technical ' +
            'aid for documentation, not a conformity assessment and not legal advice.',
        },
      ],
    },
    product_tree: {
      full_product_names: [...products.values()].map((entry) => ({
        product_id: entry.product_id,
        name: entry.name,
        product_identification_helper: { purl: entry.purl },
      })),
    },
    vulnerabilities,
  }
}

function toVulnerability(
  id: string,
  findings: readonly Finding[],
  productIdFor: (finding: Finding) => string,
): CsafVulnerability {
  const first = findings[0]
  const vulnerability: CsafVulnerability = {}
  if (first?.summary !== undefined && first.summary !== '') vulnerability.title = first.summary

  // CSAF has a dedicated `cve` field and a general `ids` list. cradle keys on
  // GHSA, so the GHSA goes in `ids` and the CVE alias, where there is one, goes
  // in the field built for it.
  const cve = [id, ...(first?.aliases ?? [])].find((candidate) => candidate.startsWith('CVE-'))
  if (cve !== undefined) vulnerability.cve = cve

  const ids = [id, ...(first?.aliases ?? [])]
    .filter((candidate) => candidate !== cve)
    .map((candidate) => ({
      system_name: candidate.startsWith('GHSA-') ? 'GitHub Security Advisory' : 'Advisory',
      text: candidate,
    }))
  if (ids.length > 0) vulnerability.ids = ids

  // Grouped by justification, because CSAF puts the label on the flag rather
  // than on the product.
  const byJustification = new Map<VexJustification, string[]>()
  const notAffected: string[] = []
  const withoutJustification: string[] = []

  for (const finding of findings) {
    const productId = productIdFor(finding)
    notAffected.push(productId)
    const justification = finding.suppression?.justification
    if (justification === undefined) {
      withoutJustification.push(productId)
      continue
    }
    const list = byJustification.get(justification)
    if (list === undefined) byJustification.set(justification, [productId])
    else list.push(productId)
  }

  vulnerability.product_status = { known_not_affected: notAffected }

  const flags = [...byJustification].map(([label, product_ids]) => ({ label, product_ids }))
  if (flags.length > 0) vulnerability.flags = flags

  // The CSAF VEX profile wants a reason for every known_not_affected product:
  // either a flag or an impact statement. cradle makes the justification
  // mandatory on `suppress`, so this only fires for a hand-edited vex.json - and
  // leaving the product with no reason at all would produce a document that
  // asserts "not affected" and declines to say why.
  const impact = findings
    .filter((finding) => finding.suppression?.justification === undefined)
    .map((finding) => finding.suppression?.notes)
    .find((note) => note !== undefined && note !== '')
  if (withoutJustification.length > 0) {
    vulnerability.threats = [
      {
        category: 'impact',
        details: impact ?? 'No justification was recorded for this statement.',
        product_ids: withoutJustification,
      },
    ]
  }

  const notes = findings
    .map((finding) => finding.suppression?.notes)
    .filter((note): note is string => note !== undefined && note !== '')
  if (notes.length > 0) {
    vulnerability.notes = [{ category: 'other', title: 'Assessment', text: notes.join('\n\n') }]
  }

  if (first?.osvUrl !== undefined) {
    vulnerability.references = [{ category: 'external', summary: 'OSV', url: first.osvUrl }]
  }

  return vulnerability
}
