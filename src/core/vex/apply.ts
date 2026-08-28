import type {
  Finding,
  Suppression,
  VexDocument,
  VexStatement,
  VexStatus,
} from '../../types/index.js'

/** Statuses that take a finding out of the active count. */
const SUPPRESSING: readonly VexStatus[] = ['not_affected', 'fixed']

export interface VexApplication {
  /** Findings that still count. */
  active: Finding[]
  /** Findings a live statement has ruled out, each carrying its justification. */
  suppressed: Finding[]
  /**
   * Statements that matched nothing in this scan. Usually the finding was fixed
   * by an upgrade, so the statement is now dead weight in the repository.
   */
  unmatched: VexStatement[]
}

const DAY = 86_400_000

/**
 * Apply VEX statements to findings.
 *
 * An expired statement deliberately does not suppress. That is the entire point
 * of putting a date on one: a decision made about a dependency two years ago
 * should have to be renewed rather than quietly outliving the reasoning behind
 * it. Expired matches still come back attached to the finding, so the report can
 * say "this lapsed" instead of the finding silently reappearing with no history.
 */
export function applyVex(
  findings: readonly Finding[],
  document: VexDocument | undefined,
  now: Date,
): VexApplication {
  if (document === undefined || document.statements.length === 0) {
    return { active: [...findings], suppressed: [], unmatched: [] }
  }

  const used = new Set<VexStatement>()
  const active: Finding[] = []
  const suppressed: Finding[] = []

  for (const finding of findings) {
    const statement = document.statements.find((candidate) => matches(candidate, finding))
    if (statement === undefined) {
      active.push(finding)
      continue
    }
    used.add(statement)

    const suppression = toSuppression(statement, now)
    const isSuppressed = !suppression.expired && SUPPRESSING.includes(suppression.status)
    const annotated: Finding = { ...finding, suppressed: isSuppressed, suppression }
    if (isSuppressed) suppressed.push(annotated)
    else active.push(annotated)
  }

  return {
    active,
    suppressed,
    unmatched: document.statements.filter((statement) => !used.has(statement)),
  }
}

function toSuppression(statement: VexStatement, now: Date): Suppression {
  const suppression: Suppression = { status: statement.status, expired: false }

  if (statement['@id'] !== undefined) suppression.statementId = statement['@id']
  if (statement.justification !== undefined) suppression.justification = statement.justification
  const notes = statement.status_notes ?? statement.impact_statement
  if (notes !== undefined && notes !== '') suppression.notes = notes
  if (statement.action_statement !== undefined) {
    suppression.actionStatement = statement.action_statement
  }

  const expires = statement['cradle:expires']
  if (expires !== undefined) {
    const at = Date.parse(expires)
    if (!Number.isNaN(at)) {
      suppression.expires = expires
      // Whole days, rounded up, so "expires today" reads as 0 rather than -1.
      suppression.expiresInDays = Math.ceil((at - now.getTime()) / DAY)
      suppression.expired = at <= now.getTime()
    }
  }

  return suppression
}

/**
 * Does this statement speak about this finding?
 *
 * The vulnerability may be named by any of its identifiers: people write down
 * the CVE they read about, while OSV keys npm advisories by GHSA.
 */
function matches(statement: VexStatement, finding: Finding): boolean {
  const names = new Set([finding.id, ...finding.aliases].map((name) => name.toUpperCase()))
  if (!names.has(statement.vulnerability.name.toUpperCase())) return false

  // No products at all means the statement speaks about everything it names.
  // OpenVEX allows products to cascade from the document; we have none there, so
  // the sensible reading is "every occurrence of this vulnerability".
  const products = statement.products ?? []
  if (products.length === 0) return true

  for (const product of products) {
    if (purlMatches(product['@id'], finding.component.purl)) return true
    for (const subcomponent of product.subcomponents ?? []) {
      if (purlMatches(subcomponent['@id'], finding.component.purl)) return true
    }
  }
  return false
}

/**
 * Compare a purl from the VEX file against a component's purl.
 *
 * An exact match is the normal case. A versionless purl (`pkg:npm/lodash`) also
 * matches, because that is how people write these by hand and refusing it would
 * be pedantry rather than safety.
 */
function purlMatches(candidate: string, componentPurl: string): boolean {
  if (candidate === componentPurl) return true
  return !candidate.includes('@') && componentPurl.startsWith(`${candidate}@`)
}

/** Statements whose expiry is within `days`, so the report can warn ahead of time. */
export function expiringSoon(
  document: VexDocument | undefined,
  now: Date,
  days = 30,
): { statement: VexStatement; inDays: number }[] {
  if (document === undefined) return []

  const soon: { statement: VexStatement; inDays: number }[] = []
  for (const statement of document.statements) {
    const expires = statement['cradle:expires']
    if (expires === undefined) continue
    const at = Date.parse(expires)
    if (Number.isNaN(at)) continue

    const inDays = Math.ceil((at - now.getTime()) / DAY)
    if (inDays >= 0 && inDays <= days) soon.push({ statement, inDays })
  }
  return soon.sort((a, b) => a.inDays - b.inDays)
}
