import type {
  BaselineDocument,
  CradleConfig,
  DependencyGraph,
  Finding,
  ReadinessCheck,
  ReadinessReport,
  ReadinessStatus,
} from '../../types/index.js'
import type { PackageFacts } from './registry.js'

const DAY = 86_400_000
const STALE_MONTHS = 24

export interface ReadinessInput {
  graph: DependencyGraph
  /** Active findings, after live VEX statements have been applied. */
  findings: readonly Finding[]
  /** Findings a live VEX statement rules out. */
  suppressed: readonly Finding[]
  baseline: BaselineDocument | undefined
  config: CradleConfig | undefined
  now: Date
  /** True when the run had no network, so anything needing it is unassessable. */
  offline: boolean

  /** When the SBOM was last written, if it exists. */
  sbomWrittenAt?: Date
  /** When the lockfile was last changed. */
  lockfileChangedAt?: Date
  /** Contents of SECURITY.md, if the project has one. */
  securityPolicy?: string
  /** Registry facts keyed by component purl. */
  packageFacts?: ReadonlyMap<string, PackageFacts>
}

/**
 * Evaluate the CRA readiness checklist.
 *
 * The point of this list is that the regulation asks for documentation and
 * process, not only for a clean dependency tree, and that is the part teams
 * forget. Every item states what was found and what to do next; none of them
 * claims that doing so makes anyone compliant.
 *
 * Where cradle cannot tell, it says `not-assessable` rather than guessing in
 * either direction. A checklist that reports green because it did not look is
 * worse than no checklist.
 */
export function evaluateReadiness(input: ReadinessInput): ReadinessReport {
  const checks: ReadinessCheck[] = [
    sbomFreshness(input),
    disclosurePolicy(input),
    supportPeriod(input),
    licenceCoverage(input),
    maintenance(input),
    unresolvedFindings(input),
  ]

  const counts: Record<ReadinessStatus, number> = {
    met: 0,
    partial: 0,
    open: 0,
    'not-assessable': 0,
  }
  for (const check of checks) counts[check.status] += 1

  return { checks, counts }
}

function sbomFreshness(input: ReadinessInput): ReadinessCheck {
  const base = {
    id: 'sbom',
    title: 'A machine-readable SBOM exists and is current',
    reference: 'Annex I, Part II(1)',
  }

  if (input.sbomWrittenAt === undefined) {
    return {
      ...base,
      status: 'open',
      detail: 'No SBOM has been written yet.',
      nextStep: 'Run `cradle scan` and commit the resulting .cradle/sbom.cdx.json.',
    }
  }
  if (input.lockfileChangedAt === undefined) {
    return {
      ...base,
      status: 'partial',
      detail: 'An SBOM exists, but the lockfile could not be read to compare dates.',
      nextStep: 'Re-run `cradle scan` from the project root so the two can be compared.',
    }
  }
  if (input.sbomWrittenAt < input.lockfileChangedAt) {
    return {
      ...base,
      status: 'open',
      detail: 'The SBOM is older than the lockfile, so the dependency tree has changed since.',
      nextStep: 'Re-run `cradle scan`, and wire it into CI so this cannot drift again.',
    }
  }
  return {
    ...base,
    status: 'met',
    detail: 'The SBOM is at least as recent as the lockfile.',
    nextStep:
      'Keep it that way by running `cradle check` in CI. The SBOM belongs to the technical ' +
      'documentation and has to be kept for ten years.',
  }
}

function disclosurePolicy(input: ReadinessInput): ReadinessCheck {
  const base = {
    id: 'disclosure',
    title: 'A coordinated vulnerability disclosure policy is published',
    reference: 'Annex I, Part II(5)',
  }
  const configured = input.config?.contactEmail

  if (input.securityPolicy === undefined) {
    return {
      ...base,
      status: 'open',
      detail: 'The project has no SECURITY.md.',
      nextStep:
        'Add a SECURITY.md naming an address for vulnerability reports and how quickly you ' +
        'aim to respond. GitHub surfaces it on the repository automatically.',
    }
  }

  // A policy no one can act on is only half a policy, so look for a way to reach
  // someone rather than trusting the file's presence.
  const hasContact =
    /[\w.+-]+@[\w-]+\.[\w.-]+/.test(input.securityPolicy) ||
    /https?:\/\/\S+/.test(input.securityPolicy)
  if (!hasContact) {
    return {
      ...base,
      status: 'partial',
      detail: 'SECURITY.md exists but names no address or link a reporter could use.',
      nextStep:
        'Add an email address or a reporting URL to SECURITY.md' +
        (configured === undefined ? '.' : `, for example ${configured}.`),
    }
  }

  return {
    ...base,
    status: 'met',
    detail: 'SECURITY.md exists and gives reporters a way to reach you.',
    nextStep:
      'Check that the address is monitored, and that someone is responsible for the 24-hour ' +
      'early warning that applies to actively exploited vulnerabilities from 11 September 2026.',
  }
}

function supportPeriod(input: ReadinessInput): ReadinessCheck {
  const base = {
    id: 'support-period',
    title: 'The support period is documented',
    reference: 'Art. 13(8), (9) and (13)',
  }
  const retention =
    'Remember the two companion obligations: security updates stay available for at least ' +
    'ten years after they are issued, and the technical documentation is kept for ten years ' +
    'or the support period, whichever is longer.'

  const end = input.config?.supportPeriodEnd
  if (end === undefined) {
    return {
      ...base,
      status: 'open',
      detail: 'No support period is recorded.',
      nextStep:
        'Add "supportPeriodEnd" to .cradle/config.json. It has to reflect how long the product ' +
        'is expected to be in use, and be at least five years unless the expected use is ' +
        `shorter than that. ${retention}`,
    }
  }

  const endsAt = Date.parse(end)
  if (Number.isNaN(endsAt)) {
    return {
      ...base,
      status: 'partial',
      detail: `"supportPeriodEnd" is set to ${end}, which is not a date cradle can read.`,
      nextStep: 'Use an ISO date, for example 2032-06-30.',
    }
  }
  if (endsAt <= input.now.getTime()) {
    return {
      ...base,
      status: 'open',
      detail: `The recorded support period ended on ${end}.`,
      nextStep:
        'Either extend it and say so publicly, or document that the product has reached end ' +
        `of support. ${retention}`,
    }
  }

  // The five-year floor is measured from placing on the market, which cradle
  // cannot know unless it is written down.
  const placed = input.config?.placedOnMarket
  const placedAt = placed === undefined ? Number.NaN : Date.parse(placed)
  if (!Number.isNaN(placedAt)) {
    // Calendar arithmetic, not a day count. Five years is 1826 days across a
    // leap year and 1825 otherwise, so dividing by an average year length reads
    // exactly five calendar years as 4.999 and would tell a compliant user they
    // are not.
    const floor = addYears(new Date(placedAt), 5)
    if (endsAt < floor.getTime()) {
      return {
        ...base,
        status: 'partial',
        detail:
          `Support runs from ${placed} until ${end}, which is short of the five years the ` +
          'regulation sets as the floor.',
        nextStep:
          `Five years from ${placed} would be ${isoDate(floor)}. Extend the period to at ` +
          'least that, or record why the product is expected to be in use for less than five ' +
          `years. ${retention}`,
      }
    }
    return {
      ...base,
      status: 'met',
      detail: `Support runs from ${placed} until ${end}, which clears the five-year floor.`,
      nextStep: retention,
    }
  }

  return {
    ...base,
    status: 'partial',
    detail: `Support is documented until ${end}, but the date it started is not recorded.`,
    nextStep:
      'Add "placedOnMarket" to .cradle/config.json so the five-year floor can actually be ' +
      `checked. ${retention}`,
  }
}

function licenceCoverage(input: ReadinessInput): ReadinessCheck {
  const base = {
    id: 'licences',
    title: 'Every component declares a licence',
    reference: 'Annex I, Part II(1)',
  }
  const unknown = input.graph.components.filter((component) => component.licenseUnknown)

  if (unknown.length === 0) {
    return {
      ...base,
      status: 'met',
      detail: `All ${input.graph.components.length} components declare a licence.`,
      nextStep: 'Nothing to do. Re-check when dependencies change.',
    }
  }

  const names = unknown.slice(0, 5).map((c) => `${c.name}@${c.version}`)
  const more = unknown.length > 5 ? `, and ${unknown.length - 5} more` : ''
  return {
    ...base,
    status: 'partial',
    detail: `${unknown.length} of ${input.graph.components.length} components declare no licence: ${names.join(', ')}${more}.`,
    nextStep:
      'Check each one against its repository and record what you find. For your own workspace ' +
      'packages, add a "license" field to their package.json.',
  }
}

function maintenance(input: ReadinessInput): ReadinessCheck {
  const base = {
    id: 'maintenance',
    title: 'Dependencies are still maintained',
    reference: 'Annex I, Part II(2)',
  }

  if (input.offline || input.packageFacts === undefined) {
    return {
      ...base,
      status: 'not-assessable',
      detail: 'Release dates and deprecation notices live in the registry, which was not queried.',
      nextStep: 'Re-run without --offline to have this checked.',
    }
  }

  const deprecated: string[] = []
  const stale: string[] = []
  const cutoff = input.now.getTime() - STALE_MONTHS * 30.44 * DAY

  for (const component of input.graph.components) {
    const facts = input.packageFacts.get(component.purl)
    if (facts === undefined) continue
    if (facts.deprecated !== undefined) deprecated.push(`${component.name}@${component.version}`)
    if (facts.lastPublish !== undefined && Date.parse(facts.lastPublish) < cutoff) {
      stale.push(`${component.name} (last release ${facts.lastPublish.slice(0, 10)})`)
    }
  }

  // Release dates are only fetched for direct dependencies; say so rather than
  // implying the whole tree was checked.
  const scope =
    `Deprecation was checked for all ${input.graph.components.length} components; ` +
    'release dates for the direct dependencies only.'

  if (deprecated.length === 0 && stale.length === 0) {
    return {
      ...base,
      status: 'met',
      detail: `No deprecated packages, and no direct dependency without a release in ${STALE_MONTHS} months. ${scope}`,
      nextStep: 'Nothing to do.',
    }
  }

  const parts: string[] = []
  if (deprecated.length > 0) {
    parts.push(`${deprecated.length} deprecated: ${deprecated.slice(0, 5).join(', ')}`)
  }
  if (stale.length > 0) {
    parts.push(
      `${stale.length} without a release in ${STALE_MONTHS} months: ${stale.slice(0, 5).join(', ')}`,
    )
  }

  return {
    ...base,
    status: 'partial',
    detail: `${parts.join('. ')}. ${scope}`,
    nextStep:
      'An unmaintained dependency will not get a fix when one is needed. Decide for each ' +
      'whether to replace it, vendor it, or accept the risk in writing.',
  }
}

/**
 * The check the whole exercise is really about.
 *
 * A finding with no fix and no VEX statement is one nobody has ruled on. Under
 * the reporting duty that applies from 11 September 2026, that is the category
 * that turns into a deadline if it is ever actively exploited.
 *
 * A baselined finding counts as open here. `cradle check` stays green on it,
 * because a gate that is red from day one gets switched off — but the baseline
 * says "we know", not "it does not apply", and only VEX says the latter. If the
 * checklist accepted the baseline too, the baseline would quietly launder
 * findings, and this list would report green exactly where it matters most.
 */
function unresolvedFindings(input: ReadinessInput): ReadinessCheck {
  const base = {
    id: 'unresolved',
    title: 'No open findings without a fix and without a ruling',
    reference: 'Art. 14',
  }

  if (input.findings.length === 0) {
    return {
      ...base,
      status: 'met',
      detail:
        input.suppressed.length === 0
          ? 'No open findings.'
          : `No open findings. ${input.suppressed.length} are ruled out by VEX statements.`,
      nextStep:
        'Nothing to do. Advisories are published continuously, so keep the scan running in CI.',
    }
  }

  const unfixable = input.findings.filter((finding) => finding.fixedIn === undefined)
  const fixable = input.findings.length - unfixable.length
  const baselined = input.baseline === undefined ? 0 : countBaselined(input)

  const detail: string[] = []
  if (unfixable.length > 0) {
    detail.push(
      `${unfixable.length} open ${unfixable.length === 1 ? 'finding has' : 'findings have'} no fix available and no VEX statement`,
    )
  }
  if (fixable > 0) detail.push(`${fixable} could be closed by an upgrade`)
  if (baselined > 0) {
    detail.push(
      `${baselined} of these are in the baseline, which keeps CI green but is not a ruling`,
    )
  }

  return {
    ...base,
    status: unfixable.length > 0 ? 'open' : 'partial',
    detail: `${detail.join('; ')}.`,
    nextStep:
      unfixable.length > 0
        ? 'For each one with no fix, record a decision with `cradle suppress`, using the ' +
          'justification that fits. These are the findings that would become reportable ' +
          'within 24 hours if one turned out to be actively exploited.'
        : 'Apply the upgrades listed under Next steps, or record a ruling for the ones you ' +
          'are not going to take.',
  }
}

/** Calendar-exact year arithmetic, in UTC so a timezone cannot shift the date. */
function addYears(date: Date, years: number): Date {
  const shifted = new Date(date.getTime())
  shifted.setUTCFullYear(shifted.getUTCFullYear() + years)
  return shifted
}

function isoDate(date: Date): string {
  return date.toISOString().slice(0, 10)
}

function countBaselined(input: ReadinessInput): number {
  const accepted = new Set(
    (input.baseline?.entries ?? []).map((entry) => `${entry.id}|${entry.package}`),
  )
  return input.findings.filter((finding) => accepted.has(`${finding.id}|${finding.component.name}`))
    .length
}
