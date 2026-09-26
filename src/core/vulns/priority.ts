import type { Finding } from '../../types/index.js'
import type { VulnCache } from './cache.js'

/**
 * Two signals about whether anyone is actually exploiting a vulnerability, as
 * opposed to how bad it would be if they did.
 *
 * A CVSS base score answers "how severe, in the abstract". It is the wrong
 * question for triage under a clock, and it is the only question cradle could
 * answer until now: a critical that nobody has ever exploited outranks a medium
 * on the CISA list, which is backwards.
 *
 * - **EPSS** (FIRST) estimates the probability of exploitation in the next 30
 *   days. A number between 0 and 1, updated daily.
 * - **CISA KEV** is a list of vulnerabilities CISA has evidence are being
 *   exploited. Not a probability — a statement of fact, with a date.
 *
 * Both are **additional**, never a replacement. `--fail-on` stays CVSS-based,
 * because a gate whose threshold moves daily with somebody else's model is a
 * gate that goes red overnight for reasons nobody in the team changed. These
 * signals order the work; the threshold decides what blocks.
 *
 * Both are keyed on **CVE**, and cradle keys npm advisories on GHSA (SPEC.md
 * §6.3), so a finding without a CVE alias simply has no score. That is reported
 * as absent rather than as zero: "no data" and "no risk" are different answers.
 */

export const EPSS_ENDPOINT = 'https://api.first.org/data/v1/epss'
export const KEV_ENDPOINT =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

/** The most CVEs to ask EPSS about in one request. */
const EPSS_BATCH = 100

export interface ExploitSignals {
  /** Probability of exploitation in the next 30 days, 0..1. Absent when unknown. */
  epss?: number
  /** Where this sits among all scored CVEs, 0..1. */
  epssPercentile?: number
  /** The date of the EPSS model run, so a stale number is visibly stale. */
  epssDate?: string
  /** On CISA's Known Exploited Vulnerabilities list. */
  knownExploited?: boolean
  /** When CISA added it, present only when knownExploited. */
  knownExploitedSince?: string
}

export interface PriorityOptions {
  fetch: typeof globalThis.fetch
  cache: VulnCache
  userAgent?: string
  /** Today, for the KEV cache key. Injected so tests are deterministic. */
  today: string
}

export interface PriorityResult {
  /** CVE -> signals. Only CVEs that either source knew about appear. */
  byCve: Map<string, ExploitSignals>
  /** Sources that could not be reached, named so the report can say which. */
  unavailable: string[]
}

/**
 * Look up both signals for the CVEs among these findings.
 *
 * A failure in either source is **not** an error. These improve the ordering of
 * work; they are not the purpose of the tool, and an outage at FIRST or CISA
 * must not fail a scan — the same rule the registry lookup in the readiness
 * check follows (SPEC.md §6.5). What it must not do is fail silently, so the
 * unreachable source is named and the report says the column is incomplete.
 */
export async function fetchExploitSignals(
  findings: readonly Finding[],
  options: PriorityOptions,
): Promise<PriorityResult> {
  const cves = cvesOf(findings)
  if (cves.length === 0) return { byCve: new Map(), unavailable: [] }

  const byCve = new Map<string, ExploitSignals>()
  const unavailable: string[] = []

  const epss = await fetchEpss(cves, options)
  if (epss === undefined) unavailable.push('EPSS (api.first.org)')
  else {
    for (const [cve, signal] of epss) byCve.set(cve, { ...byCve.get(cve), ...signal })
  }

  const kev = await fetchKev(options)
  if (kev === undefined) unavailable.push('CISA KEV (cisa.gov)')
  else {
    for (const cve of cves) {
      const added = kev.get(cve)
      if (added === undefined) continue
      byCve.set(cve, { ...byCve.get(cve), knownExploited: true, knownExploitedSince: added })
    }
  }

  return { byCve, unavailable }
}

/**
 * The CVE identifiers among these findings, deduplicated.
 *
 * cradle's primary id is a GHSA, so the CVE lives in `aliases`. A finding with no
 * CVE cannot be looked up in either source, which is a gap in the data rather
 * than a property of the vulnerability.
 */
export function cvesOf(findings: readonly Finding[]): string[] {
  const cves = new Set<string>()
  for (const finding of findings) {
    for (const id of [finding.id, ...finding.aliases]) {
      if (/^CVE-\d{4}-\d+$/.test(id)) cves.add(id)
    }
  }
  return [...cves].sort()
}

/** Attach the signals to a finding, by its CVE alias. */
export function withExploitSignals(
  finding: Finding,
  byCve: ReadonlyMap<string, ExploitSignals>,
): Finding {
  for (const id of [finding.id, ...finding.aliases]) {
    const signals = byCve.get(id)
    if (signals !== undefined) return { ...finding, exploit: signals }
  }
  return finding
}

/**
 * Order findings for triage: known-exploited first, then by EPSS, then by
 * severity.
 *
 * This is the order the ranking exists for. A medium that CISA has evidence is
 * being exploited is more urgent than a critical that nobody has touched, and
 * sorting by severity alone says the opposite. Severity remains the tiebreak, so
 * a list with no exploit data at all sorts exactly as it did before.
 */
export function byExploitPriority(a: Finding, b: Finding, severityRank: (s: Finding) => number) {
  const known =
    Number(b.exploit?.knownExploited ?? false) - Number(a.exploit?.knownExploited ?? false)
  if (known !== 0) return known

  const epss = (b.exploit?.epss ?? -1) - (a.exploit?.epss ?? -1)
  if (epss !== 0) return epss

  return severityRank(a) - severityRank(b)
}

// ---------------------------------------------------------------------------
// EPSS
// ---------------------------------------------------------------------------

interface EpssResponse {
  data?: { cve?: string; epss?: string; percentile?: string; date?: string }[]
}

async function fetchEpss(
  cves: readonly string[],
  options: PriorityOptions,
): Promise<Map<string, ExploitSignals> | undefined> {
  const result = new Map<string, ExploitSignals>()

  for (let index = 0; index < cves.length; index += EPSS_BATCH) {
    const batch = cves.slice(index, index + EPSS_BATCH)
    // Cached per batch and per day: the model is re-run daily, so yesterday's
    // answer is a different answer and must not be served as today's.
    const key = `epss/v1/${options.today}/${batch.join(',')}`
    const cached = await options.cache.get(key)

    let body: EpssResponse | undefined
    if (cached !== undefined) {
      body = safeParse<EpssResponse>(cached)
    } else {
      const raw = await get(`${EPSS_ENDPOINT}?cve=${batch.join(',')}`, options)
      if (raw === undefined) return undefined
      body = safeParse<EpssResponse>(raw)
      if (body !== undefined) await options.cache.set(key, raw)
    }
    if (body === undefined) return undefined

    for (const entry of body.data ?? []) {
      if (typeof entry.cve !== 'string') continue
      const signals: ExploitSignals = {}
      const epss = Number.parseFloat(entry.epss ?? '')
      const percentile = Number.parseFloat(entry.percentile ?? '')
      if (Number.isFinite(epss)) signals.epss = epss
      if (Number.isFinite(percentile)) signals.epssPercentile = percentile
      if (typeof entry.date === 'string') signals.epssDate = entry.date
      if (Object.keys(signals).length > 0) result.set(entry.cve, signals)
    }
  }
  return result
}

// ---------------------------------------------------------------------------
// CISA KEV
// ---------------------------------------------------------------------------

interface KevResponse {
  catalogVersion?: string
  vulnerabilities?: { cveID?: string; dateAdded?: string }[]
}

/**
 * The KEV catalogue, as a CVE -> date-added map.
 *
 * CISA publishes one file with every entry and offers no per-CVE endpoint, so the
 * whole catalogue comes down — about 1.7 MB and 1700 entries. Only the ids and
 * dates are kept in the cache, which turns that into a few tens of kilobytes,
 * and the key is the date: the catalogue changes at most daily, so a second run
 * the same day costs nothing.
 */
async function fetchKev(options: PriorityOptions): Promise<Map<string, string> | undefined> {
  const key = `kev/v1/${options.today}`
  const cached = await options.cache.get(key)
  if (cached !== undefined) {
    const stored = safeParse<Record<string, string>>(cached)
    if (stored !== undefined) return new Map(Object.entries(stored))
  }

  const raw = await get(KEV_ENDPOINT, options)
  if (raw === undefined) return undefined
  const body = safeParse<KevResponse>(raw)
  if (body === undefined) return undefined

  const map = new Map<string, string>()
  for (const entry of body.vulnerabilities ?? []) {
    if (typeof entry.cveID !== 'string') continue
    map.set(entry.cveID, typeof entry.dateAdded === 'string' ? entry.dateAdded : '')
  }
  await options.cache.set(key, JSON.stringify(Object.fromEntries(map)))
  return map
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/**
 * One request, with no retry and no throw.
 *
 * Deliberately simpler than the OSV client, which retries on 429 because its
 * answer is the point of the run. These two are enrichment: if a source is down,
 * the right behaviour is to say so and carry on, not to spend the user's time
 * waiting for a column.
 */
async function get(url: string, options: PriorityOptions): Promise<string | undefined> {
  try {
    const response = await options.fetch(url, {
      headers: {
        accept: 'application/json',
        ...(options.userAgent === undefined ? {} : { 'user-agent': options.userAgent }),
      },
    })
    if (!response.ok) return undefined
    return await response.text()
  } catch {
    return undefined
  }
}

function safeParse<T>(raw: string): T | undefined {
  try {
    return JSON.parse(raw) as T
  } catch {
    return undefined
  }
}
