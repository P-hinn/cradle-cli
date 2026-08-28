import type { BaselineDiff, BaselineDocument, BaselineEntry, Finding } from '../../types/index.js'
import { CradleError } from '../errors.js'
import { severityRank } from '../vulns/severity.js'

/**
 * How a finding is identified in the baseline: advisory plus package name, with
 * the version deliberately left out.
 *
 * Including the version would make every patch bump of an unfixed dependency
 * look like a brand-new finding, and a gate that goes red on unrelated churn is
 * a gate people switch off. The severity is recorded separately so that a
 * re-rated advisory is still caught.
 */
export function baselineKey(id: string, packageName: string): string {
  return `${id}|${packageName}`
}

/**
 * Compare this scan against the accepted state.
 *
 * The point of a baseline is that an existing project always has a backlog, and
 * a gate that is red from day one gets ignored. So `check` asks a narrower
 * question than `scan`: what changed?
 */
export function diffAgainstBaseline(
  findings: readonly Finding[],
  baseline: BaselineDocument | undefined,
): BaselineDiff {
  if (baseline === undefined) {
    return { added: [...findings], known: [], resolved: [], worsened: [] }
  }

  const accepted = new Map<string, BaselineEntry>()
  for (const entry of baseline.entries) {
    accepted.set(baselineKey(entry.id, entry.package), entry)
  }

  const added: Finding[] = []
  const known: Finding[] = []
  const worsened: Finding[] = []
  const seen = new Set<string>()

  for (const finding of findings) {
    const key = baselineKey(finding.id, finding.component.name)
    seen.add(key)

    const entry = accepted.get(key)
    if (entry === undefined) {
      added.push(finding)
      continue
    }

    // Accepting a medium is not accepting the critical it was later re-rated to.
    if (severityRank(finding.severity) < severityRank(entry.severity)) {
      worsened.push(finding)
      added.push(finding)
      continue
    }
    known.push(finding)
  }

  const resolved = baseline.entries.filter(
    (entry) => !seen.has(baselineKey(entry.id, entry.package)),
  )

  return { added, known, resolved, worsened }
}

export function toBaseline(
  findings: readonly Finding[],
  meta: Omit<BaselineDocument, 'entries'>,
): BaselineDocument {
  const entries = findings
    .map(
      (finding): BaselineEntry => ({
        id: finding.id,
        package: finding.component.name,
        severity: finding.severity,
        acceptedAt: meta.timestamp,
      }),
    )
    // One entry per advisory-and-package, sorted, so the committed file has a
    // readable diff when it changes.
    .filter(
      (entry, index, all) =>
        all.findIndex(
          (other) => baselineKey(other.id, other.package) === baselineKey(entry.id, entry.package),
        ) === index,
    )
    .sort((a, b) => a.package.localeCompare(b.package) || a.id.localeCompare(b.id))

  return { ...meta, entries }
}

export function parseBaseline(raw: string, source: string): BaselineDocument {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (cause) {
    throw new CradleError(
      `${source} is not valid JSON`,
      'Delete it and re-run `cradle check --baseline` to write a fresh one.',
      { cause },
    )
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new CradleError(`${source} is not a baseline document`, 'Expected a JSON object.')
  }

  const document = parsed as Partial<BaselineDocument>
  if (!Array.isArray(document.entries)) {
    throw new CradleError(
      `${source} has no "entries" array`,
      'A baseline records which findings were accepted. Re-run `cradle check --baseline`.',
    )
  }

  const entries = document.entries.map((entry, index) => {
    const candidate = entry as Partial<BaselineEntry>
    if (typeof candidate.id !== 'string' || typeof candidate.package !== 'string') {
      throw new CradleError(
        `${source} entry ${index + 1} is missing "id" or "package"`,
        'Re-run `cradle check --baseline` to rewrite the file.',
      )
    }
    return {
      id: candidate.id,
      package: candidate.package,
      severity: candidate.severity ?? 'unknown',
      acceptedAt: candidate.acceptedAt ?? '',
    }
  })

  return {
    schemaVersion: 1,
    timestamp: typeof document.timestamp === 'string' ? document.timestamp : '',
    tool: document.tool ?? { name: '', version: '' },
    project: document.project ?? { name: '', version: '' },
    scope: document.scope === 'all' ? 'all' : 'production',
    entries,
  }
}

export function serializeBaseline(baseline: BaselineDocument): string {
  return `${JSON.stringify(baseline, null, 2)}\n`
}
