import { severityRank } from '../core/vulns/severity.js'
import type { BaselineDiff, Finding, Severity } from '../types/index.js'
import { type Language, type Strings, strings } from './i18n/index.js'

/**
 * The marker that makes the pull-request comment idempotent.
 *
 * The action looks for it to decide between editing the existing comment and
 * posting another one. A pull request that accumulates one comment per push is
 * a pull request where nobody reads the comments.
 */
export const COMMENT_MARKER = '<!-- cradle-cli:report -->'

/** How many findings to list before the comment stops being readable. */
const MAX_ROWS = 10

export interface PullRequestCommentInput {
  project: { name: string; version: string }
  packageManager: string
  scope: 'production' | 'all'
  componentCount: number
  diff: BaselineDiff
  suppressed: number
  /** Findings that are new *and* at or above the gate's threshold. */
  failing: readonly Finding[]
  threshold: Severity | 'never'
  hasBaseline: boolean
  toolName: string
  toolVersion: string
  /** Where the full report was uploaded, when the action uploaded one. */
  artifactName?: string
  /** Defaults to English, like the report. */
  lang?: Language
}

/**
 * Render the pull-request comment.
 *
 * It answers one question — what changed — and leaves the rest to the report.
 * The backlog is already known; repeating it on every push trains people to
 * scroll past.
 */
export function buildPullRequestComment(input: PullRequestCommentInput): string {
  const { diff } = input
  const t = strings(input.lang)
  const total = diff.added.length + diff.known.length

  const lines: string[] = [
    COMMENT_MARKER,
    `### ${verdict(input, t)}`,
    '',
    `\`${input.project.name}@${input.project.version}\` · ` +
      t.markdown.subtitle(
        input.componentCount,
        input.packageManager,
        input.scope === 'all' ? t.markdown.scopeAll : t.markdown.scopeProduction,
      ),
    '',
  ]

  const summary = [t.markdown.knownFindings(total), t.markdown.newSinceBaseline(diff.added.length)]
  if (input.suppressed > 0) summary.push(t.markdown.ruledOutByVex(input.suppressed))
  if (!input.hasBaseline) summary.push(t.markdown.noBaselineYet)
  lines.push(summary.join(' · '), '')

  if (diff.added.length > 0) {
    lines.push(
      `| ${t.markdown.severity} | ${t.markdown.advisory} | ${t.markdown.package} | ${t.markdown.fixedIn} |`,
      '| --- | --- | --- | --- |',
    )

    const sorted = [...diff.added].sort(
      (a, b) => severityRank(a.severity) - severityRank(b.severity),
    )
    for (const finding of sorted.slice(0, MAX_ROWS)) {
      const fix = finding.fixedIn === undefined ? t.markdown.noFixYet : `\`${finding.fixedIn}\``
      const route = finding.component.direct
        ? ''
        : `<br><sub>${escapeCell(finding.path.join(' › '))}</sub>`
      lines.push(
        `| ${t.severity[finding.severity]} | [${escapeCell(finding.id)}](${finding.osvUrl}) | ` +
          `\`${escapeCell(finding.component.name)}\` ${escapeCell(finding.component.version)}${route} | ${fix} |`,
      )
    }
    if (sorted.length > MAX_ROWS) {
      lines.push('')
      // Never truncate silently: a list that stops without saying so reads as
      // the complete picture.
      lines.push(t.markdown.truncated(sorted.length - MAX_ROWS))
    }
    lines.push('')
  }

  if (diff.resolved.length > 0) {
    lines.push(t.markdown.resolved(diff.resolved.length), '')
  }

  const unfixable = diff.added.filter((finding) => finding.fixedIn === undefined)
  if (unfixable.length > 0) {
    lines.push(
      `<details><summary>${t.markdown.unfixableSummary(unfixable.length)}</summary>`,
      '',
      t.markdown.unfixableBody,
      '',
      '</details>',
      '',
    )
  }

  if (input.artifactName !== undefined) {
    lines.push(t.markdown.artifact(escapeCell(input.artifactName)), '')
  }

  lines.push(`<sub>${t.markdown.footer(input.toolName, input.toolVersion)}</sub>`)

  return lines.join('\n')
}

function verdict(input: PullRequestCommentInput, t: Strings): string {
  if (input.failing.length > 0) {
    const threshold = input.threshold === 'never' ? input.threshold : t.severity[input.threshold]
    return t.markdown.verdictFailing(input.failing.length, threshold)
  }
  if (input.diff.added.length > 0) {
    return t.markdown.verdictNewBelowThreshold(input.diff.added.length)
  }
  return t.markdown.verdictClean
}

/** Keep advisory text from breaking out of a markdown table cell. */
function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}
