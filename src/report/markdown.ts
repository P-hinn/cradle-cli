import { severityRank } from '../core/vulns/severity.js'
import type { BaselineDiff, Finding, Severity } from '../types/index.js'

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
  const total = diff.added.length + diff.known.length

  const lines: string[] = [
    COMMENT_MARKER,
    `### ${verdict(input)}`,
    '',
    `\`${input.project.name}@${input.project.version}\` · ${input.componentCount} components · ` +
      `${input.packageManager} · ${input.scope === 'all' ? 'all dependencies' : 'production only'}`,
    '',
  ]

  const summary = [
    `**${total}** known ${total === 1 ? 'finding' : 'findings'}`,
    `**${diff.added.length}** new since the baseline`,
  ]
  if (input.suppressed > 0) summary.push(`**${input.suppressed}** ruled out by VEX`)
  if (!input.hasBaseline) {
    summary.push('_no baseline yet, so everything counts as new_')
  }
  lines.push(summary.join(' · '), '')

  if (diff.added.length > 0) {
    lines.push('| Severity | Advisory | Package | Fixed in |', '| --- | --- | --- | --- |')

    const sorted = [...diff.added].sort(
      (a, b) => severityRank(a.severity) - severityRank(b.severity),
    )
    for (const finding of sorted.slice(0, MAX_ROWS)) {
      const fix = finding.fixedIn === undefined ? '— _no fix yet_' : `\`${finding.fixedIn}\``
      const route = finding.component.direct
        ? ''
        : `<br><sub>${escapeCell(finding.path.join(' › '))}</sub>`
      lines.push(
        `| ${finding.severity} | [${escapeCell(finding.id)}](${finding.osvUrl}) | ` +
          `\`${escapeCell(finding.component.name)}\` ${escapeCell(finding.component.version)}${route} | ${fix} |`,
      )
    }
    if (sorted.length > MAX_ROWS) {
      lines.push('')
      // Never truncate silently: a list that stops without saying so reads as
      // the complete picture.
      lines.push(
        `_${sorted.length - MAX_ROWS} further new ${sorted.length - MAX_ROWS === 1 ? 'finding is' : 'findings are'} listed in the report._`,
      )
    }
    lines.push('')
  }

  if (diff.resolved.length > 0) {
    const label = diff.resolved.length === 1 ? 'finding is' : 'findings are'
    lines.push(
      `${diff.resolved.length} baselined ${label} gone. \`cradle check --baseline\` tidies the file up.`,
      '',
    )
  }

  const unfixable = diff.added.filter((finding) => finding.fixedIn === undefined)
  if (unfixable.length > 0) {
    lines.push(
      `<details><summary>${unfixable.length} of the new ${unfixable.length === 1 ? 'finding has' : 'findings have'} no fix available</summary>`,
      '',
      'Those need a decision rather than an upgrade. `cradle suppress <id> --justification ' +
        '<category>` records one in `.cradle/vex.json`, where a reviewer can see and disagree ' +
        'with it.',
      '',
      '</details>',
      '',
    )
  }

  if (input.artifactName !== undefined) {
    lines.push(
      `The full report, the SBOM and \`findings.json\` are attached to this run as **${escapeCell(input.artifactName)}**.`,
      '',
    )
  }

  lines.push(
    '<sub>' +
      `${input.toolName} ${input.toolVersion} — a technical snapshot, not legal advice and not a ` +
      'conformity assessment.</sub>',
  )

  return lines.join('\n')
}

function verdict(input: PullRequestCommentInput): string {
  if (input.failing.length > 0) {
    const count = input.failing.length
    return `❌ ${count} new ${count === 1 ? 'finding' : 'findings'} at or above ${input.threshold}`
  }
  if (input.diff.added.length > 0) {
    return `⚠️ ${input.diff.added.length} new ${input.diff.added.length === 1 ? 'finding' : 'findings'}, none above the threshold`
  }
  return '✅ Nothing new since the baseline'
}

/** Keep advisory text from breaking out of a markdown table cell. */
function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}
