import type { ProfileReport } from '../core/readiness/profiles/bsi-tr-03183.js'
import type { ReadinessStatus } from '../types/index.js'

const MARK: Record<ReadinessStatus, string> = {
  met: 'met',
  partial: 'partial',
  open: 'open',
  'not-assessable': 'not assessable',
}

/**
 * The profile as plain text, for `cradle check --profile`.
 *
 * Fields are grouped by status rather than listed in document order, because the
 * question a reader has is "what is missing", not "what does section 5.2.2 say".
 * The clause travels with each line so the answer can be checked against the
 * guideline.
 */
export function renderProfileText(report: ProfileReport): string {
  const { profile } = report
  const lines = [
    '',
    `  ${profile.title} v${profile.version} (${profile.date})`,
    `  ${summaryLine(report)}`,
    '',
  ]

  for (const status of ['open', 'partial', 'not-assessable', 'met'] as const) {
    const fields = report.fields.filter((field) => field.status === status)
    if (fields.length === 0) continue
    lines.push(`  ${MARK[status]} — ${fields.length}`)
    for (const field of fields) {
      const required = field.requirement === 'required' ? ' [required]' : ''
      lines.push(`    · ${field.title} (${field.clause})${required}`)
      // Only the actionable statuses get their next step here; "met" needs none,
      // and printing all twenty would bury the four that matter.
      if (status !== 'met') {
        lines.push(`      ${field.detail}`)
        lines.push(`      -> ${field.nextStep}`)
      }
    }
    lines.push('')
  }

  lines.push(`  ${profile.url}`)
  lines.push('  This compares one SBOM against a list of data fields. It is not a conformity')
  lines.push('  assessment, and it does not make anything compliant.')
  lines.push('')
  return lines.join('\n')
}

/** One line of arithmetic, used by every format so they cannot disagree. */
export function summaryLine(report: ProfileReport): string {
  const { counts } = report
  const parts = [
    `${counts.met} met`,
    counts.partial > 0 ? `${counts.partial} partial` : '',
    counts.open > 0 ? `${counts.open} open` : '',
    counts['not-assessable'] > 0 ? `${counts['not-assessable']} not assessable` : '',
  ].filter((part) => part !== '')
  const required = report.requiredFieldsSatisfied
    ? 'no required field is open'
    : 'a required field is open'
  return `${parts.join(', ')} — ${required}`
}

/**
 * The profile as GitHub workflow commands.
 *
 * Notices, never errors. The profile describes the SBOM; it does not gate. Several
 * of its fields are manufacturer statements cradle cannot know, so failing a build
 * on them would make the build permanently red and then switched off.
 */
export function renderProfileAnnotations(report: ProfileReport): string[] {
  const lines: string[] = []
  for (const field of report.fields) {
    if (field.status === 'met') continue
    const level = field.status === 'open' && field.requirement === 'required' ? 'warning' : 'notice'
    lines.push(
      `::${level} title=${report.profile.title} ${field.clause}::` +
        `${field.title}: ${field.detail} ${field.nextStep}`.replace(/\r?\n/g, ' '),
    )
  }
  return lines
}

/** The profile as a collapsed markdown section, for a pull-request comment. */
export function renderProfileMarkdown(report: ProfileReport): string {
  const rows = report.fields.map((field) => {
    const cells = [
      field.status === 'met' ? 'met' : MARK[field.status],
      field.requirement,
      `${field.title}<br><sub>${field.clause}</sub>`,
      field.status === 'met' ? field.detail : `${field.detail}<br><sub>${field.nextStep}</sub>`,
    ]
    return `| ${cells.join(' | ')} |`
  })

  return [
    '',
    `<details><summary><b>${report.profile.title} v${report.profile.version}</b> — ${summaryLine(report)}</summary>`,
    '',
    '| Status | | Data field | Detail |',
    '| :-- | :-- | :-- | :-- |',
    ...rows,
    '',
    `[${report.profile.title} v${report.profile.version}, ${report.profile.date}](${report.profile.url}).`,
    'This compares one SBOM against a list of data fields. It is not a conformity',
    'assessment, and it does not make anything compliant.',
    '',
    '</details>',
  ].join('\n')
}
