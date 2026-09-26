import {
  ARTICLE_14,
  type NotifyInput,
  type NotifyStage,
  PLACEHOLDER,
  stageDefinition,
} from './article14.js'

/**
 * Render one Article 14 stage as markdown.
 *
 * Markdown because the document is going to be read, edited and pasted into a
 * web form by a person under time pressure. A JSON payload would be the wrong
 * shape for that, and the ENISA platform's own schema is not something cradle
 * should pretend to know.
 *
 * The header is the most important part of the file. Somebody who receives this
 * document without context has to learn, before anything else, that it is a
 * draft, that cradle did not determine the reporting duty applies, and that
 * nothing was submitted.
 */
export function renderNotification(stage: NotifyStage, input: NotifyInput): string {
  const definition = stageDefinition(stage)
  const product = input.config.productName ?? input.project.name

  const lines: string[] = [
    `# ${definition.title} — ${definition.clause}`,
    '',
    `**Draft. Nothing has been submitted.**`,
    '',
    `| | |`,
    `| :-- | :-- |`,
    `| Stage | ${definition.title} (${definition.clause}) |`,
    `| Deadline | ${definition.deadline}, ${definition.clockStarts} |`,
    `| Route | ENISA single reporting platform **and** the coordinating CSIRT, simultaneously (Art. 14(1)) |`,
    `| Product | ${product} ${input.project.version} |`,
    `| Advisory | \`${input.finding.id}\` |`,
    `| Prepared | ${input.timestamp} |`,
    '',
    '> **cradle did not determine that this has to be reported.**',
    '> Article 14 concerns *actively exploited* vulnerabilities and severe incidents.',
    '> cradle knows that an advisory exists and that this project resolves the affected',
    '> version. It cannot know whether anyone is exploiting it, and no dependency scanner',
    '> can. Whether the reporting obligation applies is your determination, not this file’s.',
    '',
    `> Article 14 applies from **${ARTICLE_14.applies}**. This template is a technical aid,`,
    '> not legal advice and not a conformity assessment. Check it against',
    `> [${ARTICLE_14.regulation}](${ARTICLE_14.url}) and your own counsel before sending it.`,
    '',
    '---',
    '',
  ]

  for (const section of definition.sections) {
    lines.push(`## ${section.heading}`, '')
    if (section.note !== undefined) lines.push(`*${section.note}*`, '')
    lines.push(section.fill(input) ?? PLACEHOLDER(section.heading), '')
  }

  lines.push(
    '---',
    '',
    `Prepared by ${input.project.name} tooling from \`.cradle/findings.json\`. Every`,
    `**[TO BE COMPLETED]** above is a field cradle has no way to answer.`,
    '',
  )

  return lines.join('\n')
}

/** How many fields the reader still has to fill in. Reported, not hidden. */
export function countPlaceholders(markdown: string): number {
  return (markdown.match(/\*\*\[TO BE COMPLETED:/g) ?? []).length
}
