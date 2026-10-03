import type { CradleConfig, Finding } from '../../types/index.js'

/**
 * Article 14 reporting templates.
 *
 * Article 14 of Regulation (EU) 2024/2847 applies from **11 September 2026** and
 * is three obligations, not one. For an actively exploited vulnerability, Art.
 * 14(2):
 *
 * - **(a) early warning** — without undue delay, in any event within **24 hours**
 *   of the manufacturer becoming aware of it.
 * - **(b) vulnerability notification** — within **72 hours** of becoming aware.
 * - **(c) final report** — no later than **14 days after a corrective or
 *   mitigating measure is available**. Note the clock: it starts at availability
 *   of the measure, not at awareness. Getting that wrong in either direction is
 *   the sort of mistake a template should not help anyone make.
 *
 * The route is the ENISA single reporting platform **and** the coordinating
 * CSIRT, simultaneously — Art. 14(1).
 *
 * ## What this is not
 *
 * **It does not decide that you have to report.** Art. 14 is about *actively
 * exploited* vulnerabilities and severe incidents. cradle knows that an advisory
 * exists and that your lockfile contains the affected version. It does not know
 * whether anyone is exploiting it, and no dependency scanner can. That
 * determination is the manufacturer's, and the template says so at the top
 * rather than in a footnote.
 *
 * **It does not submit anything.** It writes a file. Submission is a deliberate
 * act by a person who has read it, and a tool that posted to a regulator on a
 * timer would be the worst feature in this codebase.
 *
 * **It is not legal advice.** The same disclaimer that governs the rest of
 * cradle governs this more strongly, because the output looks like a form.
 */
export const ARTICLE_14 = {
  regulation: 'Regulation (EU) 2024/2847',
  applies: '2026-09-11',
  url: 'https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng',
} as const

export type NotifyStage = 'early-warning' | 'notification' | 'final'

export const NOTIFY_STAGES: readonly NotifyStage[] = ['early-warning', 'notification', 'final']

interface StageDefinition {
  stage: NotifyStage
  clause: string
  title: string
  /** The deadline, in the regulation's own terms rather than as a number. */
  deadline: string
  /** What starts the clock, which is not the same for all three. */
  clockStarts: string
  /**
   * The content the paragraph asks for. Each entry becomes a section of the
   * document; `fill` returns what cradle can answer, or undefined where only the
   * manufacturer can.
   */
  sections: {
    heading: string
    /** Why the regulation asks for this, in one line. */
    note?: string
    fill: (input: NotifyInput) => string | undefined
  }[]
}

export interface NotifyInput {
  finding: Finding
  config: CradleConfig
  /** Project name and version, where config does not name the product. */
  project: { name: string; version: string }
  /** ISO 8601, for the document's own date. */
  timestamp: string
  packageManager: string
  /** Set when the graph came from a supplied SBOM rather than a lockfile. */
  source?: { kind: 'sbom'; path: string }
}

/** Marks a field only the manufacturer can answer. Deliberately hard to miss. */
export const PLACEHOLDER = (what: string): string => `**[TO BE COMPLETED: ${what}]**`

const STAGES: readonly StageDefinition[] = [
  {
    stage: 'early-warning',
    clause: 'Art. 14(2)(a)',
    title: 'Early warning',
    deadline: 'within 24 hours',
    clockStarts: 'from becoming aware of the actively exploited vulnerability',
    sections: [
      {
        heading: 'Manufacturer',
        fill: (input) => manufacturer(input),
      },
      {
        heading: 'Product with digital elements concerned',
        fill: (input) => product(input),
      },
      {
        heading: 'Indication of an actively exploited vulnerability',
        note: 'The early warning is deliberately minimal: an indication, not an analysis.',
        fill: (input) =>
          `The vulnerability tracked as \`${input.finding.id}\`${aliasList(input.finding)} affects ` +
          `\`${input.finding.component.name}\` ${input.finding.component.version}, a component of ` +
          `this product.\n\n` +
          `${PLACEHOLDER('confirm that this vulnerability is being actively exploited, and on what basis')}`,
      },
      {
        heading: 'Member States in which the product is made available',
        note: 'Asked for at this stage so that the relevant CSIRTs can be involved early.',
        fill: () =>
          PLACEHOLDER('list the Member States where this product is placed on the market'),
      },
    ],
  },
  {
    stage: 'notification',
    clause: 'Art. 14(2)(b)',
    title: 'Vulnerability notification',
    deadline: 'within 72 hours',
    clockStarts: 'from becoming aware of the actively exploited vulnerability',
    sections: [
      { heading: 'Manufacturer', fill: (input) => manufacturer(input) },
      {
        heading: 'General information about the product with digital elements',
        fill: (input) => product(input),
      },
      {
        heading: 'General nature of the exploit and of the vulnerability concerned',
        fill: (input) => vulnerabilityDetail(input),
      },
      {
        heading: 'Corrective or mitigating measures taken',
        fill: (input) =>
          input.finding.fixedIn === undefined
            ? `The advisory names no fixed version for \`${input.finding.component.name}\`.\n\n` +
              PLACEHOLDER('describe the corrective or mitigating measures you have taken')
            : `A fixed version of \`${input.finding.component.name}\` is available: **${input.finding.fixedIn}**. ` +
              `The affected version in this product is ${input.finding.component.version}.\n\n` +
              PLACEHOLDER('state whether the update has been applied and released, and when'),
      },
      {
        heading: 'Corrective or mitigating measures users can take',
        note: 'A separate question from what you did: it is what the user is asked to do.',
        fill: () =>
          PLACEHOLDER('describe what users of the product should do, and how they were told'),
      },
    ],
  },
  {
    stage: 'final',
    clause: 'Art. 14(2)(c)',
    title: 'Final report',
    deadline: 'no later than 14 days',
    clockStarts:
      'from a corrective or mitigating measure becoming available — **not** from becoming aware',
    sections: [
      { heading: 'Manufacturer', fill: (input) => manufacturer(input) },
      {
        heading: 'Product with digital elements',
        fill: (input) => product(input),
      },
      {
        heading: 'Description of the vulnerability',
        fill: (input) => vulnerabilityDetail(input),
      },
      {
        heading: 'Malicious actors, where that information is available',
        note: 'Nothing in a dependency scan can answer this.',
        fill: () =>
          PLACEHOLDER(
            'describe any information about the actors exploiting the vulnerability, or state that none is available',
          ),
      },
      {
        heading: 'Security update or other corrective measure',
        fill: (input) =>
          input.finding.fixedIn === undefined
            ? PLACEHOLDER(
                'describe the security update or corrective measure, its version, and when it was made available',
              )
            : `The upstream fix is \`${input.finding.component.name}\` **${input.finding.fixedIn}**.\n\n` +
              PLACEHOLDER(
                'state the version of **your** product that carries the fix, and the date it was made available to users',
              ),
      },
    ],
  },
]

export function stageDefinition(stage: NotifyStage): StageDefinition {
  const found = STAGES.find((candidate) => candidate.stage === stage)
  // The type makes this unreachable; the throw is so a future stage cannot be
  // added to the union and silently produce an empty document.
  if (found === undefined) throw new Error(`No Article 14 stage definition for '${stage}'`)
  return found
}

// ---------------------------------------------------------------------------
// Shared sections
// ---------------------------------------------------------------------------

function manufacturer(input: NotifyInput): string {
  const lines: string[] = []
  lines.push(
    input.config.productName === undefined
      ? PLACEHOLDER('name of the manufacturer')
      : `Manufacturer: ${input.config.productName}`,
  )
  lines.push(
    input.config.contactEmail === undefined
      ? PLACEHOLDER('contact point for this report')
      : `Contact: ${input.config.contactEmail}`,
  )
  return lines.join('\n\n')
}

function product(input: NotifyInput): string {
  const name = input.config.productName ?? input.project.name
  return (
    `Product: **${name}**, version ${input.project.version}.\n\n` +
    `The affected component is \`${input.finding.component.name}\` ` +
    `${input.finding.component.version}, reached as \`${input.finding.path.join(' › ')}\` ` +
    `${
      input.source === undefined
        ? `(resolved from the ${input.packageManager} lockfile).`
        : '(read from the supplied software bill of materials, not resolved from a lockfile).'
    }`
  )
}

function vulnerabilityDetail(input: NotifyInput): string {
  const { finding } = input
  const lines = [
    `Advisory: \`${finding.id}\`${aliasList(finding)}`,
    '',
    finding.summary === '' ? PLACEHOLDER('description of the vulnerability') : finding.summary,
    '',
    `Severity as recorded by cradle: **${finding.severity}**` +
      (finding.cvss === undefined
        ? ' (as rated by the advisory database; no scoreable CVSS vector was published).'
        : `, from CVSS v${finding.cvss.version} base score ${finding.cvss.score} \`${finding.cvss.vector}\`.`),
    '',
    // The distinction the whole report rests on.
    'A CVSS base score rates the vulnerability in the abstract. It says nothing about ' +
      'exploitability in this product, which is what Article 14 is about.',
    '',
    `Source: ${finding.osvUrl}`,
    '',
    PLACEHOLDER('describe the nature of the exploit as it affects this product'),
  ]
  return lines.join('\n')
}

function aliasList(finding: Finding): string {
  return finding.aliases.length === 0 ? '' : ` (also ${finding.aliases.join(', ')})`
}
