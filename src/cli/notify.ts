import { existsSync } from 'node:fs'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { CradleError } from '../core/errors.js'
import {
  ARTICLE_14,
  NOTIFY_STAGES,
  type NotifyStage,
  stageDefinition,
} from '../core/notify/article14.js'
import { countPlaceholders, renderNotification } from '../core/notify/render.js'
import type { Finding, FindingsDocument } from '../types/index.js'
import { readConfig } from './readiness.js'

export const NOTIFY_HELP = `cradle notify — draft an Article 14 report for one advisory

Usage:
  cradle notify <advisory-id> [path] --stage <stage>

Options:
  --stage <stage>       early-warning (24h), notification (72h) or final
                        (14 days after a measure is available)
  --output <file>       Write to this file instead of stdout
  --output-dir <dir>    Where .cradle files live (default: .cradle)
  -h, --help            Show this help

Reads the advisory out of .cradle/findings.json, so run \`cradle scan\` first.
Everything cradle cannot know is left as a clearly marked placeholder.

cradle does not decide that you have to report. Article 14 concerns actively
exploited vulnerabilities; whether that is the case is your determination. And
nothing is ever submitted — this writes a file.
`

export interface NotifyDependencies {
  now?: () => Date
}

export async function runNotify(
  argv: string[],
  stdout: NodeJS.WritableStream,
  dependencies: NotifyDependencies = {},
): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      stage: { type: 'string' },
      output: { type: 'string' },
      'output-dir': { type: 'string', default: '.cradle' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  if (values.help === true) {
    stdout.write(NOTIFY_HELP)
    return 0
  }

  const advisoryId = positionals[0]
  if (advisoryId === undefined || advisoryId === '') {
    throw new CradleError(
      'cradle notify needs an advisory id',
      'For example: cradle notify GHSA-xvch-5gv4-984h --stage early-warning',
    )
  }

  const stage = values.stage
  if (!isStage(stage)) {
    throw new CradleError(
      stage === undefined ? 'cradle notify needs --stage' : `Unknown --stage '${stage}'`,
      `Article 14 is three obligations, not one: ${NOTIFY_STAGES.join(', ')}. ` +
        'Which one you owe depends on how long ago you became aware.',
    )
  }

  const projectDir = resolve(positionals[1] ?? process.cwd())
  const outputDir = resolve(projectDir, values['output-dir'] ?? '.cradle')
  const now = (dependencies.now ?? (() => new Date()))()

  const document = await readFindings(outputDir)
  const finding = findAdvisory(document, advisoryId)
  const config = (await readConfig(outputDir)) ?? {}

  const markdown = renderNotification(stage, {
    finding,
    config,
    project: document.project,
    timestamp: now.toISOString(),
    packageManager: document.packageManager,
    ...(document.source === undefined ? {} : { source: document.source }),
  })

  const outstanding = countPlaceholders(markdown)

  if (values.output === undefined) {
    stdout.write(markdown)
    return 0
  }

  const target = resolve(projectDir, values.output)
  await mkdir(dirname(target), { recursive: true })
  await writeFile(target, markdown, 'utf8')

  const definition = stageDefinition(stage)
  stdout.write(
    `\n  Wrote ${values.output}\n` +
      `  ${definition.title} (${definition.clause}) — ${definition.deadline}, ${definition.clockStarts.replace(/\*\*/g, '')}\n` +
      `  ${outstanding} ${outstanding === 1 ? 'field needs' : 'fields need'} completing before this is worth sending.\n\n` +
      `  Nothing was submitted. Article 14 applies from ${ARTICLE_14.applies}, and whether it\n` +
      '  applies to this vulnerability is your determination, not cradle’s.\n\n',
  )
  return 0
}

function isStage(value: string | undefined): value is NotifyStage {
  return NOTIFY_STAGES.includes(value as NotifyStage)
}

/**
 * The advisory has to come from a scan rather than from the network.
 *
 * Under a 24-hour clock, the last thing anybody needs is this command failing
 * because OSV is slow. `findings.json` is already on disk, already carries the
 * route through the tree, and is the same data the report was built from — so a
 * notification cannot disagree with the report it accompanies.
 */
async function readFindings(outputDir: string): Promise<FindingsDocument> {
  const path = join(outputDir, 'findings.json')
  if (!existsSync(path)) {
    throw new CradleError(
      `No findings file at ${path}`,
      'Run `cradle scan` first. notify draws on the scan rather than the network, so that a ' +
        '24-hour clock never waits on an API.',
    )
  }
  try {
    return JSON.parse(await readFile(path, 'utf8')) as FindingsDocument
  } catch (cause) {
    throw new CradleError(`${path} is not valid JSON`, 'Re-run `cradle scan`.', { cause })
  }
}

/**
 * Match on the primary id or any alias, because people write down the CVE they
 * read about while cradle keys npm advisories on the GHSA (SPEC.md §6.3).
 *
 * Suppressed findings are searched too. A VEX statement saying "not affected"
 * and an actively exploited vulnerability are not mutually exclusive: the
 * statement may simply be wrong, and finding out is exactly when this command
 * gets used.
 */
function findAdvisory(document: FindingsDocument, advisoryId: string): Finding {
  const wanted = advisoryId.toUpperCase()
  const all = [...document.findings, ...document.suppressed]
  const match = all.find(
    (finding) =>
      finding.id.toUpperCase() === wanted ||
      finding.aliases.some((alias) => alias.toUpperCase() === wanted),
  )
  if (match !== undefined) return match

  const known = [...new Set(all.map((finding) => finding.id))]
  throw new CradleError(
    `No finding for '${advisoryId}' in this scan`,
    known.length === 0
      ? 'This scan found nothing. If the advisory is real but newer than the scan, re-run `cradle scan`.'
      : `This scan has: ${known.slice(0, 8).join(', ')}${known.length > 8 ? `, +${known.length - 8} more` : ''}.`,
  )
}
