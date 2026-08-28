import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { existsSync } from 'node:fs'
import { readFile, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { CradleError } from '../core/errors.js'
import {
  emptyDocument,
  isJustification,
  parseDocument,
  serializeDocument,
  upsertStatement,
} from '../core/vex/document.js'
import {
  type Finding,
  type FindingsDocument,
  VEX_JUSTIFICATION_TEXT,
  VEX_JUSTIFICATIONS,
  type VexJustification,
  type VexStatement,
} from '../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../version.generated.js'

export const SUPPRESS_HELP = `cradle suppress — record why a finding does not apply

Usage:
  cradle suppress <advisory-id> [path] [options]

The advisory ID may be the one cradle reports (GHSA-...) or any alias it
carries (CVE-...).

Options:
  --justification <j>  Why it does not apply. Required. One of:
${VEX_JUSTIFICATIONS.map((j) => `                         ${j}\n                           ${VEX_JUSTIFICATION_TEXT[j]}`).join('\n')}
  --component <purl>   Which component the statement covers. Required when more
                       than one component is affected.
  --note "..."         Free text alongside the category. Recommended: the
                       category is what makes this auditable, the note is what
                       makes it understandable a year from now.
  --expires <date>     ISO date after which the suppression stops applying,
                       e.g. 2027-03-31. Not an OpenVEX field; see SPEC.md.
  --author <who>       Who is making this statement. Defaults to your git
                       user.email.
  --output-dir <dir>   Where .cradle files live (default: .cradle)
  -h, --help           Show this help
`

export interface SuppressDependencies {
  now?: () => Date
  uuid?: () => string
  /** Injected so tests do not depend on the machine's git configuration. */
  defaultAuthor?: () => string | undefined
}

export async function runSuppress(
  argv: string[],
  stdout: NodeJS.WritableStream,
  dependencies: SuppressDependencies = {},
): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      justification: { type: 'string' },
      component: { type: 'string' },
      note: { type: 'string' },
      expires: { type: 'string' },
      author: { type: 'string' },
      'output-dir': { type: 'string', default: '.cradle' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  if (values.help === true || positionals.length === 0) {
    stdout.write(SUPPRESS_HELP)
    return values.help === true ? 0 : 2
  }

  const advisoryId = positionals[0] ?? ''
  const projectDir = resolve(positionals[1] ?? process.cwd())
  const outputDir = resolve(projectDir, values['output-dir'] ?? '.cradle')
  const now = (dependencies.now ?? (() => new Date()))()
  const timestamp = now.toISOString()

  const justification = values.justification
  if (justification === undefined) {
    throw new CradleError(
      'No --justification given',
      'A suppression has to say which category it falls under. That requirement is ' +
        'deliberate: it is what turns a suppression into something an auditor can ' +
        `review. Pick one of: ${VEX_JUSTIFICATIONS.join(', ')}.`,
    )
  }
  if (!isJustification(justification)) {
    throw new CradleError(
      `'${justification}' is not an OpenVEX justification`,
      `Use one of the five the standard defines: ${VEX_JUSTIFICATIONS.join(', ')}.`,
    )
  }

  if (values.expires !== undefined && Number.isNaN(Date.parse(values.expires))) {
    throw new CradleError(
      `Could not read --expires ${JSON.stringify(values.expires)} as a date`,
      'Use an ISO date, for example 2027-03-31.',
    )
  }

  const findings = await loadFindings(outputDir)
  const matching = findings.filter(
    (finding) =>
      finding.id.toUpperCase() === advisoryId.toUpperCase() ||
      finding.aliases.some((alias) => alias.toUpperCase() === advisoryId.toUpperCase()),
  )
  if (matching.length === 0) {
    throw new CradleError(
      `No finding with the ID '${advisoryId}' in ${join(outputDir, 'findings.json')}`,
      'Run `cradle scan` first, and check the ID against the report. Both the ' +
        'GHSA and the CVE identifier work.',
    )
  }

  const component = chooseComponent(matching, values.component, advisoryId)
  const affected = matching.filter((finding) => finding.component.purl === component.purl)
  const first = affected[0] ?? matching[0]
  if (first === undefined) throw new CradleError('No finding to suppress', 'This is a bug.')

  const statement = buildStatement({
    finding: first,
    componentPurl: component.purl,
    justification,
    timestamp,
    id: `urn:uuid:${(dependencies.uuid ?? randomUUID)()}`,
    ...(values.note === undefined ? {} : { note: values.note }),
    ...(values.expires === undefined ? {} : { expires: values.expires }),
  })

  const author = values.author ?? (dependencies.defaultAuthor ?? gitAuthor)() ?? undefined
  if (author === undefined || author === '') {
    throw new CradleError(
      'Could not work out who is making this statement',
      'OpenVEX requires an author, and an unattributed suppression is worth little ' +
        'in an audit. Pass --author "you@example.com", or set git user.email.',
    )
  }

  const path = join(outputDir, 'vex.json')
  const existing = existsSync(path)
    ? parseDocument(await readFile(path, 'utf8'), path)
    : emptyDocument({
        id: `urn:uuid:${(dependencies.uuid ?? randomUUID)()}`,
        author,
        timestamp,
        tooling: `${TOOL_NAME}/${TOOL_VERSION}`,
      })

  const { document, replaced } = upsertStatement(existing, statement, timestamp)
  await writeFile(path, serializeDocument(document), 'utf8')

  stdout.write(
    summarize({ path, statement, replaced, component, count: affected.length, projectDir }),
  )
  return 0
}

async function loadFindings(outputDir: string): Promise<Finding[]> {
  const path = join(outputDir, 'findings.json')
  if (!existsSync(path)) {
    throw new CradleError(
      `No findings to suppress: ${path} does not exist`,
      'Run `cradle scan` first. Suppressions are recorded against findings cradle ' +
        'has actually seen, so a typo in an ID fails here rather than silently ' +
        'doing nothing.',
    )
  }

  let document: FindingsDocument
  try {
    document = JSON.parse(await readFile(path, 'utf8')) as FindingsDocument
  } catch (cause) {
    throw new CradleError(`${path} is not valid JSON`, 'Re-run `cradle scan` to rewrite it.', {
      cause,
    })
  }
  // A suppressed finding is still a legitimate target: re-running suppress is how
  // you correct a justification or extend an expiry.
  return [...(document.findings ?? []), ...(document.suppressed ?? [])]
}

interface ChosenComponent {
  purl: string
  name: string
  version: string
}

/**
 * Work out which component the statement covers.
 *
 * When several are affected, the component has to be named. Suppressing by
 * advisory ID alone would silence the vulnerability everywhere it occurs, which
 * is exactly the blanket dismissal VEX exists to prevent.
 */
function chooseComponent(
  matching: readonly Finding[],
  requested: string | undefined,
  advisoryId: string,
): ChosenComponent {
  const components = new Map<string, ChosenComponent>()
  for (const finding of matching) {
    components.set(finding.component.purl, {
      purl: finding.component.purl,
      name: finding.component.name,
      version: finding.component.version,
    })
  }

  if (requested !== undefined) {
    const chosen = components.get(requested)
    if (chosen === undefined) {
      throw new CradleError(
        `${advisoryId} does not affect ${requested}`,
        `It affects: ${[...components.keys()].join(', ')}.`,
      )
    }
    return chosen
  }

  const only = [...components.values()]
  if (only.length === 1 && only[0] !== undefined) return only[0]

  throw new CradleError(
    `${advisoryId} affects ${only.length} components, so --component is required`,
    'Suppressing by advisory ID alone would silence it everywhere it occurs. ' +
      `Pick one of: ${only.map((c) => c.purl).join(', ')}.`,
  )
}

function buildStatement(input: {
  finding: Finding
  componentPurl: string
  justification: VexJustification
  timestamp: string
  id: string
  note?: string
  expires?: string
}): VexStatement {
  const statement: VexStatement = {
    '@id': input.id,
    vulnerability: { name: input.finding.id },
    timestamp: input.timestamp,
    products: [{ '@id': input.componentPurl }],
    status: 'not_affected',
    justification: input.justification,
  }

  if (input.finding.aliases.length > 0) statement.vulnerability.aliases = input.finding.aliases
  if (input.finding.summary !== '') statement.vulnerability.description = input.finding.summary
  if (input.note !== undefined && input.note !== '') statement.status_notes = input.note
  if (input.expires !== undefined) statement['cradle:expires'] = input.expires

  return statement
}

function summarize(input: {
  path: string
  statement: VexStatement
  replaced: boolean
  component: ChosenComponent
  count: number
  projectDir: string
}): string {
  const relative = input.path.startsWith(input.projectDir)
    ? input.path.slice(input.projectDir.length + 1)
    : input.path
  const justification = input.statement.justification

  const lines = [
    '',
    `  ${input.replaced ? 'Updated' : 'Recorded'} in ${relative}`,
    '',
    `    ${input.statement.vulnerability.name}  ${input.component.name} ${input.component.version}`,
    `    not_affected — ${justification ?? ''}`,
  ]
  if (justification !== undefined) {
    lines.push(`    ${VEX_JUSTIFICATION_TEXT[justification]}`)
  }
  if (input.statement.status_notes !== undefined) {
    lines.push(`    Note: ${input.statement.status_notes}`)
  }
  if (input.statement['cradle:expires'] !== undefined) {
    lines.push(`    Expires ${input.statement['cradle:expires']}, after which it applies again.`)
  }

  lines.push('')
  lines.push('  Commit this file. It is the record of a decision, and it is what keeps')
  lines.push('  the next scan from asking the same question again.')
  lines.push('')
  return lines.join('\n')
}

/** Whoever git thinks is working here. Best available answer, and no network. */
function gitAuthor(): string | undefined {
  try {
    const email = execFileSync('git', ['config', '--get', 'user.email'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    return email === '' ? undefined : email
  } catch {
    return undefined
  }
}
