import { existsSync } from 'node:fs'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import {
  diffAgainstBaseline,
  parseBaseline,
  serializeBaseline,
  toBaseline,
} from '../core/baseline/diff.js'
import { CradleError } from '../core/errors.js'
import { atOrAbove, severityRank } from '../core/vulns/severity.js'
import { buildPullRequestComment } from '../report/markdown.js'
import {
  type BaselineDiff,
  type BaselineDocument,
  type Finding,
  SEVERITY_ORDER,
  type Severity,
} from '../types/index.js'
import { TOOL_NAME, TOOL_VERSION } from '../version.generated.js'
import { toAnnotations } from './github.js'
import { type PipelineOptions, runPipeline } from './pipeline.js'

export const CHECK_HELP = `cradle check — fail CI on findings that are new since the baseline

Usage:
  cradle check [path] [options]

Options:
  --fail-on <severity>  Fail at or above this severity (default: high).
                        One of: ${SEVERITY_ORDER.join(', ')}, never
  --baseline            Accept the current findings and write them as the new
                        baseline. Exits 0.
  --no-baseline         Ignore the baseline and judge every finding as new
  --format <style>      text (default), github for workflow-command
                        annotations, or markdown for a pull-request comment
  --artifact-name <n>   Named in the markdown output as where the full report
                        was uploaded
  --include-dev         Include development dependencies
  --no-cache            Do not read or write the local advisory cache
  --output-dir <dir>    Where .cradle files live (default: .cradle)
  -h, --help            Show this help

Exit codes:
  0  nothing new above the threshold
  1  new findings above the threshold
  2  cradle could not run

The difference between 1 and 2 matters: a broken tool must never read as a
security result.
`

export interface CheckDependencies {
  fetch?: PipelineOptions['fetch']
  cache?: PipelineOptions['cache']
  now?: () => Date
}

export async function runCheck(
  argv: string[],
  stdout: NodeJS.WritableStream,
  dependencies: CheckDependencies = {},
): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      'fail-on': { type: 'string', default: 'high' },
      // --baseline and --no-baseline are not opposites here: one writes the
      // baseline, the other ignores it. They are declared as two literal
      // options because node's parseArgs has no --no- prefix support anyway.
      baseline: { type: 'boolean', default: false },
      'no-baseline': { type: 'boolean', default: false },
      format: { type: 'string', default: 'text' },
      'include-dev': { type: 'boolean', default: false },
      'no-cache': { type: 'boolean', default: false },
      'artifact-name': { type: 'string' },
      offline: { type: 'boolean', default: false },
      'output-dir': { type: 'string', default: '.cradle' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  if (values.help === true) {
    stdout.write(CHECK_HELP)
    return 0
  }

  const threshold = parseThreshold(values['fail-on'])
  const format = values.format ?? 'text'
  if (format !== 'text' && format !== 'github' && format !== 'markdown') {
    throw new CradleError(
      `Unknown --format '${format}'`,
      'Use --format text (the default), github for workflow annotations, or markdown for a ' +
        'pull-request comment.',
    )
  }

  const projectDir = resolve(positionals[0] ?? process.cwd())
  const outputDir = resolve(projectDir, values['output-dir'] ?? '.cradle')
  const now = (dependencies.now ?? (() => new Date()))()

  const result = await runPipeline({
    projectDir,
    outputDir,
    includeDev: values['include-dev'] === true,
    offline: values.offline === true,
    useCache: values['no-cache'] !== true,
    now,
    ...(dependencies.fetch === undefined ? {} : { fetch: dependencies.fetch }),
    ...(dependencies.cache === undefined ? {} : { cache: dependencies.cache }),
  })

  const baselinePath = join(outputDir, 'baseline.json')

  // `--baseline` accepts what is there today and says nothing about pass or
  // fail; that is the whole point of adopting a backlog.
  if (values.baseline === true) {
    const document = toBaseline(result.findings, {
      schemaVersion: 1,
      timestamp: now.toISOString(),
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      project: { name: result.graph.root.name, version: result.graph.root.version },
      scope: result.graph.includeDev ? 'all' : 'production',
    })
    await mkdir(outputDir, { recursive: true })
    await writeFile(baselinePath, serializeBaseline(document), 'utf8')

    stdout.write(
      `\n  Wrote ${relative(baselinePath, projectDir)} with ${document.entries.length} accepted ` +
        `${document.entries.length === 1 ? 'finding' : 'findings'}.\n` +
        '  Commit it. From here on, cradle check only reports what is new.\n\n',
    )
    return 0
  }

  const baseline = values['no-baseline'] === true ? undefined : await loadBaseline(baselinePath)
  const diff = diffAgainstBaseline(result.findings, baseline)
  // "never" reports everything and fails on nothing, for teams adopting the gate
  // gradually.
  const failing =
    threshold === 'never'
      ? []
      : diff.added.filter((finding) => atOrAbove(finding.severity, threshold))

  if (format === 'github') {
    const manifest = await readManifest(projectDir)
    for (const annotation of toAnnotations(failing, {
      ...(manifest === undefined ? {} : { manifest, manifestPath: 'package.json' }),
    })) {
      stdout.write(`${annotation}\n`)
    }
  }

  // Markdown is the whole output, not an addition to it: the action pipes this
  // straight into a pull-request comment.
  if (format === 'markdown') {
    stdout.write(
      `${buildPullRequestComment({
        project: { name: result.graph.root.name, version: result.graph.root.version },
        packageManager: result.graph.packageManager,
        scope: result.graph.includeDev ? 'all' : 'production',
        componentCount: result.graph.components.length,
        diff,
        suppressed: result.suppressed.length,
        failing,
        threshold,
        hasBaseline: baseline !== undefined,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        ...(values['artifact-name'] === undefined ? {} : { artifactName: values['artifact-name'] }),
      })}\n`,
    )
    return failing.length > 0 ? 1 : 0
  }

  stdout.write(
    summarize({
      diff,
      failing,
      threshold,
      baseline,
      baselinePath,
      projectDir,
      suppressed: result.suppressed.length,
      offline: result.findings.length === 0 && values.offline === true,
      project: `${result.graph.root.name} ${result.graph.root.version}`,
      scope: result.graph.includeDev ? 'all dependencies' : 'production only',
    }),
  )

  return failing.length > 0 ? 1 : 0
}

function parseThreshold(value: string | undefined): Severity | 'never' {
  if (value === 'never') return 'never'
  if (value !== undefined && (SEVERITY_ORDER as readonly string[]).includes(value)) {
    return value as Severity
  }
  throw new CradleError(
    `Unknown --fail-on '${value}'`,
    `Use one of: ${SEVERITY_ORDER.join(', ')}, or "never" to report without failing.`,
  )
}

async function loadBaseline(path: string): Promise<BaselineDocument | undefined> {
  if (!existsSync(path)) return undefined
  return parseBaseline(await readFile(path, 'utf8'), path)
}

async function readManifest(projectDir: string): Promise<string | undefined> {
  try {
    return await readFile(join(projectDir, 'package.json'), 'utf8')
  } catch {
    return undefined
  }
}

function relative(path: string, projectDir: string): string {
  return path.startsWith(projectDir) ? path.slice(projectDir.length + 1) : path
}

interface SummaryInput {
  diff: BaselineDiff
  failing: Finding[]
  threshold: Severity | 'never'
  baseline: BaselineDocument | undefined
  baselinePath: string
  projectDir: string
  suppressed: number
  offline: boolean
  project: string
  scope: string
}

function summarize(input: SummaryInput): string {
  const { diff } = input
  const total = diff.added.length + diff.known.length

  const lines = ['', `cradle ${TOOL_VERSION} · ${input.project} · ${input.scope}`, '']

  if (input.baseline === undefined) {
    lines.push('  Baseline     none — every finding counts as new')
  } else {
    lines.push(
      `  Baseline     ${relative(input.baselinePath, input.projectDir)} · ` +
        `${input.baseline.entries.length} accepted`,
    )
  }
  lines.push(`  Findings     ${total}`)
  if (input.suppressed > 0) lines.push(`  Suppressed   ${input.suppressed} by VEX statements`)
  lines.push(
    `  New          ${diff.added.length}` +
      (input.threshold === 'never'
        ? ''
        : `, ${input.failing.length} at or above ${input.threshold}`),
  )
  lines.push('')

  if (diff.added.length > 0) {
    lines.push('  New since the baseline')
    for (const finding of [...diff.added].sort(
      (a, b) => severityRank(a.severity) - severityRank(b.severity),
    )) {
      const fix = finding.fixedIn === undefined ? 'no fix yet' : `fix in ${finding.fixedIn}`
      const worse = diff.worsened.includes(finding) ? ', re-rated worse since accepted' : ''
      lines.push(
        `    ${finding.severity.padEnd(8)} ${finding.id}  ${finding.component.name} ` +
          `${finding.component.version}  (${fix}${worse})`,
      )
      if (!finding.component.direct) lines.push(`             ${finding.path.join(' > ')}`)
    }
    lines.push('')
  }

  if (diff.resolved.length > 0) {
    const label = diff.resolved.length === 1 ? 'finding is' : 'findings are'
    lines.push(
      `  ${diff.resolved.length} baselined ${label} gone. Re-run with --baseline to tidy up.`,
    )
    lines.push('')
  }

  if (input.failing.length > 0) {
    lines.push(
      `  Failing: ${input.failing.length} new ${input.failing.length === 1 ? 'finding' : 'findings'} ` +
        `at or above ${input.threshold}.`,
    )
  } else if (diff.added.length > 0) {
    lines.push(
      `  Passing: nothing new reaches ${input.threshold === 'never' ? 'the threshold' : input.threshold}.`,
    )
  } else {
    lines.push('  Passing: nothing new since the baseline.')
  }
  lines.push('')

  return lines.join('\n')
}
