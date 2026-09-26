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
import { BSI_TR_03183_2, checkBsiProfile } from '../core/readiness/profiles/bsi-tr-03183.js'
import { buildBom } from '../core/sbom/cyclonedx.js'
import { atOrAbove, severityRank } from '../core/vulns/severity.js'
import { buildPullRequestComment } from '../report/markdown.js'
import {
  renderProfileAnnotations,
  renderProfileMarkdown,
  renderProfileText,
} from '../report/profile.js'
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
import { creatorFrom, readConfig } from './readiness.js'
import { workspaceTarget } from './workspace-target.js'

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
  --workspace <name>    Gate one workspace package instead of the repository.
                        Its baseline lives in that package's own .cradle/
  --profile <name>      Also check the SBOM field by field against a published
                        profile. Currently: bsi-tr-03183 (BSI TR-03183-2 v2.1.0)
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
      workspace: { type: 'string' },
      profile: { type: 'string' },
      'output-dir': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  if (values.help === true) {
    stdout.write(CHECK_HELP)
    return 0
  }

  const profile = values.profile
  if (profile !== undefined && profile !== BSI_TR_03183_2.id) {
    throw new CradleError(
      `Unknown --profile '${profile}'`,
      `The only profile cradle ships is ${BSI_TR_03183_2.id} (BSI TR-03183-2 v${BSI_TR_03183_2.version}).`,
    )
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
  const outputOverride = values['output-dir']
  const rootOutputDir = resolve(projectDir, outputOverride ?? '.cradle')
  const now = (dependencies.now ?? (() => new Date()))()

  // Deliberately one package, never `all`. A gate produces one exit code and, in
  // markdown, one pull-request comment; neither can honestly represent several
  // packages at once. A monorepo runs one check job per package, which is also
  // what makes the annotations and the baseline land in the right place.
  const workspace = values.workspace
  if (workspace === 'all') {
    throw new CradleError(
      '--workspace all is not available for `cradle check`',
      'A gate has one exit code and one comment, and neither can speak for several ' +
        'packages. Run one check per package: cradle check --workspace <name>. ' +
        '`cradle scan --workspace all` does write a report for each.',
    )
  }

  const repo = await runPipeline({
    projectDir,
    outputDir: rootOutputDir,
    includeDev: values['include-dev'] === true,
    offline: values.offline === true,
    useCache: values['no-cache'] !== true,
    now,
    ...(dependencies.fetch === undefined ? {} : { fetch: dependencies.fetch }),
    ...(dependencies.cache === undefined ? {} : { cache: dependencies.cache }),
  })

  // Sliced from the repository-wide run, never resolved separately: a gate and a
  // report about the same package must not disagree about a version.
  const target =
    workspace === undefined
      ? {
          graph: repo.graph,
          findings: repo.findings,
          suppressed: repo.suppressed,
          outputDir: rootOutputDir,
        }
      : await workspaceTarget({
          repo: repo.graph,
          name: workspace,
          projectDir,
          rootOutputDir,
          outputOverride,
          osvByPackage: repo.osvByPackage,
          offline: values.offline === true,
          now,
        })

  const result = { ...repo, ...target }
  const outputDir = target.outputDir
  const config = await readConfig(rootOutputDir)
  const creator = creatorFrom(config)
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

  // The profile is a description of the SBOM, not a gate: it never changes the
  // exit code. A field the guideline requires and cradle cannot know would
  // otherwise make the build red forever, and the build would get switched off.
  const profileReport =
    profile === undefined
      ? undefined
      : checkBsiProfile({
          bom: buildBom(result.graph, {
            specVersion: '1.6',
            timestamp: now.toISOString(),
            serialNumber: `urn:uuid:${'0'.repeat(8)}-0000-4000-8000-${'0'.repeat(12)}`,
            ...(creator === undefined ? {} : { creator }),
          }),
          config: config ?? {},
          offline: values.offline === true,
        })

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
    if (profileReport !== undefined) {
      for (const annotation of renderProfileAnnotations(profileReport)) {
        stdout.write(`${annotation}\n`)
      }
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
    if (profileReport !== undefined) stdout.write(`${renderProfileMarkdown(profileReport)}\n`)
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
  if (profileReport !== undefined) stdout.write(renderProfileText(profileReport))

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
