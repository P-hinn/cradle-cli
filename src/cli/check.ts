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
import {
  describeReasons,
  describeThresholds,
  failingFindings,
  type GateFailure,
  type GateThresholds,
  gateIsOff,
} from '../core/vulns/gate.js'
import { byExploitPriority } from '../core/vulns/priority.js'
import { severityRank } from '../core/vulns/severity.js'
import { isLanguage, LANGUAGES } from '../report/i18n/index.js'
import { buildPullRequestComment } from '../report/markdown.js'
import {
  renderProfileAnnotations,
  renderProfileMarkdown,
  renderProfileText,
} from '../report/profile.js'
import { buildSarif } from '../report/sarif.js'
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
  --fail-on-kev         Also fail on anything CISA records as being exploited,
                        whatever its severity. Article 14's 24-hour clock starts
                        on active exploitation, not on a CVSS score
  --fail-on-epss <0-1>  Also fail at or above this EPSS probability, e.g. 0.5
  --baseline            Accept the current findings and write them as the new
                        baseline. Exits 0.
  --no-baseline         Ignore the baseline and judge every finding as new
  --format <style>      text (default), github for workflow-command
                        annotations, markdown for a pull-request comment, or
                        sarif for GitHub Code Scanning and GitLab
  --artifact-name <n>   Named in the markdown output as where the full report
                        was uploaded
  --include-dev         Include development dependencies
  --no-cache            Do not read or write the local advisory cache
  --no-priority         Skip the EPSS and CISA KEV lookup
  --sort <order>        severity (default) or exploit, which puts what CISA
                        knows is being exploited first, then EPSS, then severity
  --workspace <name>    Gate one workspace package instead of the repository.
                        Its baseline lives in that package's own .cradle/
  --lang <en|de>        Language of the markdown comment (default: en)
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
      // Additive to --fail-on, not alternatives to it: a finding fails on any
      // threshold it crosses. `--fail-on never --fail-on-kev` is the gate that
      // only reacts to active exploitation.
      'fail-on-kev': { type: 'boolean', default: false },
      'fail-on-epss': { type: 'string' },
      // --baseline and --no-baseline are not opposites here: one writes the
      // baseline, the other ignores it. They are declared as two literal
      // options because node's parseArgs has no --no- prefix support anyway.
      baseline: { type: 'boolean', default: false },
      'no-baseline': { type: 'boolean', default: false },
      format: { type: 'string', default: 'text' },
      'include-dev': { type: 'boolean', default: false },
      'no-cache': { type: 'boolean', default: false },
      'no-priority': { type: 'boolean', default: false },
      sort: { type: 'string', default: 'severity' },
      'artifact-name': { type: 'string' },
      offline: { type: 'boolean', default: false },
      workspace: { type: 'string' },
      profile: { type: 'string' },
      lang: { type: 'string', default: 'en' },
      'output-dir': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  if (values.help === true) {
    stdout.write(CHECK_HELP)
    return 0
  }

  const lang = values.lang
  if (!isLanguage(lang)) {
    throw new CradleError(
      `Unknown --lang '${lang}'`,
      `cradle writes its output in: ${LANGUAGES.join(', ')}.`,
    )
  }

  const profile = values.profile
  if (profile !== undefined && profile !== BSI_TR_03183_2.id) {
    throw new CradleError(
      `Unknown --profile '${profile}'`,
      `The only profile cradle ships is ${BSI_TR_03183_2.id} (BSI TR-03183-2 v${BSI_TR_03183_2.version}).`,
    )
  }

  const sort = values.sort
  if (sort !== 'severity' && sort !== 'exploit') {
    throw new CradleError(
      `Unknown --sort '${sort}'`,
      'Use severity (the default) or exploit. The sort order changes what you look at first; ' +
        'it never changes the exit code, which stays CVSS-based.',
    )
  }

  const thresholds: GateThresholds = {
    severity: parseThreshold(values['fail-on']),
    kev: values['fail-on-kev'] === true,
    ...(values['fail-on-epss'] === undefined ? {} : { epss: parseEpss(values['fail-on-epss']) }),
  }

  // Gating on a signal the run is not allowed to fetch would pass silently, and
  // a gate that cannot see is worse than no gate.
  if (thresholds.kev || thresholds.epss !== undefined) {
    const disabled =
      values.offline === true ? '--offline' : values['no-priority'] === true ? '--no-priority' : ''
    if (disabled !== '') {
      throw new CradleError(
        `--fail-on-kev and --fail-on-epss need the exploit signals that ${disabled} switches off`,
        'Drop one or the other. Gating on a signal that was never fetched would report ' +
          'a clean run rather than an unanswerable one.',
      )
    }
  }
  const format = values.format ?? 'text'
  if (format !== 'text' && format !== 'github' && format !== 'markdown' && format !== 'sarif') {
    throw new CradleError(
      `Unknown --format '${format}'`,
      'Use --format text (the default), github for workflow annotations, markdown for a ' +
        'pull-request comment, or sarif for GitHub Code Scanning and GitLab.',
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
    noPriority: values['no-priority'] === true,
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
  const failures = failingFindings(diff.added, thresholds)
  const failing = failures.map((failure) => failure.finding)

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

  // SARIF is the whole output too, and it reports **every** finding rather than
  // only what is new. A security dashboard is an inventory, not a diff: its job
  // is to show the current state, and the baseline's job is to decide what fails
  // the build. Feeding it only the new ones would make a dismissed finding
  // disappear from the dashboard rather than stay dismissed.
  if (format === 'sarif') {
    const manifest = await readManifest(projectDir)
    const sarif = buildSarif([...result.findings, ...result.suppressed], {
      toolName: TOOL_NAME,
      toolVersion: TOOL_VERSION,
      ...(manifest === undefined ? {} : { manifest, manifestPath: 'package.json' }),
      lockfilePath: lockfileFor(result.graph.packageManager),
      offline: values.offline === true,
      unavailable: result.priorityUnavailable,
    })
    stdout.write(`${JSON.stringify(sarif, null, 2)}\n`)
    return failing.length > 0 ? 1 : 0
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
        thresholds,
        hasBaseline: baseline !== undefined,
        toolName: TOOL_NAME,
        toolVersion: TOOL_VERSION,
        lang,
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
      failures,
      thresholds,
      baseline,
      baselinePath,
      projectDir,
      suppressed: result.suppressed.length,
      offline: result.findings.length === 0 && values.offline === true,
      project: `${result.graph.root.name} ${result.graph.root.version}`,
      scope: result.graph.includeDev ? 'all dependencies' : 'production only',
      sort,
      priorityUnavailable: result.priorityUnavailable,
    }),
  )
  if (profileReport !== undefined) stdout.write(renderProfileText(profileReport))

  return failing.length > 0 ? 1 : 0
}

/** Where a transitive finding anchors, since it is declared in no manifest. */
function lockfileFor(manager: string): string {
  if (manager === 'pnpm') return 'pnpm-lock.yaml'
  if (manager === 'yarn-classic' || manager === 'yarn-berry') return 'yarn.lock'
  return 'package-lock.json'
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

/** EPSS is a probability, so the flag takes one: 0.5, not 50. */
function parseEpss(value: string): number {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new CradleError(
      `--fail-on-epss expects a probability between 0 and 1, got '${value}'`,
      'EPSS is the chance of exploitation in the next 30 days. Half of that is 0.5.',
    )
  }
  return parsed
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
  failures: GateFailure[]
  thresholds: GateThresholds
  baseline: BaselineDocument | undefined
  baselinePath: string
  projectDir: string
  suppressed: number
  offline: boolean
  project: string
  scope: string
  sort: 'severity' | 'exploit'
  priorityUnavailable: string[]
}

/**
 * One line about exploitation, or nothing.
 *
 * "Nothing" is the honest answer for a finding with no CVE alias, because both
 * sources are keyed on CVE. Printing "EPSS 0" there would turn absent data into
 * a claim that exploitation is unlikely.
 */
/** 1st, 2nd, 3rd, 4th. "91th percentile" is the kind of wrong that gets noticed. */
function ordinal(value: number): string {
  const suffix =
    value % 100 >= 11 && value % 100 <= 13 ? 'th' : (['th', 'st', 'nd', 'rd'][value % 10] ?? 'th')
  return `${value}${suffix}`
}

function exploitLine(finding: Finding): string | undefined {
  const exploit = finding.exploit
  if (exploit === undefined) return undefined

  const parts: string[] = []
  if (exploit.knownExploited === true) {
    parts.push(
      `on CISA KEV${exploit.knownExploitedSince === undefined || exploit.knownExploitedSince === '' ? '' : ` since ${exploit.knownExploitedSince}`}`,
    )
  }
  if (exploit.epss !== undefined) {
    const percentile =
      exploit.epssPercentile === undefined
        ? ''
        : `, ${ordinal(Math.round(exploit.epssPercentile * 100))} percentile`
    parts.push(`EPSS ${(exploit.epss * 100).toFixed(1)}%${percentile}`)
  }
  return parts.length === 0 ? undefined : parts.join(' · ')
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
      (gateIsOff(input.thresholds)
        ? ''
        : `, ${input.failing.length} ${describeThresholds(input.thresholds)}`),
  )
  lines.push('')

  if (diff.added.length > 0) {
    lines.push(
      input.sort === 'exploit'
        ? '  New since the baseline, most likely exploited first'
        : '  New since the baseline',
    )
    const ordered =
      input.sort === 'exploit'
        ? [...diff.added].sort((a, b) =>
            byExploitPriority(a, b, (finding) => severityRank(finding.severity)),
          )
        : [...diff.added].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))

    for (const finding of ordered) {
      const fix = finding.fixedIn === undefined ? 'no fix yet' : `fix in ${finding.fixedIn}`
      const worse = diff.worsened.includes(finding) ? ', re-rated worse since accepted' : ''
      lines.push(
        `    ${finding.severity.padEnd(8)} ${finding.id}  ${finding.component.name} ` +
          `${finding.component.version}  (${fix}${worse})`,
      )
      const exploit = exploitLine(finding)
      if (exploit !== undefined) lines.push(`             ${exploit}`)
      if (!finding.component.direct) lines.push(`             ${finding.path.join(' > ')}`)
    }
    lines.push('')
  }

  if (input.priorityUnavailable.length > 0) {
    // Named rather than swallowed: a missing column is a gap in the data, and a
    // reader who does not know it is missing will read it as "no signal".
    lines.push(
      `  ! Exploit signals incomplete — could not reach ${input.priorityUnavailable.join(' or ')}.`,
      '',
    )
  }

  if (diff.resolved.length > 0) {
    const label = diff.resolved.length === 1 ? 'finding is' : 'findings are'
    lines.push(
      `  ${diff.resolved.length} baselined ${label} gone. Re-run with --baseline to tidy up.`,
    )
    lines.push('')
  }

  if (input.failures.length > 0) {
    lines.push(
      `  Failing: ${input.failures.length} new ${input.failures.length === 1 ? 'finding' : 'findings'} ` +
        `${describeThresholds(input.thresholds)}.`,
    )
    // Which threshold caught each one, because that changes what to do about it.
    for (const failure of input.failures) {
      lines.push(
        `    ${failure.finding.id}  ${failure.finding.component.name} ` +
          `${failure.finding.component.version}  — ${describeReasons(failure.reasons)}`,
      )
    }
  } else if (diff.added.length > 0) {
    lines.push(
      gateIsOff(input.thresholds)
        ? '  Passing: the gate is off, so nothing fails.'
        : `  Passing: nothing new is ${describeThresholds(input.thresholds)}.`,
    )
  } else {
    lines.push('  Passing: nothing new since the baseline.')
  }
  lines.push('')

  return lines.join('\n')
}
