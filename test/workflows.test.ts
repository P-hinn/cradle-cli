import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import { COMMENT_MARKER } from '../src/report/markdown.js'

interface Step {
  name?: string
  uses?: string
  run?: string
  shell?: string
  with?: Record<string, unknown>
  'working-directory'?: string
}

interface Job {
  'runs-on': string
  permissions?: Record<string, string>
  strategy?: { 'fail-fast'?: boolean; matrix?: Record<string, unknown> }
  steps: Step[]
}

interface Workflow {
  name: string
  on: Record<string, unknown>
  permissions?: Record<string, string>
  concurrency?: unknown
  jobs: Record<string, Job>
}

const WORKFLOW_DIR = new URL('../.github/workflows/', import.meta.url)

function read(file: string): string {
  return readFileSync(new URL(file, WORKFLOW_DIR), 'utf8')
}

function workflow(file: string): Workflow {
  return parse(read(file)) as Workflow
}

const CI = workflow('ci.yml')
const CODEQL = workflow('codeql.yml')
const SCORECARD = workflow('scorecard.yml')

/**
 * None of these workflows can be executed here, so the tests guard the mistakes
 * that would otherwise only surface on a push: a matrix that quietly stopped
 * covering a platform, a permission widened past what a job needs, an
 * interpolation pasted into a shell.
 */
describe('ci workflow', () => {
  it('runs on both push and pull_request', () => {
    expect(Object.keys(CI.on).sort()).toEqual(['pull_request', 'push'])
  })

  it('covers Node 22 and 24 on all three operating systems', () => {
    // Six combinations, not a sample of them. The lockfile parsers join paths,
    // and a separator bug that only appears on Windows is exactly the one that
    // reaches a user before it reaches us.
    const matrix = CI.jobs.gate?.strategy?.matrix
    expect(matrix?.node).toEqual(['22', '24'])
    expect(matrix?.os).toEqual(['ubuntu-latest', 'macos-latest', 'windows-latest'])
  })

  it('does not abandon the other platforms when one fails', () => {
    // fail-fast would cancel macOS the moment Windows went red, hiding whether
    // the failure was platform-specific at all.
    expect(CI.jobs.gate?.strategy?.['fail-fast']).toBe(false)
  })

  it('declares the node floor the package declares', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      engines: { node: string }
    }
    const versions = (CI.jobs.gate?.strategy?.matrix?.node ?? []) as string[]
    expect(pkg.engines.node).toContain(`${versions[0]}.`)
  })

  it('runs the whole gate in order', () => {
    const runs = (CI.jobs.gate?.steps ?? []).map((step) => step.run)
    for (const script of [
      'npm ci',
      'npm run lint',
      'npm run typecheck',
      'npm test',
      'npm run build',
    ]) {
      expect(runs, script).toContain(script)
    }
  })

  it('exercises the built CLI against the example project, not just the unit tests', () => {
    // The gate proves the code works. This proves the thing that gets published
    // works, on a real lockfile, with no node_modules.
    const steps = (CI.jobs.gate?.steps ?? []).filter(
      (step) => step['working-directory'] === 'examples/express-service',
    )
    expect(steps.length).toBeGreaterThanOrEqual(2)

    const scripts = steps.map((step) => step.run ?? '').join('\n')
    expect(scripts).toContain('scan --offline')
    expect(scripts).toContain('check --offline')
  })

  it('asserts both sides of the exit-code contract', () => {
    // 0 clean and 2 could-not-run (SPEC.md §6.4). Asserting only the happy path
    // would let a tool error pass for a security result, which is the one
    // confusion the exit codes exist to prevent.
    const scripts = (CI.jobs.gate?.steps ?? []).map((step) => step.run ?? '').join('\n')
    expect(scripts).toContain('-ne 0')
    expect(scripts).toContain('-ne 2')
  })

  it('never reaches the network from the example scan', () => {
    // A CI job that queries api.osv.dev turns someone else's outage into a red
    // build here, and makes the run non-reproducible besides.
    for (const step of CI.jobs.gate?.steps ?? []) {
      const script = step.run ?? ''
      if (!script.includes('dist/cli/index.js')) continue
      for (const invocation of script.matchAll(/dist\/cli\/index\.js [^\n]*/g)) {
        expect(invocation[0], invocation[0]).toContain('--offline')
      }
    }
  })

  it('clears -e in any step that reads an exit code', () => {
    // GitHub invokes `shell: bash` as `bash -eo pipefail`, and `set -uo pipefail`
    // does not clear the inherited -e. A step that reads $? without `set +e`
    // dies at the first non-zero exit, so the assertion never runs and the step
    // passes by not looking. That is the worst kind of green.
    for (const step of CI.jobs.gate?.steps ?? []) {
      const script = step.run ?? ''
      if (!script.includes('$?')) continue
      expect(script, step.name).toContain('set +e')
    }
  })

  it('pins a shell for every step that runs on Windows too', () => {
    // Without an explicit shell, `run` uses pwsh on windows-latest and the
    // bash written here would not parse.
    for (const step of CI.jobs.gate?.steps ?? []) {
      if (step.run === undefined) continue
      if (!step.run.includes('\n')) continue
      expect(step.shell, step.name).toBe('bash')
    }
  })

  it('cancels a superseded run', () => {
    expect(CI.concurrency).toBeDefined()
  })
})

describe('codeql workflow', () => {
  it('analyses JavaScript and TypeScript', () => {
    const init = CODEQL.jobs.analyse?.steps.find((step) =>
      step.uses?.includes('codeql-action/init'),
    )
    expect(init?.with?.languages).toBe('javascript-typescript')
  })

  it('asks for the extended security queries', () => {
    // The default pack misses what matters here: path traversal out of the
    // project directory, and unsafe HTML construction in the report generator.
    const init = CODEQL.jobs.analyse?.steps.find((step) =>
      step.uses?.includes('codeql-action/init'),
    )
    expect(init?.with?.queries).toBe('security-extended')
  })

  it('re-runs on a schedule, not only when the code changes', () => {
    // A repository with four dependencies still gets new query packs.
    expect(CODEQL.on.schedule).toBeDefined()
  })

  it('may write security events and nothing else', () => {
    expect(CODEQL.jobs.analyse?.permissions).toEqual({
      'security-events': 'write',
      contents: 'read',
    })
  })
})

describe('scorecard workflow', () => {
  it('publishes its result, so the badge is verifiable', () => {
    const scan = SCORECARD.jobs.analysis?.steps.find((step) =>
      step.uses?.includes('ossf/scorecard-action'),
    )
    expect(scan?.with?.publish_results).toBe(true)
    // publish_results needs the OIDC token; without it the badge never updates.
    expect(SCORECARD.jobs.analysis?.permissions?.['id-token']).toBe('write')
  })

  it('checks out without credentials', () => {
    // Scorecard reads the repository's own configuration; leaving a token in the
    // working copy would hand it to every analysis step for no benefit.
    const checkout = SCORECARD.jobs.analysis?.steps.find((step) =>
      step.uses?.startsWith('actions/checkout'),
    )
    expect(checkout?.with?.['persist-credentials']).toBe(false)
  })

  it('uploads the sarif to code scanning', () => {
    const scripts = (SCORECARD.jobs.analysis?.steps ?? []).map((step) => step.uses ?? '')
    expect(scripts.some((uses) => uses.includes('upload-sarif'))).toBe(true)
  })
})

describe('every workflow', () => {
  const files = readdirSync(WORKFLOW_DIR).filter((file) => file.endsWith('.yml'))

  it('has more than just the release workflow', () => {
    expect(files.sort()).toEqual(['ci.yml', 'codeql.yml', 'release.yml', 'scorecard.yml'])
  })

  for (const file of files) {
    describe(file, () => {
      const parsed = workflow(file)

      it('is read-only at the top level and widens only per job', () => {
        // A workflow-level write permission applies to every job in it,
        // including ones that only need to read.
        expect(parsed.permissions?.contents).toBe('read')
      })

      it('pins every action it uses', () => {
        for (const job of Object.values(parsed.jobs)) {
          for (const step of job.steps) {
            if (step.uses === undefined) continue
            expect(step.uses, step.uses).toMatch(/@v\d+$/)
          }
        }
      })

      it('never interpolates into a shell', () => {
        // ${{ }} pasted into a run block is a script-injection hole; values
        // arrive through env: instead. Step names and `with:` are not shells.
        for (const job of Object.values(parsed.jobs)) {
          for (const step of job.steps) {
            if (step.run === undefined) continue
            expect(step.run, `${file}: ${step.name ?? step.run.slice(0, 40)}`).not.toMatch(/\$\{\{/)
          }
        }
      })
    })
  }
})

describe('dependabot', () => {
  const config = parse(
    readFileSync(new URL('../.github/dependabot.yml', import.meta.url), 'utf8'),
  ) as {
    version: number
    updates: {
      'package-ecosystem': string
      directory: string
      schedule: { interval: string }
      groups?: Record<string, unknown>
      'commit-message'?: { prefix?: string }
    }[]
  }

  it('watches npm and the actions, weekly', () => {
    const ecosystems = config.updates.map((update) => update['package-ecosystem'])
    expect(ecosystems).toContain('npm')
    expect(ecosystems).toContain('github-actions')
    for (const update of config.updates) {
      expect(update.schedule.interval, update['package-ecosystem']).toBe('weekly')
    }
  })

  it('groups its pull requests', () => {
    // Four runtime dependencies and a handful of dev ones. One reviewable pull
    // request a week beats eight that nobody opens.
    for (const update of config.updates) {
      expect(update.groups, update['package-ecosystem']).toBeDefined()
    }
  })

  it('uses the conventional-commit prefixes this repository uses', () => {
    const prefixes = config.updates.map((update) => update['commit-message']?.prefix)
    for (const prefix of prefixes) {
      expect(['chore', 'ci']).toContain(prefix)
    }
  })

  it('leaves the example project alone', () => {
    // examples/express-service is pinned to deliberately dated dependencies so
    // that it produces findings. Updating it would defeat the example.
    const directories = config.updates.map((update) => update.directory)
    expect(directories.every((directory) => directory === '/')).toBe(true)
  })
})

describe('the GitLab CI example', () => {
  const raw = readFileSync(new URL('../examples/gitlab-ci.yml', import.meta.url), 'utf8')
  const config = parse(raw) as Record<
    string,
    { script?: string[]; artifacts?: Record<string, unknown> }
  >

  it('separates the evidence job from the gate', () => {
    // They want different failure behaviour: the scan must pass for GitLab to
    // ingest a security report at all, including on a day the gate is red.
    expect(Object.keys(config)).toContain('cradle-scan')
    expect(Object.keys(config)).toContain('cradle-check')
  })

  it('tells 1 from 2, so a broken tool is not a security result', () => {
    const script = (config['cradle-check']?.script ?? []).join('\n')
    expect(script).toContain('set +e')
    expect(script).toContain('-eq 2')
    expect(script).toContain('not a security finding')
  })

  it('declares the SARIF report GitLab ingests', () => {
    const reports = config['cradle-check']?.artifacts?.reports as Record<string, string> | undefined
    expect(reports?.sarif).toBe('gl-cradle-sarif.json')
  })

  it('pins the tool version rather than tracking a range', () => {
    // A moving version in CI is a pipeline that changes its mind about your
    // dependencies without anyone deciding to.
    const variables = (parse(raw) as { variables: Record<string, string> }).variables
    expect(variables.CRADLE_VERSION).toMatch(/^\d+\.\d+\.\d+$/)
    expect(raw).toContain('cradle-cli@${CRADLE_VERSION}')
  })

  it('uses the same comment marker the tool writes', () => {
    // Or the merge request collects one note per push and nobody reads them.
    expect(raw).toContain(COMMENT_MARKER)
  })

  it('skips the comment job rather than failing when no token is set', () => {
    const rules = (config['cradle-comment'] as { rules?: { if?: string }[] } | undefined)?.rules
    expect(rules?.[0]?.if).toContain('CRADLE_MR_TOKEN')
  })
})
