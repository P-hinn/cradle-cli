import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import { COMMENT_MARKER } from '../src/report/markdown.js'

interface ActionStep {
  id?: string
  name?: string
  uses?: string
  shell?: string
  run?: string
  if?: string
  env?: Record<string, string>
}

interface Action {
  name: string
  description: string
  inputs: Record<string, { description: string; default?: string }>
  outputs: Record<string, { description: string; value: string }>
  runs: { using: string; steps: ActionStep[] }
}

const RAW = readFileSync(new URL('../action.yml', import.meta.url), 'utf8')
const RELEASE_RAW = readFileSync(
  new URL('../.github/workflows/release.yml', import.meta.url),
  'utf8',
)
const ACTION = parse(RAW) as Action
const SCRIPTS = ACTION.runs.steps.map((step) => step.run ?? '').join('\n')

/**
 * The action cannot be executed here, so these guard the mistakes that would
 * only show up in someone else's pipeline: a typo in an input reference, a shell
 * step without a shell, a marker that drifted away from the one the tool writes.
 */
describe('action.yml', () => {
  it('is a composite action', () => {
    expect(ACTION.runs.using).toBe('composite')
  })

  it('gives every input a description and a default', () => {
    for (const [name, input] of Object.entries(ACTION.inputs)) {
      expect(input.description, name).toBeTruthy()
      expect(input.default, name).toBeDefined()
    }
  })

  it('declares a shell for every run step, which composite actions require', () => {
    for (const step of ACTION.runs.steps) {
      if (step.run === undefined) continue
      expect(step.shell, step.name).toBe('bash')
    }
  })

  it('references only inputs that exist', () => {
    // A typo in ${{ inputs.fail-onn }} expands to an empty string, silently
    // changing behaviour rather than failing.
    const referenced = [...RAW.matchAll(/inputs\.([a-z-]+)/g)].map((match) => match[1])
    for (const name of referenced) {
      expect(Object.keys(ACTION.inputs), `inputs.${name}`).toContain(name)
    }
  })

  it('references only steps that exist', () => {
    const ids = new Set(ACTION.runs.steps.map((step) => step.id).filter(Boolean))
    for (const match of RAW.matchAll(/steps\.([a-z-]+)\./g)) {
      expect([...ids], match[0]).toContain(match[1])
    }
  })

  it('uses the same comment marker the tool writes', () => {
    // If these drift apart the action posts a fresh comment on every push.
    expect(SCRIPTS).toContain(COMMENT_MARKER)
  })

  it('edits an existing comment instead of adding one', () => {
    expect(SCRIPTS).toContain('PATCH')
    expect(SCRIPTS).toContain('POST')
  })

  it('only comments on pull requests', () => {
    const step = ACTION.runs.steps.find((candidate) => candidate.name?.includes('Comment'))
    expect(step?.if).toContain("github.event_name == 'pull_request'")
  })

  it('treats exit code 2 as a broken run, not as a security result', () => {
    expect(SCRIPTS).toContain('-ge 2')
  })

  it('quotes every interpolation into the shell through the environment', () => {
    // ${{ }} pasted straight into a run block is a script-injection hole; every
    // value has to arrive as an environment variable instead.
    for (const step of ACTION.runs.steps) {
      if (step.run === undefined) continue
      expect(step.run, step.name).not.toMatch(/\$\{\{/)
    }
  })

  it('defaults to the cradle-cli version it ships with', () => {
    // A pinned action tag has to mean a pinned tool, or `uses: ...@v0.1.0` would
    // silently start running a different release.
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version: string
    }
    expect(ACTION.inputs.version?.default).toBe(pkg.version)
  })

  it('pins the action versions it depends on', () => {
    for (const step of ACTION.runs.steps) {
      if (step.uses === undefined) continue
      expect(step.uses, step.name).toMatch(/@v\d+$/)
    }
  })
})

interface Workflow {
  on: { push?: { tags?: string[] } }
  permissions: Record<string, string>
  jobs: Record<string, { permissions?: Record<string, string>; steps: ActionStep[] }>
}

const RELEASE = parse(RELEASE_RAW) as Workflow
const RELEASE_JOB = RELEASE.jobs.release

/**
 * The release workflow cannot be exercised here either, and it is the one place
 * that publishes. These guard the mistakes that would only surface at a tag.
 */
describe('release workflow', () => {
  it('runs only on a version tag, never on a push or a pull request', () => {
    expect(RELEASE.on.push?.tags).toEqual(['v*'])
    expect(Object.keys(RELEASE.on)).toEqual(['push'])
  })

  it('asks for the OIDC token provenance needs, and nothing broader', () => {
    // id-token: write is what lets npm attest that this tarball came from this
    // commit. Without it the publish succeeds and proves nothing.
    expect(RELEASE_JOB?.permissions?.['id-token']).toBe('write')
    expect(RELEASE.permissions.contents).toBe('read')
  })

  it('publishes with provenance', () => {
    const scripts = (RELEASE_JOB?.steps ?? []).map((step) => step.run ?? '').join('\n')
    expect(scripts).toContain('npm publish --provenance --access public')
  })

  it('refuses a tag that disagrees with package.json', () => {
    // Publishing them out of step puts a version on npm that no tag points at.
    const scripts = (RELEASE_JOB?.steps ?? []).map((step) => step.run ?? '').join('\n')
    expect(scripts).toContain('does not match package.json version')
  })

  it('runs the full gate before publishing', () => {
    const runs = (RELEASE_JOB?.steps ?? []).map((step) => step.run)
    for (const script of ['npm run lint', 'npm run typecheck', 'npm test', 'npm run build']) {
      expect(runs, script).toContain(script)
    }
  })

  it('never interpolates into a shell', () => {
    for (const step of RELEASE_JOB?.steps ?? []) {
      if (step.run === undefined) continue
      expect(step.run, step.name).not.toMatch(/\$\{\{/)
    }
  })

  it('pins every action it uses', () => {
    for (const step of RELEASE_JOB?.steps ?? []) {
      if (step.uses === undefined) continue
      expect(step.uses, step.uses).toMatch(/@v\d+$/)
    }
  })

  it("attaches cradle's own SBOM to the release, under distinct names", () => {
    // A tool that asks people to keep an SBOM should ship one. Both SBOMs are
    // written as sbom.cdx.json where they are generated, and release assets are
    // keyed by filename — uploading them as-is is what broke the 0.1.3 release.
    const scripts = (RELEASE_JOB?.steps ?? []).map((step) => step.run ?? '').join('\n')
    expect(scripts).toContain('-sbom.cdx.json')
    expect(scripts).toContain('-sbom-with-dev.cdx.json')

    const uploaded = [...scripts.matchAll(/\$\{assets\}\/([^"'\s]+)/g)].map((match) => match[1])
    expect(uploaded.length).toBeGreaterThan(1)
    expect(new Set(uploaded).size).toBe(uploaded.length)
  })

  it('can be run again after a partial failure', () => {
    // 0.1.3 published and then the release step failed. Fixing that should be a
    // re-run, not a burnt version number.
    const scripts = (RELEASE_JOB?.steps ?? []).map((step) => step.run ?? '').join('\n')
    expect(scripts).toContain('already on the registry; skipping publish')
    expect(scripts).toContain('gh release view')
    expect(scripts).toContain('--clobber')
  })
})
