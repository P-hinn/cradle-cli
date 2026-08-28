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

  it('pins the action versions it depends on', () => {
    for (const step of ACTION.runs.steps) {
      if (step.uses === undefined) continue
      expect(step.uses, step.name).toMatch(/@v\d+$/)
    }
  })
})
