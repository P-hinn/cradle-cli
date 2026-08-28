import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import { main } from '../../src/cli/main.js'
import { MemoryCache } from '../../src/core/vulns/cache.js'
import type { BaselineDocument } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { fakeOsv } from '../support/osv.js'

const NOW = new Date('2026-08-28T00:00:00.000Z')

function capture(): { stream: NodeJS.WritableStream; text: () => string } {
  const chunks: string[] = []
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk))
      callback()
    },
  })
  return { stream, text: () => chunks.join('') }
}

const temporaries: string[] = []
afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

async function project(name: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cradle-check-'))
  temporaries.push(dir)
  await cp(fixture(name), dir, {
    recursive: true,
    filter: (source) => !source.includes('node_modules') && !source.includes('.cradle'),
  })
  return dir
}

async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out = capture()
  const err = capture()
  const code = await main(args, out.stream, err.stream, {
    fetch: fakeOsv().fetch,
    cache: new MemoryCache(),
    now: () => NOW,
    defaultAuthor: () => 'tester@example.test',
  })
  return { code, out: out.text(), err: err.text() }
}

async function readBaseline(dir: string): Promise<BaselineDocument> {
  return JSON.parse(
    await readFile(join(dir, '.cradle', 'baseline.json'), 'utf8'),
  ) as BaselineDocument
}

describe('cradle check — exit codes', () => {
  it('fails on findings above the threshold when there is no baseline', async () => {
    const dir = await project('npm-vulnerable')
    const { code, out } = await run(['check', dir])

    expect(code).toBe(1)
    expect(out).toContain('Baseline     none')
    expect(out).toContain('Failing: 4 new findings at or above high')
  })

  it('passes on a project with nothing to report', async () => {
    const dir = await project('npm-basic')
    const { code, out } = await run(['check', dir])
    expect(code).toBe(0)
    expect(out).toContain('Passing')
  })

  it('reserves exit 2 for a broken run, so CI can tell it from a finding', async () => {
    // A tool that cannot run must never read as a security result.
    const dir = await project('detect/no-lockfile')
    const { code, err } = await run(['check', dir])
    expect(code).toBe(2)
    expect(err).toContain('No lockfile found')
  })

  it('respects --fail-on', async () => {
    const dir = await project('npm-vulnerable')
    expect((await run(['check', dir, '--fail-on', 'critical'])).code).toBe(1)
    // Nothing above critical exists once the one critical is excluded by raising
    // the bar past it, so "never" is the way to report without failing.
    const never = await run(['check', dir, '--fail-on', 'never'])
    expect(never.code).toBe(0)
    expect(never.out).toContain('New since the baseline')
  })

  it('rejects a threshold it does not know', async () => {
    const dir = await project('npm-vulnerable')
    const { code, err } = await run(['check', dir, '--fail-on', 'annoying'])
    expect(code).toBe(2)
    expect(err).toContain("Unknown --fail-on 'annoying'")
  })
})

describe('cradle check — baseline', () => {
  it('adopts the backlog and then goes green', async () => {
    // A gate that is red from day one is a gate people switch off.
    const dir = await project('npm-vulnerable')
    expect((await run(['check', dir])).code).toBe(1)

    const adopt = await run(['check', dir, '--baseline'])
    expect(adopt.code).toBe(0)
    expect(adopt.out).toContain('with 8 accepted findings')

    const after = await run(['check', dir])
    expect(after.code).toBe(0)
    expect(after.out).toContain('Passing: nothing new since the baseline')
  })

  it('reports a finding that is not in the baseline', async () => {
    const dir = await project('npm-vulnerable')
    await run(['check', dir, '--baseline'])

    const baseline = await readBaseline(dir)
    baseline.entries = baseline.entries.filter((entry) => entry.id !== 'GHSA-xvch-5gv4-984h')
    await writeFile(
      join(dir, '.cradle', 'baseline.json'),
      JSON.stringify(baseline, null, 2),
      'utf8',
    )

    const { code, out } = await run(['check', dir])
    expect(code).toBe(1)
    expect(out).toContain('GHSA-xvch-5gv4-984h')
    expect(out).toContain('Failing: 1 new finding at or above high')
  })

  it('reports an advisory that has been re-rated worse since it was accepted', async () => {
    const dir = await project('npm-vulnerable')
    await run(['check', dir, '--baseline'])

    const baseline = await readBaseline(dir)
    const entry = baseline.entries.find((candidate) => candidate.id === 'GHSA-p6mc-m468-83gw')
    if (entry === undefined) throw new Error('fixture changed')
    entry.severity = 'low'
    await writeFile(
      join(dir, '.cradle', 'baseline.json'),
      JSON.stringify(baseline, null, 2),
      'utf8',
    )

    const { code, out } = await run(['check', dir])
    expect(code).toBe(1)
    expect(out).toContain('re-rated worse since accepted')
  })

  it('--no-baseline judges everything as new again', async () => {
    const dir = await project('npm-vulnerable')
    await run(['check', dir, '--baseline'])
    expect((await run(['check', dir])).code).toBe(0)

    const { code, out } = await run(['check', dir, '--no-baseline'])
    expect(code).toBe(1)
    expect(out).toContain('Baseline     none')
  })

  it('points out baselined findings that are gone', async () => {
    const dir = await project('npm-vulnerable')
    await run(['check', dir, '--baseline'])

    const baseline = await readBaseline(dir)
    baseline.entries.push({
      id: 'GHSA-long-fixed',
      package: 'lodash',
      severity: 'high',
      acceptedAt: NOW.toISOString(),
    })
    await writeFile(
      join(dir, '.cradle', 'baseline.json'),
      JSON.stringify(baseline, null, 2),
      'utf8',
    )

    const { out } = await run(['check', dir])
    expect(out).toContain('1 baselined finding is gone')
  })

  it('refuses to run on a corrupt baseline instead of ignoring it', async () => {
    const dir = await project('npm-vulnerable')
    await run(['check', dir, '--baseline'])
    await writeFile(join(dir, '.cradle', 'baseline.json'), '{ nope', 'utf8')

    const { code, err } = await run(['check', dir])
    expect(code).toBe(2)
    expect(err).toContain('not valid JSON')
  })
})

describe('cradle check — VEX interaction', () => {
  it('does not count a suppressed finding as new', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    await run([
      'suppress',
      'GHSA-xvch-5gv4-984h',
      dir,
      '--justification',
      'vulnerable_code_not_in_execute_path',
    ])

    const { out } = await run(['check', dir])
    expect(out).toContain('Suppressed   1 by VEX statements')
    expect(out).not.toContain('GHSA-xvch-5gv4-984h')
  })
})

describe('cradle check — github format', () => {
  it('emits one annotation per failing finding, anchored to package.json', async () => {
    const dir = await project('npm-vulnerable')
    const { out } = await run(['check', dir, '--format', 'github'])

    const annotations = out.split('\n').filter((line) => line.startsWith('::error'))
    expect(annotations).toHaveLength(4)
    expect(annotations[0]).toContain('file=package.json')
    expect(annotations[0]).toContain('line=')
  })

  it('annotates only what fails, not the whole backlog', async () => {
    const dir = await project('npm-vulnerable')
    const { out } = await run(['check', dir, '--format', 'github', '--fail-on', 'critical'])
    expect(out.split('\n').filter((line) => line.startsWith('::error'))).toHaveLength(1)
  })

  it('rejects an unknown format', async () => {
    const dir = await project('npm-vulnerable')
    const { code, err } = await run(['check', dir, '--format', 'junit'])
    expect(code).toBe(2)
    expect(err).toContain("Unknown --format 'junit'")
  })
})
