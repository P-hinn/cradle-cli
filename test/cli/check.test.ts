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

  it('emits a pull-request comment with --format markdown, and nothing else', async () => {
    const dir = await project('npm-vulnerable')
    const { code, out } = await run(['check', dir, '--format', 'markdown'])

    expect(code).toBe(1)
    expect(out.startsWith('<!-- cradle-cli:report -->')).toBe(true)
    expect(out).toContain('4 new findings at or above high')
    // The console summary would be noise inside a comment body.
    expect(out).not.toContain('Baseline     none')
    expect(out).not.toContain('::error')
  })

  it('names the artifact in the comment when the action uploaded one', async () => {
    const dir = await project('npm-vulnerable')
    const { out } = await run([
      'check',
      dir,
      '--format',
      'markdown',
      '--artifact-name',
      'cradle-report',
    ])
    expect(out).toContain('**cradle-report**')
  })

  it('rejects an unknown format', async () => {
    const dir = await project('npm-vulnerable')
    const { code, err } = await run(['check', dir, '--format', 'junit'])
    expect(code).toBe(2)
    expect(err).toContain("Unknown --format 'junit'")
  })
})

describe('cradle check — the exploit gate', () => {
  it('fails on an exploited finding the severity threshold would let through', async () => {
    // CVE-2020-8203 is a high, and the fake CISA catalogue lists it. Raising the
    // severity bar past it leaves --fail-on-kev as the only thing that catches it.
    const dir = await project('npm-vulnerable')
    const severityOnly = await run(['check', dir, '--fail-on', 'critical'])
    const withKev = await run(['check', dir, '--fail-on', 'critical', '--fail-on-kev'])

    expect(withKev.code).toBe(1)
    expect(withKev.out).toContain('GHSA-p6mc-m468-83gw')
    expect(severityOnly.out).not.toContain('— exploited')
  })

  it('can gate on exploitation alone', async () => {
    const dir = await project('npm-vulnerable')
    const { code, out } = await run(['check', dir, '--fail-on', 'never', '--fail-on-kev'])

    expect(code).toBe(1)
    expect(out).toContain('Failing: 1 new finding known to be exploited')
    expect(out).toContain('— exploited')
  })

  it('names which threshold caught each finding', async () => {
    // Severity says how bad it would be, KEV says someone is doing it. A reader
    // acts differently on each, so "failed" on its own is not an answer.
    const dir = await project('npm-vulnerable')
    const { out } = await run(['check', dir, '--fail-on', 'high', '--fail-on-kev'])
    expect(out).toMatch(/GHSA-p6mc-m468-83gw.*— severity \+ exploited/)
  })

  it('gates on an EPSS probability', async () => {
    const dir = await project('npm-vulnerable')
    const caught = await run(['check', dir, '--fail-on', 'never', '--fail-on-epss', '0.04'])
    const missed = await run(['check', dir, '--fail-on', 'never', '--fail-on-epss', '0.9'])

    expect(caught.code).toBe(1)
    expect(caught.out).toContain('— EPSS')
    expect(missed.code).toBe(0)
    expect(missed.out).toContain('nothing new is EPSS at or above 90%')
  })

  it('rejects a probability that is not one', async () => {
    const dir = await project('npm-vulnerable')
    const { code, err } = await run(['check', dir, '--fail-on-epss', '50'])
    expect(code).toBe(2)
    expect(err).toContain('between 0 and 1')
  })

  it.each(['--offline', '--no-priority'])(
    'refuses to gate on a signal %s switches off',
    async (flag) => {
      // Gating on a signal that was never fetched would report a clean run
      // rather than an unanswerable one.
      const dir = await project('npm-vulnerable')
      const { code, err } = await run(['check', dir, flag, '--fail-on-kev'])
      expect(code).toBe(2)
      expect(err).toContain(flag)
      expect(err).toContain('exploit signals')
    },
  )

  it('leaves the default gate on severity alone', async () => {
    const dir = await project('npm-vulnerable')
    const { code, out } = await run(['check', dir])
    expect(code).toBe(1)
    expect(out).toContain('at or above high')
    expect(out).not.toContain('known to be exploited')
  })
})

describe('cradle check — --from-sbom', () => {
  it('checks a shipped product whose lockfile is gone', async () => {
    // The case the feature exists for: the repository has moved on, but the SBOM
    // in the technical documentation is what was placed on the market, and the
    // support period obliges someone to keep watching that.
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])

    const shipped = join(dir, 'shipped.cdx.json')
    await cp(join(dir, '.cradle', 'sbom.cdx.json'), shipped)
    await rm(join(dir, 'package-lock.json'))

    const { code, out } = await run(['check', dir, '--from-sbom', shipped])
    expect(code).toBe(1)
    expect(out).toContain('Findings     8')
  })

  it('finds the same findings from the SBOM as from the lockfile', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    const shipped = join(dir, 'shipped.cdx.json')
    await cp(join(dir, '.cradle', 'sbom.cdx.json'), shipped)

    const fromLockfile = await run(['check', dir, '--fail-on', 'never'])
    const fromSbom = await run(['check', dir, '--from-sbom', shipped, '--fail-on', 'never'])

    const advisories = (text: string) => [...text.matchAll(/GHSA-[\w-]+/g)].map((m) => m[0]).sort()
    expect(advisories(fromSbom.out)).toEqual(advisories(fromLockfile.out))
  })

  it('says where the graph came from instead of naming a package manager', async () => {
    // A supplied document says nothing about the tool that installed anything.
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    const shipped = join(dir, 'shipped.cdx.json')
    await cp(join(dir, '.cradle', 'sbom.cdx.json'), shipped)

    const { out } = await run(['scan', dir, '--from-sbom', shipped, '--output-dir', 'from-sbom'])
    expect(out).toContain('from shipped.cdx.json')
  })

  it('reports a file it cannot read rather than falling back to the lockfile', async () => {
    const dir = await project('npm-vulnerable')
    const { code, err } = await run(['check', dir, '--from-sbom', join(dir, 'absent.cdx.json')])
    expect(code).toBe(2)
    expect(err).toContain('Could not read')
  })
})
