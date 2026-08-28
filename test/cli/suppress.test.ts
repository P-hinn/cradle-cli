import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import { main } from '../../src/cli/main.js'
import { MemoryCache } from '../../src/core/vulns/cache.js'
import type { FindingsDocument, VexDocument } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { fakeOsv } from '../support/osv.js'

const NOW = new Date('2026-08-28T00:00:00.000Z')
const AUTHOR = 'tester@example.test'

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

/** A throwaway copy of a fixture, so a test can write into it. */
async function project(name: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cradle-suppress-'))
  temporaries.push(dir)
  await cp(fixture(name), dir, {
    recursive: true,
    // Leave behind anything a previous run left in the fixture; each test
    // starts from just the package.json and lockfile.
    filter: (source) => !source.includes('node_modules') && !source.includes('.cradle'),
  })
  return dir
}

let uuidCounter = 0
function nextUuid(): string {
  uuidCounter += 1
  return `0000000${uuidCounter}-0000-4000-8000-000000000000`
}

async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out = capture()
  const err = capture()
  const code = await main(args, out.stream, err.stream, {
    fetch: fakeOsv().fetch,
    cache: new MemoryCache(),
    now: () => NOW,
    uuid: nextUuid,
    defaultAuthor: () => AUTHOR,
  })
  return { code, out: out.text(), err: err.text() }
}

async function readVex(dir: string): Promise<VexDocument> {
  return JSON.parse(await readFile(join(dir, '.cradle', 'vex.json'), 'utf8')) as VexDocument
}

describe('cradle suppress', () => {
  it('records an OpenVEX statement for the named finding', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    const { code, out } = await run([
      'suppress',
      'GHSA-p6mc-m468-83gw',
      dir,
      '--justification',
      'vulnerable_code_not_present',
      '--note',
      'We never call zipObjectDeep.',
    ])

    expect(code).toBe(0)
    const vex = await readVex(dir)
    expect(vex['@context']).toBe('https://openvex.dev/ns/v0.2.0')
    expect(vex.author).toBe(AUTHOR)
    expect(vex.tooling).toBe('cradle-cli/0.0.0')
    expect(vex.version).toBe(1)

    const statement = vex.statements[0]
    expect(statement?.status).toBe('not_affected')
    expect(statement?.justification).toBe('vulnerable_code_not_present')
    expect(statement?.status_notes).toBe('We never call zipObjectDeep.')
    expect(statement?.products).toEqual([{ '@id': 'pkg:npm/lodash@4.17.15' }])

    expect(out).toContain('Recorded in')
    expect(out).toContain('The component is present, but the vulnerable code is not.')
  })

  it('accepts the CVE alias and records the advisory id cradle uses', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    await run(['suppress', 'CVE-2020-8203', dir, '--justification', 'vulnerable_code_not_present'])

    const statement = (await readVex(dir)).statements[0]
    expect(statement?.vulnerability.name).toBe('GHSA-p6mc-m468-83gw')
    expect(statement?.vulnerability.aliases).toContain('CVE-2020-8203')
  })

  it('takes the finding out of the count on the next scan, and says so', async () => {
    const dir = await project('npm-vulnerable')
    const before = await run(['scan', dir])
    expect(before.out).toContain('Findings     8')

    await run([
      'suppress',
      'GHSA-p6mc-m468-83gw',
      dir,
      '--justification',
      'vulnerable_code_not_present',
    ])
    const after = await run(['scan', dir])

    expect(after.out).toContain('Findings     7')
    expect(after.out).toContain('Suppressed   1 by VEX statements')

    // Recorded, not discarded: an audit wants to see the decision.
    const findings = JSON.parse(
      await readFile(join(dir, '.cradle', 'findings.json'), 'utf8'),
    ) as FindingsDocument
    expect(findings.findings).toHaveLength(7)
    expect(findings.suppressed).toHaveLength(1)
    expect(findings.suppressed[0]?.suppression?.justification).toBe('vulnerable_code_not_present')
  })

  it('records an expiry and warns before it lapses', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    await run([
      'suppress',
      'GHSA-p6mc-m468-83gw',
      dir,
      '--justification',
      'inline_mitigations_already_exist',
      '--expires',
      '2026-09-15',
    ])

    expect((await readVex(dir)).statements[0]?.['cradle:expires']).toBe('2026-09-15')
    const { out } = await run(['scan', dir])
    expect(out).toContain('1 suppression expires soon, the first in 18 days')
  })

  it('lets a lapsed suppression bring the finding back', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    await run([
      'suppress',
      'GHSA-p6mc-m468-83gw',
      dir,
      '--justification',
      'inline_mitigations_already_exist',
      '--expires',
      '2020-01-01',
    ])

    const { out } = await run(['scan', dir])
    expect(out).toContain('Findings     8')
    expect(out).not.toContain('Suppressed')
  })

  it('replaces the statement instead of stacking a second one', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    const args = [
      'suppress',
      'GHSA-p6mc-m468-83gw',
      dir,
      '--justification',
      'vulnerable_code_not_present',
    ]
    await run(args)
    const { out } = await run([...args, '--note', 'On reflection: not in the execute path.'])

    const vex = await readVex(dir)
    expect(vex.statements).toHaveLength(1)
    expect(vex.statements[0]?.status_notes).toBe('On reflection: not in the execute path.')
    expect(out).toContain('Updated in')
  })
})

describe('cradle suppress — refusals', () => {
  it('will not suppress without a justification category', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    const { code, err } = await run(['suppress', 'GHSA-p6mc-m468-83gw', dir])

    expect(code).toBe(2)
    expect(err).toContain('No --justification given')
    expect(err).toContain('component_not_present')
  })

  it('rejects a justification the standard does not define', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    const { code, err } = await run([
      'suppress',
      'GHSA-p6mc-m468-83gw',
      dir,
      '--justification',
      'we_will_get_to_it',
    ])
    expect(code).toBe(2)
    expect(err).toContain('not an OpenVEX justification')
  })

  it('refuses an ID that is not in the findings, rather than doing nothing', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    const { code, err } = await run([
      'suppress',
      'GHSA-typo',
      dir,
      '--justification',
      'component_not_present',
    ])
    expect(code).toBe(2)
    expect(err).toContain("No finding with the ID 'GHSA-typo'")
  })

  it('tells the user to scan first when there are no findings on disk', async () => {
    const dir = await project('npm-vulnerable')
    const { code, err } = await run([
      'suppress',
      'GHSA-p6mc-m468-83gw',
      dir,
      '--justification',
      'component_not_present',
    ])
    expect(code).toBe(2)
    expect(err).toContain('cradle scan')
  })

  it('rejects an unreadable expiry date', async () => {
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    const { code, err } = await run([
      'suppress',
      'GHSA-p6mc-m468-83gw',
      dir,
      '--justification',
      'component_not_present',
      '--expires',
      'soon',
    ])
    expect(code).toBe(2)
    expect(err).toContain('--expires')
  })

  it('stops the scan on a broken vex.json instead of ignoring it', async () => {
    // Ignoring it would silently re-report findings the team already ruled on.
    const dir = await project('npm-vulnerable')
    await run(['scan', dir])
    await writeFile(join(dir, '.cradle', 'vex.json'), '{ "statements": [] }', 'utf8')

    const { code, err } = await run(['scan', dir])
    expect(code).toBe(2)
    expect(err).toContain('no "author"')
  })
})
