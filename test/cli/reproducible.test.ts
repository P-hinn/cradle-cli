import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import { main } from '../../src/cli/main.js'
import { MemoryCache } from '../../src/core/vulns/cache.js'
import type { CdxBom } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { fakeOsv } from '../support/osv.js'
import { validateBom } from '../support/schema.js'

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
async function outputDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cradle-repro-'))
  temporaries.push(dir)
  return dir
}

afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out = capture()
  const err = capture()
  const code = await main(args, out.stream, err.stream, {
    fetch: fakeOsv().fetch,
    cache: new MemoryCache(),
  })
  return { code, out: out.text(), err: err.text() }
}

const TIMESTAMP = '2026-09-26T12:00:00.000Z'
const SERIAL = 'urn:uuid:11111111-2222-4333-8444-555555555555'

/**
 * A reproducible build wants the same bytes out for the same input in. Two things
 * stop an SBOM being reproducible, and both are deliberate: it stamps the moment
 * it was made, and it mints a fresh serial number so a reader can tell two BOMs
 * apart. Neither is wrong — they are simply not what a build system wants — so
 * both are overridable rather than removed.
 */
describe('cradle scan --timestamp and --serial-number', () => {
  it('produces byte-identical files across two runs', async () => {
    const first = await outputDir()
    const second = await outputDir()
    const args = ['--offline', '--timestamp', TIMESTAMP, '--serial-number', SERIAL]

    expect((await run(['scan', fixture('npm-basic'), '--output-dir', first, ...args])).code).toBe(0)
    expect((await run(['scan', fixture('npm-basic'), '--output-dir', second, ...args])).code).toBe(
      0,
    )

    // All three, not just the SBOM: the report carries the timestamp and the
    // serial number too, and findings.json carries the timestamp.
    for (const file of ['sbom.cdx.json', 'findings.json', 'report.html']) {
      const a = await readFile(join(first, file), 'utf8')
      const b = await readFile(join(second, file), 'utf8')
      expect(a, file).toBe(b)
    }
  })

  it('differs between runs without them, which is the right default', async () => {
    // The negative half. If two default runs matched, it would mean the timestamp
    // is not being stamped at all.
    const first = await outputDir()
    const second = await outputDir()
    await run(['scan', fixture('npm-basic'), '--offline', '--output-dir', first])
    await run(['scan', fixture('npm-basic'), '--offline', '--output-dir', second])

    const a = JSON.parse(await readFile(join(first, 'sbom.cdx.json'), 'utf8')) as CdxBom
    const b = JSON.parse(await readFile(join(second, 'sbom.cdx.json'), 'utf8')) as CdxBom
    expect(a.serialNumber).not.toBe(b.serialNumber)
  })

  it('writes the values it was given, unchanged', async () => {
    const dir = await outputDir()
    await run([
      'scan',
      fixture('npm-basic'),
      '--offline',
      '--output-dir',
      dir,
      '--timestamp',
      TIMESTAMP,
      '--serial-number',
      SERIAL,
    ])

    const bom = JSON.parse(await readFile(join(dir, 'sbom.cdx.json'), 'utf8')) as CdxBom
    expect(bom.serialNumber).toBe(SERIAL)
    expect(bom.metadata.timestamp).toBe(TIMESTAMP)

    // And it is still a valid document, which a hand-passed value could easily
    // have broken.
    const { valid, errors } = validateBom(bom, '1.6')
    expect(errors).toEqual([])
    expect(valid).toBe(true)
  })

  it('normalises an equivalent timestamp to one spelling', async () => {
    // `2026-09-26T14:00:00+02:00` and `2026-09-26T12:00:00Z` are the same instant.
    // Reproducibility would be a lie if the spelling leaked into the output.
    const first = await outputDir()
    const second = await outputDir()
    await run([
      'scan',
      fixture('npm-basic'),
      '--offline',
      '--output-dir',
      first,
      '--timestamp',
      '2026-09-26T14:00:00+02:00',
      '--serial-number',
      SERIAL,
    ])
    await run([
      'scan',
      fixture('npm-basic'),
      '--offline',
      '--output-dir',
      second,
      '--timestamp',
      TIMESTAMP,
      '--serial-number',
      SERIAL,
    ])

    expect(await readFile(join(first, 'sbom.cdx.json'), 'utf8')).toBe(
      await readFile(join(second, 'sbom.cdx.json'), 'utf8'),
    )
  })

  it('refuses a timestamp that is not a timestamp', async () => {
    // `new Date('2026')` is a real date, so a loose parse would accept it as
    // midnight on New Year - a plausible wrong answer in the field an auditor
    // reads as "when was this scanned".
    const { code, err } = await run([
      'scan',
      fixture('npm-basic'),
      '--offline',
      '--timestamp',
      'last tuesday',
    ])
    expect(code).toBe(2)
    expect(err).toContain('not a valid ISO 8601 timestamp')
  })

  it('refuses a serial number that is not a UUID URN', async () => {
    const { code, err } = await run([
      'scan',
      fixture('npm-basic'),
      '--offline',
      '--serial-number',
      'sbom-42',
    ])
    expect(code).toBe(2)
    expect(err).toContain('not a UUID URN')
  })

  it('refuses one serial number for every package of a monorepo', async () => {
    // A serial number identifies one BOM. Handing the same one to six packages
    // would produce six documents claiming to be the same document.
    const { code, err } = await run([
      'scan',
      fixture('npm-workspaces'),
      '--offline',
      '--workspace',
      'all',
      '--serial-number',
      SERIAL,
    ])
    expect(code).toBe(2)
    expect(err).toContain('cannot be combined with --serial-number')
    expect(err).toContain('one package at a time')
  })
})
