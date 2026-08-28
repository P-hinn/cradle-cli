import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import { main } from '../../src/cli/main.js'
import { MemoryCache } from '../../src/core/vulns/cache.js'
import type { CdxBom, FindingsDocument } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
import { fakeOsv } from '../support/osv.js'
import { validateBom } from '../support/schema.js'

/** Collects everything written to it, so nothing reaches the real console. */
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
  const dir = await mkdtemp(join(tmpdir(), 'cradle-test-'))
  temporaries.push(dir)
  return dir
}

afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

async function run(
  args: string[],
  dependencies: Parameters<typeof main>[3] = {},
): Promise<{ code: number; out: string; err: string }> {
  const out = capture()
  const err = capture()
  // The OSV client always gets a replay unless a test says otherwise; the setup
  // file makes a real request throw, so a missing injection cannot slip past.
  const code = await main(args, out.stream, err.stream, {
    fetch: fakeOsv().fetch,
    cache: new MemoryCache(),
    ...dependencies,
  })
  return { code, out: out.text(), err: err.text() }
}

describe('cradle scan', () => {
  it('writes a schema-valid SBOM and reports what it found', async () => {
    const dir = await outputDir()
    const { code, out, err } = await run(['scan', fixture('npm-basic'), '--output-dir', dir])

    expect(err).toBe('')
    expect(code).toBe(0)

    const bom = JSON.parse(await readFile(join(dir, 'sbom.cdx.json'), 'utf8')) as CdxBom
    expect(validateBom(bom, '1.6').errors).toEqual([])
    expect(bom.metadata.component.name).toBe('acme-widget')

    expect(out).toContain('acme-widget 2.3.0')
    expect(out).toContain('production only')
    expect(out).toContain('3 (2 direct, 1 transitive)')
    expect(out).toContain('Findings     0')
  })

  it('writes a report next to the SBOM and the findings', async () => {
    const dir = await outputDir()
    const { out } = await run(['scan', fixture('npm-vulnerable'), '--output-dir', dir])

    const html = await readFile(join(dir, 'report.html'), 'utf8')
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain('acme-vulnerable')
    expect(out).toContain('report.html')

    // The report and the SBOM must be tied together by the same serial number,
    // so an auditor can tell they describe one scan.
    const bom = JSON.parse(await readFile(join(dir, 'sbom.cdx.json'), 'utf8')) as CdxBom
    expect(html).toContain(bom.serialNumber)
  })

  it('writes findings.json alongside the SBOM', async () => {
    const dir = await outputDir()
    await run(['scan', fixture('npm-vulnerable'), '--output-dir', dir])

    const doc = JSON.parse(await readFile(join(dir, 'findings.json'), 'utf8')) as FindingsDocument
    expect(doc.project).toEqual({ name: 'acme-vulnerable', version: '1.0.0' })
    expect(doc.scope).toBe('production')
    expect(doc.offline).toBe(false)
    expect(doc.findings).toHaveLength(8)
    // Worst first, so the file is useful without re-sorting.
    expect(doc.findings[0]?.severity).toBe('critical')
    expect(doc.findings[0]?.path[0]).toBe('acme-vulnerable')
  })

  it('leads with the upgrades that clear the most, worst first', async () => {
    const dir = await outputDir()
    const { out } = await run(['scan', fixture('npm-vulnerable'), '--output-dir', dir])

    expect(out).toContain('Findings     8 (1 critical, 3 high, 4 medium)')
    expect(out).toContain('Next steps')
    expect(out).toContain('minimist 1.2.0 -> 1.2.6')
    expect(out).toContain('worst critical')
    // At most three upgrades, so the summary stays a summary. Readiness items
    // are their own list further down.
    const upgrades = out
      .slice(out.indexOf('Next steps'), out.indexOf('CRA readiness'))
      .split('\n')
      .filter((line) => line.trimStart().startsWith('· '))
    expect(upgrades.length).toBeGreaterThan(0)
    expect(upgrades.length).toBeLessThanOrEqual(3)
  })

  it('says the lookup was skipped rather than implying a clean result', async () => {
    const dir = await outputDir()
    const { out } = await run(['scan', fixture('npm-vulnerable'), '--output-dir', dir, '--offline'])

    expect(out).toContain('Findings     not checked (--offline)')
    expect(out).toContain('the vulnerability lookup was skipped')

    const doc = JSON.parse(await readFile(join(dir, 'findings.json'), 'utf8')) as FindingsDocument
    expect(doc.offline).toBe(true)
    expect(doc.findings).toEqual([])
  })

  it('makes no network request at all when offline', async () => {
    const dir = await outputDir()
    const osv = fakeOsv()
    await run(['scan', fixture('npm-vulnerable'), '--output-dir', dir, '--offline'], {
      fetch: osv.fetch,
    })
    expect(osv.calls).toEqual([])
  })

  it('reuses the cache on a second run', async () => {
    const dir = await outputDir()
    const cache = new MemoryCache()
    const cold = fakeOsv()
    await run(['scan', fixture('npm-vulnerable'), '--output-dir', dir], {
      fetch: cold.fetch,
      cache,
    })
    const warm = fakeOsv()
    await run(['scan', fixture('npm-vulnerable'), '--output-dir', dir], {
      fetch: warm.fetch,
      cache,
    })
    // Only the batch request is repeated; advisory details come from the cache.
    // Registry traffic for the readiness checks is counted separately.
    expect(cold.osvCalls.length).toBeGreaterThan(1)
    expect(warm.osvCalls).toHaveLength(1)
  })

  it('emits 1.7 when asked', async () => {
    const dir = await outputDir()
    const { code } = await run([
      'scan',
      fixture('npm-basic'),
      '--output-dir',
      dir,
      '--spec-version',
      '1.7',
    ])
    expect(code).toBe(0)
    const bom = JSON.parse(await readFile(join(dir, 'sbom.cdx.json'), 'utf8')) as CdxBom
    expect(bom.specVersion).toBe('1.7')
    expect(validateBom(bom, '1.7').errors).toEqual([])
  })

  it('widens the scope with --include-dev', async () => {
    const dir = await outputDir()
    const { out } = await run(['scan', fixture('npm-basic'), '--output-dir', dir, '--include-dev'])
    expect(out).toContain('all dependencies')
    const bom = JSON.parse(await readFile(join(dir, 'sbom.cdx.json'), 'utf8')) as CdxBom
    expect(bom.components.map((c) => c.name)).toContain('chalk')
  })

  it('names the packages that declare no licence', async () => {
    const dir = await outputDir()
    const { out } = await run(['scan', fixture('npm-workspaces'), '--output-dir', dir])
    expect(out).toContain('1 unknown')
    expect(out).toContain('No licence declared: @acme/ui@0.4.2')
  })
})

describe('cradle scan — failures', () => {
  it('rejects an unknown CycloneDX version with a usable hint', async () => {
    const { code, err } = await run(['scan', fixture('npm-basic'), '--spec-version', '1.4'])
    expect(code).toBe(2)
    expect(err).toContain("Unsupported CycloneDX version '1.4'")
    expect(err).toContain('1.6, 1.7')
  })

  it('says what to do about a pnpm project instead of failing obscurely', async () => {
    const { code, err } = await run(['scan', fixture('detect/pnpm')])
    expect(code).toBe(2)
    expect(err).toContain('pnpm projects are not supported yet')
    expect(err).toContain('--package-lock-only')
  })

  it('gives bun its own message', async () => {
    const { code, err } = await run(['scan', fixture('detect/bun')])
    expect(code).toBe(2)
    expect(err).toContain('Bun projects are not supported yet')
  })

  it('reports a missing lockfile as a tool error, not a finding', async () => {
    const { code, err } = await run(['scan', fixture('detect/no-lockfile')])
    // Exit 2 is "the tool could not run". Exit 1 is reserved for real findings,
    // so CI never mistakes a broken setup for a security problem.
    expect(code).toBe(2)
    expect(err).toContain('No lockfile found')
  })
})

describe('cradle — dispatch', () => {
  it('prints help with no arguments', async () => {
    const { code, out } = await run([])
    expect(code).toBe(0)
    expect(out).toContain('cradle <command>')
  })

  it('prints the version', async () => {
    const { code, out } = await run(['--version'])
    expect(code).toBe(0)
    expect(out.trim()).toMatch(/^\d+\.\d+\.\d+/)
  })

  it('exits 2 on an unknown command', async () => {
    const { code, err } = await run(['bogus'])
    expect(code).toBe(2)
    expect(err).toContain("unknown command 'bogus'")
  })

  it('lists every command it actually has', async () => {
    const { out } = await run([])
    for (const command of ['scan', 'check', 'suppress']) expect(out).toContain(command)
  })
})
