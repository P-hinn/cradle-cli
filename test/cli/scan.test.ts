import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import { main } from '../../src/cli/main.js'
import type { CdxBom } from '../../src/types/index.js'
import { fixture } from '../support/fixtures.js'
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

async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out = capture()
  const err = capture()
  const code = await main(args, out.stream, err.stream)
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
    // The summary must not imply a clean security result before we can give one.
    expect(out).toContain('Vulnerability lookup is not implemented yet')
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

  it('admits which commands are not built yet', async () => {
    for (const command of ['check', 'suppress']) {
      const { code, err } = await run([command])
      expect(code).toBe(2)
      expect(err).toContain('not implemented yet')
    }
  })
})
