import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import { main } from '../../src/cli/main.js'
import { MemoryCache } from '../../src/core/vulns/cache.js'
import type { CdxBom, FindingsDocument } from '../../src/types/index.js'
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

/**
 * A writable copy of a fixture. `--workspace all` writes into each package's own
 * directory, so it cannot be redirected with `--output-dir` — the project itself
 * has to be somewhere disposable.
 */
async function workingCopy(source: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cradle-ws-'))
  temporaries.push(dir)
  await cp(source, join(dir, 'project'), { recursive: true })
  return join(dir, 'project')
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

const PNPM_MONOREPO = fileURLToPath(new URL('../corpus/pnpm-workspace', import.meta.url))

/**
 * A monorepo has one lockfile and several deliverables. The repository-wide report
 * answers "what is in this repository"; a per-package report answers "what is in
 * the thing my team ships", which is a different question and the one that decides
 * who fixes a finding.
 *
 * The per-package graph is sliced out of the repository-wide one rather than
 * resolved separately, so the two can never disagree about a version.
 */
describe('cradle scan --workspace', () => {
  it('makes the named package the product, with only its own dependencies', async () => {
    const project = await workingCopy(fixture('npm-workspaces'))
    const { code, out, err } = await run([
      'scan',
      project,
      '--offline',
      '--include-dev',
      '--workspace',
      '@acme/ui',
    ])

    expect(err).toBe('')
    expect(code).toBe(0)
    expect(out).toContain('@acme/ui 0.4.2')

    const bom = JSON.parse(
      await readFile(join(project, 'packages/ui/.cradle/sbom.cdx.json'), 'utf8'),
    ) as CdxBom
    expect(bom.metadata.component.name).toBe('@acme/ui')

    // @acme/ui depends on @acme/core and debug; debug brings ms. What it must not
    // contain is a sibling it does not depend on, or a dependency of the root.
    const names = bom.components.map((component) => component.name).sort()
    expect(names).toEqual(['@acme/core', 'debug', 'ms'])
    expect(names).not.toContain('@sindresorhus/is')
  })

  it('writes one report per package with --workspace all', async () => {
    const project = await workingCopy(fixture('npm-workspaces'))
    const { code, out } = await run([
      'scan',
      project,
      '--offline',
      '--include-dev',
      '--workspace',
      'all',
    ])

    expect(code).toBe(0)
    for (const [directory, name] of [
      ['packages/core', '@acme/core'],
      ['packages/ui', '@acme/ui'],
    ]) {
      const bom = JSON.parse(
        await readFile(join(project, directory ?? '', '.cradle/sbom.cdx.json'), 'utf8'),
      ) as CdxBom
      expect(bom.metadata.component.name).toBe(name)
      // The report lands with the code it describes, not under the repository root.
      await expect(
        readFile(join(project, directory ?? '', '.cradle/report.html'), 'utf8'),
      ).resolves.toContain('<!doctype html>')
    }
    expect(out).toContain('@acme/core')
    expect(out).toContain('@acme/ui')
  })

  it('agrees with the repository-wide scan about every version', async () => {
    // The point of slicing rather than re-resolving. Two reports about the same
    // code that disagree on a version are worse than one report.
    const project = await workingCopy(fixture('npm-workspaces'))
    await run(['scan', project, '--offline', '--include-dev'])
    await run(['scan', project, '--offline', '--include-dev', '--workspace', 'all'])

    const repo = JSON.parse(
      await readFile(join(project, '.cradle/sbom.cdx.json'), 'utf8'),
    ) as CdxBom
    const repoVersions = new Map(repo.components.map((c) => [c.name, c.version]))

    for (const directory of ['packages/core', 'packages/ui']) {
      const bom = JSON.parse(
        await readFile(join(project, directory, '.cradle/sbom.cdx.json'), 'utf8'),
      ) as CdxBom
      for (const component of bom.components) {
        expect(repoVersions.get(component.name), component.name).toBe(component.version)
      }
    }
  })

  it('shortens the route to start at the package rather than the repository', async () => {
    const project = await workingCopy(fixture('npm-vulnerable-workspaces'))
    await run(['scan', project, '--include-dev'])
    await run(['scan', project, '--include-dev', '--workspace', 'all'])

    const repo = JSON.parse(
      await readFile(join(project, '.cradle/findings.json'), 'utf8'),
    ) as FindingsDocument
    const member = JSON.parse(
      await readFile(join(project, 'packages/api/.cradle/findings.json'), 'utf8'),
    ) as FindingsDocument

    expect(member.findings.length).toBeGreaterThan(0)
    expect(member.project.name).toBe('@acme/api')
    for (const finding of member.findings) {
      // The route now begins at the package a team owns.
      expect(finding.path[0]).toBe('@acme/api')
    }
    for (const finding of repo.findings) {
      expect(finding.path[0]).not.toBe('@acme/api')
    }
  })

  it('writes a schema-valid SBOM for every package', async () => {
    const project = await workingCopy(PNPM_MONOREPO)
    const { code } = await run([
      'scan',
      project,
      '--offline',
      '--include-dev',
      '--workspace',
      'all',
    ])
    expect(code).toBe(0)

    for (const directory of ['packages/api', 'packages/shared', 'apps/web']) {
      const bom = JSON.parse(
        await readFile(join(project, directory, '.cradle/sbom.cdx.json'), 'utf8'),
      ) as CdxBom
      const { valid, errors } = validateBom(bom, '1.6')
      expect(errors.slice(0, 3), directory).toEqual([])
      expect(valid).toBe(true)

      // Every edge still points at something that exists in this narrower graph.
      const refs = new Set([
        bom.metadata.component['bom-ref'],
        ...bom.components.map((component) => component['bom-ref']),
      ])
      for (const dependency of bom.dependencies) {
        expect(refs, dependency.ref).toContain(dependency.ref)
        for (const target of dependency.dependsOn ?? []) {
          expect(refs, `${dependency.ref} -> ${target}`).toContain(target)
        }
      }
    }
  })

  it('keeps a sibling dependency as a component, since it is one', async () => {
    const project = await workingCopy(PNPM_MONOREPO)
    await run(['scan', project, '--offline', '--include-dev', '--workspace', '@corpus/api'])

    const bom = JSON.parse(
      await readFile(join(project, 'packages/api/.cradle/sbom.cdx.json'), 'utf8'),
    ) as CdxBom
    // @corpus/api depends on @corpus/shared. From here it is a dependency like
    // any other - just one you can fix yourself - and zod comes with it.
    const names = bom.components.map((component) => component.name)
    expect(names).toContain('@corpus/shared')
    expect(names).toContain('zod')
  })

  it('applies a suppression recorded at the repository root', async () => {
    // Reading only the package's own vex.json would re-report a finding the team
    // had already ruled on, which is exactly what a VEX file exists to prevent.
    const project = await workingCopy(fixture('npm-vulnerable-workspaces'))
    await run(['scan', project, '--include-dev'])

    const findings = JSON.parse(
      await readFile(join(project, '.cradle/findings.json'), 'utf8'),
    ) as FindingsDocument
    const target = findings.findings[0]
    expect(target).toBeDefined()

    await writeFile(
      join(project, '.cradle/vex.json'),
      JSON.stringify(
        {
          '@context': 'https://openvex.dev/ns/v0.2.0',
          '@id': 'https://acme.example/vex/1',
          author: 'security@acme.example',
          timestamp: '2026-09-26T00:00:00.000Z',
          version: 1,
          statements: [
            {
              vulnerability: { name: target?.id },
              products: [{ '@id': target?.component.purl }],
              status: 'not_affected',
              justification: 'vulnerable_code_not_in_execute_path',
              status_notes: 'Ruled on once, for the whole repository.',
            },
          ],
        },
        null,
        2,
      ),
      'utf8',
    )

    await run(['scan', project, '--include-dev', '--workspace', 'all'])
    const member = JSON.parse(
      await readFile(join(project, 'packages/api/.cradle/findings.json'), 'utf8'),
    ) as FindingsDocument

    expect(member.findings.map((finding) => finding.id)).not.toContain(target?.id)
    expect(member.suppressed.map((finding) => finding.id)).toContain(target?.id)
  })
})

describe('cradle scan --workspace, refusals', () => {
  it('names the packages that do exist when given one that does not', async () => {
    const { code, err } = await run([
      'scan',
      fixture('npm-workspaces'),
      '--offline',
      '--workspace',
      'nope',
    ])
    expect(code).toBe(2)
    expect(err).toContain("No workspace package named 'nope'")
    expect(err).toContain('@acme/core, @acme/ui')
  })

  it('refuses --workspace all together with --output-dir', async () => {
    // Every package would write to the same directory and only the last would
    // survive, which looks like a successful run.
    const { code, err } = await run([
      'scan',
      fixture('npm-workspaces'),
      '--offline',
      '--workspace',
      'all',
      '--output-dir',
      '/tmp/does-not-matter',
    ])
    expect(code).toBe(2)
    expect(err).toContain('cannot be combined with --output-dir')
  })

  it('says so when the project is not a monorepo', async () => {
    const { code, err } = await run([
      'scan',
      fixture('npm-basic'),
      '--offline',
      '--workspace',
      'all',
    ])
    expect(code).toBe(2)
    expect(err).toContain('has no workspace packages')
  })
})

describe('cradle check --workspace', () => {
  it('gates one package, with its baseline in that package’s directory', async () => {
    const project = await workingCopy(fixture('npm-vulnerable-workspaces'))

    // @acme/api carries the advisories; @acme/web depends only on ms.
    const failing = await run(['check', project, '--include-dev', '--workspace', '@acme/api'])
    expect(failing.code).toBe(1)
    expect(failing.out).toContain('@acme/api')

    const clean = await run(['check', project, '--include-dev', '--workspace', '@acme/web'])
    expect(clean.code).toBe(0)

    // Accepting the backlog writes the baseline next to the package, not at the
    // repository root - one team, one decision, one file.
    const accepted = await run([
      'check',
      project,
      '--include-dev',
      '--workspace',
      '@acme/api',
      '--baseline',
    ])
    expect(accepted.code).toBe(0)
    await expect(
      readFile(join(project, 'packages/api/.cradle/baseline.json'), 'utf8'),
    ).resolves.toContain('"entries"')

    // And from there the gate is green, because nothing is new.
    const after = await run(['check', project, '--include-dev', '--workspace', '@acme/api'])
    expect(after.code).toBe(0)
  })

  it('does not let a sibling’s backlog turn another package’s gate red', async () => {
    // The reason a per-package gate is worth having at all.
    const project = await workingCopy(fixture('npm-vulnerable-workspaces'))
    const repo = await run(['check', project, '--include-dev'])
    const web = await run(['check', project, '--include-dev', '--workspace', '@acme/web'])

    expect(repo.code).toBe(1)
    expect(web.code).toBe(0)
  })

  it('refuses --workspace all, and says what to do instead', async () => {
    // A gate has one exit code and one comment; neither can speak for several
    // packages, and pretending otherwise would report a green that means nothing.
    const { code, err } = await run([
      'check',
      fixture('npm-vulnerable-workspaces'),
      '--offline',
      '--workspace',
      'all',
    ])
    expect(code).toBe(2)
    expect(err).toContain('--workspace all is not available')
    expect(err).toContain('cradle check --workspace <name>')
  })

  it('names the packages that exist when given one that does not', async () => {
    const { code, err } = await run([
      'check',
      fixture('npm-vulnerable-workspaces'),
      '--offline',
      '--workspace',
      'nope',
    ])
    expect(code).toBe(2)
    expect(err).toContain("No workspace package named 'nope'")
  })
})
