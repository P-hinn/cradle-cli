import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import type { RawPackage } from '../../src/core/resolve/graph.js'
import {
  hoistedCandidates,
  pnpmCandidates,
  readLicensesFromDisk,
} from '../../src/core/resolve/licenses.js'

const temporaries: string[] = []
afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

async function scratch(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cradle-licences-'))
  temporaries.push(dir)
  return dir
}

function pkg(overrides: Partial<RawPackage> = {}): RawPackage {
  const name = overrides.name ?? 'lodash'
  return {
    key: `${name}@1.0.0`,
    name,
    version: '1.0.0',
    dependencies: new Map(),
    ...overrides,
  }
}

async function manifest(path: string, body: object): Promise<void> {
  await mkdir(path, { recursive: true })
  await writeFile(join(path, 'package.json'), JSON.stringify(body), 'utf8')
}

describe('readLicensesFromDisk', () => {
  it('reads a hoisted package', async () => {
    const root = await scratch()
    await manifest(join(root, 'node_modules', 'lodash'), { name: 'lodash', license: 'MIT' })

    const found = await readLicensesFromDisk(root, [pkg()], hoistedCandidates)
    expect(found.get('lodash@1.0.0')).toEqual([{ kind: 'id', id: 'MIT' }])
  })

  it("reads a package out of pnpm's .pnpm store, scope and all", async () => {
    const root = await scratch()
    await manifest(
      join(root, 'node_modules', '.pnpm', '@acme+ui@1.0.0', 'node_modules', '@acme', 'ui'),
      { name: '@acme/ui', license: 'Apache-2.0' },
    )

    const found = await readLicensesFromDisk(root, [pkg({ name: '@acme/ui' })], pnpmCandidates)
    expect(found.get('@acme/ui@1.0.0')).toEqual([{ kind: 'id', id: 'Apache-2.0' }])
  })

  it('ignores a manifest for a different package at the same path', async () => {
    // A hoisted path can hold another version, or another package entirely.
    const root = await scratch()
    await manifest(join(root, 'node_modules', 'lodash'), { name: 'something-else', license: 'MIT' })

    const found = await readLicensesFromDisk(root, [pkg()], hoistedCandidates)
    expect(found.size).toBe(0)
  })

  it('refuses to read outside the project directory', async () => {
    // Package names and install locations come out of a lockfile, which is an
    // input like any other. Without containment, a package named ../../secret
    // reads a manifest outside the project and copies its licence into the SBOM.
    const root = await scratch()
    const outside = await scratch()
    await manifest(outside, { name: '../../secret', license: 'PROOF-OF-TRAVERSAL' })

    const escaping = pkg({
      name: '../../secret',
      location: `../${outside.split('/').pop() ?? ''}`,
    })
    const found = await readLicensesFromDisk(root, [escaping], hoistedCandidates)
    expect(found.size).toBe(0)
  })

  it('reports nothing rather than failing when node_modules is absent', async () => {
    // A fresh clone: the licence is unknown, and the readiness check says so.
    const root = await scratch()
    await expect(readLicensesFromDisk(root, [pkg()], hoistedCandidates)).resolves.toEqual(new Map())
  })

  it('skips a manifest that is not valid JSON', async () => {
    const root = await scratch()
    await mkdir(join(root, 'node_modules', 'lodash'), { recursive: true })
    await writeFile(join(root, 'node_modules', 'lodash', 'package.json'), '{oops', 'utf8')

    await expect(readLicensesFromDisk(root, [pkg()], hoistedCandidates)).resolves.toEqual(new Map())
  })
})
