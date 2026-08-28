import { existsSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { ARTIFACT_SCHEMA_VERSION } from '../src/index.js'

describe('scaffolding', () => {
  it('exports shared types', () => {
    expect(ARTIFACT_SCHEMA_VERSION).toBe(1)
  })

  it('ships the CycloneDX schemas we validate against', () => {
    for (const file of ['bom-1.6.schema.json', 'bom-1.7.schema.json']) {
      expect(existsSync(new URL(`../schema/${file}`, import.meta.url))).toBe(true)
    }
  })

  it('has an npm fixture with a prod/dev split and a scoped package', () => {
    const lock = JSON.parse(
      readFileSync(new URL('./fixtures/npm-basic/package-lock.json', import.meta.url), 'utf8'),
    ) as { lockfileVersion: number; packages: Record<string, { dev?: boolean }> }
    expect(lock.lockfileVersion).toBe(3)
    expect(lock.packages['node_modules/@sindresorhus/is']).toBeDefined()
    expect(lock.packages['node_modules/chalk']?.dev).toBe(true)
  })

  it('has a workspace fixture containing a package without a license', () => {
    const lock = JSON.parse(
      readFileSync(new URL('./fixtures/npm-workspaces/package-lock.json', import.meta.url), 'utf8'),
    ) as { packages: Record<string, { license?: string; peer?: boolean }> }
    expect(lock.packages['packages/ui']?.license).toBeUndefined()
    expect(lock.packages['node_modules/debug']?.peer).toBe(true)
  })
})
