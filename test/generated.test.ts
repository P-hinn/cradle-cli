import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { SPDX_LICENSE_IDS } from '../src/core/sbom/spdx-ids.generated.js'
import { TOOL_NAME, TOOL_VERSION } from '../src/version.generated.js'

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8')) as Record<string, unknown>
}

/**
 * The generated files are committed so the build stays hermetic. These tests
 * fail if someone changes the source of truth without re-running
 * `npm run generate`.
 */
describe('generated sources are current', () => {
  it('stamps the published name and version into every SBOM', () => {
    const pkg = readJson('../package.json')
    expect(TOOL_NAME).toBe(pkg.name)
    expect(TOOL_VERSION).toBe(pkg.version)
  })

  it('mirrors the SPDX identifiers CycloneDX validates against', () => {
    const schema = readJson('../schema/spdx.schema.json')
    const ids = schema.enum as string[]
    expect(SPDX_LICENSE_IDS.size).toBe(ids.length)
    for (const id of ids) expect(SPDX_LICENSE_IDS.has(id)).toBe(true)
  })
})
