import { readdirSync, readFileSync } from 'node:fs'
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

describe('scripts that run during the build', () => {
  const scripts = readdirSync(new URL('../scripts/', import.meta.url)).filter((file) =>
    file.endsWith('.mjs'),
  )

  it.each(scripts)('%s builds paths with fileURLToPath, not URL.pathname', (script) => {
    // On Windows, `new URL(…).pathname` yields "/D:/a/project/x.mjs" — a leading
    // slash in front of the drive letter, which node cannot execute and fs
    // cannot open. It cost a red build the first time CI ran on Windows, and it
    // is invisible on every other platform, so a grep is the only cheap guard.
    const source = readFileSync(new URL(`../scripts/${script}`, import.meta.url), 'utf8')
    expect(source, script).not.toMatch(/new URL\([^)]*\)\.pathname/)
  })
})
