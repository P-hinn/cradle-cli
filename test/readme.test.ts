import { existsSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
/** Prose is hard-wrapped, so phrase checks run against a flattened copy. */
const PROSE = README.replace(/\s+/g, ' ')

/**
 * The README is the first thing anyone sees and the easiest thing to let rot.
 * These check the claims that would be embarrassing to get wrong, and the links
 * that would 404.
 */
describe('README', () => {
  it('has no leftover placeholders', () => {
    expect(README).not.toMatch(/TODO|FIXME|XXX|TBD/)
  })

  it('links only to files that exist', () => {
    const targets = [...README.matchAll(/\]\((?!https?:|#)([^)]+)\)/g)]
      .map((match) => (match[1] ?? '').split('#')[0])
      .filter((target): target is string => target !== undefined && target !== '')

    expect(targets.length).toBeGreaterThan(0)
    for (const target of targets) {
      expect(existsSync(new URL(`../${target}`, import.meta.url)), target).toBe(true)
    }
  })

  it('shows a demo image that is in the repository and fetches nothing', () => {
    const match = README.match(/<img src="([^"]+)"/)
    expect(match?.[1]).toBe('assets/demo.svg')

    const svg = readFileSync(new URL('../assets/demo.svg', import.meta.url), 'utf8')
    // The XML namespace is a name, not a request; anything else would be one.
    const urls = [...svg.matchAll(/https?:\/\/[^"' ]+/g)].map((m) => m[0])
    expect(urls).toEqual(['http://www.w3.org/2000/svg'])
    expect(svg).not.toMatch(/<image|xlink:href|@import/)
  })

  it('states the version-dependent facts consistently with package.json', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      engines: { node: string }
      dependencies: Record<string, string>
    }

    expect(README).toContain(`runtime%20deps-${Object.keys(pkg.dependencies).length}`)
    expect(pkg.engines.node).toBe('>=22.9.0')
    expect(PROSE).toContain('Node.js 22.9 or newer')
  })

  it('keeps the disclaimer', () => {
    expect(PROSE).toContain('not legal advice')
    expect(PROSE).toContain('not a conformity assessment')
  })

  it('documents every command the CLI actually has', () => {
    // A README that lists three commands for a tool with four is the first thing
    // a reader stops trusting.
    for (const command of ['cradle scan', 'cradle check', 'cradle suppress', 'cradle notify']) {
      expect(README, command).toContain(command)
    }
  })

  it('lists the flags the commands accept', () => {
    for (const flag of [
      '--sbom-format',
      '--vex-format',
      '--lang',
      '--workspace',
      '--profile',
      '--timestamp',
      '--serial-number',
      '--sort',
      '--no-priority',
      '--stage',
    ]) {
      expect(README, flag).toContain(flag)
    }
  })

  it('no longer claims SPDX is out of scope, since it is not', () => {
    // It was on the "what it does not do" list until the export existed. A stale
    // exclusion is worse than a missing feature: it tells people not to look.
    const exclusions = PROSE.slice(PROSE.indexOf('What it does not do'), PROSE.indexOf('## In CI'))
    expect(exclusions).not.toMatch(/SPDX output\. CycloneDX 1\.6 and 1\.7 only/)
    expect(PROSE).toContain('--sbom-format spdx')
  })

  it('states the Article 14 deadlines with the clock each one runs on', () => {
    // The final report is 14 days from a measure becoming available, not from
    // becoming aware. Most summaries get this wrong.
    expect(PROSE).toContain('24 hours')
    expect(PROSE).toContain('72 hours')
    expect(PROSE).toContain('corrective or mitigating measure becoming available')
  })

  it('says cradle does not decide that a report is owed', () => {
    expect(PROSE).toContain('does not decide that you owe a report')
    expect(PROSE).toContain('actively exploited')
  })

  it('names the BSI guideline version it checks against', () => {
    // If the guideline moves, this and the profile have to move together.
    expect(PROSE).toContain('BSI TR-03183-2')
    expect(PROSE).toContain('version 2.1.0')
  })

  it('records every network destination in both places', () => {
    // SECURITY.md is where a static analyser's reader looks; the README is where
    // everyone else does. They must not disagree about what leaves the machine.
    const security = readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8')
    for (const host of ['api.osv.dev', 'registry.npmjs.org', 'api.first.org', 'cisa.gov']) {
      expect(README, host).toContain(host)
      expect(security, host).toContain(host)
    }
  })

  it('keeps the promise that only CVE ids reach the exploit sources', () => {
    expect(PROSE).toContain('no package name, no version, nothing about your project')
  })
})
