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
})
