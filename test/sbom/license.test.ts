import { describe, expect, it } from 'vitest'
import { normalizeLicense, toCycloneDx } from '../../src/core/sbom/license.js'

describe('normalizeLicense', () => {
  it('recognises a plain SPDX identifier', () => {
    expect(normalizeLicense({ license: 'MIT' })).toEqual([{ kind: 'id', id: 'MIT' }])
  })

  it('keeps a compound expression as an expression', () => {
    expect(normalizeLicense({ license: '(MIT OR Apache-2.0)' })).toEqual([
      { kind: 'expression', expression: '(MIT OR Apache-2.0)' },
    ])
  })

  it('keeps an identifier with an exception as an expression', () => {
    expect(normalizeLicense({ license: 'GPL-2.0-only WITH Classpath-exception-2.0' })).toEqual([
      { kind: 'expression', expression: 'GPL-2.0-only WITH Classpath-exception-2.0' },
    ])
  })

  it('falls back to a free-text name for non-SPDX text', () => {
    expect(normalizeLicense({ license: 'SEE LICENSE IN LICENSE.md' })).toEqual([
      { kind: 'name', name: 'SEE LICENSE IN LICENSE.md' },
    ])
  })

  it("treats npm's UNLICENSED as declared intent, not as unknown", () => {
    expect(normalizeLicense({ license: 'UNLICENSED' })).toEqual([
      { kind: 'name', name: 'UNLICENSED' },
    ])
  })

  it('reads the legacy license object form', () => {
    expect(normalizeLicense({ license: { type: 'ISC', url: 'https://example.test' } })).toEqual([
      { kind: 'id', id: 'ISC' },
    ])
  })

  it('reads the legacy licenses array form', () => {
    expect(normalizeLicense({ licenses: [{ type: 'MIT' }, { type: 'Apache-2.0' }] })).toEqual([
      { kind: 'id', id: 'MIT' },
      { kind: 'id', id: 'Apache-2.0' },
    ])
  })

  it('returns nothing when no licence is declared, so the gap stays visible', () => {
    expect(normalizeLicense({})).toEqual([])
    expect(normalizeLicense({ license: '   ' })).toEqual([])
    expect(normalizeLicense({ license: 42 })).toEqual([])
  })
})

describe('toCycloneDx', () => {
  it('renders each kind into the shape CycloneDX expects', () => {
    expect(
      toCycloneDx([
        { kind: 'id', id: 'MIT' },
        { kind: 'expression', expression: '(MIT OR ISC)' },
        { kind: 'name', name: 'UNLICENSED' },
      ]),
    ).toEqual([
      { license: { id: 'MIT' } },
      { expression: '(MIT OR ISC)' },
      { license: { name: 'UNLICENSED' } },
    ])
  })
})
