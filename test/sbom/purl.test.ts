import { describe, expect, it } from 'vitest'
import { npmPurl } from '../../src/core/sbom/purl.js'

describe('npmPurl', () => {
  it('encodes the @ of a scoped package', () => {
    // The case the spec calls out: the scope is the namespace including the @,
    // which has to be percent-encoded.
    expect(npmPurl('@sindresorhus/is', '7.0.1')).toBe('pkg:npm/%40sindresorhus/is@7.0.1')
  })

  it('leaves an unscoped package alone', () => {
    expect(npmPurl('debug', '4.3.7')).toBe('pkg:npm/debug@4.3.7')
  })

  it('lowercases the name, as the purl spec requires for npm', () => {
    expect(npmPurl('UPPER-Case', '1.0.0')).toBe('pkg:npm/upper-case@1.0.0')
  })

  it('encodes a prerelease version', () => {
    expect(npmPurl('debug', '5.0.0-beta.1')).toBe('pkg:npm/debug@5.0.0-beta.1')
  })
})
