import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { parseIntegrity } from '../../src/core/sbom/hash.js'

/** Build a real SRI string so the test is not asserting against a made-up digest. */
function sri(alg: 'sha1' | 'sha256' | 'sha512', payload: string): { sri: string; hex: string } {
  const digest = createHash(alg).update(payload).digest()
  return { sri: `${alg}-${digest.toString('base64')}`, hex: digest.toString('hex') }
}

describe('parseIntegrity', () => {
  it('converts npm base64 integrity into the hex CycloneDX requires', () => {
    const { sri: input, hex } = sri('sha512', 'cradle')
    expect(parseIntegrity(input)).toEqual([{ alg: 'SHA-512', content: hex }])
  })

  it('maps sha1 to the CycloneDX spelling, for older lockfiles', () => {
    const { sri: input, hex } = sri('sha1', 'cradle')
    expect(parseIntegrity(input)).toEqual([{ alg: 'SHA-1', content: hex }])
  })

  it('reads every entry of a multi-hash SRI string', () => {
    const a = sri('sha512', 'cradle')
    const b = sri('sha256', 'cradle')
    expect(parseIntegrity(`${a.sri} ${b.sri}`)).toEqual([
      { alg: 'SHA-512', content: a.hex },
      { alg: 'SHA-256', content: b.hex },
    ])
  })

  it('returns nothing when there is no integrity', () => {
    expect(parseIntegrity(undefined)).toEqual([])
    expect(parseIntegrity(null)).toEqual([])
    expect(parseIntegrity('')).toEqual([])
  })

  it('drops entries it cannot trust rather than emitting a wrong hash', () => {
    expect(parseIntegrity('rot13-abcdef')).toEqual([]) // unknown algorithm
    expect(parseIntegrity('sha512-dHJ1bmNhdGVk')).toEqual([]) // wrong digest length
    expect(parseIntegrity('nonsense')).toEqual([]) // no algorithm prefix
  })
})
