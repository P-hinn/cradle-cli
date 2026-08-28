import { describe, expect, it } from 'vitest'
import { CradleError } from '../../src/core/errors.js'
import { parseConfig } from '../../src/core/readiness/config.js'

function fails(raw: string): CradleError {
  try {
    parseConfig(raw, 'config.json')
  } catch (error) {
    if (error instanceof CradleError) return error
    throw error
  }
  throw new Error('expected a CradleError')
}

describe('parseConfig', () => {
  it('reads the settings it knows', () => {
    expect(
      parseConfig(
        JSON.stringify({
          productName: 'Acme Widget',
          contactEmail: 'security@acme.example',
          placedOnMarket: '2026-01-15',
          supportPeriodEnd: '2031-01-15',
        }),
        'config.json',
      ),
    ).toEqual({
      productName: 'Acme Widget',
      contactEmail: 'security@acme.example',
      placedOnMarket: '2026-01-15',
      supportPeriodEnd: '2031-01-15',
    })
  })

  it('accepts an empty object, since every setting is optional', () => {
    expect(parseConfig('{}', 'config.json')).toEqual({})
  })

  it('rejects a key it does not know, rather than silently ignoring it', () => {
    // A misspelt "supportPeriodEnd" would otherwise leave the check reporting
    // "not documented" while the user is sure they documented it.
    const error = fails(JSON.stringify({ supportPeriodEndd: '2031-01-15' }))
    expect(error.message).toContain('supportPeriodEndd')
    expect(error.hint).toContain('supportPeriodEnd')
  })

  it('rejects a date it cannot read', () => {
    expect(fails(JSON.stringify({ supportPeriodEnd: 'in five years' })).message).toContain(
      'supportPeriodEnd',
    )
  })

  it('rejects a value of the wrong type', () => {
    expect(fails(JSON.stringify({ contactEmail: 42 })).message).toContain('must be a string')
  })

  it('fails loudly on malformed JSON, but says the file is optional', () => {
    const error = fails('{oops')
    expect(error.message).toContain('not valid JSON')
    expect(error.hint).toContain('runs fine without it')
  })
})
