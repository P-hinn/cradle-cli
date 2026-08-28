import { describe, expect, it } from 'vitest'
import { scoreCvssV3 } from '../../src/core/vulns/cvss.js'

describe('scoreCvssV3', () => {
  it.each([
    // The advisory cradle itself surfaces first: CVE-2020-8203 in lodash.
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H', 7.4],
    // Published FIRST examples.
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', 5.5],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N', 0],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
  ])('scores %s as %s', (vector, expected) => {
    expect(scoreCvssV3(vector)?.score).toBe(expected)
  })

  it('reports which version of the formula it used', () => {
    expect(scoreCvssV3('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')?.version).toBe('3.0')
    expect(scoreCvssV3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')?.version).toBe('3.1')
  })

  it('declines vectors it cannot score exactly', () => {
    // Guessing at a v2 or v4 score would be worse than falling back to the label.
    expect(scoreCvssV3('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeNull()
    expect(scoreCvssV3('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H')).toBeNull()
    expect(scoreCvssV3('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull()
    expect(scoreCvssV3('nonsense')).toBeNull()
  })
})
