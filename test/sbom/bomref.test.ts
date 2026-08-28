import { describe, expect, it } from 'vitest'
import { assignBomRefs } from '../../src/core/sbom/bomref.js'

describe('assignBomRefs', () => {
  it('uses the bare purl while it is unique', () => {
    const refs = assignBomRefs([
      { location: 'node_modules/debug', name: 'debug', version: '4.3.7' },
      { location: 'node_modules/ms', name: 'ms', version: '2.1.3' },
    ])
    expect(refs.get('node_modules/debug')).toBe('pkg:npm/debug@4.3.7')
    expect(refs.get('node_modules/ms')).toBe('pkg:npm/ms@2.1.3')
  })

  it('keeps different versions of one package apart on the purl alone', () => {
    const refs = assignBomRefs([
      { location: 'node_modules/ms', name: 'ms', version: '2.0.0' },
      { location: 'node_modules/debug/node_modules/ms', name: 'ms', version: '2.1.3' },
    ])
    expect([...new Set(refs.values())]).toHaveLength(2)
  })

  it('disambiguates the same name@version at two locations', () => {
    // Without this, every edge to either copy would collapse onto one node and
    // the dependencies block would quietly describe a different tree.
    const refs = assignBomRefs([
      { location: 'node_modules/ms', name: 'ms', version: '2.1.3' },
      { location: 'packages/ui/node_modules/ms', name: 'ms', version: '2.1.3' },
    ])
    expect(refs.get('node_modules/ms')).toBe('pkg:npm/ms@2.1.3#node_modules/ms')
    expect(refs.get('packages/ui/node_modules/ms')).toBe(
      'pkg:npm/ms@2.1.3#packages/ui/node_modules/ms',
    )
    expect(new Set(refs.values()).size).toBe(2)
  })

  it('encodes a scoped name in the ref', () => {
    const refs = assignBomRefs([{ location: 'packages/ui', name: '@acme/ui', version: '0.4.2' }])
    expect(refs.get('packages/ui')).toBe('pkg:npm/%40acme/ui@0.4.2')
  })
})
