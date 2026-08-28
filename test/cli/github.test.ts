import { describe, expect, it } from 'vitest'
import { findManifestLine, toAnnotations } from '../../src/cli/github.js'
import type { Finding } from '../../src/types/index.js'

const MANIFEST = `{
  "name": "app",
  "version": "1.0.0",
  "main": "lodash",
  "dependencies": {
    "lodash": "4.17.15",
    "minimist": "1.2.0"
  },
  "devDependencies": {
    "vitest": "^4"
  }
}
`

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'GHSA-p6mc-m468-83gw',
    aliases: ['CVE-2020-8203'],
    summary: 'Prototype Pollution in lodash',
    severity: 'high',
    severitySource: 'cvss',
    component: {
      bomRef: 'pkg:npm/lodash@4.17.15',
      name: 'lodash',
      version: '4.17.15',
      purl: 'pkg:npm/lodash@4.17.15',
      direct: true,
    },
    path: ['app', 'lodash'],
    dependents: ['app'],
    references: [],
    osvUrl: 'https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw',
    fixedIn: '4.17.19',
    ...overrides,
  }
}

describe('findManifestLine', () => {
  it('finds a dependency by its line', () => {
    expect(findManifestLine(MANIFEST, 'lodash')).toBe(6)
    expect(findManifestLine(MANIFEST, 'minimist')).toBe(7)
  })

  it('finds a dev dependency too', () => {
    expect(findManifestLine(MANIFEST, 'vitest')).toBe(10)
  })

  it('does not mistake a value for a key', () => {
    // "main": "lodash" is on line 4 and must not win over the real dependency.
    expect(findManifestLine(MANIFEST, 'lodash')).not.toBe(4)
  })

  it('returns nothing for a transitive package, which is declared nowhere', () => {
    expect(findManifestLine(MANIFEST, 'ms')).toBeUndefined()
  })
})

describe('toAnnotations', () => {
  it('anchors a direct dependency to its line in package.json', () => {
    // An annotation on the line you can change gets read; one on line 1 does not.
    const [annotation] = toAnnotations([finding()], {
      manifest: MANIFEST,
      manifestPath: 'package.json',
    })
    expect(annotation).toContain('file=package.json')
    expect(annotation).toContain('line=6')
    expect(annotation).toContain('::high: GHSA-p6mc-m468-83gw in lodash 4.17.15')
    expect(annotation).toContain('fixed in lodash 4.17.19')
    expect(annotation).toContain('https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw')
  })

  it('names the route instead of a file for a transitive dependency', () => {
    const [annotation] = toAnnotations(
      [
        finding({
          component: {
            bomRef: 'pkg:npm/ms@2.1.3',
            name: 'ms',
            version: '2.1.3',
            purl: 'pkg:npm/ms@2.1.3',
            direct: false,
          },
          path: ['app', 'debug', 'ms'],
        }),
      ],
      { manifest: MANIFEST, manifestPath: 'package.json' },
    )
    expect(annotation).not.toContain('file=')
    expect(annotation).toContain('via app > debug > ms')
  })

  it('says so plainly when there is no fix', () => {
    const withoutFix = finding()
    delete withoutFix.fixedIn
    const [annotation] = toAnnotations([withoutFix])
    expect(annotation).toContain('no fix available yet')
  })

  it('escapes the characters the workflow-command format reserves', () => {
    // An unescaped newline or colon would truncate or corrupt the annotation.
    const [annotation] = toAnnotations([
      finding({ id: 'GHSA-a:b,c', summary: 'line one\nline two 100%' }),
    ])
    expect(annotation).toContain('GHSA-a%3Ab%2Cc')
    expect(annotation?.split('\n')).toHaveLength(1)
    expect(annotation).not.toContain('100%:')
  })
})
