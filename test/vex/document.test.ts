import { describe, expect, it } from 'vitest'
import { CradleError } from '../../src/core/errors.js'
import {
  emptyDocument,
  parseDocument,
  serializeDocument,
  upsertStatement,
} from '../../src/core/vex/document.js'
import type { VexDocument, VexStatement } from '../../src/types/index.js'

const AUTHOR = 'someone@example.test'
const TIMESTAMP = '2026-08-28T00:00:00.000Z'

function statement(overrides: Partial<VexStatement> = {}): VexStatement {
  return {
    vulnerability: { name: 'GHSA-p6mc-m468-83gw' },
    products: [{ '@id': 'pkg:npm/lodash@4.17.15' }],
    status: 'not_affected',
    justification: 'vulnerable_code_not_present',
    ...overrides,
  }
}

function fails(run: () => unknown): CradleError {
  try {
    run()
  } catch (error) {
    if (error instanceof CradleError) return error
    throw error
  }
  throw new Error('expected a CradleError')
}

describe('emptyDocument', () => {
  it('declares the OpenVEX context version it conforms to', () => {
    const document = emptyDocument({ id: 'urn:uuid:x', author: AUTHOR, timestamp: TIMESTAMP })
    expect(document['@context']).toBe('https://openvex.dev/ns/v0.2.0')
  })

  it('starts at version zero, so the first statement produces version 1', () => {
    const document = emptyDocument({ id: 'urn:uuid:x', author: AUTHOR, timestamp: TIMESTAMP })
    const { document: written } = upsertStatement(document, statement(), TIMESTAMP)
    expect(written.version).toBe(1)
  })
})

describe('parseDocument', () => {
  it('reads a document we wrote ourselves', () => {
    const original = upsertStatement(
      emptyDocument({ id: 'urn:uuid:x', author: AUTHOR, timestamp: TIMESTAMP }),
      statement(),
      TIMESTAMP,
    ).document
    const round = parseDocument(serializeDocument(original), 'vex.json')
    expect(round).toEqual(original)
  })

  it('refuses a not_affected statement with no justification', () => {
    // The whole point of the category is that a suppression can be reviewed.
    const raw = JSON.stringify({
      author: AUTHOR,
      statements: [{ vulnerability: { name: 'CVE-1' }, status: 'not_affected' }],
    })
    const error = fails(() => parseDocument(raw, 'vex.json'))
    expect(error.message).toContain('not_affected without a justification')
    expect(error.hint).toContain('component_not_present')
  })

  it('accepts an impact_statement in place of a justification, as OpenVEX allows', () => {
    const raw = JSON.stringify({
      author: AUTHOR,
      statements: [
        {
          vulnerability: { name: 'CVE-1' },
          status: 'not_affected',
          impact_statement: 'The parser is never given untrusted input.',
        },
      ],
    })
    expect(parseDocument(raw, 'vex.json').statements).toHaveLength(1)
  })

  it('names the offending statement, not just the file', () => {
    const raw = JSON.stringify({
      author: AUTHOR,
      statements: [statement(), { vulnerability: { name: 'CVE-2' }, status: 'made_up' }],
    })
    expect(fails(() => parseDocument(raw, 'vex.json')).message).toContain('statement 2')
  })

  it('rejects a document with no author', () => {
    // An unattributed suppression is worth little in an audit.
    const error = fails(() => parseDocument(JSON.stringify({ statements: [] }), 'vex.json'))
    expect(error.message).toContain('no "author"')
  })

  it('rejects an unreadable expiry rather than treating it as "never"', () => {
    const raw = JSON.stringify({
      author: AUTHOR,
      statements: [statement({ 'cradle:expires': 'next tuesday' })],
    })
    expect(fails(() => parseDocument(raw, 'vex.json')).message).toContain('cradle:expires')
  })

  it('fails loudly on malformed JSON instead of ignoring the file', () => {
    // Skipping it silently would re-report findings the team already ruled on.
    const error = fails(() => parseDocument('{not json', 'vex.json'))
    expect(error.message).toContain('not valid JSON')
  })

  it.each([
    ['a bare array', '[]'],
    ['a string', '"hello"'],
    ['null', 'null'],
  ])('rejects %s', (_label, raw) => {
    expect(() => parseDocument(raw, 'vex.json')).toThrow(CradleError)
  })
})

describe('upsertStatement', () => {
  const base = emptyDocument({ id: 'urn:uuid:x', author: AUTHOR, timestamp: TIMESTAMP })

  it('replaces the statement covering the same vulnerability and products', () => {
    // Re-running suppress is how a justification gets corrected; two
    // contradictory statements would leave a reviewer to guess which applies.
    const first = upsertStatement(base, statement({ status_notes: 'first take' }), TIMESTAMP)
    const second = upsertStatement(
      first.document,
      statement({ status_notes: 'corrected' }),
      TIMESTAMP,
    )

    expect(second.replaced).toBe(true)
    expect(second.document.statements).toHaveLength(1)
    expect(second.document.statements[0]?.status_notes).toBe('corrected')
  })

  it('keeps statements about different components apart', () => {
    const first = upsertStatement(base, statement(), TIMESTAMP)
    const second = upsertStatement(
      first.document,
      statement({ products: [{ '@id': 'pkg:npm/minimist@1.2.0' }] }),
      TIMESTAMP,
    )
    expect(second.replaced).toBe(false)
    expect(second.document.statements).toHaveLength(2)
  })

  it('bumps the version and stamps last_updated on every write', () => {
    const first = upsertStatement(base, statement(), TIMESTAMP)
    const second = upsertStatement(first.document, statement({ status_notes: 'x' }), TIMESTAMP)
    expect(second.document.version).toBe(2)
    expect(second.document.last_updated).toBe(TIMESTAMP)
  })
})

describe('serializeDocument', () => {
  it('writes keys in a fixed order, so pull-request diffs stay readable', () => {
    const document: VexDocument = {
      ...upsertStatement(
        emptyDocument({
          id: 'urn:uuid:x',
          author: AUTHOR,
          timestamp: TIMESTAMP,
          tooling: 'cradle-cli/0.0.0',
        }),
        statement(),
        TIMESTAMP,
      ).document,
    }
    const keys = Object.keys(JSON.parse(serializeDocument(document)) as object)
    expect(keys).toEqual([
      '@context',
      '@id',
      'author',
      'timestamp',
      'last_updated',
      'version',
      'tooling',
      'statements',
    ])
  })

  it('ends with a newline, so the file plays well with git', () => {
    const document = emptyDocument({ id: 'urn:uuid:x', author: AUTHOR, timestamp: TIMESTAMP })
    expect(serializeDocument(document).endsWith('}\n')).toBe(true)
  })
})
