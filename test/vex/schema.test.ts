import { describe, expect, it } from 'vitest'
import { emptyDocument, serializeDocument, upsertStatement } from '../../src/core/vex/document.js'
import { VEX_JUSTIFICATIONS, type VexDocument, type VexStatement } from '../../src/types/index.js'
import {
  cradleExtensionKeys,
  validateOpenVex,
  withoutCradleExtensions,
} from '../support/schema.js'

const TIMESTAMP = '2026-09-26T09:00:00.000Z'

function statement(overrides: Partial<VexStatement> = {}): VexStatement {
  return {
    vulnerability: { name: 'GHSA-xvch-5gv4-984h', aliases: ['CVE-2021-44906'] },
    products: [{ '@id': 'pkg:npm/minimist@1.2.0' }],
    status: 'not_affected',
    justification: 'vulnerable_code_not_in_execute_path',
    status_notes: 'Only our own CI wrapper parses argv here; no untrusted input reaches minimist.',
    ...overrides,
  }
}

/**
 * An `affected` statement, which is never written by cradle and only reaches
 * vex.json through a hand edit. Built without a justification at all rather than
 * with an explicit undefined, which under exactOptionalPropertyTypes is a
 * different thing.
 */
function affected(overrides: Partial<VexStatement> = {}): VexStatement {
  return {
    vulnerability: { name: 'GHSA-aaaa-bbbb-cccc' },
    products: [{ '@id': 'pkg:npm/minimist@1.2.0' }],
    status: 'affected',
    ...overrides,
  }
}

function document(...statements: VexStatement[]): VexDocument {
  let doc = emptyDocument({
    id: 'https://cradle.example/vex/acme-widget',
    author: 'security@acme.example',
    timestamp: TIMESTAMP,
    tooling: 'cradle-cli/0.0.0',
  })
  for (const entry of statements) {
    doc = upsertStatement(doc, entry, TIMESTAMP).document
  }
  return doc
}

/**
 * `.cradle/vex.json` is the artefact that accrues value: it is committed, reviewed
 * in pull requests, and is what a third party reads to see what was decided. So it
 * is held to the official OpenVEX schema from openvex/spec rather than to our own
 * idea of the shape.
 *
 * The schema also settled a question the documentation had got slightly wrong. It
 * sets `additionalProperties: false` on a statement, which means `cradle:expires`
 * does not merely go **ignored** by a conforming consumer — it makes the document
 * **invalid**. That is a stronger consequence than the README claimed, so both
 * halves are pinned here: without the extension the document validates exactly,
 * and the extension is the only thing that deviates.
 */
describe('vex.json against the official OpenVEX schema', () => {
  it('validates a document with one suppression', () => {
    const { valid, errors } = validateOpenVex(document(statement()))
    expect(errors).toEqual([])
    expect(valid).toBe(true)
  })

  it('validates for every justification the standard defines', () => {
    for (const justification of VEX_JUSTIFICATIONS) {
      const doc = document(
        statement({
          justification,
          vulnerability: { name: `GHSA-0000-0000-${justification.slice(0, 4)}` },
        }),
      )
      const { valid, errors } = validateOpenVex(doc)
      expect(errors, justification).toEqual([])
      expect(valid, justification).toBe(true)
    }
  })

  it('validates a document with several statements', () => {
    const doc = document(
      statement(),
      statement({
        vulnerability: { name: 'GHSA-1111-2222-3333' },
        products: [{ '@id': 'pkg:npm/%40acme/widget@2.0.0' }],
        status: 'affected',
        // Required by the schema for `affected`, and easy to miss by hand: a
        // statement that admits a product is affected has to say what to do
        // about it. cradle only ever writes `not_affected` itself, so this shape
        // reaches the file only through a hand edit.
        action_statement: 'Upgrade to 2.1.0, scheduled for 2026-10-15.',
        status_notes: 'Reachable from the public API.',
      }),
    )
    const { valid, errors } = validateOpenVex(doc)
    expect(errors).toEqual([])
    expect(valid).toBe(true)
  })

  it('shows that an affected statement without an action is invalid', () => {
    // Worth a test rather than a comment: this is the trap for anyone editing
    // vex.json by hand, and cradle's own parser accepts it.
    const doc = document(
      affected({ status_notes: 'known' }),
    )
    const { valid, errors } = validateOpenVex(doc)
    expect(valid).toBe(false)
    expect(errors.join(' ')).toContain('action_statement')
  })

  it('only ever writes not_affected itself', () => {
    // The suppress command exists to record "this does not apply to us". If it
    // ever wrote another status, the assertion above about action_statement would
    // become a live constraint on cradle rather than on hand edits.
    const doc = document(statement())
    expect(doc.statements.map((entry) => entry.status)).toEqual(['not_affected'])
  })

  it('validates what serializeDocument actually writes to disk', () => {
    // The in-memory object and the file are not automatically the same thing: the
    // serialiser reorders keys and drops undefined ones, and the file is what a
    // third party validates.
    const written = JSON.parse(serializeDocument(document(statement())))
    const { valid, errors } = validateOpenVex(written)
    expect(errors).toEqual([])
    expect(valid).toBe(true)
  })

  it('numbers an empty document below the schema minimum, and never writes one', () => {
    // emptyDocument starts at version 0 with no statements so the first
    // suppression produces version 1 — but the schema requires version >= 1 and
    // at least one statement, so that intermediate state must never be written.
    const empty = emptyDocument({ id: 'x', author: 'a@b.example', timestamp: TIMESTAMP })
    expect(empty.version).toBe(0)
    expect(validateOpenVex(empty).valid).toBe(false)

    const withOne = upsertStatement(empty, statement(), TIMESTAMP).document
    expect(withOne.version).toBe(1)
    expect(validateOpenVex(withOne).valid).toBe(true)
  })
})

describe('the cradle:expires extension', () => {
  const withExpiry = document(statement({ 'cradle:expires': '2027-03-31' } as VexStatement))

  it('is the only thing in the document that is not plain OpenVEX', () => {
    expect(cradleExtensionKeys(withExpiry)).toEqual(['.statements[0].cradle:expires'])
  })

  it('makes the document fail the official schema, rather than being ignored', () => {
    // Worth stating plainly: OpenVEX has no extension point. `additionalProperties:
    // false` on a statement means a consumer validating strictly rejects the whole
    // file, not just the unknown key. The prefix keeps it recognisable as ours; it
    // does not make it tolerated.
    const { valid, errors } = validateOpenVex(withExpiry)
    expect(valid).toBe(false)
    expect(errors.join(' ')).toContain('cradle:expires')
  })

  it('leaves a document that validates exactly once it is stripped', () => {
    // This is the part that matters: the deviation is one key, not a divergent
    // shape. Everything else is conforming OpenVEX.
    const { valid, errors } = validateOpenVex(withoutCradleExtensions(withExpiry))
    expect(errors).toEqual([])
    expect(valid).toBe(true)
  })
})
