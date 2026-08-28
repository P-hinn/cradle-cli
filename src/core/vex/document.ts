import {
  OPENVEX_CONTEXT,
  VEX_JUSTIFICATIONS,
  type VexDocument,
  type VexJustification,
  type VexStatement,
  type VexStatus,
} from '../../types/index.js'
import { CradleError } from '../errors.js'

const STATUSES: readonly VexStatus[] = ['not_affected', 'affected', 'fixed', 'under_investigation']

export function isJustification(value: string): value is VexJustification {
  return (VEX_JUSTIFICATIONS as readonly string[]).includes(value)
}

export function emptyDocument(options: {
  id: string
  author: string
  timestamp: string
  tooling?: string
}): VexDocument {
  const document: VexDocument = {
    '@context': OPENVEX_CONTEXT,
    '@id': options.id,
    author: options.author,
    timestamp: options.timestamp,
    // Zero, not one: the first upsertStatement bumps it, so the file a user
    // first sees is version 1 with one statement in it.
    version: 0,
    statements: [],
  }
  if (options.tooling !== undefined) document.tooling = options.tooling
  return document
}

/**
 * Parse a `.cradle/vex.json` written by anyone: us, a hand edit, another tool.
 *
 * This file is the artefact that accrues value over time and lives in the user's
 * git repository, so a malformed one has to fail loudly and say what is wrong,
 * never be silently ignored. Ignoring it would mean quietly re-reporting
 * findings the team had already ruled on.
 */
export function parseDocument(raw: string, source: string): VexDocument {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (cause) {
    throw new CradleError(`${source} is not valid JSON`, 'Fix or delete the file, then re-run.', {
      cause,
    })
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new CradleError(`${source} is not an OpenVEX document`, 'Expected a JSON object.')
  }

  const document = parsed as Partial<VexDocument>
  if (typeof document.author !== 'string' || document.author === '') {
    throw new CradleError(
      `${source} has no "author"`,
      'OpenVEX requires an author. Add one, or recreate the file with `cradle suppress --author ...`.',
    )
  }
  if (!Array.isArray(document.statements)) {
    throw new CradleError(
      `${source} has no "statements" array`,
      'An OpenVEX document must carry a statements list, even an empty one.',
    )
  }

  const statements = document.statements.map((statement, index) =>
    validateStatement(statement, `${source} statement ${index + 1}`),
  )

  return {
    '@context': OPENVEX_CONTEXT,
    '@id': typeof document['@id'] === 'string' ? document['@id'] : '',
    author: document.author,
    ...(typeof document.role === 'string' ? { role: document.role } : {}),
    timestamp: typeof document.timestamp === 'string' ? document.timestamp : '',
    ...(typeof document.last_updated === 'string' ? { last_updated: document.last_updated } : {}),
    version: typeof document.version === 'number' ? document.version : 1,
    ...(typeof document.tooling === 'string' ? { tooling: document.tooling } : {}),
    statements,
  }
}

function validateStatement(value: unknown, where: string): VexStatement {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new CradleError(
      `${where} is not an object`,
      'Each entry of "statements" must be an object.',
    )
  }
  const statement = value as Partial<VexStatement>

  const name = statement.vulnerability?.name
  if (typeof name !== 'string' || name === '') {
    throw new CradleError(
      `${where} names no vulnerability`,
      'Every statement needs a "vulnerability" object with a "name", such as CVE-2020-8203.',
    )
  }

  const status = statement.status
  if (status === undefined || !STATUSES.includes(status)) {
    throw new CradleError(
      `${where} has an unknown status ${JSON.stringify(status)}`,
      `Use one of: ${STATUSES.join(', ')}.`,
    )
  }

  // The one place OpenVEX is strict, and the one that matters most here: a
  // suppression has to say why.
  if (
    status === 'not_affected' &&
    (statement.justification === undefined || !isJustification(statement.justification)) &&
    (typeof statement.impact_statement !== 'string' || statement.impact_statement === '')
  ) {
    throw new CradleError(
      `${where} declares not_affected without a justification`,
      'OpenVEX requires a justification or an impact_statement for not_affected. ' +
        `Valid justifications: ${VEX_JUSTIFICATIONS.join(', ')}.`,
    )
  }

  const expires = statement['cradle:expires']
  if (expires !== undefined && Number.isNaN(Date.parse(expires))) {
    throw new CradleError(
      `${where} has an unreadable "cradle:expires" value ${JSON.stringify(expires)}`,
      'Use an ISO date, for example 2027-03-31.',
    )
  }

  return statement as VexStatement
}

/**
 * Add a statement, or replace the one that already covers the same vulnerability
 * and the same products.
 *
 * Replacing rather than appending is deliberate: re-running `suppress` for the
 * same pair should read as a correction, not leave two contradictory statements
 * for a reviewer to reconcile.
 */
export function upsertStatement(
  document: VexDocument,
  statement: VexStatement,
  timestamp: string,
): { document: VexDocument; replaced: boolean } {
  const key = (candidate: VexStatement): string =>
    `${candidate.vulnerability.name} ${(candidate.products ?? [])
      .map((product) => product['@id'])
      .sort()
      .join(',')}`

  const target = key(statement)
  const statements = [...document.statements]
  const index = statements.findIndex((existing) => key(existing) === target)
  if (index === -1) statements.push(statement)
  else statements[index] = statement

  return {
    document: { ...document, version: document.version + 1, last_updated: timestamp, statements },
    replaced: index !== -1,
  }
}

/**
 * Serialise with a stable key order.
 *
 * This file is reviewed in pull requests, so the diff between two versions
 * should show what changed, not where the serialiser happened to put a key.
 */
export function serializeDocument(document: VexDocument): string {
  const ordered = {
    '@context': document['@context'],
    '@id': document['@id'],
    author: document.author,
    ...(document.role === undefined ? {} : { role: document.role }),
    timestamp: document.timestamp,
    ...(document.last_updated === undefined ? {} : { last_updated: document.last_updated }),
    version: document.version,
    ...(document.tooling === undefined ? {} : { tooling: document.tooling }),
    statements: document.statements,
  }
  return `${JSON.stringify(ordered, null, 2)}\n`
}
