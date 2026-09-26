import { readFileSync } from 'node:fs'
import { Ajv, type ValidateFunction } from 'ajv'
import { Ajv2020 } from 'ajv/dist/2020.js'
import ajvFormats from 'ajv-formats'
import type { CycloneDxSpecVersion } from '../../src/types/index.js'

function load(file: string): object {
  return JSON.parse(readFileSync(new URL(`../../schema/${file}`, import.meta.url), 'utf8'))
}

// ajv-formats is a CommonJS package whose .d.ts declares a default export.
// Under NodeNext that lands as the module namespace rather than the function it
// is at runtime (its index.js does `module.exports = formatsPlugin`), so the
// call signature has to be restated here.
const addFormats = ajvFormats as unknown as (ajv: Ajv) => Ajv

const validators = new Map<CycloneDxSpecVersion, ValidateFunction>()

/**
 * Validate a document against the official CycloneDX schema we vendored under
 * schema/. Nothing here is hand-rolled: if the spec says a field is wrong, this
 * fails, which is the whole point of shipping the schemas.
 */
export function validateBom(
  bom: unknown,
  specVersion: CycloneDxSpecVersion,
): { valid: boolean; errors: string[] } {
  const cached = validators.get(specVersion)
  const validate = cached ?? compile(specVersion)
  if (cached === undefined) validators.set(specVersion, validate)

  const valid = validate(bom)
  const errors = (validate.errors ?? []).map((e) =>
    `${e.instancePath || '/'} ${e.message ?? ''} ${JSON.stringify(e.params)}`.trim(),
  )
  return { valid, errors }
}

function compile(specVersion: CycloneDxSpecVersion): ValidateFunction {
  const ajv = new Ajv({ strict: false, allErrors: true })
  addFormats(ajv)
  // CycloneDX uses two formats ajv-formats does not ship. Both are supersets of
  // types ajv does know, so accepting any string here does not weaken the parts
  // of the schema we actually care about.
  ajv.addFormat('iri-reference', true)
  ajv.addFormat('idn-email', true)

  // The BOM schemas reference these by filename; 1.7 adds cryptography-defs.
  for (const name of [
    'spdx.schema.json',
    'jsf-0.82.schema.json',
    'cryptography-defs.schema.json',
  ]) {
    ajv.addSchema(load(name), name)
  }
  return ajv.compile(load(`bom-${specVersion}.schema.json`))
}

// ---------------------------------------------------------------------------
// OpenVEX
// ---------------------------------------------------------------------------

/** The cradle extension OpenVEX has no field for. See CRADLE_EXPIRES in vex/. */
const CRADLE_PREFIX = 'cradle:'

let openVexValidator: ValidateFunction | undefined

/**
 * Validate against the official OpenVEX JSON Schema, vendored under `schema/`
 * from openvex/spec. It declares draft 2020-12, which needs a different Ajv
 * entry point than the CycloneDX schemas above.
 */
export function validateOpenVex(document: unknown): { valid: boolean; errors: string[] } {
  openVexValidator ??= compileOpenVex()
  const valid = openVexValidator(document)
  const errors = (openVexValidator.errors ?? []).map((e) =>
    `${e.instancePath || '/'} ${e.message ?? ''} ${JSON.stringify(e.params)}`.trim(),
  )
  return { valid, errors }
}

function compileOpenVex(): ValidateFunction {
  const ajv = new Ajv2020({ strict: false, allErrors: true })
  ;(ajvFormats as unknown as (instance: Ajv2020) => void)(ajv)
  // `iri` is not a format ajv-formats ships. It is a superset of uri, so
  // accepting any string here does not weaken the parts under test.
  ajv.addFormat('iri', true)
  ajv.addFormat('iri-reference', true)
  return ajv.compile(load('openvex-0.2.0.schema.json'))
}

/**
 * Strip cradle's own extension keys, so what remains can be held to the official
 * schema exactly.
 *
 * This is not a convenience. The OpenVEX schema sets `additionalProperties:
 * false` on a statement, which means an extension does not merely go ignored by a
 * conforming consumer — it makes the whole document invalid. cradle writes
 * `cradle:expires` deliberately (SPEC.md §6.3), so the honest test is: with the
 * extension removed the document validates exactly, and the extension is the
 * only thing that deviates. Both halves are asserted.
 */
export function withoutCradleExtensions<T>(document: T): T {
  return JSON.parse(
    JSON.stringify(document, (key, value) => (key.startsWith(CRADLE_PREFIX) ? undefined : value)),
  ) as T
}

/** Every cradle-prefixed key anywhere in the document, as dotted paths. */
export function cradleExtensionKeys(document: unknown): string[] {
  const found: string[] = []
  const walk = (node: unknown, path: string): void => {
    if (Array.isArray(node)) {
      for (const [index, item] of node.entries()) walk(item, `${path}[${index}]`)
      return
    }
    if (node === null || typeof node !== 'object') return
    for (const [key, value] of Object.entries(node)) {
      if (key.startsWith(CRADLE_PREFIX)) found.push(`${path}.${key}`)
      walk(value, `${path}.${key}`)
    }
  }
  walk(document, '')
  return found.sort()
}
