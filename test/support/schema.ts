import { readFileSync } from 'node:fs'
import { Ajv, type ValidateFunction } from 'ajv'
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
