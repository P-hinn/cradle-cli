import type { CradleConfig } from '../../types/index.js'
import { CradleError } from '../errors.js'

const KNOWN_KEYS = ['productName', 'contactEmail', 'supportPeriodEnd', 'placedOnMarket']

/**
 * Parse `.cradle/config.json`.
 *
 * Configuration is optional and additive, never a precondition: everything works
 * without this file, and its absence simply leaves some readiness checks open.
 * A file that *is* present but wrong, though, is worth an error — a typo in
 * "supportPeriodEnd" would otherwise leave the check reporting "not documented"
 * while the user is sure they documented it.
 */
export function parseConfig(raw: string, source: string): CradleConfig {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (cause) {
    throw new CradleError(
      `${source} is not valid JSON`,
      'Fix the syntax, or delete the file — cradle runs fine without it.',
      { cause },
    )
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new CradleError(`${source} is not a configuration object`, 'Expected a JSON object.')
  }

  const record = parsed as Record<string, unknown>
  const unknown = Object.keys(record).filter((key) => !KNOWN_KEYS.includes(key))
  if (unknown.length > 0) {
    throw new CradleError(
      `${source} has settings cradle does not know: ${unknown.join(', ')}`,
      `Supported settings are: ${KNOWN_KEYS.join(', ')}. A misspelt key would silently do nothing.`,
    )
  }

  const config: CradleConfig = {}
  for (const key of KNOWN_KEYS) {
    const value = record[key]
    if (value === undefined) continue
    if (typeof value !== 'string') {
      throw new CradleError(
        `${source}: "${key}" must be a string`,
        `Found ${JSON.stringify(value)}.`,
      )
    }
    if (value !== '') Object.assign(config, { [key]: value })
  }

  for (const key of ['supportPeriodEnd', 'placedOnMarket'] as const) {
    const value = config[key]
    if (value !== undefined && Number.isNaN(Date.parse(value))) {
      throw new CradleError(
        `${source}: "${key}" is not a date cradle can read`,
        `Found ${JSON.stringify(value)}. Use an ISO date, for example 2032-06-30.`,
      )
    }
  }

  return config
}
