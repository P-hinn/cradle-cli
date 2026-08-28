/**
 * CVSS v3.0 / v3.1 base score.
 *
 * OSV hands out the vector string, not the number, and a severity label alone is
 * too coarse to sort a findings table by. The formula is fully specified by
 * FIRST, so computing it here is exact rather than an approximation — see
 * test/vulns/cvss.test.ts, which checks it against published examples.
 *
 * v2 and v4 vectors are not scored here. v4 needs a large lookup table, and
 * guessing would be worse than falling back to the advisory's own label.
 */

const ATTACK_VECTOR: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const ATTACK_COMPLEXITY: Record<string, number> = { L: 0.77, H: 0.44 }
const PRIVILEGES_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 }
// A changed scope makes low and high privileges count for more.
const PRIVILEGES_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 }
const USER_INTERACTION: Record<string, number> = { N: 0.85, R: 0.62 }
const IMPACT: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }

export interface CvssScore {
  version: '3.0' | '3.1'
  score: number
}

/** Returns null for anything that is not a well-formed CVSS v3 base vector. */
export function scoreCvssV3(vector: string): CvssScore | null {
  const parts = vector.trim().split('/')
  const prefix = parts[0]
  if (prefix !== 'CVSS:3.0' && prefix !== 'CVSS:3.1') return null
  const version = prefix === 'CVSS:3.0' ? '3.0' : '3.1'

  const metrics = new Map<string, string>()
  for (const part of parts.slice(1)) {
    const [key, value] = part.split(':')
    if (key !== undefined && value !== undefined) metrics.set(key, value)
  }

  const scopeChanged = metrics.get('S') === 'C'
  const av = ATTACK_VECTOR[metrics.get('AV') ?? '']
  const ac = ATTACK_COMPLEXITY[metrics.get('AC') ?? '']
  const pr = (scopeChanged ? PRIVILEGES_CHANGED : PRIVILEGES_UNCHANGED)[metrics.get('PR') ?? '']
  const ui = USER_INTERACTION[metrics.get('UI') ?? '']
  const c = IMPACT[metrics.get('C') ?? '']
  const i = IMPACT[metrics.get('I') ?? '']
  const a = IMPACT[metrics.get('A') ?? '']
  if ([av, ac, pr, ui, c, i, a].some((value) => value === undefined)) return null
  if (metrics.get('S') !== 'C' && metrics.get('S') !== 'U') return null

  const iss = 1 - (1 - (c as number)) * (1 - (i as number)) * (1 - (a as number))
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss
  if (impact <= 0) return { version, score: 0 }

  const exploitability = 8.22 * (av as number) * (ac as number) * (pr as number) * (ui as number)
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10)

  return { version, score: version === '3.1' ? roundUp31(raw) : Math.ceil(raw * 10) / 10 }
}

/**
 * v3.1 replaced the naive ceiling with integer arithmetic, because floating
 * point made some scores round up one notch too far.
 */
function roundUp31(value: number): number {
  const scaled = Math.round(value * 100000)
  if (scaled % 10000 === 0) return scaled / 100000
  return (Math.floor(scaled / 10000) + 1) / 10
}
