import { CradleError } from '../errors.js'
import type { VulnCache } from './cache.js'
import type { OsvBatchResponse, OsvVulnerability } from './osv-types.js'

/** OSV caps a batch at 1000 queries. */
const MAX_BATCH = 1000
const API = 'https://api.osv.dev/v1'

export interface OsvQuery {
  name: string
  version: string
}

export interface OsvClientOptions {
  /** Injected so tests never reach the network. */
  fetch: typeof globalThis.fetch
  cache: VulnCache
  /** Injected so retry tests do not actually wait. */
  sleep?: (ms: number) => Promise<void>
  batchSize?: number
  maxRetries?: number
  /** Detail requests in flight at once. */
  concurrency?: number
  userAgent?: string
}

export interface OsvResult {
  /** `name@version` -> the vulnerabilities affecting it. */
  byPackage: Map<string, OsvVulnerability[]>
  requests: number
  cacheHits: number
}

export function packageKey(name: string, version: string): string {
  return `${name}@${version}`
}

/**
 * Look up vulnerabilities for a set of packages.
 *
 * Two calls per advisory are unavoidable: `querybatch` says *which* advisories
 * apply but returns only ids, so details come from `/vulns/{id}`. Those details
 * are cached under the advisory's own `modified` timestamp, which means a
 * changed advisory invalidates itself and repeat runs cost one batch request.
 */
export async function queryOsv(
  queries: readonly OsvQuery[],
  options: OsvClientOptions,
): Promise<OsvResult> {
  const batchSize = Math.min(options.batchSize ?? MAX_BATCH, MAX_BATCH)
  const result: OsvResult = { byPackage: new Map(), requests: 0, cacheHits: 0 }
  if (queries.length === 0) return result

  // The same name@version can sit at several places in a tree; ask once.
  const unique = new Map<string, OsvQuery>()
  for (const query of queries) unique.set(packageKey(query.name, query.version), query)
  const ordered = [...unique.values()]

  /** advisory id -> its `modified` stamp, used as the cache key. */
  const wanted = new Map<string, string>()
  /** package key -> advisory ids affecting it. */
  const idsByPackage = new Map<string, string[]>()

  for (let offset = 0; offset < ordered.length; offset += batchSize) {
    const chunk = ordered.slice(offset, offset + batchSize)
    const response = await request<OsvBatchResponse>(
      `${API}/querybatch`,
      {
        method: 'POST',
        body: JSON.stringify({
          queries: chunk.map((q) => ({
            package: { name: q.name, ecosystem: 'npm' },
            version: q.version,
          })),
        }),
      },
      options,
    )
    result.requests += 1

    // Results align with the request array by index; an unaffected package
    // comes back as an empty object rather than being omitted.
    const results = response.results ?? []
    for (const [index, query] of chunk.entries()) {
      const ids = (results[index]?.vulns ?? []).map((v) => {
        wanted.set(v.id, v.modified ?? '')
        return v.id
      })
      if (ids.length > 0) idsByPackage.set(packageKey(query.name, query.version), ids)
    }
  }

  const details = new Map<string, OsvVulnerability>()
  await forEachLimited([...wanted.entries()], options.concurrency ?? 8, async ([id, modified]) => {
    const cacheKey = `osv/v1/${id}@${modified}`
    const cached = await options.cache.get(cacheKey)
    if (cached !== undefined) {
      try {
        details.set(id, JSON.parse(cached) as OsvVulnerability)
        result.cacheHits += 1
        return
      } catch {
        // A corrupt cache entry is not worth failing over; refetch it.
      }
    }

    const vulnerability = await request<OsvVulnerability>(`${API}/vulns/${id}`, {}, options)
    result.requests += 1
    details.set(id, vulnerability)
    await options.cache.set(cacheKey, JSON.stringify(vulnerability))
  })

  for (const [key, ids] of idsByPackage) {
    const vulnerabilities = ids
      .map((id) => details.get(id))
      .filter((v): v is OsvVulnerability => v !== undefined)
      // A withdrawn advisory is one the upstream database retracted.
      .filter((v) => v.withdrawn === undefined)
    if (vulnerabilities.length > 0) result.byPackage.set(key, vulnerabilities)
  }

  return result
}

async function request<T>(url: string, init: RequestInit, options: OsvClientOptions): Promise<T> {
  const maxRetries = options.maxRetries ?? 4
  const sleep = options.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)))

  let lastReason = ''
  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    let response: Response
    try {
      response = await options.fetch(url, {
        ...init,
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          'user-agent': options.userAgent ?? 'cradle-cli',
          ...init.headers,
        },
      })
    } catch (cause) {
      lastReason = cause instanceof Error ? cause.message : String(cause)
      if (attempt === maxRetries) break
      await sleep(backoff(attempt))
      continue
    }

    if (response.ok) return (await response.json()) as T

    // 429 and 5xx are worth retrying; a 400 means we sent something wrong.
    if (response.status !== 429 && response.status < 500) {
      throw new CradleError(
        `OSV rejected the request (HTTP ${response.status})`,
        'This is likely a bug in cradle. Re-run with --offline to skip the vulnerability ' +
          'lookup, and please report the failing project if you can.',
      )
    }

    lastReason = `HTTP ${response.status}`
    if (attempt === maxRetries) break
    await sleep(retryAfter(response) ?? backoff(attempt))
  }

  throw new CradleError(
    `Could not reach the OSV API (${lastReason})`,
    'Check the network connection, or run with --offline to produce an SBOM without ' +
      'the vulnerability lookup. The report will say the lookup was skipped.',
  )
}

/** Exponential with a little jitter-free growth: 500ms, 1s, 2s, 4s. */
function backoff(attempt: number): number {
  return 500 * 2 ** attempt
}

function retryAfter(response: Response): number | undefined {
  const header = response.headers.get('retry-after')
  if (header === null) return undefined
  const seconds = Number.parseInt(header, 10)
  return Number.isFinite(seconds) ? Math.min(seconds, 30) * 1000 : undefined
}

/** Run `worker` over every item, at most `limit` at a time. */
async function forEachLimited<T>(
  items: readonly T[],
  limit: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  let cursor = 0
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const item = items[cursor]
      cursor += 1
      if (item !== undefined) await worker(item)
    }
  })
  await Promise.all(runners)
}
