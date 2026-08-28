import { describe, expect, it } from 'vitest'
import { CradleError } from '../../src/core/errors.js'
import { MemoryCache, NULL_CACHE } from '../../src/core/vulns/cache.js'
import { queryOsv } from '../../src/core/vulns/osv.js'
import { fakeOsv } from '../support/osv.js'

const PACKAGES = [
  { name: 'lodash', version: '4.17.15' },
  { name: 'minimist', version: '1.2.0' },
]

const noSleep = () => Promise.resolve()

describe('queryOsv', () => {
  it('resolves advisories for the packages that have them', async () => {
    const osv = fakeOsv()
    const result = await queryOsv(PACKAGES, { fetch: osv.fetch, cache: NULL_CACHE })

    expect([...result.byPackage.keys()].sort()).toEqual(['lodash@4.17.15', 'minimist@1.2.0'])
    expect(result.byPackage.get('lodash@4.17.15')?.map((v) => v.id)).toContain(
      'GHSA-p6mc-m468-83gw',
    )
  })

  it('asks about each name@version once, however often it appears in the tree', async () => {
    const osv = fakeOsv()
    await queryOsv([...PACKAGES, ...PACKAGES, ...PACKAGES], {
      fetch: osv.fetch,
      cache: NULL_CACHE,
    })
    const [batch] = osv.batchBodies as { queries: unknown[] }[]
    expect(batch?.queries).toHaveLength(2)
  })

  it('splits into batches of at most the configured size', async () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ name: `pkg-${i}`, version: '1.0.0' }))
    const osv = fakeOsv({ batchResponse: { results: [{}, {}] } })
    await queryOsv(many, { fetch: osv.fetch, cache: NULL_CACHE, batchSize: 2 })

    const batches = osv.calls.filter((url) => url.endsWith('/querybatch'))
    expect(batches).toHaveLength(3)
    expect((osv.batchBodies as { queries: unknown[] }[]).map((b) => b.queries.length)).toEqual([
      2, 2, 1,
    ])
  })

  it('sends the npm ecosystem and the exact resolved version', async () => {
    const osv = fakeOsv()
    await queryOsv([{ name: '@acme/ui', version: '0.4.2' }], {
      fetch: osv.fetch,
      cache: NULL_CACHE,
    })
    expect(osv.batchBodies[0]).toEqual({
      queries: [{ package: { name: '@acme/ui', ecosystem: 'npm' }, version: '0.4.2' }],
    })
  })

  it('serves advisory details from the cache on a second run', async () => {
    const cache = new MemoryCache()
    const first = fakeOsv()
    const cold = await queryOsv(PACKAGES, { fetch: first.fetch, cache })
    expect(cold.cacheHits).toBe(0)
    expect(cache.size).toBe(8)

    const second = fakeOsv()
    const warm = await queryOsv(PACKAGES, { fetch: second.fetch, cache })
    expect(warm.cacheHits).toBe(8)
    // Only the batch call goes out; the eight detail requests are served locally.
    expect(second.calls).toHaveLength(1)
    expect(warm.byPackage).toEqual(cold.byPackage)
  })

  it('keys the cache on the advisory timestamp, so an updated advisory refetches', async () => {
    const cache = new MemoryCache()
    await queryOsv(PACKAGES, { fetch: fakeOsv().fetch, cache })

    // Same ids, newer modified stamps.
    const moved = fakeOsv({
      batchResponse: {
        results: [{ vulns: [{ id: 'GHSA-p6mc-m468-83gw', modified: '2099-01-01T00:00:00Z' }] }, {}],
      },
    })
    const result = await queryOsv(PACKAGES, { fetch: moved.fetch, cache })
    expect(result.cacheHits).toBe(0)
    expect(moved.calls.filter((u) => u.includes('/vulns/'))).toHaveLength(1)
  })

  it('retries a 429 and then succeeds', async () => {
    const osv = fakeOsv({ failWith: [429, 429] })
    const result = await queryOsv(PACKAGES, {
      fetch: osv.fetch,
      cache: NULL_CACHE,
      sleep: noSleep,
    })
    expect(result.byPackage.size).toBe(2)
  })

  it('retries a network error and then succeeds', async () => {
    const osv = fakeOsv({ networkErrors: 2 })
    const result = await queryOsv(PACKAGES, {
      fetch: osv.fetch,
      cache: NULL_CACHE,
      sleep: noSleep,
    })
    expect(result.byPackage.size).toBe(2)
  })

  it('gives up with an actionable message when OSV stays unreachable', async () => {
    const osv = fakeOsv({ networkErrors: 99 })
    const error = await queryOsv(PACKAGES, {
      fetch: osv.fetch,
      cache: NULL_CACHE,
      sleep: noSleep,
      maxRetries: 2,
    }).catch((e: unknown) => e)

    expect(error).toBeInstanceOf(CradleError)
    expect((error as CradleError).hint).toContain('--offline')
  })

  it('does not retry a 4xx that is our own fault', async () => {
    const osv = fakeOsv({ failWith: [400] })
    const error = await queryOsv(PACKAGES, {
      fetch: osv.fetch,
      cache: NULL_CACHE,
      sleep: noSleep,
    }).catch((e: unknown) => e)

    expect(error).toBeInstanceOf(CradleError)
    expect((error as CradleError).message).toContain('HTTP 400')
    expect(osv.calls).toHaveLength(1)
  })

  it('drops withdrawn advisories', async () => {
    const osv = fakeOsv({
      batchResponse: { results: [{ vulns: [{ id: 'withdrawn', modified: 'x' }] }] },
    })
    const withdrawn = {
      ...osv,
      fetch: (async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input)
        if (url.endsWith('/querybatch')) return osv.fetch(input, init)
        return Response.json({ id: 'withdrawn', withdrawn: '2026-01-01T00:00:00Z' })
      }) as typeof globalThis.fetch,
    }
    const result = await queryOsv([{ name: 'x', version: '1.0.0' }], {
      fetch: withdrawn.fetch,
      cache: NULL_CACHE,
    })
    expect(result.byPackage.size).toBe(0)
  })

  it('makes no request at all for an empty tree', async () => {
    const osv = fakeOsv()
    const result = await queryOsv([], { fetch: osv.fetch, cache: NULL_CACHE })
    expect(osv.calls).toEqual([])
    expect(result.byPackage.size).toBe(0)
  })
})
