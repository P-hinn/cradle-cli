import { describe, expect, it } from 'vitest'
import { fetchPackageFacts } from '../../src/core/readiness/registry.js'
import { MemoryCache, NULL_CACHE } from '../../src/core/vulns/cache.js'
import type { ResolvedComponent } from '../../src/types/index.js'

function component(overrides: Partial<ResolvedComponent> = {}): ResolvedComponent {
  const name = overrides.name ?? 'lodash'
  const version = overrides.version ?? '4.17.15'
  return {
    bomRef: `pkg:npm/${name}@${version}`,
    name,
    version,
    purl: `pkg:npm/${name}@${version}`,
    location: `node_modules/${name}`,
    licenses: [],
    licenseUnknown: false,
    hashes: [],
    direct: true,
    dev: false,
    workspace: false,
    kinds: ['prod'],
    ...overrides,
  }
}

interface FakeRegistry {
  fetch: typeof globalThis.fetch
  calls: string[]
}

function fakeRegistry(
  responses: Record<string, unknown>,
  options: { fail?: boolean } = {},
): FakeRegistry {
  const calls: string[] = []
  const fetch = (async (input: string | URL | Request) => {
    const url = String(input)
    calls.push(url)
    if (options.fail === true) throw new TypeError('fetch failed')
    const path = url.replace('https://registry.npmjs.org/', '')
    const body = responses[path]
    if (body === undefined) return new Response('not found', { status: 404 })
    return Response.json(body)
  }) as typeof globalThis.fetch
  return { fetch, calls }
}

describe('fetchPackageFacts', () => {
  it('reads deprecation from the single-version manifest', () => {
    const registry = fakeRegistry({
      'lodash/4.17.15': { deprecated: 'no longer maintained' },
      lodash: { time: { '4.17.15': '2020-01-01T00:00:00Z' } },
    })
    return fetchPackageFacts([component()], {
      fetch: registry.fetch,
      cache: NULL_CACHE,
    }).then((facts) => {
      expect(facts.get('pkg:npm/lodash@4.17.15')?.deprecated).toBe('no longer maintained')
    })
  })

  it('takes the newest publish date from the packument, ignoring created and modified', async () => {
    // The registry's own `modified` moves when metadata changes, so it says
    // nothing about releases: request reads as modified this year while its last
    // release was in 2020.
    const registry = fakeRegistry({
      'request/2.88.2': {},
      request: {
        time: {
          created: '2011-01-01T00:00:00Z',
          modified: '2026-07-17T00:00:00Z',
          '2.88.0': '2019-01-01T00:00:00Z',
          '2.88.2': '2020-02-11T16:35:36.122Z',
        },
      },
    })
    const facts = await fetchPackageFacts([component({ name: 'request', version: '2.88.2' })], {
      fetch: registry.fetch,
      cache: NULL_CACHE,
    })
    expect(facts.get('pkg:npm/request@2.88.2')?.lastPublish).toBe('2020-02-11T16:35:36.122Z')
  })

  it('fetches the expensive packument for direct dependencies only', async () => {
    const registry = fakeRegistry({
      'lodash/4.17.15': {},
      'ms/2.1.3': {},
      lodash: { time: { '4.17.15': '2020-01-01T00:00:00Z' } },
      ms: { time: { '2.1.3': '2020-01-01T00:00:00Z' } },
    })
    await fetchPackageFacts(
      [component(), component({ name: 'ms', version: '2.1.3', direct: false })],
      { fetch: registry.fetch, cache: NULL_CACHE },
    )

    // Both get the cheap manifest; only the direct one gets the packument.
    expect(registry.calls).toContain('https://registry.npmjs.org/lodash/4.17.15')
    expect(registry.calls).toContain('https://registry.npmjs.org/ms/2.1.3')
    expect(registry.calls).toContain('https://registry.npmjs.org/lodash')
    expect(registry.calls).not.toContain('https://registry.npmjs.org/ms')
  })

  it('encodes a scoped name so the slash survives into the path', async () => {
    const registry = fakeRegistry({})
    await fetchPackageFacts([component({ name: '@acme/ui', version: '1.0.0' })], {
      fetch: registry.fetch,
      cache: NULL_CACHE,
    })
    expect(registry.calls[0]).toBe('https://registry.npmjs.org/%40acme/ui/1.0.0')
  })

  it('skips workspace packages, which the registry knows nothing about', async () => {
    const registry = fakeRegistry({})
    await fetchPackageFacts([component({ name: '@acme/core', workspace: true })], {
      fetch: registry.fetch,
      cache: NULL_CACHE,
    })
    expect(registry.calls).toEqual([])
  })

  it('returns nothing rather than failing when the registry is unreachable', async () => {
    // This information improves the checklist; it is not what the tool is for.
    const registry = fakeRegistry({}, { fail: true })
    await expect(
      fetchPackageFacts([component()], { fetch: registry.fetch, cache: NULL_CACHE }),
    ).resolves.toEqual(new Map())
  })

  it('treats a 404 as no answer', async () => {
    const registry = fakeRegistry({})
    const facts = await fetchPackageFacts([component({ name: 'private-pkg' })], {
      fetch: registry.fetch,
      cache: NULL_CACHE,
    })
    expect(facts.size).toBe(0)
  })

  it('serves a second run from the cache', async () => {
    const cache = new MemoryCache()
    const responses = {
      'lodash/4.17.15': { deprecated: 'x' },
      lodash: { time: { '4.17.15': '2020-01-01T00:00:00Z' } },
    }
    await fetchPackageFacts([component()], { fetch: fakeRegistry(responses).fetch, cache })

    const warm = fakeRegistry(responses)
    const facts = await fetchPackageFacts([component()], { fetch: warm.fetch, cache })
    expect(warm.calls).toEqual([])
    expect(facts.get('pkg:npm/lodash@4.17.15')?.deprecated).toBe('x')
  })
})
