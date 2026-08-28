import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const DIR = fileURLToPath(new URL('../fixtures/osv/', import.meta.url))

function read(file: string): unknown {
  return JSON.parse(readFileSync(`${DIR}${file}`, 'utf8'))
}

export interface FakeOsv {
  fetch: typeof globalThis.fetch
  /** Every URL requested, in order. */
  calls: string[]
  /** Only the OSV ones, for tests that care about advisory traffic. */
  osvCalls: string[]
  batchBodies: unknown[]
}

/**
 * The packages the recorded querybatch.json covers, in request order. Anything
 * else is answered as "no advisories", which is what OSV does.
 */
const RECORDED_ORDER = ['lodash@4.17.15', 'minimist@1.2.0']

export interface FakeOsvOptions {
  /**
   * Status codes to return before serving normally, e.g. [429, 429] to exercise
   * the retry path.
   */
  failWith?: number[]
  /** Throw a network error this many times first. */
  networkErrors?: number
  /** Serve this batch response instead of the recorded one. */
  batchResponse?: unknown
}

/**
 * Replays the OSV responses recorded under test/fixtures/osv/.
 *
 * The client is never allowed near the real API in tests: an advisory changing
 * upstream would turn an unrelated commit red, and the recorded pair (batch +
 * details) is exactly what the code has to cope with.
 */
export function fakeOsv(options: FakeOsvOptions = {}): FakeOsv {
  const calls: string[] = []
  const osvCalls: string[] = []
  const batchBodies: unknown[] = []
  const failures = [...(options.failWith ?? [])]
  let networkErrors = options.networkErrors ?? 0

  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    calls.push(url)

    // The readiness checks also talk to the npm registry. Answering with "no
    // such package" keeps those checks honest (they report not-assessable)
    // without any test needing to know they exist.
    if (url.startsWith('https://registry.npmjs.org/')) {
      return new Response('not found', { status: 404 })
    }
    osvCalls.push(url)

    if (networkErrors > 0) {
      networkErrors -= 1
      throw new TypeError('fetch failed')
    }
    const status = failures.shift()
    if (status !== undefined) {
      return new Response('', { status, headers: { 'retry-after': '0' } })
    }

    if (url.endsWith('/querybatch')) {
      const body = typeof init?.body === 'string' ? JSON.parse(init.body) : { queries: [] }
      batchBodies.push(body)
      if (options.batchResponse !== undefined) return Response.json(options.batchResponse)

      // Answer against the packages actually asked about, rather than replaying
      // a fixed array — otherwise a different fixture silently gets lodash's
      // advisories attributed to whatever sat at the same index.
      const recorded = read('querybatch.json') as { results: unknown[] }
      const queries = (body as { queries: { package: { name: string }; version: string }[] })
        .queries
      return Response.json({
        results: queries.map((query) => {
          const index = RECORDED_ORDER.indexOf(`${query.package.name}@${query.version}`)
          return index === -1 ? {} : (recorded.results[index] ?? {})
        }),
      })
    }

    const id = url.slice(url.lastIndexOf('/') + 1)
    if (!existsSync(`${DIR}${id}.json`)) {
      return new Response('not found', { status: 404 })
    }
    return Response.json(read(`${id}.json`))
  }) as typeof globalThis.fetch

  return { fetch, calls, osvCalls, batchBodies }
}
