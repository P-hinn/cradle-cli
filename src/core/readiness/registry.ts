import type { ResolvedComponent } from '../../types/index.js'
import type { VulnCache } from '../vulns/cache.js'

const REGISTRY = 'https://registry.npmjs.org'

export interface PackageFacts {
  /** The deprecation message the registry carries for the installed version. */
  deprecated?: string
  /** When the package last published any version. */
  lastPublish?: string
}

export interface RegistryOptions {
  fetch: typeof globalThis.fetch
  cache: VulnCache
  concurrency?: number
  userAgent?: string
}

/**
 * Look up maintenance facts for the dependency tree.
 *
 * Two questions with very different costs, so they get different scopes:
 *
 *   - *Is the installed version deprecated?* comes from the single-version
 *     manifest, a few kilobytes, so every component is checked.
 *   - *When did this package last publish?* only exists in the full packument,
 *     which runs to hundreds of kilobytes per package. That is checked for
 *     direct dependencies only, and the report says so. It is also the set the
 *     answer is actionable for: for a transitive package the response is
 *     "upgrade its parent", which is a different conversation.
 *
 * The registry's own `modified` timestamp looks like a cheap shortcut and is
 * not one — it moves when metadata changes. The `request` package reads as
 * modified last month while its last actual release was in 2020.
 */
export async function fetchPackageFacts(
  components: readonly ResolvedComponent[],
  options: RegistryOptions,
): Promise<Map<string, PackageFacts>> {
  const facts = new Map<string, PackageFacts>()
  const concurrency = options.concurrency ?? 8

  // Workspace packages are this repository's own code; the registry knows
  // nothing about them.
  const external = components.filter((component) => !component.workspace)

  await forEachLimited(external, concurrency, async (component) => {
    const manifest = await getJson<{ deprecated?: unknown }>(
      `${REGISTRY}/${encodeName(component.name)}/${encodeURIComponent(component.version)}`,
      `registry/v1/manifest/${component.name}@${component.version}`,
      options,
    )
    if (manifest === undefined) return
    if (typeof manifest.deprecated === 'string' && manifest.deprecated !== '') {
      facts.set(component.purl, {
        ...facts.get(component.purl),
        deprecated: manifest.deprecated,
      })
    }
  })

  const direct = external.filter((component) => component.direct)
  await forEachLimited(direct, concurrency, async (component) => {
    const packument = await getJson<{ time?: Record<string, string> }>(
      `${REGISTRY}/${encodeName(component.name)}`,
      // Not keyed by version: the answer is about the package, not the release
      // we happen to have installed.
      `registry/v1/packument/${component.name}`,
      options,
    )
    const lastPublish = newestPublish(packument?.time)
    if (lastPublish === undefined) return
    facts.set(component.purl, { ...facts.get(component.purl), lastPublish })
  })

  return facts
}

/** `time` also holds `created` and `modified`, which are not releases. */
function newestPublish(time: Record<string, string> | undefined): string | undefined {
  if (time === undefined) return undefined
  let newest: string | undefined
  for (const [key, value] of Object.entries(time)) {
    if (key === 'created' || key === 'modified') continue
    if (typeof value !== 'string') continue
    if (newest === undefined || value > newest) newest = value
  }
  return newest
}

/** A scoped name has a slash that must survive into the path. */
function encodeName(name: string): string {
  return name.startsWith('@')
    ? `${encodeURIComponent(name.slice(0, name.indexOf('/')))}/${encodeURIComponent(name.slice(name.indexOf('/') + 1))}`
    : encodeURIComponent(name)
}

/**
 * A registry lookup that never fails the scan.
 *
 * This information makes the readiness checklist better; it is not what the tool
 * is for. An unreachable registry, a private package, a 404 — all of them mean
 * "no answer", which the checklist reports honestly as not assessable.
 */
async function getJson<T>(
  url: string,
  cacheKey: string,
  options: RegistryOptions,
): Promise<T | undefined> {
  const cached = await options.cache.get(cacheKey)
  if (cached !== undefined) {
    try {
      return JSON.parse(cached) as T
    } catch {
      // Fall through and refetch.
    }
  }

  try {
    const response = await options.fetch(url, {
      headers: {
        accept: 'application/json',
        'user-agent': options.userAgent ?? 'cradle-cli',
      },
    })
    if (!response.ok) return undefined
    const body = (await response.json()) as T
    await options.cache.set(cacheKey, JSON.stringify(body))
    return body
  } catch {
    return undefined
  }
}

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
