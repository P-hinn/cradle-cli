import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'
import type { DependencyGraph, PackageManager } from '../../types/index.js'
import { CradleError } from '../errors.js'
import { buildGraph, type RawPackage, type RootManifest } from './graph.js'
import { hoistedCandidates, readLicensesFromDisk } from './licenses.js'
import { readManifest } from './manifest.js'

/**
 * One resolved entry, keyed by every `name@range` descriptor that resolves to it.
 * Both Yarn formats are shaped this way; only the syntax differs.
 */
export interface YarnEntry {
  descriptors: string[]
  name: string
  version: string
  integrity?: string
  resolvedUrl?: string
  /** Dependency name -> the range it was declared with. */
  dependencies: Map<string, string>
  peers: Set<string>
  workspace?: boolean
}

export interface ResolveYarnOptions {
  projectDir: string
  includeDev: boolean
}

/**
 * Resolve a Yarn project, Classic or Berry.
 *
 * Neither format records whether a package is a development dependency — Classic
 * has no marker at all, and Berry folds the root's dev dependencies in with the
 * rest. So the split is derived by walking the graph twice from package.json,
 * which `buildGraph` does for every ecosystem alike.
 */
export async function resolveYarn(
  manager: 'yarn-classic' | 'yarn-berry',
  options: ResolveYarnOptions,
): Promise<DependencyGraph> {
  const lockPath = join(options.projectDir, 'yarn.lock')
  const raw = await read(lockPath)
  const manifest = await readManifest(options.projectDir)

  const entries =
    manager === 'yarn-berry' ? parseBerryLockfile(raw, lockPath) : parseClassicLockfile(raw)

  // A descriptor is `name@range`; resolving an edge means looking up the range a
  // dependent declared, because that is all either lockfile records.
  const byDescriptor = new Map<string, YarnEntry>()
  for (const entry of entries) {
    for (const descriptor of entry.descriptors) byDescriptor.set(descriptor, entry)
  }

  const packages = new Map<string, RawPackage>()
  for (const entry of entries) {
    if (entry.workspace === true) continue
    const key = `${entry.name}@${entry.version}`
    const pkg: RawPackage = {
      key,
      name: entry.name,
      version: entry.version,
      dependencies: new Map(),
      peers: new Set(),
    }
    if (entry.integrity !== undefined) pkg.integrity = entry.integrity
    if (entry.resolvedUrl !== undefined) pkg.resolvedUrl = entry.resolvedUrl
    packages.set(key, pkg)
  }

  const resolve = (name: string, range: string): string | undefined => {
    const entry = byDescriptor.get(`${name}@${range}`)
    return entry === undefined ? undefined : `${entry.name}@${entry.version}`
  }

  for (const entry of entries) {
    if (entry.workspace === true) continue
    const pkg = packages.get(`${entry.name}@${entry.version}`)
    if (pkg === undefined) continue
    for (const [name, range] of entry.dependencies) {
      const key = resolve(name, range)
      if (key === undefined) continue
      pkg.dependencies.set(name, key)
      if (entry.peers.has(name)) pkg.peers?.add(name)
    }
  }

  const rootProd = new Map<string, string>()
  const rootDev = new Map<string, string>()
  for (const [name, range] of Object.entries(manifest.dependencies ?? {})) {
    const key = resolve(name, range)
    if (key !== undefined) rootProd.set(name, key)
  }
  for (const [name, range] of Object.entries(manifest.optionalDependencies ?? {})) {
    const key = resolve(name, range)
    if (key !== undefined) rootProd.set(name, key)
  }
  for (const [name, range] of Object.entries(manifest.devDependencies ?? {})) {
    const key = resolve(name, range)
    if (key !== undefined) rootDev.set(name, key)
  }

  const licenses = await readLicensesFromDisk(
    options.projectDir,
    packages.values(),
    hoistedCandidates,
  )

  return buildGraph({
    packageManager: manager satisfies PackageManager,
    projectDir: options.projectDir,
    manifest,
    packages,
    rootProd,
    rootDev,
    includeDev: options.includeDev,
    licenses,
  })
}

// ---------------------------------------------------------------------------
// Yarn Classic
// ---------------------------------------------------------------------------

/**
 * Parse Yarn Classic's own text format.
 *
 * Written by hand rather than pulled in: `@yarnpkg/lockfile` has not been
 * published since 2018, and a dead dependency in a supply-chain tool is a poor
 * look. The grammar is small — two-space indentation, quoted-or-bare values, and
 * a `dependencies:` block — so this is about 60 lines rather than a parser
 * generator.
 */
export function parseClassicLockfile(raw: string): YarnEntry[] {
  const entries: YarnEntry[] = []
  const lines = raw.split('\n')

  let current: YarnEntry | undefined
  let section: 'dependencies' | 'optionalDependencies' | 'peerDependencies' | undefined

  for (const line of lines) {
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue

    const indent = line.length - line.trimStart().length
    const text = line.trim()

    if (indent === 0) {
      if (current !== undefined) entries.push(current)
      current = {
        descriptors: parseClassicHeader(text),
        name: '',
        version: '',
        dependencies: new Map(),
        peers: new Set(),
      }
      section = undefined
      continue
    }
    if (current === undefined) continue

    if (indent === 2) {
      section = undefined
      if (text === 'dependencies:') section = 'dependencies'
      else if (text === 'optionalDependencies:') section = 'optionalDependencies'
      else if (text === 'peerDependencies:') section = 'peerDependencies'
      else {
        const [key, ...rest] = text.split(' ')
        const value = unquote(rest.join(' '))
        if (key === 'version') current.version = value
        else if (key === 'integrity') current.integrity = value
        else if (key === 'resolved') current.resolvedUrl = value.split('#')[0] ?? value
      }
      continue
    }

    if (indent >= 4 && section !== undefined) {
      const space = text.indexOf(' ')
      if (space === -1) continue
      const name = unquote(text.slice(0, space))
      const range = unquote(text.slice(space + 1))
      // Peer ranges are recorded so the graph can label the edge, but they
      // resolve through the same descriptor table as everything else.
      if (section === 'peerDependencies') current.peers.add(name)
      current.dependencies.set(name, range)
    }
  }
  if (current !== undefined) entries.push(current)

  for (const entry of entries) {
    const first = entry.descriptors[0]
    if (first === undefined) continue
    entry.name = splitDescriptor(first).name
  }
  return entries.filter((entry) => entry.name !== '' && entry.version !== '')
}

/** `"a@^1", b@^2:` -> the descriptors, without quotes or the trailing colon. */
function parseClassicHeader(text: string): string[] {
  const withoutColon = text.endsWith(':') ? text.slice(0, -1) : text
  return withoutColon.split(',').map((part) => unquote(part.trim()))
}

// ---------------------------------------------------------------------------
// Yarn Berry
// ---------------------------------------------------------------------------

interface BerryEntry {
  version?: unknown
  resolution?: unknown
  checksum?: unknown
  linkType?: unknown
  dependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
  dependenciesMeta?: unknown
}

/**
 * Parse Yarn Berry's YAML lockfile.
 *
 * Descriptors carry a protocol — `lodash@npm:^4.17.21` — which is stripped so
 * ranges compare against what package.json declares.
 *
 * Berry's `checksum` is deliberately not read as a hash. It is sha512-sized and
 * looks like an integrity value, but it is Yarn's own cache key over its own
 * archive format, not the npm tarball digest: for the same package npm records
 * `4162e5d8…` where Yarn records `6d43a916…`. Emitting it as a CycloneDX
 * SHA-512 would be a plausible-looking lie, so Berry SBOMs carry no hashes.
 */
export function parseBerryLockfile(raw: string, source: string): YarnEntry[] {
  let parsed: unknown
  try {
    parsed = parseYaml(raw)
  } catch (cause) {
    throw new CradleError(
      `${source} is not valid YAML`,
      'Delete it and run `yarn install` to write a fresh one.',
      { cause },
    )
  }
  if (parsed === null || typeof parsed !== 'object') return []

  const entries: YarnEntry[] = []
  for (const [key, value] of Object.entries(parsed as Record<string, BerryEntry>)) {
    if (key === '__metadata') continue
    if (value === null || typeof value !== 'object') continue

    const version = typeof value.version === 'string' ? value.version : ''
    const resolution = typeof value.resolution === 'string' ? value.resolution : ''
    if (version === '') continue

    const descriptors = key
      .split(',')
      .map((part) => stripProtocol(unquote(part.trim())))
      .filter((part) => part !== '')

    const entry: YarnEntry = {
      descriptors,
      name: descriptors[0] === undefined ? '' : splitDescriptor(descriptors[0]).name,
      version,
      dependencies: new Map(),
      peers: new Set(),
    }
    // `workspace:` resolutions are this repository's own packages.
    if (resolution.includes('@workspace:') || value.linkType === 'soft') entry.workspace = true

    for (const [name, range] of Object.entries(value.dependencies ?? {})) {
      entry.dependencies.set(name, stripRangeProtocol(range))
    }
    for (const [name, range] of Object.entries(value.peerDependencies ?? {})) {
      entry.peers.add(name)
      entry.dependencies.set(name, stripRangeProtocol(range))
    }

    if (entry.name !== '') entries.push(entry)
  }
  return entries
}

/** `lodash@npm:^4.17.21` -> `lodash@^4.17.21`. */
function stripProtocol(descriptor: string): string {
  const { name, range } = splitDescriptor(descriptor)
  return name === '' ? descriptor : `${name}@${stripRangeProtocol(range)}`
}

function stripRangeProtocol(range: string): string {
  return range.startsWith('npm:') ? range.slice(4) : range
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** Split on the version separator, not on a scope's leading `@`. */
export function splitDescriptor(descriptor: string): { name: string; range: string } {
  const at = descriptor.lastIndexOf('@')
  if (at <= 0) return { name: descriptor, range: '' }
  return { name: descriptor.slice(0, at), range: descriptor.slice(at + 1) }
}

function unquote(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

async function read(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8')
  } catch (cause) {
    throw new CradleError(`Could not read ${path}`, 'Run `yarn install` and try again.', { cause })
  }
}

export type { RootManifest }
