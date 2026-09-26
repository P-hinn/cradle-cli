import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'
import type { DependencyGraph, PackageManager, ResolveNote } from '../../types/index.js'
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
  /** Berry's `resolution:` line verbatim. Classic has no equivalent. */
  resolution?: string
  /**
   * The protocol part of the range this entry was requested under. Berry has it in
   * `resolution:`; for Classic the descriptor is the only place it appears, and
   * without it a git or a local dependency is indistinguishable from a registry
   * one.
   */
  requestedRange?: string
  /** The name it is installed under, when that differs from the published name. */
  installedAs?: string
  /** Dependency name -> the range it was declared with. */
  dependencies: Map<string, string>
  peers: Set<string>
  workspace?: boolean
}

/**
 * Protocols that mean the installed code is not the published package: a local
 * path, a git checkout, or a patch Yarn applied on the way in.
 */
const LOCAL_PROTOCOL = /^(file:|link:|portal:)/
const GIT_PROTOCOL = /^(git\+|git:|ssh:\/\/|https?:\/\/.*\.git)/

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

  const resolve = (name: string, range: string): string | undefined => {
    const entry = byDescriptor.get(`${name}@${range}`)
    return entry === undefined ? undefined : `${entry.name}@${entry.version}`
  }

  const notes: ResolveNote[] = []
  const packages = new Map<string, RawPackage>()
  for (const entry of entries) {
    if (entry.workspace === true) continue
    const key = `${entry.name}@${entry.version}`
    const subject = `${entry.name}@${entry.version}`

    // A `patch:` entry is Yarn applying a patch to a package that also appears
    // under its plain resolution. It is deliberately not a second component -
    // that would double-count - but the code on disk is not the published code,
    // and that is not something to leave unsaid. The descriptor table still maps
    // the patch descriptor onto this same key, so an edge declared against the
    // patch still lands on the right component.
    if (entry.resolution?.includes('@patch:') === true) {
      notes.push({
        kind: 'patched-dependency',
        subject,
        message: `${entry.name} has a Yarn patch applied on top of version ${entry.version}.`,
        hint:
          'The SBOM lists the unpatched package, because that is what advisories are keyed ' +
          'on. Whether the patch closes or opens anything is not something cradle can see.',
      })
      continue
    }

    // Berry states the protocol in `resolution:`; Classic only ever shows it in
    // the descriptor it was requested under.
    const protocol =
      entry.resolution === undefined
        ? (entry.requestedRange ?? '')
        : splitDescriptor(entry.resolution).range

    if (GIT_PROTOCOL.test(protocol) || protocol.includes('commit=')) {
      notes.push({
        kind: 'git-dependency',
        subject,
        message: `${entry.name} is installed from git, not from a registry.`,
        hint:
          `The version ${entry.version} is what that commit's package.json claims; it is not ` +
          'a published release, and yarn.lock does not record what the package is published ' +
          `as — so "${entry.name}" here is the name it was installed under.`,
      })
    } else if (LOCAL_PROTOCOL.test(protocol)) {
      notes.push({
        kind: 'local-dependency',
        subject,
        message: `${entry.name} is installed from a local path, not from a registry.`,
        hint:
          'Its purl names a registry package that may not be the same code, and advisory ' +
          'lookups will match on that name. Vendored code has to be reviewed on its own.',
      })
    }

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

  // An `npm:` alias installs a package under a name it is not published as. The
  // component carries the published name, because that is what OSV keys on -
  // which means the name in package.json appears nowhere in the output. Berry
  // records both names in the lockfile; Classic records only the alias, so there
  // the manifest range is the only place the pairing exists.
  for (const entry of entries) {
    if (entry.workspace === true || entry.installedAs === undefined) continue
    notes.push({
      kind: 'aliased-dependency',
      subject: `${entry.name}@${entry.version}`,
      message: `${entry.name} is installed under the name ${entry.installedAs}.`,
      hint:
        `The SBOM records the published name ${entry.name}, because that is what advisories ` +
        'are keyed on. Searching it for the alias will find nothing.',
    })
  }

  for (const [name, range] of Object.entries({
    ...manifest.dependencies,
    ...manifest.devDependencies,
    ...manifest.optionalDependencies,
  })) {
    if (!range.startsWith('npm:')) continue
    const target = range.slice('npm:'.length)
    // `npm:@scope/real@^1.0.0` is an alias; a bare `npm:^2.1.3` is only a
    // protocol-qualified range, and reading a name out of it produced notes about
    // a package called "^2.1.3".
    if (target.indexOf('@', 1) === -1) continue
    const aliased = splitDescriptor(target).name
    if (aliased === '' || aliased === name) continue
    notes.push({
      kind: 'aliased-dependency',
      subject: resolve(name, range) ?? aliased,
      message: `${aliased} is installed under the name ${name}.`,
      hint:
        `The SBOM records the published name ${aliased}, because that is what advisories are ` +
        'keyed on. Searching it for the alias will find nothing.',
    })
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
  const optionalNames = new Set(Object.keys(manifest.optionalDependencies ?? {}))

  const linkRoot = (
    ranges: Record<string, string> | undefined,
    into: Map<string, string>,
  ): void => {
    for (const [name, range] of Object.entries(ranges ?? {})) {
      const key = resolve(name, range)
      if (key !== undefined && packages.has(key)) {
        into.set(name, key)
        continue
      }
      // An unmet optional dependency is the normal case; anything else declared
      // but unresolvable is missing from the SBOM and from the lookup, and used
      // to vanish without a word.
      if (optionalNames.has(name)) continue
      notes.push({
        kind: 'unresolved-dependency',
        subject: name,
        message: `${name} is declared in package.json but absent from yarn.lock.`,
        hint:
          'It is missing from the SBOM and from the vulnerability lookup. Run `yarn install` ' +
          'to write a complete lockfile.',
      })
    }
  }

  linkRoot(manifest.dependencies, rootProd)
  linkRoot(manifest.optionalDependencies, rootProd)
  linkRoot(manifest.devDependencies, rootDev)

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
    rootOptional: optionalNames,
    includeDev: options.includeDev,
    licenses,
    notes,
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
    const { name, range } = splitDescriptor(first)
    entry.name = name
    entry.requestedRange = range
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

    // Both spellings are registered. A dependent may declare `ms@^2.1.3` where the
    // lockfile keys it as `ms@npm:^2.1.3`, and an alias is declared as
    // `npm:@scope/real@^1.0.0` — whose stripped form is meaningless. Keeping both
    // means either lookup finds the entry; stripping only lost the alias.
    const raw = key
      .split(',')
      .map((part) => unquote(part.trim()))
      .filter((part) => part !== '')
    // Berry appends `::locator=…` to a portal or patch descriptor to record which
    // workspace asked for it. package.json carries the range without it, so the
    // bare spelling is registered as well or the dependency never resolves.
    const withoutLocator = raw.map((part) => part.split('::')[0] ?? part)
    const descriptors = [
      ...new Set([
        ...raw,
        ...withoutLocator,
        ...raw.map(stripProtocol),
        ...withoutLocator.map(stripProtocol),
      ]),
    ]

    // The name comes from `resolution`, not from the descriptor. For an alias
    // those differ: `is-alias@npm:@sindresorhus/is@^7.0.1` resolves to
    // `@sindresorhus/is@npm:7.2.0`, and taking the descriptor's name produced a
    // component called `is-alias` with a purl for a package that does not exist.
    const resolvedName = resolution === '' ? '' : splitDescriptor(resolution).name
    const declaredName = raw[0] === undefined ? '' : splitDescriptor(raw[0]).name

    const entry: YarnEntry = {
      descriptors,
      name: resolvedName !== '' ? resolvedName : declaredName,
      version,
      dependencies: new Map(),
      peers: new Set(),
    }
    if (resolution !== '') entry.resolution = resolution
    if (declaredName !== '' && declaredName !== entry.name) entry.installedAs = declaredName
    // Only a `workspace:` resolution is this repository's own package. `linkType:
    // soft` is not a synonym for it: Berry gives `portal:` and `link:`
    // dependencies a soft link too, and treating those as workspaces dropped them
    // from the SBOM entirely while reporting them as missing from a lockfile they
    // were plainly in.
    if (resolution.includes('@workspace:')) entry.workspace = true

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

/**
 * Split a descriptor into the package name and everything after it.
 *
 * The separator is the **first** `@` past position zero, not the last. A scope's
 * leading `@` sits at position zero, and everything after the separator is the
 * range — which is entirely free to contain more of them:
 *
 *   `lodash@npm:^4.17.21`                        -> lodash
 *   `@esbuild/aix-ppc64@npm:0.28.2`              -> @esbuild/aix-ppc64
 *   `myalias@npm:@scope/real@^1.0.0`             -> myalias
 *   `typescript@patch:typescript@npm%3A5.9.3#…`  -> typescript
 *   `left-pad@git+ssh://git@github.com/x/y.git`  -> left-pad
 *
 * Splitting on the last `@` got the first two right and the last three wrong,
 * yielding names like `typescript@patch:typescript` — which then produce a purl
 * for a package that does not exist. Those entries happened to be unreachable in
 * Yarn's own built-in patches, so the damage stayed invisible; a hand-written
 * `patch:` or an alias would have surfaced it as a fabricated component.
 */
export function splitDescriptor(descriptor: string): { name: string; range: string } {
  const at = descriptor.indexOf('@', 1)
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
