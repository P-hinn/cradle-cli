import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'
import type { DependencyGraph } from '../../types/index.js'
import { CradleError } from '../errors.js'
import { buildGraph, type RawPackage, type RootManifest } from './graph.js'
import { pnpmCandidates, readLicensesFromDisk } from './licenses.js'
import { readManifest } from './manifest.js'

/** One entry under an importer's dependencies block. */
interface ImporterEntry {
  specifier?: string
  version?: string
}

interface Importer {
  dependencies?: Record<string, ImporterEntry>
  devDependencies?: Record<string, ImporterEntry>
  optionalDependencies?: Record<string, ImporterEntry>
}

interface Lockfile {
  lockfileVersion?: string | number
  importers?: Record<string, Importer>
  packages?: Record<string, { resolution?: { integrity?: string; tarball?: string } }>
  snapshots?: Record<
    string,
    { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }
  >
}

export interface ResolvePnpmOptions {
  projectDir: string
  includeDev: boolean
}

/**
 * Resolve a pnpm project from `pnpm-lock.yaml`.
 *
 * pnpm v9 splits what npm keeps together: `packages` carries resolution and
 * integrity, `snapshots` carries the edges, and `importers` records what each
 * workspace asked for. Snapshot keys also carry the peer context they were
 * resolved under — `debug@4.3.7(supports-color@7.2.0)` — which has to come off
 * before the key means anything as a package identity.
 */
export async function resolvePnpm(options: ResolvePnpmOptions): Promise<DependencyGraph> {
  const lockPath = join(options.projectDir, 'pnpm-lock.yaml')
  const lock = await readLockfile(lockPath)
  const manifest = await readManifest(options.projectDir)

  const packages = new Map<string, RawPackage>()
  for (const [rawKey, entry] of Object.entries(lock.packages ?? {})) {
    const key = basePackageKey(rawKey)
    const parsed = splitNameVersion(key)
    if (parsed === undefined) continue

    const pkg: RawPackage = {
      key,
      name: parsed.name,
      version: parsed.version,
      dependencies: new Map(),
    }
    const integrity = entry.resolution?.integrity
    if (typeof integrity === 'string') pkg.integrity = integrity
    const tarball = entry.resolution?.tarball
    if (typeof tarball === 'string') pkg.resolvedUrl = tarball
    packages.set(key, pkg)
  }

  for (const [rawKey, snapshot] of Object.entries(lock.snapshots ?? {})) {
    const pkg = packages.get(basePackageKey(rawKey))
    if (pkg === undefined) continue

    for (const [name, version] of Object.entries(snapshot.dependencies ?? {})) {
      if (version.startsWith('link:')) continue
      pkg.dependencies.set(name, `${name}@${basePackageKey(version)}`)
    }
    for (const [name, version] of Object.entries(snapshot.optionalDependencies ?? {})) {
      if (version.startsWith('link:')) continue
      pkg.dependencies.set(name, `${name}@${basePackageKey(version)}`)
      pkg.optional = (pkg.optional ?? new Set()).add(name)
    }
  }

  // Workspace packages are read first, so that a `link:` dependency has
  // something to resolve to when the importers are walked below.
  const workspacesByPath = new Map<string, RawPackage>()
  for (const importerPath of Object.keys(lock.importers ?? {})) {
    if (importerPath === '.') continue
    const workspace = await readWorkspacePackage(options.projectDir, importerPath)
    if (workspace === undefined) continue
    packages.set(workspace.key, workspace)
    workspacesByPath.set(normalizeImporterPath(importerPath), workspace)
  }

  const rootProd = new Map<string, string>()
  const rootDev = new Map<string, string>()

  for (const [importerPath, importer] of Object.entries(lock.importers ?? {})) {
    const workspace =
      importerPath === '.' ? undefined : workspacesByPath.get(normalizeImporterPath(importerPath))

    const collect = (
      entries: Record<string, ImporterEntry> | undefined,
      into: Map<string, string>,
      optional: boolean,
    ): void => {
      for (const [name, entry] of Object.entries(entries ?? {})) {
        if (typeof entry.version !== 'string') continue
        const key = resolveImporterDependency(
          importerPath,
          name,
          entry.version,
          workspacesByPath,
          normalizeImporterPath,
        )
        if (key === undefined) continue
        into.set(name, key)
        if (optional && workspace !== undefined) {
          workspace.optional = (workspace.optional ?? new Set()).add(name)
        }
      }
    }

    if (workspace === undefined) {
      collect(importer.dependencies, rootProd, false)
      collect(importer.optionalDependencies, rootProd, true)
      collect(importer.devDependencies, rootDev, false)
      continue
    }

    // A workspace member's dependencies hang off that member, not off the root.
    // `@acme/api › fastify` is the route; flattening it to `root › fastify` loses
    // exactly what a route is for, and left the member itself with no incoming
    // edge at all — a component nothing points at, which is the broken
    // dependencies block SPEC.md §5c is about.
    //
    // Dev dependencies are linked the same way the npm resolver links a
    // workspace's own dev dependencies, so that the parsers agree on what a
    // production scope contains (SPEC.md §6.1).
    collect(importer.dependencies, workspace.dependencies, false)
    collect(importer.optionalDependencies, workspace.dependencies, true)
    collect(importer.devDependencies, workspace.dependencies, false)
    rootProd.set(workspace.name, workspace.key)
  }

  const licenses = await readLicensesFromDisk(options.projectDir, packages.values(), pnpmCandidates)

  return buildGraph({
    packageManager: 'pnpm',
    projectDir: options.projectDir,
    manifest,
    packages,
    rootProd,
    rootDev,
    includeDev: options.includeDev,
    licenses,
  })
}

/**
 * Turn what an importer asked for into the key of the package it got.
 *
 * Most of the time that is `name@version`. The interesting case is
 * `link:../shared`, which is how pnpm records a `workspace:*` range: a path
 * relative to the importer's own directory, pointing at a sibling workspace.
 * Those have no entry under `packages` — they are the repository's own code —
 * so they resolve through the importer table instead.
 */
function resolveImporterDependency(
  importerPath: string,
  name: string,
  version: string,
  workspacesByPath: ReadonlyMap<string, RawPackage>,
  normalize: (path: string) => string,
): string | undefined {
  if (!version.startsWith('link:')) return `${name}@${basePackageKey(version)}`

  const base = importerPath === '.' ? '' : importerPath
  const target = normalize(posixJoin(base, version.slice('link:'.length)))
  return workspacesByPath.get(target)?.key
}

/**
 * pnpm writes importer paths and `link:` targets with forward slashes regardless
 * of platform, so they are joined as posix paths rather than with node:path —
 * which on Windows would produce a backslash that never matches an importer key.
 */
function posixJoin(base: string, relative: string): string {
  return base === '' ? relative : `${base}/${relative}`
}

/** Collapse `./a/../b` and trailing slashes so two spellings of one path match. */
function normalizeImporterPath(path: string): string {
  const parts: string[] = []
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') {
      if (parts.length > 0 && parts[parts.length - 1] !== '..') parts.pop()
      else parts.push('..')
      continue
    }
    parts.push(part)
  }
  return parts.length === 0 ? '.' : parts.join('/')
}

/**
 * Strip the peer-resolution context pnpm appends to a key.
 *
 * `debug@4.3.7(supports-color@7.2.0)` and `debug@4.3.7` are the same package
 * installed under different peer sets. For an SBOM they are one component.
 */
function basePackageKey(key: string): string {
  const paren = key.indexOf('(')
  return paren === -1 ? key : key.slice(0, paren)
}

/** Split `@scope/name@1.2.3` on the version separator, not on the scope's `@`. */
function splitNameVersion(key: string): { name: string; version: string } | undefined {
  const at = key.lastIndexOf('@')
  if (at <= 0) return undefined
  const name = key.slice(0, at)
  const version = key.slice(at + 1)
  if (name === '' || version === '') return undefined
  return { name, version }
}

/**
 * A workspace package, read from its own package.json.
 *
 * pnpm's lockfile names workspace importers by path and never by package name,
 * so the only way to list them as components — as the npm resolver does — is to
 * open their manifests.
 */
async function readWorkspacePackage(
  projectDir: string,
  path: string,
): Promise<RawPackage | undefined> {
  let manifest: RootManifest
  try {
    manifest = JSON.parse(
      await readFile(join(projectDir, path, 'package.json'), 'utf8'),
    ) as RootManifest
  } catch {
    return undefined
  }
  if (manifest.name === undefined || manifest.name === '') return undefined

  const version = manifest.version ?? '0.0.0'
  const pkg: RawPackage = {
    key: `${manifest.name}@${version}`,
    name: manifest.name,
    version,
    dependencies: new Map(),
    workspace: true,
    location: path,
  }
  return pkg
}

async function readLockfile(path: string): Promise<Lockfile> {
  let raw: string
  try {
    raw = await readFile(path, 'utf8')
  } catch (cause) {
    throw new CradleError(`Could not read ${path}`, 'Run `pnpm install` and try again.', { cause })
  }

  let parsed: unknown
  try {
    parsed = parseYaml(raw)
  } catch (cause) {
    throw new CradleError(
      `${path} is not valid YAML`,
      'Delete it and run `pnpm install` to write a fresh one.',
      { cause },
    )
  }
  if (parsed === null || typeof parsed !== 'object') {
    throw new CradleError(`${path} is not a pnpm lockfile`, 'Expected a YAML mapping.')
  }

  const lock = parsed as Lockfile
  const version = String(lock.lockfileVersion ?? '')
  // v9 introduced the packages/snapshots split. Older layouts would parse into
  // an empty tree, which is worse than saying so.
  if (!version.startsWith('9') && !version.startsWith('10')) {
    throw new CradleError(
      `${path} has lockfileVersion ${version || '(missing)'}, which cradle cannot read`,
      'Only pnpm lockfile versions 9 and 10 are supported. Run `pnpm install` with pnpm 9 ' +
        'or newer to upgrade the lockfile.',
    )
  }
  return lock
}
