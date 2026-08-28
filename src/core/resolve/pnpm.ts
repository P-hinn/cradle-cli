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

  const rootProd = new Map<string, string>()
  const rootDev = new Map<string, string>()
  for (const [path, importer] of Object.entries(lock.importers ?? {})) {
    // Every importer is part of this product, so its production dependencies are
    // the product's too. The root is simply the importer at ".".
    collect(importer.dependencies, rootProd)
    collect(importer.optionalDependencies, rootProd)
    collect(importer.devDependencies, rootDev)

    if (path === '.') continue
    const workspace = await readWorkspacePackage(options.projectDir, path)
    if (workspace !== undefined) packages.set(workspace.key, workspace)
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

function collect(
  entries: Record<string, ImporterEntry> | undefined,
  into: Map<string, string>,
): void {
  for (const [name, entry] of Object.entries(entries ?? {})) {
    const version = entry.version
    // `link:../other` points at a workspace sibling rather than a registry
    // package; those have no entry under `packages`.
    if (typeof version !== 'string' || version.startsWith('link:')) continue
    into.set(name, `${name}@${basePackageKey(version)}`)
  }
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
