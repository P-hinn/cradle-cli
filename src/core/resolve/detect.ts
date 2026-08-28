import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { PackageManager } from '../../types/index.js'
import { CradleError } from '../errors.js'

/** Lockfile -> package manager, in the order we probe for them. */
const LOCKFILES: readonly { file: string; manager: PackageManager }[] = [
  { file: 'package-lock.json', manager: 'npm' },
  { file: 'npm-shrinkwrap.json', manager: 'npm' },
  { file: 'pnpm-lock.yaml', manager: 'pnpm' },
  { file: 'bun.lock', manager: 'bun' },
  { file: 'bun.lockb', manager: 'bun' },
  { file: 'yarn.lock', manager: 'yarn-classic' },
]

export interface Detection {
  manager: PackageManager
  /** The lockfile we detected it from, relative to the project directory. */
  lockfile: string
}

/**
 * Work out which package manager produced this project's lockfile.
 *
 * `yarn.lock` needs a second look: Yarn Classic and Yarn Berry share the
 * filename but have entirely incompatible formats. Berry writes a `__metadata`
 * block, Classic never does.
 */
export async function detectPackageManager(projectDir: string): Promise<Detection> {
  if (!existsSync(join(projectDir, 'package.json'))) {
    throw new CradleError(
      `No package.json in ${projectDir}`,
      'Run cradle from the root of an npm project, or pass the path: cradle scan ./my-project',
    )
  }

  for (const { file, manager } of LOCKFILES) {
    const path = join(projectDir, file)
    if (!existsSync(path)) continue
    if (manager !== 'yarn-classic') return { manager, lockfile: file }
    return { manager: await yarnFlavour(path), lockfile: file }
  }

  throw new CradleError(
    `No lockfile found in ${projectDir}`,
    'cradle reads the resolved dependency tree from a lockfile. Run your package ' +
      "manager's install once (for example `npm install`) and try again.",
  )
}

async function yarnFlavour(lockfilePath: string): Promise<PackageManager> {
  const head = (await readFile(lockfilePath, 'utf8')).slice(0, 2048)
  return /^__metadata:/m.test(head) ? 'yarn-berry' : 'yarn-classic'
}
