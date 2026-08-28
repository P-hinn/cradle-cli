import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { CradleError } from '../errors.js'
import type { RootManifest } from './graph.js'

/** Read the project's own package.json. */
export async function readManifest(projectDir: string): Promise<RootManifest> {
  const path = join(projectDir, 'package.json')
  try {
    return JSON.parse(await readFile(path, 'utf8')) as RootManifest
  } catch (cause) {
    throw new CradleError(
      `Could not read ${path}`,
      'Run cradle from the root of the project you want to scan.',
      { cause },
    )
  }
}
