import { fileURLToPath } from 'node:url'

/** Absolute path of a fixture project under test/fixtures/. */
export function fixture(name: string): string {
  return fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url))
}
