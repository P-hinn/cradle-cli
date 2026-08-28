import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * The version lives in package.json and is repeated in six other places: the
 * generated constant, the action's default, and the `uses:` tag in the README,
 * the spec and the example workflow.
 *
 * `npm version` bumps one of them. The first release attempt failed in CI
 * because of the other five, which is the good outcome - but it should fail
 * here, in a second, rather than after a tag has already been pushed.
 */
describe('version references', () => {
  it('all match package.json', () => {
    const script = fileURLToPath(new URL('../scripts/sync-version.mjs', import.meta.url))
    expect(() =>
      execFileSync(process.execPath, [script, '--check'], { stdio: 'pipe' }),
    ).not.toThrow()
  })
})
