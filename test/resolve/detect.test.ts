import { describe, expect, it } from 'vitest'
import { CradleError } from '../../src/core/errors.js'
import { detectPackageManager } from '../../src/core/resolve/detect.js'
import { fixture } from '../support/fixtures.js'

describe('detectPackageManager', () => {
  it.each([
    ['npm', 'npm', 'package-lock.json'],
    ['pnpm', 'pnpm', 'pnpm-lock.yaml'],
    ['bun', 'bun', 'bun.lockb'],
  ] as const)('detects %s', async (dir, manager, lockfile) => {
    await expect(detectPackageManager(fixture(`detect/${dir}`))).resolves.toEqual({
      manager,
      lockfile,
    })
  })

  it('tells the two yarn.lock formats apart by their __metadata block', async () => {
    // Same filename, incompatible formats — this is why there are two parsers.
    await expect(detectPackageManager(fixture('detect/yarn-classic'))).resolves.toEqual({
      manager: 'yarn-classic',
      lockfile: 'yarn.lock',
    })
    await expect(detectPackageManager(fixture('detect/yarn-berry'))).resolves.toEqual({
      manager: 'yarn-berry',
      lockfile: 'yarn.lock',
    })
  })

  it('explains what to do when there is no lockfile', async () => {
    const error = await detectPackageManager(fixture('detect/no-lockfile')).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(CradleError)
    expect((error as CradleError).message).toContain('No lockfile')
    expect((error as CradleError).hint).toContain('npm install')
  })

  it('explains what to do when the directory is not a project', async () => {
    const error = await detectPackageManager(fixture('detect/not-a-project')).catch(
      (e: unknown) => e,
    )
    expect(error).toBeInstanceOf(CradleError)
    expect((error as CradleError).message).toContain('No package.json')
    expect((error as CradleError).hint).toContain('cradle scan')
  })
})
