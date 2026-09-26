import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'

function root(file: string): string {
  return readFileSync(new URL(`../${file}`, import.meta.url), 'utf8')
}

const CONTRIBUTING = root('CONTRIBUTING.md')
const CONDUCT = root('CODE_OF_CONDUCT.md')
const PR_TEMPLATE = root('.github/PULL_REQUEST_TEMPLATE.md')
const TEMPLATE_DIR = new URL('../.github/ISSUE_TEMPLATE/', import.meta.url)

interface IssueTemplate {
  name: string
  description: string
  labels?: string[]
  body: {
    type: string
    id?: string
    attributes: {
      label?: string
      options?: (string | { label: string })[]
    }
    validations?: { required?: boolean }
  }[]
}

/**
 * The files nobody runs, and therefore the files that rot. These check the parts
 * that carry a promise: that the issue templates ask for the fields a
 * false-positive report is useless without, and that the rules CONTRIBUTING.md
 * states are the rules the repository actually enforces.
 */
describe('CONTRIBUTING.md', () => {
  it('names the four commands that make up the gate', () => {
    const pkg = JSON.parse(root('package.json')) as { scripts: Record<string, string> }
    for (const script of ['lint', 'typecheck', 'test', 'build']) {
      expect(pkg.scripts[script], script).toBeDefined()
      expect(CONTRIBUTING, script).toContain(
        `npm run ${script}`.replace('npm run test', 'npm test'),
      )
    }
  })

  it('states the rules that the gate cannot check', () => {
    const prose = CONTRIBUTING.replace(/\s+/g, ' ')
    expect(prose).toContain('Tests are never weakened')
    expect(prose).toContain('No new runtime dependency')
    expect(prose).toContain('No telemetry')
    expect(prose).toContain('report/escape.ts')
  })

  it('explains both kinds of lockfile fixture and where each goes', () => {
    expect(CONTRIBUTING).toContain('test/fixtures/')
    expect(CONTRIBUTING).toContain('test/corpus/')
    // The rule that keeps the test suite offline and fast.
    expect(CONTRIBUTING.replace(/\s+/g, ' ')).toContain('no installed `node_modules`')
  })

  it('says SPEC.md is binding and German', () => {
    const prose = CONTRIBUTING.replace(/\s+/g, ' ')
    expect(prose).toContain('binding reference')
    expect(prose).toContain('German')
  })

  it('links only to files that exist', () => {
    const targets = [...CONTRIBUTING.matchAll(/\]\((?!https?:|#)([^)]+)\)/g)]
      .map((match) => (match[1] ?? '').split('#')[0])
      .filter((target): target is string => target !== undefined && target !== '')

    expect(targets.length).toBeGreaterThan(0)
    for (const target of targets) {
      expect(() => root(target), target).not.toThrow()
    }
  })
})

describe('CODE_OF_CONDUCT.md', () => {
  it('is Contributor Covenant 2.1', () => {
    expect(CONDUCT).toContain('Contributor Covenant')
    expect(CONDUCT).toContain('version 2.1')
    expect(CONDUCT).toContain(
      'https://www.contributor-covenant.org/version/2/1/code_of_conduct.html',
    )
  })

  it('keeps all four enforcement tiers', () => {
    // A covenant with the ladder removed is a statement of intent, not a policy.
    for (const tier of ['Correction', 'Warning', 'Temporary Ban', 'Permanent Ban']) {
      expect(CONDUCT, tier).toContain(tier)
    }
  })

  it('gives a real reporting address rather than a placeholder', () => {
    expect(CONDUCT).not.toMatch(/\[INSERT|TODO|FIXME|CONTACT_METHOD/)
    const security = root('SECURITY.md')
    const address = CONDUCT.match(/[\w.+-]+@[\w.-]+\.\w+/)?.[0]
    expect(address).toBeDefined()
    // The same address the security policy publishes, so there is one place to
    // keep current rather than two that drift.
    expect(security).toContain(address as string)
  })
})

describe('issue templates', () => {
  const files = readdirSync(TEMPLATE_DIR)
    .filter((file) => file.endsWith('.yml'))
    .filter((file) => file !== 'config.yml')

  it('offers bug, feature and false-positive', () => {
    expect(files.sort()).toEqual(['bug.yml', 'false-positive.yml', 'feature.yml'])
  })

  it('routes security reports away from the public tracker', () => {
    const config = parse(readFileSync(new URL('config.yml', TEMPLATE_DIR), 'utf8')) as {
      blank_issues_enabled: boolean
      contact_links: { name: string; url: string }[]
    }
    // A blank issue is how a vulnerability ends up public.
    expect(config.blank_issues_enabled).toBe(false)
    expect(config.contact_links.some((link) => link.url.includes('security/advisories/new'))).toBe(
      true,
    )
  })

  for (const file of files) {
    describe(file, () => {
      const template = parse(readFileSync(new URL(file, TEMPLATE_DIR), 'utf8')) as IssueTemplate

      it('has a name, a description and a label', () => {
        expect(template.name).toBeTruthy()
        expect(template.description).toBeTruthy()
        expect(template.labels?.length).toBeGreaterThan(0)
      })

      it('gives every field an id and a label', () => {
        for (const field of template.body) {
          if (field.type === 'markdown') continue
          expect(field.id, JSON.stringify(field.attributes)).toBeTruthy()
          expect(field.attributes.label, field.id).toBeTruthy()
        }
      })

      it('lists the four package managers cradle supports wherever it asks', () => {
        const dropdown = template.body.find((field) => field.id === 'package-manager')
        if (dropdown === undefined) return
        const options = (dropdown.attributes.options ?? []).join(' ')
        for (const manager of ['npm', 'pnpm', 'Yarn Classic', 'Yarn Berry']) {
          expect(options, manager).toContain(manager)
        }
      })
    })
  }

  it('asks a false-positive report for the three fields it is useless without', () => {
    // Package manager, lockfile version and advisory ID. Without all three the
    // report cannot be reproduced, and an irreproducible false positive is an
    // opinion.
    const template = parse(
      readFileSync(new URL('false-positive.yml', TEMPLATE_DIR), 'utf8'),
    ) as IssueTemplate

    for (const id of ['package-manager', 'lockfile-version', 'advisory-id']) {
      const field = template.body.find((candidate) => candidate.id === id)
      expect(field, id).toBeDefined()
      expect(field?.validations?.required, id).toBe(true)
    }
  })

  it('tells a false-positive reporter when to use suppress instead', () => {
    const raw = readFileSync(new URL('false-positive.yml', TEMPLATE_DIR), 'utf8')
    // "The advisory is right but does not apply to us" is what VEX is for, not
    // a bug. Saying so in the template is cheaper than saying it in every reply.
    expect(raw).toContain('cradle suppress')
  })

  it('asks a bug report for the lockfile version too', () => {
    const template = parse(readFileSync(new URL('bug.yml', TEMPLATE_DIR), 'utf8')) as IssueTemplate
    const field = template.body.find((candidate) => candidate.id === 'lockfile-version')
    expect(field?.validations?.required).toBe(true)
  })
})

describe('pull request template', () => {
  it('lists the four gate commands as checkboxes', () => {
    for (const command of ['npm run lint', 'npm run typecheck', 'npm test', 'npm run build']) {
      expect(PR_TEMPLATE, command).toContain(`- [ ] \`${command}\``)
    }
  })

  it('asks about the things a reviewer cannot see in a diff', () => {
    const prose = PR_TEMPLATE.replace(/\s+/g, ' ')
    expect(prose).toContain('No test was weakened')
    expect(prose).toContain('No new runtime dependency')
    expect(prose).toContain('`SPEC.md` extended')
    expect(prose).toContain('CHANGELOG.md')
    expect(prose).toContain('No telemetry')
  })
})
