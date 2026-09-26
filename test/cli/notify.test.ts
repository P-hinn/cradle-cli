import { cp, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Writable } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import { main } from '../../src/cli/main.js'
import { NOTIFY_STAGES } from '../../src/core/notify/article14.js'
import { MemoryCache } from '../../src/core/vulns/cache.js'
import { fixture } from '../support/fixtures.js'
import { fakeOsv } from '../support/osv.js'

function capture(): { stream: NodeJS.WritableStream; text: () => string } {
  const chunks: string[] = []
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk))
      callback()
    },
  })
  return { stream, text: () => chunks.join('') }
}

const temporaries: string[] = []

async function scannedProject(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cradle-notify-'))
  temporaries.push(dir)
  const project = join(dir, 'project')
  await cp(fixture('npm-vulnerable'), project, { recursive: true })
  await run(['scan', project])
  return project
}

afterEach(async () => {
  await Promise.all(temporaries.splice(0).map((dir) => rm(dir, { recursive: true, force: true })))
})

async function run(args: string[]): Promise<{ code: number; out: string; err: string }> {
  const out = capture()
  const err = capture()
  const code = await main(args, out.stream, err.stream, {
    fetch: fakeOsv().fetch,
    cache: new MemoryCache(),
    now: () => new Date('2026-09-26T09:00:00.000Z'),
  })
  return { code, out: out.text(), err: err.text() }
}

const ADVISORY = 'GHSA-xvch-5gv4-984h'

/**
 * Article 14 is the part of the CRA with a clock on it, and the part where a tool
 * can do the most damage by overreaching. So these test two things in equal
 * measure: that the template carries what the paragraph asks for, and that it
 * never claims the reporting duty applies.
 *
 * cradle knows an advisory exists and that the lockfile resolves the affected
 * version. It cannot know whether anyone is exploiting it — and Article 14 is
 * about actively exploited vulnerabilities. That gap is the reason the disclaimer
 * sits at the top of the document rather than at the bottom.
 */
describe('cradle notify', () => {
  it('drafts each of the three stages', async () => {
    const project = await scannedProject()
    for (const stage of NOTIFY_STAGES) {
      const { code, out } = await run(['notify', ADVISORY, project, '--stage', stage])
      expect(code, stage).toBe(0)
      expect(out, stage).toContain('Art. 14(2)')
      expect(out, stage).toContain(ADVISORY)
    }
  })

  it('cites the right paragraph and deadline for each stage', async () => {
    const project = await scannedProject()
    const draft = async (stage: string): Promise<string> =>
      (await run(['notify', ADVISORY, project, '--stage', stage])).out

    expect(await draft('early-warning')).toContain('Art. 14(2)(a)')
    expect(await draft('early-warning')).toContain('within 24 hours')
    expect(await draft('notification')).toContain('Art. 14(2)(b)')
    expect(await draft('notification')).toContain('within 72 hours')
    expect(await draft('final')).toContain('Art. 14(2)(c)')
    expect(await draft('final')).toContain('no later than 14 days')
  })

  it('says the final report’s clock starts at the measure, not at awareness', async () => {
    // The detail most summaries get wrong, including an earlier version of this
    // repository's own SPEC. 14 days runs from a corrective or mitigating measure
    // becoming available.
    const project = await scannedProject()
    const { out } = await run(['notify', ADVISORY, project, '--stage', 'final'])
    expect(out).toContain('from a corrective or mitigating measure becoming available')
    expect(out).toContain('**not** from becoming aware')
  })

  it('names both reporting destinations', async () => {
    // Art. 14(1): the ENISA platform and the coordinating CSIRT, simultaneously.
    // "Report to ENISA" on its own is the shortcut that leaves out a recipient.
    const project = await scannedProject()
    const { out } = await run(['notify', ADVISORY, project, '--stage', 'early-warning'])
    expect(out).toContain('ENISA single reporting platform')
    expect(out).toContain('coordinating CSIRT')
    expect(out).toContain('simultaneously')
  })

  it('refuses to imply that cradle decided anything', async () => {
    const project = await scannedProject()
    for (const stage of NOTIFY_STAGES) {
      const { out } = await run(['notify', ADVISORY, project, '--stage', stage])
      expect(out, stage).toContain('cradle did not determine that this has to be reported')
      expect(out, stage).toContain('actively exploited')
      expect(out, stage).toContain('your determination')
      expect(out, stage).toContain('Draft. Nothing has been submitted.')
      expect(out, stage).toContain('not legal advice')
    }
  })

  it('fills in what the scan knows', async () => {
    const project = await scannedProject()
    const { out } = await run(['notify', ADVISORY, project, '--stage', 'notification'])

    // The component, the route through the tree, and the advisory's own alias.
    expect(out).toContain('minimist')
    expect(out).toContain('CVE-2021-44906')
    expect(out).toContain('›')
    expect(out).toContain('https://osv.dev/vulnerability/')
  })

  it('separates a CVSS score from exploitability', async () => {
    // A base score rates the vulnerability in the abstract, and Article 14 is
    // about exploitation in this product. Blurring the two in a regulatory
    // document is the worst place to blur them.
    const project = await scannedProject()
    const { out } = await run(['notify', ADVISORY, project, '--stage', 'final'])
    expect(out).toContain('says nothing about exploitability in this product')
  })

  it('marks every unanswerable field, visibly', async () => {
    const project = await scannedProject()
    const { out } = await run(['notify', ADVISORY, project, '--stage', 'final'])

    // Member States, malicious actors, the released version: none of these is in
    // a lockfile, and a blank line would read as "nothing to say".
    expect(out).toContain('[TO BE COMPLETED:')
    expect(out).toContain('Malicious actors')
    expect((out.match(/\[TO BE COMPLETED:/g) ?? []).length).toBeGreaterThanOrEqual(3)
  })

  it('asks for the Member States in the early warning, where Article 14 does', async () => {
    const project = await scannedProject()
    const { out } = await run(['notify', ADVISORY, project, '--stage', 'early-warning'])
    expect(out).toContain('Member States')
  })

  it('uses the configured product name and contact when there is one', async () => {
    const project = await scannedProject()
    await run(['notify', ADVISORY, project, '--stage', 'early-warning'])

    // The example fixture has no config, so both are placeholders; with one, they
    // are filled. Checked here rather than assumed, because a template that
    // silently drops a configured contact is worse than one that never had it.
    const withoutConfig = (await run(['notify', ADVISORY, project, '--stage', 'early-warning'])).out
    expect(withoutConfig).toContain('name of the manufacturer')

    await cp(fixture('npm-vulnerable'), project, { recursive: true })
    const { writeFile, mkdir } = await import('node:fs/promises')
    await mkdir(join(project, '.cradle'), { recursive: true })
    await writeFile(
      join(project, '.cradle/config.json'),
      JSON.stringify({ productName: 'Acme Widget', contactEmail: 'security@acme.example' }),
      'utf8',
    )
    await run(['scan', project])
    const withConfig = (await run(['notify', ADVISORY, project, '--stage', 'early-warning'])).out
    expect(withConfig).toContain('Acme Widget')
    expect(withConfig).toContain('security@acme.example')
    expect(withConfig).not.toContain('name of the manufacturer')
  })

  it('writes to a file and reports how much is still missing', async () => {
    const project = await scannedProject()
    const { code, out } = await run([
      'notify',
      ADVISORY,
      project,
      '--stage',
      'notification',
      '--output',
      'reports/art14-72h.md',
    ])
    expect(code).toBe(0)

    const written = await readFile(join(project, 'reports/art14-72h.md'), 'utf8')
    expect(written).toContain('Art. 14(2)(b)')
    // The console says what is left, rather than implying the file is done.
    expect(out).toContain('fields need completing')
    expect(out).toContain('Nothing was submitted')
  })

  it('accepts the CVE somebody actually wrote down', async () => {
    // People note the CVE they read about; cradle keys npm advisories on GHSA.
    const project = await scannedProject()
    const { code, out } = await run([
      'notify',
      'cve-2021-44906',
      project,
      '--stage',
      'early-warning',
    ])
    expect(code).toBe(0)
    expect(out).toContain(ADVISORY)
  })
})

describe('cradle notify, refusals', () => {
  it('needs a stage, and says Article 14 is three obligations', async () => {
    const project = await scannedProject()
    const { code, err } = await run(['notify', ADVISORY, project])
    expect(code).toBe(2)
    expect(err).toContain('needs --stage')
    expect(err).toContain('three obligations')
  })

  it('refuses a stage it does not have', async () => {
    const project = await scannedProject()
    const { code, err } = await run(['notify', ADVISORY, project, '--stage', 'incident'])
    expect(code).toBe(2)
    expect(err).toContain("Unknown --stage 'incident'")
  })

  it('needs an advisory id', async () => {
    // No positionals at all, so nothing is read and nothing depends on where the
    // test happens to be running from.
    const { code, err } = await run(['notify', '--stage', 'final'])
    expect(code).toBe(2)
    expect(err).toContain('needs an advisory id')
  })

  it('treats a path in the first position as an advisory id, and says so', async () => {
    // `cradle notify ./my-project --stage final` is an easy mistake: the first
    // positional is always the advisory. The error has to be legible rather than
    // a complaint about a missing file.
    const project = await scannedProject()
    const { code, err } = await run(['notify', './my-project', project, '--stage', 'final'])
    expect(code).toBe(2)
    expect(err).toContain("No finding for './my-project'")
    expect(err).toContain('This scan has:')
  })

  it('says to scan first when there is no findings file', async () => {
    const { code, err } = await run([
      'notify',
      ADVISORY,
      fixture('npm-basic'),
      '--stage',
      'final',
      '--output-dir',
      '.nowhere',
    ])
    expect(code).toBe(2)
    expect(err).toContain('Run `cradle scan` first')
    // And why it reads a file rather than the network.
    expect(err).toContain('24-hour clock never waits on an API')
  })

  it('lists the advisories the scan does have', async () => {
    const project = await scannedProject()
    const { code, err } = await run(['notify', 'GHSA-0000-0000-0000', project, '--stage', 'final'])
    expect(code).toBe(2)
    expect(err).toContain('This scan has:')
    expect(err).toContain('GHSA-')
  })
})
