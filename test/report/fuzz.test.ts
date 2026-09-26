import { describe, expect, it } from 'vitest'
import { escapeHtml } from '../../src/report/escape.js'
import { buildReport, type ReportInput } from '../../src/report/html.js'
import type {
  DependencyGraph,
  Finding,
  ReadinessReport,
  ResolveNote,
} from '../../src/types/index.js'
import {
  FORBIDDEN_ELEMENTS,
  FORBIDDEN_IN_TAGS,
  HOSTILE_PAYLOADS,
  HOSTILE_URLS,
  JS_LINE_TERMINATORS,
  tagSkeletons,
  unbalancedQuotes,
} from '../support/hostile.js'

const BASE = {
  timestamp: '2026-09-26T00:00:00.000Z',
  offline: false,
  specVersion: '1.6',
  serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
  toolName: 'cradle-cli',
  toolVersion: '0.0.0',
} satisfies Omit<ReportInput, 'graph' | 'findings'>

/**
 * Put `value` into every field of the report that carries text from outside, all
 * at once. One payload at a time through one field would miss the interesting
 * case, which is a payload in a field nobody remembered was rendered.
 */
function poisonedReport(value: string, url: string): string {
  const graph: DependencyGraph = {
    packageManager: 'npm',
    projectDir: '/app',
    root: {
      bomRef: 'pkg:npm/app@1.0.0',
      name: value,
      version: value,
      purl: 'pkg:npm/app@1.0.0',
      description: value,
      licenses: [{ kind: 'name', name: value }],
    },
    components: [
      {
        bomRef: 'pkg:npm/x@1.0.0',
        name: value,
        version: value,
        purl: 'pkg:npm/x@1.0.0',
        location: value,
        licenses: [
          { kind: 'name', name: value },
          { kind: 'expression', expression: value },
        ],
        licenseUnknown: false,
        hashes: [{ alg: 'SHA-512', content: 'ab'.repeat(64) }],
        resolvedUrl: url,
        direct: true,
        dev: false,
        workspace: false,
        kinds: ['prod'],
      },
    ],
    edges: new Map([['pkg:npm/app@1.0.0', ['pkg:npm/x@1.0.0']]]),
    includeDev: false,
    workspaces: [value],
    notes: [
      {
        kind: 'git-dependency',
        subject: value,
        message: value,
        hint: value,
      } satisfies ResolveNote,
    ],
  }

  const finding: Finding = {
    id: value,
    aliases: [value],
    summary: value,
    severity: 'critical',
    severitySource: 'cvss',
    component: {
      bomRef: 'pkg:npm/x@1.0.0',
      name: value,
      version: value,
      purl: 'pkg:npm/x@1.0.0',
      direct: true,
    },
    path: [value, value],
    dependents: [value],
    references: [
      { type: value, url },
      { type: 'ADVISORY', url: 'https://example.test/ok' },
    ],
    osvUrl: url,
  }

  const suppressed: Finding = {
    ...finding,
    suppression: {
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      notes: value,
      actionStatement: value,
      expires: value,
      expired: false,
    },
  }

  const readiness: ReadinessReport = {
    checks: [
      {
        id: value,
        title: value,
        status: 'open',
        detail: value,
        nextStep: value,
        reference: value,
      },
    ],
    counts: { met: 0, partial: 0, open: 1, 'not-assessable': 0 },
  }

  return buildReport({ ...BASE, graph, findings: [finding], suppressed: [suppressed], readiness })
}

function scriptBlocks(html: string): string[] {
  return [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map((match) => match[1] ?? '')
}

/** Every tag, and every element, held to the patterns that must never appear. */
function expectNothingExecutable(html: string): void {
  for (const skeleton of tagSkeletons(html)) {
    for (const { name, pattern } of FORBIDDEN_IN_TAGS) {
      expect(pattern.test(skeleton), `${name} in ${skeleton.slice(0, 160)}`).toBe(false)
    }
  }
  for (const { name, pattern } of FORBIDDEN_ELEMENTS) {
    expect(pattern.test(html), name).toBe(false)
  }
  // A quote left over after quoted values are removed means a payload closed an
  // attribute, which is the breakout the patterns above are looking for.
  expect(unbalancedQuotes(html)).toEqual([])
}

/**
 * The report is a file people save, forward by email, and open from a download
 * folder — so it renders with the reader's `file://` origin, where an injected
 * script is not sandboxed by anything. Every string in it has been through a
 * registry or an advisory database.
 *
 * These drive each payload through every text-bearing field at once and assert
 * that nothing executable survives. Each payload is named, so a failure says
 * which technique got through rather than only that something did.
 */
describe.each(HOSTILE_PAYLOADS)('report fuzz: $name', ({ value }) => {
  const html = poisonedReport(value, 'https://example.test/ok')

  it('contains exactly the two script blocks the report owns', () => {
    // The embedded JSON and the behaviour script. Anything else means a payload
    // opened a block, and a count catches that where a substring search cannot.
    expect(html.match(/<script/g) ?? []).toHaveLength(2)
    expect(html.match(/<\/script>/g) ?? []).toHaveLength(2)
  })

  it('has no executable construct anywhere', () => {
    expectNothingExecutable(html)
  })

  it('keeps the document parseable as a single tree', () => {
    // A payload that opens a tag and is not escaped would leave the rest of the
    // report inside it. Tag counts staying balanced is a cheap proxy.
    const opened = (html.match(/<table[\s>]/g) ?? []).length
    const closed = (html.match(/<\/table>/g) ?? []).length
    expect(opened).toBe(closed)
  })

  it('escapes the payload rather than dropping it', () => {
    // Silently discarding hostile input would be safe and unhelpful: a package
    // really is named that, and the reader needs to see it. So the escaped form
    // has to be present, character for character.
    expect(html).toContain(escapeHtml(value))
  })

  it('escapes the JavaScript line terminators inside the script blocks', () => {
    // U+2028 and U+2029 are legal raw in JSON and are line terminators in
    // JavaScript source, so they end a statement early inside a script block.
    // In body text they are ordinary characters.
    for (const block of scriptBlocks(html)) {
      expect(JS_LINE_TERMINATORS.test(block)).toBe(false)
    }
  })

  it('leaves the embedded JSON valid', () => {
    // The block is documented as a machine-readable record of the run. If a
    // payload breaks it, the report silently stops being that.
    const block = html.match(
      /<script type="application\/json" id="cradle-data">\n([\s\S]*?)\n<\/script>/,
    )
    expect(block?.[1]).toBeDefined()
    expect(() => JSON.parse(block?.[1] ?? '')).not.toThrow()
  })
})

describe.each(HOSTILE_URLS)('report fuzz, url: $name', ({ value }) => {
  const html = poisonedReport('plain', value)

  it('never becomes an href', () => {
    // safeUrl allows http and https only. Everything here is one of the schemes
    // that has no business in a document a reader clicks around in.
    const hrefs = [...html.matchAll(/href="([^"]*)"/g)].map((match) => match[1] ?? '')
    for (const href of hrefs) {
      expect(href, href).toMatch(/^https?:\/\//)
    }
  })

  it('produces no inline handler and no dangerous scheme', () => {
    expectNothingExecutable(html)
  })

  it('still records the URL verbatim in the embedded JSON', () => {
    // Deliberate, and the same decision as the existing hostile-input tests: that
    // block is a faithful record of what the advisory said, and it is inert data.
    // Rewriting it there would make the report disagree with findings.json.
    const block = html.match(
      /<script type="application\/json" id="cradle-data">\n([\s\S]*?)\n<\/script>/,
    )
    const data = JSON.parse(block?.[1] ?? '') as {
      findings: { references: { url: string }[] }[]
    }
    expect(data.findings[0]?.references?.[0]?.url).toBe(value)
  })
})

describe('report fuzz: all payloads at once', () => {
  it('survives every payload in every field in a single document', () => {
    // The combined case, because escaping bugs tend to live at a boundary between
    // two fields rather than inside one.
    const value = HOSTILE_PAYLOADS.map((payload) => payload.value).join(' ')
    const html = poisonedReport(value, HOSTILE_URLS[0]?.value ?? 'javascript:alert(1)')

    expect(html.match(/<script/g) ?? []).toHaveLength(2)
    expectNothingExecutable(html)
    for (const block of scriptBlocks(html)) {
      expect(JS_LINE_TERMINATORS.test(block)).toBe(false)
    }
  })
})
