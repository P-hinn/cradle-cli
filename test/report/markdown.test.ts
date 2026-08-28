import { describe, expect, it } from 'vitest'
import {
  buildPullRequestComment,
  COMMENT_MARKER,
  type PullRequestCommentInput,
} from '../../src/report/markdown.js'
import type { BaselineDiff, Finding, Severity } from '../../src/types/index.js'

function finding(name: string, severity: Severity, overrides: Partial<Finding> = {}): Finding {
  return {
    id: `GHSA-${name}`,
    aliases: [],
    summary: '',
    severity,
    severitySource: 'cvss',
    component: {
      bomRef: `pkg:npm/${name}@1.0.0`,
      name,
      version: '1.0.0',
      purl: `pkg:npm/${name}@1.0.0`,
      direct: true,
    },
    path: ['app', name],
    dependents: ['app'],
    references: [],
    osvUrl: `https://osv.dev/vulnerability/GHSA-${name}`,
    fixedIn: '1.1.0',
    ...overrides,
  }
}

function diff(overrides: Partial<BaselineDiff> = {}): BaselineDiff {
  return { added: [], known: [], resolved: [], worsened: [], ...overrides }
}

function comment(overrides: Partial<PullRequestCommentInput> = {}): string {
  return buildPullRequestComment({
    project: { name: 'app', version: '1.0.0' },
    packageManager: 'npm',
    scope: 'production',
    componentCount: 12,
    diff: diff(),
    suppressed: 0,
    failing: [],
    threshold: 'high',
    hasBaseline: true,
    toolName: 'cradle-cli',
    toolVersion: '0.0.0',
    ...overrides,
  })
}

describe('buildPullRequestComment', () => {
  it('starts with the marker the action edits by', () => {
    // Without it the action would post a new comment on every push.
    expect(comment().startsWith(COMMENT_MARKER)).toBe(true)
  })

  it('says plainly when nothing is new', () => {
    expect(comment()).toContain('Nothing new since the baseline')
  })

  it('distinguishes new findings from failing ones', () => {
    const added = [finding('a', 'low')]
    expect(comment({ diff: diff({ added }) })).toContain('none above the threshold')
    expect(comment({ diff: diff({ added }), failing: added })).toContain(
      '1 new finding at or above high',
    )
  })

  it('lists new findings worst first', () => {
    const body = comment({
      diff: diff({ added: [finding('low-one', 'low'), finding('crit', 'critical')] }),
    })
    expect(body.indexOf('GHSA-crit')).toBeLessThan(body.indexOf('GHSA-low-one'))
  })

  it('shows the route for a transitive finding', () => {
    const body = comment({
      diff: diff({
        added: [
          finding('ms', 'high', {
            component: {
              bomRef: 'pkg:npm/ms@2.1.3',
              name: 'ms',
              version: '2.1.3',
              purl: 'pkg:npm/ms@2.1.3',
              direct: false,
            },
            path: ['app', 'debug', 'ms'],
          }),
        ],
      }),
    })
    expect(body).toContain('app › debug › ms')
  })

  it('never truncates the list silently', () => {
    const added = Array.from({ length: 14 }, (_, i) => finding(`pkg-${i}`, 'high'))
    const body = comment({ diff: diff({ added }) })
    expect(body).toContain('4 further new findings are listed in the report')
  })

  it('says when there is no baseline yet', () => {
    expect(comment({ hasBaseline: false })).toContain('no baseline yet')
  })

  it('points out findings with no fix, and what to do about them', () => {
    const withoutFix = finding('a', 'high')
    delete withoutFix.fixedIn
    const body = comment({ diff: diff({ added: [withoutFix] }) })
    expect(body).toContain('no fix available')
    expect(body).toContain('cradle suppress')
    expect(body).toContain('_no fix yet_')
  })

  it('mentions VEX-ruled findings without listing them', () => {
    expect(comment({ suppressed: 3 })).toContain('**3** ruled out by VEX')
  })

  it('points at the uploaded artifact when there is one', () => {
    expect(comment({ artifactName: 'cradle-report' })).toContain('**cradle-report**')
    expect(comment()).not.toContain('attached to this run')
  })

  it('keeps a pipe in advisory text from breaking the table', () => {
    const body = comment({
      diff: diff({ added: [finding('a', 'high', { id: 'GHSA-a|b' })] }),
    })
    // Escaped, so the cell renders the pipe instead of ending there.
    expect(body).toContain('GHSA-a\\|b')
    const row = body.split('\n').find((line) => line.includes('GHSA-a'))
    // Four columns means five unescaped delimiters.
    expect(row?.replace(/\\\|/g, '').split('|').length).toBe(6)
  })

  it('flattens a newline in advisory text, which would end the row', () => {
    const body = comment({
      diff: diff({ added: [finding('a', 'high', { id: 'GHSA-a\nb' })] }),
    })
    expect(body).toContain('GHSA-a b')
  })

  it('carries the disclaimer', () => {
    expect(comment()).toContain('not legal advice and not a conformity assessment')
  })
})
