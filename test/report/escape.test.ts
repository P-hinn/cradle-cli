import { describe, expect, it } from 'vitest'
import { embedJson, escapeHtml, safeUrl } from '../../src/report/escape.js'

describe('escapeHtml', () => {
  it('neutralises markup', () => {
    expect(escapeHtml('<img src=x onerror=alert(1)>')).toBe('&lt;img src=x onerror=alert(1)&gt;')
  })

  it('escapes both quote characters, so attribute values are safe too', () => {
    expect(escapeHtml(`" onmouseover="alert(1)`)).toBe('&quot; onmouseover=&quot;alert(1)')
    expect(escapeHtml("' onmouseover='alert(1)")).toBe('&#39; onmouseover=&#39;alert(1)')
  })

  it('escapes ampersands first, so entities are not double-decoded', () => {
    expect(escapeHtml('&lt;script&gt;')).toBe('&amp;lt;script&amp;gt;')
  })

  it('handles values that are not strings', () => {
    expect(escapeHtml(42)).toBe('42')
    expect(escapeHtml(undefined)).toBe('undefined')
  })
})

describe('embedJson', () => {
  it('cannot break out of a script block', () => {
    const embedded = embedJson({ summary: '</script><script>alert(1)</script>' })
    expect(embedded).not.toContain('</script>')
    expect(embedded).toContain('\\u003c/script\\u003e')
  })

  it('escapes the line separators that are literal newlines in JavaScript', () => {
    const embedded = embedJson({ text: 'a\u2028b\u2029c' })
    expect(embedded).not.toMatch(/[\u2028\u2029]/)
  })

  it('round-trips back to the original value', () => {
    const value = { a: 1, b: ['<x>', 'ü', '\u2028'] }
    expect(JSON.parse(embedJson(value))).toEqual(value)
  })
})

describe('safeUrl', () => {
  it('allows http and https', () => {
    expect(safeUrl('https://osv.dev/vulnerability/GHSA-x')).toBe(
      'https://osv.dev/vulnerability/GHSA-x',
    )
    expect(safeUrl('http://example.test/a')).toBe('http://example.test/a')
  })

  it('rejects schemes that execute or embed', () => {
    // Advisory references come from third-party databases.
    expect(safeUrl('javascript:alert(1)')).toBeUndefined()
    expect(safeUrl('  JavaScript:alert(1)  ')).toBeUndefined()
    expect(safeUrl('data:text/html,<script>alert(1)</script>')).toBeUndefined()
    expect(safeUrl('file:///etc/passwd')).toBeUndefined()
  })

  it('rejects anything that is not a URL', () => {
    expect(safeUrl('not a url')).toBeUndefined()
    expect(safeUrl('')).toBeUndefined()
    expect(safeUrl(undefined)).toBeUndefined()
  })
})
