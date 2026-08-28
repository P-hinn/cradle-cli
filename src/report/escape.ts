/**
 * Escaping for the report.
 *
 * Everything that ends up in the HTML has been through the network: package
 * names come from a registry, advisory summaries and reference URLs come from
 * OSV. None of it is trustworthy, and the report is a file people forward by
 * email and open locally, so an injected script would run with the recipient's
 * file:// origin. Escaping happens here and nowhere else.
 */

const HTML_ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

/** Escape text for use in element content or a quoted attribute value. */
export function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (character) => HTML_ENTITIES[character] ?? character)
}

/**
 * Embed a value as JSON inside a `<script>` block.
 *
 * `</script>` anywhere in the data would end the block early, and U+2028/U+2029
 * are literal line terminators in JavaScript source even though JSON permits
 * them raw.
 */
export function embedJson(value: unknown): string {
  return JSON.stringify(value, null, 2)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
}

/**
 * Return a URL only if it is safe to put in an href.
 *
 * Advisory references are third-party data; `javascript:` and `data:` URLs have
 * no business in a document a reader is expected to click around in.
 */
export function safeUrl(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const trimmed = value.trim()
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    return undefined
  }
  return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? trimmed : undefined
}
