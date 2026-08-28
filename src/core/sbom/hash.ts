import type { ComponentHash } from '../../types/index.js'

/**
 * npm stores Subresource Integrity strings: `sha512-<base64>`, possibly several
 * separated by whitespace. CycloneDX wants the algorithm spelled its way and the
 * digest as lowercase **hex** — handing it the base64 produces a field every
 * validator accepts and every consumer misreads (SPEC.md §5a).
 */
const ALGORITHMS: Record<string, ComponentHash['alg']> = {
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  sha384: 'SHA-384',
  sha512: 'SHA-512',
}

/** Expected digest length in bytes, used to reject truncated or malformed input. */
const DIGEST_BYTES: Record<ComponentHash['alg'], number> = {
  MD5: 16,
  'SHA-1': 20,
  'SHA-256': 32,
  'SHA-384': 48,
  'SHA-512': 64,
}

export function parseIntegrity(integrity: string | undefined | null): ComponentHash[] {
  if (!integrity) return []

  const hashes: ComponentHash[] = []
  for (const entry of integrity.trim().split(/\s+/)) {
    const dash = entry.indexOf('-')
    if (dash <= 0) continue

    const alg = ALGORITHMS[entry.slice(0, dash).toLowerCase()]
    if (alg === undefined) continue

    // SRI allows `?options` after the digest; nothing in npm uses it, but drop it.
    const digest = entry.slice(dash + 1).split('?')[0] ?? ''
    let bytes: Buffer
    try {
      bytes = Buffer.from(digest, 'base64')
    } catch {
      continue
    }
    if (bytes.length !== DIGEST_BYTES[alg]) continue

    hashes.push({ alg, content: bytes.toString('hex') })
  }
  return hashes
}
