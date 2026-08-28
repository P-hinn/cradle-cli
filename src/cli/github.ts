import type { Finding } from '../types/index.js'

/**
 * GitHub Actions workflow-command annotations.
 *
 * These land in the run log and, when the file and line exist in the diff, next
 * to the offending line in the pull request. That is worth the effort of finding
 * the line: an annotation on the dependency you can actually change is read, one
 * on line 1 of the repository is scrolled past.
 */

/** Escaping required by the workflow-command format itself. */
function escapeMessage(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')
}

function escapeProperty(value: string): string {
  return escapeMessage(value).replace(/:/g, '%3A').replace(/,/g, '%2C')
}

/**
 * Find the line in package.json where a dependency is declared.
 *
 * A deliberately literal search rather than a JSON parse: we need the line
 * number, which parsing throws away. Returns undefined for a transitive package,
 * which is correct — it is declared nowhere in this file.
 */
export function findManifestLine(manifest: string, packageName: string): number | undefined {
  const needle = `"${packageName}"`
  const lines = manifest.split('\n')
  for (const [index, line] of lines.entries()) {
    const at = line.indexOf(needle)
    if (at === -1) continue
    // Must be a key, so `"lodash": "^4"` matches and `"main": "lodash"` does not.
    if (
      line
        .slice(at + needle.length)
        .trimStart()
        .startsWith(':')
    )
      return index + 1
  }
  return undefined
}

export interface AnnotationOptions {
  /** Contents of the project's package.json, for locating direct dependencies. */
  manifest?: string
  manifestPath?: string
}

export function toAnnotations(
  findings: readonly Finding[],
  options: AnnotationOptions = {},
): string[] {
  return findings.map((finding) => annotate(finding, options))
}

function annotate(finding: Finding, options: AnnotationOptions): string {
  const fix =
    finding.fixedIn === undefined
      ? 'no fix available yet'
      : `fixed in ${finding.component.name} ${finding.fixedIn}`
  const route = finding.component.direct ? 'direct dependency' : `via ${finding.path.join(' > ')}`

  const message = escapeMessage(
    `${finding.severity}: ${finding.id} in ${finding.component.name} ` +
      `${finding.component.version} (${route}, ${fix}). ${finding.osvUrl}`,
  )

  const properties: string[] = [`title=${escapeProperty(`${finding.id} (${finding.severity})`)}`]
  const line =
    options.manifest === undefined
      ? undefined
      : findManifestLine(options.manifest, finding.component.name)
  if (line !== undefined && options.manifestPath !== undefined) {
    properties.unshift(`file=${escapeProperty(options.manifestPath)}`, `line=${line}`)
  }

  return `::error ${properties.join(',')}::${message}`
}
