/**
 * The slice of the OSV schema we consume. Everything is optional because OSV
 * aggregates many databases and only `id` and `modified` are guaranteed.
 * https://ossf.github.io/osv-schema/
 */

export interface OsvSeverity {
  /** e.g. `CVSS_V2`, `CVSS_V3`, `CVSS_V4`. */
  type: string
  /** A vector string, not a number. */
  score: string
}

export interface OsvEvent {
  introduced?: string
  fixed?: string
  last_affected?: string
  limit?: string
}

export interface OsvRange {
  type: string
  events?: OsvEvent[]
}

export interface OsvAffected {
  package?: { name?: string; ecosystem?: string; purl?: string }
  ranges?: OsvRange[]
  versions?: string[]
  severity?: OsvSeverity[]
  database_specific?: Record<string, unknown>
}

export interface OsvReference {
  type: string
  url: string
}

export interface OsvVulnerability {
  id: string
  modified?: string
  published?: string
  withdrawn?: string
  aliases?: string[]
  summary?: string
  details?: string
  severity?: OsvSeverity[]
  affected?: OsvAffected[]
  references?: OsvReference[]
  database_specific?: Record<string, unknown>
}

/** One entry of a `POST /v1/querybatch` response, aligned by index with the request. */
export interface OsvBatchResult {
  vulns?: { id: string; modified?: string }[]
  next_page_token?: string
}

export interface OsvBatchResponse {
  results?: OsvBatchResult[]
}
