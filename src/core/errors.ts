/**
 * Errors carry a hint alongside the message, because "ENOENT" is not an error
 * message (SPEC.md §9). The CLI prints both; nothing else formats errors.
 */
export class CradleError extends Error {
  /** What the user should do about it. */
  readonly hint: string

  constructor(message: string, hint: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'CradleError'
    this.hint = hint
  }
}
