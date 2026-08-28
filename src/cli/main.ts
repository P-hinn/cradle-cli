import { CradleError } from '../core/errors.js'
import { TOOL_VERSION } from '../version.generated.js'
import { runScan } from './scan.js'

const HELP = `cradle — SBOM, findings and a CRA readiness report for npm projects

Usage:
  cradle <command> [options]

Commands:
  scan        Resolve dependencies and write an SBOM to .cradle/
  check       Like scan, with baseline comparison and CI exit codes  (not yet implemented)
  suppress    Record an OpenVEX statement for a finding              (not yet implemented)

Options:
  -h, --help      Show this help
  -v, --version   Print the version

Run 'cradle <command> --help' for command-specific options.
`

/**
 * Exit codes are part of the contract, so CI can tell a security result from a
 * broken run: 0 clean, 1 findings over the threshold, 2 tool error (SPEC.md §6.4).
 */
export async function main(
  argv: string[],
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  const [command, ...rest] = argv

  if (command === undefined || command === '--help' || command === '-h') {
    stdout.write(HELP)
    return 0
  }
  if (command === '--version' || command === '-v') {
    stdout.write(`${TOOL_VERSION}\n`)
    return 0
  }

  try {
    switch (command) {
      case 'scan':
        return await runScan(rest, stdout)
      case 'check':
      case 'suppress':
        throw new CradleError(
          `'cradle ${command}' is not implemented yet`,
          "Only 'cradle scan' works today. See SPEC.md for the planned order of work.",
        )
      default:
        stderr.write(
          `cradle: unknown command '${command}'.\nRun 'cradle --help' to see the available commands.\n`,
        )
        return 2
    }
  } catch (error) {
    stderr.write(formatError(error))
    return 2
  }
}

function formatError(error: unknown): string {
  if (error instanceof CradleError) {
    return `\ncradle: ${error.message}\n  -> ${error.hint}\n\n`
  }
  // parseArgs throws plain TypeErrors for bad flags; its messages are already clear.
  const message = error instanceof Error ? error.message : String(error)
  return `\ncradle: ${message}\n  -> Run 'cradle --help', or open an issue if this looks like a bug.\n\n`
}
