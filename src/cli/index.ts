#!/usr/bin/env node
/**
 * CLI entry point. Argument parsing uses node:util parseArgs; help text is
 * hand-written so we keep full control over the console output (SPEC.md §4).
 *
 * Commands land here in milestones 1–6.
 */

const HELP = `cradle — SBOM, findings and a CRA readiness report for npm projects

Usage:
  cradle <command> [options]

Commands:
  scan        Resolve dependencies, write SBOM, findings and report to .cradle/
  check       Like scan, with baseline comparison and CI exit codes
  suppress    Record an OpenVEX statement for a finding

Run 'cradle <command> --help' for command-specific options.
`

function main(argv: string[]): number {
  const command = argv[0]
  if (command === undefined || command === '--help' || command === '-h') {
    process.stdout.write(HELP)
    return 0
  }
  process.stderr.write(
    `cradle: unknown command '${command}'.\n` +
      `Run 'cradle --help' to see the available commands.\n`,
  )
  return 2
}

process.exitCode = main(process.argv.slice(2))
