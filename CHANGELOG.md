# Changelog

Notable changes, newest first. Versions follow [semantic versioning](https://semver.org);
while the project is pre-1.0, a minor bump may still change behaviour.

## 0.1.0 — 2026-08-28

First release.

### Added

- **`cradle scan`** — resolves the dependency tree from the lockfile and writes a
  CycloneDX SBOM, a findings file and a self-contained HTML report to `.cradle/`.
  Production dependencies only by default; `--include-dev` widens it.
- **Four package managers** — npm, pnpm, Yarn Classic and Yarn Berry, all parsed
  from the lockfile, all producing the same graph for the same dependencies.
- **Vulnerability lookup** via OSV.dev, batched and cached under
  `node_modules/.cache/cradle`. `--offline` skips it and says so in the output.
  CVSS v3 base scores are computed from the vector rather than taken on trust,
  and every finding records where its severity came from.
- **`cradle suppress`** — records an OpenVEX statement in `.cradle/vex.json`, with
  one of the five standard justifications, attributed and optionally dated.
- **`cradle check`** — a CI gate that reports only what is new since
  `.cradle/baseline.json`. Exit 0 clean, 1 new findings above the threshold,
  2 could not run. `--format github` emits workflow annotations anchored to the
  line in `package.json`; `--format markdown` renders a pull-request comment.
- **A CRA readiness checklist** — six checks covering the documentation and
  process the regulation asks for, each with a status and a concrete next step.
  Where cradle cannot tell, it reports `not assessable` rather than guessing.
- **A composite GitHub Action** that scans, checks, uploads the report and edits
  one pull-request comment in place.
- The package is usable as a library; everything under `core/` takes its input as
  arguments and returns values.

### Notes

- Requires Node.js 22.9 or newer. Node 20 reached end of life in April 2026.
- Four runtime dependencies, six including transitives.
- Yarn Berry SBOMs carry no hashes: its `checksum` is Yarn's own cache key over
  its own archive format, not the npm tarball digest, and emitting it as a
  CycloneDX SHA-512 would be a plausible-looking lie.
- pnpm lockfiles before version 9 and npm lockfiles before version 2 are refused
  rather than half-read — both predate the data cradle needs and would otherwise
  resolve into an empty or licence-less tree.
