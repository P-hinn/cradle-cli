# Changelog

Notable changes, newest first. Versions follow [semantic versioning](https://semver.org);
while the project is pre-1.0, a minor bump may still change behaviour.

## Unreleased

### Added

- **Continuous integration.** `.github/workflows/ci.yml` runs the full gate —
  lint, typecheck, test, build — on Node 22 and 24 across Linux, macOS and
  Windows, then runs the freshly built CLI against `examples/express-service`
  from its lockfile with `--offline` and asserts both sides of the exit-code
  contract: `0` for a clean run and `2` for a path that cannot be read. Six
  matrix combinations rather than a sample, because the lockfile parsers join
  paths and a separator bug that only shows on Windows is the one that reaches a
  user before it reaches us.
- **CodeQL** with the `security-extended` query pack, and **OpenSSF Scorecard**
  publishing its result so the badge is verifiable by someone who does not trust
  the badge. Both have a badge in the README.
- **Dependabot** for npm and the workflow actions, weekly and grouped. The
  example project is deliberately excluded: it is pinned to dated dependencies
  so that it produces findings, and updating it would defeat it.
- **`CONTRIBUTING.md`**, **`CODE_OF_CONDUCT.md`** (Contributor Covenant 2.1),
  issue templates for bugs, features and **false-positive findings** — the last
  asking for the package manager, lockfile version and advisory ID, without
  which a false positive cannot be reproduced — and a pull-request template.

- **A lockfile corpus** under `test/corpus/`: real lockfiles at real size from a
  Next.js app, a Nuxt app, an Angular CLI app, a four-package pnpm workspace and
  a Yarn Berry project — between 184 and 1088 components each. Every entry is
  held to the same invariants, so adding one costs a table row: the scan
  completes, the component count equals an **independent count of the lockfile**
  derived from that format's own rules, every component has a purl, every
  dependency edge points at a `bom-ref` that exists, every component is reachable
  from the root, and the SBOM validates against both vendored CycloneDX schemas.
  A committed component count catches a parser change that quietly drops a shape
  while satisfying every other invariant.

### Fixed

- **pnpm monorepos were flattened and their members left unreachable.** Every
  workspace member's dependencies were attached to the root rather than to the
  member, so the route read `root › fastify` instead of `@acme/api › fastify` —
  and the members themselves had no incoming edge at all, which is the broken
  `dependencies` block SPEC.md §5c exists to prevent. `link:` edges, which is how
  pnpm records a `workspace:*` range, were dropped entirely: the most interesting
  edge in a monorepo is one of your own packages depending on another, and it was
  missing. The npm resolver already did this correctly; pnpm now matches it, and a
  test pins the two together because the parsers are required to agree. The corpus
  found this.
- **The release workflow could attach evidence from the wrong commit.** With
  `0.1.3` the publish succeeded and the run then failed uploading the second
  SBOM: release assets are keyed by filename, both SBOMs are written as
  `sbom.cdx.json`, and the duplicate name came back as `HTTP 404`. Making the
  names distinct fixed the upload, and making the workflow re-runnable meant a
  partial failure no longer burns a version number — but the two together left a
  gap. A re-run skips the publish when the version is already on the registry
  while still rebuilding the assets, so if the tag had moved in between, the SBOM
  and report on the release would describe a different commit than the published
  tarball. It now compares npm's recorded `gitHead` against the commit being
  built and refuses rather than publishing evidence about something other than
  what shipped. A published version is final: bump and tag again instead of
  moving a tag.
- **A failed scan is no longer discovered after the publish.** Both scans run
  with `|| true`, because a finding over the threshold is not a broken release —
  but a crash looks the same from the exit code. The evidence files are now
  checked for existence in the scan step, ahead of the publish.

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
