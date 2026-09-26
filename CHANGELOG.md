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

- **Resolution notes.** A lockfile carries shapes an SBOM cannot state exactly —
  a package installed under an alias, built from a git commit, vendored from a
  directory, patched by the package manager, or declared and then absent. cradle
  now reports each one instead of dropping it: in the console, in `findings.json`
  so a machine sees the same caveats a human does, and in the report as its own
  section ahead of the component table. An ordinary project gets no notes at all,
  so their presence means something. The rule is not "handle everything", it is
  **never skip anything in silence** — a dropped dependency leaves a component
  count that still looks complete.

- **`.cradle/vex.json` is validated against the official OpenVEX JSON Schema**,
  vendored under `schema/` alongside the CycloneDX ones. Every justification the
  standard defines, multi-statement documents and the bytes `serializeDocument`
  actually writes are all covered.
- **A fuzz fixture for the report** — 30 payloads and 9 hostile URLs driven through
  every text-bearing field at once: script and attribute breakouts, unclosed tags,
  comment and style breakouts, `javascript:`/`data:`/`vbscript:` schemes, and the
  Unicode cases an angle-bracket escaper misses (U+2028/U+2029 line separators,
  bidirectional overrides, zero-width characters, fullwidth homoglyphs, an
  ideographic space, a BOM, astral-plane characters). Each payload is named, so a
  failure says which technique got through. Nothing executable survives, nothing
  is silently dropped, and the embedded JSON stays parseable.

- **`--workspace <name|all>` for monorepos.** One report per deliverable, written
  into that package's own directory so it sits with the code it describes. The
  package becomes the product, only its own dependencies appear, and the route
  starts where a team can act on it: `@acme/api › fastify › find-my-way` rather
  than `acme-monorepo › @acme/api › fastify › find-my-way`.

  The per-package graph is **sliced out of the repository-wide one**, never
  resolved separately. A monorepo has one lockfile and therefore one resolution; a
  package resolved on its own could pick different versions, and two cradle
  reports about the same code that disagree are worse than one. That also means
  one OSV query for the whole repository rather than one per package.

  VEX statements are read from the repository root **and** the package, the package
  winning a conflict — reading only the package's own file would re-report findings
  the team had already ruled on. `--workspace all` refuses `--output-dir`, which
  would quietly make every package overwrite the last.

  `cradle check --workspace <name>` gates a single package, with its baseline in
  that package's directory, so a sibling's backlog no longer reddens your gate.
  `check --workspace all` is deliberately refused: a gate has one exit code and one
  pull-request comment, and neither can honestly speak for several packages. Run
  one check per package.

### Changed

- **The documentation overstated OpenVEX conformance, and now says what is true.**
  `cradle:expires` was described as something "conforming tools ignore". They do
  not: OpenVEX has no extension point, its schema sets `additionalProperties:
  false` on a statement, and a strict validator therefore rejects the whole
  document rather than the unknown key. Remove that one key and the file validates
  exactly — a test pins both halves. The prefix makes the extension recognisable,
  not tolerated, and dropping `--expires` is the way to get a strictly conforming
  file.

### Fixed

- **Yarn descriptors were split on the last `@` instead of the first.** A scope's
  `@` sits at position zero and everything after the separator is a range, free to
  contain more of them — so `typescript@patch:typescript@npm%3A5.9.3#…` parsed to a
  package named `typescript@patch:typescript`. Yarn's own built-in patches happened
  to be unreachable, which kept the damage invisible; a hand-written `patch:` or an
  alias would have produced a fabricated component.
- **Yarn Berry took a component's name from the descriptor rather than the
  resolution.** For an alias those differ: `is-alias@npm:@sindresorhus/is@^7.0.1`
  resolves to `@sindresorhus/is@npm:7.2.0`, and the descriptor gave a component
  called `is-alias` with a purl for a package that does not exist. Berry also
  treated `linkType: soft` as "this is a workspace" — which it also is for
  `portal:` and `link:`, so those were dropped from the SBOM and then reported as
  missing from a lockfile they were plainly in. Only an `@workspace:` resolution
  makes a workspace.
- **pnpm gave git and `file:` dependencies a location where a version belongs.**
  A git dependency became `pkg:npm/left-pad@https://codeload.github.com/…` and a
  directory dependency `pkg:npm/acme-local-lib@file:local-lib`. The real version
  comes from pnpm's own `version:` field for the former and from the directory's
  `package.json` for the latter; where neither can be read the component is left
  out **and reported**, rather than given a made-up identity.
- **An npm `file:` dependency was listed as a workspace.** Both are materialised
  outside `node_modules` and their lockfile entries are indistinguishable; only
  the declared range separates them. The effect was somebody else's vendored code
  appearing in the workspace list as one of the product's own packages.
- **Yarn Classic never detected a git or `file:` dependency at all**, because only
  Berry's `resolution` field was read. Classic has no such field; the descriptor's
  range is the only place a protocol appears.
- **A root optional dependency was labelled `prod`.** The `optional` kind applied
  only to a package's own edges, never to the root's, and CycloneDX has a
  `scope: optional` that was going unused.
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
