# Changelog

Notable changes, newest first. Versions follow [semantic versioning](https://semver.org);
while the project is pre-1.0, a minor bump may still change behaviour.

## Unreleased

Four areas: the repository's own CI and release integrity, robustness of the
lockfile parsers under real input, the exports and profiles German and EU teams
are asked for, and a translated report. Nothing here changes the default output
of `cradle scan` except two additional SBOM fields and a resolution-notes section
that is absent for an ordinary project.

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

- **`--timestamp <iso>` and `--serial-number <urn>` for reproducible builds.** Two
  runs over the same lockfile with the same values produce byte-identical
  `sbom.cdx.json`, `findings.json` **and** `report.html`. Both defaults stay as they
  were — a report should say when it was made, and a fresh serial number is what
  lets a reader tell two BOMs apart — so these override rather than replace them.

  Neither value is passed through unchecked. A timestamp is normalised to ISO UTC,
  because `2026-09-26T14:00:00+02:00` and `2026-09-26T12:00:00Z` are the same
  instant and reproducibility would be a lie if the spelling leaked into the
  output; an unparseable one is an error, since `new Date('2026')` would otherwise
  be accepted as midnight on New Year in the field an auditor reads as "when was
  this scanned". A serial number must be the UUID URN CycloneDX requires.
  `--serial-number` refuses `--workspace all`, because one serial number across
  several packages would produce several documents claiming to be the same
  document.

- **`--profile bsi-tr-03183`**, on both `scan` and `check`: the SBOM checked field
  by field against **BSI TR-03183-2 version 2.1.0 (2025-08-20)**, the German
  Federal Office for Information Security's SBOM guideline. Eighteen data fields
  from §4, §5.2.1–§5.2.4 and §6.1, each citing the section it comes from and the
  place the guideline's own mapping table puts it in CycloneDX 1.6. It appears as
  its own report section and in `check --format github` (as notices) and
  `--format markdown` (as a collapsed table).

  It never changes the exit code. Several fields the guideline requires are
  statements about your delivery — whether the shipped artefact is executable, an
  archive, a structured file — and cradle will not guess them; a build that is
  permanently red gets switched off. Those come back `not assessable` with the
  reason, as does the component creator, which a lockfile simply does not record.
  The verdict it is willing to give is "no required field is open", never
  "compliant".

  Two fields moved from unreachable to reachable: `metadata.manufacturer` is now
  written from `contactEmail` in `.cradle/config.json` (§5.2.1), and
  `bsi:component:filename` is derived from the resolved tarball URL (§5.2.2).

- **`--sbom-format cyclonedx|spdx|both`** — SPDX 2.3 JSON as `sbom.spdx.json`,
  from the same graph, with the same timestamp and the CycloneDX serial number in
  its document namespace, so the two are visibly one scan. Validated against the
  official SPDX 2.3 schema. Unknown fields say `NOASSERTION` and `filesAnalyzed`
  is `false`, both honestly: cradle reads a lockfile and never the files inside a
  package. A licence it could not map onto SPDX is `NOASSERTION` rather than an
  invented `LicenseRef`.
- **`--vex-format openvex|csaf|both`** — CSAF 2.0 in the VEX profile as
  `vex.csaf.json`, from the same suppressions that produce `vex.json`; a second
  rendering of one decision, never a second decision. The mapping is lossless
  where it matters: CSAF's `flags[].label` enumerates exactly the five
  justifications OpenVEX defines. Validated against the official CSAF schema, with
  FIRST's CVSS schemas vendored alongside it so no test reaches the network.

  With nothing suppressed, **no file is written**. The CSAF schema requires at
  least one vulnerability and one product, so an empty document is not a CSAF
  document — absent beats invalid, and the console says which.

- **`--lang en|de`.** The HTML report and the pull-request comment in German,
  with every string moved out to `src/report/i18n/` and the document's `lang`
  attribute set to match — a translated page that still says `lang="en"` is
  mispronounced by a screen reader and hyphenated wrongly by the browser.

  The terminology follows the German text of Regulation (EU) 2024/2847 rather
  than a literal translation, so a reader holding the regulation finds the same
  words: **Schwachstelle**, **Komponente**, **Begründung**,
  **Unterstützungszeitraum**. The disclaimers hedge exactly as hard in German as
  in English, and a test checks each one — softening a caveat in translation would
  make the German report claim more than the English one.

  What stays English is deliberate: the `data-*` attributes the filter script
  matches on, the CSS class names, and the comment marker the GitHub Action finds
  its own comment by. Those are vocabulary for a machine, and translating them
  would break filtering in German and nowhere else. The embedded JSON block is
  byte-identical in both languages, because it is a record of the scan rather than
  prose.

- **`cradle notify <advisory-id> --stage early-warning|notification|final`** —
  Article 14 report drafts, one per stage, filled in from `.cradle/findings.json`
  and `.cradle/config.json`. Each cites its paragraph, its deadline and what
  starts the clock, and names both destinations: the ENISA single reporting
  platform **and** the coordinating CSIRT, simultaneously (Art. 14(1)).

  It reads the scan rather than the network, so a 24-hour clock never waits on an
  API, and the draft cannot disagree with the report it accompanies. Everything a
  lockfile cannot answer — the Member States the product is placed on, any
  malicious actors, the version of *your* product that carries the fix — is a
  visible `[TO BE COMPLETED]` placeholder, and the console says how many are left.

  **It does not decide that you have to report, and it never submits anything.**
  Article 14 concerns *actively exploited* vulnerabilities; cradle knows an
  advisory exists and that the lockfile resolves the affected version, and cannot
  know whether anyone is exploiting it. That sits at the top of every draft, not
  in a footnote.

- **EPSS and CISA KEV, as an ordering signal.** A CVSS base score answers "how bad
  would this be"; triage under a clock needs "is anyone doing it". EPSS (FIRST)
  estimates the probability of exploitation in the next 30 days, and the CISA
  Known Exploited Vulnerabilities catalogue is evidence that it is happening. Both
  appear as a column in the report and a line in `cradle check`, and
  `check --sort exploit` puts known-exploited first, then EPSS, then severity — a
  medium CISA has evidence about outranks a critical nobody has touched, which is
  the opposite of what sorting by severity says.

  **`--fail-on` stays CVSS-based.** A gate whose threshold moves daily with
  somebody else's model goes red overnight for reasons nobody on the team changed.
  These order the work; the threshold decides what blocks.

  Cached like the advisory lookup, re-keyed daily because both sources are, and
  skipped by `--offline` or `--no-priority`. An outage at either source is a named
  caveat rather than a failed scan — and a finding with no CVE alias (both sources
  are keyed on CVE) shows **no data** rather than a zero, because "no data" and "no
  risk" are different answers. Only CVE identifiers leave the machine: no package
  name, no version, nothing about the project. `SECURITY.md` records both new
  destinations.

- **`check --format sarif`** — SARIF 2.1.0, which GitHub Code Scanning and
  GitLab's security dashboard both ingest, so neither needs a cradle-specific
  integration. Validated against the official schema. A direct dependency anchors
  to its line in `package.json`, where an annotation sits next to something you
  can change; a transitive one anchors to the lockfile rather than guessing a
  line. Fingerprints are advisory plus package name **without** the version, the
  same identity the baseline uses, so a patch bump of a still-vulnerable package
  does not reopen a dismissal.

  `security-severity` carries the computed CVSS base score where one exists and
  the band's midpoint where it does not — with the help text saying which, because
  a midpoint is a stand-in and 7.4 would look like a measurement. An offline run
  reports `executionSuccessful: false`, so a dashboard can tell "we looked and
  found nothing" from "we did not look".
- **`examples/gitlab-ci.yml`** — evidence, gate and merge-request comment, with the
  SBOM and SARIF uploaded as GitLab reports. It separates the scan from the gate
  because GitLab only ingests a security report from a job that passed, and it
  distinguishes exit 1 from exit 2 explicitly so a broken pipeline never reads as
  a vulnerability. Linked from the README next to the GitHub Action.

### Changed

- **The Article 14 final-report deadline is stated correctly now.** The README and
  `SPEC.md` both said "a final report within 14 days", omitting what the clock runs
  from. Art. 14(2)(c) ties it to a **corrective or mitigating measure becoming
  available**, not to becoming aware — the Commission says so explicitly. The
  difference matters in both directions, and a reporting template must not blur it.
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
