# cradle

Writes a CycloneDX SBOM for an npm project, looks up known vulnerabilities, and
produces a single HTML report you can send to an auditor.

```bash
npx cradle-cli
```

<!-- TODO: terminal recording goes here -->

---

## Quickstart

```bash
cd your-project
npx cradle-cli scan
```

That writes three files into `.cradle/`:

| File | What it is |
| --- | --- |
| `sbom.cdx.json` | CycloneDX 1.6, with real dependency edges rather than a flat list |
| `findings.json` | Known vulnerabilities, with the route from your product to each one |
| `report.html` | One self-contained page. No external requests, prints cleanly, sends by email |

No configuration, no account, no network call except the vulnerability lookup —
and `--offline` removes that one too.

## Why this exists

The EU Cyber Resilience Act, [Regulation (EU) 2024/2847][cra], applies in stages:

| Date | What starts applying |
| --- | --- |
| 11 June 2026 | Chapter IV — notification of conformity assessment bodies |
| **11 September 2026** | **Article 14 — reporting obligations** |
| **11 December 2027** | **Full application** |

Two things are worth getting right about what that means.

**The SBOM requirement is smaller than people say.** Annex I, Part II(1) asks for
a software bill of materials "in a commonly used machine-readable format covering
at the very least the top-level dependencies". Transitive dependencies are not
legally required. It is part of the technical documentation, kept for ten years,
and shown to market surveillance authorities on request — **there is no
obligation to publish it.** cradle records the whole tree anyway, because triage
under a 24-hour clock does not work without it. That is our argument, not the
legislator's.

**The reporting duty is not a single deadline.** Article 14 is three: an early
warning within 24 hours, a vulnerability notification within 72 hours, and a
final report within 14 days — to the ENISA single reporting platform *and* your
national CSIRT.

Container images have had good tooling for this for years. npm projects have SBOM
generators, and then you are on your own for the part that actually takes the
time: keeping it current, deciding which findings apply to you, and writing that
decision down somewhere an auditor can read it.

**Not everyone reading this is in scope.** The CRA covers products with digital
elements placed on the EU market. Open-source development outside a commercial
activity is largely out of scope, and "open-source software stewards" have lighter
obligations under Article 24.

## What it does

- **Four package managers.** npm, pnpm, Yarn Classic and Yarn Berry, all parsed
  from the lockfile, all producing the same graph for the same dependencies.
- **A real dependency graph.** `ms` hangs off `debug`, not off your root. That is
  the difference between an SBOM and a text file.
- **Findings with a route.** `acme-widget › express › body-parser` tells you
  whether this is an upgrade you can make or one you have to ask someone else for.
- **CVSS computed, not copied.** The v3 base score is calculated from the vector,
  and every finding records whether the severity came from that or from the
  advisory's own rating.
- **VEX suppressions that survive review.** An OpenVEX statement with one of the
  five standard justifications, signed and dated, in a file you commit.
- **A baseline, so the gate is adoptable.** An existing project always has a
  backlog. `cradle check` reports what is *new*.
- **A CRA readiness checklist.** The documentation and process questions, not
  just the packages.
- **Six runtime dependencies.** For a tool about the size of dependency trees,
  that felt like the minimum standard of care.

## What it does not do

Deliberately, so you know it is a decision and not a gap:

- Any ecosystem other than npm — no Python, no Go, no container images
- SPDX output. CycloneDX 1.6 and 1.7 only, for now
- Signed attestations, Sigstore, SLSA
- A web interface or a hosted service
- Automatic update pull requests — Dependabot and Renovate do that better
- License policy enforcement. Licences are shown, never blocked on
- Telemetry. Not now, not later

## In CI

```yaml
name: cradle
on: [pull_request]

permissions:
  contents: read
  pull-requests: write   # only needed for comment-on-pr

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: '22'
      - run: npm ci
      - uses: P-hinn/cradle-cli@v0.1.0
        with:
          fail-on: high
          upload-artifact: true
          comment-on-pr: true
```

Pin the exact tag while the project is pre-1.0. The action's default
`cradle-cli` version is the release it was cut from, so a pinned tag means a
pinned tool. A moving `v1` will exist once there is a 1.0 worth moving.

The action scans, checks against the baseline, uploads the report as a build
artifact and edits one pull-request comment in place rather than adding a new one
on every push.

Exit codes are part of the contract:

| Code | Meaning |
| --- | --- |
| `0` | Nothing new above the threshold |
| `1` | New findings above the threshold |
| `2` | cradle could not run |

The difference between 1 and 2 is the point. A broken tool must never read as a
security result.

### Adopting the gate on an existing project

A gate that is red on day one gets switched off. So accept what is there today:

```bash
npx cradle-cli check --baseline
```

Commit `.cradle/baseline.json`. From then on `cradle check` only reports what is
new. A finding is identified by advisory and package name, without the version —
bumping a still-vulnerable dependency is not news, and a gate that reddens on
unrelated churn is a gate nobody trusts. If an advisory is later re-rated *worse*
than when you accepted it, it counts as new again.

## Suppressing a finding you have looked at

Most of the pain is not "I cannot find vulnerabilities". It is drowning in
findings that do not apply to you.

```bash
npx cradle-cli suppress CVE-2021-44906 \
  --justification vulnerable_code_not_in_execute_path \
  --note "Only our own CI wrapper parses argv here; no untrusted input reaches minimist." \
  --expires 2027-03-31
```

That writes an [OpenVEX][openvex] statement into `.cradle/vex.json`:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "you@example.com",
  "statements": [
    {
      "vulnerability": { "name": "GHSA-xvch-5gv4-984h", "aliases": ["CVE-2021-44906"] },
      "products": [{ "@id": "pkg:npm/minimist@1.2.0" }],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "status_notes": "Only our own CI wrapper parses argv here; …",
      "cradle:expires": "2027-03-31"
    }
  ]
}
```

The category is mandatory, and only the five OpenVEX defines are accepted. That
is deliberately a little inconvenient: the category is what makes a suppression
something a reviewer can disagree with, rather than a silent dismissal. The free
text goes alongside it, not instead of it.

Suppressed findings stay in the report, in their own section, with the reason.
Hiding them would defeat the purpose.

`--expires` is a cradle extension — OpenVEX has no notion of expiry, so it is
written as `cradle:expires` and conforming tools ignore it. When it lapses the
finding comes back, carrying the note that its ruling expired. A decision about a
dependency should have to be renewed, not quietly outlive its reasoning.

## What belongs in git

```gitignore
**/.cradle/*
!**/.cradle/config.json
!**/.cradle/vex.json
!**/.cradle/baseline.json
```

The three exceptions record decisions. The rest is output, regenerated on every
run.

Two details that cost us an afternoon, so they may as well cost you nothing: the
negations need `.cradle/*` rather than `.cradle/`, because git cannot re-include
a file whose parent directory is excluded — and the `**/` matters in a monorepo,
because a pattern containing a slash is anchored to the directory the
`.gitignore` sits in. A blanket `.cradle/` silently drops the files holding your
own rulings.

## Configuration

Entirely optional. `.cradle/config.json` answers the questions cradle cannot work
out from your code:

```json
{
  "productName": "Acme Widget",
  "contactEmail": "security@acme.example",
  "placedOnMarket": "2026-01-15",
  "supportPeriodEnd": "2031-01-15"
}
```

`placedOnMarket` is what lets the readiness check actually test the five-year
support floor instead of just noting that a date exists. An unknown key is an
error rather than a no-op — a misspelt `supportPeriodEnd` would otherwise leave
the check reporting "not documented" while you are sure you documented it.

## Compared with the alternatives

Not a scoring table. They solve different problems.

| | Scope | Where cradle differs |
| --- | --- | --- |
| **[Syft][syft] / [Grype][grype]** | Many ecosystems, container-first | Syft and Grype are the right answer for images and polyglot repositories, and they go far wider than cradle ever will. cradle only knows npm, and spends that narrowness on the report and the checklist. |
| **[Trivy][trivy]** | Scanner for images, filesystems, IaC, secrets | Trivy is a broader security scanner with an SBOM mode. cradle is an SBOM and documentation tool with a vulnerability lookup. Different centre of gravity. |
| **[cdxgen][cdxgen]** | CycloneDX for many languages | cdxgen produces richer, more configurable SBOMs across far more ecosystems. cradle produces a narrower one and then does something with it. |
| **[@cyclonedx/cyclonedx-npm][cdxnpm]** | CycloneDX for npm | The closest comparison, actively maintained, and it does its job well. If an SBOM file is all you need, use it. cradle exists for what comes after: findings with a route, VEX, a baseline, a readiness checklist, and a report you can hand to someone. |
| **`npm audit`** | Built in, no install | Fast and free, but no SBOM, no VEX, no baseline, and nothing to send to an auditor. |

SBOM generation is table stakes. The difference is everything after it.

## Using it as a library

```ts
import { resolveNpm, buildBom, queryOsv, resolveFindings } from 'cradle-cli'

const graph = await resolveNpm({ projectDir: process.cwd(), includeDev: false })
const bom = buildBom(graph, {
  specVersion: '1.6',
  timestamp: new Date().toISOString(),
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
})
```

Everything under `core/` takes its input as arguments and returns values. It
reads a lockfile where it must, but never writes files and never prints. File
access and output live in the CLI layer.

## Requirements

Node.js 22.9 or newer. Node 20 reached end of life in April 2026, and a security
tool has no business running on an unsupported runtime.

## Legal note

cradle is a technical aid for documentation and process. **It is not legal
advice, not a conformity assessment, and not a declaration of conformity.**
Whether a product meets Regulation (EU) 2024/2847 is not something this or any
tool decides. The harmonised standards for the CRA are not final at the time of
writing.

Nothing cradle produces makes anyone compliant. It makes it easier to show what
you shipped and what you decided about it — which is the part that is tedious,
not the part that is hard.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

[cra]: https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng
[openvex]: https://github.com/openvex/spec
[syft]: https://github.com/anchore/syft
[grype]: https://github.com/anchore/grype
[trivy]: https://github.com/aquasecurity/trivy
[cdxgen]: https://github.com/CycloneDX/cdxgen
[cdxnpm]: https://github.com/CycloneDX/cyclonedx-node-npm
