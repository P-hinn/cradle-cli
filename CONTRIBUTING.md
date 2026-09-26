# Contributing to cradle

Issues and pull requests are welcome. [`SPEC.md`](SPEC.md) is the working
specification — what was decided and why — and it is the binding reference. It is
in German; the README is authoritative for users. **Read the relevant section
before changing behaviour**, and if a change extends the specification, extend
`SPEC.md` in the same pull request. Silently diverging from it is the one thing
that gets a pull request closed.

Security reports go through [`SECURITY.md`](SECURITY.md), not the issue tracker.

## Setup

Node.js 22.9 or newer. Node 20 reached end of life in April 2026 and is not
supported.

```bash
git clone https://github.com/P-hinn/cradle-cli
cd cradle-cli
npm ci
```

`npm ci` rather than `npm install`, so you get the lockfile's tree and not a
slightly different one.

## The gate

Four commands, and all four have to pass before a pull request is ready. CI runs
them on Node 22 and 24 across Linux, macOS and Windows.

```bash
npm run lint        # biome check --error-on-warnings .
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run build       # tsdown
```

`npm run lint:fix` applies what Biome can fix on its own. Warnings are errors
here: a lint warning that nobody has to act on is a lint warning nobody reads.

While working on tests, `npm run test:watch`.

### Rules that the gate cannot check

- **Tests are never weakened to go green.** Fix the cause, or say in the pull
  request that you could not and why. A deleted assertion is a silent
  regression.
- **No new runtime dependency without a justification in `SPEC.md` §4.1.** There
  are four, six including transitives. For a tool about the size of dependency
  trees that number is a feature, and `@npmcli/arborist` was removed again
  before the first release for exactly this reason.
- **No telemetry.** Not now, not later. This is not negotiable and not a feature
  request.
- **`core/` takes its input as arguments and returns values.** It never writes a
  file and never prints. File access and output live in `cli/`. This is what
  makes the tests cheap.
- **Everything the report renders goes through `report/escape.ts`.** Package
  names, advisory summaries and reference URLs come off the network, and the
  report is opened from `file://` — an injected script would run with that
  origin.
- **No `any` without a comment saying why.**

## Commits and pull requests

[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), in
English, small, each one working on its own:

```
feat(resolve): read bundledDependencies from the lockfile
fix(report): escape advisory titles in the suppressed section
test(corpus): add a Yarn Berry workspace lockfile
docs: say what --workspace does
chore(deps): bump semver to 7.7.3
refactor(sbom): one place that decides a bom-ref
```

Scopes follow the source layout: `resolve`, `sbom`, `vulns`, `vex`, `readiness`,
`baseline`, `report`, `cli`, `release`.

Add a `CHANGELOG.md` entry under `## Unreleased` for anything a user would
notice. Internal refactors and test-only changes do not need one.

The code, comments, commit messages and documentation are in English. `SPEC.md`
is the one exception and stays German.

## Adding a lockfile fixture

This is the most common contribution, and the most useful one: a lockfile shape
that cradle gets wrong is a bug report with a fix attached.

There are two kinds, and they live in different places for a reason.

### A behaviour fixture — `test/fixtures/`

Use this when you are testing what cradle *does* with a shape: an alias, a `git+`
dependency, a package with no licence field. Small, hand-written, readable in a
diff.

1. Make a directory named after what it covers, not after its package manager
   alone: `test/fixtures/npm-aliases/`, `test/fixtures/pnpm-workspace/`.
2. Put in a `package.json` and the lockfile. **Nothing else, and no installed
   `node_modules`** — cradle reads the lockfile, and the tests have to run
   offline and deterministically without an install.
3. Hand-write the lockfile down to the minimum that reproduces the shape. A
   fixture copied out of a real project carries hundreds of irrelevant packages
   and nobody can see what it is for.
4. pnpm and Yarn lockfiles carry no licences (`SPEC.md` §6.1). If your test
   needs one, check in a minimal `node_modules` tree of **`package.json` files
   only, no code**, as `pnpm-basic` and `yarn-berry-basic` do.
5. Register it in `test/support/fixtures.ts` and write the test. Assert the
   thing you came for, not a whole snapshot.
6. Add a row to the fixture table in `SPEC.md` §9 saying what it covers.

### A corpus fixture — `test/corpus/`

Use this when you are testing that cradle survives a *real* lockfile at real
size: a Next.js app, an Angular CLI project, a pnpm workspace.

1. Generate it in a scratch directory with the real package manager, then copy
   **only the lockfile and the `package.json`** into
   `test/corpus/<name>/`. Delete `node_modules`.
2. Add the entry to the table in `test/corpus/corpus.test.ts`. The invariants —
   every component has a purl, every dependency edge points at a `bom-ref` that
   exists, the SBOM validates against the CycloneDX schema — apply to every
   corpus entry automatically; you do not write them again.
3. Run the tests once and commit the component-count snapshot along with the
   fixture. That number is a tripwire: when a parser change moves it, the diff
   says by how much.
4. Note in `test/corpus/<name>/README.md` which tool version generated it. A
   lockfile format changes, and in two years nobody remembers.

### Reporting a false positive instead

If cradle reports a finding that does not apply, you do not need a fixture to
tell us. Use the **false positive** issue template — it asks for the package
manager, the lockfile version and the advisory ID, which is what makes it
reproducible.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

Contributions are accepted under [Apache-2.0](LICENSE), the project's licence.
There is no separate contributor licence agreement.
