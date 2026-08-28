# Example: a service with a backlog

A small project pinned to deliberately dated dependencies, so there is something
real to report. Everything here is what a project adopting cradle would actually
have: a lockfile, a `SECURITY.md`, a `.cradle/config.json`, and a workflow.

There is no `node_modules` and no source code — cradle reads the lockfile, so
neither is needed.

## Try it

```bash
cd examples/express-service
npx cradle-cli scan
open .cradle/report.html
```

You should see eight findings across `lodash` and `minimist`, two upgrade
suggestions that between them clear all of them, and a readiness checklist that
is mostly green because this project documents the things the checklist asks
about.

## Then adopt the gate

Running the gate on a project with a backlog fails, which is correct and also
useless:

```bash
npx cradle-cli check          # exit 1
```

Accept what is there today, and the gate starts reporting only what is new:

```bash
npx cradle-cli check --baseline   # writes .cradle/baseline.json
npx cradle-cli check              # exit 0
```

## Then rule on one

`minimist` is only reached through this project's own CLI wrapper, so the
prototype-pollution advisory does not apply. Record that rather than ignoring it:

```bash
npx cradle-cli suppress CVE-2021-44906 \
  --justification vulnerable_code_not_in_execute_path \
  --note "argv is only ever parsed from our own CI wrapper." \
  --expires 2027-03-31
```

`.cradle/vex.json` now carries a dated, attributed statement, and the report
moves that finding into its own section with the reason attached — visible, so a
reviewer can disagree.

## What to commit

`.cradle/config.json`, `.cradle/vex.json` and `.cradle/baseline.json` record
decisions and belong in git. The SBOM, the findings and the report are output and
are regenerated on every run.
