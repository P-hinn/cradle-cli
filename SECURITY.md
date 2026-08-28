# Security policy

## Reporting a vulnerability

Please report security issues privately rather than in a public issue.

- **GitHub:** [open a private advisory](https://github.com/P-hinn/cradle-cli/security/advisories/new)
- **Email:** contact@philippniestroj.com

Please include the version of `cradle-cli`, the package manager and lockfile
version involved, and a way to reproduce the problem. A project that triggers it
is worth more than a description.

You will get an acknowledgement within **5 working days**. If the report is
confirmed, expect an assessment within **14 days** and a fix or a documented
mitigation before any public disclosure. Credit is given unless you would rather
stay anonymous.

## What is in scope

`cradle` reads lockfiles, talks to OSV.dev and the npm registry, and writes an
HTML report. The report is opened locally and forwarded by email, so it runs with
the reader's `file://` origin. Anything that gets attacker-controlled content out
of that report and into execution is in scope, in particular:

- content from a package name, an advisory summary or a reference URL escaping
  its escaping in `report.html`
- a lockfile that makes cradle read or write outside the project directory
- a crafted advisory that makes cradle report a vulnerable dependency as clean

Findings that a dependency of a *scanned* project is vulnerable are not
vulnerabilities in cradle — that is the tool working.

## What cradle does on your machine

Static analysers flag capabilities, so here is the full list rather than making
you go and read the source:

| Capability | Where | Why |
| :-- | :-- | :-- |
| **Reads files** | the lockfile, `package.json`, `node_modules/*/package.json`, `.cradle/` | Resolving the tree, and reading licences for pnpm and Yarn, whose lockfiles do not carry them. Paths are contained to the project directory. |
| **Writes files** | `.cradle/` and the advisory cache | The SBOM, findings, report and VEX statements. Nothing outside those. |
| **Network** | `api.osv.dev`, `registry.npmjs.org` | Advisory lookup, and release dates and deprecation notices for the readiness check. Both are skipped entirely with `--offline`. |
| **Spawns a process** | `git config --get user.email`, once, in `cradle suppress` | OpenVEX requires an author, and this is the least intrusive way to know who is recording the decision. Fixed arguments, no shell, output ignored on failure. Pass `--author` and it is never called. |

There is no telemetry, no analytics and no phone-home of any kind.

## Supported versions

While the project is pre-1.0, only the latest published version receives fixes.
