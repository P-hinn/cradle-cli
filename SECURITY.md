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

## Supported versions

While the project is pre-1.0, only the latest published version receives fixes.
