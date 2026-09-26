<!--
Thanks for this. CONTRIBUTING.md has the setup and the rules; this is the short
version of what a reviewer will look for.
-->

## What this changes

<!-- One or two sentences. What was wrong or missing, and what it does now. -->

Closes #

## Why

<!--
The reasoning, not the diff - the diff is already below. If this is a behaviour
change, say what the old behaviour was and why the new one is better. If it
touches something SPEC.md decided, say which section and whether the decision
still holds.
-->

## The gate

All four have to pass. CI runs them on Node 22 and 24 across Linux, macOS and
Windows, so a platform-specific failure will surface there rather than here.

- [ ] `npm run lint`
- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `npm run build`

## Checks a reviewer will make

- [ ] **Tests cover the changed paths.** New behaviour has a test that fails
      without the change.
- [ ] **No test was weakened or removed to go green.** If one had to change,
      the description says why it was wrong before.
- [ ] **No new runtime dependency** — or there is one, and `SPEC.md` §4.1 now
      carries its justification.
- [ ] **`SPEC.md` extended** if this adds or changes behaviour. Diverging from it
      silently is the one thing that gets a pull request closed.
- [ ] **`CHANGELOG.md` updated under `## Unreleased`** if a user would notice.
      Internal refactors and test-only changes do not need an entry.
- [ ] **Anything rendered into the report goes through `report/escape.ts`.**
      Advisory text and package names come off the network and the report opens
      from `file://`.
- [ ] **`core/` still writes nothing and prints nothing.** File access and output
      belong in `cli/`.
- [ ] **No telemetry, no phone-home, no new network destination** — or the new
      destination is documented in `SECURITY.md` and skipped by `--offline`.
- [ ] Commit messages are Conventional Commits, in English.

## Anything a reviewer should know

<!--
Deliberate omissions, a shape you could not support and how cradle now reports
that rather than failing silently, a decision you are unsure about. This section
is more useful than an empty one.
-->
