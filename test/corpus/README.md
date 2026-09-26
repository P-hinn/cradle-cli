# Corpus

Real lockfiles at real size, to answer a question the hand-written fixtures in
`test/fixtures/` cannot: does cradle survive what people actually have?

Each directory holds **only a `package.json` and a lockfile** — no
`node_modules`, no source, no config beyond what the package manager needs to
recognise a workspace. The tests run offline and deterministically.

Every entry is checked against the same invariants by `corpus.test.ts`, so adding
one costs a table row rather than a test:

- the scan completes
- the component count equals an independent count of the lockfile, derived from
  the format's own rules rather than from cradle's output
- every component carries a purl
- every dependency edge points at a `bom-ref` that exists
- the SBOM validates against the vendored CycloneDX 1.6 and 1.7 schemas
- the component count matches a committed snapshot

The snapshot is the tripwire. The invariants above say the output is
*self-consistent*; the snapshot says it has not silently changed size. A parser
change that drops a shape would satisfy every invariant and still be a
regression.

| Directory | Package manager | Generated from |
| :-- | :-- | :-- |
| `next-app` | npm, lockfileVersion 3 | `create-next-app` dependency set, Next.js 15.3.1, React 19.1.0 |
| `nuxt-app` | npm, lockfileVersion 3 | `nuxi init` dependency set, Nuxt 3.16.2 |
| `angular-app` | npm, lockfileVersion 3 | `ng new` dependency set, Angular 19.2 |
| `pnpm-workspace` | pnpm, lockfileVersion 9.0 | a four-package workspace: root, `@corpus/shared`, `@corpus/api`, `@corpus/web`, with `workspace:*` links between them |
| `yarn-berry` | Yarn Berry, `__metadata.version` 10 | Yarn 4.18.1, including two `patch:` entries for its built-in compatibility patches |

Generated on 2026-09-26 with npm 11 / Node 24, pnpm 12.6.0 and Yarn 4.18.1,
using `--package-lock-only`, `--lockfile-only` and `--mode=update-lockfile`
respectively, so no tarball was ever downloaded.

Lockfile formats change. When one does, regenerate rather than hand-edit: a
hand-patched lockfile stops being evidence of anything.
