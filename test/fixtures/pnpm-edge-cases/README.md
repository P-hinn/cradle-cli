# pnpm-edge-cases

Modelled on real **pnpm 12.6.0** output (`pnpm install --lockfile-only`); the
`link:` entry pointing outside the workspace is added by hand, because pnpm will
not resolve a path that does not exist.

| Shape | How pnpm writes it | What cradle does |
| :-- | :-- | :-- |
| git dependency | key `left-pad@https://codeload…/<sha>`, `version: 1.3.0`, `resolution.gitHosted` | Reads the **`version:` field**; the key's tail is a URL |
| `file:` dependency | key `acme-local-lib@file:local-lib`, `resolution: {directory, type: directory}`, **no version** | Reads the version from that directory's `package.json` |
| `link:` outside the workspace | an importer entry only, nothing under `packages` | Notes it; there is nothing to describe |
| declared but absent | in `package.json`, missing from `packages` | Notes it |

The first two were producing fabricated purls. A git dependency became
`pkg:npm/left-pad@https://codeload.github.com/…` and a directory dependency
`pkg:npm/acme-local-lib@file:local-lib` — identities that name packages which
cannot exist, which is the same plausible-looking lie the Yarn Berry checksum
decision refuses (SPEC.md §6.1). A version that is not a version is now left out
with a note rather than invented.
