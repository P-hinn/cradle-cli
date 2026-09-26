# npm-edge-cases

Lockfile shapes that an SBOM cannot state exactly. The point of this fixture is
not that cradle handles all of them, it is that cradle never drops one in
silence — see `test/resolve/edge-cases.test.ts`.

| Shape | How it appears | What cradle does |
| :-- | :-- | :-- |
| `npm:` alias | `node_modules/is-alias` with `name: "@sindresorhus/is"` | Records the **published** name, because OSV is keyed on it, and notes the alias |
| git dependency | `resolved: git+ssh://…#<sha>`, no `integrity` | Keeps it, notes that the version is the commit's claim and not a release |
| `file:` dependency | an entry outside `node_modules/` plus a `link: true` pointer | Keeps it, and does **not** call it a workspace |
| bundled dependency | `inBundle: true`, no integrity of its own | Keeps it, notes that the parent's hash covers it |
| optional dependency | `optional: true` | Keeps it with `kinds: [optional]`, and says nothing — this is normal |
| override | a nested `node_modules/debug/node_modules/ms` at a different version | Two components, edges pointing at the right copy each |
| scoped package | `@sindresorhus/is` | `pkg:npm/%40sindresorhus/is@…` |
| private registry | `resolved:` on an internal host, with a token | URL stays in `externalReferences`; never in the purl, never in a hash |
| declared but absent | in `package.json`, missing from `packages` | Notes it, because the component count would otherwise describe a smaller project |

Generated with `npm install --package-lock-only` (npm 11, Node 24) so the alias,
git, `file:`, optional and override entries are npm's own output rather than
guesses. **Two entries are hand-written**, from npm's documented shape, and are
marked as such here because the distinction matters:

- `node_modules/bundler` and its `node_modules/bundler/node_modules/bundled-inner`
  — no registry publishes a small bundling package worth pinning, and generating
  one would mean publishing one.
- `missing-from-lockfile` in the root entry's `dependencies` — this is what a
  hand-edited or half-merged lockfile looks like, and npm will not write one on
  purpose.

Regenerate rather than hand-edit the rest. A hand-patched lockfile stops being
evidence of anything.
