# yarn-classic-edge-cases

Hand-written in Yarn Classic's v1 text format, which is stable and has not
changed since 2018 — Yarn 1 is no longer installed to generate against, and the
grammar is small enough to write by hand without guessing.

| Shape | How Classic writes it | What cradle does |
| :-- | :-- | :-- |
| git dependency | descriptor `left-pad-git@git+ssh://…#<sha>`, `resolved` the same | Keeps it, and says that the name is the one it was **installed under** — Classic records the published name nowhere |
| `file:` dependency | descriptor `acme-local-lib@file:./local-lib`, no `resolved` | Keeps it, notes that it has no registry identity |
| declared but absent | in `package.json`, missing from the lockfile | Notes it |

Classic is the least informative of the four formats: no prod/dev marker, no
resolution field, and for a git or aliased dependency no published name. The
detection therefore reads the **descriptor's** range, which is the only place a
protocol appears at all.
