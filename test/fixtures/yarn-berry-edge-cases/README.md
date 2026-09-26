# yarn-berry-edge-cases

Generated with **Yarn 4.18.1** (`yarn install --mode=update-lockfile`), so the
shapes below are Yarn's own output. An earlier hand-written version of this
fixture was wrong in three places at once — it is worth saying, because each
wrong guess hid a real bug rather than revealing one.

| Shape | How Berry writes it | What cradle does |
| :-- | :-- | :-- |
| `npm:` alias | descriptor `is-alias@npm:@sindresorhus/is@^7.0.1`, resolution `@sindresorhus/is@npm:7.2.0` | Takes the name from the **resolution**; notes the alias |
| `patch:` | a second entry over a package that also has a plain resolution | One component, not two, plus a note that the code on disk is not the published code |
| git dependency | resolution `left-pad-git@https://…#commit=<sha>` | Keeps it, and says plainly that Berry does not record what the package is published as |
| `portal:` | `linkType: soft`, same as a workspace | Keeps it as a dependency; only an `@workspace:` resolution makes a workspace |
| `::locator=` suffix | appended to portal and patch descriptors | Registers the bare spelling too, or `package.json`'s range never matches |

Three things this fixture pins, all of which were broken:

1. The name came from the descriptor, so an alias produced a component called
   `is-alias` with a purl for a package that does not exist.
2. `linkType: soft` was treated as "this is a workspace", so `portal:`
   dependencies were dropped and then reported as missing from a lockfile they
   were plainly in.
3. Descriptors were stored only in their protocol-stripped form, which is
   meaningless for an alias, so the alias never resolved.

`local-lib/` holds a `package.json` only. `missing-from-lockfile` is declared in
`package.json` and deliberately absent from `yarn.lock`.
