/**
 * Hard stop on network access in tests.
 *
 * Every code path that talks to OSV takes an injected fetch. If one ever forgets
 * to, this makes it fail loudly here rather than quietly depending on the
 * network — and on advisory data that changes underneath us.
 */
globalThis.fetch = (async (input: string | URL | Request) => {
  throw new Error(
    `Tests must not use the network. Something tried to fetch ${String(input)} — ` +
      'inject a fake fetch (see test/support/osv.ts) instead.',
  )
}) as typeof globalThis.fetch
