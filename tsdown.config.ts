import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts', 'src/cli/index.ts'],
  format: ['esm'],
  target: 'node22',
  dts: true,
  clean: true,
  // The package is type:module, so plain .js is the idiomatic extension.
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
})
