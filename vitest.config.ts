import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Fixtures are real directories; the setup file makes sure nothing reaches
    // the network behind our back.
    setupFiles: ['./test/support/setup.ts'],
  },
})
