import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Fixtures are real directories, not mocks — never let a test reach the network.
    env: { CRADLE_OFFLINE_GUARD: '1' },
  },
})
