import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Each test file starts its own vault on a short temporary socket directory.
    fileParallelism: false,
    testTimeout: 20_000,
  },
});
