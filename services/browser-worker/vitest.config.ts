import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globalSetup: ['test/global-setup.ts'],
    include: ['test/**/*.test.ts'],
    // Integration tests start a fixture server per file on a per-run port and each launch Chromium.
    fileParallelism: false,
    testTimeout: 90_000,
    hookTimeout: 60_000,
  },
});
