import { defineConfig } from 'vitest/config';

export default defineConfig({
  // The machine running the suites can be heavily loaded; the default of 5 s is too tight.
  // beforeAll hooks hash passwords and start real vaults, so they get 60 s.
  test: { testTimeout: 15_000, hookTimeout: 60_000 },
});
