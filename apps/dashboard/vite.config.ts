import { env } from 'node:process';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// The browser only ever talks to the dashboard's own origin. In development Vite forwards
// /v1 to the broker API so the session cookie stays same-origin and no CORS is needed.
const apiOrigin = env.AAB_API_ORIGIN ?? 'http://127.0.0.1:4000';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/v1': { target: apiOrigin, changeOrigin: false },
    },
  },
  build: {
    target: 'es2022',
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    include: ['test/**/*.test.{ts,tsx}'],
    setupFiles: ['./test/setup.ts'],
    restoreMocks: true,
  },
});
