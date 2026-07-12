import { defineConfig } from 'vitest/config';

/**
 * Unit tests live in test/ and run under jsdom-free Node with WebCrypto
 * available globally (Node 18+). The Playwright accessibility specs live in
 * e2e/ and must NOT be collected by vitest — they are driven by `npm run
 * test:a11y` instead.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
