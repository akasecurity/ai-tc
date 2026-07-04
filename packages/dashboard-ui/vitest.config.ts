import { defineConfig } from 'vitest/config';

// The shared views are presentational; the tests here cover the pure helpers
// (meta/matcher logic), so a node environment is enough — no DOM. Add jsdom +
// @testing-library here if component-render tests are introduced later.
export default defineConfig({
  test: {
    environment: 'node',
  },
});
