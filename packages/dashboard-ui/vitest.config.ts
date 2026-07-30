import { defineConfig } from 'vitest/config';

// The shared views are presentational; the tests here cover the pure helpers
// (meta/matcher logic) and server-render the views via react-dom/server, so a
// node environment is enough — no DOM. Add jsdom + @testing-library here if
// interactive component tests are introduced later.
export default defineConfig({
  test: {
    environment: 'node',
  },
});
