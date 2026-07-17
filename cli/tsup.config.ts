import { defineConfig } from 'tsup';

import { normalizeSqliteSpecifier } from './scripts/normalize-sqlite.mjs';

// Bundle the @akasecurity/* workspace packages (they ship raw .ts source) + zod into
// the binary, so the only runtime node_modules a globally-installed `aka` needs are its
// declared dependencies: ink + react (the TUI — bundling yoga-layout's wasm is
// fragile, so they stay external) and @akasecurity/web-ui (a separate spawned process),
// all declared as real package deps. node:sqlite stays a Node builtin — but
// esbuild on some releases strips the `node:` prefix to a bare `sqlite` specifier, so
// normalize-sqlite.mjs restores it on the emitted bundle (same hardening as the plugin).
export default defineConfig({
  entry: { cli: 'src/cli.ts' },
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  outDir: 'dist',
  splitting: false,
  clean: true,
  // The entry's `#!/usr/bin/env node` shebang is preserved by esbuild.
  noExternal: [/^@akasecurity\//, 'zod'],
  // @akasecurity/web-ui is a separate runtime (`aka dashboard` spawns its Next server);
  // it's resolved at runtime, never bundled into the CLI.
  external: ['@akasecurity/web-ui'],
  onSuccess: async () => {
    normalizeSqliteSpecifier('dist');
  },
});
