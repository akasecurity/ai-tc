import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { defineConfig } from 'tsup';

// Bundle the @akasecurity/* workspace packages (they ship raw .ts source) + zod into
// the binary, so the only runtime node_modules a globally-installed `aka` needs are its
// declared dependencies: ink + react (the TUI — bundling yoga-layout's wasm is
// fragile, so they stay external) and @akasecurity/web-ui (a separate spawned process),
// all declared as real package deps. node:sqlite stays a Node builtin — but
// esbuild on some releases strips the `node:` prefix to a bare `sqlite` specifier
// (a nonexistent npm package), so we restore it on the emitted bundle (same
// hardening as the claude-code plugin).
const SPECIFIER_SOURCE = String.raw`(\bfrom\s*|\b(?:import|require)\(\s*)(['"])sqlite\2`;

function normalizeSqliteSpecifier(outDir: string): void {
  for (const name of readdirSync(outDir)) {
    if (!name.endsWith('.js')) continue;
    const file = join(outDir, name);
    const before = readFileSync(file, 'utf8');
    const after = before.replace(
      new RegExp(SPECIFIER_SOURCE, 'g'),
      (_match, prefix: string, quote: string) => `${prefix}${quote}node:sqlite${quote}`,
    );
    if (after !== before) writeFileSync(file, after);
    if (new RegExp(SPECIFIER_SOURCE).test(after)) {
      throw new Error(
        `tsup: ${name} still imports a bare "sqlite" specifier after node:sqlite ` +
          `normalization — esbuild's emit format may have changed; failing the build.`,
      );
    }
  }
}

export default defineConfig({
  entry: { cli: 'src/cli.ts' },
  format: ['esm'],
  platform: 'node',
  target: 'node26',
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
