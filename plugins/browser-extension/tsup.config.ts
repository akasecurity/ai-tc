import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { defineConfig } from 'tsup';

// Same fix as plugins/codex/tsup.config.ts and plugins/claude-code/tsup.config.ts:
// esbuild (on releases predating node:sqlite in its builtin list) externalizes
// the import but strips the `node:` prefix, emitting a bare `sqlite` specifier —
// a nonexistent npm package that crashes the host at load. Restored on the
// emitted bundle since esbuild's own printer re-applies the stripping even when
// an onResolve plugin pins the path.
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
          `normalization — esbuild's emit format may have changed. The native host ` +
          `would crash at load; failing the build instead.`,
      );
    }
  }
}

// This config builds ONLY the Node-side native-messaging host — the
// browser-side entries (background/content/popup) are bundled separately by
// scripts/build.mjs via esbuild in browser mode, since tsup's platform:'node'
// output (and this sqlite fix) don't apply to them.
export default defineConfig({
  entry: {
    host: 'src/native-host/host.ts',
    // The isolated scan's worker thread. Chrome never launches it — plugin-sdk
    // starts it by path as a sibling of the running script, so it has to land
    // in this same outDir beside host.js. See src/native-host/scan-worker.ts.
    'scan-worker': 'src/native-host/scan-worker.ts',
    // The detached policy-sync child. This host calls handleSessionStart like
    // every other harness, so it triggers a policy pull on an attached machine
    // — and the trigger resolves the script as a sibling of the running one, so
    // it lands here beside host.js for the same reason scan-worker does.
    sync: 'src/native-host/sync.ts',
  },
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  outDir: 'native-host',
  splitting: false,
  // The native host ships as a self-contained script — the OS invokes it
  // directly with no node_modules alongside it, same story as the hook scripts.
  noExternal: [/^@akasecurity\//, 'zod'],
  onSuccess: async () => {
    normalizeSqliteSpecifier('native-host');
  },
});
