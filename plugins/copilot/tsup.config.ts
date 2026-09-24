import { copyFileSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { defineConfig } from 'tsup';

// esbuild (on releases predating node:sqlite in its builtin list) externalizes
// the import but strips the `node:` prefix, emitting a bare `sqlite` specifier —
// a nonexistent npm package that crashes the hook at load. esbuild's own printer
// re-applies that stripping even when an onResolve plugin pins the path, so we
// restore the prefix on the emitted bundles instead. Same fix as
// plugins/codex/tsup.config.ts — both bundle @akasecurity/persistence, which
// imports node:sqlite.
//
// Hardened against the two ways a naive string-replace is fragile:
//   - matches only real module-specifier positions (`… from "sqlite"`,
//     `import("sqlite")`, `require("sqlite")`), so an incidental "sqlite" string
//     in a bundled dependency is left untouched; both quote styles are handled.
//   - re-scans each file afterward and throws if a bare specifier survives, so a
//     future change to esbuild's emit fails the BUILD loudly rather than shipping
//     a bundle that dies at load. A future esbuild that keeps `node:sqlite` on its
//     own yields zero rewrites and zero leftovers — no false failure.
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
          `normalization — esbuild's emit format may have changed. The hook would ` +
          `crash at load; failing the build instead.`,
      );
    }
  }
}

export default defineConfig({
  // Named entries keep the output flat in scripts/ — hooks.json paths depend on it
  entry: {
    // Hook entries land here as each one is written; the map grows with them.
    // `hooks.json` names each emitted script by the key it is registered under,
    // and `test/hooks-manifest.test.ts` holds the two to each other.
    'pre-tool-use': 'src/hooks/pre-tool-use.ts',
    'session-start': 'src/hooks/session-start.ts',
    'user-prompt-submit': 'src/hooks/user-prompt-submit.ts',
    // The three detached children `handleSessionStart` spawns, resolved as
    // SIBLINGS of the running script rather than by package name — so they are
    // entries here or the spawn names a file that does not exist. Two are inert
    // until the machine attaches; `content-retention` is gated on
    // `bodyRetention.enabled` alone, so it is reachable on a standalone machine
    // and ships with the hook rather than after it.
    sync: 'src/sync.ts',
    'history-sync': 'src/history-sync.ts',
    'content-retention': 'src/content-retention.ts',
    // The isolated scan's worker thread. No hook names it — plugin-sdk starts it
    // by path from whichever hook script is running, so the emitted script has to
    // land in this same directory. See src/scan-worker.ts.
    'scan-worker': 'src/scan-worker.ts',
  },
  format: ['esm'],
  platform: 'node',
  target: 'node24',
  outDir: 'scripts',
  splitting: false,
  // Hook scripts must be self-contained: the user's machine has no node_modules
  noExternal: [/^@akasecurity\//, 'zod'],
  onSuccess: async () => {
    normalizeSqliteSpecifier('scripts');
    // Ship the locked triage rubric next to the built scripts. runJudge's
    // default path is not in the package `files`, so the adapter reads
    // scripts/triage-rubric.md at runtime — copied here from the single source,
    // the harness-agnostic rubric owned by @akasecurity/setup-wizard (every
    // other plugin's build copies the same asset).
    copyFileSync(
      '../../packages/setup-wizard/assets/triage-rubric.md',
      join('scripts', 'triage-rubric.md'),
    );
  },
});
